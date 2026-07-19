/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2026 Edgecast Cloud LLC.
 */

/*
 * Control-plane setup for the PF's data VSI: create the VSI, program the
 * default unicast and broadcast MAC filters through the switch, and configure
 * RSS (hash key, redirection table, and the hashed flow types), all through
 * the Intel common code under core/.  Ring DMA and queue-context programming
 * live in ice_tx.c and ice_rx.c; MAC registration in ice_gld.c.
 *
 * Identifier values that originate in firmware are validated before the driver
 * uses them as an index: the VSI handle is trusted only after ice_is_vsi_valid,
 * and the firmware-assigned hardware VSI number is bounds-checked before it is
 * stored.
 */

#include <sys/random.h>

#include "ice.h"
#include "ice_common.h"
#include "ice_switch.h"
#include "ice_flow.h"

static const uint8_t ice_bcast_addr[ETHERADDRL] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

/*
 * The flow types hashed for RSS: TCP and UDP over IPv4 and IPv6, plus plain
 * IPv4/IPv6 so non-TCP/UDP traffic still spreads across queues instead of all
 * landing on queue 0.
 */
static const struct {
	uint64_t	irf_hash;
	uint32_t	irf_hdrs;
} ice_rss_flows[] = {
	{ ICE_HASH_TCP_IPV4, ICE_FLOW_SEG_HDR_IPV4 | ICE_FLOW_SEG_HDR_TCP },
	{ ICE_HASH_UDP_IPV4, ICE_FLOW_SEG_HDR_IPV4 | ICE_FLOW_SEG_HDR_UDP },
	{ ICE_HASH_TCP_IPV6, ICE_FLOW_SEG_HDR_IPV6 | ICE_FLOW_SEG_HDR_TCP },
	{ ICE_HASH_UDP_IPV6, ICE_FLOW_SEG_HDR_IPV6 | ICE_FLOW_SEG_HDR_UDP },
	{ ICE_FLOW_HASH_IPV4, ICE_FLOW_SEG_HDR_IPV4 },
	{ ICE_FLOW_HASH_IPV6, ICE_FLOW_SEG_HDR_IPV6 }
};

static void
ice_fltr_entry_init(struct ice_fltr_list_entry *e, uint16_t handle,
    const uint8_t *addr)
{
	bzero(e, sizeof (*e));
	e->fltr_info.flag = ICE_FLTR_TX;
	e->fltr_info.lkup_type = ICE_SW_LKUP_MAC;
	e->fltr_info.fltr_act = ICE_FWD_TO_VSI;
	e->fltr_info.vsi_handle = handle;
	e->fltr_info.src_id = ICE_SRC_ID_VSI;
	bcopy(addr, e->fltr_info.l_data.mac.mac_addr, ETHERADDRL);
}

static void
ice_mac_filter_track(ice_vsi_t *vsi, const uint8_t *addr)
{
	ice_mac_filter_t *imf;

	imf = kmem_zalloc(sizeof (*imf), KM_SLEEP);
	bcopy(addr, imf->imf_addr, ETHERADDRL);
	mutex_enter(&vsi->vi_mac_lock);
	list_insert_tail(&vsi->vi_macs, imf);
	mutex_exit(&vsi->vi_mac_lock);
}

/*
 * Tear down everything ice_vsi_setup() may have created.  Safe to call on a
 * partially-initialized VSI: each step is gated on the state it undoes.  The
 * Tx scheduler nodes reserved by ice_cfg_vsi_lan() and the switch filter state
 * are reclaimed by ice_deinit_hw() (a lower attach-progress bit, undone later
 * in ice_unconfigure()); the best-effort removals here keep state tidy on a
 * normal detach.
 */
static void
ice_vsi_teardown(ice_t *ice)
{
	struct ice_hw *hw = &ice->ice_hw;
	ice_vsi_t *vsi = &ice->ice_pf_vsi;
	struct ice_fltr_list_entry *ents = NULL;
	ice_mac_filter_t *imf;
	uint_t n = 0, i = 0;

	/*
	 * Build the removal list under the lock, but issue the (blocking) admin
	 * queue command with the lock dropped.
	 */
	mutex_enter(&vsi->vi_mac_lock);
	for (imf = list_head(&vsi->vi_macs); imf != NULL;
	    imf = list_next(&vsi->vi_macs, imf))
		n++;
	if (n > 0) {
		struct LIST_HEAD_TYPE rm;

		ents = kmem_zalloc(n * sizeof (*ents), KM_SLEEP);
		INIT_LIST_HEAD(&rm);
		for (imf = list_head(&vsi->vi_macs); imf != NULL;
		    imf = list_next(&vsi->vi_macs, imf)) {
			ice_fltr_entry_init(&ents[i], vsi->vi_handle,
			    imf->imf_addr);
			LIST_ADD(&ents[i].list_entry, &rm);
			i++;
		}
		mutex_exit(&vsi->vi_mac_lock);

		(void) ice_remove_mac(hw, &rm);
		kmem_free(ents, n * sizeof (*ents));

		mutex_enter(&vsi->vi_mac_lock);
	}
	while ((imf = list_remove_head(&vsi->vi_macs)) != NULL)
		kmem_free(imf, sizeof (*imf));
	mutex_exit(&vsi->vi_mac_lock);

	if (vsi->vi_added) {
		struct ice_vsi_ctx *ctx = ice_get_vsi_ctx(hw, vsi->vi_handle);

		(void) ice_free_vsi(hw, vsi->vi_handle, ctx, false, NULL);
		vsi->vi_added = B_FALSE;
	}
}

/*
 * Build the VSI context for a basic PF data VSI: a contiguous block of queues
 * on TC0 with a per-VSI RSS LUT and Toeplitz hashing.  The buffer is sent in
 * full, so it must start zeroed.
 */
static int
ice_vsi_ctx_fill(ice_t *ice, struct ice_vsi_ctx *ctx)
{
	struct ice_hw *hw = &ice->ice_hw;
	ice_vsi_t *vsi = &ice->ice_pf_vsi;
	uint16_t nq = vsi->vi_nrxq;

	/*
	 * Reject stale queue sizing here because an internal capability
	 * mismatch must fail attach without panicking the machine.
	 */
	if (nq == 0 || nq > MIN(hw->func_caps.common_cap.num_rxq,
	    hw->func_caps.common_cap.num_txq)) {
		ice_error(ice, "invalid PF VSI queue count %u (rx %u, tx %u)",
		    nq, hw->func_caps.common_cap.num_rxq,
		    hw->func_caps.common_cap.num_txq);
		return (ICE_ERR_CFG);
	}

	bzero(ctx, sizeof (*ctx));

	ctx->flags = ICE_AQ_VSI_TYPE_PF;
	ctx->alloc_from_pool = 1;	/* firmware assigns the HW VSI number */
	ctx->vf_num = 0;

	ctx->info.valid_sections = CPU_TO_LE16(ICE_AQ_VSI_PROP_SW_VALID |
	    ICE_AQ_VSI_PROP_VLAN_VALID | ICE_AQ_VSI_PROP_RXQ_MAP_VALID |
	    ICE_AQ_VSI_PROP_Q_OPT_VALID);

	/* switch ids are small; the field is a u8 */
	ctx->info.sw_id = (u8)hw->port_info->sw_id;
	/* Prune frames the VSI itself sourced; do not loop them back. */
	ctx->info.sw_flags = ICE_AQ_VSI_SW_FLAG_SRC_PRUNE;
	ctx->info.sw_flags2 = ICE_AQ_VSI_SW_FLAG_LAN_ENA;
	/* A zero Tx mode blocks every host frame and increments GLV_TEPC. */
	ctx->info.inner_vlan_flags = ICE_AQ_VSI_INNER_VLAN_TX_MODE_ALL;

	/*
	 * Contiguous rx-queue map: q_mapping[0] is the first absolute queue and
	 * q_mapping[1] is the count.  Both are required; a zero count (the
	 * bzero default) maps no queues to the VSI and receive never works.
	 */
	ctx->info.mapping_flags = CPU_TO_LE16(ICE_AQ_VSI_Q_MAP_CONTIG);
	ctx->info.q_mapping[0] = CPU_TO_LE16(0);
	ctx->info.q_mapping[1] = CPU_TO_LE16(nq);
	ctx->info.tc_mapping[0] = CPU_TO_LE16(
	    (0 << ICE_AQ_VSI_TC_Q_OFFSET_S) |
	    ((uint16_t)ice_fls(nq - 1) << ICE_AQ_VSI_TC_Q_NUM_S));

	/* A PF VSI uses the PF-wide RSS LUT instance. */
	ctx->info.q_opt_rss = (ICE_AQ_VSI_Q_OPT_RSS_LUT_PF &
	    ICE_AQ_VSI_Q_OPT_RSS_LUT_M) | ICE_AQ_VSI_Q_OPT_RSS_TPLZ;

	return (ICE_SUCCESS);
}

/*
 * Permit or reject local loopback for frames that the PF VSI transmitted.
 * Both loopback flags are required for the local VEB path, and source pruning
 * must be disabled so that the VSI can receive frames bearing its own source
 * MAC address.  Restore source pruning when leaving this privileged,
 * transient diagnostic mode.  The cached common-code context is the
 * authoritative copy of the other switch-section fields, so preserve it and
 * update the cache only after firmware accepts the change.  The loopback
 * mutex serializes mode changes; detach disables loopback before tearing down
 * the VSI.
 */
int
ice_vsi_loopback_set(ice_t *ice, boolean_t enable)
{
	struct ice_hw *hw = &ice->ice_hw;
	ice_vsi_t *vsi = &ice->ice_pf_vsi;
	struct ice_vsi_ctx *cached;
	struct ice_vsi_ctx ctx;
	u8 flags;
	int status;

	ASSERT(MUTEX_HELD(&ice->ice_loopback_lock));

	cached = ice_get_vsi_ctx(hw, vsi->vi_handle);
	if (cached == NULL)
		return (ICE_ERR_DOES_NOT_EXIST);

	flags = cached->info.sw_flags;
	if (enable) {
		flags |= ICE_AQ_VSI_SW_FLAG_ALLOW_LB |
		    ICE_AQ_VSI_SW_FLAG_LOCAL_LB;
		flags &= ~ICE_AQ_VSI_SW_FLAG_SRC_PRUNE;
	} else {
		flags &= ~(ICE_AQ_VSI_SW_FLAG_ALLOW_LB |
		    ICE_AQ_VSI_SW_FLAG_LOCAL_LB);
		flags |= ICE_AQ_VSI_SW_FLAG_SRC_PRUNE;
	}
	if (flags == cached->info.sw_flags)
		return (ICE_SUCCESS);

	bzero(&ctx, sizeof (ctx));
	ctx.info = cached->info;
	ctx.info.valid_sections = CPU_TO_LE16(ICE_AQ_VSI_PROP_SW_VALID);
	ctx.info.sw_flags = flags;

	status = ice_update_vsi(hw, vsi->vi_handle, &ctx, NULL);
	if (status == ICE_SUCCESS) {
		cached->info.sw_flags = flags;
		cached->info.valid_sections |= ctx.info.valid_sections;
	}

	return (status);
}

static int
ice_vsi_setup(ice_t *ice)
{
	struct ice_hw *hw = &ice->ice_hw;
	ice_vsi_t *vsi = &ice->ice_pf_vsi;
	struct ice_vsi_ctx *cached;
	struct ice_vsi_ctx ctx;
	uint16_t max_lanqs[ICE_MAX_TRAFFIC_CLASS];
	int status;

	vsi->vi_handle = ICE_PF_VSI_HANDLE;

	vsi->vi_nrxq = ice->ice_nqueues;
	vsi->vi_ntxq = ice->ice_nqueues;

	status = ice_vsi_ctx_fill(ice, &ctx);
	if (status != ICE_SUCCESS)
		return (status);

	status = ice_add_vsi(hw, vsi->vi_handle, &ctx, NULL);
	if (status != ICE_SUCCESS) {
		ice_error(ice, "failed to add PF VSI: %d", status);
		return (status);
	}
	vsi->vi_added = B_TRUE;

	/*
	 * Trust the handle only after ice_is_vsi_valid(), and bounds-check the
	 * firmware-assigned HW VSI number before storing it: it is firmware
	 * input the driver will later use to index per-VSI state.
	 */
	if (!ice_is_vsi_valid(hw, vsi->vi_handle)) {
		ice_error(ice, "PF VSI handle %u invalid after add",
		    vsi->vi_handle);
		ice_vsi_teardown(ice);
		return (ICE_ERR_PARAM);
	}
	vsi->vi_hw_num = ice_get_hw_vsi_num(hw, vsi->vi_handle);
	if (vsi->vi_hw_num >= ICE_MAX_VSI) {
		ice_error(ice, "firmware returned out-of-range VSI number %u",
		    vsi->vi_hw_num);
		ice_vsi_teardown(ice);
		return (ICE_ERR_PARAM);
	}

	/*
	 * ice_add_vsi() refreshes only vsi_num on a context that survived the
	 * reset, so the cached copy would keep pre-reset switch flags firmware
	 * no longer has.  ice_vsi_loopback_set() reads that cache as
	 * authoritative and would then no-op against stale flags.  Copy the
	 * info section only: the cached context owns queue-context pointers
	 * the common code allocated.
	 */
	cached = ice_get_vsi_ctx(hw, vsi->vi_handle);
	if (cached == NULL) {
		ice_error(ice, "PF VSI context missing after add");
		ice_vsi_teardown(ice);
		return (ICE_ERR_DOES_NOT_EXIST);
	}
	cached->info = ctx.info;

	/*
	 * Reserve scheduler nodes for the planned tx queue count.  max_lanqs is
	 * indexed per traffic class by the common code, so it must be a full
	 * ICE_MAX_TRAFFIC_CLASS array even though only TC0 is enabled.
	 */
	bzero(max_lanqs, sizeof (max_lanqs));
	max_lanqs[0] = vsi->vi_ntxq;
	status = ice_cfg_vsi_lan(hw->port_info, vsi->vi_handle, BIT(0),
	    max_lanqs);
	if (status != ICE_SUCCESS) {
		ice_error(ice, "failed to configure VSI scheduler: %d", status);
		ice_vsi_teardown(ice);
		return (status);
	}

	return (ICE_SUCCESS);
}

static int
ice_add_mac_filters(ice_t *ice)
{
	struct ice_hw *hw = &ice->ice_hw;
	ice_vsi_t *vsi = &ice->ice_pf_vsi;
	struct ice_fltr_list_entry uc, bc;
	struct LIST_HEAD_TYPE m_list;
	const uint8_t *mac;
	int status;

	mac = hw->port_info->mac.perm_addr;
	if (IS_ZERO_ETHER_ADDR(mac)) {
		ice_error(ice, "firmware reported a zero station MAC address");
		return (ICE_ERR_PARAM);
	}

	INIT_LIST_HEAD(&m_list);
	ice_fltr_entry_init(&uc, vsi->vi_handle, mac);
	ice_fltr_entry_init(&bc, vsi->vi_handle, ice_bcast_addr);
	LIST_ADD(&uc.list_entry, &m_list);
	LIST_ADD(&bc.list_entry, &m_list);

	/*
	 * ice_add_mac()'s return is the authoritative result for the batch.
	 * On failure roll back any rule it did install (best effort; the VSI
	 * free and ice_deinit_hw() reclaim the rest).
	 */
	status = ice_add_mac(hw, &m_list);
	if (status != ICE_SUCCESS) {
		ice_error(ice, "failed to add MAC filters: %d", status);
		(void) ice_remove_mac(hw, &m_list);
		return (status);
	}

	ice_mac_filter_track(vsi, mac);
	ice_mac_filter_track(vsi, ice_bcast_addr);
	return (ICE_SUCCESS);
}

static int
ice_rss_setup(ice_t *ice)
{
	struct ice_hw *hw = &ice->ice_hw;
	ice_vsi_t *vsi = &ice->ice_pf_vsi;
	struct ice_aqc_get_set_rss_keys key;
	struct ice_aq_get_set_rss_lut_params lp;
	uint16_t lut_size = hw->func_caps.common_cap.rss_table_size;
	uint8_t *lut;
	uint_t i;
	int status;

	/*
	 * Safe mode (no DDP package) advertises no RSS table, so skip RSS
	 * rather than fail attach: a missing package is not fatal.  A non-zero
	 * but implausible size is still rejected as a hostile value.
	 */
	if (ice->ice_safe_mode) {
		vsi->vi_rss_set = B_FALSE;
		return (ICE_SUCCESS);
	}
	if (lut_size == 0 || lut_size > ICE_LUT_PF_SIZE) {
		ice_error(ice, "implausible RSS table size %u", lut_size);
		return (ICE_ERR_CFG);
	}

	(void) random_get_pseudo_bytes((uint8_t *)&key, sizeof (key));
	status = ice_aq_set_rss_key(hw, vsi->vi_handle, &key);
	if (status != ICE_SUCCESS) {
		ice_error(ice, "failed to set RSS key: %d", status);
		return (status);
	}

	/* Round-robin the PF redirection table over the planned rx queues. */
	ASSERT3U(vsi->vi_nrxq, >, 0);
	lut = kmem_zalloc(lut_size, KM_SLEEP);
	for (i = 0; i < lut_size; i++)
		lut[i] = (uint8_t)(i % vsi->vi_nrxq);

	bzero(&lp, sizeof (lp));
	lp.vsi_handle = vsi->vi_handle;
	lp.lut_type = ICE_LUT_PF;
	lp.lut_size = lut_size;
	lp.lut = lut;
	status = ice_aq_set_rss_lut(hw, &lp);
	kmem_free(lut, lut_size);
	if (status != ICE_SUCCESS) {
		ice_error(ice, "failed to set RSS LUT: %d", status);
		return (status);
	}

	for (i = 0; i < ARRAY_SIZE(ice_rss_flows); i++) {
		struct ice_rss_hash_cfg cfg;

		bzero(&cfg, sizeof (cfg));
		cfg.hash_flds = ice_rss_flows[i].irf_hash;
		cfg.addl_hdrs = ice_rss_flows[i].irf_hdrs;
		cfg.hdr_type = ICE_RSS_OUTER_HEADERS;
		cfg.symm = false;

		status = ice_add_rss_cfg(hw, vsi->vi_handle, &cfg);
		if (status != ICE_SUCCESS) {
			ice_error(ice, "failed to add RSS flow %u: %d", i,
			    status);
			return (status);
		}
	}

	vsi->vi_rss_set = B_TRUE;
	return (ICE_SUCCESS);
}

boolean_t
ice_vsi_init(ice_t *ice)
{
	ice_vsi_t *vsi = &ice->ice_pf_vsi;

	mutex_init(&vsi->vi_mac_lock, NULL, MUTEX_DRIVER, NULL);
	list_create(&vsi->vi_macs, sizeof (ice_mac_filter_t),
	    offsetof(ice_mac_filter_t, imf_node));

	if (ice_vsi_setup(ice) != ICE_SUCCESS)
		goto fail;
	if (ice_add_mac_filters(ice) != ICE_SUCCESS)
		goto fail;
	if (ice_rss_setup(ice) != ICE_SUCCESS)
		goto fail;

	return (B_TRUE);

fail:
	ice_vsi_teardown(ice);
	list_destroy(&vsi->vi_macs);
	mutex_destroy(&vsi->vi_mac_lock);
	return (B_FALSE);
}

void
ice_vsi_fini(ice_t *ice)
{
	ice_vsi_t *vsi = &ice->ice_pf_vsi;

	ice_vsi_teardown(ice);
	list_destroy(&vsi->vi_macs);
	mutex_destroy(&vsi->vi_mac_lock);
}

/*
 * Recreate the PF data VSI and its filters after a reset.  A reset clears the
 * VSI, its switch filters, and the RSS configuration; this rebuilds them from
 * the software state.  The vi_macs list is the authoritative record and is
 * replayed into hardware but never modified here.  The list_create()/mutex_init
 * done once in ice_vsi_init() is not repeated.  Called from ice_rebuild() under
 * ice_rebuild_lock.
 */
int
ice_vsi_rebuild(ice_t *ice)
{
	struct ice_hw *hw = &ice->ice_hw;
	ice_vsi_t *vsi = &ice->ice_pf_vsi;
	struct ice_fltr_list_entry *ents = NULL;
	ice_mac_filter_t *imf;
	uint_t n = 0, i = 0;
	int status;

	status = ice_vsi_setup(ice);
	if (status != ICE_SUCCESS)
		return (status);

	/*
	 * The reset cleared the switch rules in hardware but not the common
	 * code's record of them, and this rebuild frees no common-code state.
	 * Without draining that record the replay below collides with the
	 * pre-reset entries: broadcast returns ICE_ERR_ALREADY_EXISTS and the
	 * station unicast is silently skipped.  ice_replay_pre_init() moves the
	 * entries onto the replay lists; the ice_rm_all_sw_replay_rule_info()
	 * at "done" discards them on every path out.  It can fail after having
	 * already moved them, so its own error path goes through "done" too.
	 */
	status = ice_replay_pre_init(hw, hw->switch_info);
	if (status != ICE_SUCCESS) {
		ice_error(ice, "failed to prepare the filter replay: %d",
		    status);
		goto done;
	}

	/*
	 * Replay every tracked MAC filter.  Build the list under the lock but
	 * issue the blocking admin-queue command with it dropped, matching
	 * ice_vsi_teardown().
	 */
	mutex_enter(&vsi->vi_mac_lock);
	for (imf = list_head(&vsi->vi_macs); imf != NULL;
	    imf = list_next(&vsi->vi_macs, imf))
		n++;
	if (n > 0) {
		struct LIST_HEAD_TYPE add;

		ents = kmem_zalloc(n * sizeof (*ents), KM_SLEEP);
		INIT_LIST_HEAD(&add);
		for (imf = list_head(&vsi->vi_macs); imf != NULL;
		    imf = list_next(&vsi->vi_macs, imf)) {
			ice_fltr_entry_init(&ents[i], vsi->vi_handle,
			    imf->imf_addr);
			LIST_ADD(&ents[i].list_entry, &add);
			i++;
		}
		mutex_exit(&vsi->vi_mac_lock);

		status = ice_add_mac(hw, &add);
		kmem_free(ents, n * sizeof (*ents));
		if (status != ICE_SUCCESS) {
			ice_error(ice, "failed to replay MAC filters: %d",
			    status);
			goto done;
		}
	} else {
		mutex_exit(&vsi->vi_mac_lock);
	}

	status = ice_rss_setup(ice);
	if (status != ICE_SUCCESS)
		goto done;

	/* Restore promiscuous mode if it was enabled before the reset. */
	if (ice->ice_promisc_on && ice_promisc_apply(ice, B_TRUE) != 0)
		status = ICE_ERR_CFG;

done:
	/*
	 * Nothing else reclaims the entries ice_replay_pre_init() set aside, so
	 * drop them on the failure path too.
	 */
	ice_rm_all_sw_replay_rule_info(hw);
	return (status);
}
