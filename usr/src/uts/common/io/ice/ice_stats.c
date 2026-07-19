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
 * Hardware statistics.
 *
 * The E810 exposes free-running MAC counters at two levels: per physical port
 * (GLPRT_*) and per VSI (GLV_*).  The vendored common code reads a single
 * counter and folds it into a running software total through
 * ice_stat_update40/32, subtracting a baseline captured on the first read so
 * the reported values count up from attach even though the hardware counters
 * survive a PF reset.  A few VSI counters (GLV_REPC) clear on read, so a single
 * serialized reader must own them; ice_stat_lock provides that serialization
 * for both the kstat and mac_stat consumers.
 *
 * The counter selection and register layout follow FreeBSD
 * sys/dev/ice/ice_lib.c (ice_update_pf_stats, ice_update_vsi_hw_stats); the
 * kstat presentation follows the in-tree i40e driver.
 */

#include <sys/types.h>
#include <sys/kstat.h>
#include <sys/ddifm.h>
#include <sys/time.h>

#include "ice.h"
#include "ice_common.h"
#include "ice_switch.h"

/* Coalesce the individual callbacks made for one MAC kstat snapshot. */
#define	ICE_STATS_MIN_UPDATE_NS	MSEC2NSEC(10)

/*
 * Refresh the cached port counters.  ice_stat_update40 reads a 40-bit counter
 * from the "low" register (the adjacent high register is captured by the same
 * 64-bit access); ice_stat_update32 reads a 32-bit counter.
 */
void
ice_stats_update_port(ice_t *ice)
{
	struct ice_hw *hw = &ice->ice_hw;
	struct ice_hw_port_stats *cur = &ice->ice_stat_port_cur;
	struct ice_hw_port_stats *prev = &ice->ice_stat_port_prev;
	boolean_t loaded = ice->ice_stat_port_loaded;
	hrtime_t now;
	uint8_t lport;

	ASSERT(MUTEX_HELD(&ice->ice_stat_lock));

	now = gethrtime();
	if (ice->ice_stat_port_last_update != 0 &&
	    now - ice->ice_stat_port_last_update < ICE_STATS_MIN_UPDATE_NS)
		return;
	if (hw->port_info == NULL)
		return;
	lport = hw->port_info->lport;

#define	ICE_PORT_STAT40(reg, field)					\
	ice_stat_update40(hw, reg ## L(lport), loaded,			\
	    &prev->field, &cur->field)
#define	ICE_PORT_STAT32(reg, field)					\
	ice_stat_update32(hw, reg(lport), loaded,			\
	    &prev->field, &cur->field)

	ICE_PORT_STAT40(GLPRT_GORC, eth.rx_bytes);
	ICE_PORT_STAT40(GLPRT_UPRC, eth.rx_unicast);
	ICE_PORT_STAT40(GLPRT_MPRC, eth.rx_multicast);
	ICE_PORT_STAT40(GLPRT_BPRC, eth.rx_broadcast);
	ICE_PORT_STAT40(GLPRT_GOTC, eth.tx_bytes);
	ICE_PORT_STAT40(GLPRT_UPTC, eth.tx_unicast);
	ICE_PORT_STAT40(GLPRT_MPTC, eth.tx_multicast);
	ICE_PORT_STAT40(GLPRT_BPTC, eth.tx_broadcast);

	ICE_PORT_STAT32(GLPRT_TDOLD, tx_dropped_link_down);
	ICE_PORT_STAT32(GLPRT_LXONRXC, link_xon_rx);
	ICE_PORT_STAT32(GLPRT_LXOFFRXC, link_xoff_rx);
	ICE_PORT_STAT32(GLPRT_LXONTXC, link_xon_tx);
	ICE_PORT_STAT32(GLPRT_LXOFFTXC, link_xoff_tx);
	ICE_PORT_STAT32(GLPRT_CRCERRS, crc_errors);
	ICE_PORT_STAT32(GLPRT_ILLERRC, illegal_bytes);
	ICE_PORT_STAT32(GLPRT_MLFC, mac_local_faults);
	ICE_PORT_STAT32(GLPRT_MRFC, mac_remote_faults);
	ICE_PORT_STAT32(GLPRT_RLEC, rx_len_errors);
	ICE_PORT_STAT32(GLPRT_RUC, rx_undersize);
	ICE_PORT_STAT32(GLPRT_RFC, rx_fragments);
	ICE_PORT_STAT32(GLPRT_ROC, rx_oversize);
	ICE_PORT_STAT32(GLPRT_RJC, rx_jabber);

#undef	ICE_PORT_STAT40
#undef	ICE_PORT_STAT32

	ice->ice_stat_port_loaded = B_TRUE;
	ice->ice_stat_port_last_update = gethrtime();
}

/*
 * Refresh the cached VSI counters for this interface's PF VSI.  GLV_REPC clears
 * on read and is handled by the common code, which accumulates its
 * no-descriptor and error sub-counts into the current stats.
 */
void
ice_stats_update_vsi(ice_t *ice)
{
	struct ice_hw *hw = &ice->ice_hw;
	struct ice_eth_stats *cur = &ice->ice_stat_vsi_cur;
	struct ice_eth_stats *prev = &ice->ice_stat_vsi_prev;
	boolean_t loaded = ice->ice_stat_vsi_loaded;
	uint16_t handle = ice->ice_pf_vsi.vi_handle;
	uint16_t vsi_num;

	ASSERT(MUTEX_HELD(&ice->ice_stat_lock));

	if (!ice_is_vsi_valid(hw, handle))
		return;
	vsi_num = ice_get_hw_vsi_num(hw, handle);

#define	ICE_VSI_STAT40(reg, field)					\
	ice_stat_update40(hw, reg ## L(vsi_num), loaded,		\
	    &prev->field, &cur->field)
#define	ICE_VSI_STAT32(reg, field)					\
	ice_stat_update32(hw, reg(vsi_num), loaded,			\
	    &prev->field, &cur->field)

	ICE_VSI_STAT40(GLV_GORC, rx_bytes);
	ICE_VSI_STAT40(GLV_UPRC, rx_unicast);
	ICE_VSI_STAT40(GLV_MPRC, rx_multicast);
	ICE_VSI_STAT40(GLV_BPRC, rx_broadcast);
	ICE_VSI_STAT32(GLV_RDPC, rx_discards);
	ICE_VSI_STAT40(GLV_GOTC, tx_bytes);
	ICE_VSI_STAT40(GLV_UPTC, tx_unicast);
	ICE_VSI_STAT40(GLV_MPTC, tx_multicast);
	ICE_VSI_STAT40(GLV_BPTC, tx_broadcast);
	ICE_VSI_STAT32(GLV_TEPC, tx_errors);

#undef	ICE_VSI_STAT40
#undef	ICE_VSI_STAT32

	ice_stat_update_repc(hw, handle, loaded, cur);

	ice->ice_stat_vsi_loaded = B_TRUE;
}

/*
 * A failed private-kstat refresh does not affect service, so record it as
 * unaffected, matching i40e and ixgbe.  The GLDv3 MAC-stat path applies its
 * stronger degraded-service policy in ice_m_stat().
 */
static void
ice_stats_check_acc(ice_t *ice)
{
	if (ice_check_acc_handle(ice->ice_osdep.ios_reg_handle) != DDI_FM_OK)
		ddi_fm_service_impact(ice->ice_dip, DDI_SERVICE_UNAFFECTED);
}

static int
ice_pf_kstat_update(kstat_t *ksp, int rw)
{
	ice_t *ice = ksp->ks_private;
	ice_pf_kstats_t *ipk = ksp->ks_data;
	struct ice_hw_port_stats *ps = &ice->ice_stat_port_cur;

	if (rw == KSTAT_WRITE)
		return (EACCES);

	/*
	 * ice_rebuild_lock is the outermost lock: a reset rebuild shuts the
	 * control queue down and clears the scheduler tables, so the counter
	 * reads (which deref hw->port_info and index registers by its lport)
	 * must not straddle it.
	 */
	mutex_enter(&ice->ice_rebuild_lock);
	mutex_enter(&ice->ice_stat_lock);
	ice_stats_update_port(ice);

	ipk->ipk_rx_bytes.value.ui64 = ps->eth.rx_bytes;
	ipk->ipk_rx_unicast.value.ui64 = ps->eth.rx_unicast;
	ipk->ipk_rx_multicast.value.ui64 = ps->eth.rx_multicast;
	ipk->ipk_rx_broadcast.value.ui64 = ps->eth.rx_broadcast;
	ipk->ipk_tx_bytes.value.ui64 = ps->eth.tx_bytes;
	ipk->ipk_tx_unicast.value.ui64 = ps->eth.tx_unicast;
	ipk->ipk_tx_multicast.value.ui64 = ps->eth.tx_multicast;
	ipk->ipk_tx_broadcast.value.ui64 = ps->eth.tx_broadcast;
	ipk->ipk_crc_errors.value.ui64 = ps->crc_errors;
	ipk->ipk_illegal_bytes.value.ui64 = ps->illegal_bytes;
	ipk->ipk_mac_local_faults.value.ui64 = ps->mac_local_faults;
	ipk->ipk_mac_remote_faults.value.ui64 = ps->mac_remote_faults;
	ipk->ipk_rx_len_errors.value.ui64 = ps->rx_len_errors;
	ipk->ipk_rx_undersize.value.ui64 = ps->rx_undersize;
	ipk->ipk_rx_fragments.value.ui64 = ps->rx_fragments;
	ipk->ipk_rx_oversize.value.ui64 = ps->rx_oversize;
	ipk->ipk_rx_jabber.value.ui64 = ps->rx_jabber;
	ipk->ipk_tx_dropped_link_down.value.ui64 = ps->tx_dropped_link_down;
	ipk->ipk_link_xon_rx.value.ui64 = ps->link_xon_rx;
	ipk->ipk_link_xoff_rx.value.ui64 = ps->link_xoff_rx;
	ipk->ipk_link_xon_tx.value.ui64 = ps->link_xon_tx;
	ipk->ipk_link_xoff_tx.value.ui64 = ps->link_xoff_tx;

	ice_stats_check_acc(ice);
	mutex_exit(&ice->ice_stat_lock);
	mutex_exit(&ice->ice_rebuild_lock);
	return (0);
}

static int
ice_vsi_kstat_update(kstat_t *ksp, int rw)
{
	ice_t *ice = ksp->ks_private;
	ice_vsi_kstats_t *ivk = ksp->ks_data;
	struct ice_eth_stats *es = &ice->ice_stat_vsi_cur;

	if (rw == KSTAT_WRITE)
		return (EACCES);

	/*
	 * ice_rebuild_lock is the outermost lock: a reset rebuild recreates the
	 * PF VSI, so the VSI handle lookup and the register reads it feeds must
	 * not straddle it.
	 */
	mutex_enter(&ice->ice_rebuild_lock);
	mutex_enter(&ice->ice_stat_lock);
	ice_stats_update_vsi(ice);

	ivk->ivk_rx_bytes.value.ui64 = es->rx_bytes;
	ivk->ivk_rx_unicast.value.ui64 = es->rx_unicast;
	ivk->ivk_rx_multicast.value.ui64 = es->rx_multicast;
	ivk->ivk_rx_broadcast.value.ui64 = es->rx_broadcast;
	ivk->ivk_rx_discards.value.ui64 = es->rx_discards;
	ivk->ivk_rx_no_desc.value.ui64 = es->rx_no_desc;
	ivk->ivk_rx_errors.value.ui64 = es->rx_errors;
	ivk->ivk_tx_bytes.value.ui64 = es->tx_bytes;
	ivk->ivk_tx_unicast.value.ui64 = es->tx_unicast;
	ivk->ivk_tx_multicast.value.ui64 = es->tx_multicast;
	ivk->ivk_tx_broadcast.value.ui64 = es->tx_broadcast;
	ivk->ivk_tx_errors.value.ui64 = es->tx_errors;

	ice_stats_check_acc(ice);
	mutex_exit(&ice->ice_stat_lock);
	mutex_exit(&ice->ice_rebuild_lock);
	return (0);
}

static boolean_t
ice_pf_kstat_init(ice_t *ice)
{
	kstat_t *ksp;
	ice_pf_kstats_t *ipk;

	ksp = kstat_create(ICE_MODULE_NAME, ice->ice_instance, "pfstats",
	    "net", KSTAT_TYPE_NAMED,
	    sizeof (ice_pf_kstats_t) / sizeof (kstat_named_t), 0);
	if (ksp == NULL)
		return (B_FALSE);

	ice->ice_pf_kstat = ksp;
	ipk = ksp->ks_data;
	ksp->ks_update = ice_pf_kstat_update;
	ksp->ks_private = ice;

	kstat_named_init(&ipk->ipk_rx_bytes, "rx_bytes", KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_rx_unicast, "rx_unicast", KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_rx_multicast, "rx_multicast",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_rx_broadcast, "rx_broadcast",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_tx_bytes, "tx_bytes", KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_tx_unicast, "tx_unicast", KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_tx_multicast, "tx_multicast",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_tx_broadcast, "tx_broadcast",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_crc_errors, "crc_errors", KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_illegal_bytes, "illegal_bytes",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_mac_local_faults, "mac_local_faults",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_mac_remote_faults, "mac_remote_faults",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_rx_len_errors, "rx_length_errors",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_rx_undersize, "rx_undersize",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_rx_fragments, "rx_fragments",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_rx_oversize, "rx_oversize",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_rx_jabber, "rx_jabber", KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_tx_dropped_link_down, "tx_dropped_link_down",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_link_xon_rx, "link_xon_rx",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_link_xoff_rx, "link_xoff_rx",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_link_xon_tx, "link_xon_tx",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_link_xoff_tx, "link_xoff_tx",
	    KSTAT_DATA_UINT64);

	kstat_install(ksp);
	return (B_TRUE);
}

static boolean_t
ice_vsi_kstat_init(ice_t *ice)
{
	kstat_t *ksp;
	ice_vsi_kstats_t *ivk;

	ksp = kstat_create(ICE_MODULE_NAME, ice->ice_instance, "vsistats",
	    "net", KSTAT_TYPE_NAMED,
	    sizeof (ice_vsi_kstats_t) / sizeof (kstat_named_t), 0);
	if (ksp == NULL)
		return (B_FALSE);

	ice->ice_vsi_kstat = ksp;
	ivk = ksp->ks_data;
	ksp->ks_update = ice_vsi_kstat_update;
	ksp->ks_private = ice;

	kstat_named_init(&ivk->ivk_rx_bytes, "rx_bytes", KSTAT_DATA_UINT64);
	kstat_named_init(&ivk->ivk_rx_unicast, "rx_unicast", KSTAT_DATA_UINT64);
	kstat_named_init(&ivk->ivk_rx_multicast, "rx_multicast",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ivk->ivk_rx_broadcast, "rx_broadcast",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ivk->ivk_rx_discards, "rx_discards",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ivk->ivk_rx_no_desc, "rx_no_descriptor",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ivk->ivk_rx_errors, "rx_errors", KSTAT_DATA_UINT64);
	kstat_named_init(&ivk->ivk_tx_bytes, "tx_bytes", KSTAT_DATA_UINT64);
	kstat_named_init(&ivk->ivk_tx_unicast, "tx_unicast", KSTAT_DATA_UINT64);
	kstat_named_init(&ivk->ivk_tx_multicast, "tx_multicast",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ivk->ivk_tx_broadcast, "tx_broadcast",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ivk->ivk_tx_errors, "tx_errors", KSTAT_DATA_UINT64);

	kstat_install(ksp);
	return (B_TRUE);
}

boolean_t
ice_stats_init(ice_t *ice)
{
	mutex_init(&ice->ice_stat_lock, NULL, MUTEX_DRIVER, NULL);

	/*
	 * Establish both hardware baselines before exposing either kstat.
	 * Otherwise, traffic and clear-on-read errors before the first observer
	 * would be discarded as pre-attach activity.
	 */
	mutex_enter(&ice->ice_stat_lock);
	ice_stats_update_port(ice);
	ice_stats_update_vsi(ice);
	mutex_exit(&ice->ice_stat_lock);
	ice_stats_check_acc(ice);

	if (!ice_pf_kstat_init(ice))
		goto fail;
	if (!ice_vsi_kstat_init(ice))
		goto fail;

	return (B_TRUE);

fail:
	ice_stats_fini(ice);
	return (B_FALSE);
}

void
ice_stats_fini(ice_t *ice)
{
	if (ice->ice_vsi_kstat != NULL) {
		kstat_delete(ice->ice_vsi_kstat);
		ice->ice_vsi_kstat = NULL;
	}
	if (ice->ice_pf_kstat != NULL) {
		kstat_delete(ice->ice_pf_kstat);
		ice->ice_pf_kstat = NULL;
	}

	mutex_destroy(&ice->ice_stat_lock);
}
