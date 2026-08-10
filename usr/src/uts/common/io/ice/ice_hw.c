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
 * Copyright 2019, Joyent, Inc.
 * Copyright 2026 RackTop Systems, Inc.
 */

/*
 * Drive interactions withi hardware that require us to manipulate registers and
 * therefore may change from version to version.
 */

#include "ice.h"

/*
 * These two values indicate the amount of time that we should spin waiting for
 * a PF reset to complete. Datasheet section '4.1.3.1 PFR Flow' suggests that a
 * PF reset should occur within 100ms. If it does not complete, then that
 * indicates that it's being blocked by something else.
 */
clock_t ice_hw_pf_reset_delay = 1000;
uint_t ice_hw_pf_reset_count = 100;

typedef struct ice_context_map {
	uint_t	icm_member;
	uint_t	icm_memlen;
	uint_t	icm_minbit;
	uint_t	icm_maxbit;
} ice_context_map_t;

const ice_context_map_t ice_rxq_map[] = {
	{ offsetof(ice_hw_rxq_context_t, ihrc_head), 2, 0, 12 },
	{ offsetof(ice_hw_rxq_context_t, ihrc_base), 8, 32, 88 },
	{ offsetof(ice_hw_rxq_context_t, ihrc_qlen), 2, 89, 101 },
	{ offsetof(ice_hw_rxq_context_t, ihrc_dbuff), 1, 102, 108 },
	{ offsetof(ice_hw_rxq_context_t, ihrc_hbuff), 1, 109, 113 },
	{ offsetof(ice_hw_rxq_context_t, ihrc_dtype), 1, 114, 115 },
	{ offsetof(ice_hw_rxq_context_t, ihrc_dsize), 1, 116, 116 },
	{ offsetof(ice_hw_rxq_context_t, ihrc_crcstrip), 1, 117, 117 },
	{ offsetof(ice_hw_rxq_context_t, ihrc_l2tsel), 1, 119, 119 },
	{ offsetof(ice_hw_rxq_context_t, ihrc_hsplit0), 1, 120, 123 },
	{ offsetof(ice_hw_rxq_context_t, ihrc_hsplit1), 1, 124, 125 },
	{ offsetof(ice_hw_rxq_context_t, ihrc_showiv), 1, 127, 127 },
	{ offsetof(ice_hw_rxq_context_t, ihrc_rxmax), 2, 174, 187 },
	{ offsetof(ice_hw_rxq_context_t, ihrc_tphrdesc), 1, 193, 193 },
	{ offsetof(ice_hw_rxq_context_t, ihrc_tphwdesc), 1, 194, 194 },
	{ offsetof(ice_hw_rxq_context_t, ihrc_tphdata), 1, 195, 195 },
	{ offsetof(ice_hw_rxq_context_t, ihrc_tphhead), 1, 196, 196 },
	{ offsetof(ice_hw_rxq_context_t, ihrc_lrxqthresh), 1, 198, 200 },
	{ offsetof(ice_hw_rxq_context_t, ihrc_req),  1, 201, 201 }
};

/*
 * From Table 10-29 (section 10.5.5.2.1), bit 91 is 'Internal Usage Flag'
 * but must be equal to TSO_Enabled_Queue (bit 152). So we propagate the
 * value of ice_hw_txq_context_t.ihtc_tso to both bits.
 */
const ice_context_map_t ice_txq_map[] = {
	{ offsetof(ice_hw_txq_context_t, ihtc_base), 8, 0, 56 },
	{ offsetof(ice_hw_txq_context_t, ihtc_port), 1, 57, 59 },
	{ offsetof(ice_hw_txq_context_t, ihtc_cgd), 1, 60, 64 },
	{ offsetof(ice_hw_txq_context_t, ihtc_pf), 1, 65, 67 },
	{ offsetof(ice_hw_txq_context_t, ihtc_vmvf_num), 2, 68, 77 },
	{ offsetof(ice_hw_txq_context_t, ihtc_vmvf_type), 1, 78, 79 },
	{ offsetof(ice_hw_txq_context_t, ihtc_vsi_id), 2, 80, 89 },
	{ offsetof(ice_hw_txq_context_t, ihtc_tsync), 1, 90, 90 },
	{ offsetof(ice_hw_txq_context_t, ihtc_tso), 1, 91, 91 },
	{ offsetof(ice_hw_txq_context_t, ihtc_alt_vlan), 1, 92, 92 },
	{ offsetof(ice_hw_txq_context_t, ihtc_cpuid), 1, 93, 100 },
	{ offsetof(ice_hw_txq_context_t, ihtc_wb_mode), 1, 101, 101 },
	{ offsetof(ice_hw_txq_context_t, ihtc_tphrdesc), 1, 102, 102 },
	{ offsetof(ice_hw_txq_context_t, ihtc_tphdrdata), 1, 103, 103 },
	{ offsetof(ice_hw_txq_context_t, ihtc_tphwrdesc), 1, 104, 104 },
	{ offsetof(ice_hw_txq_context_t, ihtc_compq_id), 2, 105, 113 },
	{ offsetof(ice_hw_txq_context_t, ihtc_func_qnum), 2, 114, 127 },
	{ offsetof(ice_hw_txq_context_t, ihtc_itr_mode), 1, 128, 128 },
	{ offsetof(ice_hw_txq_context_t, ihtc_profile), 1, 129, 134 },
	{ offsetof(ice_hw_txq_context_t, ihtc_qlen), 2, 135, 147 },
	{ offsetof(ice_hw_txq_context_t, ihtc_quanta), 1, 148, 151 },
	{ offsetof(ice_hw_txq_context_t, ihtc_tso), 1, 152, 152 },
	{ offsetof(ice_hw_txq_context_t, ihtc_tso_queue), 2, 153, 163 },
	{ offsetof(ice_hw_txq_context_t, ihtc_legacy), 1, 164, 164 },
	{ offsetof(ice_hw_txq_context_t, ihtc_drop), 1, 165, 165 },
	{ offsetof(ice_hw_txq_context_t, ihtc_cache), 1, 166, 167 },
	{ offsetof(ice_hw_txq_context_t, ihtc_pkg_shape), 1, 168, 170 }
};

static uintptr_t
ice_rxq_context_register(uint_t queue, uint_t byteoff)
{
	uint_t index;

	ASSERT3U(queue, <, ICE_MAX_RX_QUEUES);
	ASSERT3U(byteoff, <, ICE_HW_RXQ_CTX_PHYSICAL_SIZE);

	index = byteoff / 4;
	return (ICE_REG_RXQ_CONTEXT_BASE + 0x2000 * index + 0x4 * queue);
}

/*
 * We need to take a normal aligned value an write it into a fixed size byte
 * field in dest. The map entry describes to us the offset in source and the bit
 * length that it will show up in dest. To do this, we end up trying to find a
 * number of bytes that this will fit in and memcpy and edit that.
 */
static bool
ice_context_write(ice_t *ice, const uint8_t *src, void *dest, size_t destlen,
    const ice_context_map_t *map)
{
	uint_t nbits, fbyte, shift;
	uint64_t val, mask, tmp;

	nbits = map->icm_maxbit - map->icm_minbit + 1;
	if (nbits > map->icm_memlen * 8) {
		ice_error(ice, "invalid context entry, asked to use %u bits "
		    "from a %u byte length member", nbits, map->icm_memlen);
		return (false);
	}

	/*
	 * Make sure that we can place a uint64_t worth of data from fbyte.
	 */
	fbyte = map->icm_minbit / 8;
	if (fbyte + sizeof (uint64_t) > destlen) {
		ice_error(ice, "context entry starts at byte %u, but the "
		    "buffer is %zu bytes long and we need space for 8 bytes",
		    fbyte, destlen);
		return (false);
	}

	/*
	 * We go through and take the corresponding field and store it in a
	 * uint64_t. This makes it easier for us to do the rest of the
	 * manipulation and at this point ignore what the actual field size is.
	 */
	switch (map->icm_memlen) {
	case 1:
		val = *((uint8_t *)src + map->icm_member);
		break;
	case 2:
		val = *((uint16_t *)(src + map->icm_member));
		break;
	case 4:
		val = *((uint32_t *)(src + map->icm_member));
		break;
	case 8:
		val = *((uint64_t *)(src + map->icm_member));
		break;
	default:
		ice_error(ice, "context entry has invalid member length: %u",
		    map->icm_memlen);
		return (false);
	}

	/*
	 * Now that we've unified the value into a uint64_t, let's make sure
	 * that we don't have any inappropriate bits set in our value.
	 */
	if (nbits == 64) {
		mask = UINT64_MAX;
	} else {
		mask = (1 << nbits) - 1;
	}
	if ((~mask & val) != 0) {
		ice_error(ice, "found illegal bits set in context entry: "
		    "have value %" PRIx64 " and mask %" PRIx64, val, mask);
		return (false);
	}

	/*
	 * Now, both the mask and value need to be shifted based upon the number
	 * of bits off from the starting byte we have.
	 */
	shift = map->icm_minbit % 8;
	mask = mask << shift;
	val = val << shift;

	bcopy(dest + fbyte, &tmp, sizeof (tmp));
	tmp &= ~LE_64(mask);
	tmp |= LE_64(val);
	bcopy(&tmp, dest + fbyte, sizeof (tmp));

	return (true);
}

bool
ice_rxq_context_write(ice_t *ice, ice_hw_rxq_context_t *ctxt, uint_t index)
{
	/* Similar to the TXQ, we need some padding for ice_context_write() */
	uint8_t buf[ICE_HW_RXQ_CTX_PHYSICAL_SIZE + sizeof (uint64_t)];
	uint_t i;

	if (index >= ICE_MAX_RX_QUEUES) {
		ice_error(ice, "asked to write rxq context to illegal index: "
		    "%u", index);
		return (false);
	}

	bzero(buf, sizeof (buf));
	for (i = 0; i < ARRAY_SIZE(ice_rxq_map); i++) {
		if (!ice_context_write(ice, (uint8_t *)ctxt, buf, sizeof (buf),
		    &ice_rxq_map[i])) {
			ice_error(ice, "failed writing RX queue context "
			    "field %u", i);
			return (false);
		}
	}

	for (i = 0; i < ICE_HW_RXQ_CTX_PHYSICAL_SIZE; i += sizeof (uint32_t)) {
		uintptr_t reg = ice_rxq_context_register(index, i);
		uint32_t val;

		bcopy(&buf[i], &val, sizeof (uint32_t));
		ice_reg_write(ice, reg, val);
	}

	return (true);
}

/*
 * ice_context_write() required len to be a multiple of 8 (sizeof (uint64_t)),
 * however the size in the hw struct is 22 bytes (Table 10-34), so we have
 * to bounce the packed context through a temporary buffer.
 */
#define	ICE_TX_CTX_TEMP_SZ 32

bool
ice_txq_context_write(ice_t *ice, ice_hw_txq_context_t *ctxt, uint8_t *dest,
    size_t len)
{
	uint8_t bounce[ICE_TX_CTX_TEMP_SZ] = { 0 };
	uint_t i;

	ASSERT3U(len, <=, sizeof (bounce));

	bzero(dest, len);
	for (i = 0; i < ARRAY_SIZE(ice_txq_map); i++) {
		if (!ice_context_write(ice, (uint8_t *)ctxt, bounce,
		    sizeof (bounce), &ice_txq_map[i])) {
			ice_error(ice, "failed writing TX queue context "
			    "field %u (bits [%u, %u])", i,
			    ice_txq_map[i].icm_minbit,
			    ice_txq_map[i].icm_maxbit);
			return (false);
		}
	}
	bcopy(bounce, dest, len);

	return (true);
}

/*
 * Check if a global reset is active, and if so, wait for it to complete
 */
static bool
ice_pf_check_reset(ice_t *ice)
{
	uint32_t val, val2;
	uint_t i;

	val = ice_reg_read(ice, ICE_REG_GLGEN_RSTAT);
	val2 = ice_reg_read(ice, ICE_REG_GLNVM_ULD);

	/* No reset active, we're good */
	if ((ICE_REG_GLGEN_RSTAT_DEVSTATE(val) ==
	    ICE_REG_GLGEN_RSTAT_DEVSTATE_ACTIVE) &&
	    (val2 & ICE_REG_GLNVM_ULD_DONE) == ICE_REG_GLNVM_ULD_DONE) {
		return (true);
	}

	val = ice_reg_read(ice, ICE_REG_GLGEN_RSTAT);
	/*
	 * The FreeBSD driver suggests adding 1s to the delay time to allow
	 * long running AQ commands to complete. We follow this suggestion.
	 */
	val += 10;

	for (i = 0; i < val; i++) {
		/*
		 * The timeout is in units of 100ms, so we'll wait
		 * 100ms at a time.
		 */
		delay(drv_usectohz(100 * 1000));

		val2 = ice_reg_read(ice, ICE_REG_GLGEN_RSTAT);
		if (ICE_REG_GLGEN_RSTAT_DEVSTATE(val2) ==
		    ICE_REG_GLGEN_RSTAT_DEVSTATE_ACTIVE) {
			break;
		}
	}

	if (i == val) {
		ice_error(ice, "timeout waiting for global reset to complete");
		return (false);
	}

	/*
	 * Check global reset processes. Check a somewhat arbitrary every
	 * 10ms for completion.
	 */
	for (i = 0; i < ICE_GLNVM_RESET_WAIT / 10; i++) {
		val = ice_reg_read(ice, ICE_REG_GLNVM_ULD);
		if ((val & ICE_REG_GLNVM_ULD_DONE) == ICE_REG_GLNVM_ULD_DONE) {
			/* All done */
			return (true);
		}

		delay(drv_usectohz(10 * 1000));
	}

	ice_error(ice, "timeout waiting for global reset processes to "
	    "complete: GLNVM_ULD = 0x%b", val, ICE_REG_GLNVM_ULD_STR);

	return (false);
}

bool
ice_pf_reset(ice_t *ice)
{
	uint_t i;
	uint32_t val;

	if (!ice_pf_check_reset(ice)) {
		return (false);
	}

	val = ice_reg_read(ice, ICE_REG_PFGEN_CTRL);
	val |= ICE_REG_PFGEN_CTRL_PFSWR;
	ice_reg_write(ice, ICE_REG_PFGEN_CTRL, val);

	for (i = 0; i < ice_hw_pf_reset_count; i++) {
		val = ice_reg_read(ice, ICE_REG_PFGEN_CTRL);
		if ((val & ICE_REG_PFGEN_CTRL_PFSWR) == 0) {
			break;
		}

		delay(drv_usectohz(ice_hw_pf_reset_delay));
	}

	if (i == ice_hw_pf_reset_count) {
		ice_error(ice, "failed to reset PF after 100ms");
		return (false);
	}

	return (true);
}

/*
 * Provide more context-specific error messages for the add/modify/del
 * switch rule commands.
 */
static const char *
ice_sw_rule_err(ice_cq_errno_t e)
{
	switch (e) {
	case ICE_CQ_EACCESS:
		return ("resource not owned by this PF");
	case ICE_CQ_ENOSPC:
		return ("could not allocate space for rule");
	case ICE_CQ_EINVAL:
		return ("invalid parameter or rule exists");
	case ICE_CQ_ENOENT:
		return ("bad resource index");
	default:
		return (ice_controlq_errmsg(e));
	}
}

#define	RULE_DATA_SZ	16
#define	ADD_RULE_SZ	(sizeof (ice_sw_lookup_t) + RULE_DATA_SZ)

typedef enum init_rule_flags {
	IRF_RX = 	0,
	IRF_TX =	(1 << 0),
	IRF_LB =	(1 << 1)
} init_rule_flags_t;

static void *
ice_init_rule(ice_sw_lookup_t *lk, uint16_t vsi_id, uint16_t src,
    init_rule_flags_t flags)
{
	uint32_t action;

	action = ICE_SW_RULE_ACT_T_LOGICAL_PORT_FWD |
	    ICE_SW_RULE_ACT_LAN_EN |
	    ICE_SW_RULE_ACT_SET_VSI(0, vsi_id) |
	    ICE_SW_RULE_ACT_VSI_VALID;
	if ((flags & IRF_LB) != 0) {
		action |= ICE_SW_RULE_ACT_LB_EN;
	}

	lk->iswl_hdr.iswrh_type = ((flags & IRF_TX) != 0) ?
	    LE_16(ICE_SW_RULE_T_LOOKUP_TX) :
	    LE_16(ICE_SW_RULE_T_LOOKUP_RX);

	lk->iswl_rid = LE_16(ICE_SW_RECIPE_PROMISC);
	lk->iswl_source = LE_16(src);
	lk->iswl_action = LE_32(action);
	lk->iswl_header_len = LE_16(RULE_DATA_SZ);

	return (&lk->iswl_data[RULE_DATA_SZ]);
}

static void *
ice_init_remove_rule(ice_sw_lookup_t *lk, uint16_t rid)
{
	/*
	 * Unlike adding, we don't need to specify any data -- just
	 * specify the rule id to delete
	 */
	lk->iswl_index = LE_16(rid);
	return (lk->iswl_data);
}

/*
 * Add a MAC address (any type) for the given VSI (by hw id).
 * This needs to be called for every MAC address that will be accepted
 * by the VSI (based on the FreeBSD source) -- so the main MAC address,
 * the broadcast address, as well as anything else. This creates
 * the appropriate switch rule to pass the traffic. On success, it
 * sets *idxp to the rule index returned by the hardware.
 */
int
ice_add_mac(ice_t *ice, uint_t vsi_id, const uint8_t *mac, uint16_t *idxp)
{
	uint8_t		buf[ADD_RULE_SZ] = { 0 };
	ice_sw_lookup_t	*lk = (ice_sw_lookup_t *)buf;
	ice_sw_lookup_t *end;
	uint16_t	len;

	/*
	 * If seems a bit unintuitive that this is a TX rule when adding
	 * a MAC address. However after scouring the FreeBSD source this
	 * appears to be how it's ice_add_mac() creates the rule, so we
	 * do the same.
	 */
	end = ice_init_rule(lk, vsi_id, vsi_id, IRF_TX|IRF_LB);
	len = (uintptr_t)end - (uintptr_t)lk;

	ASSERT3U(len, <=, sizeof (buf));

	/* Copy the mac address to the 'dest' part of the rule data */
	bcopy(mac, lk->iswl_data, ETHERADDRL);

	if (!ice_cmd_switch_rules(ice, ICE_CQ_OP_ADD_SW_RULES, 1, buf, len)) {
		return (EIO);
	}

	if (lk->iswl_hdr.iswrh_status != 0) {
		ice_error(ice, "failed to add mac %02x:%02x:%02x:%02x:%02x: %s",
		    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
		    ice_sw_rule_err(lk->iswl_hdr.iswrh_status));
		return (EIO);
	}

	*idxp = LE_16(lk->iswl_index);

	return (0);
}

#define	NRULE	4

enum rules {
	R_TX = 0,
	R_MTX,
	R_RX,
	R_MRX
};

static const char *r_str[] = {
	"TX", "multicast TX", "RX", "multicast RX"
};

bool
ice_promisc_on(ice_t *ice)
{
	uint8_t		buf[NRULE * ADD_RULE_SZ] = { 0 };
	ice_vsi_t	*vsi;
	ice_sw_lookup_t	*next, *r[NRULE];
	size_t		len;
	uint_t		i, n_rids;
	uint16_t	rids[NRULE] = { 0 };

	/*
	 * Per mac_capab_rings(9E), multicast, and promiscuous mode should
	 * only be enabled on the first group, which is in the first VSI
	 */
	vsi = list_head(&ice->ice_vsi);

	struct {
		enum rules	rule;
		uint16_t	src;
		bool		is_tx;
		bool		is_mcast;
	} params[] = {
		{ R_TX, vsi->ivsi_id, true, false },
		{ R_MTX, vsi->ivsi_id, true, true },
		{ R_RX, ice->ice_port_id, false, false },
		{ R_MRX, ice->ice_port_id, false, true },
	};

	next = (ice_sw_lookup_t *)buf;
	for (i = 0; i < NRULE; i++) {
		init_rule_flags_t	flags;

		flags = params[i].is_tx ? IRF_TX : IRF_RX;

		r[i] = next;
		next = ice_init_rule(r[i], vsi->ivsi_id, params[i].src, flags);

		r[i]->iswl_data[0] = 0x02;
		r[i]->iswl_data[6] = 0x02;

		if (params[i].is_mcast) {
			r[i]->iswl_data[0] |= 0x01;
		}
	}

	len = (uintptr_t)next - (uintptr_t)buf;
	ASSERT3U(len, <=, sizeof (buf));

	if (!ice_cmd_switch_rules(ice, ICE_CQ_OP_ADD_SW_RULES, NRULE,
	    buf, len)) {
			return (false);
	}

	/* Check for partial addition */
	n_rids = 0;
	for (i = 0; i < NRULE; i++) {
		if (r[i]->iswl_hdr.iswrh_status == 0) {
			rids[n_rids++] = r[i]->iswl_index;
		} else {
			ice_error(ice, "failed to add %s rule: %s", r_str[i],
			    ice_sw_rule_err(r[i]->iswl_hdr.iswrh_status));
		}
	}

	if (n_rids == NRULE) {
		/* All good */
		ice->ice_promisc_rid_tx = rids[R_TX];
		ice->ice_promisc_m_rid_tx = rids[R_MTX];
		ice->ice_promisc_rid_rx = rids[R_RX];
		ice->ice_promisc_m_rid_rx = rids[R_MRX];

		return (true);
	}

	/*
	 * Remove any rules that did succeed so we're not in some
	 * quasi-promiscuous mode
	 */
	(void) ice_remove_rule(ice, n_rids, rids);

	return (false);
}

bool
ice_promisc_off(ice_t *ice)
{
	uint16_t rids[NRULE] = {
		ice->ice_promisc_rid_tx,
		ice->ice_promisc_m_rid_tx,
		ice->ice_promisc_rid_rx,
		ice->ice_promisc_m_rid_rx,
	};
	int	ret;
	
	ret = ice_remove_rule(ice, NRULE, rids);
	return ((ret == 0) ? true : false);
}
#undef NRULE

/*
 * This removes the switch rule given by the given rule index (set by the
 * hardware when a rule is added). This is used both to remove MAC addresses
 * as well as VLAN rules.
 */
int
ice_remove_rule(ice_t *ice, uint16_t nrule, uint16_t *rids)
{
	ice_sw_lookup_t	*lk, *next;
	void		*buf;
	size_t		buflen;
	size_t		len;
	int		ret = 0;

	if (nrule == 0) {
		return (0);
	}

	buflen = (size_t)nrule * sizeof (ice_sw_lookup_t);
	buf = kmem_zalloc(buflen, KM_SLEEP);

	next = buf;
	for (uint_t i = 0; i < nrule; i++) {
		lk = next;
		next = ice_init_remove_rule(lk, rids[i]);
	}

	len = (uintptr_t)next - (uintptr_t)buf;
	ASSERT3U(len, <=, buflen);

	if (!ice_cmd_switch_rules(ice, ICE_CQ_OP_REMOVE_SW_RULES, nrule, buf,
	    len)) {
		ret = EIO;
	}

	kmem_free(buf, buflen);
	return (ret);
}
