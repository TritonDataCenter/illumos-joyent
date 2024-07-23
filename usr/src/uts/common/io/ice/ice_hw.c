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

const ice_context_map_t ice_txq_map[] = {
	{ offsetof(ice_hw_txq_context_t, ihtc_base), 8, 0, 56 },
	{ offsetof(ice_hw_txq_context_t, ihtc_port), 1, 57, 59 },
	{ offsetof(ice_hw_txq_context_t, ihtc_cgd), 1, 60, 64 },
	{ offsetof(ice_hw_txq_context_t, ihtc_pf), 1, 65, 67 },
	{ offsetof(ice_hw_txq_context_t, ihtc_vmvf_num), 2, 68, 77 },
	{ offsetof(ice_hw_txq_context_t, ihtc_vmvf_type), 1, 78, 79 },
	{ offsetof(ice_hw_txq_context_t, ihtc_vsi_id), 2, 80, 89 },
	{ offsetof(ice_hw_txq_context_t, ihtc_tsync), 1, 90, 90 },
	{ offsetof(ice_hw_txq_context_t, ihtc_alt_vlan), 1, 92, 92 },
	{ offsetof(ice_hw_txq_context_t, ihtc_cpuid), 1, 93, 100 },
	{ offsetof(ice_hw_txq_context_t, ihtc_wb_mode), 1, 101, 101 },
	{ offsetof(ice_hw_txq_context_t, ihtc_tphrdesc), 1, 102, 102 },
	{ offsetof(ice_hw_txq_context_t, ihtc_tphdrdata), 1, 103, 103 },
	{ offsetof(ice_hw_txq_context_t, ihtc_compq_id), 2, 104, 104 },
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
static boolean_t
ice_context_write(ice_t *ice, const uint8_t *src, void *dest, size_t destlen,
    const ice_context_map_t *map)
{
	uint_t nbits, fbyte, shift;
	uint64_t val, mask, tmp;

	nbits = map->icm_maxbit - map->icm_minbit + 1;
	if (nbits > map->icm_memlen * 8) {
		ice_error(ice, "invalid context entry, asked to use %u bits "
		    "from a %u byte length member", nbits, map->icm_memlen);
		return (B_FALSE);
	}

	/*
	 * Make sure that we can place a uint64_t worth of data from fbyte.
	 */
	fbyte = map->icm_minbit / 8;
	if (fbyte + sizeof (uint64_t) >= destlen) {
		ice_error(ice, "context entry starts at byte %u, but the "
		    "buffer is %zu bytes long and we need space for 8 bytes",
		    fbyte, destlen);
		return (B_FALSE);
	}

	/*
	 * We go through and take the corresponding field and store it in a
	 * uint64_t. This makes it easier for us to do the rest of the
	 * manipulation and at this point ignore what the actual field size is.
	 */
	switch (map->icm_memlen) {
	case 1:
		val = *(uint8_t *)src;
		break;
	case 2:
		val = *(uint16_t *)src;
		break;
	case 4:
		val = *(uint32_t *)src;
		break;
	case 8:
		val = *(uint64_t *)src;
		break;
	default:
		ice_error(ice, "context entry has invalid member legth: %u",
		    map->icm_memlen);
		return (B_FALSE);
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
		return (B_FALSE);
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

	return (B_TRUE);
}

boolean_t
ice_rxq_context_write(ice_t *ice, ice_hw_rxq_context_t *ctxt, uint_t index)
{
	uint_t i;
	uint8_t buf[ICE_HW_RXQ_CTX_PHYSICAL_SIZE];

	if (index >= ICE_MAX_RX_QUEUES) {
		ice_error(ice, "asked to write rxq context to illegal index: "
		    "%u", index);
		return (B_FALSE);
	}

	bzero(buf, sizeof (buf));
	for (i = 0; i < ARRAY_SIZE(ice_rxq_map); i++) {
		if (!ice_context_write(ice, (uint8_t *)ctxt, buf, sizeof (buf),
		    &ice_rxq_map[i])) {
			return (B_FALSE);
		}
	}

	for (i = 0; i < ICE_HW_RXQ_CTX_PHYSICAL_SIZE; i += sizeof (uint32_t)) {
		uintptr_t reg = ice_rxq_context_register(index, i);
		uint32_t val;

		bcopy(&buf[i], &val, sizeof (uint32_t));
		ice_reg_write(ice, reg, val);
	}

	return (B_TRUE);
}

boolean_t
ice_pf_reset(ice_t *ice)
{
	uint_t i;
	uint32_t val;

	/*
	 * XXX Check if a global reset is in progress.
	 */
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
		return (B_FALSE);
	}

	return (B_TRUE);
}
