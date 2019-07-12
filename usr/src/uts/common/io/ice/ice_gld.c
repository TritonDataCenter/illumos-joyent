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
 * Describe the purpose of this file.
 */

#include "ice.h"

/*
 * This table maps the Intel PHY bits to and from the corresponding MAC values
 * as well as tracks the various link speeds that we care about. The Intel PHY
 * table orders them based on speed, therefore we have our table based on the
 * minimum and maximum bits that are used.
 */
typedef struct ice_phy_map {
	uint_t	ipm_bit_min;
	uint_t	ipm_bit_max;
	uint_t	ipm_adv_prop;
	uint_t	ipm_en_prop;
} ice_phy_map_t;

/*
 * This maps a subset of hardware PHY IDs to properties and things that we know
 * about in the GLDv3. The datasheet supports 200G and 400G based speeds, but we
 * do not support them currently in the GLDv3. XXX fix this.
 */
ice_phy_map_t ice_phy_map[] = {
	{ ICE_PHY_100BASE_TX, ICE_PHY_100M_SGMII,
	    MAC_PROP_ADV_100FDX_CAP, MAC_PROP_EN_100FDX_CAP },
	{ ICE_PHY_1000BASE_T, ICE_PHY_1G_SGMII,
	    MAC_PROP_ADV_1000FDX_CAP, MAC_PROP_EN_1000FDX_CAP },
	{ ICE_PHY_2500BASE_T, ICE_PHY_2500BASE_KX,
	    MAC_PROP_ADV_2500FDX_CAP, MAC_PROP_EN_2500FDX_CAP },
	{ ICE_PHY_5GBASE_T, ICE_PHY_5GBASE_KR,
	    MAC_PROP_ADV_5000FDX_CAP, MAC_PROP_EN_5000FDX_CAP },
	{ ICE_PHY_10GBASE_T, ICE_PHY_10G_SFI_C2C,
	    MAC_PROP_ADV_10GFDX_CAP, MAC_PROP_EN_10GFDX_CAP },
	{ ICE_PHY_25GBASE_T, ICE_PHY_25G_AUI_C2C,
	    MAC_PROP_ADV_25GFDX_CAP, MAC_PROP_EN_25GFDX_CAP },
	{ ICE_PHY_40GBASE_CR4, ICE_PHY_40G_XLAUI,
	    MAC_PROP_ADV_40GFDX_CAP, MAC_PROP_EN_40GFDX_CAP },
	{ ICE_PHY_50GBASE_CR2, ICE_PHY_50G_AUI1,
	    MAC_PROP_ADV_50GFDX_CAP, MAC_PROP_EN_50GFDX_CAP },
	{ ICE_PHY_100GBASE_CR4, ICE_PHY_100G_AUI2,
	    MAC_PROP_ADV_100GFDX_CAP, MAC_PROP_EN_100GFDX_CAP },
};

static int
ice_group_add_mac(void *arg, const uint8_t *mac_addr)
{
	return (0);
}

static int
ice_group_remove_mac(void *arg, const uint8_t *mac_addr)
{
	return (0);
}

/*
 * XXX Stub I/O related functions should probably move to their own file.
 */
static int
ice_ring_rx_start(mac_ring_driver_t rh, uint64_t gen_num)
{
	return (0);
}

static mblk_t *
ice_ring_rx_poll(void *arg, int poll_bytes)
{
	return (NULL);
}

static mblk_t *
ice_ring_tx(void *arg, mblk_t *mp)
{
	freemsg(mp);
	return (NULL);
}

static int
ice_ring_rx_stat(mac_ring_driver_t rh, uint_t stat, uint64_t *val)
{
	return (ENOTSUP);
}

static int
ice_ring_tx_stat(mac_ring_driver_t rh, uint_t stat, uint64_t *val)
{
	return (ENOTSUP);
}

static int
ice_ring_rx_intr_enable(mac_intr_handle_t intrh)
{
	return (0);
}

static int
ice_ring_rx_intr_disable(mac_intr_handle_t intrh)
{
	return (0);
}

static void
ice_fill_rx_ring(void *arg, mac_ring_type_t rtype, const int group_index,
    const int ring_index, mac_ring_info_t *infop, mac_ring_handle_t rh)
{
	infop->mri_start = ice_ring_rx_start;
	infop->mri_poll = ice_ring_rx_poll;
	infop->mri_stat = ice_ring_rx_stat;
	infop->mri_intr.mi_enable = ice_ring_rx_intr_enable;
	infop->mri_intr.mi_disable = ice_ring_rx_intr_disable;
}

static void
ice_fill_tx_ring(void *arg, mac_ring_type_t rtype, const int group_index,
    const int ring_index, mac_ring_info_t *infop, mac_ring_handle_t rh)
{
	infop->mri_tx = ice_ring_tx;
	infop->mri_stat = ice_ring_tx_stat;
}

static void
ice_fill_rx_group(void *arg, mac_ring_type_t rtype, const int index,
    mac_group_info_t *infop, mac_group_handle_t gh)
{
	ice_t *ice = arg;

	if (rtype != MAC_RING_TYPE_RX) {
		return;
	}

	infop->mgi_driver = (mac_group_driver_t)ice;
	infop->mgi_start = NULL;
	infop->mgi_stop = NULL;
	infop->mgi_addmac = ice_group_add_mac;
	infop->mgi_remmac = ice_group_remove_mac;
	infop->mgi_count = ice->ice_num_rxq_per_vsi;
}

static int
ice_m_stat(void *arg, uint_t stat, uint64_t *valp)
{
	ice_t *ice = arg;
	int ret = 0;

	/*
	 * XXX This lock doesn't cover all stats nor should it.
	 * XXX I only have a few stats here to get things going.
	 */
	mutex_enter(&ice->ice_lse_lock);
	switch (stat) {
	case MAC_STAT_IFSPEED:
		*valp = ice->ice_link_cur_speed * 1000000ULL;
		break;
	case ETHER_STAT_LINK_DUPLEX:
		*valp = ice->ice_link_cur_duplex;
		break;
	default:
		ret = ENOTSUP;
	}
	mutex_exit(&ice->ice_lse_lock);

	return (ret);
}

static void
ice_m_stop(void *arg)
{
	ice_t *ice = arg;

	if (!ice_cmd_setup_link(ice, B_FALSE)) {
		ice_error(ice, "failed to stop link");
	}

	mutex_enter(&ice->ice_lse_lock);
	ice->ice_lse_state &= ~ICE_LSE_STATE_ENABLE;
	mutex_exit(&ice->ice_lse_lock);

	if (!ice_link_status_update(ice)) {
		ice_error(ice, "failed to disable link status event updates");
	}

	ice_intr_hw_fini(ice);
}

static int
ice_m_start(void *arg)
{
	ice_t *ice = arg;
	uint16_t mask;

	if (!ice_intr_hw_init(ice)) {
		return (EIO);
	}

	/*
	 * Mask off link status events. While we don't want to mask the
	 * following events per se, currently firmware will generate an infinite
	 * loop of link status events when an SFP is plugged into the adapter,
	 * but not at the other end.
	 */
	mask = ICE_CQ_SET_EVENT_MASK_LINK_FAULT |
	    ICE_CQ_SET_EVENT_MASK_SIGNAL_DETECT;

	if (!ice_cmd_set_event_mask(ice, mask)) {
		ice_error(ice, "failed to set LSE event mask");
		goto err;
	}

	mutex_enter(&ice->ice_lse_lock);
	ice->ice_lse_state |= ICE_LSE_STATE_ENABLE;
	mutex_exit(&ice->ice_lse_lock);

	if (!ice_link_status_update(ice)) {
		ice_error(ice, "failed to enable link status updates");

		mutex_enter(&ice->ice_lse_lock);
		ice->ice_lse_state &= ~ICE_LSE_STATE_ENABLE;
		mutex_exit(&ice->ice_lse_lock);
		goto err;
	}

	if (!ice_cmd_setup_link(ice, B_TRUE)) {
		ice_error(ice, "failed to start link");

		mutex_enter(&ice->ice_lse_lock);
		ice->ice_lse_state &= ~ICE_LSE_STATE_ENABLE;
		mutex_exit(&ice->ice_lse_lock);

		(void) ice_link_status_update(ice);
	}

	return (0);
err:
	ice_intr_hw_fini(ice);
	return (EIO);
}

static int
ice_m_setpromisc(void *arg, boolean_t enable)
{
	return (0);
}

static int
ice_m_multicast(void *arg, boolean_t add, const uint8_t *mac)
{
	return (0);
}

static boolean_t
ice_m_getcapab(void *arg, mac_capab_t capab, void *cap_data)
{
	ice_t *ice = arg;
	mac_capab_rings_t *cap_rings;

	switch (capab) {
	case MAC_CAPAB_RINGS:
		cap_rings = cap_data;
		cap_rings->mr_group_type = MAC_GROUP_TYPE_STATIC;
		switch (cap_rings->mr_type) {
		case MAC_RING_TYPE_TX:
			cap_rings->mr_gnum = 0;
			cap_rings->mr_rnum = ice->ice_num_txq;
			cap_rings->mr_rget = ice_fill_tx_ring;
			cap_rings->mr_gget = NULL;
			cap_rings->mr_gaddring = NULL;
			cap_rings->mr_gremring = NULL;
			break;
		case MAC_RING_TYPE_RX:
			cap_rings->mr_rnum = ice->ice_num_rxq_per_vsi;
			cap_rings->mr_rget = ice_fill_rx_ring;
			cap_rings->mr_gnum = ice->ice_num_vsis;
			cap_rings->mr_gget = ice_fill_rx_group;
			cap_rings->mr_gaddring = NULL;
			cap_rings->mr_gremring = NULL;
			break;
		default:
			return (B_FALSE);
		}

		break;
	case MAC_CAPAB_HCKSUM:
	case MAC_CAPAB_LSO:
	case MAC_CAPAB_LED:
	case MAC_CAPAB_TRANSCEIVER:
		return (B_FALSE);
	default:
		return (B_FALSE);
	}

	return (B_TRUE);
}

static int
ice_m_setprop(void *arg, const char *pr_name, mac_prop_id_t pr_num,
    uint_t pr_valsize, const void *pr_val)
{
	return (ENOTSUP);
}

static int
ice_m_getprop(void *arg, const char *pr_name, mac_prop_id_t pr_num,
    uint_t pr_valsize, void *pr_val)
{
	ice_t *ice = arg;
	int ret = 0;
	uint64_t speed;
	uint8_t *u8;

	mutex_enter(&ice->ice_lse_lock);

	switch (pr_num) {
	case MAC_PROP_DUPLEX:
		if (pr_valsize < sizeof (link_duplex_t)) {
			ret = EOVERFLOW;
			break;
		}
		bcopy(&ice->ice_link_cur_duplex, pr_val,
		    sizeof (link_duplex_t));
		break;
	case MAC_PROP_SPEED:
		if (pr_valsize < sizeof (uint64_t)) {
			ret = EOVERFLOW;
			break;
		}
		speed = ice->ice_link_cur_speed * 1000000ULL;
		bcopy(&speed, pr_val, sizeof (speed));
		break;
	case MAC_PROP_STATUS:
		if (pr_valsize < sizeof (link_state_t)) {
			ret = EOVERFLOW;
			break;
		}

		bcopy(&ice->ice_link_cur_state, pr_val,
		    sizeof (link_state_t));
		break;
	case MAC_PROP_AUTONEG:
		if (pr_valsize < sizeof (uint8_t)) {
			ret = EOVERFLOW;
			break;
		}

		/* XXX Confirm that there is no control for autoneg */
		u8 = pr_val;
		*u8 = 1;
		break;
	case MAC_PROP_FLOWCTRL:
		if (pr_valsize < sizeof (link_flowctrl_t)) {
			ret = EOVERFLOW;
			break;
		}

		bcopy(&ice->ice_link_cur_fctl, pr_val,
		    sizeof (link_flowctrl_t));
		break;
	case MAC_PROP_MTU:
		ret = ENOTSUP;	
		/* XXX Come back to me */
		break;

	case MAC_PROP_ADV_100FDX_CAP:
	case MAC_PROP_EN_100FDX_CAP:
		break;

	case MAC_PROP_ADV_1000FDX_CAP:
	case MAC_PROP_EN_1000FDX_CAP:

	case MAC_PROP_ADV_2500FDX_CAP:
	case MAC_PROP_EN_2500FDX_CAP:

	case MAC_PROP_ADV_5000FDX_CAP:
	case MAC_PROP_EN_5000FDX_CAP:

	case MAC_PROP_ADV_10GFDX_CAP:
	case MAC_PROP_EN_10GFDX_CAP:

	case MAC_PROP_ADV_25GFDX_CAP:
	case MAC_PROP_EN_25GFDX_CAP:

	case MAC_PROP_ADV_40GFDX_CAP:
	case MAC_PROP_EN_40GFDX_CAP:

	case MAC_PROP_ADV_50GFDX_CAP:
	case MAC_PROP_EN_50GFDX_CAP:

	case MAC_PROP_ADV_100GFDX_CAP:
	case MAC_PROP_EN_100GFDX_CAP:


	default:
		ret = ENOTSUP;
	}

	mutex_exit(&ice->ice_lse_lock);

	return (ret);
}

static void
ice_m_propinfo(void *arg, const char *pr_name, mac_prop_id_t pr_num,
    mac_prop_info_handle_t hdl)
{
	return;
}

static mac_callbacks_t ice_m_callbacks = {
	.mc_callbacks = MC_GETCAPAB | MC_GETPROP | MC_SETPROP | MC_PROPINFO,
	.mc_getstat = ice_m_stat,
	.mc_start = ice_m_start,
	.mc_stop = ice_m_stop,
	.mc_setpromisc = ice_m_setpromisc,
	.mc_multicst = ice_m_multicast,
	.mc_getcapab = ice_m_getcapab,
	.mc_setprop = ice_m_setprop,
	.mc_getprop = ice_m_getprop,
	.mc_propinfo = ice_m_propinfo
};

void
ice_mac_unregister(ice_t *ice)
{
	int ret;

	/*
	 * We're going away, there's not much else we can do at this point if
	 * this fails.
	 */
	ret = mac_unregister(ice->ice_mac_hdl);
	if (ret != 0) {
		ice_error(ice, "failed to unregister from MAC: %d", ret);
	}
}

boolean_t
ice_mac_register(ice_t *ice)
{
	int ret;
	mac_register_t *regp;

	if ((regp = mac_alloc(MAC_VERSION)) == NULL) {
		ice_error(ice, "failed to allocate MAC handle");
		return (B_FALSE);
	}

	regp->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
	regp->m_driver = ice;
	regp->m_dip = ice->ice_dip;
	regp->m_instance = 0;
	regp->m_src_addr = ice->ice_mac;
	regp->m_dst_addr = NULL;
	regp->m_callbacks = &ice_m_callbacks;
	regp->m_min_sdu = 0;
	regp->m_max_sdu = ice->ice_max_mtu;
	regp->m_pdata = NULL;
	regp->m_pdata_size = 0;
	regp->m_priv_props = NULL;
	regp->m_margin = VLAN_TAGSZ;
	regp->m_v12n = MAC_VIRT_LEVEL1;

	if ((ret = mac_register(regp, &ice->ice_mac_hdl)) != 0) {
		ice_error(ice, "failed to register ICE with MAC: %d", ret);
	}

	mac_free(regp);
	return (ret == 0);
}
