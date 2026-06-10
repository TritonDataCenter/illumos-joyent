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
 * about in the GLDv3.
 *
 * XXX: The latest revisison (2.8) seems to omit the 400GB entries --
 * should we do that as well?
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
	{ ICE_PHY_200GBASE_CR4_PAM4, ICE_PHY_200G_AUI8,
	    MAC_PROP_ADV_200GFDX_CAP, MAC_PROP_EN_200GFDX_CAP },
	{ ICE_PHY_400G_BASE_FR8, ICE_PHY_400G_AUI8,
	    MAC_PROP_ADV_400GFDX_CAP, MAC_PROP_EN_400GFDX_CAP },
};

static ice_vsi_mac_t *
ice_find_mac(list_t *l, const uint8_t *addr)
{
	ice_vsi_mac_t *mac = NULL;

	for (mac = list_head(l); mac != NULL; mac = list_next(l, mac)) {
		if (bcmp(mac->ivm_mac, addr, ETHERADDRL) == 0) {
			return (mac);
		}
	}

	return (NULL);
}

static ice_vsi_mac_t *
ice_vsi_find_mac(ice_vsi_t *vsi, const uint8_t *addr)
{
	ASSERT(MUTEX_HELD(&vsi->ivsi_lock));
	return (ice_find_mac(&vsi->ivsi_macs, addr));
}

static int
ice_group_add_mac(void *arg, const uint8_t *mac_addr)
{
	ice_vsi_t	*vsi = (ice_vsi_t *)arg;
	ice_t		*ice = vsi->ivsi_ice;
	ice_vsi_mac_t	*mac;
	int		ret = 0;

	mac = kmem_zalloc(sizeof (*mac), KM_SLEEP);
	bcopy(mac_addr, mac->ivm_mac, ETHERADDRL);

	mutex_enter(&vsi->ivsi_lock);
	if (ice_vsi_find_mac(vsi, mac_addr) != NULL) {
		/*
		 * mac_filter(9e) is a bit ambiguous here -- the mac is
		 * already there, so returning EEXIST seems reasonable,
		 * but it also has been added (just not by this call),
		 * so we return 0 to indicate that it has been added.
		 *
		 * XXX: might a dtrace probe or kstat be of use?
		 */
		goto fail;
	}

	ret = ice_add_mac(ice, vsi->ivsi_id, mac_addr, &mac->ivm_idx);
	if (ret != 0) {
		goto fail;
	}

	list_insert_tail(&vsi->ivsi_macs, mac);
	mutex_exit(&vsi->ivsi_lock);
	return (0);

fail:
	mutex_exit(&vsi->ivsi_lock);
	kmem_free(mac, sizeof (*mac));
	return (ret);
}

static int
ice_group_remove_mac(void *arg, const uint8_t *mac_addr)
{
	ice_vsi_t	*vsi = (ice_vsi_t *)arg;
	ice_t		*ice = vsi->ivsi_ice;
	ice_vsi_mac_t	*mac = NULL;
	int		ret = 0;

	mutex_enter(&vsi->ivsi_lock);
	mac = ice_vsi_find_mac(vsi, mac_addr);
	if (mac == NULL) {
		mutex_exit(&vsi->ivsi_lock);
		return (ENOENT);
	}

	ret = ice_remove_rule(ice, mac->ivm_idx);
	if (ret == 0) {
		list_remove(&vsi->ivsi_macs, mac);
	}

	mutex_exit(&vsi->ivsi_lock);
	return (0);
}

static void
ice_fill_rx_ring(void *arg, mac_ring_type_t rtype, const int group_index,
    const int ring_index, mac_ring_info_t *infop, mac_ring_handle_t rh)
{
	ice_t		*ice = arg;
	ice_rx_ring_t	*rxr;

	ASSERT3S(group_index, ==, 0);
	ASSERT3S(ring_index, <, ice->ice_num_rxq_per_vsi);

	rxr = &ice->ice_rxr[ring_index];
	rxr->irxr_macrxring = rh;

	infop->mri_driver = (mac_ring_driver_t)rxr;
	infop->mri_start = ice_ring_rx_start;
	infop->mri_stop = ice_ring_rx_stop;
	infop->mri_poll = ice_ring_rx_poll;
	infop->mri_stat = ice_ring_rx_stat;
	infop->mri_intr.mi_handle = (mac_intr_handle_t)rxr;
	infop->mri_intr.mi_enable = ice_ring_rx_intr_enable;
	infop->mri_intr.mi_disable = ice_ring_rx_intr_disable;
}

static void
ice_fill_tx_ring(void *arg, mac_ring_type_t rtype, const int group_index,
    const int ring_index, mac_ring_info_t *infop, mac_ring_handle_t rh)
{
	ice_t		*ice = arg;
	ice_tx_ring_t	*txr;

	ASSERT3S(group_index, ==, 0);
	ASSERT3S(ring_index, <, ice->ice_num_txq);

	txr = &ice->ice_txr[ring_index];
	txr->itxr_mactxring = rh;

	infop->mri_driver = (mac_ring_driver_t)txr;
	infop->mri_start = ice_ring_tx_start;
	infop->mri_stop = ice_ring_tx_stop;
	infop->mri_tx = ice_ring_tx;
	infop->mri_stat = ice_ring_tx_stat;
	infop->mri_intr.mi_handle = (mac_intr_handle_t)txr;
	infop->mri_intr.mi_enable = ice_ring_tx_intr_enable;
	infop->mri_intr.mi_disable = ice_ring_tx_intr_disable;
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

	ice_tx_stop(ice);
	ice_rx_stop(ice);
	ice_buf_fini(ice);
}

static int
ice_m_start(void *arg)
{
	ice_t *ice = arg;
	uint16_t mask;

	ice_buf_init(ice);

	ice_rx_start(ice);
	ice_tx_start(ice);

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

#define	RULE_DATA_SZ	16
#define	RULE_SZ		(sizeof (ice_sw_rule_t) + RULE_DATA_SZ)
CTASSERT(RULE_SZ % sizeof (uint64_t) == 0);

static void
ice_promisc_init_rule(ice_sw_rule_t *rule, uint16_t vsi_id, uint16_t src,
    bool tx, bool mcast)
{
	ice_sw_lookup_t *lk = &rule->iswr_data.iswr_lookup;

	rule->iswr_type = tx ?
		LE_16(ICE_SW_RULE_T_LOOKUP_TX) :
		LE_16(ICE_SW_RULE_T_LOOKUP_RX);

	lk->iswl_rid = LE_16(ICE_SW_RECIPE_PROMISC);
	lk->iswl_source = LE_16(src);
	lk->iswl_action = LE_32(
		ICE_SW_RULE_ACT_T_LOGICAL_PORT_FWD |
		ICE_SW_RULE_ACT_LAN_EN |
		(uint32_t)vsi_id << ICE_SW_RULE_ACT_VSI_SHIFT |
		ICE_SW_RULE_ACT_VSI_VALID);
	lk->iswl_header_len = RULE_DATA_SZ;

	lk->iswl_data[0] = 0x2;
	lk->iswl_data[6] = 0x2;

	if (mcast)
		lk->iswl_data[0] |= 0x01;
}

static int
ice_m_setpromisc(void *arg, boolean_t enable)
{
	ice_t		*ice = arg;
	ice_vsi_t	*vsi;
	union {
		ice_sw_rule_t	rule;
		uint64_t	data[RULE_SZ/sizeof (uint64_t)];
	} u[4];
	ice_sw_rule_t	*r_rx = &u[0].rule;
	ice_sw_rule_t	*r_mrx = &u[1].rule;
	ice_sw_rule_t	*r_tx = &u[2].rule;
	ice_sw_rule_t	*r_mtx = &u[3].rule;

	/*
	 * Per mac_capab_rings(9E), broadcast, multicast, and
	 * promiscuous mode should only be enabled on the first group
	 * which is always the first VSI
	 */
	vsi = list_head(&ice->ice_vsi);

	bzero(u, sizeof (u));

	if (!enable) {

		(void) ice_remove_rule(ice, ice->ice_promisc_rid_tx);
		(void) ice_remove_rule(ice, ice->ice_promisc_m_rid_tx);
		(void) ice_remove_rule(ice, ice->ice_promisc_rid_rx);
		(void) ice_remove_rule(ice, ice->ice_promisc_m_rid_rx);

		/*
		 * Since all of these rule ids have to be distinct, we
		 * set them all to 0 to indicate that they're not set
		 * (there doesn't appear to be any sort of 'invalid'
		 * sentinel value that could be used).
		 */
		ice->ice_promisc_rid_tx = ice->ice_promisc_m_rid_tx =
		    ice->ice_promisc_rid_rx = ice->ice_promisc_m_rid_rx = 0;

		return (0);
	}

	ice_promisc_init_rule(r_rx, vsi->ivsi_id, ice->ice_port_id, false,
	    false);
	ice_promisc_init_rule(r_mrx, vsi->ivsi_id, ice->ice_port_id, false,
	    true);
	ice_promisc_init_rule(r_tx, vsi->ivsi_id, vsi->ivsi_id, true, false);
	ice_promisc_init_rule(r_mtx, vsi->ivsi_id, vsi->ivsi_id, true, true);

	if (!ice_cmd_switch_rules(ice, ICE_CQ_OP_ADD_SW_RULES, 4, r_rx)) {
		return (EIO);
	}

	uint16_t rids[4] = { 0 };
	uint_t n_succeed = 0;

	for (uint_t i = 0; i < 4; i++) {
		if (u[i].rule.iswr_status == 0) {
			rids[n_succeed++] =
			    u[i].rule.iswr_data.iswr_lookup.iswl_index;
		}
	}

	if (n_succeed == 0) {
		/* Failed to add any rule, just return failure */
		return (EIO);
	}

	if (n_succeed != 4) {
		ice_sw_rule_t	*r = &u[0].rule;

		/*
		 * Only partially succeeded, so need to delete the rules that
		 * succeeded so we can back out.
		 */
		bzero(&u, sizeof (u));
		for (uint_t i = 0; i < n_succeed; i++) {
			r[i].iswr_data.iswr_lookup.iswl_index = rids[i];
		}

		(void) ice_cmd_switch_rules(ice, ICE_CQ_OP_REMOVE_SW_RULES,
		    n_succeed, &u[0].rule);

		return (EIO);
	}

	ice->ice_promisc_rid_tx = r_tx->iswr_data.iswr_lookup.iswl_index;
	ice->ice_promisc_m_rid_tx = r_mtx->iswr_data.iswr_lookup.iswl_index;
	ice->ice_promisc_rid_rx = r_rx->iswr_data.iswr_lookup.iswl_index;
	ice->ice_promisc_m_rid_rx = r_rx->iswr_data.iswr_lookup.iswl_index;

	return (0);
}

static int
ice_m_multicast(void *arg, boolean_t add, const uint8_t *addr)
{
	ice_t		*ice = arg;
	ice_vsi_t	*vsi;
	ice_vsi_mac_t	*mac = NULL;
	int		ret = 0;

	/*
	 * As noted elsewhere, multicast (as well as promiscuous) mode
	 * stuff always happens on the first ring group (i.e. the first
	 * VSI).
	 *
	 * This also means we use the first VSI's lock for controlling
	 * access to the list of multicast addresses, despite the list being
	 * held on the ice_t (mostly since we use the VSI lock for the MACs
	 * on that VSI).
	 *
	 * XXX: An alternative might be to just have one list of all
	 * MAC addresses (unicast and multicast) per VSI and just assert
	 * that we only have multicast addresses on the first VSI.
	 */
	vsi = list_head(&ice->ice_vsi);

	mutex_enter(&vsi->ivsi_lock);

	mac = ice_find_mac(&ice->ice_mc_macs, addr);
	if (!add) {
		if (mac == NULL) {
			mutex_exit(&vsi->ivsi_lock);
			return (ENOENT);
		}

		ret = ice_remove_rule(ice, mac->ivm_idx);
		if (ret != 0) {
			list_remove(&ice->ice_mc_macs, mac);
			kmem_free(mac, sizeof (*mac));
		}
	} else {
		if (mac != NULL) {
			mutex_exit(&vsi->ivsi_lock);
			/*
			 * Similarly to adding a unicast MAC to a ring group,
			 * it's unclear since the MAC is already there if we
			 * should return something like EEXIST, or just
			 * return success, since both seem like they could
			 * be reasonable. For now at least, we'll just
			 * return success.
			 */
			return (0);
		}

		mac = kmem_zalloc(sizeof (*mac), KM_SLEEP);
		bcopy(addr, mac->ivm_mac, ETHERADDRL);

		ret = ice_add_mac(ice, vsi->ivsi_id, addr, &mac->ivm_idx);
		if (ret != 0) {
			list_insert_tail(&ice->ice_mc_macs, mac);
		}
	}

	mutex_exit(&vsi->ivsi_lock);
	return (ret);
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

	/* TODO MAC_PROP_{ADV,EN}_FEC_CAP */

	/*
	 * There doesn't appear to be a way to manage or manipulate
	 * autoneg for individual speeds, so for now at least we report
	 * not supported
	 */
	case MAC_PROP_ADV_100FDX_CAP:
	case MAC_PROP_EN_100FDX_CAP:

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
