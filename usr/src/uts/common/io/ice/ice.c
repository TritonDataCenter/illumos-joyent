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
 * Intel 100 GbE Ethernet Driver
 */

#include "ice.h"

void
ice_error(ice_t *ice, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (ice != NULL && ice->ice_dip != NULL) {
		vdev_err(ice->ice_dip, CE_WARN, fmt, ap);
	} else {
		vcmn_err(CE_WARN, fmt, ap);
	}
	va_end(ap);
}

int
ice_regs_check(ice_t *ice)
{
	ddi_fm_error_t de;

	if (!DDI_FM_ACC_ERR_CAP(ice->ice_fm_caps)) {
		return (DDI_FM_OK);
	}

	ddi_fm_acc_err_get(ice->ice_reg_hdl, &de, DDI_FME_VERSION);
	ddi_fm_acc_err_clear(ice->ice_reg_hdl, DDI_FME_VERSION);
	return (de.fme_status);
}

uint32_t
ice_reg_read(ice_t *ice, uintptr_t reg)
{
	return (ddi_get32(ice->ice_reg_hdl, (uint32_t *)(ice->ice_reg_base +
	    reg)));
}

void
ice_reg_write(ice_t *ice, uintptr_t reg, uint32_t val)
{
	ddi_put32(ice->ice_reg_hdl, (uint32_t *)(ice->ice_reg_base +
	    reg), val);
}

static ice_capability_t *
ice_capability_find(ice_t *ice, boolean_t device, ice_cap_id_t capid,
    uint_t major)
{
	uint_t i, max;
	ice_capability_t *cap;

	if (device) {
		cap = ice->ice_dev_caps;
		max = ice->ice_ndev_caps;
	} else {
		cap = ice->ice_func_caps;
		max = ice->ice_nfunc_caps;
	}

	for (i = 0; i < max; i++) {
		if (cap[i].icap_cap == capid) {
			if (cap[i].icap_major != major) {
				ice_error(ice, "found capability 0x%x, but it "
				    "has an unsupported major version 0x%x, "
				    "expected 0x%x", capid, cap[i].icap_cap,
				    major);
				continue;
			}
			return (&cap[i]);
		}
	}

	return (NULL);
}

static void
ice_fm_init(ice_t *ice)
{
	/*
	 * XXX At the moment, we don't actually do anything with FMA, but having
	 * this here and assuming we do in the rest of the driver will help us
	 * get going.
	 */
	ice->ice_fm_caps = DDI_FM_NOT_CAPABLE;
}

static boolean_t
ice_regs_map(ice_t *ice)
{
	int ret;

	if (ddi_dev_regsize(ice->ice_dip, ICE_REG_NUMBER, &ice->ice_reg_size) !=
	    DDI_SUCCESS) {
		ice_error(ice, "failed to get register set %d size",
		    ICE_REG_NUMBER);
		return (B_FALSE);
	}

	bzero(&ice->ice_reg_attr, sizeof (ddi_device_acc_attr_t));
	ice->ice_reg_attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	ice->ice_reg_attr.devacc_attr_endian_flags = DDI_STRUCTURE_LE_ACC;
	ice->ice_reg_attr.devacc_attr_version = DDI_STRICTORDER_ACC;
	if (DDI_FM_ACC_ERR_CAP(ice->ice_fm_caps)) {
		ice->ice_reg_attr.devacc_attr_access = DDI_FLAGERR_ACC;
	} else {
		ice->ice_reg_attr.devacc_attr_access = DDI_DEFAULT_ACC;
	}

	if ((ret = ddi_regs_map_setup(ice->ice_dip, ICE_REG_NUMBER,
	    &ice->ice_reg_base, 0, ice->ice_reg_size, &ice->ice_reg_attr,
	    &ice->ice_reg_hdl)) != DDI_SUCCESS) {
		ice_error(ice, "failed to map register set %d: %d",
		    ICE_REG_NUMBER, ret);
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * Identify the hardware in question. This looks at PCI configuration
 * information, saves that information, and potentially identifies information
 * about the device as a result.
 *
 * Right now there is only one primary MAC that this driver supports. We save
 * PCI information for debugging. If we support additional MACs in the future,
 * they should be added here.
 */
static void
ice_identify(ice_t *ice)
{
	uint32_t reg;

	ice->ice_pci_vid = pci_config_get16(ice->ice_pci_hdl, PCI_CONF_VENID);
	ice->ice_pci_did = pci_config_get16(ice->ice_pci_hdl, PCI_CONF_DEVID);
	ice->ice_pci_rev = pci_config_get8(ice->ice_pci_hdl, PCI_CONF_REVID);
	ice->ice_pci_svid = pci_config_get16(ice->ice_pci_hdl,
	    PCI_CONF_SUBVENID);
	ice->ice_pci_sdid = pci_config_get16(ice->ice_pci_hdl,
	    PCI_CONF_SUBSYSID);

	/*
	 * Determine the maximum speed of the device and determine anything that
	 * we need to derive from that.
	 */
	reg = ice_reg_read(ice, ICE_REG_GL_UFUSE_SOC);
	ice->ice_soc = reg;
	switch (ICE_REG_GL_UFUSE_SOC_BANDWIDTH(reg)) {
	case ICE_REG_GL_UFUSE_SOC_25_GBE:
		ice->ice_itr_gran = ICE_ITR_GRAN_25GBE;
		break;
	case ICE_REG_GL_UFUSE_SOC_50_GBE:
	case ICE_REG_GL_UFUSE_SOC_100_GBE:
	case ICE_REG_GL_UFUSE_SOC_200_GBE:
		ice->ice_itr_gran = ICE_ITR_GRAN;
		break;
	}

	reg = ice_reg_read(ice, ICE_REG_PF_FUNC_RID);
	ice->ice_pci_bus = ICE_REG_PF_FUNC_RID_BUS(reg);
	ice->ice_pci_dev = ICE_REG_PF_FUNC_RID_DEV(reg);
	ice->ice_pci_func = ICE_REG_PF_FUNC_RID_FUNC(reg);
	ice->ice_pf_id = ice->ice_pci_func;
}


/*
 * Initialize any properties that we want to support via a driver.conf option.
 */
static void
ice_properties_init(ice_t *ice)
{
	/* XXX Come here and handle things like mtu, etc. */
	ice->ice_mtu = ICE_MTU_DEFAULT;
	ice->ice_itr_rx = ICE_ITR_RX_DEFAULT;
	ice->ice_itr_tx = ICE_ITR_TX_DEFAULT;
	ice->ice_itr_other = ICE_ITR_OTHER_DEFAULT;
}

static boolean_t
ice_firmware_check(ice_t *ice)
{
	if (!ice_cmd_get_version(ice, &ice->ice_fwinfo)) {
		ice_error(ice, "failed to get firmware version "
		    "information");
		return (B_FALSE);
	}

	dev_err(ice->ice_dip, CE_NOTE, "firmware: %u.%u.%u",
	    ice->ice_fwinfo.ifi_fw_major, ice->ice_fwinfo.ifi_fw_minor,
	    ice->ice_fwinfo.ifi_fw_patch);

	/* XXX Check if both are version 1? */

	return (B_TRUE);
}

static boolean_t
ice_caps_fetch(ice_t *ice)
{
	ice_capability_t *cap;

	if (!ice_cmd_get_caps(ice, B_TRUE, &ice->ice_ndev_caps,
	    &ice->ice_dev_caps)) {
		ice_error(ice, "failed to get device capabilities");
		return (B_FALSE);
	}

	if (!ice_cmd_get_caps(ice, B_FALSE, &ice->ice_nfunc_caps,
	    &ice->ice_func_caps)) {
		ice_error(ice, "failed to get function capabilities");
		goto err;
	}

	/*
	 * Go through and find the capabilities that we expect and need to
	 * progress.
	 */
	if ((cap = ice_capability_find(ice, B_FALSE, ICE_CAP_VSI,
	    ICE_CAP_MAJOR_VSI)) == NULL) {
		ice_error(ice, "failed to find function VSI capability");
		goto err;
	}
	ice->ice_max_vsis = cap->icap_number;

	if ((cap = ice_capability_find(ice, B_FALSE, ICE_CAP_MAX_MTU,
	    ICE_CAP_MAJOR_MTU)) == NULL) {
		ice_error(ice, "failed to find function MTU capability");
		goto err;
	}
	ice->ice_max_mtu = cap->icap_number;

	if ((cap = ice_capability_find(ice, B_FALSE, ICE_CAP_RX_QUEUES,
	    ICE_CAP_MAJOR_RXQ)) == NULL) {
		ice_error(ice, "failed to find RX Queues capability");
		goto err;
	}
	ice->ice_max_rxq = cap->icap_number;
	ice->ice_first_rxq = cap->icap_physid;

	if ((cap = ice_capability_find(ice, B_FALSE, ICE_CAP_TX_QUEUES,
	    ICE_CAP_MAJOR_TXQ)) == NULL) {
		ice_error(ice, "failed to find TX Queues capability");
		goto err;
	}
	ice->ice_max_txq = cap->icap_number;
	ice->ice_first_txq = cap->icap_physid;

	if ((cap = ice_capability_find(ice, B_FALSE, ICE_CAP_MSI_X,
	    ICE_CAP_MAJOR_MSI_X)) == NULL) {
		ice_error(ice, "failed to find MSI-X capability");
		goto err;
	}
	ice->ice_max_msix = cap->icap_number;
	ice->ice_first_msix = cap->icap_physid;

	return (B_TRUE);

err:
	if (ice->ice_dev_caps != NULL) {
		kmem_free(ice->ice_dev_caps, ice->ice_ndev_caps *
		    sizeof (ice_capability_t));
		ice->ice_ndev_caps = 0;
		ice->ice_dev_caps = NULL;
	}

	if (ice->ice_func_caps != NULL) {
		kmem_free(ice->ice_func_caps, ice->ice_nfunc_caps *
		    sizeof (ice_capability_t));
		ice->ice_nfunc_caps = 0;
		ice->ice_func_caps = NULL;
	}

	return (B_FALSE);
}

static void
ice_intr_ddi_free(ice_t *ice)
{
	int i;

	for (i = 0; i < ice->ice_nintrs; i++) {
		int ret = ddi_intr_free(ice->ice_intr_handles[i]);
		if (ret != DDI_SUCCESS) {
			ice_error(ice, "failed to free interrupt %d: %d",
			    i, ret);
		}
	}

	if (ice->ice_intr_handles != NULL) {
		kmem_free(ice->ice_intr_handles, ice->ice_intr_handle_size);
		ice->ice_intr_handle_size = 0;
		ice->ice_intr_handles = NULL;
	}
}

static boolean_t
ice_intr_alloc_type(ice_t *ice, int type)
{
	int ret, req, min, count, act;

	switch (type) {
	case DDI_INTR_TYPE_FIXED:
	case DDI_INTR_TYPE_MSI:
		req = 1;
		min = 1;
		break;
	case DDI_INTR_TYPE_MSIX:
		min = 2;
		req = ice->ice_max_msix;
		break;
	default:
		ice_error(ice, "invalid interrupt type specified: %d", type);
		return (B_FALSE);
	}

	if ((ret = ddi_intr_get_nintrs(ice->ice_dip, type, &count)) !=
	    DDI_SUCCESS) {
		ice_error(ice, "failed to get number of interrupts of type %d: "
		    "%d", type, ret);
		return (B_FALSE);
	} else if (count < min) {
		ice_error(ice, "number of interrupts of type %d is %d, but "
		    "minimum number for the driver is %d", type, count, min);
		return (B_FALSE);
	}

	if ((ret = ddi_intr_get_navail(ice->ice_dip, type, &count)) !=
	    DDI_SUCCESS) {
		ice_error(ice, "failed to get available interrupts of type %d: "
		    "%d", type, ret);
		return (B_FALSE);
	} else if (count < min) {
		ice_error(ice, "available interrupts of type %d is %d, but "
		    "minimum number for the driver is %d", type, count, min);
		return (B_FALSE);
	}

	/*
	 * Limit the number of interrupts we request based on what's available.
	 */
	req = MIN(req, count);
	ice->ice_intr_handle_size = req * sizeof (ddi_intr_handle_t);
	ice->ice_intr_handles = kmem_alloc(ice->ice_intr_handle_size, KM_SLEEP);
	if ((ret = ddi_intr_alloc(ice->ice_dip, ice->ice_intr_handles, type, 0,
	    req, &act, DDI_INTR_ALLOC_NORMAL)) != DDI_SUCCESS) {
		ice_error(ice, "failed to allocate %d interrupts of type %d: "
		    "%d", req, type, ret);
		goto err;
	}

	ice->ice_intr_type = type;
	ice->ice_nintrs = act;

	if (act < min) {
		ice_error(ice, "allocated %d interrupts of type %d, but "
		    "required %d at a minimum", act, type, min);
		goto err;
	}

	if ((ret = ddi_intr_get_cap(ice->ice_intr_handles[0],
	    &ice->ice_intr_cap)) != DDI_SUCCESS) {
		ice_error(ice, "failed to get interrupt capability, type %d, "
		    "error: %d", type, ret);
		goto err;
	}

	if ((ret = ddi_intr_get_pri(ice->ice_intr_handles[0],
	    &ice->ice_intr_pri)) != DDI_SUCCESS) {
		ice_error(ice, "failed to get interrupt priority, type %d, "
		    "error: %d", type, ret);
		goto err;
	}

	return (B_TRUE);

err:
	ice_intr_ddi_free(ice);
	return (B_FALSE);
}

static boolean_t
ice_intr_ddi_alloc(ice_t *ice)
{
	int ret, types;

	if ((ret = ddi_intr_get_supported_types(ice->ice_dip, &types)) !=
	    DDI_SUCCESS) {
		ice_error(ice, "failed to get interrupt types: %d", ret);
		return (B_FALSE);
	}

	if ((types & DDI_INTR_TYPE_MSIX) != 0) {
		if (ice_intr_alloc_type(ice, DDI_INTR_TYPE_MSIX)) {
			return (B_TRUE);
		}
	}

	if ((types & DDI_INTR_TYPE_MSI) != 0) {
		if (ice_intr_alloc_type(ice, DDI_INTR_TYPE_MSI)) {
			return (B_TRUE);
		}
	}

	if ((types & DDI_INTR_TYPE_FIXED) != 0) {
		if (ice_intr_alloc_type(ice, DDI_INTR_TYPE_FIXED)) {
			return (B_TRUE);
		}
	}

	ice_error(ice, "failed to allocate interrupts for device");
	return (B_FALSE);
}

/*
 * Here, we need to go through our number of interrupts and determine the number
 * of VSIs that we're going to actually create and manage along with the number
 * of queue pairs for each. Note we don't do any allocations yet for all this.
 * XXX This is totally arbitrary right now.
 */
static boolean_t
ice_calculate_groups(ice_t *ice)
{
	if (ice->ice_intr_type == DDI_INTR_TYPE_MSIX) {
		/* XXX These are bs, but will help us get off the ground */
		ice->ice_num_vsis = 1;
		ice->ice_num_rxq_per_vsi = ice->ice_nintrs;
		ice->ice_num_txq = ice->ice_nintrs;
	} else {
		ice->ice_num_vsis = 1;
		ice->ice_num_rxq_per_vsi = 1;
		ice->ice_num_txq = 1;
	}

	return (B_TRUE);
}

static void
ice_intr_rem_ddi_handles(ice_t *ice)
{
	int i;

	for (i = 0; i < ice->ice_nintrs; i++) {
		int ret;

		if ((ret = ddi_intr_remove_handler(ice->ice_intr_handles[i])) !=
		    DDI_SUCCESS) {
			ice_error(ice, "failed to remove interrupt type %u "
			    "vector %d: %u", ice->ice_intr_type, i, ret);
		}
	}
}

static boolean_t
ice_intr_add_ddi_handles(ice_t *ice)
{
	int i;
	ddi_intr_handler_t *func;

	switch (ice->ice_intr_type) {
	case DDI_INTR_TYPE_MSIX:
		func = ice_intr_msix;
		break;
	case DDI_INTR_TYPE_MSI:
		func = ice_intr_msi;
		break;
	case DDI_INTR_TYPE_FIXED:
		func = ice_intr_intx;
		break;
	default:
		ice_error(ice, "encountered malformed ice interrupt type: %u",
		    ice->ice_intr_type);
		return (B_FALSE);
	}

	for (i = 0; i < ice->ice_nintrs; i++) {
		int ret;
		caddr_t vector = (void *)(uintptr_t)i;
		if ((ret = ddi_intr_add_handler(ice->ice_intr_handles[i],
		    func, ice, vector)) != DDI_SUCCESS) {
			ice_error(ice, "failed to add interrupt handler "
			    "type %u, vector %u", ret, vector);

			while (i > 0) {
				i--;
				(void) ddi_intr_remove_handler(
				    ice->ice_intr_handles[i]);
			}
			return (B_FALSE);
		}
	}

	return (B_TRUE);
}

static boolean_t
ice_intr_ddi_disable(ice_t *ice)
{
	int ret;
	boolean_t rval = B_TRUE;

	if (ice->ice_intr_cap & DDI_INTR_FLAG_BLOCK) {
		if ((ret = ddi_intr_block_disable(ice->ice_intr_handles,
		    ice->ice_nintrs)) != DDI_SUCCESS) {
			ice_error(ice, "failed to block disable interrupts: %d",
			    ret);
			rval = B_FALSE;
		}
	} else {
		int i;
		for (i = 0; i < ice->ice_nintrs; i++) {
			ret = ddi_intr_disable(ice->ice_intr_handles[i]);
			if (ret != DDI_SUCCESS) {
				ice_error(ice, "failed to disable interrupt "
				    "%d: %d", i, ret);
				rval = B_FALSE;
			}
		}
	}

	return (rval);
}

static boolean_t
ice_intr_ddi_enable(ice_t *ice)
{
	int ret;

	if (ice->ice_intr_cap & DDI_INTR_FLAG_BLOCK) {
		if ((ret = ddi_intr_block_enable(ice->ice_intr_handles,
		    ice->ice_nintrs)) != DDI_SUCCESS) {
			ice_error(ice, "failed to block enable interrupts: %d",
			    ret);
			return (B_FALSE);
		}
	} else {
		int i;
		for (i = 0; i < ice->ice_nintrs; i++) {
			if ((ret = ddi_intr_enable(ice->ice_intr_handles[i])) !=
			    DDI_SUCCESS) {
				ice_error(ice, "failed to enable interrupt "
				    "%d: %d", i, ret);
				while (--i >= 0) {
					(void) ddi_intr_disable(
					    ice->ice_intr_handles[i]);
				}
				return (B_FALSE);
			}
		}
	}

	return (B_TRUE);
}

static void
ice_task_fini(ice_t *ice)
{
	ice_task_t *task = &ice->ice_task;

	taskq_wait(task->itk_tq);

	mutex_destroy(&task->itk_lock);
	taskq_destroy(task->itk_tq);
}

static boolean_t
ice_task_init(ice_t *ice)
{
	ice_task_t *task = &ice->ice_task;

	task->itk_tq = taskq_create_instance("ice_task", ice->ice_inst, 1,
	    minclsyspri, 0, 0, 0);
	if (task->itk_tq == NULL) {
		ice_error(ice, "failed to create ice taskq");
		return (B_FALSE);
	}

	mutex_init(&task->itk_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(ice->ice_intr_pri));

	return (B_TRUE);
}

static void
ice_link_state_set(ice_t *ice, link_state_t state)
{
	if (ice->ice_link_cur_state == state)
		return;

	ice->ice_link_cur_state = state;
	/*
	 * XXX This can fire while coming up in attach before we've actually
	 * registered with MAC.
	 */
	if (ice->ice_mac_hdl != NULL) {
		mac_link_update(ice->ice_mac_hdl, ice->ice_link_cur_state);
	}
}

/*
 * Go over the PHY and Link data to synthesize data that is useful to have
 * cached on the driver both for MAC and for inspection via mdb.
 */
static void
ice_link_prop_update(ice_t *ice)
{
	ice_link_status_t *link = &ice->ice_link;

	ASSERT(MUTEX_HELD(&ice->ice_lse_lock));

	if ((link->ils_status & ICE_LINK_STATUS_LINK_UP) == 0) {
		ice_link_state_set(ice, LINK_STATE_DOWN);
		ice->ice_link_cur_duplex = LINK_DUPLEX_UNKNOWN;
		ice->ice_link_cur_speed = 0;
		ice->ice_link_cur_fctl = LINK_FLOWCTRL_NONE;
		return;
	}

	ice_link_state_set(ice, LINK_STATE_UP);
	ice->ice_link_cur_duplex = LINK_DUPLEX_FULL;

	switch (link->ils_curspeed) {
	case ICE_LINK_SPEED_200GB:
		ice->ice_link_cur_speed = 200000;
		break;
	case ICE_LINK_SPEED_100GB:
		ice->ice_link_cur_speed = 100000;
		break;
	case ICE_LINK_SPEED_50GB:
		ice->ice_link_cur_speed = 50000;
		break;
	case ICE_LINK_SPEED_40GB:
		ice->ice_link_cur_speed = 40000;
		break;
	case ICE_LINK_SPEED_25GB:
		ice->ice_link_cur_speed = 25000;
		break;
	case ICE_LINK_SPEED_20GB:
		ice->ice_link_cur_speed = 20000;
		break;
	case ICE_LINK_SPEED_10GB:
		ice->ice_link_cur_speed = 10000;
		break;
	case ICE_LINK_SPEED_5GB:
		ice->ice_link_cur_speed = 5000;
		break;
	case ICE_LINK_SPEED_2500MB:
		ice->ice_link_cur_speed = 2500;
		break;
	case ICE_LINK_SPEED_1GB:
		ice->ice_link_cur_speed = 1000;
		break;
	case ICE_LINK_SPEED_100MB:
		ice->ice_link_cur_speed = 100;
		break;
	case ICE_LINK_SPEED_10MB:
		ice->ice_link_cur_speed = 10;
		break;
	default:
		ice->ice_link_cur_speed = 0;
		break;
	}

	if ((link->ils_autoneg & ICE_LINK_AUTONEG_PAUSE_TX) != 0 &&
	    (link->ils_autoneg & ICE_LINK_AUTONEG_PAUSE_RX) != 0) {
		ice->ice_link_cur_fctl = LINK_FLOWCTRL_BI;
	} else if ((link->ils_autoneg & ICE_LINK_AUTONEG_PAUSE_TX) != 0) {
		ice->ice_link_cur_fctl = LINK_FLOWCTRL_TX;
	} else if ((link->ils_autoneg & ICE_LINK_AUTONEG_PAUSE_RX) != 0) {
		ice->ice_link_cur_fctl = LINK_FLOWCTRL_RX;
	} else {
		ice->ice_link_cur_fctl = LINK_FLOWCTRL_NONE;
	}
}

boolean_t
ice_link_status_update(ice_t *ice)
{
	ice_link_status_t link;
	ice_phy_abilities_t phy;
	ice_lse_t lse;
	boolean_t valid = B_FALSE;

	bzero(&link, sizeof (link));
	bzero(&phy, sizeof (phy));

	mutex_enter(&ice->ice_lse_lock);
	while ((ice->ice_lse_state & ICE_LSE_STATE_UPDATING) != 0) {
		cv_wait(&ice->ice_lse_cv, &ice->ice_lse_lock);
	}

	ice->ice_lse_state |= ICE_LSE_STATE_UPDATING;

	if ((ice->ice_lse_state & ICE_LSE_STATE_ENABLE) != 0) {
		lse = ICE_LSE_ENABLE;
	} else {
		lse = ICE_LSE_DISABLE;
	}
	mutex_exit(&ice->ice_lse_lock);

	if (!ice_cmd_get_phy_abilities(ice, &phy, B_TRUE)) {
		goto out;
	}

	if (!ice_cmd_get_link_status(ice, &link, lse)) {
		goto out;
	}
	valid = B_TRUE;

out:
	mutex_enter(&ice->ice_lse_lock);
	if (valid) {
		bcopy(&link, &ice->ice_link, sizeof (link));
		bcopy(&phy, &ice->ice_phy, sizeof (phy));

		ice_link_prop_update(ice);
	}

	ice->ice_lse_state &= ~ICE_LSE_STATE_UPDATING;
	cv_broadcast(&ice->ice_lse_cv);
	mutex_exit(&ice->ice_lse_lock);

	return (valid);
}

static void
ice_schedule_taskq(void *arg)
{
	ice_t *ice = arg;
	ice_task_t *task = &ice->ice_task;
	ice_work_task_t work;
	boolean_t again;

	/*
	 * Indicate that we've started running and snapshot the events that we
	 * need to operate on. It's important that we do this here as once we
	 * do, new events may be added in here. Once we grab this, we drop our
	 * hold on the lock to minimize time spent here.
	 */
start:
	mutex_enter(&task->itk_lock);
	work = task->itk_work;
	task->itk_work = 0;
	task->itk_state |= ICE_TASK_S_RUNNING;
	task->itk_state &= ~ICE_TASK_S_DISPATCHED;
	mutex_exit(&task->itk_lock);

	/*
	 * Process the control queue first as it may need to add additional work
	 * tasks that we should do in this iteration of the loop such as a link
	 * status event.
	 */
	if ((work & ICE_WORK_CONTROLQ) != 0) {
		work |= ice_controlq_rq_process(ice);
		work &= ~ICE_WORK_CONTROLQ;
	}

	if ((work & ICE_WORK_LINK_STATUS_EVENT) != 0) {
		ice_error(ice, "XXX attempting LSE");
		if (!ice_link_status_update(ice)) {
			ice_error(ice, "failed to update ice link status due "
			    "to controlq event");
		}
		work &= ~ICE_WORK_LINK_STATUS_EVENT;
	}

	if ((work & ICE_WORK_NEED_RESET) != 0) {
		ice_error(ice, "implement ice need reset");
		work &= ~ICE_WORK_NEED_RESET;
	}

	if ((work & ICE_WORK_RESET_DETECTED) != 0) {
		ice_error(ice, "implement ice reset detected");
		work &= ~ICE_WORK_RESET_DETECTED;
	}

	ASSERT0(work);

	/*
	 * At this point we believe that we have completed all of our work.
	 * Indicate that we're no longer running and
	 */
	mutex_enter(&task->itk_lock);
	task->itk_state &= ~ICE_TASK_S_RUNNING;
	again = (task->itk_state & ICE_TASK_S_DISPATCHED) != 0;
	mutex_exit(&task->itk_lock);

	if (again) {
		goto start;
	}
}

void
ice_schedule(ice_t *ice, ice_work_task_t work)
{
	ice_task_t *task = &ice->ice_task;

	mutex_enter(&task->itk_lock);
	task->itk_work |= work;

	/*
	 * If we already have dispatched the event, then there's no need for us
	 * to do anything else. It will be picked up as our scheduled work comes
	 * back around.
	 */
	if ((task->itk_state & ICE_TASK_S_DISPATCHED) != 0) {
		mutex_exit(&task->itk_lock);
		return;
	}

	task->itk_state |= ICE_TASK_S_DISPATCHED;
	if ((task->itk_state & ICE_TASK_S_RUNNING) == 0) {
		taskq_dispatch_ent(task->itk_tq, ice_schedule_taskq, ice, 0,
		    &task->itk_ent);
	}
	mutex_exit(&task->itk_lock);
}

/*
 * Walk the switch configuration to find information about our physical port. We
 * only expect there to be one such entry on a given device.
 */
static boolean_t
ice_switch_init(ice_t *ice)
{
	ice_hw_switch_config_t *swconf;
	uint16_t cur, nents, next;
	boolean_t port_seen = B_FALSE;

	swconf = kmem_alloc(ICE_CQ_GET_SWITCH_CONFIG_BUF_MAX, KM_SLEEP);
	cur = 0;
	do {
		uint16_t i;

		bzero(swconf, ICE_CQ_GET_SWITCH_CONFIG_BUF_MAX);
		if (!ice_cmd_get_switch_config(ice, swconf,
		    ICE_CQ_GET_SWITCH_CONFIG_BUF_MAX, cur, &nents, &next)) {
			ice_error(ice, "failed to get initial switch config");
			goto err;
		}

		for (i = 0; i < nents; i++) {
			uint16_t info = swconf[i].isc_vsi_info;

			if (ICE_SWITCH_ELT_TYPE(info) !=
			    ICE_SWITCH_TYPE_PHYSICAL_PORT) {
				continue;
			}

			if (port_seen) {
				ice_error(ice, "encounterd two different "
				    "physical port entries! First has ID "
				    "0x%x/0x%x, second has ID 0x%x/0x%x",
				    ice->ice_port_id, ice->ice_port_swid,
				    ICE_SWITCH_ELT_NUMBER(info),
				    swconf[i].isc_swid);
				goto err;
			}

			ice->ice_port_id = ICE_SWITCH_ELT_NUMBER(info);
			ice->ice_port_swid = swconf[i].isc_swid;
			port_seen = B_TRUE;
		}

		cur = next;
	} while (cur != 0);

	kmem_free(swconf, ICE_CQ_GET_SWITCH_CONFIG_BUF_MAX);
	return (B_TRUE);

err:
	kmem_free(swconf, ICE_CQ_GET_SWITCH_CONFIG_BUF_MAX);
	return (B_FALSE);
}

static boolean_t
ice_tx_scheduler_init(ice_t *ice)
{
	if (!ice_cmd_get_default_scheduler(ice, ice->ice_sched_buf,
	    sizeof (ice->ice_sched_buf), &ice->ice_sched_nbranches)) {
		return (B_FALSE);
	}
	return (B_TRUE);
}

static void
ice_vsi_context_fill(ice_t *ice, ice_vsi_t *vsi)
{
	ice_hw_vsi_context_t *ctx = &vsi->ivsi_ctxt;
	uint32_t table;
	uint16_t tc;

	/*
	 * Make sure everything in the context starts off zeroed.
	 */
	bzero(ctx, sizeof (*ctx));

	/*
	 * Set up general switch parameters. The default settings here are such
	 * that we don't allow traffic to loop back from the VSI, we explicitly
	 * allow it to reach the LAN, and we follow the programming manual's
	 * advice to turn on source pruning.
	 *
	 * XXX Come back for statistics
	 */
	ctx->ihvc_switch_id = ice->ice_port_swid;
	ctx->ihvc_switch_flags = ICE_HW_VSI_SWITCH_APPLY_SOURCE_PRUNE;
	ctx->ihvc_switch_flags2 = ICE_HW_VSI_SWITCH_LAN_ENABLE;

	/*
	 * By default we do not enable anything in the security section.
	 */

	/*
	 * For VLAN handling, by default we allow all tagged and untaggd packets
	 * on a given VSI. We do not enable VLAN insertion and we set it up such
	 * that hardware leaves the VLAN ID in the packet.
	 */
	ctx->ihvc_vlan_flags = ICE_HW_VSI_VLAN_SET_TAG(ctx->ihvc_vlan_flags,
	    ICE_HW_VSI_VLAN_ALL);
	ctx->ihvc_vlan_flags = ICE_HW_VSI_VLAN_SET_UP_MODE(ctx->ihvc_vlan_flags,
	    ICE_HW_VSI_VLAN_UP_DO_NONE);

	/*
	 * The next values are used to allow us to remap priority values that
	 * are found in VLAN tags. We make this a direct mapping. Both the
	 * ingress and egress tables are defined the same way, so we build one
	 * table.
	 */
	table = 0;
	for (uint_t i = 0; i < 8; i++) {
		table = ICE_HW_VSI_UP_TABLE_SET(table, i, i);
	}
	ctx->ihvc_ingress_table = LE_32(table);
	ctx->ihvc_egress_table = LE_32(table);
	ctx->ihvc_outer_table = LE_32(table);

	/*
	 * We do not set up any outer tag handling. The default setting of
	 * everyting to zero indicates that nothing should happen.
	 */

	/*
	 * Assign a contiguous set of queues to the VSI. They all go into the
	 * default traffic class as well. The traffic class is written as a
	 * number of queues that is 2^n. Therefore to correctly calculate the
	 * traffic class we need to subtract one from the total number of queues
	 * before passing that into ddi_fls.
	 */
	ctx->ihvc_queue_method = ICE_HW_VSI_QMAP_CONTIG;
	ctx->ihvc_queue_mapping[0] = LE_16(vsi->ivsi_frxq);
	ctx->ihvc_queue_mapping[1] = LE_16(vsi->ivsi_nrxq);
	tc = 0;
	tc = ICE_HW_VSI_TC_SET_QUEUE_OFF(tc, 0);
	tc = ICE_HW_VSI_TC_SET_NQUEUES(tc, ddi_fls(vsi->ivsi_nrxq - 1));
	ctx->ihvc_queue_tc[0] = LE_16(tc);

	/*
	 * For RSS, we always set things up to use the VSI's own RSS table.
	 */
	ctx->ihvc_qopt_rss = ICE_HW_VSI_RSS_SET_LUT(0, ICE_HW_VSI_RSS_LUT_VSI);
	ctx->ihvc_qopt_rss = ICE_HW_VSI_RSS_SET_HASH_SCHEME(ctx->ihvc_qopt_rss,
	    ICE_HW_VSI_RSS_SCHEME_TOEPLITZ);

	/*
	 * We don't define anything for ACLs, Flow director, or PASID. As the
	 * default zeroing of the structure leaves them disabled, this should be
	 * sufficient for now.
	 */
}

static void
ice_vsi_free(ice_t *ice, ice_vsi_t *vsi)
{
	if (vsi == NULL)
		return;

	if ((vsi->ivsi_flags & ICE_VSI_F_ACTIVE) != 0) {
		(void) ice_cmd_free_vsi(ice, vsi, B_FALSE);
	}

	kmem_free(vsi, sizeof (ice_vsi_t));
}

static boolean_t
ice_vsi_rss_init(ice_t *ice, ice_vsi_t *vsi)
{
	uint8_t rss_key[ICE_RSS_KEY_LENGTH];
	uint8_t rss_lut[ICE_RSS_LUT_SIZE_VSI];
	uint_t i;

	/*
	 * Initialize the RSS key to random data. We're supposed to zero the
	 * extended bytes. So only fill the basic bytes with random data.
	 */
	bzero(rss_key, sizeof (rss_key));
	(void) random_get_pseudo_bytes(rss_key, ICE_RSS_KEY_STANDARD_LENGTH);

	/*
	 * The LUT needs to be filled with target queues indexes. We do this
	 * naively by just filling up the LUT in order based on the number of
	 * queues present.
	 */
	for (i = 0; i < sizeof (rss_lut); i++) {
		rss_lut[i] = i % vsi->ivsi_nrxq;
	}

	if (!ice_cmd_set_rss_key(ice, vsi, rss_key, sizeof (rss_key))) {
		return (B_FALSE);
	}

	/*
	 * XXX At some point we'll need to go through and make sure that we've
	 * programmed hardware for the right RSS types. This shouldn't happen on
	 * a per-VSI basis, but should happen globally.
	 */

	/*
	 * XXX This currently doesn't work and it's not 100% clear why. It may
	 * be because we haven't actually assigned any queues to the VSI yet.
	 * When we come back to RX we should sort this out and re-enable this.
	 */
#if 0
	if (!ice_cmd_set_rss_lut(ice, vsi, rss_lut, sizeof (rss_lut))) {
		return (B_FALSE);
	}
#endif

	return (B_TRUE);
}

static ice_vsi_t *
ice_vsi_alloc(ice_t *ice, uint_t vsi_id, ice_vsi_type_t type)
{
	ice_vsi_t *vsi;

	vsi = kmem_zalloc(sizeof (ice_vsi_t), KM_SLEEP);
	vsi->ivsi_id = vsi_id;
	vsi->ivsi_type = type;

	/*
	 * All of the VSIs that we create need to be allocated from the general
	 * pool.
	 */
	vsi->ivsi_flags |= ICE_VSI_F_POOL_ALLOC;

	/*
	 * XXX This only makes sense for the PF and even then not very much.
	 * Figure out how to do queue assignments better. Also, keep in mind
	 * whether these queue allocations are in the function space or in the
	 * global space.
	 */
	vsi->ivsi_nrxq = 1;
	vsi->ivsi_frxq = 0;

	ice_vsi_context_fill(ice, vsi);

	if (!ice_cmd_add_vsi(ice, vsi)) {
		ice_vsi_free(ice, vsi);
		return (NULL);
	}
	vsi->ivsi_flags |= ICE_VSI_F_ACTIVE;

	if (!ice_vsi_rss_init(ice, vsi)) {
		ice_vsi_free(ice, vsi);
		return (NULL);
	}
	vsi->ivsi_flags |= ICE_VSI_F_RSS_SET;

	/*
	 * XXX What queue initialization should we be doing here?
	 */

	list_insert_tail(&ice->ice_vsi, vsi);

	return (vsi);
}

static boolean_t
ice_pf_vsi_init(ice_t *ice)
{
	ice_vsi_t *vsi;

	list_create(&ice->ice_vsi, sizeof (ice_vsi_t),
	    offsetof(ice_vsi_t, ivsi_node));

	vsi = ice_vsi_alloc(ice, 0, ICE_VSI_TYPE_PF);
	if (vsi == NULL) {
		list_destroy(&ice->ice_vsi);
		return (B_FALSE);
	}

	/*
	 * XXX We need to set up basic switch rules so that this gets the
	 * primary MAC, etc.
	 */

	return (B_TRUE);
}

static void
ice_cleanup(ice_t *ice)
{
	if (ice == NULL) {
		return;
	}

	if (ice->ice_seq & ICE_ATTACH_INTR_ENABLE) {
		(void) ice_intr_ddi_disable(ice);
		ice->ice_seq &= ~ICE_ATTACH_INTR_ENABLE;
	}

	if (ice->ice_seq & ICE_ATTACH_MAC) {
		ice_mac_unregister(ice);
		ice->ice_seq &= ~ICE_ATTACH_MAC;
	}

	if (ice->ice_seq & ICE_ATTACH_VSI) {
		ice_vsi_t *vsi;

		while ((vsi = list_remove_tail(&ice->ice_vsi)) != NULL) {
			ice_vsi_free(ice, vsi);
		}
		list_destroy(&ice->ice_vsi);
		ice->ice_seq &= ~ICE_ATTACH_VSI;
	}

	if (ice->ice_seq & ICE_ATTACH_TASK) {
		ice_task_fini(ice);
		ice->ice_seq &= ~ICE_ATTACH_TASK;
	}

	if (ice->ice_seq & ICE_ATTACH_INTR_HANDLER) {
		ice_intr_rem_ddi_handles(ice);
		ice->ice_seq &= ~ICE_ATTACH_INTR_HANDLER;
	}

	if (ice->ice_seq & ICE_ATTACH_INTR_ALLOC) {
		ice_intr_ddi_free(ice);
		ice->ice_seq &= ~ICE_ATTACH_INTR_ALLOC;
	}

	if (ice->ice_seq & ICE_ATTACH_PBA) {
		kmem_free(ice->ice_pba, ice->ice_pba_len);
		ice->ice_seq &= ~ICE_ATTACH_PBA;
	}

	if (ice->ice_seq & ICE_ATTACH_LSE) {
		mutex_destroy(&ice->ice_lse_lock);
		cv_destroy(&ice->ice_lse_cv);
		ice->ice_seq &= ~ICE_ATTACH_LSE;
	}

	if (ice->ice_seq & ICE_ATTACH_CAPS) {
		if (ice->ice_dev_caps != NULL) {
			kmem_free(ice->ice_dev_caps, ice->ice_ndev_caps *
			    sizeof (ice_capability_t));
		}
		if (ice->ice_func_caps != NULL) {
			kmem_free(ice->ice_func_caps, ice->ice_nfunc_caps *
			    sizeof (ice_capability_t));
		}
		ice->ice_seq &= ~ICE_ATTACH_CAPS;
	}

	if (ice->ice_seq & ICE_ATTACH_NVM) {
		ice_nvm_fini(ice);
		ice->ice_seq &= ~ICE_ATTACH_NVM;
	}

	if (ice->ice_seq & ICE_ATTACH_CONTROLQ) {
		ice_controlq_fini(ice);
		ice->ice_seq &= ~ICE_ATTACH_CONTROLQ;
	}

	if (ice->ice_seq & ICE_ATTACH_REGS) {
		ddi_regs_map_free(&ice->ice_reg_hdl);
		ice->ice_seq &= ~ICE_ATTACH_REGS;
	}

	if (ice->ice_seq & ICE_ATTACH_PCI) {
		pci_config_teardown(&ice->ice_pci_hdl);
		ice->ice_seq &= ~ICE_ATTACH_PCI;
	}

	if (ice->ice_seq & ICE_ATTACH_FM) {
		if (ice->ice_fm_caps != DDI_FM_NOT_CAPABLE) {
			ddi_fm_fini(ice->ice_dip);
		}
		ice->ice_seq &= ~ICE_ATTACH_FM;
	}

	ASSERT0(ice->ice_seq);
	kmem_free(ice, sizeof (ice_t));
}

static int
ice_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	ice_t *ice;

	if (cmd != DDI_ATTACH) {
		return (DDI_FAILURE);
	}

	ice = kmem_zalloc(sizeof (ice_t), KM_SLEEP);
	ice->ice_dip = dip;
	ice->ice_inst = ddi_get_instance(dip);

	ice_fm_init(ice);
	ice->ice_seq |= ICE_ATTACH_FM;

	if (pci_config_setup(dip, &ice->ice_pci_hdl) != 0) {
		ice_error(ice, "failed to initialize PCI config space");
		goto err;
	}
	ice->ice_seq |= ICE_ATTACH_PCI;

	if (!ice_regs_map(ice)) {
		goto err;
	}
	ice->ice_seq |= ICE_ATTACH_REGS;

	ice_identify(ice);
	ice_properties_init(ice);

	if (!ice_pf_reset(ice)) {
		goto err;
	}

	if (!ice_controlq_init(ice)) {
		goto err;
	}
	ice->ice_seq |= ICE_ATTACH_CONTROLQ;

	if (!ice_firmware_check(ice)) {
		goto err;
	}

	if (!ice_cmd_clear_pf_config(ice)) {
		goto err;
	}

	if (!ice_cmd_clear_pxe(ice)) {
		goto err;
	}

	if (!ice_nvm_init(ice)) {
		goto err;
	}
	ice->ice_seq |= ICE_ATTACH_NVM;

	if (!ice_caps_fetch(ice)) {
		goto err;
	}
	ice->ice_seq |= ICE_ATTACH_CAPS;

	if (!ice_cmd_mac_read(ice, ice->ice_mac)) {
		goto err;
	}

	mutex_init(&ice->ice_lse_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&ice->ice_lse_cv, NULL, CV_DRIVER, NULL);
	ice->ice_seq |= ICE_ATTACH_LSE;

	if (!ice_link_status_update(ice)) {
		goto err;
	}

	/*
	 * XXX Firmware always returns EPERM if we try to read this, though the
	 * datasheet suggests that we should be able to do otherwise.
	 */
#if 0
	if (!ice_nvm_read_pba(ice)) {
		goto err;
	}
	ice->ice_seq |= ICE_ATTACH_PBA;
#endif

	if (!ice_intr_ddi_alloc(ice)) {
		goto err;
	}
	ice->ice_seq |= ICE_ATTACH_INTR_ALLOC;

	if (!ice_calculate_groups(ice)) {
		goto err;
	}

	if (!ice_intr_add_ddi_handles(ice)) {
		goto err;
	}
	ice->ice_seq |= ICE_ATTACH_INTR_HANDLER;


	if (!ice_task_init(ice)) {
		goto err;
	}
	ice->ice_seq |= ICE_ATTACH_TASK;

	if (!ice_switch_init(ice)) {
		goto err;
	}

	if (!ice_tx_scheduler_init(ice)) {
		goto err;
	}

	if (!ice_pf_vsi_init(ice)) {
		goto err;
	}
	ice->ice_seq |= ICE_ATTACH_VSI;

	/*
	 * XXX Once we have interrupts go back and figure out all of the initial
	 * switch configuration. Figure out the default VSI, tx scheduler, the
	 * switch itself, etc.
	 */

	/*
	 * XXX We're punting on getting the switch and port configuration so we
	 * can deal with the tx scheduler. Wait to deal with the phy and link
	 * capabilities until we've done other stuff.
	 */

	/*
	 * XXX We need to go through and enable the global RSS configuration
	 * potentially depending on the state that firmware is going to
	 * guarantee leaving us in. This can be dealt with once we have general
	 * I/O working.
	 */

	if (!ice_mac_register(ice)) {
		goto err;
	}
	ice->ice_seq |= ICE_ATTACH_MAC;

	if (!ice_intr_ddi_enable(ice)) {
		goto err;
	}
	ice->ice_seq |= ICE_ATTACH_INTR_ENABLE;

	/*
	 * XXX Enable link state change notifications and set the event mask so
	 * that way we can accurately know what's going on even when we haven't
	 * called start
	 */

	ddi_set_driver_private(dip, ice);

	return (DDI_SUCCESS);

err:
	ice_cleanup(ice);
	return (DDI_FAILURE);
}

static int
ice_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	ice_t *ice;

	if (cmd != DDI_DETACH) {
		return (DDI_FAILURE);
	}

	if ((ice = ddi_get_driver_private(dip)) == NULL) {
		dev_err(dip, CE_WARN, "asked to detach instance %d, but "
		    "no ice_t state", ddi_get_instance(dip));
		return (DDI_FAILURE);
	}

	ddi_set_driver_private(dip, NULL);
	ice_cleanup(ice);

	return (DDI_SUCCESS);
}

static struct cb_ops ice_cb_ops = {
	.cb_open = nodev,
	.cb_close = nodev,
	.cb_strategy = nodev,
	.cb_print = nodev,
	.cb_dump = nodev,
	.cb_read = nodev,
	.cb_write = nodev,
	.cb_ioctl = nodev,
	.cb_devmap = nodev,
	.cb_mmap = nodev,
	.cb_segmap = nodev,
	.cb_chpoll = nochpoll,
	.cb_prop_op = ddi_prop_op,
	.cb_flag = D_MP,
	.cb_rev = CB_REV,
	.cb_aread = nodev,
	.cb_awrite = nodev
};

static struct dev_ops ice_dev_ops = {
	.devo_rev = DEVO_REV,
	.devo_refcnt = 0,
	.devo_getinfo = NULL,
	.devo_identify = nulldev,
	.devo_probe = nulldev,
	.devo_attach = ice_attach,
	.devo_detach = ice_detach,
	.devo_reset = nodev,
	.devo_power = ddi_power,
	.devo_quiesce = ddi_quiesce_not_supported,
	.devo_cb_ops = &ice_cb_ops
};

static struct modldrv ice_modldrv = {
	.drv_modops = &mod_driverops,
	.drv_linkinfo = "Intel 100 Gb Ethernet",
	.drv_dev_ops = &ice_dev_ops
};

static struct modlinkage ice_modlinkage = {
	.ml_rev = MODREV_1,
	.ml_linkage = { &ice_modldrv, NULL }
};

int
_init(void)
{
	int ret;

	mac_init_ops(&ice_dev_ops, ICE_MODULE_NAME);

	if ((ret = mod_install(&ice_modlinkage)) != 0) {
		mac_fini_ops(&ice_dev_ops);
		return (ret);
	}

	return (ret);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&ice_modlinkage, modinfop));
}

int
_fini(void)
{
	int ret;

	if ((ret = mod_remove(&ice_modlinkage)) != 0) {
		return (ret);
	}

	mac_fini_ops(&ice_dev_ops);
	return (ret);
}
