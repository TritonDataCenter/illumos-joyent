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
 * Interrupt handling for ice(4D): MSI-X enable/disable, the "other interrupt
 * cause" (OICR) vector that carries admin-queue async events, link-status
 * changes, and error causes, and the taskq that drains the admin receive
 * queue off the interrupt.  Link state is read through the common code and
 * cached in the softc; it is reported to MAC once the handle from
 * mac_register() exists.
 */

#include <sys/atomic.h>

#include "ice.h"
#include "ice_common.h"

/*
 * OICR is always MSI-X vector 0; queue vectors start at 1.  The other cause
 * uses a dedicated ITR slot (ICE_ITR_INDEX_NONE, in ice.h, is the "do not
 * update the ITR" encoding used when simply re-arming a vector).
 */
#define	ICE_OICR_VECTOR		0
#define	ICE_ITR_INDEX_OTHER	2

/*
 * Hard cap on a single ARQ drain pass so a wedged ring cannot spin forever.
 * Set above the ring depth (ICE_AQ_LEN, 1023) so a merely busy ring still
 * drains fully in one pass.
 */
#define	ICE_ARQ_MAX_ELEMS	2048

/* Admin poll interval; FreeBSD's ice_admin_timer uses the same hz/2. */
#define	ICE_ADMIN_PERIOD_NS	500000000ULL

/*
 * Causes enabled in PFINT_OICR_ENA.  Link changes and the error causes; the
 * generic INTEVENT bit (0) is reserved in this register and is delivered via
 * control-queue routing instead.
 */
#define	ICE_OICR_ENA_MASK	\
	(PFINT_OICR_LINK_STAT_CHANGE_M | PFINT_OICR_GRST_M |	\
	PFINT_OICR_ECC_ERR_M | PFINT_OICR_MAL_DETECT_M |	\
	PFINT_OICR_PCI_EXCEPTION_M | PFINT_OICR_HMC_ERR_M |	\
	PFINT_OICR_PE_CRITERR_M | PFINT_OICR_VFLR_M)

/*
 * Fatal causes that leave the function on untrustworthy state and require a PF
 * reset and rebuild.  GRST (a reset already under way) and MAL_DETECT (needs
 * per-PF register decode) are handled separately.
 */
#define	ICE_OICR_FATAL_MASK	\
	(PFINT_OICR_ECC_ERR_M | PFINT_OICR_PCI_EXCEPTION_M |	\
	PFINT_OICR_HMC_ERR_M | PFINT_OICR_PE_CRITERR_M)

/*
 * Causes the OICR worker logs and acts on (see ice_oicr_fatal).  MAL_DETECT is
 * deliberately absent: it is carried as ICE_STATE_MDD_PENDING instead, because
 * this snapshot is consumed unconditionally by the worker and would be lost if
 * the lifetime gate swallowed that run.
 */
#define	ICE_OICR_CAUSE_MASK	\
	(ICE_OICR_FATAL_MASK | PFINT_OICR_GRST_M)

static void
ice_link_state_set(ice_t *ice, link_state_t state)
{
	ASSERT(MUTEX_HELD(&ice->ice_lse_lock));

	/*
	 * Link state is cached until mac_register() completes; mac_link_
	 * update() must not be called with a NULL handle.
	 */
	if (ice->ice_mac_hdl == NULL)
		return;

	mac_link_update(ice->ice_mac_hdl, state);
}

/*
 * Set the cached link state and report it to MAC under ice_lse_lock.  The
 * reset path uses this to force the link down while the function is rebuilt.
 */
void
ice_link_report(ice_t *ice, link_state_t state)
{
	mutex_enter(&ice->ice_lse_lock);
	ice->ice_link_state = state;
	ice_link_state_set(ice, state);
	mutex_exit(&ice->ice_lse_lock);
}

/*
 * Publish the state cached by the attach-time hardware query after the MAC
 * handle becomes valid.  Serialize with asynchronous link updates so MAC
 * always receives the newest cached state.
 */
void
ice_link_state_publish(ice_t *ice)
{
	mutex_enter(&ice->ice_lse_lock);
	ice_link_state_set(ice, ice->ice_link_state);
	mutex_exit(&ice->ice_lse_lock);
}

/*
 * Decode the firmware-supplied link_info into the cached link state.  Every
 * field here originates in a firmware-written DMA buffer and is treated as
 * untrusted: the speed bitmap is masked and zero-guarded before being turned
 * into an index, and the speed lookup itself (ice_get_link_speed) is bounds
 * checked by the common code.
 */
static void
ice_link_prop_update(ice_t *ice)
{
	struct ice_link_status *li = &ice->ice_hw.port_info->phy.link_info;
	link_flowctrl_t fctl = LINK_FLOWCTRL_NONE;
	uint64_t speed = 0;
	uint16_t spd_bits;

	ASSERT(MUTEX_HELD(&ice->ice_lse_lock));

	/* Internal MAC loopback is usable without a physical carrier. */
	if (ice->ice_loopback_mode == ICE_LB_INTERNAL_MAC) {
		ice->ice_link_state = LINK_STATE_UP;
		ice->ice_link_speed = 0;
		ice->ice_link_duplex = LINK_DUPLEX_FULL;
		ice->ice_link_fctl = LINK_FLOWCTRL_NONE;
		ice_link_state_set(ice, LINK_STATE_UP);
		return;
	}

	if ((li->link_info & ICE_AQ_LINK_UP) == 0) {
		ice->ice_link_state = LINK_STATE_DOWN;
		ice->ice_link_speed = 0;
		ice->ice_link_duplex = LINK_DUPLEX_UNKNOWN;
		ice->ice_link_fctl = LINK_FLOWCTRL_NONE;
		ice_link_state_set(ice, LINK_STATE_DOWN);
		return;
	}

	/*
	 * link_speed is a one-hot bitmap (bits 0-11 valid).  Mask to the valid
	 * range and guard zero before highbit(), then decode the bit index
	 * through the bounds-checked common-code helper.
	 */
	spd_bits = li->link_speed & ICE_AQ_LINK_SPEED_M;
	if (spd_bits != 0)
		speed = ice_get_link_speed((u16)(highbit(spd_bits) - 1));

	if (li->an_info & ICE_AQ_LINK_PAUSE_TX) {
		fctl = (li->an_info & ICE_AQ_LINK_PAUSE_RX) ?
		    LINK_FLOWCTRL_BI : LINK_FLOWCTRL_TX;
	} else if (li->an_info & ICE_AQ_LINK_PAUSE_RX) {
		fctl = LINK_FLOWCTRL_RX;
	}

	/* PHY/serdes links are point-to-point: always full duplex. */
	ice->ice_link_state = LINK_STATE_UP;
	ice->ice_link_speed = speed;
	ice->ice_link_duplex = LINK_DUPLEX_FULL;
	ice->ice_link_fctl = fctl;

	ice_link_state_set(ice, LINK_STATE_UP);
}

/*
 * Apply or remove the link-state override associated with internal MAC
 * loopback.  Disabling first publishes UNKNOWN; the caller then refreshes
 * the real hardware state, leaving UNKNOWN if that query fails.
 */
void
ice_link_loopback_update(ice_t *ice, uint32_t mode)
{
	link_state_t state;

	ASSERT(mode == ICE_LB_NONE || mode == ICE_LB_INTERNAL_MAC);

	mutex_enter(&ice->ice_lse_lock);
	ice->ice_loopback_mode = mode;
	ice->ice_link_speed = 0;
	ice->ice_link_fctl = LINK_FLOWCTRL_NONE;
	if (mode == ICE_LB_INTERNAL_MAC) {
		state = LINK_STATE_UP;
		ice->ice_link_duplex = LINK_DUPLEX_FULL;
	} else {
		state = LINK_STATE_UNKNOWN;
		ice->ice_link_duplex = LINK_DUPLEX_UNKNOWN;
	}
	ice->ice_link_state = state;
	ice_link_state_set(ice, state);
	mutex_exit(&ice->ice_lse_lock);
}

static uint16_t
ice_phy_types_to_speeds(const struct ice_aqc_get_phy_caps_data *pcaps)
{
	static const uint16_t speeds[] = {
		ICE_AQ_LINK_SPEED_1000MB,
		ICE_AQ_LINK_SPEED_2500MB,
		ICE_AQ_LINK_SPEED_5GB,
		ICE_AQ_LINK_SPEED_10GB,
		ICE_AQ_LINK_SPEED_25GB,
		ICE_AQ_LINK_SPEED_40GB,
		ICE_AQ_LINK_SPEED_50GB,
		ICE_AQ_LINK_SPEED_100GB
	};
	u64 caps_low = LE64_TO_CPU(pcaps->phy_type_low);
	u64 caps_high = LE64_TO_CPU(pcaps->phy_type_high);
	uint16_t mask = 0;
	uint_t i;

	for (i = 0; i < ARRAY_SIZE(speeds); i++) {
		u64 phy_low = 0;
		u64 phy_high = 0;

		ice_update_phy_type(&phy_low, &phy_high, speeds[i]);
		if ((caps_low & phy_low) != 0 || (caps_high & phy_high) != 0)
			mask |= speeds[i];
	}

	return (mask);
}

static link_fec_t
ice_phy_fec_negotiated(uint8_t fec_info)
{
	link_fec_t fec = 0;

	fec_info &= ICE_AQ_FEC_MASK;
	if ((fec_info & (ICE_AQ_LINK_25G_RS_528_FEC_EN |
	    ICE_AQ_LINK_25G_RS_544_FEC_EN)) != 0)
		fec |= LINK_FEC_RS;
	if ((fec_info & ICE_AQ_LINK_25G_KR_FEC_EN) != 0)
		fec |= LINK_FEC_BASE_R;

	return (fec != 0 ? fec : LINK_FEC_NONE);
}

void
ice_phy_caps_update(ice_t *ice)
{
	struct ice_hw *hw = &ice->ice_hw;
	struct ice_port_info *pi = hw->port_info;
	struct ice_aqc_get_phy_caps_data pcaps;
	struct ice_aqc_get_phy_caps_data active;
	uint16_t speeds_supp = 0;
	uint16_t speeds_adv = 0;
	boolean_t update = B_FALSE;
	int status;

	if (pi == NULL)
		return;

	mutex_enter(&ice->ice_lse_lock);
	while (ice->ice_lse_flags & ICE_LSE_F_UPDATING)
		cv_wait(&ice->ice_lse_cv, &ice->ice_lse_lock);
	ice->ice_lse_flags |= ICE_LSE_F_UPDATING;
	mutex_exit(&ice->ice_lse_lock);

	bzero(&pcaps, sizeof (pcaps));
	status = ice_aq_get_phy_caps(pi, false,
	    ICE_AQC_REPORT_TOPO_CAP_MEDIA, &pcaps, NULL);
	if (status != ICE_SUCCESS) {
		ice_error(ice, "failed to read media PHY caps: %d", status);
		goto out;
	}

	bzero(&active, sizeof (active));
	status = ice_aq_get_phy_caps(pi, false, ICE_AQC_REPORT_ACTIVE_CFG,
	    &active, NULL);
	if (status != ICE_SUCCESS) {
		ice_error(ice, "failed to read active PHY config: %d", status);
		goto out;
	}

	speeds_supp = ice_phy_types_to_speeds(&pcaps);
	speeds_adv = ice_phy_types_to_speeds(&active);
	update = B_TRUE;

out:
	mutex_enter(&ice->ice_lse_lock);
	if (update) {
		ice->ice_phy_speeds_supp = speeds_supp;
		ice->ice_phy_speeds_adv = speeds_adv;
		ice->ice_fec_neg = ice_phy_fec_negotiated(
		    pi->phy.link_info.fec_info);
	}
	ice->ice_lse_flags &= ~ICE_LSE_F_UPDATING;
	cv_broadcast(&ice->ice_lse_cv);
	mutex_exit(&ice->ice_lse_lock);
}

/*
 * Refresh the cached link state from hardware.  The blocking common-code read
 * runs outside ice_lse_lock; a single in-flight update is enforced with the
 * UPDATING flag so concurrent callers (taskq and attach) serialize.
 */
static void
ice_link_status_update_impl(ice_t *ice, boolean_t *media_inserted)
{
	struct ice_port_info *pi = ice->ice_hw.port_info;
	int rc;

	if (media_inserted != NULL)
		*media_inserted = B_FALSE;
	if (pi == NULL)
		return;

	mutex_enter(&ice->ice_lse_lock);
	while (ice->ice_lse_flags & ICE_LSE_F_UPDATING)
		cv_wait(&ice->ice_lse_cv, &ice->ice_lse_lock);
	ice->ice_lse_flags |= ICE_LSE_F_UPDATING;
	mutex_exit(&ice->ice_lse_lock);

	pi->phy.get_link_info = 1;
	rc = ice_update_link_info(pi);

	mutex_enter(&ice->ice_lse_lock);
	if (media_inserted != NULL) {
		*media_inserted =
		    (pi->phy.link_info.link_info &
		    ICE_AQ_MEDIA_AVAILABLE) != 0 &&
		    (pi->phy.link_info_old.link_info &
		    ICE_AQ_MEDIA_AVAILABLE) == 0;
	}
	if (rc == 0) {
		ice_link_prop_update(ice);
	} else {
		ice_error(ice, "link info update failed: %d", rc);
	}
	ice->ice_lse_flags &= ~ICE_LSE_F_UPDATING;
	cv_broadcast(&ice->ice_lse_cv);
	mutex_exit(&ice->ice_lse_lock);
}

void
ice_link_status_update(ice_t *ice)
{
	ice_link_status_update_impl(ice, NULL);
}

/*
 * Coalesce a rebuild request and hand it to the dedicated reset taskq.
 * Mirrors the ice_oicr_pending idiom: at most one task is queued at a time,
 * and the flag re-arms when ice_reset_task clears it.  Runs in thread context
 * only (the OICR worker or the DEBUG test hook), never at interrupt priority.
 */
void
ice_reset_dispatch(ice_t *ice)
{
	boolean_t dispatch = B_FALSE;

	mutex_enter(&ice->ice_lock);
	if (!ice->ice_reset_pending) {
		ice->ice_reset_pending = B_TRUE;
		dispatch = B_TRUE;
	}
	mutex_exit(&ice->ice_lock);

	if (dispatch && ddi_taskq_dispatch(ice->ice_reset_taskq, ice_reset_task,
	    ice, DDI_NOSLEEP) != DDI_SUCCESS) {
		mutex_enter(&ice->ice_lock);
		ice->ice_reset_pending = B_FALSE;
		mutex_exit(&ice->ice_lock);
		ice_error(ice, "reset taskq dispatch failed");
	}
}

/*
 * Atomically clear a state bit and report whether it had been set.  A plain
 * read-then-atomic_and_32 would wipe a cause the ISR set between the two,
 * which is exactly the loss this carries state to avoid.  Mirrors FreeBSD's
 * ice_testandclear_state() (ice_lib.c:8339 uses it for MDD).
 */
static boolean_t
ice_state_testclear(ice_t *ice, uint32_t bit)
{
	uint32_t old;

	do {
		old = ice->ice_state;
		if ((old & bit) == 0)
			return (B_FALSE);
	} while (atomic_cas_32(&ice->ice_state, old, old & ~bit) != old);

	return (B_TRUE);
}

/*
 * Convert a raw PFINT_OICR snapshot into the persistent state the deferred
 * worker acts on.  Shared by the ISR and by the attach-time harvest in
 * ice_intr_oicr_setup() so the two cannot drift.  FreeBSD's ice_msix_admin()
 * does the same conversion inline (if_ice_iflib.c:1331, 1361, 1375, 1387) and
 * never carries the raw value across the deferral boundary.
 */
static void
ice_oicr_causes_latch(ice_t *ice, uint32_t oicr)
{
	struct ice_hw *hw = &ice->ice_hw;
	uint32_t state = 0;

	if ((oicr & PFINT_OICR_GRST_M) != 0) {
		/*
		 * A reset is being performed on the function.  Make concurrent
		 * admin-queue commands soft-fail instead of hanging on
		 * resetting hardware, and fail the datapath closed.
		 */
		hw->reset_ongoing = true;
		state |= ICE_STATE_RESET_PENDING | ICE_STATE_ERROR;
	}

	if ((oicr & ICE_OICR_FATAL_MASK) != 0) {
		/*
		 * ECC/PCIe/HMC/PE-critical errors leave the function on
		 * untrustworthy state.  Fail the datapath closed and request a
		 * PF reset rebuild.
		 */
		ddi_fm_service_impact(ice->ice_dip, DDI_SERVICE_DEGRADED);
		state |= ICE_STATE_ERROR | ICE_STATE_PFR_REQ;
	}

	/*
	 * MDD owes a register decode, not a reset: only ice_oicr_mdd() can tell
	 * whether this function or another one was the offender, so it gets its
	 * own persistent bit rather than riding ICE_OICR_CAUSE_MASK.
	 */
	if ((oicr & PFINT_OICR_MAL_DETECT_M) != 0)
		state |= ICE_STATE_MDD_PENDING;

	if (state != 0)
		atomic_or_32(&ice->ice_state, state);
}

/*
 * Decode a malicious-driver-detection event.  Clear the global detection
 * registers so the cause does not re-fire, and if this function is the offender
 * fail the datapath closed and request a rebuild.  Returns B_TRUE only when
 * this function caused the event.
 */
static boolean_t
ice_oicr_mdd(ice_t *ice)
{
	struct ice_hw *hw = &ice->ice_hw;
	boolean_t pf_mdd = B_FALSE;

	if (rd32(hw, GL_MDET_TX_PQM) != 0)
		wr32(hw, GL_MDET_TX_PQM, 0xffffffff);
	if (rd32(hw, GL_MDET_TX_TCLAN) != 0)
		wr32(hw, GL_MDET_TX_TCLAN, 0xffffffff);
	if (rd32(hw, GL_MDET_RX) != 0)
		wr32(hw, GL_MDET_RX, 0xffffffff);

	if ((rd32(hw, PF_MDET_TX_PQM) & PF_MDET_TX_PQM_VALID_M) != 0) {
		wr32(hw, PF_MDET_TX_PQM, 0xffffffff);
		pf_mdd = B_TRUE;
	}
	if ((rd32(hw, PF_MDET_TX_TCLAN) & PF_MDET_TX_TCLAN_VALID_M) != 0) {
		wr32(hw, PF_MDET_TX_TCLAN, 0xffffffff);
		pf_mdd = B_TRUE;
	}
	if ((rd32(hw, PF_MDET_RX) & PF_MDET_RX_VALID_M) != 0) {
		wr32(hw, PF_MDET_RX, 0xffffffff);
		pf_mdd = B_TRUE;
	}

	if (pf_mdd) {
		ice_error(ice, "malicious driver event on this function; "
		    "datapath halted pending reset");
		ddi_fm_service_impact(ice->ice_dip, DDI_SERVICE_DEGRADED);
		atomic_or_32(&ice->ice_state,
		    ICE_STATE_ERROR | ICE_STATE_PFR_REQ);
	} else {
		ice_error(ice, "malicious driver event on another function");
	}

	return (pf_mdd);
}

/*
 * Report the fatal OICR causes latched by the ISR and fail the link closed so
 * clients stop offering traffic.  The datapath already observes ICE_STATE_ERROR
 * and stops touching hardware; reset rebuild, when requested, runs separately.
 */
static void
ice_oicr_fatal(ice_t *ice, uint32_t cause, boolean_t mdd)
{
	boolean_t fault = (cause & (ICE_OICR_FATAL_MASK |
	    PFINT_OICR_GRST_M)) != 0;

	if ((cause & PFINT_OICR_ECC_ERR_M) != 0)
		ice_error(ice, "ECC error detected; datapath halted");
	if ((cause & PFINT_OICR_PCI_EXCEPTION_M) != 0)
		ice_error(ice, "PCIe exception detected; datapath halted");
	if ((cause & PFINT_OICR_HMC_ERR_M) != 0)
		ice_error(ice, "HMC error detected; datapath halted");
	if ((cause & PFINT_OICR_PE_CRITERR_M) != 0)
		ice_error(ice, "PE critical error detected; datapath halted");
	if ((cause & PFINT_OICR_GRST_M) != 0)
		ice_error(ice, "global reset detected; datapath halted");
	if (mdd && ice_oicr_mdd(ice))
		fault = B_TRUE;

	/*
	 * Only fail the link closed when this function actually faulted; a
	 * malicious-driver event on another function must not down our link.
	 */
	if (fault) {
		mutex_enter(&ice->ice_lse_lock);
		ice->ice_link_state = LINK_STATE_DOWN;
		ice_link_state_set(ice, LINK_STATE_DOWN);
		mutex_exit(&ice->ice_lse_lock);
	}
}

/*
 * Taskq worker: decode the causes latched as persistent state, drain the admin
 * receive queue, and refresh link.  Driven both by the OICR and by the admin
 * periodic, so every step must be safe to repeat.  The drain loop is bounded
 * both by the firmware-reported pending count and by a hard element cap.
 */
static void
ice_oicr_task(void *arg)
{
	ice_t *ice = arg;
	struct ice_hw *hw = &ice->ice_hw;
	struct ice_rq_event_info evt;
	boolean_t media_inserted;
	uint16_t pending;
	uint_t guard = 0;
	uint32_t cause;
	boolean_t mdd;
	int rc;

	mutex_enter(&ice->ice_lock);
	ice->ice_oicr_pending = B_FALSE;
	cause = ice->ice_oicr_cause;
	ice->ice_oicr_cause = 0;
	mutex_exit(&ice->ice_lock);

	/*
	 * ice_rebuild_lock is the outermost lock and is taken only after
	 * ice_lock is dropped: everything below rides the admin queue or
	 * dereferences hw->port_info, which a reset rebuild shuts down and
	 * reinitializes.  Testing the reset state outside it would be a
	 * check-then-use race, since ice_prepare_for_reset sets reset_ongoing
	 * after the test would have passed.  ice_reset_dispatch only sets a
	 * flag and hands the rebuild to the reset taskq, which waits on this
	 * lock, so there is no self-deadlock.
	 */
	mutex_enter(&ice->ice_rebuild_lock);

	/*
	 * Gate before ice_oicr_fatal(): it reports the link down through the
	 * MAC handle, which detach is about to invalidate and attach has not
	 * yet created.  The datapath is already fenced by ICE_STATE_ERROR set
	 * in the ISR, so dropping the log line for a cause that lands outside
	 * the instance's lifetime is the right trade.  No work owed by that
	 * cause is dropped with it: every cause is carried as persistent state,
	 * so ice_reset_redispatch() requeues an owed rebuild when the gate
	 * lifts and the MDD decode below is retried on the next admin periodic.
	 *
	 * ICE_STATE_RESET_FAILED joins the gate because the admin periodic
	 * keeps firing on a terminally failed instance whose control queue
	 * ice_rebuild() has already shut down: without it every tick fails a
	 * drain and a link update and logs both at CE_WARN, forever.  FreeBSD
	 * skips control-queue work on the same bit (if_ice_iflib.c:2449).
	 */
	if (ice->ice_attaching || ice->ice_detaching ||
	    (ice->ice_state & ICE_STATE_RESET_FAILED) != 0) {
		mutex_exit(&ice->ice_rebuild_lock);
		return;
	}

	/*
	 * Test and clear before the decode, as FreeBSD's ice_handle_mdd_event()
	 * does (ice_lib.c:8339), so an MDD arriving during the decode gets its
	 * own later pass instead of being merged into this one.  It sits below
	 * the gate above -- which is the point of the persistent bit -- and
	 * above the reset skip below, because PF_MDET_* has reset source CORER
	 * and a PFR rebuild does not clear it: leaving it latched would
	 * misattribute another function's next event to us.  FreeBSD's admin
	 * task orders it the same way (if_ice_iflib.c:2447 precedes the
	 * control-queue skip at :2449).
	 */
	mdd = ice_state_testclear(ice, ICE_STATE_MDD_PENDING);

	if (cause != 0 || mdd)
		ice_oicr_fatal(ice, cause, mdd);

	/*
	 * A reset in progress or owed leaves the admin queue unusable or about
	 * to be rebuilt; skip the drain.  An owed rebuild is handed to the
	 * dedicated reset taskq -- it can run for seconds and shares this
	 * worker's single ice_aqbuf, so it must never run here -- unless the
	 * instance is terminally failed, which ice_reset_redispatch() honours.
	 */
	if (hw->reset_ongoing || (ice->ice_state &
	    (ICE_STATE_RESET_PENDING | ICE_STATE_PFR_REQ)) != 0) {
		ice_reset_redispatch(ice);
		mutex_exit(&ice->ice_rebuild_lock);
		return;
	}

	bzero(&evt, sizeof (evt));
	evt.buf_len = ICE_AQ_MAX_BUF_LEN;
	evt.msg_buf = ice->ice_aqbuf;

	do {
		rc = ice_clean_rq_elem(hw, &hw->adminq, &evt, &pending);
		if (rc == ICE_ERR_AQ_NO_WORK)
			break;
		if (rc != 0) {
			ice_error(ice, "admin receive queue clean failed: %d",
			    rc);
			break;
		}

		switch (LE_16(evt.desc.opcode)) {
		case ice_aqc_opc_get_link_status:
			ice_link_status_update_impl(ice, &media_inserted);
			if (media_inserted)
				ice_setup_link(ice);
			ice_phy_caps_update(ice);
			break;
		default:
			break;
		}
	} while (pending != 0 && ++guard < ICE_ARQ_MAX_ELEMS);

	if (guard >= ICE_ARQ_MAX_ELEMS) {
		ice_error(ice, "admin receive queue drain cap hit; pending %u",
		    pending);
	}

	/*
	 * Refresh link unconditionally, not just when the drain saw a
	 * get_link_status message.  Every cause this driver acts on is a
	 * one-shot latch, and ice_intr_oicr_setup() read-clears PFINT_OICR, so
	 * an event delivered while the OICR was masked leaves its message in
	 * the ring with no interrupt pending.  FreeBSD polls the same state
	 * from its admin timer for this reason (if_ice_iflib.c:2477).
	 */
	ice_link_status_update_impl(ice, NULL);

	mutex_exit(&ice->ice_rebuild_lock);
}

static void
ice_intr_oicr_enable(ice_t *ice)
{
	struct ice_hw *hw = &ice->ice_hw;

	wr32(hw, GLINT_DYN_CTL(ICE_OICR_VECTOR),
	    GLINT_DYN_CTL_INTENA_M | GLINT_DYN_CTL_CLEARPBA_M |
	    ((ICE_ITR_INDEX_NONE << GLINT_DYN_CTL_ITR_INDX_S) &
	    GLINT_DYN_CTL_ITR_INDX_M));
	ice_flush(hw);
}

/*
 * Admin periodic: drives the OICR worker from outside the ISR so every cause
 * is polled rather than trusted to a one-shot interrupt.  Mirrors FreeBSD's
 * ice_admin_timer (if_ice_iflib.c:2289), which runs at hz/2 whether or not the
 * interface is up, and each run covers what its admin task covers
 * (if_ice_iflib.c:2440-2477): an owed reset is redispatched, ICE_STATE_MDD_
 * PENDING is decoded, the control queue is drained, and link state is
 * refreshed unconditionally.  Without it a cause lost to a masked OICR or to
 * the attach/detach gate is never re-delivered: the port stays down, or an
 * owed reset or MDD decode never runs, for the life of the instance.
 */
static void
ice_admin_periodic(void *arg)
{
	ice_t *ice = arg;

	if (ice->ice_detaching || ice->ice_attaching)
		return;

	ice_oicr_resync(ice);
}

void
ice_admin_periodic_start(ice_t *ice)
{
	ice->ice_admin_periodic = ddi_periodic_add(ice_admin_periodic, ice,
	    ICE_ADMIN_PERIOD_NS, DDI_IPL_0);
}

void
ice_admin_periodic_stop(ice_t *ice)
{
	if (ice->ice_admin_periodic != NULL) {
		ddi_periodic_delete(ice->ice_admin_periodic);
		ice->ice_admin_periodic = NULL;
	}
}

/*
 * Drain the admin receive queue once from outside the ISR.  Used by the admin
 * periodic above and by attach, which must consume anything stranded before
 * the OICR was armed.
 */
void
ice_oicr_resync(ice_t *ice)
{
	if (ddi_taskq_dispatch(ice->ice_oicr_taskq, ice_oicr_task, ice,
	    DDI_NOSLEEP) != DDI_SUCCESS)
		ice_error(ice, "failed to dispatch admin queue resync");
}

void
ice_intr_oicr_disable(ice_t *ice)
{
	struct ice_hw *hw = &ice->ice_hw;

	wr32(hw, GLINT_DYN_CTL(ICE_OICR_VECTOR),
	    (ICE_ITR_INDEX_NONE << GLINT_DYN_CTL_ITR_INDX_S) &
	    GLINT_DYN_CTL_ITR_INDX_M);
	ice_flush(hw);
}

/*
 * Route and arm the OICR.  The mandatory read of PFINT_OICR below is
 * read-clear, so it destroys every cause latched since the register was last
 * reset.  When harvest is set those causes are converted to persistent state
 * first: on the attach path they were latched on this driver's watch, the
 * window is hundreds of milliseconds of firmware interaction, and nothing else
 * re-derives them.  The rebuild path must NOT harvest -- it has just performed
 * the owed rebuild and cleared the reset-owed bits, so re-latching would
 * dispatch the same rebuild in a loop.
 */
void
ice_intr_oicr_setup(ice_t *ice, boolean_t harvest)
{
	struct ice_hw *hw = &ice->ice_hw;
	uint32_t reg, oicr;

	/* Mask all causes and clear any stale status (the read clears it). */
	wr32(hw, PFINT_OICR_ENA, 0);
	oicr = rd32(hw, PFINT_OICR);

	if (harvest) {
		/*
		 * A severed bus reads all ones, which would synthesise a
		 * phantom GRST plus MDD plus every fatal cause.
		 */
		if (ice_check_acc_handle(ice->ice_osdep.ios_reg_handle) !=
		    DDI_FM_OK) {
			ddi_fm_service_impact(ice->ice_dip, DDI_SERVICE_LOST);
			atomic_or_32(&ice->ice_state, ICE_STATE_ERROR);
		} else {
			ice_oicr_causes_latch(ice, oicr);
		}
	}

	/* Route the FW/admin control-queue cause to vector 0, OTHER ITR. */
	reg = ((ICE_OICR_VECTOR << PFINT_FW_CTL_MSIX_INDX_S) &
	    PFINT_FW_CTL_MSIX_INDX_M) |
	    ((ICE_ITR_INDEX_OTHER << PFINT_FW_CTL_ITR_INDX_S) &
	    PFINT_FW_CTL_ITR_INDX_M) | PFINT_FW_CTL_CAUSE_ENA_M;
	wr32(hw, PFINT_FW_CTL, reg);

	/* Route the generic OICR cause (link change + errors) to vector 0. */
	reg = ((ICE_OICR_VECTOR << PFINT_OICR_CTL_MSIX_INDX_S) &
	    PFINT_OICR_CTL_MSIX_INDX_M) |
	    ((ICE_ITR_INDEX_OTHER << PFINT_OICR_CTL_ITR_INDX_S) &
	    PFINT_OICR_CTL_ITR_INDX_M) | PFINT_OICR_CTL_CAUSE_ENA_M;
	wr32(hw, PFINT_OICR_CTL, reg);

	wr32(hw, PFINT_OICR_ENA, ICE_OICR_ENA_MASK);

	ice_intr_oicr_enable(ice);
}

static uint_t
ice_intr_oicr(ice_t *ice)
{
	struct ice_hw *hw = &ice->ice_hw;
	boolean_t dispatch = B_FALSE;
	uint32_t oicr;

	oicr = rd32(hw, PFINT_OICR);

	if (ice_check_acc_handle(ice->ice_osdep.ios_reg_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(ice->ice_dip, DDI_SERVICE_DEGRADED);
		atomic_or_32(&ice->ice_state, ICE_STATE_ERROR);
		return (DDI_INTR_CLAIMED);
	}

	ice_oicr_causes_latch(ice, oicr);

	/*
	 * PFINT_FW_CTL and PFINT_OICR share this dedicated admin vector.  The
	 * hardware may clear PFINT_FW_CTL_INTEVENT while acknowledging the
	 * interrupt, so PFINT_OICR cannot reliably say whether the ARQ fired.
	 * Check it on every admin interrupt, as FreeBSD does.  The pending flag
	 * coalesces a burst into one single-threaded, bounded drain and packet
	 * queue interrupts use separate vectors.
	 */
	mutex_enter(&ice->ice_lock);
	ice->ice_oicr_cause |= oicr & ICE_OICR_CAUSE_MASK;
	if (!ice->ice_oicr_pending) {
		ice->ice_oicr_pending = B_TRUE;
		dispatch = B_TRUE;
	}
	mutex_exit(&ice->ice_lock);

	if (dispatch && ddi_taskq_dispatch(ice->ice_oicr_taskq, ice_oicr_task,
	    ice, DDI_NOSLEEP) != DDI_SUCCESS) {
		mutex_enter(&ice->ice_lock);
		ice->ice_oicr_pending = B_FALSE;
		mutex_exit(&ice->ice_lock);
		ice_error(ice, "OICR taskq dispatch failed");
	}

	ice_intr_oicr_enable(ice);
	return (DDI_INTR_CLAIMED);
}

static uint_t
ice_intr_queue(ice_t *ice, uint_t vector)
{
	struct ice_hw *hw = &ice->ice_hw;
	uint_t idx = vector - 1;

	/*
	 * Data queue i (rx and tx) is wired to vector i + 1 (ice_rx.c,
	 * ice_tx.c) and ice_nqueues never exceeds ice_intr_count - 1, so the
	 * firing vector maps directly to ring index vector - 1.  Indexing
	 * instead of scanning every ring keeps each ISR off the other queues'
	 * cache lines.  Vector 0 (OICR) never reaches here.  Rx delivery is
	 * suppressed while mac polls the ring (ice_rx_ring_intr).
	 */
	if (idx < ice->ice_num_rxr)
		ice_rx_ring_intr(&ice->ice_rxr[idx]);
	if (idx < ice->ice_num_txr)
		ice_tx_ring_intr(&ice->ice_txr[idx]);

	wr32(hw, GLINT_DYN_CTL(vector),
	    GLINT_DYN_CTL_INTENA_M | GLINT_DYN_CTL_CLEARPBA_M |
	    ((ICE_ITR_INDEX_NONE << GLINT_DYN_CTL_ITR_INDX_S) &
	    GLINT_DYN_CTL_ITR_INDX_M));
	ice_flush(hw);

	return (DDI_INTR_CLAIMED);
}

uint_t
ice_intr_msix(caddr_t arg1, caddr_t arg2)
{
	ice_t *ice = (ice_t *)arg1;
	uint_t vector = (uint_t)(uintptr_t)arg2;

	if (vector == ICE_OICR_VECTOR)
		return (ice_intr_oicr(ice));

	/*
	 * Only ice_intr_count handlers are registered, so vector is always in
	 * range; guard defensively so a stray vector cannot re-arm
	 * GLINT_DYN_CTL() for a vector this function does not own.
	 */
	if (vector >= (uint_t)ice->ice_intr_count)
		return (DDI_INTR_CLAIMED);

	return (ice_intr_queue(ice, vector));
}

boolean_t
ice_intr_enable(ice_t *ice)
{
	int i, rc;

	if (ice->ice_intr_cap & DDI_INTR_FLAG_BLOCK) {
		rc = ddi_intr_block_enable(ice->ice_intr_handles,
		    ice->ice_intr_count);
		if (rc != DDI_SUCCESS) {
			ice_error(ice, "interrupt block-enable failed: %d", rc);
			return (B_FALSE);
		}
		return (B_TRUE);
	}

	for (i = 0; i < ice->ice_intr_count; i++) {
		rc = ddi_intr_enable(ice->ice_intr_handles[i]);
		if (rc != DDI_SUCCESS) {
			ice_error(ice, "interrupt enable %d failed: %d", i, rc);
			while (--i >= 0) {
				(void) ddi_intr_disable(
				    ice->ice_intr_handles[i]);
			}
			return (B_FALSE);
		}
	}

	return (B_TRUE);
}

void
ice_intr_disable(ice_t *ice)
{
	int i;

	if (ice->ice_intr_handles == NULL)
		return;

	if (ice->ice_intr_cap & DDI_INTR_FLAG_BLOCK) {
		(void) ddi_intr_block_disable(ice->ice_intr_handles,
		    ice->ice_intr_count);
	} else {
		for (i = 0; i < ice->ice_intr_count; i++)
			(void) ddi_intr_disable(ice->ice_intr_handles[i]);
	}
}

/*
 * Bring the PHY up.  The active configuration can contain only the current
 * fallback mode, so use the full media/default capabilities to keep
 * autonegotiation from becoming pinned there.
 */
void
ice_setup_link(ice_t *ice)
{
	struct ice_hw *hw = &ice->ice_hw;
	struct ice_port_info *pi = hw->port_info;
	struct ice_aqc_get_phy_caps_data pcaps;
	struct ice_aqc_set_phy_cfg_data cfg;
	u8 report_mode = ice_fw_supports_report_dflt_cfg(hw) ?
	    ICE_AQC_REPORT_DFLT_CFG : ICE_AQC_REPORT_TOPO_CAP_MEDIA;
	int status;

	if (pi == NULL)
		return;

	bzero(&pcaps, sizeof (pcaps));
	status = ice_aq_get_phy_caps(pi, false, report_mode, &pcaps, NULL);
	if (status != ICE_SUCCESS) {
		ice_error(ice, "failed to read PHY caps: %d", status);
		return;
	}

	/*
	 * With no module, topology capabilities can be empty.  The insertion
	 * event will re-drive the configuration once media is identifiable.
	 */
	if (pcaps.phy_type_low == 0 && pcaps.phy_type_high == 0)
		return;

	bzero(&cfg, sizeof (cfg));
	ice_copy_phy_caps_to_cfg(pi, &pcaps, &cfg);
	(void) ice_cfg_phy_fec(pi, &cfg, ICE_FEC_AUTO);
	cfg.caps |= ICE_AQ_PHY_ENA_AUTO_LINK_UPDT | ICE_AQ_PHY_ENA_LINK;

	status = ice_aq_set_phy_cfg(hw, pi, &cfg, NULL);
	if (status != ICE_SUCCESS &&
	    hw->adminq.sq_last_status != ICE_AQ_RC_EBUSY)
		ice_error(ice, "failed to enable PHY: %d", status);
}

/*
 * Ask firmware to deliver link and media events on the admin receive queue.
 * The event mask is inverted: a clear bit means "deliver".
 */
boolean_t
ice_set_link_events(ice_t *ice)
{
	struct ice_hw *hw = &ice->ice_hw;
	struct ice_port_info *pi = hw->port_info;
	uint16_t mask;
	int rc;

	if (pi == NULL)
		return (B_FALSE);

	/*
	 * Also wake on media insert/remove and unqualified-module plug so the
	 * cached link/transceiver state stays current and a media-available
	 * transition can re-drive the PHY enable.
	 */
	mask = (uint16_t)~(ICE_AQ_LINK_EVENT_UPDOWN |
	    ICE_AQ_LINK_EVENT_MEDIA_NA | ICE_AQ_LINK_EVENT_MODULE_QUAL_FAIL);

	mutex_enter(&ice->ice_lse_lock);
	ice->ice_lse_flags |= ICE_LSE_F_ENABLE;
	mutex_exit(&ice->ice_lse_lock);

	rc = ice_aq_set_event_mask(hw, pi->lport, mask, NULL);
	if (rc != 0) {
		ice_error(ice, "failed to set link event mask: %d", rc);
		return (B_FALSE);
	}

	return (B_TRUE);
}
