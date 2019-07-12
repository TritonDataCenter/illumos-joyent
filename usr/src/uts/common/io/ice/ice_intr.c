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
 * ice(7D) interrupt management
 */

#include "ice.h"

static uintptr_t
ice_intr_itr_reg(ice_t *ice, ice_itr_index_t type, int intr)
{
	uintptr_t out = ICE_REG_GLINT_ITR_BASE;

	ASSERT3U(type, <, ICE_ITR_INDEX_NONE);
	ASSERT3U(intr, <=, ice->ice_nintrs);

	return (out + 0x2000 * type + 4 * intr);
}

static void
ice_intr_itr_set(ice_t *ice, ice_itr_index_t type, uint_t val)
{
	int i;

	for (i = 0; i < ice->ice_nintrs; i++) {
		ice_reg_write(ice, ice_intr_itr_reg(ice, type, i), val);
	}
}

static void
ice_intr_program(ice_t *ice, uintptr_t reg, uint_t msix, ice_itr_index_t itr)
{
	uint32_t val = ice_reg_read(ice, reg);

	val = ICE_REG_PFINT_MSIX_INDX_SET(val, msix);
	val = ICE_REG_PFINT_ITR_INDX_SET(val, itr);

	ice_reg_write(ice, reg, val);
}

static void
ice_intr_cause_disable(ice_t *ice, uintptr_t reg)
{
	uint32_t val = ice_reg_read(ice, reg);

	val = ICE_REG_PFINT_CAUSE_ENA_SET(val, 0);
	ice_reg_write(ice, reg, val);
}

static void
ice_intr_cause_enable(ice_t *ice, uintptr_t reg)
{
	uint32_t val = ice_reg_read(ice, reg);

	val = ICE_REG_PFINT_CAUSE_ENA_SET(val, 1);
	ice_reg_write(ice, reg, val);
}

static void
ice_intr_msix_enable(ice_t *ice, int vector)
{
	uintptr_t reg;
	uint32_t val = 0;

	ASSERT3S(vector, >=, 0);
	ASSERT3S(vector, <, ice->ice_nintrs);

	reg = vector * 4 + ICE_REG_GLINT_DYN_CTL_BASE;
	val = ICE_REG_GLINT_DYN_CTL_INTENA_SET(val);
	val = ICE_REG_GLINT_DYN_CTL_CLEARPBA_SET(val);
	val = ICE_REG_GLINT_DYN_CTL_ITR_INDX_SET(val, ICE_ITR_INDEX_NONE);

	ice_reg_write(ice, reg, val);
}

static void
ice_intr_msix_disable(ice_t *ice, int vector)
{
	uintptr_t reg;
	uint32_t val = 0;

	ASSERT3S(vector, >=, 0);
	ASSERT3S(vector, <, ice->ice_nintrs);

	reg = vector * 4 + ICE_REG_GLINT_DYN_CTL_BASE;

	val = ICE_REG_GLINT_DYN_CTL_ITR_INDX_SET(val, ICE_ITR_INDEX_NONE);
	ice_reg_write(ice, reg, val);
}

void
ice_intr_hw_fini(ice_t *ice)
{
	ice_intr_msix_disable(ice, 0);

	/*
	 * Clear all other cause values. Note, there is no explicit
	 * ice_intr_cause_disable required for this because the control for this is
	 * all based in the OICR enable.
	 */
	ice_reg_write(ice, ICE_REG_PFINT_OICR_ENA, 0);
	ice_intr_cause_disable(ice, ICE_REG_PFINT_FW_CTL);
}

/*
 * Program hardware to enable interrupts for the things that we care about.
 */
boolean_t
ice_intr_hw_init(ice_t *ice)
{
	uint_t i;
	uint32_t oicr = 0;

	/*
	 * In theory firmware should program this correctly. However, let's just
	 * make sure it's in a reasonable state.
	 */
	for (i = 0; i < ice->ice_nintrs; i++) {
		uintptr_t reg = ICE_REG_GLINT_VECT2FUNC_BASE + i * 4;
		uint32_t val = 0;

		val = ICE_REG_GLINT_VECT2FUNC_PF_NUM_SET(val, ice->ice_pf_id);
		val = ICE_REG_GLINT_VECT2FUNC_IS_PF_SET(val, 1);
		ice_reg_write(ice, reg, val);
	}

	ice_intr_itr_set(ice, ICE_ITR_INDEX_RX, ice->ice_itr_rx);
	ice_intr_itr_set(ice, ICE_ITR_INDEX_TX, ice->ice_itr_tx);
	ice_intr_itr_set(ice, ICE_ITR_INDEX_OTHER, ice->ice_itr_other);

	/*
	 * XXX Eventually program allocated RX and TX queues.
	 */
	ice_intr_program(ice, ICE_REG_PFINT_FW_CTL, 0, ICE_ITR_INDEX_OTHER);
	ice_intr_cause_enable(ice, ICE_REG_PFINT_FW_CTL);

	/*
	 * Set up the OICR register. First we want to make sure nothing that was
	 * previously there is present. To do that we have to make sure that we
	 * set the current register to zero and then do a read of the OICR. As
	 * it's an auto-clearing register, that should work fine.
	 */
	ice_reg_write(ice, ICE_REG_PFINT_OICR_ENA, 0);
	(void) ice_reg_read(ice, ICE_REG_PFINT_OICR);
	oicr = ICE_REG_PFINT_OICR_SET(oicr, ICE_REG_OICR_ECC_ERR, 1);
	oicr = ICE_REG_PFINT_OICR_SET(oicr, ICE_REG_OICR_MAL_DETECT, 1);
	oicr = ICE_REG_PFINT_OICR_SET(oicr, ICE_REG_OICR_GRST, 1);
	oicr = ICE_REG_PFINT_OICR_SET(oicr, ICE_REG_OICR_HMC_ERR, 1);
	ice_reg_write(ice, ICE_REG_PFINT_OICR_ENA, oicr);
	ice_intr_program(ice, ICE_REG_PFINT_OICR_CTL, 0, ICE_ITR_INDEX_OTHER);
	ice_intr_cause_enable(ice, ICE_REG_PFINT_OICR_CTL);

	/*
	 * XXX Enable interrupts other than Int 0.
	 */
	ice_intr_msix_enable(ice, 0);

	return (B_TRUE);
}

void
ice_intr_trigger_softint(ice_t *ice)
{
	uintptr_t reg = ICE_REG_GLINT_DYN_CTL_BASE;
	uint32_t val = 0;

	val = ICE_REG_GLINT_DYN_CTL_SWINT_TRIG_SET(val);
	val = ICE_REG_GLINT_DYN_CTL_ITR_INDX_SET(val, ICE_ITR_INDEX_NONE);
	val = ICE_REG_GLINT_DYN_CTL_INTENA_MSK_SET(val);
	ice_reg_write(ice, reg, val);
}

/*
 * We've had our miscellaneous interrupt fire. This means that we need to go
 * through and see what actions we need to take. Almost all of the actions that
 * this indicates are handled asynchronously. This includes processing the
 * following data sources:
 *
 *  o OICR
 *  o Admin queue
 *
 * As a side effect of this, the interrupt will be enabled again and by reading
 * the OICR, it will be cleared.
 */
static void
ice_intr_misc_work(ice_t *ice)
{
	ice_work_task_t work = ICE_WORK_NONE;
	uint32_t oicr;

	/*
	 * Hardware doesn't provide a way of knowing whether or not the receive
	 * side of the admin queue has fired or not. We must always assume it
	 * has and ask it to be read by users.
	 */
	work |= ICE_WORK_CONTROLQ;

	/*
	 * Read the OICR and see if it indicates we need to do anything. Note
	 * this has a side effect of clearing the OICR.
	 */
	oicr = ice_reg_read(ice, ICE_REG_PFINT_OICR);

	/*
	 * XXX All of these events need to be tracked and dealt with.
	 */
	if (ICE_REG_PFINT_OICR_GET(oicr, ICE_REG_OICR_ECC_ERR) != 0) {
		work |= ICE_WORK_NEED_RESET;
	}

	if (ICE_REG_PFINT_OICR_GET(oicr, ICE_REG_OICR_MAL_DETECT) != 0) {
		/*
		 * We are not currently enabling any VFs, so if this fires,
		 * that's a very suspicious thing and indicates that we need to
		 * question what's going on with hardware and probably deserves
		 * a reset.
		 */
		work |= ICE_WORK_NEED_RESET;
	}

	if (ICE_REG_PFINT_OICR_GET(oicr, ICE_REG_OICR_GRST) != 0) {
		work |= ICE_WORK_RESET_DETECTED;
	}

	if (ICE_REG_PFINT_OICR_GET(oicr, ICE_REG_OICR_HMC_ERR) != 0) {
		/* XXX Not clear what we should do here */
	}

	/* XXX Verify that we've dealt with all of OICR */
	ice_schedule(ice, work);

	/*
	 * Come back and re-enable this interrupt.
	 */
	ice_intr_msix_enable(ice, 0);
}

uint_t
ice_intr_msix(caddr_t arg, caddr_t arg2)
{
	ice_t *ice = (ice_t *)arg;
	uint_t vector = (uintptr_t)(void *)arg2;

	if (vector == 0) {
		ice_intr_misc_work(ice);
		return (DDI_INTR_CLAIMED);
	}

	ice_error(ice, "fired MSI-X interrupt %u", vector);
	return (DDI_INTR_CLAIMED);
}

uint_t
ice_intr_msi(caddr_t arg, caddr_t arg2)
{
	ice_t *ice = (ice_t *)arg;
	ice_error(ice, "fired MSI interrupt");
	return (DDI_INTR_CLAIMED);
}

uint_t
ice_intr_intx(caddr_t arg, caddr_t arg2)
{
	ice_t *ice = (ice_t *)arg;
	ice_error(ice, "fired INT-X interrupt");
	return (DDI_INTR_CLAIMED);
}
