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
 * This file implements the control queue interface
 *
 * XXX Assumptions we need to document: every register is the same in terms of
 * format, but the address is different.
 *  - Need to mention that RQ must be programmed before use
 *  - Need to mention that get version command is first command
 *  - Need to mention shutdown command
 */

#include "ice.h"

/*
 * In general, the various registers and bits from hardware are supposed to be
 * the same for programing the various registers. We check that this hasn't
 * changed below and define a single definition for them so as to keep the code
 * simpler.
 */
CTASSERT(ICE_REG_PF_FW_ATQBAL != ICE_REG_PF_FW_ARQBAL);
CTASSERT(ICE_REG_PF_FW_ATQBAH != ICE_REG_PF_FW_ARQBAH);
CTASSERT(ICE_REG_PF_FW_ATQLEN != ICE_REG_PF_FW_ARQLEN);
CTASSERT(ICE_REG_PF_FW_ATQH != ICE_REG_PF_FW_ARQH);
CTASSERT(ICE_REG_PF_FW_ATQT != ICE_REG_PF_FW_ARQT);
CTASSERT(ICE_REG_PC_FW_ATQLEN_ATQLEN_MASK == ICE_REG_PC_FW_ARQLEN_ATQLEN_MASK);
CTASSERT(ICE_REG_PC_FW_ATQLEN_ATQVFE == ICE_REG_PC_FW_ARQLEN_ATQVFE);
CTASSERT(ICE_REG_PC_FW_ATQLEN_ATQOVFL == ICE_REG_PC_FW_ARQLEN_ATQOVFL);
CTASSERT(ICE_REG_PC_FW_ATQLEN_ATQCRIT == ICE_REG_PC_FW_ARQLEN_ATQCRIT);
CTASSERT(ICE_REG_PC_FW_ATQLEN_ATQENABLE == ICE_REG_PC_FW_ARQLEN_ATQENABLE);

#define	ICE_CONTROLQ_LEN_MASK	ICE_REG_PC_FW_ATQLEN_ATQLEN_MASK
#define	ICE_CONTROLQ_ENABLE	ICE_REG_PC_FW_ATQLEN_ATQENABLE

/*
 * These are default times for us to wait for commands to complete. The default
 * is to wait 10ms for up to 100 times.
 */
clock_t icq_controlq_delay = 10000;	/* 10ms in us */
uint_t icq_controlq_count = 100;

static uint_t
ice_controlq_incr(ice_controlq_t *cqp, uint_t val)
{
	ASSERT3U(val, <, cqp->icq_nents);
	val++;
	val %= cqp->icq_nents;
	return (val);
}

static void
ice_controlq_free(ice_controlq_t *cqp)
{
	if (cqp->icq_data_dma != NULL) {
		uint_t i;
		ASSERT3U(cqp->icq_nents, !=, 0);

		for (i = 0; i < cqp->icq_nents; i++) {
			ice_dma_free(&cqp->icq_data_dma[i]);
		}
		kmem_free(cqp->icq_data_dma, sizeof (ice_dma_buffer_t) *
		    cqp->icq_nents);
	}
	ice_dma_free(&cqp->icq_dma);
	cv_destroy(&cqp->icq_cv);
	mutex_destroy(&cqp->icq_lock);
}

static boolean_t
ice_controlq_alloc(ice_t *ice, ice_controlq_t *cqp)
{
	size_t len;
	uint_t i;
	ddi_dma_attr_t attr;
	ddi_device_acc_attr_t acc;

	ASSERT3U(cqp->icq_nents, !=, 0);
	ASSERT3U(cqp->icq_bufsize, !=, 0);

	mutex_init(&cqp->icq_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&cqp->icq_cv, NULL, CV_DRIVER, NULL);

	len = cqp->icq_nents * sizeof (ice_cq_desc_t);
	ice_dma_acc_attr(ice, &acc);
	ice_dma_transfer_controlq_attr(ice, &attr);
	if (!ice_dma_alloc(ice, &cqp->icq_dma, &attr, &acc, B_TRUE, len,
	    B_FALSE)) {
		ice_controlq_free(cqp);
		ice_error(ice, "!failed to allocate controlq ring");
		return (B_FALSE);
	}

	cqp->icq_desc = (ice_cq_desc_t *)cqp->icq_dma.idb_va;
	len = sizeof (ice_dma_buffer_t) * cqp->icq_nents;
	cqp->icq_data_dma = kmem_zalloc(len, KM_NOSLEEP);
	if (cqp->icq_data_dma == NULL) {
		ice_error(ice, "!failed to allocate %lu bytes to track "
		    "contorlq buffers");
		ice_controlq_free(cqp);
		return (B_FALSE);
	}

	for (i = 0; i < cqp->icq_nents; i++) {
		if (!ice_dma_alloc(ice, &cqp->icq_data_dma[i], &attr, &acc,
		    B_TRUE, cqp->icq_bufsize, B_FALSE)) {
			ice_error(ice, "!failed to allocate controlq buffer %u",
			    i);
			ice_controlq_free(cqp);
			return (B_FALSE);
		}
	}

	return (B_TRUE);
}

static void
ice_controlq_pf_sq_regs(ice_controlq_t *cqp)
{
	cqp->icq_reg_head = ICE_REG_PF_FW_ATQH;
	cqp->icq_reg_tail = ICE_REG_PF_FW_ATQT;
	cqp->icq_reg_len = ICE_REG_PF_FW_ATQLEN;
	cqp->icq_reg_base_hi = ICE_REG_PF_FW_ATQBAH;
	cqp->icq_reg_base_lo = ICE_REG_PF_FW_ATQBAL;
}

static void
ice_controlq_pf_rq_regs(ice_controlq_t *cqp)
{
	cqp->icq_reg_head = ICE_REG_PF_FW_ARQH;
	cqp->icq_reg_tail = ICE_REG_PF_FW_ARQT;
	cqp->icq_reg_len = ICE_REG_PF_FW_ARQLEN;
	cqp->icq_reg_base_hi = ICE_REG_PF_FW_ARQBAH;
	cqp->icq_reg_base_lo = ICE_REG_PF_FW_ARQBAL;
}

/*
 * This is part of the teardown sequence as described in '9.5.4 Driver Unload
 * and Queue Shutdown'. It is assumed that someone has already called the queue
 * shutdown admin command.
 */
static void
ice_controlq_stop(ice_t *ice, ice_controlq_t *cqp)
{
	uint32_t val;

	if ((cqp->icq_flags & ICE_CONTROLQ_F_ENABLED) == 0) {
		return;
	}

	/*
	 * Make sure to turn off the enable bit first.
	 */
	val = ice_reg_read(ice, cqp->icq_reg_len);
	val &= ~ICE_CONTROLQ_ENABLE;
	ice_reg_write(ice, cqp->icq_reg_len, val);

	/*
	 * Now zero all the rest of the registers
	 */
	ice_reg_write(ice, cqp->icq_reg_len, 0);
	ice_reg_write(ice, cqp->icq_reg_base_hi, 0);
	ice_reg_write(ice, cqp->icq_reg_base_lo, 0);
	ice_reg_write(ice, cqp->icq_reg_head, 0);
	ice_reg_write(ice, cqp->icq_reg_tail, 0);

	cqp->icq_flags &= ~ICE_CONTROLQ_F_ENABLED;
}

/*
 * Follow the steps in '9.5.3 Initialization' to program and enable a given
 * controlq. Note, there are other constraints that are required to use the
 * controlq before it can generally be used.
 */
static void
ice_controlq_program(ice_t *ice, ice_controlq_t *cqp, uint_t tail)
{
	/*
	 * First zero the head and tail.
	 */
	ice_reg_write(ice, cqp->icq_reg_head, 0);
	ice_reg_write(ice, cqp->icq_reg_tail, 0);
	cqp->icq_head = 0;
	cqp->icq_tail = tail;

	/*
	 * Program the base and length registers, setting the enable bit.
	 */
	ice_reg_write(ice, cqp->icq_reg_base_lo,
	    cqp->icq_dma.idb_cookie.dmac_laddress & UINT32_MAX);
	ice_reg_write(ice, cqp->icq_reg_base_hi,
	    cqp->icq_dma.idb_cookie.dmac_laddress >> 32);

	VERIFY0(cqp->icq_nents & ~ICE_CONTROLQ_LEN_MASK);
	ice_reg_write(ice, cqp->icq_reg_len, cqp->icq_nents |
	    ICE_CONTROLQ_ENABLE);

	/*
	 * Update the tail now if it's non-zero.
	 */
	if (tail != 0) {
		ice_reg_write(ice, cqp->icq_reg_tail, tail);
	}

	cqp->icq_flags |= ICE_CONTROLQ_F_ENABLED;
}

/*
 * Reset a receive queue element into a state that makes sense for hardware to
 * receive it.
 */
static void
ice_controlq_rq_desc_reset(ice_controlq_t *cqp, uint_t ent)
{
	ice_cq_desc_t *desc;
	ice_dma_buffer_t *dmap;
	uint16_t flags = ICE_CQ_DESC_FLAGS_BUF;

	VERIFY3U(ent, <, cqp->icq_nents);
	desc = &cqp->icq_desc[ent];
	dmap = &cqp->icq_data_dma[ent];
	bzero(desc, sizeof (*desc));

	if (cqp->icq_bufsize > ICE_CQ_LARGE_BUF) {
		flags |= ICE_CQ_DESC_FLAGS_LB;
	}

	desc->icqd_flags = LE_16(flags);
	desc->icqd_data_len = LE_16(cqp->icq_bufsize);
	desc->icqd_command.icc_generic.iccg_data_high =
	    LE_32(dmap->idb_cookie.dmac_laddress >> 32);
	desc->icqd_command.icc_generic.iccg_data_low =
	    LE_32(dmap->idb_cookie.dmac_laddress & UINT32_MAX);
}

void
ice_controlq_fini(ice_t *ice)
{
	/*
	 * Attempt to shutdown the queue. If we can't, drive on.
	 */
	if (!ice_cmd_queue_shutdown(ice, B_TRUE)) {
		ice_error(ice, "!failed to shut down command queue, continuing "
		    "with controlq teardown");
	}
	ice_controlq_stop(ice, &ice->ice_arq);
	ice_controlq_stop(ice, &ice->ice_asq);
	ice_controlq_free(&ice->ice_arq);
	ice_controlq_free(&ice->ice_asq);
}

boolean_t
ice_controlq_init(ice_t *ice)
{
	uint_t i;
	int ret;

	ice->ice_asq.icq_nents = ICE_CONTROLQ_SQ_NENTS;
	ice->ice_asq.icq_bufsize = ICE_CONTROLQ_BUFSIZE;
	ice->ice_arq.icq_nents = ICE_CONTROLQ_RQ_NENTS;
	ice->ice_arq.icq_bufsize = ICE_CONTROLQ_BUFSIZE;

	if (!ice_controlq_alloc(ice, &ice->ice_asq)) {
		return (B_FALSE);
	}

	if (!ice_controlq_alloc(ice, &ice->ice_arq)) {
		ice_controlq_free(&ice->ice_asq);
		return (B_FALSE);
	}

	ice_controlq_pf_sq_regs(&ice->ice_asq);
	ice_controlq_program(ice, &ice->ice_asq, 0);

	ice_controlq_pf_rq_regs(&ice->ice_arq);
	for (i = 0; i < ice->ice_arq.icq_nents; i++) {
		ice_controlq_rq_desc_reset(&ice->ice_arq, i);

	}
	ICE_DMA_SYNC(ice->ice_arq.icq_dma, DDI_DMA_SYNC_FORDEV);
	ice_controlq_program(ice, &ice->ice_arq, ice->ice_arq.icq_nents - 1);

	if ((ret = ice_regs_check(ice)) != DDI_FM_OK) {
		ice_error(ice, "failed to program registers: FM I/O error: %d",
		    ret);
		/*
		 * It may be a little silly to try and shut down in face of an
		 * error, but we might as well give it a shot before we fail to
		 * attach.
		 */
		ice_controlq_fini(ice);
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * Process all extant entries in the receive side control queue. For each entry
 * received, turn around and prepare it again. The main item that we expect to
 * receive information about are link status notifications. These should all be
 * amortized and dealt with at the end. We note that we receive such link status
 * events, but as we need to send another one to re-arm it, we wait until we
 * have that in place before we do anything else.
 */
ice_work_task_t
ice_controlq_rq_process(ice_t *ice)
{
	ice_controlq_t *cqp = &ice->ice_arq;
	uint_t head, len;
	ice_work_task_t ret = ICE_WORK_NONE;

	mutex_enter(&cqp->icq_lock);
	len = ice_reg_read(ice, cqp->icq_reg_len);

	/*
	 * In the event that we have an overflow, assume that we've missed some
	 * number of work link status events. Normal processing of the queue
	 * below should cause us to hopefully recover.
	 *
	 * XXX There is probably other processing required here.
	 */
	if ((len & ICE_REG_PC_FW_ARQLEN_ATQOVFL) != 0) {
		ice_error(ice, "admin rq overflow");
		ret |= ICE_WORK_LINK_STATUS_EVENT;
	}

	if ((len & ICE_REG_PC_FW_ARQLEN_ATQCRIT) != 0) {
		ice_error(ice, "admin rq critical error");
		/* XXX How to handle */
	}

	head = ice_reg_read(ice, cqp->icq_reg_head);
	/* XXX DMA Sync */

	while (head != cqp->icq_head) {
		uint16_t opcode;
		ice_cq_desc_t *desc;

		desc = &cqp->icq_desc[cqp->icq_head];
		opcode = LE_16(desc->icqd_opcode);
		switch (opcode) {
		case ICE_CQ_OP_GET_LINK_STATUS:
			ret |= ICE_WORK_LINK_STATUS_EVENT;
			break;
		default:
			ice_error(ice, "reiceved unknown ARQ opcode: 0x%x, "
			    "ignoring", opcode);
		}

		/*
		 * Reset the descriptor for service in the ring.
		 */
		ice_controlq_rq_desc_reset(cqp, cqp->icq_head);
		cqp->icq_head = ice_controlq_incr(cqp, cqp->icq_head);
		cqp->icq_tail = ice_controlq_incr(cqp, cqp->icq_tail);
		ice_reg_write(ice, cqp->icq_reg_tail, cqp->icq_tail);
	}
	mutex_exit(&cqp->icq_lock);

	return (ret);
}

/*
 * Initialize a command structure for a basic direct command.
 */
static void
ice_cmd_direct_init(ice_cq_desc_t *desc, ice_cq_opcode_t op)
{
	bzero(desc, sizeof (ice_cq_desc_t));

	desc->icqd_flags = LE_16(ICE_CQ_DESC_FLAGS_SI);
	desc->icqd_opcode = LE_16(op);
}

static void
ice_cmd_indirect_init(ice_cq_desc_t *desc, ice_cq_opcode_t op, uint16_t len,
    boolean_t fw_read_buf)
{
	uint16_t flags;
	bzero(desc, sizeof (ice_cq_desc_t));

	ASSERT3U(len, <=, ICE_CQ_MAX_BUF);
	flags = ICE_CQ_DESC_FLAGS_SI | ICE_CQ_DESC_FLAGS_BUF;
	if (fw_read_buf) {
		flags |= ICE_CQ_DESC_FLAGS_RD;
	}
	if (len >= ICE_CQ_LARGE_BUF) {
		flags |= ICE_CQ_DESC_FLAGS_LB;
	}

	desc->icqd_flags = LE_16(flags);
	desc->icqd_opcode = LE_16(op);
	desc->icqd_data_len = LE_16(len);
}

typedef enum {
	ICE_CMD_COPY_NONE	= 0,
	ICE_CMD_COPY_TO_DEV	= 0x1,
	ICE_CMD_COPY_FROM_DEV	= 0x2,
	ICE_CMD_COPY_BOTH	= 3
} ice_cmd_copy_t;

/*
 * Submit a command to the send queue, bump the register that indicates that we
 * own it,
 * XXX Indirect commands are being punted on, we're not properly copying things
 * out.
 */
static boolean_t
ice_cmd_submit(ice_t *ice, ice_controlq_t *cqp, ice_cq_desc_t *desc, void *buf,
    ice_cmd_copy_t copy)
{
	uint_t i;
	ice_cq_desc_t *hwd;
	ice_dma_buffer_t *extra = NULL;

#ifdef	DEBUG
	if (buf == NULL) {
		ASSERT3U(copy, ==, ICE_CMD_COPY_NONE);
	} else {
		ASSERT3U(copy, !=, ICE_CMD_COPY_NONE);
		switch (copy) {
		case ICE_CMD_COPY_TO_DEV:
		case ICE_CMD_COPY_FROM_DEV:
		case ICE_CMD_COPY_BOTH:
			break;
		default:
			panic("ice bad command copy type: 0x%x", copy);
		}
	}
#endif

	mutex_enter(&cqp->icq_lock);
	while ((cqp->icq_flags & ICE_CONTROLQ_F_BUSY) != 0) {
		cv_wait(&cqp->icq_cv, &cqp->icq_lock);
	}

	/*
	 * If we don't believe the queue can't be used, then there's no point
	 * even trying to go any further. However, we must make sure that we
	 * notify anyone else who may be attempting to use it.
	 */
	if ((cqp->icq_flags & ICE_CONTROLQ_F_DEAD) != 0) {
		cv_broadcast(&cqp->icq_cv);
		mutex_exit(&cqp->icq_lock);
		return (B_FALSE);
	}

	cqp->icq_flags |= ICE_CONTROLQ_F_BUSY;
	mutex_exit(&cqp->icq_lock);

	hwd = &cqp->icq_desc[cqp->icq_tail];
	bcopy(desc, hwd, sizeof (ice_cq_desc_t));

	/*
	 * Check if we need to set up the secondary DMA buffer.
	 */
	if (buf != NULL) {
		ice_cq_cmd_generic_t *gen;

		extra = &cqp->icq_data_dma[cqp->icq_tail];
		gen = &hwd->icqd_command.icc_generic;
		gen->iccg_data_high = LE_32(extra->idb_cookie.dmac_laddress >>
		    32);
		gen->iccg_data_low = LE_32(extra->idb_cookie.dmac_laddress &
		    UINT32_MAX);

		/*
		 * XXX Come back to this, if hw returns a bad value, we'll
		 * overwrite our buffers, but this gets us off the ground
		 */
		bzero(extra->idb_va, extra->idb_len);
		if ((copy & ICE_CMD_COPY_TO_DEV) != 0) {
			bcopy(buf, extra->idb_va, LE_16(hwd->icqd_data_len));
		}
		ICE_DMA_SYNC(*extra, DDI_DMA_SYNC_FORDEV);
	}

	ICE_DMA_SYNC(ice->ice_arq.icq_dma, DDI_DMA_SYNC_FORDEV);

	cqp->icq_tail = ice_controlq_incr(cqp, cqp->icq_tail);
	ice_reg_write(ice, cqp->icq_reg_tail, cqp->icq_tail);
	for (i = 0; i < icq_controlq_count; i++) {
		uint32_t head;

		head = ice_reg_read(ice, cqp->icq_reg_head);
		if (head == cqp->icq_tail)
			break;

		delay(drv_usectohz(icq_controlq_delay));
	}

	cqp->icq_head = ice_reg_read(ice, cqp->icq_reg_head);
	mutex_enter(&cqp->icq_lock);
	cqp->icq_flags &= ~ICE_CONTROLQ_F_BUSY;

	if (cqp->icq_head != cqp->icq_tail) {
		ice_error(ice, "Command 0x%x timed out! Marking "
		    "adminq dead", LE_16(desc->icqd_opcode));
		cqp->icq_flags |= ICE_CONTROLQ_F_DEAD;
		cv_signal(&cqp->icq_cv);
		mutex_exit(&cqp->icq_lock);
		return (B_FALSE);
	}

	ICE_DMA_SYNC(ice->ice_arq.icq_dma, DDI_DMA_SYNC_FORKERNEL);

	/*
	 * Verify that DD is set.
	 */
	if ((LE_16(hwd->icqd_flags) & ICE_CQ_DESC_FLAGS_DD) == 0) {
		ice_error(ice, "Hardware incremented tail, but DD missing "
		    "from command 0x%x, flags: 0x%x; marking admin queue dead",
		    LE_16(desc->icqd_opcode), LE_16(desc->icqd_flags));
		cqp->icq_flags |= ICE_CONTROLQ_F_DEAD;
		cv_signal(&cqp->icq_cv);
		mutex_exit(&cqp->icq_lock);
		return (B_FALSE);
	}

	bcopy(hwd, desc, sizeof (ice_cq_desc_t));
	if ((copy & ICE_CMD_COPY_FROM_DEV) != 0) {
		ICE_DMA_SYNC(*extra, DDI_DMA_SYNC_FORKERNEL);
		bcopy(extra->idb_va, buf, LE_16(hwd->icqd_data_len));
	}

	cv_signal(&cqp->icq_cv);
	mutex_exit(&cqp->icq_lock);
	return (B_TRUE);
}

static boolean_t
ice_cmd_result(ice_cq_desc_t *desc, ice_cq_errno_t *errp, uint8_t *hwcode)
{
	uint16_t ret = LE_16(desc->icqd_id_ret);

	if (ret == 0) {
		*errp = ICE_CQ_SUCCESS;
		*hwcode = 0;
		return (B_TRUE);
	}

	*errp = (ret & ICE_CQ_ERR_CODE_MASK);
	*hwcode = ((ret & ICE_CQ_ERR_CODE_FW_MASK) >> ICE_CQ_ERR_CODE_FW_SHIFT);

	return (B_FALSE);
}

/*
 * Query the firmware for its version information and store that on the ice_t as
 * appropriate.
 */
boolean_t
ice_cmd_get_version(ice_t *ice, ice_fw_info_t *ifi)
{
	ice_cq_desc_t desc;
	ice_cq_errno_t err;
	uint8_t hw;
	ice_cq_cmd_get_version_t *gvp;

	ice_cmd_direct_init(&desc, ICE_CQ_OP_GET_VER);
	if (!ice_cmd_submit(ice, &ice->ice_asq, &desc, NULL,
	    ICE_CMD_COPY_NONE)) {
		return (B_FALSE);
	}

	if (!ice_cmd_result(&desc, &err, &hw)) {
		ice_error(ice, "get version command failed with: 0x%x "
		    "(fw private: %x)", err, hw);
		return (B_FALSE);
	}

	gvp = &desc.icqd_command.icc_get_version;
	ifi->ifi_fw_branch = gvp->iccgv_fw_branch;
	ifi->ifi_fw_branch = gvp->iccgv_fw_branch;
	ifi->ifi_fw_major = gvp->iccgv_fw_major;
	ifi->ifi_fw_minor = gvp->iccgv_fw_minor;
	ifi->ifi_fw_patch = gvp->iccgv_fw_patch;
	ifi->ifi_aq_branch = gvp->iccgv_aq_branch;
	ifi->ifi_aq_major = gvp->iccgv_aq_major;
	ifi->ifi_aq_minor = gvp->iccgv_aq_minor;
	ifi->ifi_aq_patch = gvp->iccgv_aq_patch;
	ifi->ifi_rom_build = LE_32(gvp->iccgv_rom_build);
	ifi->ifi_fw_build = LE_32(gvp->iccgv_fw_build);

	return (B_TRUE);
}

boolean_t
ice_cmd_queue_shutdown(ice_t *ice, boolean_t unload)
{
	ice_cq_desc_t desc;
	ice_cq_errno_t err;
	uint8_t hw;
	ice_cq_cmd_queue_shutdown_t *qsp;

	ice_cmd_direct_init(&desc, ICE_CQ_OP_QUEUE_SHUTDOWN);
	qsp = &desc.icqd_command.icc_queue_shutdown;
	if (unload) {
		qsp->iccqs_flags |= ICE_CQ_CMD_QUEUE_SHUTDOWN_UNLOADING;
	}

	if (!ice_cmd_submit(ice, &ice->ice_asq, &desc, NULL,
	    ICE_CMD_COPY_NONE)) {
		return (B_FALSE);
	}

	if (!ice_cmd_result(&desc, &err, &hw)) {
		ice_error(ice, "queue shutdown command failed with: 0x%x "
		    "(fw private: %x)", err, hw);
		return (B_FALSE);
	}

	return (B_TRUE);
}

boolean_t
ice_cmd_clear_pf_config(ice_t *ice)
{
	ice_cq_desc_t desc;
	ice_cq_errno_t err;
	uint8_t hw;

	ice_cmd_direct_init(&desc, ICE_CQ_OP_CLEAR_PF_CONFIGURATION);
	if (!ice_cmd_submit(ice, &ice->ice_asq, &desc, NULL,
	    ICE_CMD_COPY_NONE)) {
		return (B_FALSE);
	}

	if (!ice_cmd_result(&desc, &err, &hw)) {
		ice_error(ice, "clear pf config command failed with: 0x%x "
		    "(fw private: %x)", err, hw);
		return (B_FALSE);
	}

	return (B_TRUE);

}

boolean_t
ice_cmd_clear_pxe(ice_t *ice)
{
	ice_cq_desc_t desc;
	ice_cq_errno_t err;
	uint8_t hw;
	ice_cq_cmd_clear_pxe_t *cpp;

	ice_cmd_direct_init(&desc, ICE_CQ_OP_CLEAR_PXE);
	cpp = &desc.icqd_command.icc_clear_pxe;
	cpp->icccp_flags = ICE_CQ_CLEAR_PXE_FLAG;

	if (!ice_cmd_submit(ice, &ice->ice_asq, &desc, NULL,
	    ICE_CMD_COPY_NONE)) {
		return (B_FALSE);
	}

	/*
	 * If PXE has already been cleared, then this command is defined to
	 * return EEXIST. We need to check against that and not fail the command
	 * if that happens.
	 */
	if (!ice_cmd_result(&desc, &err, &hw) && err != ICE_CQ_EEXIST) {
		ice_error(ice, "clear pxe command failed with: 0x%x "
		    "(fw private: %x)", err, hw);
		return (B_FALSE);
	}

	return (B_TRUE);
}

boolean_t
ice_cmd_release_nvm(ice_t *ice)
{
	ice_cq_desc_t desc;
	ice_cq_errno_t err;
	uint8_t hw;
	ice_cq_cmd_request_resource_t *rsrc;

#ifdef	DEBUG
	mutex_enter(&ice->ice_nvm.in_lock);
	ASSERT(ice->ice_nvm.in_flags & ICE_NVM_LOCKED);
	mutex_exit(&ice->ice_nvm.in_lock);
#endif

	ice_cmd_direct_init(&desc, ICE_CQ_OP_RELEASE_RESOURCE);
	rsrc = &desc.icqd_command.icc_request_resource;
	rsrc->iccrr_res_id = LE_16(ICE_CQ_RESOURCE_NVM);
	rsrc->iccrr_res_number = 0;

	if (!ice_cmd_submit(ice, &ice->ice_asq, &desc, NULL,
	    ICE_CMD_COPY_NONE)) {
		return (B_FALSE);
	}

	if (!ice_cmd_result(&desc, &err, &hw)) {
		ice_error(ice, "NVM release resource command failed with: 0x%x "
		    "(fw private: %x)", err, hw);
		return (B_FALSE);
	}

	mutex_enter(&ice->ice_nvm.in_lock);
	ice->ice_nvm.in_flags &= ~ICE_NVM_LOCKED;
	mutex_exit(&ice->ice_nvm.in_lock);

	return (B_TRUE);
}

boolean_t
ice_cmd_acquire_nvm(ice_t *ice, boolean_t write)
{
	ice_cq_desc_t desc;
	ice_cq_errno_t err;
	uint8_t hw;
	ice_cq_cmd_request_resource_t *rsrc;

#ifdef	DEBUG
	mutex_enter(&ice->ice_nvm.in_lock);
	ASSERT0(ice->ice_nvm.in_flags & ICE_NVM_LOCKED);
	mutex_exit(&ice->ice_nvm.in_lock);
#endif

	ice_cmd_direct_init(&desc, ICE_CQ_OP_REQUEST_RESOURCE);
	rsrc = &desc.icqd_command.icc_request_resource;
	rsrc->iccrr_res_id = LE_16(ICE_CQ_RESOURCE_NVM);
	if (write) {
		rsrc->iccrr_acc_type = LE_16(ICE_CQ_ACCESS_WRITE);
		rsrc->iccrr_timeout = LE_32(ICE_CQ_TIMEOUT_NVM_WRITE);
	} else {
		rsrc->iccrr_acc_type = LE_16(ICE_CQ_ACCESS_READ);
		rsrc->iccrr_timeout = LE_32(ICE_CQ_TIMEOUT_NVM_READ);
	}
	rsrc->iccrr_res_number = 0;

	if (!ice_cmd_submit(ice, &ice->ice_asq, &desc, NULL,
	    ICE_CMD_COPY_NONE)) {
		return (B_FALSE);
	}

	if (!ice_cmd_result(&desc, &err, &hw)) {
		ice_error(ice, "NVM request resource command failed with: 0x%x "
		    "(fw private: %x)", err, hw);
		return (B_FALSE);
	}

	mutex_enter(&ice->ice_nvm.in_lock);
	ice->ice_nvm.in_flags |= ICE_NVM_LOCKED;
	mutex_exit(&ice->ice_nvm.in_lock);

	return (B_TRUE);
}

boolean_t
ice_cmd_nvm_read(ice_t *ice, uint16_t module, uint32_t offset, uint16_t *lenp,
    uint16_t *outp, boolean_t last)
{
	ice_cq_desc_t desc;
	uint32_t bpage, fpage;
	ice_cq_cmd_nvm_read_t *read;
	ice_cq_errno_t err;
	uint8_t hw;

	ice_nvm_t *nvm = &ice->ice_nvm;
	uint16_t len = *lenp;

#ifdef DEBUG
	mutex_enter(&nvm->in_lock);
	VERIFY(nvm->in_flags & ICE_NVM_LOCKED);
	mutex_exit(&nvm->in_lock);
#endif

	/*
	 * We can only read up to 4k at a time and we cannot cross a 4k sector.
	 * Also, we only have three bytes of offset, therefore if offset has
	 * invalid bits set, that's an error.
	 */
	if ((offset & 0xff000000) != 0 || len > nvm->in_sector) {
		ice_error(ice, "invalid nvm read offset or length");
		return (B_FALSE);
	}
	bpage = offset & ~(nvm->in_sector - 1);
	fpage = (offset + len) & ~(nvm->in_sector - 1);
	if (bpage != fpage) {
		ice_error(ice, "NVM read crosses pages, 0x%x, 0x%x",
		    bpage, fpage);
		return (B_FALSE);
	}

	ice_cmd_indirect_init(&desc, ICE_CQ_OP_NVM_READ, len, B_FALSE);
	read = &desc.icqd_command.icc_nvm_read;
	read->iccnr_offset[0] = offset & 0xff;
	read->iccnr_offset[1] = (offset >> 8) & 0xff;
	read->iccnr_offset[2] = (offset >> 16) & 0xff;
	if (last) {
		read->iccnr_flags |= ICE_CQ_NVM_READ_LAST_COMMAND;
	}
	read->iccnr_module_type = LE_16(module);
	read->iccnr_length = LE_16(len);

	if (!ice_cmd_submit(ice, &ice->ice_asq, &desc, outp,
	    ICE_CMD_COPY_FROM_DEV)) {
		return (B_FALSE);
	}

	if (!ice_cmd_result(&desc, &err, &hw)) {
		ice_error(ice, "failed to read %d bytes at off %x with: 0x%x "
		    "(fw private: %x)", len, offset, err, hw);
		return (B_FALSE);
	}

	*lenp = LE_16(desc.icqd_data_len);

	return (B_TRUE);
}

/*
 * We need to obtain all of the capabilities based on the type listed. We do
 * this in two pases. The first to get the exact number of capabilities, the
 * second to get all of them. We guess a given number of caps, but throw that
 * out
 */
boolean_t
ice_cmd_get_caps(ice_t *ice, boolean_t device, uint_t *ncapsp,
    ice_capability_t **capp)
{
	ice_cq_desc_t desc;
	uint_t ncaps = 1;
	ice_capability_t *cap;
	uint16_t len;
	ice_cq_opcode_t op;
	ice_cq_errno_t err;
	uint8_t hw;

	if (device) {
		op = ICE_CQ_OP_DISCOVER_DEVICE_CAPS;
	} else {
		op = ICE_CQ_OP_DISCOVER_FUNCTION_CAPS;
	}

	len = ncaps * sizeof (*cap);
	cap = kmem_zalloc(sizeof (*cap) * ncaps, KM_SLEEP);

	ice_cmd_indirect_init(&desc, op, len, B_FALSE);

	if (!ice_cmd_submit(ice, &ice->ice_asq, &desc, cap,
	    ICE_CMD_COPY_FROM_DEV)) {
		goto err;
	}

	if (!ice_cmd_result(&desc, &err, &hw) && err != ICE_CQ_ENOMEM) {
		ice_error(ice, "failed to get capabilities: 0x%x "
		    "(fw private: %x)", err, hw);
		goto err;
	}
	kmem_free(cap, sizeof (*cap) * ncaps);
	cap = NULL;
	/*
	 * The number of capabilities are returned in param 1.
	 */
	ncaps = LE_32(desc.icqd_command.icc_generic.iccg_param1);
	if (UINT16_MAX / sizeof (*cap) > ICE_CQ_MAX_BUF) {
		ice_error(ice, "invalid number of caps returned, would "
		    "overflow max buf");
		goto err;
	}

	len = ncaps * sizeof (*cap);
	cap = kmem_zalloc(len, KM_SLEEP);

	ice_cmd_indirect_init(&desc, op, len, B_FALSE);
	if (!ice_cmd_submit(ice, &ice->ice_asq, &desc, cap,
	    ICE_CMD_COPY_FROM_DEV)) {
		goto err;
	}

	if (!ice_cmd_result(&desc, &err, &hw)) {
		ice_error(ice, "failed to get capabilities: 0x%x "
		    "(fw private: %x)", err, hw);
		goto err;
	}

	*ncapsp = ncaps;
	*capp = cap;

	return (B_TRUE);
err:
	if (cap != NULL) {
		kmem_free(cap, sizeof (*cap) * ncaps);
	}
	return (B_FALSE);
}

boolean_t
ice_cmd_mac_read(ice_t *ice, uint8_t *addr)
{
	uint8_t buf[ICE_CQ_MANAGE_MAC_READ_BUFSIZE];
	ice_cq_desc_t desc;
	ice_cq_errno_t err;
	uint8_t hw, i, maxaddr;
	ice_hw_mac_t *macp;
	ice_cq_cmd_manage_mac_read_t *cmdp;
	uint16_t flags;

	bzero(buf, sizeof (buf));

	ice_cmd_indirect_init(&desc, ICE_CQ_OP_MANAGE_MAC_READ, sizeof (buf),
	    B_FALSE);
	if (!ice_cmd_submit(ice, &ice->ice_asq, &desc, buf,
	    ICE_CMD_COPY_FROM_DEV)) {
		return (B_FALSE);
	}

	if (!ice_cmd_result(&desc, &err, &hw)) {
		ice_error(ice, "failed to read MAC address: 0x%x "
		    "(fw private: %x)", err, hw);
		return (B_FALSE);
	}

	cmdp = &desc.icqd_command.icc_mac_read;
	macp = (ice_hw_mac_t *)buf;

	flags = LE_16(cmdp->iccmmr_flags);
	if ((flags & ICE_CQ_MANAGE_MAC_READ_LAN_VALID) == 0) {
		ice_error(ice, "failed to obtain a valid MAC address");
		return (B_FALSE);
	}

	/*
	 * Determine the maximum valid MAC address we can have here. Since we
	 * only have a fixed buffer size, use that as a starting point and then
	 * take the minimum of that and hardware.
	 */
	maxaddr = ICE_CQ_MANAGE_MAC_READ_BUFSIZE / sizeof (ice_hw_mac_t);
	for (i = 0; i < MIN(maxaddr, cmdp->iccmmr_count); i++) {
		if (macp->ihm_type == ICE_HW_MAC_TYPE_LAN) {
			if (macp->ihm_mac[0] & 0x01) {
				ice_error(ice, "encountered illegal mcast "
				    "address as primary MAC: %02x:%02x:%02x:"
				    "%02x:%02x:%02x", macp->ihm_mac[0],
				    macp->ihm_mac[1], macp->ihm_mac[2],
				    macp->ihm_mac[3], macp->ihm_mac[4],
				    macp->ihm_mac[5]);
				continue;
			}

			if (macp->ihm_mac[0] == 0 && macp->ihm_mac[1] == 0 &&
			    macp->ihm_mac[2] == 0 && macp->ihm_mac[3] == 0 &&
			    macp->ihm_mac[4] == 0 && macp->ihm_mac[5] == 0) {
				ice_error(ice, "encountered all zeros MAC");
				continue;
			}

			bcopy(macp->ihm_mac, addr, ETHERADDRL);

			return (B_TRUE);
		}
	}

	ice_error(ice, "failed to find a valid MAC address");
	return (B_FALSE);
}

boolean_t
ice_cmd_get_phy_abilities(ice_t *ice, ice_phy_abilities_t *datap,
    boolean_t modules)
{
	ice_cq_desc_t desc;
	ice_cq_cmd_get_phy_abilities_t *phy;
	ice_cq_errno_t err;
	uint8_t hw;
	uint16_t flags;

	ice_cmd_indirect_init(&desc, ICE_CQ_OP_GET_PHY_ABILITIES,
	    sizeof (*datap), B_FALSE);
	phy = &desc.icqd_command.icc_phy_abilities;
	flags = ICE_CQ_GET_PHY_ABILITIES_REPORT_MEDIA;
	if (modules) {
		flags |= ICE_CQ_GET_PHY_ABILITIES_REPORT_MODS;
	}
	phy->iccgpa_param0 = LE_16(flags);

	if (!ice_cmd_submit(ice, &ice->ice_asq, &desc, datap,
	    ICE_CMD_COPY_FROM_DEV)) {
		return (B_FALSE);
	}

	if (!ice_cmd_result(&desc, &err, &hw)) {
		ice_error(ice, "failed to read PHY abilities: 0x%x "
		    "(fw private: %x)", err, hw);
		return (B_FALSE);
	}

	/*
	 * Fix up endian issues.
	 */
	datap->ipa_eee = LE_16(datap->ipa_eee);
	datap->ipa_eeer = LE_16(datap->ipa_eeer);

	return (B_TRUE);
}

boolean_t
ice_cmd_get_link_status(ice_t *ice, ice_link_status_t *linkp, ice_lse_t lse)
{
	ice_cq_desc_t desc;
	ice_cq_cmd_get_link_status_t *status;
	ice_cq_errno_t err;
	uint8_t hw;
	uint16_t flags;

	ice_cmd_indirect_init(&desc, ICE_CQ_OP_GET_LINK_STATUS, sizeof (*linkp),
	    B_FALSE);
	status = &desc.icqd_command.icc_get_link_status;
	switch (lse) {
	case ICE_LSE_NO_CHANGE:
		flags = ICE_CQ_GET_LINK_STATUS_LSE_NOP;
		break;
	case ICE_LSE_ENABLE:
		flags = ICE_CQ_GET_LINK_STATUS_LSE_ENABLE;
		break;
	case ICE_LSE_DISABLE:
		flags = ICE_CQ_GET_LINK_STATUS_LSE_DISABLE;
		break;
	default:
		return (B_FALSE);
	}
	status->iccgls_flags = LE_16(flags);

	if (!ice_cmd_submit(ice, &ice->ice_asq, &desc, linkp,
	    ICE_CMD_COPY_FROM_DEV)) {
		return (B_FALSE);
	}

	if (!ice_cmd_result(&desc, &err, &hw)) {
		ice_error(ice, "failed to get link status: 0x%x "
		    "(fw private: %x)", err, hw);
		return (B_FALSE);
	}

	linkp->ils_frame = LE_16(linkp->ils_frame);
	linkp->ils_curspeed = LE_16(linkp->ils_curspeed);

	return (B_TRUE);
}

boolean_t
ice_cmd_set_event_mask(ice_t *ice, uint16_t mask)
{
	ice_cq_desc_t desc;
	ice_cq_errno_t err;
	uint8_t hw;
	ice_cq_cmd_set_event_mask_t *emp;

	ice_cmd_direct_init(&desc, ICE_CQ_OP_SET_EVENT_MASK);
	emp = &desc.icqd_command.icc_set_event_mask;
	emp->iccsem_mask = LE_16(mask);

	if (!ice_cmd_submit(ice, &ice->ice_asq, &desc, NULL,
	    ICE_CMD_COPY_NONE)) {
		return (B_FALSE);
	}

	if (!ice_cmd_result(&desc, &err, &hw)) {
		ice_error(ice, "set event mask command failed with: 0x%x "
		    "(fw private: %x)", err, hw);
		return (B_FALSE);
	}

	return (B_TRUE);
}

boolean_t
ice_cmd_setup_link(ice_t *ice, boolean_t enable)
{
	ice_cq_desc_t desc;
	ice_cq_errno_t err;
	uint8_t hw;
	ice_cq_cmd_setup_link_t *setup;

	ice_cmd_direct_init(&desc, ICE_CQ_OP_SETUP_LINK);
	setup = &desc.icqd_command.icc_setup_link;
	setup->iccsl_flags = ICE_CQ_SETUP_LINK_RESTART_LINK;
	if (enable) {
		setup->iccsl_flags |= ICE_CQ_SETUP_LINK_ENABLE_LINK;
	}

	if (!ice_cmd_submit(ice, &ice->ice_asq, &desc, NULL,
	    ICE_CMD_COPY_NONE)) {
		return (B_FALSE);
	}

	if (!ice_cmd_result(&desc, &err, &hw)) {
		ice_error(ice, "setup link command failed with: 0x%x "
		    "(fw private: %x)", err, hw);
		return (B_FALSE);
	}

	return (B_TRUE);
}

boolean_t
ice_cmd_get_switch_config(ice_t *ice, void *buf, size_t bufsize, uint16_t first,
    uint16_t *neltsp, uint16_t *nexteltp)
{
	ice_cq_desc_t desc;
	ice_cq_errno_t err;
	uint8_t hw;
	ice_cq_cmd_get_switch_config_t *config;
	ice_hw_switch_config_t *swconf;
	uint16_t nelts, i;

	/*
	 * Hardware says that the maximum allowed size is 2k. Limit this if it
	 * would otherwise be too large.
	 */
	bufsize = MIN(bufsize, ICE_CQ_GET_SWITCH_CONFIG_BUF_MAX);
	ice_cmd_indirect_init(&desc, ICE_CQ_OP_GET_SWITCH_CONFIG, bufsize,
	    B_FALSE);
	config = &desc.icqd_command.icc_get_switch_config;
	config->iccgsc_next_elt = LE_16(first);

	if (!ice_cmd_submit(ice, &ice->ice_asq, &desc, buf,
	    ICE_CMD_COPY_FROM_DEV)) {
		return (B_FALSE);
	}

	if (!ice_cmd_result(&desc, &err, &hw)) {
		ice_error(ice, "failed to get link status: 0x%x "
		    "(fw private: %x)", err, hw);
		return (B_FALSE);
	}

	nelts = LE_16(config->iccgsc_nelts);
	if (nelts > bufsize / sizeof (ice_hw_switch_config_t)) {
		ice_error(ice, "hardware told us we had more elements than we "
		    "gave it buffer for, got %u switch elements, but the "
		    "buffer was %lx bytes large", nelts, bufsize);
		return (B_FALSE);
	}

	*neltsp = nelts;
	*nexteltp = LE_16(config->iccgsc_next_elt);

	swconf = buf;
	for (i = 0; i < nelts; i++) {
		swconf[i].isc_vsi_info = LE_16(swconf[i].isc_vsi_info);
		swconf[i].isc_swid = LE_16(swconf[i].isc_swid);
		swconf[i].isc_pfid = LE_16(swconf[i].isc_pfid);
	}

	return (B_TRUE);
}

boolean_t
ice_cmd_free_vsi(ice_t *ice, ice_vsi_t *vsi, boolean_t keep)
{
	ice_cq_desc_t desc;
	ice_cq_errno_t err;
	uint8_t hw;
	ice_cq_cmd_free_vsi_t *freep;

	if ((vsi->ivsi_flags & ICE_VSI_F_ACTIVE) == 0) {
		ice_error(ice, "asked to remove non-active VSI with ID %u",
		    vsi->ivsi_id);
		return (B_FALSE);
	}

	ice_cmd_direct_init(&desc, ICE_CQ_OP_FREE_VSI);
	freep = &desc.icqd_command.icc_free_vsi;
	freep->iccfv_vsi = LE_16(vsi->ivsi_id | ICE_CQ_VSI_VALID);
	if (keep) {
		freep->iccfv_flags = LE_16(ICE_CQ_VSI_KEEP_ALLOC);
	}

	if (!ice_cmd_submit(ice, &ice->ice_asq, &desc, NULL,
	    ICE_CMD_COPY_NONE)) {
		return (B_FALSE);
	}

	if (!ice_cmd_result(&desc, &err, &hw)) {
		ice_error(ice, "free vsi (%u) command failed with: 0x%x "
		    "(fw private: %x)", vsi->ivsi_id, err, hw);
		return (B_FALSE);
	}

	return (B_TRUE);
}

boolean_t
ice_cmd_add_vsi(ice_t *ice, ice_vsi_t *vsi)
{
	ice_cq_desc_t desc;
	ice_cq_errno_t err;
	uint8_t hw;
	ice_cq_cmd_add_vsi_t *add;
	ice_cq_cmd_add_vsi_reply_t *reply;
	uint16_t hw_type;

	if ((vsi->ivsi_flags & ICE_VSI_F_POOL_ALLOC) == 0 &&
	    vsi->ivsi_id >= ICE_MAX_VSIS) {
		ice_error(ice, "asked to remove VSI ID %u larger than maximum",
		    vsi->ivsi_id);
		return (B_FALSE);
	}

	if (vsi->ivsi_type != ICE_VSI_TYPE_PF) {
		ice_error(ice, "asked to add support for a non-PF VSI");
		return (B_FALSE);
	}

	ice_cmd_indirect_init(&desc, ICE_CQ_OP_ADD_VSI,
	    sizeof (vsi->ivsi_ctxt), B_TRUE);
	add = &desc.icqd_command.icc_add_vsi;
	if ((vsi->ivsi_flags & ICE_VSI_F_POOL_ALLOC) == 0) {
		add->iccav_vsi = LE_16(vsi->ivsi_id | ICE_CQ_VSI_VALID);
	}
	switch (vsi->ivsi_type) {
	case ICE_VSI_TYPE_PF:
		hw_type = ICE_CQ_VSI_TYPE_PF;
		break;
	case ICE_VSI_TYPE_VF:
		hw_type = ICE_CQ_VSI_TYPE_VF;
		break;
	case ICE_VSI_TYPE_VMDQ2:
		hw_type = ICE_CQ_VSI_TYPE_VMDQ2;
		break;
	case ICE_VSI_TYPE_EMP_MNG:
		hw_type = ICE_CQ_VSI_TYPE_EMP_MNG;
		break;
	default:
		ice_error(ice, "invalid hardware VSI type: %u",
		    vsi->ivsi_type);
		return (B_FALSE);
	}
	add->iccav_type = LE_16(hw_type);

	if (!ice_cmd_submit(ice, &ice->ice_asq, &desc, &vsi->ivsi_ctxt,
	    ICE_CMD_COPY_TO_DEV)) {
		return (B_FALSE);
	}

	if (!ice_cmd_result(&desc, &err, &hw)) {
		ice_error(ice, "add vsi (%u) command failed with: 0x%x "
		    "(fw private: %x)", vsi->ivsi_id, err, hw);
		return (B_FALSE);
	}

	if ((vsi->ivsi_flags & ICE_VSI_F_POOL_ALLOC) == 0) {
		return (B_TRUE);
	}

	/*
	 * For pool based allocations we need to get the VSI ID out from the
	 * results.
	 */

	reply = &desc.icqd_command.icc_add_vsi_reply;
	vsi->ivsi_id = LE_16(reply->iccavr_vsi) & ICE_CQ_VSI_MASK;

	return (B_TRUE);
}

boolean_t
ice_cmd_set_rss_key(ice_t *ice, ice_vsi_t *vsi, void *buf, uint_t len)
{
	ice_cq_desc_t desc;
	ice_cq_errno_t err;
	uint8_t hw;
	ice_cq_cmd_set_rss_key_t *set_key;

	if ((vsi->ivsi_flags & ICE_VSI_F_ACTIVE) == 0) {
		ice_error(ice, "asked to set up RSS for an inactive VSI: %u",
		    vsi->ivsi_id);
		return (B_FALSE);
	}

	if (buf == NULL || len != ICE_RSS_KEY_LENGTH) {
		ice_error(ice, "invalid key length or buffer passed to RSS "
		    "set key: %p/%u", buf, len);
		return (B_FALSE);
	}

	ice_cmd_indirect_init(&desc, ICE_CQ_OP_SET_RSS_KEY, len, B_TRUE);
	set_key = &desc.icqd_command.icc_set_rss_key;
	set_key->iccsrk_vsi_id = LE_16(vsi->ivsi_id | ICE_CQ_VSI_VALID);

	if (!ice_cmd_submit(ice, &ice->ice_asq, &desc, buf,
	    ICE_CMD_COPY_TO_DEV)) {
		return (B_FALSE);
	}

	if (!ice_cmd_result(&desc, &err, &hw)) {
		ice_error(ice, "set rss key (VSI %u) command failed with: 0x%x "
		    "(fw private: %x)", vsi->ivsi_id, err, hw);
		return (B_FALSE);
	}

	return (B_TRUE);
}

boolean_t
ice_cmd_set_rss_lut(ice_t *ice, ice_vsi_t *vsi, void *buf, uint_t len)
{
	ice_cq_desc_t desc;
	ice_cq_errno_t err;
	uint8_t hw;
	uint16_t flags;
	ice_cq_cmd_set_rss_lut_t *lut;

	if ((vsi->ivsi_flags & ICE_VSI_F_ACTIVE) == 0) {
		ice_error(ice, "asked to set up RSS for an inactive VSI: %u",
		    vsi->ivsi_id);
		return (B_FALSE);
	}

	if (buf == NULL || len != ICE_RSS_LUT_SIZE_VSI) {
		ice_error(ice, "invalid lut length or buffer passed to RSS "
		    "set lut: %p/%u", buf, len);
		return (B_FALSE);
	}

	ice_cmd_indirect_init(&desc, ICE_CQ_OP_SET_RSS_KEY, len, B_TRUE);
	lut = &desc.icqd_command.icc_set_rss_lut;
	lut->iccsrl_vsi_id = LE_16(vsi->ivsi_id | ICE_CQ_VSI_VALID);

	/*
	 * We only support the VSI LUT mode today.
	 */
	flags = 0;
	flags = ICE_CQ_RSS_LUT_SET_TYPE(flags, ICE_CQ_RSS_LUT_TYPE_VSI);
	flags = ICE_CQ_RSS_LUT_SET_SIZE(flags, ICE_CQ_RSS_LUT_SIZE_VSI);
	lut->iccsrl_flags = LE_16(flags);

	if (!ice_cmd_submit(ice, &ice->ice_asq, &desc, buf,
	    ICE_CMD_COPY_TO_DEV)) {
		return (B_FALSE);
	}

	if (!ice_cmd_result(&desc, &err, &hw)) {
		ice_error(ice, "set rss lut (VSI %u) command failed with: 0x%x "
		    "(fw private: %x)", vsi->ivsi_id, err, hw);
		return (B_FALSE);
	}

	return (B_TRUE);
}

boolean_t
ice_cmd_get_default_scheduler(ice_t *ice, void *buf, size_t len,
    uint16_t *nbranches)
{
	ice_cq_desc_t desc;
	ice_cq_errno_t err;
	uint8_t hw;
	ice_cq_cmd_query_default_scheduler_t *sched;

	if (len != ICE_CQ_QUERY_DEFAULT_SCHED_BUF_SIZE) {
		ice_error(ice, "passed illegal buf size to get default "
		    "scheduling command");
		return (B_FALSE);
	}

	ice_cmd_indirect_init(&desc, ICE_CQ_OP_QUERY_DEFAULT_SCHEDULER,
	    len, B_FALSE);

	if (!ice_cmd_submit(ice, &ice->ice_asq, &desc, buf,
	    ICE_CMD_COPY_FROM_DEV)) {
		return (B_FALSE);
	}

	if (!ice_cmd_result(&desc, &err, &hw)) {
		ice_error(ice, "query default tx scheduler command failed "
		    "with: 0x%x (fw private: %x)", err, hw);
		return (B_FALSE);
	}

	sched = &desc.icqd_command.icc_query_default_scheduler;
	*nbranches = LE_16(sched->iccqds_nbranches);

	return (B_TRUE);
}
