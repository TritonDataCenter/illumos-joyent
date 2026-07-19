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
 * Receive ring DMA allocation and receive queue-context programming for
 * ice(4D).  Each rx ring owns a descriptor ring (a contiguous block of
 * union ice_32b_rx_flex_desc) and a per-slot array of receive control blocks;
 * the control blocks' data buffers and the desballoc loaners are posted by
 * ice_rx_setup_bufs() when the ring is started, so only the array is
 * allocated here.
 *
 * The hardware queue context (struct ice_rlan_ctx) is packed and written by the
 * Intel common code (ice_write_rxq_ctx) under core/; the per-queue enable and
 * the queue-to-MSI-X-vector wiring are raw register operations the common code
 * does not wrap.  No packets flow until the data path posts buffers and rings
 * the tail doorbell.
 */

#include <sys/strsun.h>
#include <sys/pattr.h>
#include <sys/vlan.h>

#include "ice.h"
#include "ice_common.h"
#include "ice_lan_tx_rx.h"

static void ice_rx_free_rcbs(ice_rx_ring_t *);

/*
 * Free a single rx ring's DMA and per-slot state.  Safe to call on a ring that
 * was only partially set up: each step is gated on what ice_rx_ring_alloc()
 * actually completed.
 *
 * The control-block pool is normally released by ice_rx_stop() at unplumb, but
 * a stop that timed out waiting for loans leaves it behind.  Reclaiming it here
 * is the last chance to do so, and it is safe: detach only reaches this after
 * ice_rx_drain() confirmed irxr_nloaned is zero on every ring, and freeing a
 * pool with a loan outstanding would double free the stack's mblk.
 */
static void
ice_rx_ring_free(ice_rx_ring_t *irr)
{
	ASSERT0(irr->irxr_nloaned);
	ice_rx_free_rcbs(irr);

	if (irr->irxr_kstat != NULL) {
		kstat_delete(irr->irxr_kstat);
		irr->irxr_kstat = NULL;
	}

	if (irr->irxr_rcbs != NULL) {
		kmem_free(irr->irxr_rcbs,
		    irr->irxr_size * sizeof (ice_rx_ctrl_block_t *));
		irr->irxr_rcbs = NULL;
	}

	if (irr->irxr_descs != NULL) {
		ice_dma_free(&irr->irxr_desc_dma);
		irr->irxr_descs = NULL;
	}

	cv_destroy(&irr->irxr_cv);
	mutex_destroy(&irr->irxr_lock);
}

static boolean_t
ice_rx_kstat_init(ice_t *ice, ice_rx_ring_t *irr)
{
	ice_rxq_stat_t *rxs = &irr->irxr_stats;
	char name[KSTAT_STRLEN];

	(void) snprintf(name, sizeof (name), "rx_ring_%u", irr->irxr_index);
	irr->irxr_kstat = kstat_create(ICE_MODULE_NAME, ice->ice_instance, name,
	    "net", KSTAT_TYPE_NAMED,
	    sizeof (ice_rxq_stat_t) / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL);
	if (irr->irxr_kstat == NULL)
		return (B_FALSE);

	irr->irxr_kstat->ks_data = rxs;
	kstat_named_init(&rxs->icrxs_bytes, "rx_bytes", KSTAT_DATA_UINT64);
	kstat_named_init(&rxs->icrxs_packets, "rx_packets", KSTAT_DATA_UINT64);
	kstat_named_init(&rxs->icrxs_bind_bytes, "rx_bind_bytes",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&rxs->icrxs_bind_segs, "rx_bind_segs",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&rxs->icrxs_copy_bytes, "rx_copy_bytes",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&rxs->icrxs_copy_segs, "rx_copy_segs",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&rxs->icrxs_desc_error, "rx_desc_error",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&rxs->icrxs_copy_nomem, "rx_copy_nomem",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&rxs->icrxs_no_rcb, "rx_no_rcb", KSTAT_DATA_UINT64);
	kstat_install(irr->irxr_kstat);

	return (B_TRUE);
}

static boolean_t
ice_rx_ring_alloc(ice_t *ice, ice_rx_ring_t *irr, uint_t index)
{
	ddi_dma_attr_t dma_attr;
	ddi_device_acc_attr_t acc_attr;
	size_t desc_len;

	irr->irxr_ice = ice;

	/* Absolute HW rx queue index; the single PF VSI's queues start at 0. */
	irr->irxr_index = index;

	/*
	 * MSI-X vector 0 is the OICR; queue vectors begin at 1.  A 1:1 mapping
	 * is used while there are at least as many vectors as rings; otherwise
	 * the last vector absorbs the overflow.
	 */
	irr->irxr_vec = 1 + index;
	if (irr->irxr_vec >= (uint32_t)ice->ice_intr_count)
		irr->irxr_vec = ice->ice_intr_count - 1;

	irr->irxr_size = ice->ice_rx_ring_size;
	irr->irxr_dbuf = ICE_RX_BUF_SIZE;
	irr->irxr_head = 0;
	irr->irxr_tail = 0;

	mutex_init(&irr->irxr_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(ice->ice_intr_pri));
	cv_init(&irr->irxr_cv, NULL, CV_DRIVER, NULL);

	desc_len = (size_t)irr->irxr_size *
	    sizeof (union ice_32b_rx_flex_desc);

	ice_dma_ring_attr(ice, &dma_attr);
	ice_dma_acc_attr(ice, &acc_attr);
	if (!ice_dma_alloc(ice, &irr->irxr_desc_dma, &dma_attr, &acc_attr,
	    B_FALSE, desc_len, B_TRUE)) {
		ice_error(ice, "failed to allocate rx descriptor ring for "
		    "queue %u", index);
		cv_destroy(&irr->irxr_cv);
		mutex_destroy(&irr->irxr_lock);
		return (B_FALSE);
	}
	irr->irxr_descs =
	    (union ice_32b_rx_flex_desc *)irr->irxr_desc_dma.idb_va;

	/*
	 * The control blocks themselves (data buffers, desballoc loaners) are
	 * posted by the data path; only the by-slot array is allocated now.
	 */
	irr->irxr_rcbs = kmem_zalloc(
	    irr->irxr_size * sizeof (ice_rx_ctrl_block_t *), KM_SLEEP);

	if (!ice_rx_kstat_init(ice, irr)) {
		ice_error(ice, "failed to create rx ring %u kstat", index);
		kmem_free(irr->irxr_rcbs,
		    irr->irxr_size * sizeof (ice_rx_ctrl_block_t *));
		irr->irxr_rcbs = NULL;
		ice_dma_free(&irr->irxr_desc_dma);
		irr->irxr_descs = NULL;
		cv_destroy(&irr->irxr_cv);
		mutex_destroy(&irr->irxr_lock);
		return (B_FALSE);
	}

	return (B_TRUE);
}

boolean_t
ice_rx_rings_alloc(ice_t *ice)
{
	uint_t i;

	ASSERT3U(ice->ice_num_rxr, >, 0);

	ice->ice_rxr = kmem_zalloc(
	    ice->ice_num_rxr * sizeof (ice_rx_ring_t), KM_SLEEP);

	for (i = 0; i < ice->ice_num_rxr; i++) {
		if (!ice_rx_ring_alloc(ice, &ice->ice_rxr[i], i)) {
			while (i-- > 0)
				ice_rx_ring_free(&ice->ice_rxr[i]);
			kmem_free(ice->ice_rxr,
			    ice->ice_num_rxr * sizeof (ice_rx_ring_t));
			ice->ice_rxr = NULL;
			return (B_FALSE);
		}
	}

	return (B_TRUE);
}

void
ice_rx_rings_free(ice_t *ice)
{
	uint_t i;

	if (ice->ice_rxr == NULL)
		return;

	for (i = 0; i < ice->ice_num_rxr; i++)
		ice_rx_ring_free(&ice->ice_rxr[i]);

	kmem_free(ice->ice_rxr, ice->ice_num_rxr * sizeof (ice_rx_ring_t));
	ice->ice_rxr = NULL;
}

/*
 * Tie an rx queue to its MSI-X vector and arm the cause.  There is no common
 * code helper for this; the driver writes QINT_RQCTL directly.
 */
void
ice_map_rxq_vector(ice_t *ice, ice_rx_ring_t *irr)
{
	struct ice_hw *hw = &ice->ice_hw;
	uint32_t reg;

	reg = ((irr->irxr_vec << QINT_RQCTL_MSIX_INDX_S) &
	    QINT_RQCTL_MSIX_INDX_M) |
	    ((ICE_ITR_IDX_0 << QINT_RQCTL_ITR_INDX_S) &
	    QINT_RQCTL_ITR_INDX_M) |
	    QINT_RQCTL_CAUSE_ENA_M;
	wr32(hw, QINT_RQCTL(irr->irxr_index), reg);
	ice_flush(hw);
}

/*
 * Program the per-vector interrupt throttle interval and arm the vector.  Used
 * by both the tx and rx queue->vector wiring, so it is keyed on the vector
 * rather than a ring.
 */
void
ice_cfg_itr(ice_t *ice, uint32_t vector)
{
	struct ice_hw *hw = &ice->ice_hw;
	uint32_t gran = hw->itr_gran != 0 ? hw->itr_gran : 2;
	uint32_t interval = ICE_ITR_DEFAULT_US / gran;

	/* Program ITR slot 0's interval; the queues' QINT_*CTL select it. */
	wr32(hw, GLINT_ITR(ICE_ITR_IDX_0, vector),
	    interval & GLINT_ITR_INTERVAL_M);

	/*
	 * Arm the vector with ITR_INDEX_NONE: a real ITR index here would
	 * reload that slot's interval from this register's (zero) interval
	 * field, undoing the throttle just programmed.
	 */
	wr32(hw, GLINT_DYN_CTL(vector),
	    GLINT_DYN_CTL_INTENA_M | GLINT_DYN_CTL_CLEARPBA_M |
	    ((ICE_ITR_INDEX_NONE << GLINT_DYN_CTL_ITR_INDX_S) &
	    GLINT_DYN_CTL_ITR_INDX_M));
	ice_flush(hw);
}

/*
 * Program an rx queue's context through the common code, then request the
 * queue enable and poll for it.  No buffers are posted here, so the queue is
 * armed but idle until the data path writes the tail doorbell.
 */
int
ice_rx_ring_program(ice_t *ice, ice_rx_ring_t *irr)
{
	struct ice_hw *hw = &ice->ice_hw;
	struct ice_rlan_ctx rlan;
	uint32_t reg;
	uint_t i;
	int status;

	bzero(&rlan, sizeof (rlan));

	/* base and dbuf are expressed in 128-byte units (>> _S of 7). */
	rlan.base = ICE_DMA_PA(&irr->irxr_desc_dma) >> ICE_RLAN_BASE_S;
	rlan.qlen = irr->irxr_size;
	rlan.dbuf = irr->irxr_dbuf >> ICE_RLAN_CTX_DBUF_S;
	rlan.hbuf = 0;				/* no header split */
	rlan.dtype = 0;				/* no descriptor split */
	rlan.dsize = 1;				/* 32-byte descriptors */
	rlan.crcstrip = 1;			/* strip the Ethernet FCS */
	rlan.l2tsel = 1;
	rlan.hsplit_0 = 0;
	rlan.hsplit_1 = 0;
	rlan.showiv = 0;
	/*
	 * A frame may span up to ICE_RX_MAX_DESC 2048-byte buffers, bounded by
	 * vi_max_frame.  rxmax is a 14-bit field and the hardware frame limit
	 * is safely representable.
	 */
	rlan.rxmax = ice->ice_pf_vsi.vi_max_frame;
	rlan.lrxqthresh = 1;
	/* ice_write_rxq_ctx forces prefena = 1; set it for clarity. */
	rlan.prefena = 1;
	/* TPH descriptor/data hints are left off, matching both references. */

	status = ice_write_rxq_ctx(hw, &rlan, irr->irxr_index);
	if (status != ICE_SUCCESS) {
		ice_error(ice, "failed to write rx queue context for queue "
		    "%u: %d", irr->irxr_index, status);
		return (status);
	}

	/*
	 * Select the Flex-NIC receive descriptor profile so the hardware
	 * writeback layout matches the descriptor the data path decodes.  This
	 * is not part of the queue context and is reset only by a core reset,
	 * so it is programmed explicitly per queue.
	 */
	reg = rd32(hw, QRXFLXP_CNTXT(irr->irxr_index));
	reg &= ~(QRXFLXP_CNTXT_RXDID_IDX_M | QRXFLXP_CNTXT_RXDID_PRIO_M);
	reg |= (ICE_RXDID_FLEX_NIC << QRXFLXP_CNTXT_RXDID_IDX_S) &
	    QRXFLXP_CNTXT_RXDID_IDX_M;
	reg |= (0x3 << QRXFLXP_CNTXT_RXDID_PRIO_S) & QRXFLXP_CNTXT_RXDID_PRIO_M;
	wr32(hw, QRXFLXP_CNTXT(irr->irxr_index), reg);

	/*
	 * Zero the tail so head == tail == 0: the queue is enabled empty until
	 * the data path posts buffers, regardless of any stale tail left by a
	 * prior incarnation that did not core-reset the function.
	 */
	wr32(hw, QRX_TAIL(irr->irxr_index), 0);
	ice_flush(hw);

	/* Request the enable, then poll QENA_STAT for the queue to come up. */
	reg = rd32(hw, QRX_CTRL(irr->irxr_index));
	reg |= QRX_CTRL_QENA_REQ_M;
	wr32(hw, QRX_CTRL(irr->irxr_index), reg);

	for (i = 0; i < ICE_Q_ENA_MAX_WAIT; i++) {
		reg = rd32(hw, QRX_CTRL(irr->irxr_index));
		if ((reg & QRX_CTRL_QENA_STAT_M) != 0)
			break;
		drv_usecwait(20);
	}

	if ((reg & QRX_CTRL_QENA_STAT_M) == 0) {
		ice_error(ice, "rx queue %u failed to enable", irr->irxr_index);
		return (ICE_ERR_CFG);
	}

	return (ICE_SUCCESS);
}

/*
 * Disable an rx queue and clear its context.  Best effort: teardown proceeds
 * even if the queue does not acknowledge the disable, so the result is not
 * propagated.
 */
void
ice_rx_ring_unprogram(ice_t *ice, ice_rx_ring_t *irr)
{
	struct ice_hw *hw = &ice->ice_hw;
	uint32_t reg;
	uint_t i;

	reg = rd32(hw, QRX_CTRL(irr->irxr_index));
	reg &= ~QRX_CTRL_QENA_REQ_M;
	wr32(hw, QRX_CTRL(irr->irxr_index), reg);

	for (i = 0; i < ICE_Q_ENA_MAX_WAIT; i++) {
		reg = rd32(hw, QRX_CTRL(irr->irxr_index));
		if ((reg & QRX_CTRL_QENA_STAT_M) == 0)
			break;
		drv_usecwait(20);
	}

	if ((reg & QRX_CTRL_QENA_STAT_M) != 0) {
		ice_error(ice, "rx queue %u failed to disable",
		    irr->irxr_index);
	}

	(void) ice_clear_rxq_ctx(hw, irr->irxr_index);
}

/*
 * Receive packet datapath.
 *
 * Each rx ring posts irxr_size data buffers (ICE_RX_BUF_SIZE) to the hardware
 * and decodes the Flex-NIC (RxDID 2) writeback the hardware produces.  A
 * control block (ice_rx_ctrl_block_t) owns each posted buffer and a
 * desballoc(9F) loaner mblk; a large segment is loaned up the stack (the slot
 * is refilled from a spare control block), a small segment is copied into a
 * fresh mblk and the buffer is left on the ring.  Loaned buffers return through
 * ice_rx_recycle(); teardown blocks until every loan is back.
 *
 * Everything the hardware writes into the descriptor writeback is untrusted.
 * The decode reads each Descriptor Done bit first, issues a read barrier before
 * touching any other writeback field, and clamps every segment length to the
 * posted buffer size before it is ever used to advance b_wptr or size a copy.
 */

/*
 * Loan high-water mark: spare control blocks allocated per ring beyond the
 * irxr_size that are posted.  A loan that would exceed the buffers actually
 * available falls back to copy, so this only bounds how many frames can be
 * outstanding up the stack at once.
 */
#define	ICE_RX_LOAN_RESERVE	256

/* Bind (loan) a frame at least this large; smaller frames are copied. */
#define	ICE_RX_COPY_THRESHOLD	256

/*
 * Upper bound on a teardown path's wait for loaned rx buffers to return, in
 * microseconds.  Bounds both the unplumb (ice_rx_stop()) and the reset and
 * detach drains.  Generous (5s total across rings) so a merely busy stack
 * still drains, but finite so neither an unplumb nor the autonomous reset
 * taskq can wedge on a loan that never comes back.
 */
#define	ICE_RX_LOAN_WAIT_US	5000000

static mblk_t *ice_ring_rx(ice_rx_ring_t *, int);

/*
 * Attach a desballoc(9F) loaner mblk to a control block if it lacks one.  The
 * mblk points directly at the control block's DMA buffer; freemsg(9F) routes
 * back to ice_rx_recycle() via ircb_free_rtn.  Returns B_FALSE only when
 * desballoc fails (transient memory pressure), in which case the caller copies.
 */
static boolean_t
ice_rx_alloc_mp(ice_rx_ctrl_block_t *rcb)
{
	if (rcb->ircb_mp != NULL)
		return (B_TRUE);

	rcb->ircb_mp = desballoc((unsigned char *)rcb->ircb_dma.idb_va,
	    rcb->ircb_dma.idb_len, 0, &rcb->ircb_free_rtn);

	return (rcb->ircb_mp != NULL);
}

/*
 * Pull a free control block off the ring's spare list.  Used both to fill the
 * ring at setup and to replace a slot whose buffer is being loaned out.  The
 * loan accounting is updated only when loaning: a loan that would exceed the
 * spare reserve is refused so the caller can fall back to copy and leave the
 * buffer on the ring.
 */
static ice_rx_ctrl_block_t *
ice_rcb_alloc(ice_rx_ring_t *irr, boolean_t loan)
{
	ice_rx_ctrl_block_t *rcb;

	ASSERT(MUTEX_HELD(&irr->irxr_lock));

	if (irr->irxr_nfree == 0)
		return (NULL);

	if (loan && irr->irxr_nloaned >= irr->irxr_nreserve)
		return (NULL);

	rcb = irr->irxr_free_rcbs[--irr->irxr_nfree];
	ASSERT3S(rcb->ircb_state, ==, IRXB_FREE);
	ASSERT3P(rcb->ircb_ring, ==, irr);

	rcb->ircb_state = IRXB_ONRING;
	if (loan)
		irr->irxr_nloaned++;

	return (rcb);
}

/*
 * Return a control block to the ring's spare list.  Only loaned buffers
 * decrement the loan counter; the state is tested before it is cleared (the
 * jasonbking import cleared it first, so the onloan count never dropped).
 */
static void
ice_rcb_free(ice_rx_ring_t *irr, ice_rx_ctrl_block_t *rcb)
{
	ASSERT(MUTEX_HELD(&irr->irxr_lock));
	ASSERT3P(rcb->ircb_ring, ==, irr);

	if (rcb->ircb_state == IRXB_ONLOAN) {
		ASSERT3U(irr->irxr_nloaned, >, 0);
		irr->irxr_nloaned--;
	}

	rcb->ircb_state = IRXB_FREE;
	ASSERT3U(irr->irxr_nfree, <, irr->irxr_nrcb);
	irr->irxr_free_rcbs[irr->irxr_nfree++] = rcb;
}

/*
 * freemsg(9F) callback for a loaned buffer.  A loaned buffer's mblk is gone
 * once we are here, so drop the reference and either re-arm a fresh loaner and
 * return the control block to the spare list, or, during teardown, signal the
 * waiter that one more loan has come home.
 */
void
ice_rx_recycle(caddr_t arg)
{
	ice_rx_ctrl_block_t *rcb = (ice_rx_ctrl_block_t *)arg;
	ice_rx_ring_t *irr = rcb->ircb_ring;

	/* The mblk that called us is gone; a fresh one is built below. */
	rcb->ircb_mp = NULL;

	/*
	 * A control block that was sitting free or on the ring (not loaned)
	 * reaching here means the ring is being torn down and its loaner was
	 * freed; there is nothing to return.
	 */
	if (rcb->ircb_state != IRXB_ONLOAN)
		return;

	mutex_enter(&irr->irxr_lock);

	if (irr->irxr_shutdown) {
		/*
		 * Teardown is waiting on outstanding loans.  Account this
		 * one as returned and wake the waiter; the buffer is freed
		 * by the teardown path, not re-armed.
		 */
		ASSERT3U(irr->irxr_nloaned, >, 0);
		irr->irxr_nloaned--;
		rcb->ircb_state = IRXB_FREE;
		cv_signal(&irr->irxr_cv);
		mutex_exit(&irr->irxr_lock);
		return;
	}

	/*
	 * Re-arm a loaner for the next time this buffer is posted and loaned.
	 * If desballoc fails now, the rx path retries before loaning, so this
	 * is not fatal.
	 */
	(void) ice_rx_alloc_mp(rcb);
	ice_rcb_free(irr, rcb);

	mutex_exit(&irr->irxr_lock);
}

/*
 * Post a control block's buffer into descriptor slot idx.  The Flex descriptor
 * read format is just the packet-buffer IOVA in pkt_addr; hdr_addr is zero
 * (no header split).  Writing hdr_addr clears the writeback Done bit (bit 0 of
 * hdr_addr) so the slot is handed back to hardware.
 */
static void
ice_rx_reset_desc(ice_rx_ring_t *irr, uint16_t idx, ice_rx_ctrl_block_t *rcb)
{
	union ice_32b_rx_flex_desc *desc = &irr->irxr_descs[idx];

	ASSERT3U(idx, <, irr->irxr_size);
	ASSERT3U(rcb->ircb_dma.idb_ncookies, ==, 1);

	irr->irxr_rcbs[idx] = rcb;
	desc->read.pkt_addr = CPU_TO_LE64(ICE_DMA_PA(&rcb->ircb_dma));
	desc->read.hdr_addr = 0;
}

/*
 * Allocate the per-ring control-block backing: one control block per
 * descriptor slot plus a loan reserve, each owning an ICE_RX_BUF_SIZE DMA
 * buffer and a desballoc loaner.  Builds the spare free list; the descriptor
 * ring is populated by ice_rx_setup_bufs().
 */
static boolean_t
ice_rx_alloc_rcbs(ice_rx_ring_t *irr)
{
	ice_t *ice = irr->irxr_ice;
	ddi_dma_attr_t attr;
	ddi_device_acc_attr_t acc;
	uint_t i;

	ASSERT(MUTEX_HELD(&irr->irxr_lock));

	irr->irxr_nreserve = ICE_RX_LOAN_RESERVE;
	irr->irxr_nrcb = irr->irxr_size + irr->irxr_nreserve;

	irr->irxr_rcb_area = kmem_zalloc(
	    irr->irxr_nrcb * sizeof (ice_rx_ctrl_block_t), KM_SLEEP);
	irr->irxr_free_rcbs = kmem_zalloc(
	    irr->irxr_nrcb * sizeof (ice_rx_ctrl_block_t *), KM_SLEEP);

	ice_pkt_dma_attr(ice, &attr);
	ice_dma_acc_attr(ice, &acc);

	for (i = 0; i < irr->irxr_nrcb; i++) {
		ice_rx_ctrl_block_t *rcb = &irr->irxr_rcb_area[i];

		rcb->ircb_ring = irr;
		rcb->ircb_state = IRXB_FREE;
		rcb->ircb_free_rtn.free_func = ice_rx_recycle;
		rcb->ircb_free_rtn.free_arg = (caddr_t)rcb;

		if (!ice_dma_alloc(ice, &rcb->ircb_dma, &attr, &acc, B_TRUE,
		    ICE_RX_BUF_SIZE, B_TRUE)) {
			ice_error(ice, "failed to allocate rx buffer for queue "
			    "%u", irr->irxr_index);
			return (B_FALSE);
		}

		(void) ice_rx_alloc_mp(rcb);

		irr->irxr_free_rcbs[irr->irxr_nfree++] = rcb;
	}

	return (B_TRUE);
}

/*
 * Free the per-ring control-block backing.  May only be called with
 * irxr_nloaned == 0: a loaned control block still holds the stack's mblk in
 * ircb_mp, so freeing here while a loan is outstanding is a double free of
 * that mblk and a use-after-free of live DMA.
 */
static void
ice_rx_free_rcbs(ice_rx_ring_t *irr)
{
	uint_t i;

	if (irr->irxr_rcb_area == NULL)
		return;

	for (i = 0; i < irr->irxr_nrcb; i++) {
		ice_rx_ctrl_block_t *rcb = &irr->irxr_rcb_area[i];

		if (rcb->ircb_mp != NULL) {
			freemsg(rcb->ircb_mp);
			rcb->ircb_mp = NULL;
		}
		ice_dma_free(&rcb->ircb_dma);
	}

	kmem_free(irr->irxr_free_rcbs,
	    irr->irxr_nrcb * sizeof (ice_rx_ctrl_block_t *));
	irr->irxr_free_rcbs = NULL;
	kmem_free(irr->irxr_rcb_area,
	    irr->irxr_nrcb * sizeof (ice_rx_ctrl_block_t));
	irr->irxr_rcb_area = NULL;

	irr->irxr_nfree = irr->irxr_nrcb = irr->irxr_nreserve = 0;
	/* No pool implies not started, ice_rx_start()'s realloc included. */
	irr->irxr_started = B_FALSE;
}

/*
 * Fill every descriptor slot with a posted buffer and hand the whole ring to
 * hardware.  The tail is set to size - 1: the hardware owns slots [head, tail]
 * and stops one short of head, so posting all but conceptually leaving head as
 * the next-to-be-filled slot is expressed by tail = size - 1.
 */
static boolean_t
ice_rx_setup_bufs(ice_rx_ring_t *irr)
{
	ice_t *ice = irr->irxr_ice;
	struct ice_hw *hw = &ice->ice_hw;
	uint16_t i;

	ASSERT(MUTEX_HELD(&irr->irxr_lock));

	for (i = 0; i < irr->irxr_size; i++) {
		ice_rx_ctrl_block_t *rcb = ice_rcb_alloc(irr, B_FALSE);

		/* Setup posts exactly irxr_size; the reserve covers rest. */
		ASSERT3P(rcb, !=, NULL);
		ice_rx_reset_desc(irr, i, rcb);
	}

	irr->irxr_head = 0;
	irr->irxr_tail = irr->irxr_size - 1;

	if (ddi_dma_sync(irr->irxr_desc_dma.idb_dma_handle, 0, 0,
	    DDI_DMA_SYNC_FORDEV) != DDI_SUCCESS) {
		ice_error(ice, "failed to sync rx ring %u", irr->irxr_index);
		return (B_FALSE);
	}

	wr32(hw, QRX_TAIL(irr->irxr_index), irr->irxr_tail);
	ice_flush(hw);

	return (B_TRUE);
}

/*
 * Advance a ring index by one, wrapping at the ring size.
 */
static inline uint16_t
ice_rx_next(const ice_rx_ring_t *irr, uint16_t idx)
{
	idx++;
	if (idx == irr->irxr_size)
		idx = 0;
	return (idx);
}

/*
 * Copy a received frame of plen bytes from the posted buffer into a fresh mblk,
 * leaving the buffer on the ring.  Used for small frames and as the fallback
 * when a loaner cannot be obtained.  The caller has already validated plen
 * against the buffer size and synced the buffer for the CPU.
 */
static mblk_t *
ice_rx_copy(ice_rx_ring_t *irr, ice_rx_ctrl_block_t *rcb, uint16_t plen)
{
	mblk_t *mp;

	mp = allocb(plen, 0);
	if (mp == NULL) {
		irr->irxr_stats.icrxs_copy_nomem.value.ui64++;
		return (NULL);
	}

	bcopy(rcb->ircb_dma.idb_va, mp->b_rptr, plen);
	mp->b_wptr = mp->b_rptr + plen;

	irr->irxr_stats.icrxs_copy_bytes.value.ui64 += plen;
	irr->irxr_stats.icrxs_copy_segs.value.ui64++;
	return (mp);
}

/*
 * Loan a received frame up the stack: hand the control block's loaner mblk to
 * the caller and refill the descriptor slot from a spare control block.  Falls
 * back (returns NULL) when no spare is available or the loaner could not be
 * (re)allocated, in which case the caller copies and leaves the buffer in
 * place.  The caller has already validated plen and synced the buffer.
 */
static mblk_t *
ice_rx_bind(ice_rx_ring_t *irr, uint16_t idx, ice_rx_ctrl_block_t *rcb,
    uint16_t plen)
{
	ice_rx_ctrl_block_t *replacement;
	mblk_t *mp;

	ASSERT(MUTEX_HELD(&irr->irxr_lock));

	replacement = ice_rcb_alloc(irr, B_TRUE);
	if (replacement == NULL) {
		irr->irxr_stats.icrxs_no_rcb.value.ui64++;
		return (NULL);
	}

	if (!ice_rx_alloc_mp(rcb)) {
		/*
		 * The loan never happens: undo the count ice_rcb_alloc() took
		 * for it.  The replacement is on-ring, not on-loan, so
		 * ice_rcb_free() will not decrement it.
		 */
		irr->irxr_nloaned--;
		ice_rcb_free(irr, replacement);
		return (NULL);
	}

	mp = rcb->ircb_mp;
	mp->b_cont = mp->b_next = NULL;
	mp->b_rptr = (unsigned char *)rcb->ircb_dma.idb_va;
	mp->b_wptr = mp->b_rptr + plen;

	rcb->ircb_state = IRXB_ONLOAN;

	/* The slot now holds the replacement buffer, posted by the caller. */
	ice_rx_reset_desc(irr, idx, replacement);

	irr->irxr_stats.icrxs_bind_bytes.value.ui64 += plen;
	irr->irxr_stats.icrxs_bind_segs.value.ui64++;
	return (mp);
}

/*
 * Report hardware checksum results to mac.  The flex writeback gives the
 * integrity-processed bit and per-layer error bits; the ptype identifies which
 * layers are present.  A clear error bit on a present, processed layer is a
 * verified-good checksum.  Tunneled and unknown packets are left unverified.
 */
static void
ice_rx_hcksum(ice_rx_ring_t *irr, mblk_t *mp, uint16_t status0, uint16_t ptype)
{
	struct ice_rx_ptype_decoded pinfo = ice_decode_rx_desc_ptype(ptype);
	uint32_t cksum = 0;

	/*
	 * Without the DDP package the pipeline does not classify or checksum,
	 * so the descriptor status bits carry no verdict worth reporting; see
	 * ice_set_safe_mode_caps().  The tx side withholds the capability in
	 * ice_m_getcapab(), and the rx side must not claim a verified checksum.
	 */
	if (irr->irxr_ice->ice_safe_mode)
		return;

	if (pinfo.known == 0)
		return;
	if ((status0 & BIT(ICE_RX_FLEX_DESC_STATUS0_L3L4P_S)) == 0)
		return;

	if (pinfo.outer_ip == ICE_RX_PTYPE_OUTER_IP &&
	    pinfo.outer_ip_ver == ICE_RX_PTYPE_OUTER_IPV4 &&
	    pinfo.tunnel_type == ICE_RX_PTYPE_TUNNEL_NONE &&
	    (status0 & (BIT(ICE_RX_FLEX_DESC_STATUS0_XSUM_IPE_S) |
	    BIT(ICE_RX_FLEX_DESC_STATUS0_XSUM_EIPE_S))) == 0)
		cksum |= HCK_IPV4_HDRCKSUM_OK;

	/*
	 * IPV6EXADD marks IPv6 extension headers that make the L4 checksum
	 * coverage unreliable even when the L4-error bit is clear, so it must
	 * also suppress the verified-good result (no-op for IPv4 frames).
	 */
	if (pinfo.outer_ip == ICE_RX_PTYPE_OUTER_IP &&
	    pinfo.tunnel_type == ICE_RX_PTYPE_TUNNEL_NONE &&
	    (pinfo.inner_prot == ICE_RX_PTYPE_INNER_PROT_TCP ||
	    pinfo.inner_prot == ICE_RX_PTYPE_INNER_PROT_UDP ||
	    pinfo.inner_prot == ICE_RX_PTYPE_INNER_PROT_SCTP) &&
	    (status0 & (BIT(ICE_RX_FLEX_DESC_STATUS0_XSUM_L4E_S) |
	    BIT(ICE_RX_FLEX_DESC_STATUS0_XSUM_EUDPE_S))) == 0 &&
	    (status0 & BIT(ICE_RX_FLEX_DESC_STATUS0_IPV6EXADD_S)) == 0)
		cksum |= HCK_FULLCKSUM_OK;

	if (cksum != 0)
		mac_hcksum_set(mp, 0, 0, 0, 0, cksum);
}

/*
 * Re-post every descriptor in a frame that cannot be delivered.  Advancing
 * irxr_head is unconditional: even a hostile chain that never supplies EOP
 * must not wedge the ring on the same descriptor forever.
 */
static void
ice_rx_discard_frame(ice_rx_ring_t *irr, uint16_t nsegs)
{
	uint16_t h = irr->irxr_head;
	uint16_t i;

	ASSERT(MUTEX_HELD(&irr->irxr_lock));
	ASSERT3U(nsegs, >, 0);
	ASSERT3U(nsegs, <=, ICE_RX_MAX_DESC);

	for (i = 0; i < nsegs; i++) {
		ice_rx_reset_desc(irr, h, irr->irxr_rcbs[h]);
		h = ice_rx_next(irr, h);
	}

	irr->irxr_head = h;
}

/*
 * Put a hardware-extracted VLAN tag back into the frame.  illumos MAC has no
 * rx VLAN metadata channel; it demultiplexes a VLAN link from the tag inline,
 * so a stripped tag means the frame can never reach the VLAN client.  vmp
 * carries a copy of the address pair, the 802.1Q header and the original
 * ethertype, and the original head is advanced past the ether header it
 * already holds, which keeps the payload zero-copy.  tci is in host byte
 * order.
 *
 * The split point mirrors mac_add_vlan_tag(): MAC requires the head to hold a
 * full struct ether_vlan_header, and mac_strip_vlan_tag() asserts it.
 */
static mblk_t *
ice_rx_vlan_insert(mblk_t *mp, mblk_t *vmp, uint16_t tci)
{
	uint8_t *p = vmp->b_wptr;

	ASSERT3U(MBLKL(mp), >=, sizeof (struct ether_header));

	bcopy(mp->b_rptr, p, 2 * ETHERADDRL);
	p += 2 * ETHERADDRL;

	/* The 802.1Q header is built in network byte order. */
	*p++ = (ETHERTYPE_VLAN >> 8) & 0xff;
	*p++ = ETHERTYPE_VLAN & 0xff;
	*p++ = (tci >> 8) & 0xff;
	*p++ = tci & 0xff;

	/* A 2-byte copy keeps network byte order without an aligned load. */
	bcopy(mp->b_rptr + 2 * ETHERADDRL, p, sizeof (uint16_t));
	p += sizeof (uint16_t);

	vmp->b_wptr = p;
	mp->b_rptr += sizeof (struct ether_header);

	/*
	 * Drop a now-empty head rather than pass it upstack.  Only a 14-byte
	 * first segment can get here, which is below ICE_RX_COPY_THRESHOLD and
	 * so is always a copy mblk: freeb() cannot re-enter ice_rx_recycle()
	 * under the ring lock.
	 */
	if (MBLKL(mp) == 0) {
		vmp->b_cont = mp->b_cont;
		mp->b_cont = NULL;
		freeb(mp);
	} else {
		vmp->b_cont = mp;
	}

	ASSERT3U(MBLKL(vmp), >=, sizeof (struct ether_vlan_header));

	return (vmp);
}

/*
 * Validate one complete frame without changing ring state, then assemble its
 * descriptor buffers into a b_cont chain.  On entry, a non-zero *total_lenp
 * is the remaining budget for a non-empty poll result; zero means unlimited.
 * A frame that exceeds that budget is deferred without consuming any slots.
 */
static mblk_t *
ice_ring_rx_frame(ice_rx_ring_t *irr, uint32_t *total_lenp,
    boolean_t *deferp)
{
	ice_t *ice = irr->irxr_ice;
	mblk_t *mp_head = NULL, *mp_tail = NULL, *vmp = NULL;
	ice_rx_ctrl_block_t *loaned[ICE_RX_MAX_DESC];
	uint16_t seglens[ICE_RX_MAX_DESC];
	uint32_t frame_limit = *total_lenp;
	uint32_t total = 0;
	uint16_t h = irr->irxr_head;
	uint16_t eop_status0 = 0, eop_ptype = 0, eop_l2tag1 = 0;
	uint16_t nsegs = 0, nloans = 0, i;
	boolean_t bad = B_FALSE, eop = B_FALSE, vlan = B_FALSE;
	boolean_t dma_fault = B_FALSE;

	ASSERT(MUTEX_HELD(&irr->irxr_lock));

	*total_lenp = 0;
	*deferp = B_FALSE;

	/*
	 * Pass A: validate only.  DD is authoritative for every descriptor;
	 * no other writeback field is read until after the consumer barrier.
	 */
	for (;;) {
		union ice_32b_rx_flex_desc *desc = &irr->irxr_descs[h];
		uint16_t status0, seglen;

		(void) ddi_dma_sync(irr->irxr_desc_dma.idb_dma_handle,
		    (off_t)((uintptr_t)desc - (uintptr_t)irr->irxr_descs),
		    sizeof (*desc), DDI_DMA_SYNC_FORKERNEL);

		status0 = LE16_TO_CPU(desc->wb.status_error0);
		if ((status0 & BIT(ICE_RX_FLEX_DESC_STATUS0_DD_S)) == 0) {
			*deferp = B_TRUE;
			return (NULL);
		}

		membar_consumer();

		seglen = LE16_TO_CPU(desc->wb.pkt_len) &
		    ICE_RX_FLX_DESC_PKT_LEN_M;
		if (seglen == 0 || seglen > irr->irxr_dbuf)
			bad = B_TRUE;

		seglens[nsegs] = seglen;
		total += seglen;
		nsegs++;

		if ((status0 & BIT(ICE_RX_FLEX_DESC_STATUS0_EOF_S)) != 0) {
			eop_status0 = status0;
			eop_ptype = LE16_TO_CPU(desc->wb.ptype_flex_flags0) &
			    ICE_RX_FLEX_DESC_PTYPE_M;
			eop_l2tag1 = LE16_TO_CPU(desc->wb.l2tag1);
			eop = B_TRUE;
			break;
		}

		if (nsegs == ICE_RX_MAX_DESC)
			break;
		h = ice_rx_next(irr, h);
	}

	/*
	 * A tag the hardware extracted has to go back into the frame, so it
	 * counts against the frame limits and the poll budget below, and the
	 * first segment must be long enough to donate a whole ether header.
	 */
	if (eop && (eop_status0 &
	    BIT(ICE_RX_FLEX_DESC_STATUS0_L2TAG1P_S)) != 0) {
		vlan = B_TRUE;
		total += VLAN_TAGSZ;
		if (seglens[0] < sizeof (struct ether_header))
			bad = B_TRUE;
	}

	if (!eop || total > ice->ice_pf_vsi.vi_max_frame ||
	    (eop && (eop_status0 &
	    BIT(ICE_RX_FLEX_DESC_STATUS0_RXE_S)) != 0))
		bad = B_TRUE;

	if (bad) {
		ice_rx_discard_frame(irr, nsegs);
		irr->irxr_stats.icrxs_desc_error.value.ui64++;
		return (NULL);
	}

	/* Do not consume a second or later frame that exceeds a poll budget. */
	if (frame_limit != 0 && total > frame_limit) {
		*deferp = B_TRUE;
		return (NULL);
	}

	/*
	 * Obtain the tag header before any descriptor is consumed: a failure
	 * here is then just a dropped frame, not a partially unwound one.
	 */
	if (vlan) {
		vmp = allocb(sizeof (struct ether_vlan_header), 0);
		if (vmp == NULL) {
			ice_rx_discard_frame(irr, nsegs);
			irr->irxr_stats.icrxs_copy_nomem.value.ui64++;
			return (NULL);
		}
	}

	/* Pass B: every segment is present and its length is now trusted. */
	h = irr->irxr_head;
	for (i = 0; i < nsegs; i++) {
		ice_rx_ctrl_block_t *rcb = irr->irxr_rcbs[h];
		mblk_t *mp = NULL;
		uint16_t seglen = seglens[i];
		boolean_t bound = B_FALSE;

		if (ddi_dma_sync(rcb->ircb_dma.idb_dma_handle, 0, seglen,
		    DDI_DMA_SYNC_FORKERNEL) != DDI_SUCCESS ||
		    ice_check_dma_handle(rcb->ircb_dma.idb_dma_handle) !=
		    DDI_FM_OK) {
			dma_fault = B_TRUE;
			goto assemble_fail;
		}

		if (seglen >= ICE_RX_COPY_THRESHOLD) {
			mp = ice_rx_bind(irr, h, rcb, seglen);
			if (mp != NULL) {
				bound = B_TRUE;
				loaned[nloans++] = rcb;
			}
		}
		if (mp == NULL)
			mp = ice_rx_copy(irr, rcb, seglen);
		if (mp == NULL)
			goto assemble_fail;

		/* ice_rx_bind() has already posted a replacement. */
		if (!bound)
			ice_rx_reset_desc(irr, h, rcb);

		if (mp_tail == NULL)
			mp_head = mp_tail = mp;
		else {
			mp_tail->b_cont = mp;
			mp_tail = mp;
		}

		h = ice_rx_next(irr, h);
	}

	/* hcksum metadata belongs on the final head, so prepend first. */
	if (vmp != NULL)
		mp_head = ice_rx_vlan_insert(mp_head, vmp, eop_l2tag1);

	ice_rx_hcksum(irr, mp_head, eop_status0, eop_ptype);
	irr->irxr_head = h;
	*total_lenp = total;
	return (mp_head);

assemble_fail:
	/*
	 * desballoc(9F) invokes ice_rx_recycle() synchronously from
	 * freemsg(9F).  Mark partial loans returned while holding the ring
	 * lock so the callback takes its non-loaned path and cannot recursively
	 * enter this mutex; re-arm and stack the control blocks afterwards.
	 */
	for (i = 0; i < nloans; i++) {
		ASSERT3S(loaned[i]->ircb_state, ==, IRXB_ONLOAN);
		ASSERT3U(irr->irxr_nloaned, >, 0);
		irr->irxr_nloaned--;
		loaned[i]->ircb_state = IRXB_FREE;
	}
	if (mp_head != NULL)
		freemsg(mp_head);
	if (vmp != NULL)
		freeb(vmp);
	for (i = 0; i < nloans; i++) {
		(void) ice_rx_alloc_mp(loaned[i]);
		ice_rcb_free(irr, loaned[i]);
	}

	ice_rx_discard_frame(irr, nsegs);

	if (dma_fault) {
		ddi_fm_service_impact(ice->ice_dip, DDI_SERVICE_DEGRADED);
		atomic_or_32(&ice->ice_state, ICE_STATE_ERROR);
	}

	return (NULL);
}

/*
 * Drain the rx ring, returning a b_next chain of received frames.  Segments
 * within a frame are linked with b_cont by ice_ring_rx_frame().
 *
 * poll_bytes > 0 caps the bytes delivered (mac polling); poll_bytes == 0 means
 * deliver everything ready (interrupt context).  Refilled slots advance the
 * tail doorbell so hardware can reuse them.
 */
static mblk_t *
ice_ring_rx(ice_rx_ring_t *irr, int poll_bytes)
{
	ice_t *ice = irr->irxr_ice;
	struct ice_hw *hw = &ice->ice_hw;
	mblk_t *mp_head = NULL, *mp_tail = NULL;
	uint32_t bytes = 0;
	uint_t npkts = 0, nposted = 0;

	ASSERT(MUTEX_HELD(&irr->irxr_lock));

	if ((ice->ice_state & ICE_STATE_ERROR) != 0)
		return (NULL);

	for (;;) {
		mblk_t *mp;
		uint32_t total_len = 0;
		uint16_t frame_head = irr->irxr_head;
		boolean_t defer;

		if (poll_bytes > 0 && bytes >= (uint32_t)poll_bytes)
			break;
		if (poll_bytes > 0 && bytes > 0)
			total_len = (uint32_t)poll_bytes - bytes;

		mp = ice_ring_rx_frame(irr, &total_len, &defer);
		if (defer)
			break;

		if (irr->irxr_head >= frame_head)
			nposted += irr->irxr_head - frame_head;
		else
			nposted += irr->irxr_size - frame_head +
			    irr->irxr_head;

		if (mp == NULL) {
			if ((ice->ice_state & ICE_STATE_ERROR) != 0)
				break;
			continue;
		}

		ASSERT(poll_bytes == 0 || bytes == 0 ||
		    bytes + total_len <= (uint32_t)poll_bytes);

		if (mp_tail == NULL)
			mp_head = mp_tail = mp;
		else {
			mp_tail->b_next = mp;
			mp_tail = mp;
		}
		bytes += total_len;
		npkts++;
	}

	if (nposted == 0)
		return (mp_head);

	/*
	 * Hand the refilled slots back to hardware: sync the descriptors we
	 * rewrote, then advance the tail to the slot behind head (hardware
	 * fills [head, tail] and stops at tail).
	 */
	if (ddi_dma_sync(irr->irxr_desc_dma.idb_dma_handle, 0, 0,
	    DDI_DMA_SYNC_FORDEV) != DDI_SUCCESS ||
	    ice_check_dma_handle(irr->irxr_desc_dma.idb_dma_handle) !=
	    DDI_FM_OK) {
		ddi_fm_service_impact(ice->ice_dip, DDI_SERVICE_DEGRADED);
		atomic_or_32(&ice->ice_state, ICE_STATE_ERROR);
	}

	irr->irxr_tail = (irr->irxr_head == 0) ? irr->irxr_size - 1 :
	    irr->irxr_head - 1;
	wr32(hw, QRX_TAIL(irr->irxr_index), irr->irxr_tail);
	if (ice_check_acc_handle(ice->ice_osdep.ios_reg_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(ice->ice_dip, DDI_SERVICE_DEGRADED);
		atomic_or_32(&ice->ice_state, ICE_STATE_ERROR);
	}

	if (npkts > 0) {
		irr->irxr_stats.icrxs_bytes.value.ui64 += bytes;
		irr->irxr_stats.icrxs_packets.value.ui64 += npkts;
	}

	return (mp_head);
}

/*
 * mac(9E) poll entry point.
 */
mblk_t *
ice_ring_rx_poll(void *arg, int poll_bytes)
{
	ice_rx_ring_t *irr = arg;
	mblk_t *mp;

	ASSERT3S(poll_bytes, >, 0);

	mutex_enter(&irr->irxr_lock);
	if (irr->irxr_shutdown) {
		mutex_exit(&irr->irxr_lock);
		return (NULL);
	}
	mp = ice_ring_rx(irr, poll_bytes);
	mutex_exit(&irr->irxr_lock);

	return (mp);
}

/*
 * Interrupt-context service for one rx ring: drain everything ready and push
 * the chain to mac.  Called from the MSI-X handler after it maps the firing
 * vector back to this ring.
 */
void
ice_rx_ring_intr(ice_rx_ring_t *irr)
{
	ice_t *ice = irr->irxr_ice;
	mblk_t *mp;
	uint64_t gen;

	mutex_enter(&irr->irxr_lock);
	if (irr->irxr_shutdown || irr->irxr_intr_poll) {
		mutex_exit(&irr->irxr_lock);
		return;
	}
	mp = ice_ring_rx(irr, 0);
	gen = irr->irxr_rxgen;
	mutex_exit(&irr->irxr_lock);

	if (mp != NULL) {
		mac_rx_ring(ice->ice_mac_hdl, irr->irxr_macrxring, mp, gen);
	}
}

/*
 * mac(9E) interrupt enable/disable for a poll-capable ring.  Toggling the
 * queue's interrupt cause is what flips the ring between interrupt and poll
 * modes; mac owns the transition.
 */
int
ice_ring_rx_intr_enable(mac_intr_handle_t intrh)
{
	ice_rx_ring_t *irr = (ice_rx_ring_t *)intrh;
	struct ice_hw *hw = &irr->irxr_ice->ice_hw;
	uint32_t reg;

	mutex_enter(&irr->irxr_lock);
	irr->irxr_intr_poll = B_FALSE;

	reg = rd32(hw, QINT_RQCTL(irr->irxr_index));
	reg |= QINT_RQCTL_CAUSE_ENA_M;
	wr32(hw, QINT_RQCTL(irr->irxr_index), reg);

	/* Re-arm the vector (ITR_INDEX_NONE keeps the configured throttle). */
	wr32(hw, GLINT_DYN_CTL(irr->irxr_vec),
	    GLINT_DYN_CTL_INTENA_M | GLINT_DYN_CTL_CLEARPBA_M |
	    ((ICE_ITR_INDEX_NONE << GLINT_DYN_CTL_ITR_INDX_S) &
	    GLINT_DYN_CTL_ITR_INDX_M));
	ice_flush(hw);
	mutex_exit(&irr->irxr_lock);

	return (0);
}

int
ice_ring_rx_intr_disable(mac_intr_handle_t intrh)
{
	ice_rx_ring_t *irr = (ice_rx_ring_t *)intrh;
	struct ice_hw *hw = &irr->irxr_ice->ice_hw;
	uint32_t reg;

	mutex_enter(&irr->irxr_lock);
	irr->irxr_intr_poll = B_TRUE;

	reg = rd32(hw, QINT_RQCTL(irr->irxr_index));
	reg &= ~QINT_RQCTL_CAUSE_ENA_M;
	wr32(hw, QINT_RQCTL(irr->irxr_index), reg);
	ice_flush(hw);
	mutex_exit(&irr->irxr_lock);

	return (0);
}

/*
 * Exact precondition of ice_rx_setup_bufs(): the pool exists and nothing is
 * posted or loaned out of it.  Since irxr_nrcb is irxr_size plus the loan
 * reserve, it also proves the free list cannot run dry mid-post.
 */
static boolean_t
ice_rx_ring_postable(ice_rx_ring_t *irr)
{
	ASSERT(MUTEX_HELD(&irr->irxr_lock));

	return (irr->irxr_rcb_area != NULL &&
	    irr->irxr_nfree == irr->irxr_nrcb);
}

/*
 * Post a ring's buffers and open it for traffic.  Idempotent, because both
 * MAC's per-ring start callback and the reset rebuild drive it and neither
 * observes the other: mac_start_ring()'s mr_state guard never sees the
 * rebuild's start, and mac_provider.h exposes no way to read mr_state back.
 * irxr_lock is the only thing serializing the two, so the guard, the
 * precondition and the post must share a single acquisition.
 */
static int
ice_rx_ring_open_locked(ice_rx_ring_t *irr)
{
	ASSERT(MUTEX_HELD(&irr->irxr_lock));

	if (irr->irxr_started)
		return (0);

	/*
	 * A teardown that timed out waiting for loans leaves the pool either
	 * freed or partly outstanding; posting into it would exhaust the free
	 * list and fault on the NULL control block.
	 */
	if (!ice_rx_ring_postable(irr))
		return (EIO);

	if (!ice_rx_setup_bufs(irr))
		return (EIO);

	irr->irxr_shutdown = B_FALSE;
	irr->irxr_started = B_TRUE;

	return (0);
}

/*
 * mac(9E) ring start: post buffers and record the mac generation number.  The
 * queue context is already programmed and the queue enabled at attach; this
 * only fills the ring and opens it for traffic.
 */
int
ice_ring_rx_start(mac_ring_driver_t rh, uint64_t gen_num)
{
	ice_rx_ring_t *irr = (ice_rx_ring_t *)rh;
	int ret;

	mutex_enter(&irr->irxr_lock);

	/*
	 * Unconditionally, and before the open can short-circuit: mac_stop_ring
	 * bumps mr_gen_num and mac_rx_ring() frees any chain that does not
	 * match, so a start the rebuild already satisfied must still refresh
	 * the generation or the ring becomes a silent rx blackhole.
	 */
	irr->irxr_rxgen = gen_num;

	ret = ice_rx_ring_open_locked(irr);
	mutex_exit(&irr->irxr_lock);

	/*
	 * MAC unwinds a failed mr_start without calling mi_stop, so nothing
	 * else would record why the plumb failed.  The next mac start clears
	 * this and reallocates the pool.
	 */
	if (ret != 0) {
		ice_t *ice = irr->irxr_ice;

		atomic_or_32(&ice->ice_state, ICE_STATE_ERROR);
		ice_error(ice, "!rx ring %u could not be opened; buffers are "
		    "still outstanding up the stack", irr->irxr_index);
	}

	return (ret);
}

/*
 * mac(9E) ring stop: close the ring to new traffic.  Buffers and loans are
 * reclaimed by ice_rx_stop() at the softc level; this only marks the ring
 * quiescent so the datapath stops touching it.
 */
void
ice_ring_rx_stop(mac_ring_driver_t rh)
{
	ice_rx_ring_t *irr = (ice_rx_ring_t *)rh;

	mutex_enter(&irr->irxr_lock);
	irr->irxr_shutdown = B_TRUE;
	irr->irxr_started = B_FALSE;
	mutex_exit(&irr->irxr_lock);
}

int
ice_ring_rx_stat(mac_ring_driver_t rh, uint_t stat, uint64_t *val)
{
	ice_rx_ring_t *irr = (ice_rx_ring_t *)rh;

	switch (stat) {
	case MAC_STAT_RBYTES:
		*val = irr->irxr_stats.icrxs_bytes.value.ui64;
		break;
	case MAC_STAT_IPACKETS:
		*val = irr->irxr_stats.icrxs_packets.value.ui64;
		break;
	default:
		*val = 0;
		return (ENOTSUP);
	}

	return (0);
}

/*
 * Allocate the control blocks for every rx ring.  Called once the queue
 * contexts are programmed; the descriptors are posted by ice_ring_rx_start().
 *
 * A pool may have survived a teardown that timed out waiting for loans; it is
 * never reused, because ice_rx_recycle()'s shutdown path drops returning
 * control blocks without re-arming them or putting them back on the free list.
 * Reclaim it once drained, and refuse to start at all while loans remain.
 */
boolean_t
ice_rx_start(ice_t *ice)
{
	uint_t i;

	for (i = 0; i < ice->ice_num_rxr; i++) {
		ice_rx_ring_t *irr = &ice->ice_rxr[i];

		mutex_enter(&irr->irxr_lock);
		if (irr->irxr_rcb_area != NULL) {
			if (irr->irxr_nloaned > 0) {
				mutex_exit(&irr->irxr_lock);
				goto unwind;
			}
			ice_rx_free_rcbs(irr);
		}

		if (!ice_rx_alloc_rcbs(irr)) {
			ice_rx_free_rcbs(irr);
			mutex_exit(&irr->irxr_lock);
			goto unwind;
		}
		mutex_exit(&irr->irxr_lock);
	}

	return (B_TRUE);

unwind:
	while (i-- > 0) {
		ice_rx_ring_t *irr = &ice->ice_rxr[i];

		mutex_enter(&irr->irxr_lock);
		ice_rx_free_rcbs(irr);
		mutex_exit(&irr->irxr_lock);
	}

	return (B_FALSE);
}

/*
 * Close every rx ring and wait for its loaned buffers to come back through
 * ice_rx_recycle().  A loan can be held arbitrarily long by the stack with no
 * driver bug (reassembly queues, a stopped process's socket buffer), so
 * waiting forever would wedge the unplumb thread and, on the reset path, the
 * reset taskq.  Returns B_FALSE if any ring still has loans outstanding when
 * the deadline expires.  Releases nothing: the reset path must be able to
 * quiesce without giving up DMA hardware can still reach.
 *
 * Closing every ring before waiting on any of them is what makes one shared
 * deadline fair.  irxr_shutdown is the gate that stops new loans, so a ring
 * still open while an earlier one is waited out keeps issuing them -- and
 * ice_prepare_for_reset() runs this before ice_queues_disable(), so hardware
 * is still delivering.  A late ring could otherwise reach its wait with more
 * loans than when this was entered and no budget left.  ice_rx_drain() needs
 * no such pass because ice_rx_stop() has already closed every ring.
 */
boolean_t
ice_rx_quiesce(ice_t *ice)
{
	clock_t deadline;
	boolean_t drained = B_TRUE;
	uint_t i;

	for (i = 0; i < ice->ice_num_rxr; i++) {
		ice_rx_ring_t *irr = &ice->ice_rxr[i];

		mutex_enter(&irr->irxr_lock);
		irr->irxr_shutdown = B_TRUE;
		irr->irxr_started = B_FALSE;
		mutex_exit(&irr->irxr_lock);
	}

	deadline = ddi_get_lbolt() + drv_usectohz(ICE_RX_LOAN_WAIT_US);

	for (i = 0; i < ice->ice_num_rxr; i++) {
		ice_rx_ring_t *irr = &ice->ice_rxr[i];

		mutex_enter(&irr->irxr_lock);

		while (irr->irxr_nloaned > 0) {
			if (cv_timedwait(&irr->irxr_cv, &irr->irxr_lock,
			    deadline) == -1)
				break;
		}

		if (irr->irxr_nloaned > 0)
			drained = B_FALSE;

		mutex_exit(&irr->irxr_lock);
	}

	return (drained);
}

/*
 * Free the control-block pool of every ring that fully drained.  A ring that
 * did not is left fully intact -- its control blocks are NOT freed and its
 * descriptors are NOT reposted -- so the loaned buffers return harmlessly
 * later, and irxr_shutdown stays set so they are not re-armed.  The loan count
 * is re-tested under the ring lock because a late return can land between the
 * quiesce and here.
 */
void
ice_rx_reclaim(ice_t *ice)
{
	uint_t i;

	for (i = 0; i < ice->ice_num_rxr; i++) {
		ice_rx_ring_t *irr = &ice->ice_rxr[i];

		mutex_enter(&irr->irxr_lock);
		if (irr->irxr_nloaned == 0)
			ice_rx_free_rcbs(irr);
		mutex_exit(&irr->irxr_lock);
	}
}

/*
 * Tear down every rx ring's control blocks on mac_stop.
 * ice_queues_disable() has already disabled the hardware queues, so the
 * reclaim is safe immediately.  The reset path drives the two halves
 * separately, around the reset barrier.
 */
boolean_t
ice_rx_stop(ice_t *ice)
{
	boolean_t drained;

	drained = ice_rx_quiesce(ice);
	ice_rx_reclaim(ice);

	return (drained);
}

/*
 * Detach-time drain: the last gate before the rx rings themselves are freed.
 * ice_rx_recycle() dereferences its ring, so a late loan return after the
 * rings are gone is a use-after-free; detach must fail rather than proceed
 * while any loan is outstanding.
 *
 * This waits and nothing more, matching i40e_drain_rx().  It runs while the
 * rings are still live and armed, so freeing anything here would leave the
 * datapath reading buffers it no longer owns; the reclaim belongs to
 * ice_rx_ring_free(), which runs only once teardown is committed.
 */
boolean_t
ice_rx_drain(ice_t *ice)
{
	clock_t deadline = ddi_get_lbolt() +
	    drv_usectohz(ICE_RX_LOAN_WAIT_US);
	boolean_t drained = B_TRUE;
	uint_t i;

	for (i = 0; i < ice->ice_num_rxr; i++) {
		ice_rx_ring_t *irr = &ice->ice_rxr[i];

		mutex_enter(&irr->irxr_lock);

		while (irr->irxr_nloaned > 0) {
			if (cv_timedwait(&irr->irxr_cv, &irr->irxr_lock,
			    deadline) == -1)
				break;
		}

		if (irr->irxr_nloaned > 0)
			drained = B_FALSE;

		mutex_exit(&irr->irxr_lock);
	}

	return (drained);
}

/*
 * Resume the rx rings after a reset rebuild.  Unlike a plumb, a reset does not
 * have MAC re-drive the per-ring start callbacks, so repost the buffers, reopen
 * each ring, and re-enable its interrupt here.  ice_start_datapath() must have
 * re-allocated the rcb pool first.  The generation number each ring already
 * holds is the one MAC last assigned, so it is left alone; a late mr_start
 * racing this refreshes it and finds the ring already open.
 */
boolean_t
ice_rx_rings_resume(ice_t *ice)
{
	uint_t i;

	for (i = 0; i < ice->ice_num_rxr; i++) {
		ice_rx_ring_t *irr = &ice->ice_rxr[i];
		int ret;

		mutex_enter(&irr->irxr_lock);
		ret = ice_rx_ring_open_locked(irr);
		mutex_exit(&irr->irxr_lock);

		if (ret != 0)
			return (B_FALSE);

		(void) ice_ring_rx_intr_enable((mac_intr_handle_t)irr);
	}

	return (B_TRUE);
}
