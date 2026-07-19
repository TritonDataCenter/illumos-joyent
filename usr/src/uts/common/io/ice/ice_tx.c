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
 * Transmit ring DMA allocation and Tx queue-context programming.
 *
 * This file builds the per-ring state and hands the LAN Tx queue context
 * to the Intel common code: the descriptor ring is allocated as physically
 * contiguous DMA, the sparse ice_tlan_ctx is filled and bit-packed into the
 * Add Tx LAN Queues command buffer, and ice_ena_vsi_txq() programs and enables
 * the queue in one admin-queue round trip (there is no separate per-queue Tx
 * enable register).  The scheduler element TEID the firmware returns is saved;
 * ice_dis_vsi_txq() requires it at teardown.  The packet datapath (descriptor
 * fill, doorbell, completion reclaim) follows below.
 */

#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/pattr.h>
#include <sys/ethernet.h>
#include <netinet/in.h>

#include "ice.h"
#include "ice_common.h"
#include "ice_lan_tx_rx.h"

/*
 * Map a Tx queue to its MSI-X vector and arm the queue's interrupt cause.
 * There is no common-code helper for this; the driver writes QINT_TQCTL
 * directly.  Exposed via a prototype in ice.h so the attach path can wire the
 * vectors as its own step (ICE_ATTACH_QUEUE_INTR), after the queues have been
 * programmed and enabled as part of ICE_ATTACH_RINGS.
 */
void
ice_map_txq_vector(ice_t *ice, ice_tx_ring_t *itr)
{
	struct ice_hw *hw = &ice->ice_hw;
	uint32_t reg;

	reg = ((itr->itxr_vec << QINT_TQCTL_MSIX_INDX_S) &
	    QINT_TQCTL_MSIX_INDX_M) |
	    ((ICE_ITR_IDX_0 << QINT_TQCTL_ITR_INDX_S) &
	    QINT_TQCTL_ITR_INDX_M) |
	    QINT_TQCTL_CAUSE_ENA_M;
	wr32(hw, QINT_TQCTL(itr->itxr_index), reg);
	ice_flush(hw);
}

static boolean_t
ice_tx_kstat_init(ice_t *ice, ice_tx_ring_t *itr)
{
	ice_txq_stat_t *txs = &itr->itxr_stats;
	char name[KSTAT_STRLEN];

	(void) snprintf(name, sizeof (name), "tx_ring_%u", itr->itxr_index);
	itr->itxr_kstat = kstat_create(ICE_MODULE_NAME, ice->ice_instance, name,
	    "net", KSTAT_TYPE_NAMED,
	    sizeof (ice_txq_stat_t) / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL);
	if (itr->itxr_kstat == NULL)
		return (B_FALSE);

	itr->itxr_kstat->ks_data = txs;
	kstat_named_init(&txs->ictxs_bytes, "tx_bytes", KSTAT_DATA_UINT64);
	kstat_named_init(&txs->ictxs_packets, "tx_packets", KSTAT_DATA_UINT64);
	kstat_named_init(&txs->ictxs_bind_bytes, "tx_bind_bytes",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&txs->ictxs_bind_frags, "tx_bind_frags",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&txs->ictxs_copy_bytes, "tx_copy_bytes",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&txs->ictxs_copy_frags, "tx_copy_frags",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&txs->ictxs_bind_fails, "tx_bind_fails",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&txs->ictxs_no_pkt_cache, "tx_no_pkt_cache",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&txs->ictxs_drops, "tx_drops", KSTAT_DATA_UINT64);
	kstat_named_init(&txs->ictxs_blocked, "tx_blocked", KSTAT_DATA_UINT64);
	kstat_named_init(&txs->ictxs_lso_packets, "tx_lso_packets",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&txs->ictxs_lso_drops, "tx_lso_drops",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&txs->ictxs_lso_pullups, "tx_lso_pullups",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&txs->ictxs_lso_nores, "tx_lso_nores",
	    KSTAT_DATA_UINT64);
	kstat_install(itr->itxr_kstat);

	return (B_TRUE);
}

static void
ice_tx_ring_fini(ice_t *ice, ice_tx_ring_t *itr)
{
	if (itr->itxr_kstat != NULL) {
		kstat_delete(itr->itxr_kstat);
		itr->itxr_kstat = NULL;
	}

	ice_dma_free(&itr->itxr_dma);
	itr->itxr_descs = NULL;

	if (itr->itxr_tcb_free_list != NULL) {
		kmem_free(itr->itxr_tcb_free_list,
		    itr->itxr_size * sizeof (ice_tx_ctrl_block_t *));
		itr->itxr_tcb_free_list = NULL;
	}
	if (itr->itxr_tcbs != NULL) {
		kmem_free(itr->itxr_tcbs,
		    itr->itxr_size * sizeof (ice_tx_ctrl_block_t *));
		itr->itxr_tcbs = NULL;
	}
	if (itr->itxr_tcb_area != NULL) {
		/*
		 * The ring is quiesced and reclaimed before teardown, so every
		 * TCB is back in the pool holding nothing; free the backing.
		 */
		kmem_free(itr->itxr_tcb_area,
		    itr->itxr_size * sizeof (ice_tx_ctrl_block_t));
		itr->itxr_tcb_area = NULL;
	}

	mutex_destroy(&itr->itxr_tcb_lock);
	cv_destroy(&itr->itxr_cv);
	mutex_destroy(&itr->itxr_lock);
}

static boolean_t
ice_tx_ring_alloc(ice_t *ice, ice_tx_ring_t *itr, uint_t index)
{
	ddi_dma_attr_t attr;
	ddi_device_acc_attr_t acc;
	size_t descsz;
	uint16_t i;

	itr->itxr_ice = ice;

	/*
	 * Absolute HW Tx queue index.  The single PF data VSI's queues start at
	 * zero, so ring i is queue i; with multiple VSIs sharing the function
	 * this becomes the VSI's first queue plus i.
	 */
	itr->itxr_index = index;

	/*
	 * Vector 0 is the OICR; queue vectors begin at 1.  A simple 1:1 map,
	 * capped so queues beyond the vector count share the last vector.
	 */
	itr->itxr_vec = 1 + index;
	if (itr->itxr_vec >= (uint32_t)ice->ice_intr_count)
		itr->itxr_vec = ice->ice_intr_count - 1;

	itr->itxr_size = ice->ice_tx_ring_size != 0 ?
	    ice->ice_tx_ring_size : ICE_DEF_TX_RING_SIZE;

	mutex_init(&itr->itxr_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(ice->ice_intr_pri));
	cv_init(&itr->itxr_cv, NULL, CV_DRIVER, NULL);
	mutex_init(&itr->itxr_tcb_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(ice->ice_intr_pri));

	descsz = (size_t)itr->itxr_size * sizeof (struct ice_tx_desc);
	ice_dma_ring_attr(ice, &attr);
	ice_dma_acc_attr(ice, &acc);
	if (!ice_dma_alloc(ice, &itr->itxr_dma, &attr, &acc, B_TRUE, descsz,
	    B_TRUE)) {
		ice_error(ice, "failed to allocate tx descriptor ring %u",
		    index);
		goto fail;
	}
	itr->itxr_descs = (struct ice_tx_desc *)itr->itxr_dma.idb_va;

	itr->itxr_tcb_area = kmem_zalloc(itr->itxr_size *
	    sizeof (ice_tx_ctrl_block_t), KM_SLEEP);
	itr->itxr_tcbs = kmem_zalloc(itr->itxr_size *
	    sizeof (ice_tx_ctrl_block_t *), KM_SLEEP);
	itr->itxr_tcb_free_list = kmem_zalloc(itr->itxr_size *
	    sizeof (ice_tx_ctrl_block_t *), KM_SLEEP);

	/*
	 * The by-slot parked array starts all-NULL (it is kmem_zalloc'd above):
	 * ice_tx_emit() is the sole populator, parking a TCB only at a packet's
	 * first-descriptor slot.  Every TCB begins life only on the free list.
	 */
	for (i = 0; i < itr->itxr_size; i++) {
		ice_tx_ctrl_block_t *itcb = &itr->itxr_tcb_area[i];

		itcb->itcb_ring = itr;
		itcb->itcb_type = ITCB_NOT_USED;
		itr->itxr_tcb_free_list[i] = itcb;
	}
	itr->itxr_tcb_nfree = itr->itxr_size;
	itr->itxr_avail = itr->itxr_size;
	if (!ice_tx_kstat_init(ice, itr)) {
		ice_error(ice, "failed to create tx ring %u kstat", index);
		goto fail;
	}

	return (B_TRUE);

fail:
	ice_tx_ring_fini(ice, itr);
	return (B_FALSE);
}

boolean_t
ice_tx_rings_alloc(ice_t *ice)
{
	uint_t i;

	ice->ice_txr = kmem_zalloc(ice->ice_num_txr * sizeof (ice_tx_ring_t),
	    KM_SLEEP);

	for (i = 0; i < ice->ice_num_txr; i++) {
		if (!ice_tx_ring_alloc(ice, &ice->ice_txr[i], i)) {
			while (i-- > 0)
				ice_tx_ring_fini(ice, &ice->ice_txr[i]);
			kmem_free(ice->ice_txr,
			    ice->ice_num_txr * sizeof (ice_tx_ring_t));
			ice->ice_txr = NULL;
			return (B_FALSE);
		}
	}

	return (B_TRUE);
}

void
ice_tx_rings_free(ice_t *ice)
{
	uint_t i;

	if (ice->ice_txr == NULL)
		return;

	for (i = 0; i < ice->ice_num_txr; i++)
		ice_tx_ring_fini(ice, &ice->ice_txr[i]);

	kmem_free(ice->ice_txr, ice->ice_num_txr * sizeof (ice_tx_ring_t));
	ice->ice_txr = NULL;
}

int
ice_tx_ring_program(ice_t *ice, ice_tx_ring_t *itr)
{
	struct ice_hw *hw = &ice->ice_hw;
	ice_vsi_t *vsi = &ice->ice_pf_vsi;
	struct ice_tlan_ctx tlan;
	struct ice_aqc_add_tx_qgrp *qg;
	uint8_t ctx[ICE_TXQ_CTX_SZ];
	uint16_t qg_size;
	int status;

	bzero(&tlan, sizeof (tlan));

	/* base is the ring DMA address in 128-byte units. */
	tlan.base = ICE_DMA_PA(&itr->itxr_dma) >> ICE_TLAN_CTX_BASE_S;
	tlan.port_num = hw->port_info->lport;
	tlan.pf_num = hw->pf_id;
	tlan.vmvf_type = ICE_TLAN_CTX_VMVF_TYPE_PF;
	tlan.src_vsi = ice_get_hw_vsi_num(hw, vsi->vi_handle);
	tlan.qlen = itr->itxr_size;

	/*
	 * The LAN Tx queue context requires these for normal (legacy,
	 * non-context-descriptor) operation; int_q_state is hardware-owned and
	 * left zero.  Segmentation offload is not advertised yet, but tso_ena
	 * is part of the required legacy configuration.
	 */
	tlan.tso_ena = 1;
	tlan.tso_qnum = (uint16_t)itr->itxr_index;
	tlan.internal_usage_flag = 1;
	tlan.legacy_int = 1;

	/*
	 * ice_ena_vsi_txq() does not pack the context for us: bit-pack the
	 * sparse ice_tlan_ctx into the dense LAN Tx context and copy the valid
	 * leading bytes into the command's per-queue context field.
	 */
	bzero(ctx, sizeof (ctx));
	status = ice_set_ctx(hw, (uint8_t *)&tlan, ctx, ice_tlan_ctx_info);
	if (status != ICE_SUCCESS) {
		ice_error(ice, "failed to pack tx queue %u context: %d",
		    itr->itxr_index, status);
		return (status);
	}

	qg_size = ice_struct_size(qg, txqs, 1);
	qg = kmem_zalloc(qg_size, KM_SLEEP);
	qg->num_txqs = 1;
	qg->txqs[0].txq_id = CPU_TO_LE16((uint16_t)itr->itxr_index);
	bcopy(ctx, qg->txqs[0].txq_ctx, sizeof (qg->txqs[0].txq_ctx));

	/*
	 * One queue group, one queue.  The queue handle is the per-VSI queue
	 * index (ring i for the single PF VSI); it must be within the queue
	 * count reserved by ice_cfg_vsi_lan().
	 */
	mutex_enter(&ice->ice_lock);
	status = ice_ena_vsi_txq(hw->port_info, vsi->vi_handle, 0,
	    (uint16_t)itr->itxr_index, 1, qg, qg_size, NULL);
	if (status == ICE_SUCCESS)
		itr->itxr_q_teid = LE32_TO_CPU(qg->txqs[0].q_teid);
	mutex_exit(&ice->ice_lock);

	kmem_free(qg, qg_size);

	if (status != ICE_SUCCESS) {
		ice_error(ice, "ice_ena_vsi_txq failed for tx queue %u: %d",
		    itr->itxr_index, status);
		return (status);
	}

	return (ICE_SUCCESS);
}

void
ice_tx_ring_unprogram(ice_t *ice, ice_tx_ring_t *itr)
{
	struct ice_hw *hw = &ice->ice_hw;
	uint16_t q_handle, q_id;
	uint32_t q_teid;
	int status;

	q_handle = (uint16_t)itr->itxr_index;
	q_id = (uint16_t)itr->itxr_index;
	q_teid = itr->itxr_q_teid;

	mutex_enter(&ice->ice_lock);
	status = ice_dis_vsi_txq(hw->port_info, ice->ice_pf_vsi.vi_handle, 0, 1,
	    &q_handle, &q_id, &q_teid, ICE_NO_RESET, 0, NULL);
	mutex_exit(&ice->ice_lock);

	if (status != ICE_SUCCESS) {
		ice_error(ice, "!ice_dis_vsi_txq failed for tx queue %u: %d",
		    itr->itxr_index, status);
	}
}

/*
 * Tx packet datapath.
 *
 * A frame arrives as an mblk_t chain of arbitrary fragments.  A whole packet
 * up to ICE_TX_SMALL_PKT is copied into a single pre-mapped small-pool buffer;
 * otherwise every fragment is DMA-bound, up to ICE_TX_MAX_COOKIE cookies for
 * the whole packet, falling back to one full-packet copy if a bind fails or
 * the packet would exceed that budget.  Each bound cookie or copy buffer
 * becomes one ice_tx_desc on the ring; the final descriptor of the packet
 * carries EOP|RS so hardware reports completion.
 *
 * The control blocks (TCBs) consumed by a packet are parked in itxr_tcbs[] at
 * the same slots as the descriptors they describe.  Because a packet always
 * uses at least as many descriptors as TCBs, reserving descriptor space also
 * reserves TCB-slot space.  Reclaim walks from itxr_head: with RS set,
 * hardware rewrites the last descriptor's DTYPE to DESC_DONE, which is the
 * signal that the packet (and every descriptor before it) is complete.
 *
 * LSO packets prepend one context descriptor.  Their headers are copied into
 * a dedicated single-cookie buffer, and payload descriptors are constrained
 * so each hardware segment stays within the controller's fetch limit.
 */

/* QW1 dtype mask, fully shifted, to read the completion writeback. */
#define	ICE_TX_QW1_DTYPE_DONE_M	ICE_TXD_QW1_DTYPE_M

/*
 * Outcome of assembling a packet's TCB chain.  NORES is transient (no buffers
 * or descriptors right now) and the packet should be retried; DROP means the
 * packet can never be sent on this configuration and must be discarded.
 */
typedef enum ice_tx_build {
	ICE_TX_BUILD_OK,
	ICE_TX_BUILD_NORES,
	ICE_TX_BUILD_DROP,
	ICE_TX_BUILD_PULLUP
} ice_tx_build_t;

static inline uint16_t
ice_tx_ring_next(const ice_tx_ring_t *itr, uint16_t idx)
{
	idx++;
	if (idx == itr->itxr_size)
		idx = 0;
	return (idx);
}

static ice_tx_ctrl_block_t *
ice_tcb_alloc(ice_tx_ring_t *itr)
{
	ice_tx_ctrl_block_t *tcb = NULL;

	mutex_enter(&itr->itxr_tcb_lock);
	if (itr->itxr_tcb_nfree > 0) {
		tcb = itr->itxr_tcb_free_list[--itr->itxr_tcb_nfree];
		itr->itxr_tcb_free_list[itr->itxr_tcb_nfree] = NULL;
	}
	mutex_exit(&itr->itxr_tcb_lock);

	return (tcb);
}

/*
 * Release whatever a TCB holds (copy buffer, DMA binding, retained mblk) and
 * return it to the ring's free list.  The bind handles are allocated lazily in
 * ice_tx_bind_fragment() and freed here so the append-only datapath does not
 * have to touch the attach-time ring alloc/teardown paths.
 */
static void
ice_tcb_free(ice_tx_ring_t *itr, ice_tx_ctrl_block_t *tcb)
{
	ice_t *ice = itr->itxr_ice;

	if (tcb == NULL)
		return;

	switch (tcb->itcb_type) {
	case ITCB_NOT_USED:
		break;
	case ITCB_SMALL_COPY:
		ice_small_buf_free(ice, tcb->itcb_buf);
		tcb->itcb_buf = NULL;
		break;
	case ITCB_COPY:
		ice_buf_free(ice, tcb->itcb_buf);
		tcb->itcb_buf = NULL;
		break;
	case ITCB_LSO_COPY:
		ice_lso_buf_free(ice, tcb->itcb_buf);
		tcb->itcb_buf = NULL;
		break;
	case ITCB_BIND:
		(void) ddi_dma_unbind_handle(tcb->itcb_dmah);
		ddi_dma_free_handle(&tcb->itcb_dmah);
		tcb->itcb_dmah = NULL;
		break;
	case ITCB_LSO_BIND:
		(void) ddi_dma_unbind_handle(tcb->itcb_lso_dmah);
		ddi_dma_free_handle(&tcb->itcb_lso_dmah);
		tcb->itcb_lso_dmah = NULL;
		break;
	}

	tcb->itcb_type = ITCB_NOT_USED;
	tcb->itcb_len = 0;
	if (tcb->itcb_mp != NULL) {
		freemsg(tcb->itcb_mp);
		tcb->itcb_mp = NULL;
	}

	mutex_enter(&itr->itxr_tcb_lock);
	ASSERT3U(itr->itxr_tcb_nfree, <, itr->itxr_size);
	itr->itxr_tcb_free_list[itr->itxr_tcb_nfree++] = tcb;
	mutex_exit(&itr->itxr_tcb_lock);
}

/*
 * DMA-bind a single mblk fragment.  Returns the bound TCB with the binding
 * left in place; the cookies are walked at descriptor-fill time and the
 * handle is unbound/freed when the TCB is recycled.  *ncookiesp is the cookie
 * count, which is also the number of descriptors this fragment will consume.
 */
static ice_tx_ctrl_block_t *
ice_tx_bind_fragment(ice_tx_ring_t *itr, mblk_t *mp, uint_t *ncookiesp)
{
	ice_t *ice = itr->itxr_ice;
	ice_tx_ctrl_block_t *tcb;
	ddi_dma_attr_t attr;
	uint_t ncookies;
	int ret;

	tcb = ice_tcb_alloc(itr);
	if (tcb == NULL)
		return (NULL);

	ice_pkt_txbind_attr(ice, &attr);
	if (ddi_dma_alloc_handle(ice->ice_dip, &attr, DDI_DMA_DONTWAIT, NULL,
	    &tcb->itcb_dmah) != DDI_SUCCESS) {
		ice_tcb_free(itr, tcb);
		return (NULL);
	}

	ret = ddi_dma_addr_bind_handle(tcb->itcb_dmah, NULL,
	    (caddr_t)mp->b_rptr, MBLKL(mp), DDI_DMA_WRITE | DDI_DMA_STREAMING,
	    DDI_DMA_DONTWAIT, NULL, NULL, NULL);
	if (ret != DDI_DMA_MAPPED) {
		ddi_dma_free_handle(&tcb->itcb_dmah);
		tcb->itcb_dmah = NULL;
		ice_tcb_free(itr, tcb);
		itr->itxr_stats.ictxs_bind_fails.value.ui64++;
		return (NULL);
	}

	ncookies = ddi_dma_ncookies(tcb->itcb_dmah);
	tcb->itcb_type = ITCB_BIND;
	tcb->itcb_len = MBLKL(mp);

	itr->itxr_stats.ictxs_bind_bytes.value.ui64 += tcb->itcb_len;
	itr->itxr_stats.ictxs_bind_frags.value.ui64++;

	*ncookiesp = ncookies;
	return (tcb);
}

/*
 * LSO binds may span more cookies than ordinary frames.  The separate handle
 * prevents a failed LSO bind from disturbing the ordinary bind lifecycle.
 */
static ice_tx_ctrl_block_t *
ice_tx_bind_lso_fragment(ice_tx_ring_t *itr, caddr_t addr, size_t len,
    uint_t *ncookiesp)
{
	ice_t *ice = itr->itxr_ice;
	ice_tx_ctrl_block_t *tcb;
	ddi_dma_attr_t attr;
	uint_t ncookies;
	int ret;

	if (len == 0 || len > ICE_LSO_MAXLEN)
		return (NULL);

	tcb = ice_tcb_alloc(itr);
	if (tcb == NULL)
		return (NULL);

	ice_pkt_txbind_lso_attr(ice, &attr);
	if (ddi_dma_alloc_handle(ice->ice_dip, &attr, DDI_DMA_DONTWAIT, NULL,
	    &tcb->itcb_lso_dmah) != DDI_SUCCESS) {
		ice_tcb_free(itr, tcb);
		return (NULL);
	}

	ret = ddi_dma_addr_bind_handle(tcb->itcb_lso_dmah, NULL, addr, len,
	    DDI_DMA_WRITE | DDI_DMA_STREAMING, DDI_DMA_DONTWAIT, NULL, NULL,
	    NULL);
	if (ret != DDI_DMA_MAPPED) {
		ddi_dma_free_handle(&tcb->itcb_lso_dmah);
		tcb->itcb_lso_dmah = NULL;
		ice_tcb_free(itr, tcb);
		itr->itxr_stats.ictxs_bind_fails.value.ui64++;
		return (NULL);
	}

	ncookies = ddi_dma_ncookies(tcb->itcb_lso_dmah);
	if (ncookies == 0 || ncookies > ICE_TX_LSO_MAX_COOKIE) {
		(void) ddi_dma_unbind_handle(tcb->itcb_lso_dmah);
		ddi_dma_free_handle(&tcb->itcb_lso_dmah);
		tcb->itcb_lso_dmah = NULL;
		ice_tcb_free(itr, tcb);
		return (NULL);
	}

	tcb->itcb_type = ITCB_LSO_BIND;
	tcb->itcb_len = (uint32_t)len;
	itr->itxr_stats.ictxs_bind_bytes.value.ui64 += len;
	itr->itxr_stats.ictxs_bind_frags.value.ui64++;

	*ncookiesp = ncookies;
	return (tcb);
}

/*
 * Copy the entire packet into a single pool buffer.  Used for small packets
 * and as the fallback when a fragment cannot be (or is not worth) bound.  The
 * small pool is tried first; if it cannot hold the frame, the full-size pool
 * is used.  On success returns the TCB; *resp distinguishes a transient
 * no-buffer condition (NORES) from a frame too large for any pool buffer
 * (DROP) -- the latter must not loop in back-pressure.
 */
static ice_tx_ctrl_block_t *
ice_tx_copy_packet(ice_tx_ring_t *itr, mblk_t *mp, size_t msglen,
    ice_tx_build_t *resp)
{
	ice_t *ice = itr->itxr_ice;
	ice_tx_ctrl_block_t *tcb;
	mblk_t *cmp;
	caddr_t dst;

	tcb = ice_tcb_alloc(itr);
	if (tcb == NULL) {
		*resp = ICE_TX_BUILD_NORES;
		return (NULL);
	}

	if (msglen <= ICE_TX_SMALL_PKT &&
	    (tcb->itcb_buf = ice_small_buf_alloc(ice)) != NULL) {
		tcb->itcb_type = ITCB_SMALL_COPY;
	} else if ((tcb->itcb_buf = ice_buf_alloc(ice)) != NULL) {
		tcb->itcb_type = ITCB_COPY;
	} else {
		ice_tcb_free(itr, tcb);
		*resp = ICE_TX_BUILD_NORES;
		return (NULL);
	}

	/*
	 * The pool buffers are fixed size.  A frame larger than the chosen
	 * buffer cannot be copied; since it also failed to bind within the
	 * cookie budget, it is undeliverable and must be dropped.
	 */
	if (msglen > tcb->itcb_buf->idb_len) {
		ice_tcb_free(itr, tcb);
		*resp = ICE_TX_BUILD_DROP;
		return (NULL);
	}

	dst = tcb->itcb_buf->idb_va;
	for (cmp = mp; cmp != NULL; cmp = cmp->b_cont) {
		size_t clen = MBLKL(cmp);

		if (clen == 0)
			continue;
		bcopy(cmp->b_rptr, dst, clen);
		dst += clen;
	}
	tcb->itcb_len = msglen;

	itr->itxr_stats.ictxs_copy_bytes.value.ui64 += msglen;
	itr->itxr_stats.ictxs_copy_frags.value.ui64++;

	*resp = ICE_TX_BUILD_OK;
	return (tcb);
}

/*
 * Copy from an mblk cursor while advancing it.  Header and fallback copies use
 * the same cursor so malformed chains cannot make the payload walk revisit or
 * skip bytes.
 */
static boolean_t
ice_tx_mblk_copy(mblk_t **mpp, size_t *offp, caddr_t dst, size_t len)
{
	mblk_t *mp = *mpp;
	size_t off = *offp;

	while (len > 0) {
		size_t mlen, ncopy;

		if (mp == NULL || mp->b_wptr < mp->b_rptr)
			return (B_FALSE);

		mlen = MBLKL(mp);
		if (off > mlen)
			return (B_FALSE);
		if (off == mlen) {
			mp = mp->b_cont;
			off = 0;
			continue;
		}

		ncopy = MIN(len, mlen - off);
		bcopy(mp->b_rptr + off, dst, ncopy);
		dst += ncopy;
		off += ncopy;
		len -= ncopy;

		if (off == mlen) {
			mp = mp->b_cont;
			off = 0;
		}
	}

	*mpp = mp;
	*offp = off;
	return (B_TRUE);
}

static boolean_t
ice_tx_mblk_advance(mblk_t **mpp, size_t *offp, size_t len)
{
	mblk_t *mp = *mpp;
	size_t off = *offp;

	while (len > 0) {
		size_t mlen, nadvance;

		if (mp == NULL || mp->b_wptr < mp->b_rptr)
			return (B_FALSE);

		mlen = MBLKL(mp);
		if (off > mlen)
			return (B_FALSE);
		if (off == mlen) {
			mp = mp->b_cont;
			off = 0;
			continue;
		}

		nadvance = MIN(len, mlen - off);
		off += nadvance;
		len -= nadvance;
		if (off == mlen) {
			mp = mp->b_cont;
			off = 0;
		}
	}

	*mpp = mp;
	*offp = off;
	return (B_TRUE);
}

static ice_tx_ctrl_block_t *
ice_tx_lso_copy(ice_tx_ring_t *itr, mblk_t **mpp, size_t *offp, size_t len,
    ice_tx_build_t *resp)
{
	ice_t *ice = itr->itxr_ice;
	ice_tx_ctrl_block_t *tcb;

	tcb = ice_tcb_alloc(itr);
	if (tcb == NULL) {
		*resp = ICE_TX_BUILD_NORES;
		return (NULL);
	}

	tcb->itcb_buf = ice_lso_buf_alloc(ice);
	if (tcb->itcb_buf == NULL) {
		ice_tcb_free(itr, tcb);
		*resp = ICE_TX_BUILD_NORES;
		return (NULL);
	}
	tcb->itcb_type = ITCB_LSO_COPY;

	if (len == 0 || len > tcb->itcb_buf->idb_len ||
	    !ice_tx_mblk_copy(mpp, offp, tcb->itcb_buf->idb_va, len)) {
		ice_tcb_free(itr, tcb);
		*resp = ICE_TX_BUILD_DROP;
		return (NULL);
	}

	tcb->itcb_len = (uint32_t)len;
	itr->itxr_stats.ictxs_copy_bytes.value.ui64 += len;
	itr->itxr_stats.ictxs_copy_frags.value.ui64++;
	*resp = ICE_TX_BUILD_OK;

	return (tcb);
}

/*
 * Push only the descriptors this packet wrote, splitting at ring wrap.  Slot 0
 * of the ring sits at offset 0 of itxr_dma, so offsets are just slot * size.
 */
static void
ice_tx_sync_descs(ice_tx_ring_t *itr, uint16_t start, uint_t n)
{
	ddi_dma_handle_t h = itr->itxr_dma.idb_dma_handle;
	const size_t dsz = sizeof (struct ice_tx_desc);
	uint_t head = MIN(n, (uint_t)(itr->itxr_size - start));

	(void) ddi_dma_sync(h, (off_t)start * dsz, head * dsz,
	    DDI_DMA_SYNC_FORDEV);
	if (n > head) {
		(void) ddi_dma_sync(h, 0, (n - head) * dsz,
		    DDI_DMA_SYNC_FORDEV);
	}
}

/*
 * Write one DATA descriptor.  buf_addr is the fragment's IOVA; bufsz its
 * length (capped at ICE_TX_MAX_BUFSZ -- the caller guarantees fragments fit,
 * since copy buffers are frame-sized and bound cookies obey the bind attrs).
 */
static void
ice_tx_write_desc(ice_tx_ring_t *itr, uint16_t slot, uint64_t pa,
    uint32_t len, uint64_t cmd, uint64_t off)
{
	struct ice_tx_desc *desc = &itr->itxr_descs[slot];
	uint64_t qw1;

	ASSERT3U(len, <=, ICE_TX_MAX_BUFSZ);

	qw1 = ((uint64_t)ICE_TX_DESC_DTYPE_DATA << ICE_TXD_QW1_DTYPE_S) |
	    (cmd << ICE_TXD_QW1_CMD_S) |
	    (off << ICE_TXD_QW1_OFFSET_S) |
	    ((uint64_t)len << ICE_TXD_QW1_TX_BUF_SZ_S);

	desc->buf_addr = CPU_TO_LE64(pa);
	desc->cmd_type_offset_bsz = CPU_TO_LE64(qw1);
}

static void
ice_tx_write_ctx_desc(ice_tx_ring_t *itr, uint16_t slot, uint32_t mss,
    uint32_t tsolen)
{
	struct ice_tx_ctx_desc *desc;
	uint64_t qw1;

	desc = (struct ice_tx_ctx_desc *)&itr->itxr_descs[slot];
	qw1 = ((uint64_t)ICE_TX_DESC_DTYPE_CTX <<
	    ICE_TXD_CTX_QW1_DTYPE_S) |
	    ((uint64_t)ICE_TX_CTX_DESC_TSO << ICE_TXD_CTX_QW1_CMD_S) |
	    ((uint64_t)tsolen << ICE_TXD_CTX_QW1_TSO_LEN_S) |
	    ((uint64_t)mss << ICE_TXD_CTX_QW1_MSS_S);

	desc->tunneling_params = 0;
	desc->l2tag2 = 0;
	desc->rsvd = 0;
	desc->qw1 = CPU_TO_LE64(qw1);
}

/*
 * Translate requested offloads into data-descriptor fields and, when needed,
 * the TSO context.  Invalid metadata is dropped because trusting it can make
 * the hardware read beyond the packet or wedge the transmit queue.
 */
static ice_tx_build_t
ice_tx_context(ice_t *ice, mblk_t *mp, ice_tx_ctx_t *ctx)
{
	mac_ether_offload_info_t meo;
	uint32_t chkflags, lsoflags, mss = 0;
	size_t hdrlen, tsolen;
	const uint32_t l23 = MEOI_L2INFO_SET | MEOI_L3INFO_SET;

	bzero(ctx, sizeof (*ctx));

	mac_hcksum_get(mp, NULL, NULL, NULL, NULL, &chkflags);
	mac_lso_get(mp, &mss, &lsoflags);
	if (chkflags == 0 && lsoflags == 0)
		return (ICE_TX_BUILD_OK);

	mac_ether_offload_info(mp, &meo);
	ctx->itc_use_ctx = (lsoflags & HW_LSO) != 0;

	if ((chkflags & HCK_IPV4_HDRCKSUM) != 0) {
		if ((meo.meoi_flags & l23) != l23 ||
		    meo.meoi_l3proto != ETHERTYPE_IP)
			return (ICE_TX_BUILD_DROP);
		ctx->itc_data_cmd |= ICE_TX_DESC_CMD_IIPT_IPV4_CSUM;
		ctx->itc_data_off |= (uint64_t)(meo.meoi_l2hlen >> 1) <<
		    ICE_TX_DESC_LEN_MACLEN_S;
		ctx->itc_data_off |= (uint64_t)(meo.meoi_l3hlen >> 2) <<
		    ICE_TX_DESC_LEN_IPLEN_S;
	}

	if ((chkflags & HCK_PARTIALCKSUM) != 0) {
		if ((meo.meoi_flags & MEOI_L4INFO_SET) == 0)
			return (ICE_TX_BUILD_DROP);

		if ((chkflags & HCK_IPV4_HDRCKSUM) == 0) {
			if ((meo.meoi_flags & l23) != l23)
				return (ICE_TX_BUILD_DROP);
			if (meo.meoi_l3proto == ETHERTYPE_IP)
				ctx->itc_data_cmd |= ICE_TX_DESC_CMD_IIPT_IPV4;
			else if (meo.meoi_l3proto == ETHERTYPE_IPV6)
				ctx->itc_data_cmd |= ICE_TX_DESC_CMD_IIPT_IPV6;
			else
				return (ICE_TX_BUILD_DROP);
			ctx->itc_data_off |=
			    (uint64_t)(meo.meoi_l2hlen >> 1) <<
			    ICE_TX_DESC_LEN_MACLEN_S;
			ctx->itc_data_off |=
			    (uint64_t)(meo.meoi_l3hlen >> 2) <<
			    ICE_TX_DESC_LEN_IPLEN_S;
		}

		switch (meo.meoi_l4proto) {
		case IPPROTO_TCP:
			ctx->itc_data_cmd |= ICE_TX_DESC_CMD_L4T_EOFT_TCP;
			break;
		case IPPROTO_UDP:
			ctx->itc_data_cmd |= ICE_TX_DESC_CMD_L4T_EOFT_UDP;
			break;
		case IPPROTO_SCTP:
			ctx->itc_data_cmd |= ICE_TX_DESC_CMD_L4T_EOFT_SCTP;
			break;
		default:
			return (ICE_TX_BUILD_DROP);
		}
		ctx->itc_data_off |= (uint64_t)(meo.meoi_l4hlen >> 2) <<
		    ICE_TX_DESC_LEN_L4_LEN_S;
	}

	if ((lsoflags & HW_LSO) == 0)
		return (ICE_TX_BUILD_OK);

	if ((chkflags & HCK_PARTIALCKSUM) == 0 ||
	    (meo.meoi_l3proto == ETHERTYPE_IP &&
	    (chkflags & HCK_IPV4_HDRCKSUM) == 0))
		return (ICE_TX_BUILD_DROP);

	if ((meo.meoi_flags & (l23 | MEOI_L4INFO_SET)) !=
	    (l23 | MEOI_L4INFO_SET) ||
	    (meo.meoi_l3proto != ETHERTYPE_IP &&
	    meo.meoi_l3proto != ETHERTYPE_IPV6) ||
	    meo.meoi_l4proto != IPPROTO_TCP ||
	    meo.meoi_l2hlen > ICE_TXD_MACLEN_MAX ||
	    meo.meoi_l3hlen > ICE_TXD_IPLEN_MAX ||
	    meo.meoi_l4hlen > ICE_TXD_L4LEN_MAX ||
	    (meo.meoi_l2hlen & 1) != 0 ||
	    (meo.meoi_l3hlen & 3) != 0 ||
	    (meo.meoi_l4hlen & 3) != 0)
		return (ICE_TX_BUILD_DROP);

	hdrlen = meo.meoi_l2hlen + meo.meoi_l3hlen + meo.meoi_l4hlen;
	if (hdrlen == 0 || hdrlen >= meo.meoi_len ||
	    meo.meoi_len != msgdsize(mp))
		return (ICE_TX_BUILD_DROP);
	tsolen = meo.meoi_len - hdrlen;
	if (tsolen > ICE_LSO_MAXLEN)
		return (ICE_TX_BUILD_DROP);

	if (mss < ICE_TX_LSO_MIN_MSS) {
		if (meo.meoi_len > ice->ice_mtu)
			return (ICE_TX_BUILD_DROP);
		ctx->itc_use_ctx = B_FALSE;
		return (ICE_TX_BUILD_OK);
	}
	if (mss > ICE_TXD_CTX_MAX_MSS)
		return (ICE_TX_BUILD_DROP);

	ctx->itc_mss = mss;
	ctx->itc_tsolen = (uint32_t)tsolen;
	ASSERT3U(ctx->itc_mss, <=, ICE_TXD_CTX_MAX_MSS);

	return (ICE_TX_BUILD_OK);
}

/*
 * Build the TCB chain for a packet.  A whole packet up to ICE_TX_SMALL_PKT is
 * copied into one small-pool buffer; anything larger has each of its fragments
 * bound.  A bind failure, or a fragment that would push the packet past the
 * ICE_TX_MAX_COOKIE descriptor budget, forces a single full-packet copy.
 * Returns the number of TCBs produced (0 on resource exhaustion) and fills
 * tcbs[]/ndesc.
 */
static ice_tx_build_t
ice_tx_build_tcbs(ice_tx_ring_t *itr, mblk_t *mp, size_t msglen,
    ice_tx_ctrl_block_t **tcbs, uint_t *ntcbp, uint_t *ndescp)
{
	ice_tx_build_t res;
	mblk_t *cmp;
	uint_t ntcb = 0;
	uint_t ndesc = 0;

	/*
	 * Binding a small frame costs a handle alloc/bind/unbind/free per
	 * fragment, far more than copying it into a pre-mapped buffer.
	 */
	if (msglen <= ICE_TX_SMALL_PKT) {
		tcbs[0] = ice_tx_copy_packet(itr, mp, msglen, &res);
		if (tcbs[0] != NULL) {
			*ntcbp = 1;
			*ndescp = 1;
			return (ICE_TX_BUILD_OK);
		}
		if (res == ICE_TX_BUILD_DROP)
			return (res);
		/*
		 * NORES: the pool is momentarily empty.  Fall through and bind
		 * rather than block, so the small pool cannot become a new
		 * back-pressure choke point.
		 */
	}

	for (cmp = mp; cmp != NULL; cmp = cmp->b_cont) {
		ice_tx_ctrl_block_t *tcb;
		uint_t ncookies = 0;

		if (MBLKL(cmp) == 0)
			continue;

		tcb = ice_tx_bind_fragment(itr, cmp, &ncookies);
		if (tcb == NULL || ndesc + ncookies > ICE_TX_MAX_COOKIE) {
			if (tcb != NULL)
				ice_tcb_free(itr, tcb);
			goto force_copy;
		}

		tcbs[ntcb++] = tcb;
		ndesc += ncookies;
	}

	if (ntcb == 0)
		goto force_copy;

	*ntcbp = ntcb;
	*ndescp = ndesc;
	return (ICE_TX_BUILD_OK);

force_copy:
	/* Undo any partial bind work and copy the whole frame instead. */
	while (ntcb > 0)
		ice_tcb_free(itr, tcbs[--ntcb]);

	tcbs[0] = ice_tx_copy_packet(itr, mp, msglen, &res);
	if (tcbs[0] == NULL)
		return (res);

	*ntcbp = 1;
	*ndescp = 1;
	return (ICE_TX_BUILD_OK);
}

static void
ice_tx_free_tcbs(ice_tx_ring_t *itr, ice_tx_ctrl_block_t **tcbs,
    uint_t ntcb)
{
	while (ntcb > 0)
		ice_tcb_free(itr, tcbs[--ntcb]);
}

/*
 * Model the controller's sliding MSS window for one data descriptor.  A
 * descriptor that crosses an MSS boundary is counted once in both segments.
 */
static boolean_t
ice_tx_lso_desc_fits(size_t len, uint32_t mss, size_t *segbytesp,
    uint_t *segdescsp)
{
	size_t segbytes = *segbytesp;
	uint_t segdescs = *segdescsp;

	if (len == 0)
		return (B_FALSE);

	while (len > 0) {
		size_t nbytes;

		if (++segdescs > ICE_TX_LSO_SEG_DESCS)
			return (B_FALSE);

		nbytes = MIN(len, mss - segbytes);
		segbytes += nbytes;
		len -= nbytes;
		if (segbytes == mss) {
			segbytes = 0;
			segdescs = 0;
		}
	}

	*segbytesp = segbytes;
	*segdescsp = segdescs;
	return (B_TRUE);
}

/*
 * Build an LSO header and payload without changing ring accounting.  Bindings
 * that would leave an unfinished segment at the descriptor limit are replaced
 * by one copy descriptor that spans enough MSS boundaries to restore margin.
 */
static ice_tx_build_t
ice_tx_lso_build(ice_tx_ring_t *itr, mblk_t *mp,
    const ice_tx_ctx_t *ctx, ice_tx_ctrl_block_t **tcbs, uint_t *ntcbp,
    uint_t *ndescp, boolean_t allow_pullup)
{
	mac_ether_offload_info_t meo;
	ice_tx_build_t res;
	ice_tx_ctrl_block_t *tcb;
	mblk_t *cmp = mp;
	size_t coff = 0;
	size_t hdrlen, remaining;
	size_t segbytes = 0;
	uint_t segdescs = 0;
	uint_t ntcb = 0, ndesc = 0;
	const uint32_t meoflags = MEOI_L2INFO_SET | MEOI_L3INFO_SET |
	    MEOI_L4INFO_SET;

	mac_ether_offload_info(mp, &meo);
	hdrlen = meo.meoi_l2hlen + meo.meoi_l3hlen + meo.meoi_l4hlen;
	if ((meo.meoi_flags & meoflags) != meoflags ||
	    meo.meoi_l4proto != IPPROTO_TCP || hdrlen == 0 ||
	    hdrlen >= meo.meoi_len || meo.meoi_len != msgdsize(mp) ||
	    ctx->itc_tsolen != meo.meoi_len - hdrlen ||
	    hdrlen > ICE_TX_LSO_BUFSZ)
		return (ICE_TX_BUILD_DROP);

	/*
	 * Keeping headers separate prevents the controller from charging one
	 * descriptor once for the header and again for the first payload
	 * segment.
	 */
	tcb = ice_tx_lso_copy(itr, &cmp, &coff, hdrlen, &res);
	if (tcb == NULL)
		return (res);
	tcbs[ntcb++] = tcb;
	ndesc++;
	remaining = ctx->itc_tsolen;

	while (remaining > 0) {
		size_t mlen, fraglen;
		size_t tsegbytes;
		uint_t tsegdescs;
		uint_t ncookies = 0;
		uint_t c;
		boolean_t fits = B_TRUE;

		while (cmp != NULL) {
			if (cmp->b_wptr < cmp->b_rptr)
				goto drop;
			mlen = MBLKL(cmp);
			if (coff > mlen)
				goto drop;
			if (coff != mlen)
				break;
			cmp = cmp->b_cont;
			coff = 0;
		}
		if (cmp == NULL)
			goto drop;

		fraglen = MIN(remaining, mlen - coff);
		tcb = ice_tx_bind_lso_fragment(itr,
		    (caddr_t)(cmp->b_rptr + coff), fraglen, &ncookies);
		if (tcb == NULL) {
			if (allow_pullup)
				goto pullup;
			goto force_copy;
		}

		if (ndesc + ncookies > ICE_TX_MAX_LSO_DESC) {
			ice_tcb_free(itr, tcb);
			if (allow_pullup)
				goto pullup;
			goto force_copy;
		}

		tsegbytes = segbytes;
		tsegdescs = segdescs;
		for (c = 0; c < ncookies; c++) {
			const ddi_dma_cookie_t *ck;
			boolean_t more;

			ck = ddi_dma_cookie_get(tcb->itcb_lso_dmah, c);
			if (ck->dmac_size == 0 ||
			    ck->dmac_size > ICE_TX_MAX_BUFSZ ||
			    !ice_tx_lso_desc_fits(ck->dmac_size, ctx->itc_mss,
			    &tsegbytes, &tsegdescs)) {
				fits = B_FALSE;
				break;
			}

			more = c + 1 < ncookies || remaining > fraglen;
			if (more && tsegbytes != 0 &&
			    tsegdescs == ICE_TX_LSO_SEG_DESCS) {
				fits = B_FALSE;
				break;
			}
		}

		if (!fits) {
			ice_tcb_free(itr, tcb);
			goto force_copy;
		}

		if (!ice_tx_mblk_advance(&cmp, &coff, fraglen)) {
			ice_tcb_free(itr, tcb);
			goto drop;
		}
		ASSERT3U(ntcb, <, ICE_TX_MAX_LSO_DESC + 1);
		tcbs[ntcb++] = tcb;
		ndesc += ncookies;
		remaining -= fraglen;
		segbytes = tsegbytes;
		segdescs = tsegdescs;
		continue;

force_copy:
		/*
		 * One frame-sized descriptor can cross every supported MSS, so
		 * it reduces total descriptors and closes a crowded segment.
		 */
		if (ndesc == ICE_TX_MAX_LSO_DESC) {
			if (allow_pullup)
				goto pullup;
			goto drop;
		}
		fraglen = MIN(remaining, (size_t)ICE_TX_LSO_BUFSZ);
		tcb = ice_tx_lso_copy(itr, &cmp, &coff, fraglen, &res);
		if (tcb == NULL)
			goto fail;

		tsegbytes = segbytes;
		tsegdescs = segdescs;
		if (!ice_tx_lso_desc_fits(fraglen, ctx->itc_mss,
		    &tsegbytes, &tsegdescs) ||
		    (remaining > fraglen && tsegbytes != 0 &&
		    tsegdescs == ICE_TX_LSO_SEG_DESCS)) {
			ice_tcb_free(itr, tcb);
			goto drop;
		}

		ASSERT3U(ntcb, <, ICE_TX_MAX_LSO_DESC + 1);
		tcbs[ntcb++] = tcb;
		ndesc++;
		remaining -= fraglen;
		segbytes = tsegbytes;
		segdescs = tsegdescs;
	}

	ASSERT3U(ndesc, <=, ICE_TX_MAX_LSO_DESC);
	*ntcbp = ntcb;
	*ndescp = ndesc;
	return (ICE_TX_BUILD_OK);

pullup:
	res = ICE_TX_BUILD_PULLUP;
	goto fail;
drop:
	res = ICE_TX_BUILD_DROP;
fail:
	ice_tx_free_tcbs(itr, tcbs, ntcb);
	return (res);
}

/*
 * Fragmentation can make a valid LSO packet impossible to describe safely.
 * Pulling it up once gives the bind path one terminal retry while preserving
 * the original message for MAC back-pressure if allocation fails.
 */
static ice_tx_build_t
ice_tx_lso_chain(ice_tx_ring_t *itr, mblk_t *mp, const ice_tx_ctx_t *ctx,
    ice_tx_ctrl_block_t **tcbs, uint_t *ntcbp, uint_t *ndescp,
    mblk_t **txmpp)
{
	ice_tx_build_t res;
	mblk_t *pullup;

	*txmpp = mp;
	res = ice_tx_lso_build(itr, mp, ctx, tcbs, ntcbp, ndescp, B_TRUE);
	if (res != ICE_TX_BUILD_PULLUP)
		return (res);

	pullup = msgpullup(mp, -1);
	if (pullup == NULL)
		return (ICE_TX_BUILD_NORES);
	itr->itxr_stats.ictxs_lso_pullups.value.ui64++;

	res = ice_tx_lso_build(itr, pullup, ctx, tcbs, ntcbp, ndescp,
	    B_FALSE);
	if (res == ICE_TX_BUILD_OK) {
		*txmpp = pullup;
		return (res);
	}

	freemsg(pullup);
	if (res == ICE_TX_BUILD_PULLUP)
		res = ICE_TX_BUILD_NORES;
	return (res);
}

/*
 * Sync a TCB's data buffer toward the device.  Copy buffers sync the pool
 * buffer; bound fragments sync the bind handle.
 */
static boolean_t
ice_tx_sync_tcb(ice_t *ice, ice_tx_ctrl_block_t *tcb)
{
	ddi_dma_handle_t h;

	switch (tcb->itcb_type) {
	case ITCB_SMALL_COPY:
	case ITCB_COPY:
	case ITCB_LSO_COPY:
		h = tcb->itcb_buf->idb_dma_handle;
		break;
	case ITCB_BIND:
		h = tcb->itcb_dmah;
		break;
	case ITCB_LSO_BIND:
		h = tcb->itcb_lso_dmah;
		break;
	default:
		return (B_TRUE);
	}

	(void) ddi_dma_sync(h, 0, 0, DDI_DMA_SYNC_FORDEV);
	if (ice_check_dma_handle(h) != DDI_FM_OK) {
		ddi_fm_service_impact(ice->ice_dip, DDI_SERVICE_DEGRADED);
		atomic_or_32(&ice->ice_state, ICE_STATE_ERROR);
		return (B_FALSE);
	}
	return (B_TRUE);
}

/*
 * Lay a fully-built TCB chain onto the ring and ring the doorbell.  The caller
 * holds itxr_lock and has confirmed itxr_avail >= ndesc.  EOP|RS is set only on
 * the final descriptor so hardware reports the whole packet's completion once.
 * Returns B_FALSE on a fatal DMA error (packet dropped, ring left consistent).
 */
static boolean_t
ice_tx_emit(ice_tx_ring_t *itr, ice_tx_ctrl_block_t **tcbs, uint_t ntcb,
    uint_t ndesc, mblk_t *mp, const ice_tx_ctx_t *ctx)
{
	ice_t *ice = itr->itxr_ice;
	struct ice_hw *hw = &ice->ice_hw;
	uint16_t tail = itr->itxr_tail;
	uint16_t last = tail;
	uint_t written = 0;
	uint_t i;

	ASSERT(MUTEX_HELD(&itr->itxr_lock));
	ASSERT3U(itr->itxr_avail, >=, ndesc);

	for (i = 0; i < ntcb; i++) {
		ice_tx_ctrl_block_t *tcb = tcbs[i];

		if (!ice_tx_sync_tcb(ice, tcb))
			return (B_FALSE);
	}

	if (ctx->itc_use_ctx) {
		uint16_t ctxslot = tail;

		ice_tx_write_ctx_desc(itr, ctxslot, ctx->itc_mss,
		    ctx->itc_tsolen);
		itr->itxr_tcbs[ctxslot] = NULL;
		tail = ice_tx_ring_next(itr, tail);
		written++;
	}

	for (i = 0; i < ntcb; i++) {
		ice_tx_ctrl_block_t *tcb = tcbs[i];
		uint16_t first = tail;

		if (tcb->itcb_type == ITCB_BIND) {
			uint_t nc = ddi_dma_ncookies(tcb->itcb_dmah);
			uint_t c;

			for (c = 0; c < nc; c++) {
				const ddi_dma_cookie_t *ck =
				    ddi_dma_cookie_get(tcb->itcb_dmah, c);

				ice_tx_write_desc(itr, tail,
				    ck->dmac_laddress, ck->dmac_size,
				    ctx->itc_data_cmd, ctx->itc_data_off);
				last = tail;
				tail = ice_tx_ring_next(itr, tail);
				written++;
			}
		} else if (tcb->itcb_type == ITCB_LSO_BIND) {
			uint_t nc = ddi_dma_ncookies(tcb->itcb_lso_dmah);
			uint_t c;

			for (c = 0; c < nc; c++) {
				const ddi_dma_cookie_t *ck =
				    ddi_dma_cookie_get(tcb->itcb_lso_dmah, c);

				ice_tx_write_desc(itr, tail,
				    ck->dmac_laddress, ck->dmac_size,
				    ctx->itc_data_cmd, ctx->itc_data_off);
				last = tail;
				tail = ice_tx_ring_next(itr, tail);
				written++;
			}
		} else {
			ice_tx_write_desc(itr, tail,
			    ICE_DMA_PA(tcb->itcb_buf), tcb->itcb_len,
			    ctx->itc_data_cmd, ctx->itc_data_off);
			last = tail;
			tail = ice_tx_ring_next(itr, tail);
			written++;
		}

		/*
		 * Park the TCB at the slot of its first descriptor; the slots
		 * of a bound fragment's trailing cookies stay NULL.  Reclaim
		 * frees every non-NULL slot it walks, so each TCB frees once.
		 */
		itr->itxr_tcbs[first] = tcb;
	}

	ASSERT3U(written, ==, ndesc);

	/* The final descriptor reports completion for the whole packet. */
	itr->itxr_descs[last].cmd_type_offset_bsz |=
	    CPU_TO_LE64(((uint64_t)(ICE_TX_DESC_CMD_EOP | ICE_TX_DESC_CMD_RS) <<
	    ICE_TXD_QW1_CMD_S));

	ice_tx_sync_descs(itr, itr->itxr_tail, written);
	if (ice_check_dma_handle(itr->itxr_dma.idb_dma_handle) != DDI_FM_OK) {
		/*
		 * Fatal DMA error before the doorbell.  Roll the ring back to
		 * a pristine state and unpark the TCBs so the caller owns them;
		 * mp was never retained, so the caller's drop frees it once.
		 */
		uint16_t s = itr->itxr_tail;

		while (written-- > 0) {
			itr->itxr_descs[s].buf_addr = 0;
			itr->itxr_descs[s].cmd_type_offset_bsz = 0;
			itr->itxr_tcbs[s] = NULL;
			s = ice_tx_ring_next(itr, s);
		}

		ddi_fm_service_impact(ice->ice_dip, DDI_SERVICE_DEGRADED);
		atomic_or_32(&ice->ice_state, ICE_STATE_ERROR);
		return (B_FALSE);
	}

	/* The last TCB retains the mblk; freed when this packet recycles. */
	tcbs[ntcb - 1]->itcb_mp = mp;

	itr->itxr_tail = tail;
	itr->itxr_avail -= ndesc;

	wr32(hw, QTX_COMM_DBELL(itr->itxr_index), tail);

	/*
	 * The descriptors are already parked, so a faulted doorbell write only
	 * latches the error (stopping further tx until replumb); it must not
	 * unwind the TCBs the caller would otherwise free a second time.
	 */
	if (ice_check_acc_handle(ice->ice_osdep.ios_reg_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(ice->ice_dip, DDI_SERVICE_DEGRADED);
		atomic_or_32(&ice->ice_state, ICE_STATE_ERROR);
	}

	return (B_TRUE);
}

static boolean_t
ice_tx_desc_done(const ice_tx_ring_t *itr, uint16_t slot)
{
	uint64_t qw1 = LE64_TO_CPU(itr->itxr_descs[slot].cmd_type_offset_bsz);

	return ((qw1 & ICE_TX_QW1_DTYPE_DONE_M) ==
	    ((uint64_t)ICE_TX_DESC_DTYPE_DESC_DONE << ICE_TXD_QW1_DTYPE_S));
}

/*
 * Reclaim descriptors that hardware has completed.  With RS set on the last
 * descriptor of each packet, hardware rewrites that descriptor's DTYPE to
 * DESC_DONE; only that EOP descriptor is ever marked done.  Packets complete
 * in order, so the first done descriptor at or after itxr_head bounds the
 * oldest completed packet.  We free each packet's TCBs and slots, clear
 * back-pressure, and notify MAC when space frees up.  Returns descriptors
 * reclaimed.
 */
static uint_t
ice_tx_recycle(ice_tx_ring_t *itr)
{
	ice_t *ice = itr->itxr_ice;
	uint16_t head, inflight;
	uint_t nrecycled = 0;

	ASSERT(MUTEX_HELD(&itr->itxr_lock));

	if (itr->itxr_avail == itr->itxr_size) {
		/*
		 * Nothing in flight, but a blocked ring whose last completion
		 * drained here must still wake mac or it stays blocked.
		 */
		if (itr->itxr_blocked) {
			itr->itxr_blocked = B_FALSE;
			mac_tx_ring_update(ice->ice_mac_hdl,
			    itr->itxr_mactxring);
		}
		return (0);
	}

	(void) ddi_dma_sync(itr->itxr_dma.idb_dma_handle, 0, 0,
	    DDI_DMA_SYNC_FORKERNEL);
	if (ice_check_dma_handle(itr->itxr_dma.idb_dma_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(ice->ice_dip, DDI_SERVICE_DEGRADED);
		atomic_or_32(&ice->ice_state, ICE_STATE_ERROR);
		return (0);
	}

	head = itr->itxr_head;
	inflight = itr->itxr_size - itr->itxr_avail;

	/*
	 * Only the last (EOP|RS) descriptor of a packet is ever rewritten to
	 * DESC_DONE.  Packets complete in order, so the first DONE descriptor
	 * at or after head marks the tail of the oldest completed packet; every
	 * descriptor up to and including it is reclaimable.  Scan for that EOP,
	 * then free the span; repeat until no further EOP is done.
	 */
	while (nrecycled < inflight) {
		uint16_t span = 0;
		uint16_t s = head;
		boolean_t done = B_FALSE;

		/* Find the next completed EOP still in flight. */
		while (nrecycled + span < inflight) {
			span++;
			if (ice_tx_desc_done(itr, s)) {
				done = B_TRUE;
				break;
			}
			s = ice_tx_ring_next(itr, s);
		}

		if (!done)
			break;

		/* Reclaim head .. EOP inclusive (span descriptors). */
		while (span-- > 0) {
			ice_tx_ctrl_block_t *tcb = itr->itxr_tcbs[head];

			itr->itxr_tcbs[head] = NULL;
			if (tcb != NULL)
				ice_tcb_free(itr, tcb);

			itr->itxr_descs[head].buf_addr = 0;
			itr->itxr_descs[head].cmd_type_offset_bsz = 0;

			head = ice_tx_ring_next(itr, head);
			nrecycled++;
		}
	}

	if (nrecycled > 0) {
		itr->itxr_head = head;
		itr->itxr_avail += nrecycled;

		if (itr->itxr_blocked) {
			itr->itxr_blocked = B_FALSE;
			mac_tx_ring_update(ice->ice_mac_hdl,
			    itr->itxr_mactxring);
		}
	}

	return (nrecycled);
}

/*
 * Transmit a single packet.  Returns B_TRUE if the packet was placed on the
 * ring (mp consumed/retained), B_FALSE if the ring is full and the caller must
 * back off (mp left intact for the caller to return to MAC).
 */
static boolean_t
ice_tx_one(ice_tx_ring_t *itr, mblk_t *mp)
{
	ice_t *ice = itr->itxr_ice;
	ice_tx_ctrl_block_t *tcbs[ICE_TX_MAX_LSO_DESC + 1];
	ice_tx_ctx_t ctx;
	ice_tx_build_t res;
	mblk_t *txmp = mp;
	size_t msglen;
	uint_t ntcb = 0, ndesc = 0;

	msglen = msgdsize(mp);

	res = ice_tx_context(ice, mp, &ctx);
	if (res == ICE_TX_BUILD_OK && ctx.itc_use_ctx &&
	    !ice->ice_tx_lso_enable)
		res = ICE_TX_BUILD_DROP;
	if (res != ICE_TX_BUILD_OK) {
		freemsg(mp);
		itr->itxr_stats.ictxs_drops.value.ui64++;
		if (ctx.itc_use_ctx)
			itr->itxr_stats.ictxs_lso_drops.value.ui64++;
		return (B_TRUE);
	}

	if (ctx.itc_use_ctx) {
		res = ice_tx_lso_chain(itr, mp, &ctx, tcbs, &ntcb, &ndesc,
		    &txmp);
		if (res == ICE_TX_BUILD_OK) {
			ASSERT3U(ndesc, <=, ICE_TX_MAX_LSO_DESC);
			ndesc++;
		}
	} else {
		res = ice_tx_build_tcbs(itr, mp, msglen, tcbs, &ntcb,
		    &ndesc);
	}

	if (res == ICE_TX_BUILD_NORES) {
		/*
		 * No TCBs/buffers right now.  Arm back-pressure so this ring's
		 * next completion reclaim re-kicks MAC once resources return.
		 */
		mutex_enter(&itr->itxr_lock);
		itr->itxr_blocked = B_TRUE;
		itr->itxr_stats.ictxs_blocked.value.ui64++;
		if (ctx.itc_use_ctx)
			itr->itxr_stats.ictxs_lso_nores.value.ui64++;
		/*
		 * TCBs are guarded by itxr_tcb_lock, not this one, so a
		 * completion may have returned the resources we just failed to
		 * get before itxr_blocked was armed.  Re-run reclaim with the
		 * flag set: a fully drained ring gets no further completion
		 * interrupt and would otherwise stay blocked at MAC forever.
		 */
		(void) ice_tx_recycle(itr);
		mutex_exit(&itr->itxr_lock);
		return (B_FALSE);
	}
	if (res == ICE_TX_BUILD_DROP) {
		/* Undeliverable (too large to copy, unbindable); drop it. */
		freemsg(mp);
		itr->itxr_stats.ictxs_drops.value.ui64++;
		if (ctx.itc_use_ctx)
			itr->itxr_stats.ictxs_lso_drops.value.ui64++;
		return (B_TRUE);
	}
	ASSERT3U(res, ==, ICE_TX_BUILD_OK);

	mutex_enter(&itr->itxr_lock);

	if (itr->itxr_avail <= ndesc) {
		(void) ice_tx_recycle(itr);
		if (itr->itxr_avail <= ndesc) {
			itr->itxr_blocked = B_TRUE;
			itr->itxr_stats.ictxs_blocked.value.ui64++;
			if (ctx.itc_use_ctx)
				itr->itxr_stats.ictxs_lso_nores.value.ui64++;
			mutex_exit(&itr->itxr_lock);
			ice_tx_free_tcbs(itr, tcbs, ntcb);
			if (txmp != mp)
				freemsg(txmp);
			return (B_FALSE);
		}
	}

	if (!ice_tx_emit(itr, tcbs, ntcb, ndesc, txmp, &ctx)) {
		mutex_exit(&itr->itxr_lock);
		/*
		 * Fatal DMA error: the device is wedged.  Drop the frame; the
		 * emitted slots are torn back to a consistent state by emit.
		 */
		ice_tx_free_tcbs(itr, tcbs, ntcb);
		freemsg(txmp);
		if (txmp != mp)
			freemsg(mp);
		itr->itxr_stats.ictxs_drops.value.ui64++;
		if (ctx.itc_use_ctx)
			itr->itxr_stats.ictxs_lso_drops.value.ui64++;
		return (B_TRUE);
	}
	if (txmp != mp)
		freemsg(mp);

	itr->itxr_stats.ictxs_bytes.value.ui64 += msglen;
	itr->itxr_stats.ictxs_packets.value.ui64++;
	if (ctx.itc_use_ctx)
		itr->itxr_stats.ictxs_lso_packets.value.ui64++;

	mutex_exit(&itr->itxr_lock);

	return (B_TRUE);
}

/*
 * mac_ring_send entry point.  Sends as many packets from the chain as the ring
 * accepts; returns the unsent remainder for MAC to retry once the ring drains
 * (back-pressure is armed via itxr_blocked in ice_tx_one).
 */
mblk_t *
ice_ring_tx(void *arg, mblk_t *mp)
{
	ice_tx_ring_t *itr = arg;
	ice_t *ice = itr->itxr_ice;

	if ((ice->ice_state & ICE_STATE_ERROR) != 0) {
		freemsgchain(mp);
		return (NULL);
	}

	/*
	 * Check quiesce and mark this call in flight atomically so ice_tx_stop
	 * cannot start freeing parked control blocks while a transmit is mid
	 * way through ice_tx_one (which builds blocks outside the lock).
	 */
	mutex_enter(&itr->itxr_lock);
	if (itr->itxr_quiesce) {
		mutex_exit(&itr->itxr_lock);
		freemsgchain(mp);
		return (NULL);
	}
	itr->itxr_tx_active++;
	mutex_exit(&itr->itxr_lock);

	while (mp != NULL) {
		mblk_t *next = mp->b_next;

		mp->b_next = NULL;
		if (!ice_tx_one(itr, mp)) {
			/* Ring full: return this and the rest to MAC. */
			mp->b_next = next;
			break;
		}
		mp = next;
	}

	mutex_enter(&itr->itxr_lock);
	if (--itr->itxr_tx_active == 0)
		cv_signal(&itr->itxr_cv);
	mutex_exit(&itr->itxr_lock);

	return (mp);
}

/*
 * Reset the software ring state on mac_start.  The queue was (re)programmed by
 * ice_queues_program(), which reset the hardware head to zero, so the software
 * head/tail start there too and the two stay in lockstep across a plumb cycle.
 */
void
ice_tx_start(ice_t *ice)
{
	uint_t i;

	for (i = 0; i < ice->ice_num_txr; i++) {
		ice_tx_ring_t *itr = &ice->ice_txr[i];

		mutex_enter(&itr->itxr_lock);
		itr->itxr_head = 0;
		itr->itxr_tail = 0;
		itr->itxr_avail = itr->itxr_size;
		itr->itxr_quiesce = B_FALSE;
		itr->itxr_blocked = B_FALSE;
		mutex_exit(&itr->itxr_lock);
	}
}

/*
 * Close every ring to new transmits and wait out the calls already inside
 * ice_ring_tx().  Releases nothing: the reset path must be able to stop the
 * software from touching a ring without giving up DMA that hardware can still
 * reach, since the PFR is not issued until ice_rebuild().
 */
void
ice_tx_quiesce(ice_t *ice)
{
	uint_t i;

	for (i = 0; i < ice->ice_num_txr; i++) {
		ice_tx_ring_t *itr = &ice->ice_txr[i];

		mutex_enter(&itr->itxr_lock);
		itr->itxr_quiesce = B_TRUE;
		while (itr->itxr_tx_active > 0)
			cv_wait(&itr->itxr_cv, &itr->itxr_lock);
		mutex_exit(&itr->itxr_lock);
	}
}

/*
 * Release every control block the rings still hold and reset the software
 * ring state.  The caller must have quiesced the rings and must have put the
 * hardware queues beyond reach of the mappings released here, either by a
 * completed queue disable or by a completed reset; a parked control block
 * whose completion will never arrive is freed directly rather than leaked.
 * Idempotent: a second pass walks an all-NULL itxr_tcbs[].
 */
void
ice_tx_reclaim(ice_t *ice)
{
	uint_t i;
	uint16_t slot;

	for (i = 0; i < ice->ice_num_txr; i++) {
		ice_tx_ring_t *itr = &ice->ice_txr[i];

		mutex_enter(&itr->itxr_lock);
		for (slot = 0; slot < itr->itxr_size; slot++) {
			if (itr->itxr_tcbs[slot] == NULL)
				continue;
			ice_tcb_free(itr, itr->itxr_tcbs[slot]);
			itr->itxr_tcbs[slot] = NULL;
			itr->itxr_descs[slot].buf_addr = 0;
			itr->itxr_descs[slot].cmd_type_offset_bsz = 0;
		}

		itr->itxr_head = 0;
		itr->itxr_tail = 0;
		itr->itxr_avail = itr->itxr_size;
		itr->itxr_blocked = B_FALSE;
		mutex_exit(&itr->itxr_lock);
	}
}

/*
 * Quiesce the rings on mac_stop and release everything they hold.
 * ice_queues_disable() has already disabled the hardware queues, so the
 * reclaim is safe immediately.  The reset path drives the two halves
 * separately, around the reset barrier.
 */
void
ice_tx_stop(ice_t *ice)
{
	ice_tx_quiesce(ice);
	ice_tx_reclaim(ice);
}

/*
 * Tx completion service for the queue's MSI-X vector: reclaim the descriptors
 * hardware has marked done.  Called from the queue interrupt handler.
 */
void
ice_tx_ring_intr(ice_tx_ring_t *itr)
{
	mutex_enter(&itr->itxr_lock);
	(void) ice_tx_recycle(itr);
	mutex_exit(&itr->itxr_lock);
}

int
ice_ring_tx_stat(mac_ring_driver_t mrd, uint_t stat, uint64_t *val)
{
	ice_tx_ring_t *itr = (ice_tx_ring_t *)mrd;

	switch (stat) {
	case MAC_STAT_OBYTES:
		*val = itr->itxr_stats.ictxs_bytes.value.ui64;
		break;
	case MAC_STAT_OPACKETS:
		*val = itr->itxr_stats.ictxs_packets.value.ui64;
		break;
	default:
		*val = 0;
		return (ENOTSUP);
	}

	return (0);
}
