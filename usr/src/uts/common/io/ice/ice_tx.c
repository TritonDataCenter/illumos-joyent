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
 * Copyright 2026 RackTop Systems, Inc.
 */

#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/pattr.h>
#include <sys/containerof.h>
#include "ice.h"

/*
 * Transmitting packets works identical to the 700-series (i40e) NICs.
 * The 800-series (ice) does have some additional features (e.g. completion
 * queues) that aren't currently utilized.  Like any other nic, the mblk_t we're
 * transmitting consists of an arbitrary number of fragments of arbitrary size
 * (linked by the b_cont field). Transmitting the packet is a matter of
 * assembling a list of physical address and lengths for all of these fragments
 * and writing them out to the TX ring.
 *
 * The transmit control blocks (ice_tx_control_block_t aka tcb) are used to
 * track these (paddr, len) pairs. For each fragment, we either DMA bind the
 * fragment (if the fragment is sufficiently large), or we copy the contents
 * of the fragment into a pre-DMA mapped buffer. We will also attempt to copy
 * the contents of a larger fragment if the DMA mapping operation fails
 * as well as if the packet exceeds the DMA engine's per packet descriptor
 * limit (more on this below). To increase the utilization of the preallocated
 * DMA buffers, consecutive small mblk fragments will be concatenated into a
 * single pre-allocated DMA buffer. Each DMA bound mblk fragment as well as
 * each pre-allocated DMA buffer consume a tcb.
 *
 * Once we've processed every fragment, we write the physical addresses,
 * lengths, and other metadata (e.g. hw checksum offload information, etc)
 * onto the TX descriptor ring and tell the hardware to transmit the packet.
 * At the same time, the TCBs consumed by this packet are saved on another
 * ring starting at the same index as the TX descriptor ring. Since the number
 * of tcbs is always <= the number of TX descriptors used, if there is
 * enough free slots for the TX descriptors, we'll always have enough free
 * slots on the tcb ring to hold the corresponding tcbs.
 *
 * When the NIC has finished sending the NIC, it will generate a completion
 * interrupt, and we use ice_tx_recycle_ring() to go through the TX descriptor
 * and tcb descriptor rings and release the tcbs so they can be reused.
 *
 * Like the i40e NICs, the ice nics have a limit of 8 descriptors per packet.
 * For the non-LSO case, this is generally not an issue -- if the DMA binding
 * requires too many DMA cookies, we copy into one or more pre-mapped DMA
 * buffers. The DMA buffers are always sized so that an MTU sized packet
 * (even when jumbo frames are used) will always fit in 8 or fewer
 * pre-allocated packets (each pre-allocated DMA buffer is created such that
 * each one only requires a single DMA cookie).
 *
 * For the LSO case, things are unfortunately more complex. As noted in
 * Section 10.5.2, we are still limited to 8 (or fewer) DMA transactions for
 * every packet that is transmitted (i.e. every MSS sized chunk of a packet
 * the hardware is segmenting for us). What is less obvious is that it appears
 * that the packet header is not cached inside the hardware. Instead, it is
 * fetched for every segment that is transmitted and the appropriate fields
 * within the header are adjusted by the hardware as necessary. More
 * importantly, fetching the header counts against the 8 DMA
 * transaction/transmitted packet limit.
 *
 * The programming guide does not directly state this behavior, but it is
 * implied it with the examples in Section 10 of the programming guide. Comments
 * within __ice_chk_linearize() in the Linux ice driver also strongly imply
 * this behavior. This also matches the behavior seen with the i40e driver.
 * Finally, the I211 datasheet (section 7.2.4.2.1) explicitly states this is
 * the case when doing LSO with the I211 chipset. Which is to say, it strongly
 * suggests this has long been the way Intel has implemented LSO in hardware,
 * even while the documentation for the behavior has gotten poorer with
 * every new chipset.
 *
 * Based on the
 * examples in Section 10 of the programming guide as well as comments in
 * __ice_chk_linearize() in the Linux ice driver, when doing LSO there is
 * always a limit of 8 DMA transfers per packet written on the wire. That means
 * for LSO, each MSS sized portion of the original (big) packet being segmented
 * by the hardware must still be able to be fetched by the hardware using at
 * most 8 DMA transactions (i.e. 8 descriptors or less).
 *
 * Since we never segment the headers (or rather if they are segmented, we
 * copy them into a contiguous buffer so they are no longer segmented), the
 * net result is that every mss (mtu - header) chunk of packet
 * data (excluding the header bytes) must be described by 7 or fewer
 * descriptors. This unfortunately makes the process of DMA binding and/or
 * copying the mblk_t fragments more complicated compared to other hardware.
 *
 * To simplify things (a bit), when doing LSO we always copy the header
 * into its own 'small' sized premapped DMA buffer (smaller than an MTU) tracked
 * by its own tcb. As a small optimization (just because it's trivial to do),
 * we also short-circuit very small packets that can fit entirely into a
 * 'small' buffer.
 *
 * The bulk of the logic to handle the DMA descriptor limits is in
 * ice_tx_pkt_add_tcb(). The general idea is that as we handle each mblk
 * fragment, we keep track of the number of bytes and the number of
 * descriptors that will be used to write out a frame on the wire. If we
 * have handled at least mss bytes of data, we reset the count of segments
 * and data to start tracking a new frame. If we've reached the descriptor
 * limit without handling an mss amount of data and try to add a new tcb
 * (which means at least 1 more descriptor), this fails.
 *
 * ice_tx_pkt_add_tcb() fails, then we first attempt to undo/rollback the
 * work we've done for the current frame and switch to copying all of data
 * for this frame into pre-mapped buffers. If copying allows us to handle
 * all of the contents of the current frame without exceeding the descriptor
 * limit, when we cross the mss boundary, aside from resetting the segment
 * and size counters, we'll also revert back to the normal mode of attempting
 * to DMA bind larger mblk fragments. If copying fails, we undo everything
 * (except the header) and copy the entire packet.
 *
 * Since the size of the pre-mapped buffers are the smaller of the MTU or the
 * system's pagesize (e.g. 4k), copying the mblk contents requires at most 3
 * descriptors per frame with the largest possible MTU, so copying a LSO frame
 * should normally succeed. The only potential scenario where this could fail
 * is the spillover from the previous frame consumes more than 4 descriptors
 * (e.g. a bound mblk fragment of 6 cookies where the mss boundary is crossed
 * by the 2nd descriptor, and the remaining 4 cookies spill over into a new
 * partial frame). If this happens, we'll fail again and resort to copying
 * the entire packet (since that should always work).
 *
 * In reality, we should almost never need to resort to doing a full packet
 * copy when doing LSO. Since the NIC's DMA engine supports 64-bit
 * addressing and can transfer an entire MTU's worth of data in a single DMA
 * operation, when we bind an mblk fragment, the number of DMA cookies returned
 * is almost always going to be the number of pages the used by the mblk
 * fragment's data (i.e. mblk_t->b_datap->db_base) since it can just use the
 * the physical addresses used by each page of the data. This is of course
 * not strictly guaranteed, but should be extremely rare. As a result,
 * we have a kstat counter as well as a dtrace probe for this event to assist
 * with observability as it's so odd that anyone encountering it with a
 * workload might be interested in investigating why it's failing.
 *
 * To implement all of this unfortunate complexity, ice_tx_pkt_t is used
 * to track the state to build up an array of physical addresses and lengths
 * for a given mblk_t, allowing for the needed rollback and retry as needed
 * to make the packet fit. As MAC thread stacks can get quite deep, we've
 * avoided placing ice_tx_pkt_t() on the stack and opt for using a
 * kmem_cache_t instead (as it's also possible there could be multiple
 * threads trying to TX on the same ring at the same time).
 */

typedef enum ice_tx_pkt_method {
	ITPM_NORMAL,		/* Try binding and copying based on frag size */
	ITPM_COPY_MSS,		/* Try to copy the current mss segment */
	ITPM_COPY_ALL,		/* Copy the entire packet */
} ice_tx_pkt_method_t;

typedef struct ice_tx_pkt {
	ice_tx_ring_t		*itxp_ring;
	mblk_t			*itxp_mp;
	mac_ether_offload_info_t itxp_meo;
	size_t			itxp_hdrlen;	/* Size of L2+L3+L4 headers */
	size_t			itxp_msglen;	/* Total pkt length */

	/* descriptor data */
	ice_tx_ctrl_block_t	*itxp_tcbs[ICE_TX_MAX_LSO_DESC];
	uint64_t		itxp_addrs[ICE_TX_MAX_LSO_DESC];
	uint16_t		itxp_lens[ICE_TX_MAX_LSO_DESC];
	uint8_t			itxp_ntcb;
	uint8_t			itxp_desc_total;

	bool			itxp_lso;
	ice_tx_pkt_method_t	itxp_method;
	uint32_t		itxp_mss;
	uint8_t			itxp_segmax;

	/* mss frame tracking */
	uint8_t			itxp_segcnt;
	uint16_t		itxp_seglen;

	/* rollback state */
	mblk_t			*itxp_prev_mp_seg;
	size_t			itxp_prev_off;
	uint16_t		itxp_prev_seglen;
	uint8_t			itxp_prev_segcnt;
	uint8_t			itxp_prev_ntcb;
	uint8_t			itxp_prev_desc_total;

	/* initial state for rolling back to start of packet */
	mblk_t			*itxp_init_mp_seg;
	size_t			itxp_init_off;
} ice_tx_pkt_t;

static kmem_cache_t *ice_tx_pkt_cache;

static inline uintptr_t
ice_qint_tqctl(const ice_tx_ring_t *txr)
{
	uintptr_t base = ICE_REG_QINT_TQCTL_BASE;

	return (base + txr->itxr_index * 4);
}

static inline ice_tx_ring_t *
ice_ih_to_txr(const ice_intr_handler_t *h)
{
	return (__containerof(h, ice_tx_ring_t, itxr_intr));
}

static inline uint16_t
ice_tx_next(const ice_tx_ring_t *txr, uint16_t idx, uint16_t amt)
{
	/* Use a larger size to hold intermediate results to avoid overflow */
	uint32_t val;

	ASSERT3U(idx, <, txr->itxr_size);

	val = idx + amt;
	if (idx > txr->itxr_size)
		val -= txr->itxr_size;

	ASSERT3U(val, <, txr->itxr_size);
	return (val);
}

static ice_tx_ctrl_block_t *
ice_tcb_alloc(ice_tx_ring_t *txr)
{
	ice_tx_ctrl_block_t *tcb;

	mutex_enter(&txr->itxr_tcb_lock);

	if (txr->itxr_tcb_nfree == 0) {
		mutex_exit(&txr->itxr_tcb_lock);
		return (NULL);
	}

	--txr->itxr_tcb_nfree;
	tcb = txr->itxr_tcb_free_list[txr->itxr_tcb_nfree];
	txr->itxr_tcb_free_list[txr->itxr_tcb_nfree] = NULL;

	mutex_exit(&txr->itxr_tcb_lock);

	return (tcb);
}

static void
ice_tcb_free(ice_tx_ring_t *txr, ice_tx_ctrl_block_t *tcb)
{
	if (tcb == NULL)
		return;

	switch (tcb->itcb_type) {
	case ITCB_NOT_USED:
		break;
	case ITCB_SMALL_COPY:
		ice_small_buf_free(txr->itxr_ice, tcb->itcb_buf);
		tcb->itcb_buf = NULL;
		break;
	case ITCB_COPY:
		ice_buf_free(txr->itxr_ice, tcb->itcb_buf);
		tcb->itcb_buf = NULL;
		break;
	case ITCB_BIND:
		(void) ddi_dma_unbind_handle(tcb->itcb_dmah);
		break;
	case ITCB_LSO_BIND:
		(void) ddi_dma_unbind_handle(tcb->itcb_lso_dmah);
		break;
	}

	tcb->itcb_type = ITCB_NOT_USED;
	tcb->itcb_len = 0;
	if (tcb->itcb_mp != NULL) {
		freemsg(tcb->itcb_mp);
		tcb->itcb_mp = NULL;
	}

	tcb->itcb_tx_time = 0;

	mutex_enter(&txr->itxr_tcb_lock);

	ASSERT3U(txr->itxr_tcb_nfree, <, txr->itxr_size);
	txr->itxr_tcb_nfree++;
	txr->itxr_tcb_free_list[txr->itxr_tcb_nfree] = tcb;

	mutex_exit(&txr->itxr_tcb_lock);
}

static inline bool
ice_tcb_is_copy(const ice_tx_ctrl_block_t *tcb)
{
	switch (tcb->itcb_type) {
	case ITCB_SMALL_COPY:
	case ITCB_COPY:
		return (true);
	default:
		return (false);
	}
}

/* How many bytes remain for copying in the given tcb */
static inline uint32_t
ice_tcb_remaining(const ice_tx_ctrl_block_t *tcb)
{
	if (tcb == NULL)
		return (0);

	switch (tcb->itcb_type) {
	case ITCB_SMALL_COPY:
	case ITCB_COPY:
		ASSERT3U(tcb->itcb_len, <=, tcb->itcb_buf->idb_len);
		return (tcb->itcb_buf->idb_len - tcb->itcb_len);
	default:
		/* All others can't be used for copying */
		return (0);
	}
}

static inline ddi_dma_handle_t
ice_tcb_dma_handle(const ice_tx_ctrl_block_t *tcb)
{
	switch (tcb->itcb_type) {
	case ITCB_SMALL_COPY:
	case ITCB_COPY:
		return (tcb->itcb_buf->idb_dma_handle);
	case ITCB_BIND:
		return (tcb->itcb_dmah);
	case ITCB_LSO_BIND:
		return (tcb->itcb_lso_dmah);
	default:
		return (NULL);
	}
}

static inline uint_t
ice_tcb_ncookies(const ice_tx_ctrl_block_t *tcb)
{
	ddi_dma_handle_t h = ice_tcb_dma_handle(tcb);
	return ((h != NULL) ? ddi_dma_ncookies(h) : 0);
}

static inline const ddi_dma_cookie_t *
ice_tcb_cookie_iter(const ice_tx_ctrl_block_t *tcb, const ddi_dma_cookie_t *c)
{
	ddi_dma_handle_t h = ice_tcb_dma_handle(tcb);
	return ((h != NULL) ? ddi_dma_cookie_iter(h, c) : NULL);
}

static bool
ice_tx_enter(ice_tx_ring_t *txr)
{
	bool allow;

	mutex_enter(&txr->itxr_lock);
	allow = !txr->itxr_quiesce;
	if (allow)
		txr->itxr_active++;
	mutex_exit(&txr->itxr_lock);

	return (allow);
}

static void
ice_tx_exit_nolock(ice_tx_ring_t *txr)
{
	ASSERT(MUTEX_HELD(&txr->itxr_lock));

	ASSERT3U(txr->itxr_active, >, 0);
	txr->itxr_active--;
	if (txr->itxr_quiesce)
		cv_signal(&txr->itxr_cv);
}

static void
ice_tx_exit(ice_tx_ring_t *txr)
{
	mutex_enter(&txr->itxr_lock);
	ice_tx_exit_nolock(txr);
	mutex_exit(&txr->itxr_lock);
}

/*
 * Wait for all TX activity to quiesce. Returns true if already quiesced,
 * false otherwise.
 */
bool
ice_tx_quiesce(ice_tx_ring_t *txr)
{
	mutex_enter(&txr->itxr_lock);
	if (txr->itxr_quiesce) {
		/* Ring is already shutdown */
		mutex_exit(&txr->itxr_lock);
		return (true);
	}

	/* Wait for any threads in the TX path to exit */
	txr->itxr_quiesce = true;
	while (txr->itxr_active > 0)
		cv_wait(&txr->itxr_cv, &txr->itxr_lock);

	mutex_exit(&txr->itxr_lock);

	return (false);
}

/*
 * Checkpoint the current relevant packet state needed to rollback to
 * the start of an mss segment.
 */
static inline void
ice_tx_pkt_checkpoint(ice_tx_pkt_t *pkt, mblk_t *mp, size_t off)
{
	pkt->itxp_prev_seglen = pkt->itxp_seglen;
	pkt->itxp_prev_segcnt = pkt->itxp_segcnt;

	pkt->itxp_prev_ntcb = pkt->itxp_ntcb;
	pkt->itxp_prev_desc_total = pkt->itxp_desc_total;
	pkt->itxp_prev_mp_seg = mp;
	pkt->itxp_prev_off = off;
}

/*
 * Add a tcb to the packet. If adding this tcb crosses the current mss segment
 * boundary, we cache the initial state (tcb, mp, off) at the start of the
 * new mss segment in case we need to rollback to it.
 *
 * Returns true if successfully added, false if adding this tcb would
 * exceed the per-mss descriptor limit.
 */
static bool
ice_tx_pkt_add_tcb(ice_tx_pkt_t *pkt, ice_tx_ctrl_block_t *tcb, mblk_t *mp,
    size_t off)
{
	const ddi_dma_cookie_t	*c;
	ddi_dma_handle_t	h;
	uint16_t		segcnt;
	uint16_t		init_seglen;
	uint8_t			init_segcnt;
	bool			need_checkpoint;

	if (tcb == NULL)
		return (true);

	h = ice_tcb_dma_handle(tcb);

	ASSERT3U(pkt->itxp_ntcb + 1, <, ARRAY_SIZE(pkt->itxp_tcbs));

	if (!pkt->itxp_lso &&
	    pkt->itxp_segcnt + ice_tcb_ncookies(tcb) > ICE_TX_MAX_DESC) {
		return (false);
	}

	pkt->itxp_tcbs[pkt->itxp_ntcb++] = tcb;

	init_seglen = pkt->itxp_seglen;
	init_segcnt = pkt->itxp_segcnt;
	segcnt = 0;
	need_checkpoint = false;
	/*
	 * Gather up all of the physical addresses and lengths for this
	 * tcb (for DMA mapped data, there may be more than one cookie)
	 */
	for (c = ddi_dma_cookie_iter(h, NULL); c != NULL;
	    c = ddi_dma_cookie_iter(h, c)) {
		uint16_t len;

		if (pkt->itxp_segcnt == pkt->itxp_segmax)
			goto fail;

		/*
		 * itcb_len is the total length of data managed by this tcb.
		 * If there are multiple cookies, then we need the length
		 * of the current 'chunk' from this cookie (i.e. dmac_size).
		 * If there is only a single cookie, the size of the DMA
		 * cookie may be larger than the amount of valid data (e.g.
		 * if we use a preallocated DMA buffer, we may not use all
		 * of the space in it), so in this instance the length of
		 * the chunk is the length of the data covered by this tcb.
		 */
		len = (segcnt > 0) ? c->dmac_size : tcb->itcb_len;

		pkt->itxp_addrs[pkt->itxp_desc_total] = c->dmac_laddress;
		pkt->itxp_lens[pkt->itxp_desc_total] = len;

		pkt->itxp_desc_total++;
		pkt->itxp_segcnt++;
		pkt->itxp_seglen += len;

		if (pkt->itxp_seglen >= pkt->itxp_mss) {
			/*
			 * We've cross an mss boundary. If we're not doing
			 * LSO, that means we've got a packet larger than
			 * our MTU. If we are doing LSO, we need to reset
			 * the counters for the current mss segment.
			 */
			if (!pkt->itxp_lso)
				goto fail;

			pkt->itxp_seglen %= pkt->itxp_mss;
			pkt->itxp_segcnt = (pkt->itxp_seglen == 0) ? 0 : 1;
			need_checkpoint = true;
		}
		segcnt++;
	}

	if (need_checkpoint) {
		ice_tx_pkt_checkpoint(pkt, mp, off);

		/*
		 * Since we've finished with this mss segment, we can
		 * revert to attempting to bind larger fragments as long
		 * as we haven't fallen back to copying the entire packet.
		 */
		if (pkt->itxp_method == ITPM_COPY_MSS)
			pkt->itxp_method = ITPM_NORMAL;
	}

	return (true);

fail:
	while (segcnt > 0) {
		--pkt->itxp_desc_total;
		pkt->itxp_addrs[pkt->itxp_desc_total] = 0;
		pkt->itxp_lens[pkt->itxp_desc_total] = 0;
		segcnt--;
	}
	pkt->itxp_tcbs[--pkt->itxp_ntcb] = NULL;

	pkt->itxp_segcnt = init_segcnt;
	pkt->itxp_seglen = init_seglen;
	return (false);
}

/*
 * Restore the packet state to the start of the current mss segment
 * and switch to force copy mode.
 */
static void
ice_tx_pkt_retry_mss_seg(ice_tx_pkt_t *pkt, mblk_t **mpp, size_t *offp)
{
	/* We should never retry once we're copying the whole packet */
	VERIFY3S(pkt->itxp_method, !=, ITPM_COPY_ALL);

	pkt->itxp_ring->itxr_stats.ictxs_mss_retries.value.ui64++;

	if (pkt->itxp_method == ITPM_COPY_MSS) {
		VERIFY(pkt->itxp_lso);
		/*
		 * We need to rollback to the initial packet state. This
		 * should only ever happen with LSO packets -- since a non
		 * LSO packet only ever results in a single frame on the
		 * wire, the initial rewind of the current mss segment IS
		 * the start of the packet and there is no possible
		 * spillover from a previous frame as there is with LSO, so
		 * we should only ever have to attempt this once.
		 */
		VERIFY(pkt->itxp_lso);

		pkt->itxp_prev_mp_seg = pkt->itxp_init_mp_seg;
		pkt->itxp_prev_off = pkt->itxp_init_off;
		pkt->itxp_prev_seglen = 0;
		pkt->itxp_prev_segcnt = 0;
		pkt->itxp_prev_ntcb = 1;
		pkt->itxp_prev_desc_total = 1;
		pkt->itxp_ring->itxr_stats.ictxs_full_copies.value.ui64++;
		// XXX dtrace probe?
	}

	/* First pop off and free any tcbs that were added */
	while (pkt->itxp_ntcb > pkt->itxp_prev_ntcb) {
		ice_tx_ctrl_block_t *tcb;

		--pkt->itxp_ntcb;
		tcb = pkt->itxp_tcbs[pkt->itxp_ntcb];
		pkt->itxp_tcbs[pkt->itxp_ntcb]  = NULL;

		ice_tcb_free(tcb->itcb_ring, tcb);
	}

	/* Clear out the (paddr, len) for the tcbs we freed */
	while (pkt->itxp_desc_total > pkt->itxp_prev_desc_total) {
		--pkt->itxp_desc_total;
		pkt->itxp_addrs[pkt->itxp_desc_total] = 0;
		pkt->itxp_lens[pkt->itxp_desc_total] = 0;
	}

	pkt->itxp_seglen = pkt->itxp_prev_seglen;
	pkt->itxp_segcnt = pkt->itxp_prev_segcnt;

	*mpp = pkt->itxp_prev_mp_seg;
	*offp = pkt->itxp_prev_off;

	pkt->itxp_method++;
}

static uint_t
ice_tx_copy_fragment(ice_tx_ctrl_block_t *tcb, const mblk_t *mp, size_t off,
    size_t len)
{
	const void	*src = mp->b_rptr + off;
	void		*dest = tcb->itcb_buf->idb_va + tcb->itcb_len;
	size_t		to_copy = MIN(ice_tcb_remaining(tcb), len);

	ASSERT3U(to_copy, >, 0);

	ASSERT3P(src, >=, mp->b_rptr);
	ASSERT3P(src, <, mp->b_wptr);
	ASSERT3U(len, <=, MBLKL(mp));
	ASSERT3U((uintptr_t)src + len, <=, (uintptr_t)mp->b_wptr);

	ASSERT3U(ice_tcb_remaining(tcb), >, 0);
	ASSERT3U(ice_tcb_remaining(tcb) + len, <=, tcb->itcb_buf->idb_len);

	bcopy(src, dest, to_copy);
	tcb->itcb_len += to_copy;

	tcb->itcb_ring->itxr_stats.ictxs_copy_bytes.value.ui64 += to_copy;
	tcb->itcb_ring->itxr_stats.ictxs_copy_frags.value.ui64++;
	return (to_copy);
}

static ice_tx_ctrl_block_t *
ice_tx_bind_fragment(ice_tx_ring_t *txr, ice_tx_pkt_t *pkt, const mblk_t *mp,
    size_t off, size_t len)
{
	ice_tx_ctrl_block_t	*tcb;
	ddi_dma_handle_t	h;
	int			ret;

	tcb = ice_tcb_alloc(txr);
	if (tcb == NULL)
		return (NULL);

	tcb->itcb_type = pkt->itxp_lso ? ITCB_LSO_BIND : ITCB_BIND;

	h = ice_tcb_dma_handle(tcb);
	ret = ddi_dma_addr_bind_handle(h, NULL, (caddr_t)(mp->b_rptr + off),
	    MBLKL(mp) - off, DDI_DMA_WRITE | DDI_DMA_STREAMING,
	    DDI_DMA_DONTWAIT, NULL, NULL, NULL);
	if (ret != DDI_DMA_MAPPED) {
		tcb->itcb_type = ITCB_NOT_USED;
		ice_tcb_free(txr, tcb);
		txr->itxr_stats.ictxs_bind_fails.value.ui64++;
		return (NULL);
	}

	tcb->itcb_len = len;
	txr->itxr_stats.ictxs_bind_bytes.value.ui64 += len;
	txr->itxr_stats.ictxs_bind_frags.value.ui64++;
	return (tcb);
}

/*
 * Initialize pkt to transmit mp. Sets initial values in preparation for
 * copying & mapping mblk segments. Returns true on success. Returns false
 * if mp is malformed (and should be dropped).
 */
static bool
ice_tx_pkt_init(ice_tx_ring_t *txr, ice_tx_pkt_t *pkt, mblk_t *mp)
{
	uint32_t	lsoflags;

	bzero(pkt, sizeof (*pkt));

	pkt->itxp_ring = txr;
	pkt->itxp_hdrlen = pkt->itxp_meo.meoi_l2hlen +
	    pkt->itxp_meo.meoi_l3hlen + pkt->itxp_meo.meoi_l4hlen;

	pkt->itxp_mp = mp;
	pkt->itxp_msglen = msgdsize(mp);
	pkt->itxp_segmax = ICE_TX_MAX_DESC;

	pkt->itxp_init_mp_seg = mp;
	pkt->itxp_init_off = 0;

	if (pkt->itxp_msglen < pkt->itxp_hdrlen)
		return (false);

	mac_lso_get(mp, &pkt->itxp_mss, &lsoflags);
	if ((lsoflags & HW_LSO) != 0) {
		if (pkt->itxp_mss < ICE_TX_LSO_MIN_MSS) {
			/*
			 * The MSS is too small. If we can send the packet
			 * as a normal packet, we'll attempt that, otherwise
			 * we drop it.
			 */
			txr->itxr_stats.ictxs_badmss.value.ui64++;
			
			pkt->itxp_mss = 0;
			if (pkt->itxp_msglen > txr->itxr_ice->ice_max_mtu) {
				return (false);
			}
			return (true);
		}

		if (pkt->itxp_msglen - pkt->itxp_hdrlen < pkt->itxp_mss)
			return (false);

		pkt->itxp_lso = true;

		/* Reserve 1 segment / descriptor for the header */
		pkt->itxp_segmax--;
	}

	return (true);
}

static void
ice_tx_pkt_fini(ice_tx_pkt_t *pkt)
{
	for (uint_t i = 0; i < pkt->itxp_ntcb; i++)
		ice_tcb_free(pkt->itxp_ring, pkt->itxp_tcbs[i]);

	bzero(pkt, sizeof (*pkt));
}

/*
 * Prepares the pkt for transmission. Copy and/or DMA map each mblk segment.
 * Returns true on success, false if insufficient resources are available
 * and the caller should retry/reschedule sending the packet.
 */
static bool
ice_tx_prepare_pkt(ice_tx_ring_t *txr, ice_tx_pkt_t *pkt)
{
	ice_t				*ice = txr->itxr_ice;
	mblk_t				*mp = pkt->itxp_mp;
	ice_tx_ctrl_block_t		*tcb = NULL;
	size_t				off = 0;
	size_t				to_copy;
	size_t				mlen;

	if (pkt->itxp_lso || pkt->itxp_msglen < ICE_TX_SMALL_PKT) {
		size_t remaining;

		remaining = pkt->itxp_lso ? pkt->itxp_hdrlen : pkt->itxp_msglen;

		tcb = ice_tcb_alloc(txr);
		if (tcb == NULL)
			return (false);

		/*
		 * Try to use a small buf, but fallback to a full sized one
		 * if none are available.
		 */
		tcb->itcb_buf = ice_small_buf_alloc(ice);
		tcb->itcb_type = ITCB_SMALL_COPY;
		if (tcb->itcb_buf == NULL) {
			tcb->itcb_buf = ice_buf_alloc(ice);
			tcb->itcb_type = ITCB_COPY;
		}

		/* If neither are availble, we fail */
		if (tcb->itcb_buf == NULL) {
			ice_tcb_free(txr, tcb);
			return (false);
		}

		ASSERT3U(ice_tcb_remaining(tcb), >=, remaining);
		while (remaining > 0) {
			uint_t n;

			/*
			 * remaining is initialized to either the size of the
			 * L2,L3,L4 headers (when using LSO) or the total size
			 * of the packet. Either way, we cannot get this
			 * far unless we can copy remaining bytes from
			 * the packet, so this should never fail.
			 */
			ASSERT3P(mp, !=, NULL);

			mlen = MBLKL(mp);
			to_copy = MIN(mlen, remaining);

			n = ice_tx_copy_fragment(tcb, mp, off, to_copy);
			ASSERT3U(n, ==, to_copy);

			remaining -= n;
			off += n;

			if (off == mlen) {
				mp = mp->b_cont;
				off = 0;
			} else {
				/*
				 * There is trailing bytes in the current
				 * mblk segment that is not being copied.
				 * The tcb we're copying into should be
				 * large enough to contain all of the header
				 * or the entire packet if it's a 'small'
				 * packet. Therefore, this should only
				 * happen when we're copying just the
				 * header and the trailing bytes are the
				 * packet data (and thus we should have
				 * completed copying the header).
				 */
				ASSERT(pkt->itxp_lso);
				ASSERT3U(remaining, ==, 0);
			}
		}

		if (pkt->itxp_lso) {
			/*
			 * As noted above, we want to keep the header separate
			 * from the data when doing TSO/LSO, so add it now.
			 * This is the first tcb and has just the packet
			 * headers -- it should never exceed the mss
			 * segment limits, so it should always succeed.
			 */
			VERIFY(ice_tx_pkt_add_tcb(pkt, tcb, mp, off));
			tcb = NULL;

			/*
			 * Reset the mss segment counters since the header
			 * doesn't count against the limits.
			 */
			pkt->itxp_seglen = 0;
			pkt->itxp_segcnt = 0;

			/*
			 * Also set the initial state (if we have to do
			 * a full copy) to start after the header.
			 */
			pkt->itxp_init_mp_seg = mp;
			pkt->itxp_init_off = off;

			/*
			 * We never want to rollback past the end of the
			 * header with LSO, so reset the rollback point to now.
			 */
			ice_tx_pkt_checkpoint(pkt, mp, off);
		}
	}

	while (mp != NULL) {
		mlen = MBLKL(mp) - off;

		if (mlen >= ice->ice_tx_dma_min &&
		    pkt->itxp_method == ITPM_NORMAL &&
		    (tcb = ice_tx_bind_fragment(txr, pkt, mp, off, mlen)) !=
		    NULL) {
			if (!ice_tx_pkt_add_tcb(pkt, tcb, mp, off)) {
				ice_tcb_free(txr, tcb);
				tcb = NULL;
				ice_tx_pkt_retry_mss_seg(pkt, &mp, &off);
				continue;
			}

			off = 0;
			mp = mp->b_cont;
			tcb = NULL;
			continue;
		}

		if (!ice_tcb_is_copy(tcb)) {
			tcb = ice_tcb_alloc(txr);
			if (tcb == NULL)
				return (false);

			tcb->itcb_type = ITCB_COPY;
			// TODO alloc regular DMA buffer
		}

		off += ice_tx_copy_fragment(tcb, mp, off, mlen);

		/*
		 * If the tcb is full or this is the last mblk_t fragment,
		 * then add it to pkt.
		 */
		if ((ice_tcb_remaining(tcb) == 0) ||
		    ((off == mlen) && mp->b_cont == NULL)) {
			if (!ice_tx_pkt_add_tcb(pkt, tcb, mp, off)) {
				ice_tcb_free(txr, tcb);
				tcb = NULL;
				ice_tx_pkt_retry_mss_seg(pkt, &mp, &off);
				continue;
			}
		}

		if (off == mlen) {
			off = 0;
			mp = mp->b_cont;
		}
	}

	return (true);
}

/*
 * Initialize the necessary descriptor values for HW checksum offload.
 * Returns true on success, false if the checksum data was malformed and
 * the packet should be dropped.
 *
 * On success, the TX context descriptor in tx_ctx is set with the necessary
 * values for LSO (if LSO is used, otherwise it's ignored) and the qword1
 * data descriptor hw checksum fields are set in *qw1p. This is bitwise-ORed
 * with the descriptor specific fields (e.g. data descriptor length) to
 * form the final qword1 value to write to the descriptor.
 *
 * NOTE all values of the TX context descriptor and *qw1p are all in
 * local byte order.
 */
static bool
ice_tx_hcksum_init(ice_tx_pkt_t *pkt, ice_tx_desc_t *tx_ctx, uint64_t *qw1p)
{
	const mac_ether_offload_info_t	*meo = &pkt->itxp_meo;
	ice_txq_stat_t			*stats = &pkt->itxp_ring->itxr_stats;
	uint32_t			start, chkflags;

	mac_hcksum_get(pkt->itxp_mp, &start, NULL, NULL, NULL, &chkflags);

	if (chkflags == 0 && !pkt->itxp_lso)
		return (true);

	if (chkflags & HCK_IPV4_HDRCKSUM) {
		if ((meo->meoi_flags & MEOI_L2INFO_SET) == 0) {
			stats->ictxs_hck_nol2info.value.ui64++;
			return (false);
		}
		if ((meo->meoi_flags & MEOI_L3INFO_SET) == 0) {
			stats->ictxs_hck_nol3info.value.ui64++;
			return (false);
		}
		if (meo->meoi_l3proto != ETHERTYPE_IP) {
			stats->ictxs_hck_badl3.value.ui64++;
			return (false);
		}

		*qw1p |= ICE_TX_DESC_CMD_IIPT_IPV4_CSUM;
		*qw1p |= (meo->meoi_l2hlen >> 1) <<
		    ICE_TX_DESC_LENGTH_MACLEN_SHIFT;
		*qw1p |= (meo->meoi_l3hlen >> 1) <<
		    ICE_TX_DESC_LENGTH_IPLEN_SHIFT;
	}

	if (chkflags & HCK_PARTIALCKSUM) {
		if ((meo->meoi_flags & MEOI_L4INFO_SET) == 0) {
			stats->ictxs_hck_nol4info.value.ui64++;
			return (false);
		}

		if ((chkflags & HCK_IPV4_HDRCKSUM) == 0) {
			if ((meo->meoi_flags & MEOI_L2INFO_SET) == 0) {
				stats->ictxs_hck_nol2info.value.ui64++;
				return (false);
			}
			if ((meo->meoi_flags & MEOI_L3INFO_SET) == 0) {
				stats->ictxs_hck_nol3info.value.ui64++;
				return (false);
			}

			switch (meo->meoi_l3proto) {
			case ETHERTYPE_IP:
				*qw1p |= ICE_TX_DESC_CMD_IIPT_IPV4;
				break;
			case ETHERTYPE_IPV6:
				*qw1p |= ICE_TX_DESC_CMD_IIPT_IPV6;
				break;
			default:
				stats->ictxs_hck_badl3.value.ui64++;
				return (false);
			}

			*qw1p |= (meo->meoi_l2hlen >> 1) <<
			    ICE_TX_DESC_LENGTH_MACLEN_SHIFT;
			*qw1p |= (meo->meoi_l3hlen >> 1) <<
			    ICE_TX_DESC_LENGTH_IPLEN_SHIFT;
		}

		switch (meo->meoi_l4proto) {
		case IPPROTO_TCP:
			*qw1p |= ICE_TX_DESC_CMD_L4T_EOFT_TCP;
			break;
		case IPPROTO_UDP:
			*qw1p |= ICE_TX_DESC_CMD_L4T_EOFT_UDP;
			break;
		case IPPROTO_SCTP:
			*qw1p |= ICE_TX_DESC_CMD_L4T_EOFT_SCTP;
			break;
		default:
			stats->ictxs_hck_badl4.value.ui64++;
			return (false);
		}

		*qw1p |= (meo->meoi_l4hlen >> 1) <<
		    ICE_TX_DESC_LENGTH_L4_FC_LE_SHIFT;
	}

	if (!pkt->itxp_lso)
		return (true);

	uint64_t tsolen = pkt->itxp_msglen - pkt->itxp_hdrlen;

	tx_ctx->itxd_qw0 = 0;
	tx_ctx->itxd_qw1 =
	    ICE_TX_DESC_DTYPE_CONTEXT |
	    ICE_TX_CTX_DESC_TSO |
	    (tsolen << ICE_TXD_QW1_TSO_LEN_SHIFT) |
	    ((uint64_t)pkt->itxp_mss << ICE_TXD_QW1_TSO_MSS_SHIFT);

	return (true);
}

/*
 * Attempt to write the descriptors out to the TX ring. Returns:
 *	>0	The number of descriptors consumed on the ring
 *	0	Insufficient space on the ring, reschedule.
 *	-1	Error with packet, caller should drop.
 */
static int
ice_tx_send_pkt(ice_tx_ring_t *txr, ice_tx_pkt_t *pkt)
{
	ice_t			*ice = txr->itxr_ice;
	ice_tx_desc_t		*desc = NULL;
	ice_tx_desc_t		tx_ctx_desc;
	uint64_t		init_qw1;
	uint16_t		tail;
	uint16_t		desc_needed;
	uint16_t		desc_used;

	ASSERT(MUTEX_HELD(&txr->itxr_lock));

	desc_needed = pkt->itxp_desc_total;

	/*
	 * If using LSO, we need an additional slot for the TX context
	 * descriptor.
	 */
	if (pkt->itxp_lso)
		desc_needed++;

	if (txr->itxr_avail < desc_needed)
		return (0);

	/* Sync all of the data buffers */
	for (uint_t i = 0; i < pkt->itxp_ntcb; i++) {
		ddi_dma_handle_t h;

		h = ice_tcb_dma_handle(pkt->itxp_tcbs[i]);

		/*
		 * We always sync the whole region, so this should
		 * always succeed.
		 */
		VERIFY0(ddi_dma_sync(h, 0, 0, DDI_DMA_SYNC_FORDEV));

		if (ice_check_dma_handle(h) != DDI_FM_OK) {
			ddi_fm_service_impact(ice->ice_dip,
			    DDI_SERVICE_DEGRADED);
			atomic_or_32(&ice->ice_state, ICE_ERROR);
			return (-1);
		}
	}

	tx_ctx_desc.itxd_qw0 = 0;
	tx_ctx_desc.itxd_qw1 = 0;

	/*
	 * On the 700-series chips, this was the ICRC flag, on the 800-series
	 * chips it's marked as 'Reserved, must be 1b' (Section 10.5.3.1.1)
	 */
	init_qw1 = (1ULL << 2);

	if (txr->itxr_ice->ice_tx_hcksum_enable &&
	    !ice_tx_hcksum_init(pkt, &tx_ctx_desc, &init_qw1)) {
		return (-1);
	}

	desc_used = 0;
	tail = txr->itxr_tail;
	desc = &txr->itxr_descs[tail];

	if (pkt->itxp_lso) {
		/* Write out the TX context descriptor to the ring */
		desc->itxd_qw0 = LE_64(tx_ctx_desc.itxd_qw0);
		desc->itxd_qw1 = LE_64(tx_ctx_desc.itxd_qw1);

		txr->itxr_tcbs[tail] = NULL;

		tail = ice_tx_next(txr, tail, 1);
		desc = &txr->itxr_descs[tail];
		desc_used++;
	}

	for (uint_t i = 0; i < pkt->itxp_desc_total; i++) {
		uint64_t qw1 = init_qw1;

		qw1 |=
		    ((uint64_t)pkt->itxp_lens[i] << ICE_TX_DESC_LENGTH_SHIFT);

		desc->itxd_qw0 = LE_64(pkt->itxp_addrs[i]);
		desc->itxd_qw1 = LE_64(qw1);

		tail = ice_tx_next(txr, tail, 1);
		desc = &txr->itxr_descs[tail];
		desc_used++;
	}

	/*
	 * desc is now the last descriptor, set the EOP and RS (report
	 * status) bits.
	 */
	desc->itxd_qw1 |= LE_64(ICE_TX_DESC_EOP|ICE_TX_DESC_RS);
	ASSERT3U(desc_used, ==, desc_needed);

	/* Done updating descriptors, so sync the ring to the device */
	if (!ice_dma_sync(txr->itxr_ice, &txr->itxr_dma, DDI_DMA_SYNC_FORDEV)) {
		uint64_t start = txr->itxr_tail;

		/*
		 * If we hit a fatal error, it likely stops the entire
		 * device, but to be nice, clear out everything we wrote.
		 */
		while (start != tail) {
			txr->itxr_descs[start].itxd_qw0 = 0;
			txr->itxr_descs[start].itxd_qw1 = 0;
			txr->itxr_tcbs[start] = NULL;
			start = ice_tx_next(txr, start, 1);
		}

		return (-1);
	}

	txr->itxr_tail = tail;
	txr->itxr_avail -= desc_used;

	ice_reg_write(ice, ICE_QTX_TAIL(txr->itxr_index), txr->itxr_tail);

	/*
	 * Save mp in the last tcb we used so we can free it when we
	 * recycle these tcbs after TX is complete. We choose the last
	 * tcb so as we recycle the tcbs, we don't free the mblk until
	 * all of the descriptors for the packet have been processed.
	 */
	ASSERT3U(pkt->itxp_ntcb, >, 0);
	pkt->itxp_tcbs[pkt->itxp_ntcb - 1]->itcb_mp = pkt->itxp_mp;

	pkt->itxp_mp = NULL;

	// TODO update tx stats

	return (desc_used);
}

mblk_t *
ice_ring_tx(void *arg, mblk_t *mp)
{
	ice_tx_ring_t	*txr = arg;
	ice_t		*ice = txr->itxr_ice;
	ice_tx_pkt_t	*pkt;

	if (!ice_is_running(txr->itxr_ice) || !ice_tx_enter(txr)) {
		freemsgchain(mp);
		return (NULL);
	}

	pkt = kmem_cache_alloc(ice_tx_pkt_cache, KM_NOSLEEP);
	if (pkt == NULL) {
		txr->itxr_stats.ictxs_no_pkt_cache.value.ui64++;
		return (mp);
	}

	while (mp != NULL) {
		mblk_t		*mp_next = mp->b_next;
		int		n;
		uint16_t	tail;

		mp->b_next = NULL;

		if (!ice_tx_pkt_init(txr, pkt, mp)) {
			/* mp was malformed in some way, drop and continue */
			txr->itxr_stats.ictxs_drops.value.ui64++;
			bzero(pkt, sizeof (*pkt));
			mp = mp_next;
			continue;
		}

		if (!ice_tx_prepare_pkt(txr, pkt)) {
			/* No resources right now, reschedule */
			ice_tx_pkt_fini(pkt);
			mp->b_next = mp_next;
			break;
		}

		/* If we're shutting down, just drop everything */
		if (!ice_tx_enter(txr)) {
			freemsgchain(mp);
			mp = NULL;
			break;
		}

		tail = txr->itxr_tail;

		n = ice_tx_send_pkt(txr, pkt);
		if (n < 0) {
			/* Asked to drop packet */
			ice_tx_exit(txr);

			ice_tx_pkt_fini(pkt);
			freemsg(mp);

			if ((ice->ice_state & ICE_ERROR) != 0) {
				freemsgchain(mp_next);
				mp = NULL;
				break;
			}

			/*
			 * If we failed for some reason other than the NIC
			 * being in an error state, we'll just move on to
			 * the next packet.
			 */
			mp = mp_next;
			continue;
		} else if (n == 0) {
			/*
			 * Not enough descriptors are available. Try to
			 * reap any used TX descriptors and try to send
			 * again.
			 */

			if (!ice_tx_recycle_ring(txr)) {
				txr->itxr_blocked = true;
				ice_tx_exit(txr);
				mp->b_next = mp_next;
				break;
			}

			n = ice_tx_send_pkt(txr, pkt);
			if (n < 0) {
				ice_tx_exit(txr);

				ice_tx_pkt_fini(pkt);
				freemsg(mp);

				if ((ice->ice_state & ICE_ERROR) != 0) {
					freemsgchain(mp_next);
					mp = NULL;
					break;
				}

				mp = mp_next;
				continue;
			} else if (n == 0) {
				/* Give up and reschedule */
				txr->itxr_stats.ictxs_blocked.value.ui64++;
				txr->itxr_blocked = true;
				ice_tx_exit(txr);
				mp->b_next = mp_next;
				break;
			}
		}

		ice_tx_exit(txr);

		ASSERT3U(n, >, 0);
		ASSERT3U(pkt->itxp_ntcb, <=, n);

		/*
		 * Move used tcbs in pkt onto the tcb ring. These will get
		 * freed when we recycle.
		 */
		hrtime_t now = gethrtime();
		for (uint_t i = 0; i < n; i++) {
			txr->itxr_tcbs[tail] =
			    (i < pkt->itxp_ntcb) ? pkt->itxp_tcbs[i] : NULL;
			pkt->itxp_tcbs[i] = NULL;

			txr->itxr_tcbs[tail]->itcb_tx_time = now;

			tail = ice_tx_next(txr, tail, 1);
		}
		pkt->itxp_ntcb = 0;
		pkt->itxp_mp = NULL;

		mp = mp_next;
	}

	ice_tx_pkt_fini(pkt);
	kmem_cache_free(ice_tx_pkt_cache, pkt);

	return (mp);
}

static inline bool
ice_tx_desc_done(const ice_tx_desc_t *desc)
{
	uint64_t dtype = desc->itxd_qw1 & ICE_TX_DESC_DTYPE_MASK;
	return (dtype == ICE_TX_DESC_DTYPE_DONE);
}

bool
ice_tx_recycle_ring(ice_tx_ring_t *txr)
{
	ice_t			*ice = txr->itxr_ice;
	ice_tx_ctrl_block_t	*tcbs[ICE_TX_MAX_LSO_DESC];
	uint32_t		n, head;

	ASSERT(MUTEX_HELD(&txr->itxr_lock));

	ASSERT3U(txr->itxr_avail, <=, txr->itxr_size);

	if (txr->itxr_avail == txr->itxr_size) {
		if (txr->itxr_blocked) {
			txr->itxr_blocked = false;
			mac_tx_ring_update(ice->ice_mac_hdl,
			    txr->itxr_mactxring);
		}
		return (true);
	}

	if (!ice_dma_sync(ice, &txr->itxr_dma, DDI_DMA_SYNC_FORKERNEL))
		return (false);

	n = 0;
	head = txr->itxr_head;

	for (;;) {
		if (!ice_tx_desc_done(&txr->itxr_descs[head]))
			break;

		/* Zero out used descriptors for sanity */
		txr->itxr_descs[head].itxd_qw0 = 0;
		txr->itxr_descs[head].itxd_qw1 = 0;

		tcbs[n] = txr->itxr_tcbs[head];
		txr->itxr_tcbs[head] = NULL;

		n++;
		head = ice_tx_next(txr, head, 1);
	}

	if (n > 0) {
		txr->itxr_head = head;
		txr->itxr_avail += n;

		// XXX add tx update threshold?

		if (txr->itxr_blocked) {
			txr->itxr_blocked = false;
			mac_tx_ring_update(ice->ice_mac_hdl,
			    txr->itxr_mactxring);
		}
	}

	mutex_exit(&txr->itxr_lock);

	for (uint_t i = 0; i < n; i++)
		ice_tcb_free(txr, tcbs[i]);

	return ((n > 0) ? true : false);
}

static bool
ice_tx_setup_bufs(ice_tx_ring_t *txr)
{
	ice_t			*ice = txr->itxr_ice;
	ddi_dma_attr_t		desc_attr;
	ddi_dma_attr_t		bind_attr;
	ddi_dma_attr_t		lso_bind_attr;
	ddi_device_acc_attr_t	dev_attr;
	size_t			len;
	int			ret;

	ice_dma_ring_attr(ice, &desc_attr);
	ice_pkt_txbind_attr(ice, &bind_attr);
	ice_pkt_txbind_lso_attr(ice, &lso_bind_attr);
	ice_dma_acc_attr(ice, &dev_attr);

	len = txr->itxr_size * sizeof (ice_tx_desc_t);
	if (!ice_dma_alloc(ice, &txr->itxr_dma, &desc_attr, &dev_attr,
	    true, len, true)) {
		ice_error(ice, "failed to alloc TX descriptor ring");
		return (false);
	}
	txr->itxr_descs = (ice_tx_desc_t *)txr->itxr_dma.idb_va;

	len = txr->itxr_size * sizeof (ice_tx_ctrl_block_t *);
	txr->itxr_tcbs = kmem_zalloc(len, KM_SLEEP);
	txr->itxr_tcb_free_list = kmem_zalloc(len, KM_SLEEP);

	for (uint_t i = 0; i < txr->itxr_size; i++) {
		ice_tx_ctrl_block_t *tcb;

		tcb = kmem_zalloc(sizeof (*tcb), KM_SLEEP);

		ret = ddi_dma_alloc_handle(ice->ice_dip, &bind_attr,
		    DDI_DMA_SLEEP, 0, &tcb->itcb_dmah);
		if (ret != DDI_SUCCESS) {
			ice_error(ice, "failed to alloc TX DMA handle");
			kmem_free(tcb, sizeof (*tcb));
			return (false);
		}

		ret = ddi_dma_alloc_handle(ice->ice_dip, &lso_bind_attr,
		    DDI_DMA_SLEEP, 0, &tcb->itcb_lso_dmah);
		if (ret != DDI_SUCCESS) {
			ice_error(ice, "failed to alloc TX LSO DMA handle");
			ddi_dma_free_handle(&tcb->itcb_dmah);
			kmem_free(tcb, sizeof (*tcb));
			return (false);
		}

		txr->itxr_tcb_free_list[txr->itxr_tcb_nfree++] = tcb;
	}

	return (true);
}

static void
ice_tx_teardown_bufs(ice_tx_ring_t *txr)
{
	size_t len;

	len = txr->itxr_size * sizeof (ice_tx_ctrl_block_t *);

	while (txr->itxr_tcb_nfree > 0) {
		ice_tx_ctrl_block_t *tcb;

		tcb = txr->itxr_tcb_free_list[txr->itxr_tcb_nfree];
		txr->itxr_tcb_free_list[--txr->itxr_tcb_nfree] = NULL;

		ddi_dma_free_handle(&tcb->itcb_dmah);
		ddi_dma_free_handle(&tcb->itcb_lso_dmah);
		kmem_free(tcb, sizeof (*tcb));
	}

	if (txr->itxr_tcb_free_list != NULL) {
		kmem_free(txr->itxr_tcb_free_list, len);
		txr->itxr_tcb_free_list = NULL;
	}

	if (txr->itxr_tcbs != NULL) {
#ifdef DEBUG
		for (uint_t i = 0; i < txr->itxr_size; i++)
			ASSERT3P(txr->itxr_tcbs[i], ==, NULL);
#endif
		kmem_free(txr->itxr_tcbs, len);
		txr->itxr_tcbs = NULL;
	}

	if (txr->itxr_descs != NULL) {
		ice_dma_free(&txr->itxr_dma);
		txr->itxr_descs = NULL;
	}
}

int
ice_ring_tx_start(mac_ring_driver_t mri, uint64_t gen)
{
	ice_tx_ring_t		*txr = (ice_tx_ring_t *)mri;
	ice_t			*ice = txr->itxr_ice;
	ice_vsi_t		*vsi = list_head(&ice->ice_vsi);
	ice_hw_txq_context_t	ctx = {
		.ihtc_vmvf_type = ICE_HW_TXQ_CTX_VMVF_TYPE_PF,
		.ihtc_vsi_id = vsi->ivsi_id,
		.ihtc_qlen = txr->itxr_size,
		.ihtc_tso = 1,
		// TODO -- other fields
	};

	ASSERT3P(vsi, !=, NULL);

	if (!ice_tx_setup_bufs(txr)) {
		ice_tx_teardown_bufs(txr);
		return (-1);
	}

	ctx.ihtc_base = txr->itxr_dma.idb_cookie.dmac_laddress;

	if (!ice_cmd_add_txq_grp(ice, vsi, &ctx)) {
		ice_tx_teardown_bufs(txr);
		return (-1);
	}

	// TODO anything else?

	txr->itxr_head = txr->itxr_tail = 0;
	return (0);
}

void
ice_ring_tx_stop(mac_ring_driver_t mri)
{
	ice_tx_ring_t		*txr = (ice_tx_ring_t *)mri;


	// TODO -- stop queue

	ice_tx_teardown_bufs(txr);
}

int
ice_ring_tx_intr_enable(mac_intr_handle_t intrh)
{
	ice_tx_ring_t	*txr = (ice_tx_ring_t *)intrh;
	ice_t		*ice = txr->itxr_ice;
	uint32_t	val = ice_reg_read(ice, ice_qint_tqctl(txr));

	val = ICE_REG_PFINT_CAUSE_ENA_SET(val, 1);
	ice_reg_write(ice, ice_qint_tqctl(txr), val);
	return (0);
}

int
ice_ring_tx_intr_disable(mac_intr_handle_t intrh)
{
	ice_tx_ring_t	*txr = (ice_tx_ring_t *)intrh;
	ice_t		*ice = txr->itxr_ice;
	uint32_t	val = ice_reg_read(ice, ice_qint_tqctl(txr));

	val = ICE_REG_PFINT_CAUSE_ENA_SET(val, 0);
	ice_reg_write(ice, ice_qint_tqctl(txr), val);
	return (0);
}

void
ice_tx_interrupt(ice_t *ice, ice_intr_handler_t *h)
{

	ice_tx_ring_t	*txr = ice_ih_to_txr(h);

	mutex_enter(&txr->itxr_lock);
	(void) ice_tx_recycle_ring(txr);
	mutex_exit(&txr->itxr_lock);
}

int
ice_ring_tx_stat(mac_ring_driver_t rh, uint_t stat, uint64_t *val)
{
	ice_tx_ring_t *txr = (ice_tx_ring_t *)rh;

	switch (stat) {
	case MAC_STAT_OBYTES:
		*val = txr->itxr_stats.ictxs_bytes.value.ui64;
		break;
	case MAC_STAT_OPACKETS:
		*val = txr->itxr_stats.ictxs_packets.value.ui64;
		break;
	default:
		*val = 0;
		return (ENOTSUP);
	}

	return (0);
}

void
ice_tx_start(ice_t *ice)
{
}

void
ice_tx_stop(ice_t *ice)
{
}

static int
ice_tx_pkt_ctor(void *buf, void *arg __unused, int kmflags __unused)
{
	bzero(buf, sizeof (ice_tx_pkt_t));
	return (0);
}

void
ice_tx_init(void)
{
	ice_tx_pkt_cache = kmem_cache_create("ice tx pkts",
	    sizeof (ice_tx_pkt_t), 8, ice_tx_pkt_ctor, NULL, NULL, NULL, NULL,
	    0);
}

void
ice_tx_fini(void)
{
	kmem_cache_destroy(ice_tx_pkt_cache);
	ice_tx_pkt_cache = NULL;
}
