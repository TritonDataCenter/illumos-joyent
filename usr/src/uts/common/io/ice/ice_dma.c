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
 * Copyright 2026 Edgecast Cloud LLC.
 */

/*
 * DMA support for the ice(4D) driver: descriptor-ring and packet-buffer DMA
 * attributes, the allocate/free primitives that wrap the DDI DMA bind dance,
 * and the shared TX/RX buffer pools that the data path draws from.
 */

#include "ice.h"

/*
 * Construct an appropriate DMA access attribute.  Access checking is enabled
 * only when the device's FM capabilities advertise DMA error handling.  We
 * never byte-swap: the hardware consumes little-endian structures and the
 * driver builds them in place.
 */
void
ice_dma_acc_attr(ice_t *ice, ddi_device_acc_attr_t *accp)
{
	accp->devacc_attr_version = DDI_DEVICE_ATTR_V0;
	accp->devacc_attr_endian_flags = DDI_NEVERSWAP_ACC;
	accp->devacc_attr_dataorder = DDI_STRICTORDER_ACC;

	if (DDI_FM_DMA_ERR_CAP(ice->ice_fm_caps)) {
		accp->devacc_attr_access = DDI_FLAGERR_ACC;
	} else {
		accp->devacc_attr_access = DDI_DEFAULT_ACC;
	}
}

/*
 * Construct DMA attributes for the TX and RX descriptor rings.
 */
void
ice_dma_ring_attr(ice_t *ice, ddi_dma_attr_t *attrp)
{
	attrp->dma_attr_version = DMA_ATTR_V0;

	/*
	 * Hardware supports receiving DMA in the full 64-bit range.
	 */
	attrp->dma_attr_addr_lo = 0x0;
	attrp->dma_attr_addr_hi = UINT64_MAX;

	/*
	 * The amount of data that can fit in one cookie.  Ring descriptor
	 * memory has to be physically contiguous, so we just pick a somewhat
	 * arbitrary max, but one that is suitably large that it can express
	 * the largest supported ring.  It needn't be precise, just large
	 * enough that the request won't be broken up into multiple cookies
	 * (or fail because the request size exceeds this value).
	 */
	attrp->dma_attr_count_max = UINT32_MAX;

	attrp->dma_attr_align = ICE_DESC_ALIGN;
	attrp->dma_attr_seg = UINT32_MAX;

	/*
	 * It's not obvious that PCIe devices really make use of the burst
	 * size, so we choose something based on the cache line sizes since
	 * that's the closest thing.
	 */
	attrp->dma_attr_burstsizes = 0x3c0;

	/*
	 * We just set some sensible defaults here.
	 */
	attrp->dma_attr_minxfer = 0x1;
	attrp->dma_attr_maxxfer = UINT32_MAX;
	attrp->dma_attr_granular = 0x01;

	/*
	 * As noted above, descriptor memory must be physically contiguous.
	 */
	attrp->dma_attr_sgllen = 1;

	if (DDI_FM_DMA_ERR_CAP(ice->ice_fm_caps)) {
		attrp->dma_attr_flags = DDI_DMA_FLAGERR;
	} else {
		attrp->dma_attr_flags = 0;
	}
}

void
ice_pkt_dma_attr(ice_t *ice, ddi_dma_attr_t *attrp)
{
	attrp->dma_attr_version = DMA_ATTR_V0;

	/*
	 * Hardware supports the full 64-bit address range for DMA.
	 */
	attrp->dma_attr_addr_lo = 0;
	attrp->dma_attr_addr_hi = UINT64_MAX;

	attrp->dma_attr_count_max = ICE_TX_MAX_BUFSZ - 1;

	attrp->dma_attr_align = ICE_DMA_ALIGNMENT;
	attrp->dma_attr_seg = UINT64_MAX;

	attrp->dma_attr_burstsizes = 0x00000fff;

	/* Similar to the other DMA attributes, some sensible defaults. */
	attrp->dma_attr_minxfer = 0x00000001;
	attrp->dma_attr_maxxfer = UINT32_MAX;
	attrp->dma_attr_granular = 1;

	/* We want a single DMA cookie for these buffers. */
	attrp->dma_attr_sgllen = 1;

	if (DDI_FM_DMA_ERR_CAP(ice->ice_fm_caps)) {
		attrp->dma_attr_flags = DDI_DMA_FLAGERR;
	} else {
		attrp->dma_attr_flags = 0;
	}
}

void
ice_pkt_txbind_attr(ice_t *ice, ddi_dma_attr_t *attrp)
{
	ice_pkt_dma_attr(ice, attrp);

	/*
	 * When doing non-LSO binding, we must limit the number of cookies to
	 * match the DMA capabilities of the NIC.  This is the only difference
	 * from a regular packet DMA buffer.
	 */
	attrp->dma_attr_sgllen = ICE_TX_MAX_COOKIE;
}

void
ice_pkt_txbind_lso_attr(ice_t *ice, ddi_dma_attr_t *attrp)
{
	ice_pkt_txbind_attr(ice, attrp);

	/*
	 * The only difference between the regular TX bind and the LSO bind DMA
	 * attributes is that LSO binding can support more segments.
	 */
	attrp->dma_attr_sgllen = ICE_TX_LSO_MAX_COOKIE;
}

void
ice_dma_free(ice_dma_buffer_t *idb)
{
	if (idb->idb_ncookies != 0) {
		VERIFY3P(idb->idb_dma_handle, !=, NULL);
		(void) ddi_dma_unbind_handle(idb->idb_dma_handle);
		idb->idb_ncookies = 0;
		idb->idb_len = 0;
	}

	if (idb->idb_acc_handle != NULL) {
		ddi_dma_mem_free(&idb->idb_acc_handle);
		idb->idb_acc_handle = NULL;
		idb->idb_va = NULL;
	}

	if (idb->idb_dma_handle != NULL) {
		ddi_dma_free_handle(&idb->idb_dma_handle);
		idb->idb_dma_handle = NULL;
	}

	ASSERT3P(idb->idb_va, ==, NULL);
	ASSERT0(idb->idb_ncookies);
	ASSERT0(idb->idb_len);
}

boolean_t
ice_dma_alloc(ice_t *ice, ice_dma_buffer_t *idb, ddi_dma_attr_t *attrp,
    ddi_device_acc_attr_t *accp, boolean_t zero, size_t size, boolean_t sleep)
{
	int ret;
	uint_t flags = DDI_DMA_CONSISTENT;
	size_t len;
	ddi_dma_cookie_t cookie;
	uint_t ncookies;
	int (*memcb)(caddr_t);

	if (sleep) {
		memcb = DDI_DMA_SLEEP;
	} else {
		memcb = DDI_DMA_DONTWAIT;
	}

	ret = ddi_dma_alloc_handle(ice->ice_dip, attrp, memcb, NULL,
	    &idb->idb_dma_handle);
	if (ret != DDI_SUCCESS) {
		ice_error(ice, "!failed to allocate DMA handle: %d", ret);
		idb->idb_dma_handle = NULL;
		return (B_FALSE);
	}

	ret = ddi_dma_mem_alloc(idb->idb_dma_handle, size, accp, flags, memcb,
	    NULL, &idb->idb_va, &len, &idb->idb_acc_handle);
	if (ret != DDI_SUCCESS) {
		ice_error(ice, "!failed to allocate %lu bytes of DMA "
		    "memory: %d", size, ret);
		idb->idb_va = NULL;
		idb->idb_acc_handle = NULL;
		ice_dma_free(idb);
		return (B_FALSE);
	}

	if (zero)
		bzero(idb->idb_va, len);

	ret = ddi_dma_addr_bind_handle(idb->idb_dma_handle, NULL, idb->idb_va,
	    len, DDI_DMA_RDWR | flags, memcb, NULL, &cookie, &ncookies);
	if (ret != DDI_DMA_MAPPED) {
		ice_error(ice, "!failed to bind %lu bytes of DMA "
		    "memory: %d", size, ret);
		ice_dma_free(idb);
		return (B_FALSE);
	}

	idb->idb_len = size;
	idb->idb_ncookies = ncookies;
	VERIFY3U(ncookies, ==, 1);
	idb->idb_cookie = cookie;

	return (B_TRUE);
}

int
ice_check_dma_handle(ddi_dma_handle_t handle)
{
	ddi_fm_error_t de;

	ddi_fm_dma_err_get(handle, &de, DDI_FME_VERSION);
	return (de.fme_status);
}

ice_dma_buffer_t *
ice_buf_alloc(ice_t *ice)
{
	ice_dma_buffer_t *buf;

	/* ice_buf_alloc is the count of free buffers left on the stack. */
	mutex_enter(&ice->ice_buf_lock);
	if (ice->ice_buf_alloc == 0) {
		mutex_exit(&ice->ice_buf_lock);
		return (NULL);
	}

	buf = ice->ice_dma_bufs[--ice->ice_buf_alloc];
	ice->ice_dma_bufs[ice->ice_buf_alloc] = NULL;
	mutex_exit(&ice->ice_buf_lock);

	return (buf);
}

void
ice_buf_free(ice_t *ice, ice_dma_buffer_t *buf)
{
	if (buf == NULL)
		return;

	/* Make sure we're not freeing to the wrong pool. */
	ASSERT3U(buf->idb_len, ==, ICE_TX_COPY_BUFSZ);

	mutex_enter(&ice->ice_buf_lock);
	ASSERT3U(ice->ice_buf_alloc, <, ice->ice_buf_sz);
	ice->ice_dma_bufs[ice->ice_buf_alloc++] = buf;
	mutex_exit(&ice->ice_buf_lock);
}

ice_dma_buffer_t *
ice_lso_buf_alloc(ice_t *ice)
{
	ice_dma_buffer_t *buf;

	mutex_enter(&ice->ice_buf_lock);
	if (ice->ice_lso_buf_alloc == 0) {
		mutex_exit(&ice->ice_buf_lock);
		return (NULL);
	}

	buf = ice->ice_dma_lso_bufs[--ice->ice_lso_buf_alloc];
	ice->ice_dma_lso_bufs[ice->ice_lso_buf_alloc] = NULL;
	mutex_exit(&ice->ice_buf_lock);

	return (buf);
}

void
ice_lso_buf_free(ice_t *ice, ice_dma_buffer_t *buf)
{
	if (buf == NULL)
		return;

	ASSERT3U(buf->idb_len, ==, ICE_TX_LSO_BUFSZ);

	mutex_enter(&ice->ice_buf_lock);
	ASSERT3U(ice->ice_lso_buf_alloc, <, ice->ice_lso_buf_sz);
	ice->ice_dma_lso_bufs[ice->ice_lso_buf_alloc++] = buf;
	mutex_exit(&ice->ice_buf_lock);
}

ice_dma_buffer_t *
ice_small_buf_alloc(ice_t *ice)
{
	ice_dma_buffer_t *buf;

	mutex_enter(&ice->ice_small_buf_lock);
	if (ice->ice_small_buf_alloc == 0) {
		mutex_exit(&ice->ice_small_buf_lock);
		return (NULL);
	}

	buf = ice->ice_dma_small_bufs[--ice->ice_small_buf_alloc];
	ice->ice_dma_small_bufs[ice->ice_small_buf_alloc] = NULL;
	mutex_exit(&ice->ice_small_buf_lock);

	return (buf);
}

void
ice_small_buf_free(ice_t *ice, ice_dma_buffer_t *buf)
{
	if (buf == NULL)
		return;

	mutex_enter(&ice->ice_small_buf_lock);
	ASSERT3U(ice->ice_small_buf_alloc, <, ice->ice_small_buf_sz);
	ice->ice_dma_small_bufs[ice->ice_small_buf_alloc++] = buf;
	mutex_exit(&ice->ice_small_buf_lock);
}

boolean_t
ice_buf_init(ice_t *ice)
{
	ddi_dma_attr_t attr;
	ddi_device_acc_attr_t acc;
	uint_t i, n;

	ice_pkt_dma_attr(ice, &attr);
	ice_dma_acc_attr(ice, &acc);

	/*
	 * These pools back only the tx copy path (rx has its own control-block
	 * buffers), so size them to one tx ring's worth: at most every
	 * descriptor in flight is a copied packet holding a single buffer.
	 * The allocations use DDI_DMA_DONTWAIT so a shortage fails the attach
	 * cleanly rather than blocking or panicking.
	 */
	n = 0;
	for (i = 0; i < ice->ice_num_txr; i++)
		n += ice->ice_txr[i].itxr_size;

	mutex_enter(&ice->ice_buf_lock);
	ice->ice_dma_bufs = kmem_zalloc(n * sizeof (ice_dma_buffer_t *),
	    KM_SLEEP);
	ice->ice_bufs = kmem_zalloc(n * sizeof (ice_dma_buffer_t), KM_SLEEP);
	ice->ice_buf_sz = n;
	for (i = 0; i < n; i++) {
		if (!ice_dma_alloc(ice, &ice->ice_bufs[i], &attr, &acc, B_TRUE,
		    ICE_TX_COPY_BUFSZ, B_FALSE)) {
			mutex_exit(&ice->ice_buf_lock);
			ice_error(ice, "failed to allocate tx copy buffers");
			ice_buf_fini(ice);
			return (B_FALSE);
		}
		ice->ice_dma_bufs[i] = &ice->ice_bufs[i];
	}
	ice->ice_buf_alloc = n;
	mutex_exit(&ice->ice_buf_lock);

	if (ice->ice_tx_lso_enable) {
		VERIFY3U(ICE_TX_LSO_BUFSZ, >=, ICE_MAX_FRAME_SIZE);
		VERIFY3U(ICE_TX_LSO_BUFSZ, <=, ICE_TX_MAX_BUFSZ);

		/*
		 * LSO fallback copies must close an arbitrary MSS window with
		 * one descriptor.  A page-rounded maximum frame covers every
		 * supported MSS while retaining a single DMA cookie.
		 */
		mutex_enter(&ice->ice_buf_lock);
		ice->ice_dma_lso_bufs = kmem_zalloc(n *
		    sizeof (ice_dma_buffer_t *), KM_SLEEP);
		ice->ice_lso_bufs = kmem_zalloc(n *
		    sizeof (ice_dma_buffer_t), KM_SLEEP);
		ice->ice_lso_buf_sz = n;
		for (i = 0; i < n; i++) {
			if (!ice_dma_alloc(ice, &ice->ice_lso_bufs[i], &attr,
			    &acc, B_TRUE, ICE_TX_LSO_BUFSZ, B_FALSE)) {
				mutex_exit(&ice->ice_buf_lock);
				ice_error(ice,
				    "failed to allocate tx LSO copy buffers");
				ice_buf_fini(ice);
				return (B_FALSE);
			}
			ice->ice_dma_lso_bufs[i] = &ice->ice_lso_bufs[i];
		}
		ice->ice_lso_buf_alloc = n;
		mutex_exit(&ice->ice_buf_lock);
	}

	mutex_enter(&ice->ice_small_buf_lock);
	ice->ice_dma_small_bufs = kmem_zalloc(n * sizeof (ice_dma_buffer_t *),
	    KM_SLEEP);
	ice->ice_small_bufs = kmem_zalloc(n * sizeof (ice_dma_buffer_t),
	    KM_SLEEP);
	ice->ice_small_buf_sz = n;
	for (i = 0; i < n; i++) {
		if (!ice_dma_alloc(ice, &ice->ice_small_bufs[i], &attr, &acc,
		    B_TRUE, ICE_TX_SMALL_PKT, B_FALSE)) {
			mutex_exit(&ice->ice_small_buf_lock);
			ice_error(ice, "failed to allocate tx small buffers");
			ice_buf_fini(ice);
			return (B_FALSE);
		}
		ice->ice_dma_small_bufs[i] = &ice->ice_small_bufs[i];
	}
	ice->ice_small_buf_alloc = n;
	mutex_exit(&ice->ice_small_buf_lock);

	return (B_TRUE);
}

void
ice_buf_fini(ice_t *ice)
{
	size_t i;

	/*
	 * Free the DMA backing every buffer, not just the free stack: the
	 * stack only holds the not-loaned ones.  The caller must have drained
	 * all loaned buffers before tearing the pool down.
	 */
	mutex_enter(&ice->ice_small_buf_lock);
	if (ice->ice_small_bufs != NULL) {
		for (i = 0; i < ice->ice_small_buf_sz; i++)
			ice_dma_free(&ice->ice_small_bufs[i]);
		kmem_free(ice->ice_dma_small_bufs,
		    ice->ice_small_buf_sz * sizeof (ice_dma_buffer_t *));
		kmem_free(ice->ice_small_bufs,
		    ice->ice_small_buf_sz * sizeof (ice_dma_buffer_t));
		ice->ice_dma_small_bufs = NULL;
		ice->ice_small_bufs = NULL;
	}
	ice->ice_small_buf_alloc = 0;
	ice->ice_small_buf_sz = 0;
	mutex_exit(&ice->ice_small_buf_lock);

	mutex_enter(&ice->ice_buf_lock);
	if (ice->ice_lso_bufs != NULL) {
		for (i = 0; i < ice->ice_lso_buf_sz; i++)
			ice_dma_free(&ice->ice_lso_bufs[i]);
		kmem_free(ice->ice_dma_lso_bufs,
		    ice->ice_lso_buf_sz * sizeof (ice_dma_buffer_t *));
		kmem_free(ice->ice_lso_bufs,
		    ice->ice_lso_buf_sz * sizeof (ice_dma_buffer_t));
		ice->ice_dma_lso_bufs = NULL;
		ice->ice_lso_bufs = NULL;
	}
	ice->ice_lso_buf_alloc = 0;
	ice->ice_lso_buf_sz = 0;

	if (ice->ice_bufs != NULL) {
		for (i = 0; i < ice->ice_buf_sz; i++)
			ice_dma_free(&ice->ice_bufs[i]);
		kmem_free(ice->ice_dma_bufs,
		    ice->ice_buf_sz * sizeof (ice_dma_buffer_t *));
		kmem_free(ice->ice_bufs,
		    ice->ice_buf_sz * sizeof (ice_dma_buffer_t));
		ice->ice_dma_bufs = NULL;
		ice->ice_bufs = NULL;
	}
	ice->ice_buf_alloc = 0;
	ice->ice_buf_sz = 0;
	mutex_exit(&ice->ice_buf_lock);
}
