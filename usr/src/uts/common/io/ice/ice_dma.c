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
 * Copyright 2024 RackTop Systems, Inc.
 */

/*
 * Describe the purpose of this file.
 */

#include "ice.h"

/*
 * Construct an appropriate DMA attribute. Conditionally enable access checking
 * and do not enable this as swapping.
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
 * Construct appropriate DMA attributes for the control queue.
 */
void
ice_dma_transfer_controlq_attr(ice_t *ice, ddi_dma_attr_t *attrp)
{
	attrp->dma_attr_version = DMA_ATTR_V0;

	/*
	 * Hardware supports receiving DMA in the full 64-bit range.
	 */
	attrp->dma_attr_addr_lo = 0x0;
	attrp->dma_attr_addr_hi = UINT64_MAX;

	/*
	 * This indicates the amount of data that can fit in one cookie. In this
	 * case, there's not really a lot of restrictions that hardware
	 * indicates here.
	 */
	attrp->dma_attr_count_max = UINT16_MAX;

	/*
	 * The alignment and segment are related issues. The alignment tells us
	 * the alignment of the starting address, while the segment tells us an
	 * address alignment that the allocated memory segment cannot cross. In
	 * the case of the controlq, there is no such definition made explicit,
	 * so we use a large boundary.
	 */
	attrp->dma_attr_align = ICE_DMA_CONTROLQ_ALIGN;
	attrp->dma_attr_seg = UINT32_MAX;

	/*
	 * The burst size member is supposed to be used to indicate different
	 * supported bits of the maximum amount of data that can be sent. It's
	 * not obvious that this value is usd by the PCIe engines for
	 * determining anything anymore; however, we try to honor the devices
	 * request that it breaks reads into cache lines and that the default
	 * max size is 512 bytes.
	 */
	attrp->dma_attr_burstsizes = 0x3c0;

	/*
	 * Minimum and maximum amount of data we can send. This isn't strictly
	 * limited by PCI in hardare, as it'll just make the appropriate number
	 * of requests. Simiarly, PCIe allows for an arbitrary granularity. We
	 * set this to one, as it's really a matter of what hardware is
	 * requesting from us.
	 */
	attrp->dma_attr_minxfer = 0x1;
	attrp->dma_attr_maxxfer = UINT32_MAX;
	attrp->dma_attr_granular = 0x1;

	/*
	 * The controlq only allows for a single cookie worth of data. This
	 * isn't said explicitly; however, there's only a single register to
	 * program the physical address in.
	 */
	attrp->dma_attr_sgllen = 1;

	if (DDI_FM_DMA_ERR_CAP(ice->ice_fm_caps)) {
		attrp->dma_attr_flags = DDI_DMA_FLAGERR;
	} else {
		attrp->dma_attr_flags = 0;
	}
}

/*
 * Construct appropriate DMA attributes for the TX and RX descriptor rings.
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
	 * The amount of data that can fit in one cookie. Ring descriptor
	 * memory has to be physically contiguous, so we just pick a somewhat
	 * arbitrary max, but one that is suitably large that can express
	 * the largest supported cookie size (4 64 bit words / descriptor *
	 * 8192 max descriptors for RX descriptors). It needn't be precise,
	 * just large enough the request won't be broken up into multiple
	 * cookies (or fail because the request size exceeds this value).
	 */
	attrp->dma_attr_count_max = UINT32_MAX;

	attrp->dma_attr_align = ICE_DESC_ALIGN;
	attrp->dma_attr_seg = UINT32_MAX;

	/*
	 * Like the controlq, it's not obvious that PCIe devices really
	 * make use of this, so we choose something based on the cache line
	 * sizes since that's the closest thing.
	 */
	attrp->dma_attr_burstsizes = 0x3c0;
	
	/*
	 * Also similar to controlq DMA memory, we just set some sensible
	 * defaults here.
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
}

void
ice_pkt_txbind_attr(ice_t *ice, ddi_dma_attr_t *attrp)
{
	attrp->dma_attr_version = DMA_ATTR_V0;

	/*
	 * Hardware support the full 64-bit address range for DMA
	 */
	attrp->dma_attr_addr_lo = 0;
	attrp->dma_attr_addr_hi = UINT64_MAX;

	attrp->dma_attr_count_max = ICE_TX_MAX_BUFSZ;

	attrp->dma_attr_align = ICE_DMA_ALIGNMENT;
	attrp->dma_attr_seg = UINT64_MAX;

	attrp->dma_attr_burstsizes = 0x00000FFF;

	/* Similar to the other DMA attributes, some sensible defaults */
	attrp->dma_attr_minxfer = 0x00000001;
	attrp->dma_attr_maxxfer = UINT32_MAX;
	attrp->dma_attr_granular = 1;

	/*
	 * When doing non-LSO binding, we must limit the number of
	 * cookies to 8 to make the DMA capabilities of the NIC.
	 */
	attrp->dma_attr_sgllen = ICE_TX_MAX_COOKIE;

	if (DDI_FM_DMA_ERR_CAP(ice->ice_fm_caps)) {
		attrp->dma_attr_flags =	DDI_DMA_FLAGERR;
	} else {
		attrp->dma_attr_flags = 0;
	}
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
	uint_t flags = DDI_DMA_CONSISTENT; /* XXX Streaming and relaxed ordering? */
	size_t len;
	ddi_dma_cookie_t cookie;
	uint_t ncookies;
	int (*memcb)(caddr_t);

	if (sleep == B_TRUE) {
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

	if (zero == B_TRUE)
		bzero(idb->idb_va, len);

	ret = ddi_dma_addr_bind_handle(idb->idb_dma_handle, NULL, idb->idb_va,
	    len, DDI_DMA_RDWR | flags, memcb, NULL, &cookie, &ncookies);
	if (ret != 0) {
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
