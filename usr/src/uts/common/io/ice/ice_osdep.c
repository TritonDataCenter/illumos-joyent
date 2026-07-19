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
 * Out-of-line bodies for the ice(4D) OS abstraction layer.  See ice_osdep.h
 * for the contract the Intel common code (core/) depends on.
 */

#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sysmacros.h>
#include <sys/cmn_err.h>
#include <sys/pci.h>
#include <sys/pci_cap.h>
#include <sys/sdt.h>

#include "ice.h"
#include "ice_common.h"
#include "ice_osdep.h"

/*
 * Alignment used for all common-code DMA allocations.  The common code does
 * not request a specific alignment, so a page is used: it satisfies every
 * control-ring base-address constraint and is always safe.
 */
#define	ICE_DMA_ALIGN		0x1000

#define	ICE_LOG_BUFSZ		512

/*
 * The common code frees memory by bare pointer with no length, so each
 * allocation is prefixed with its total size for kmem_free().  The header is
 * u64-sized so the returned payload stays 8-byte aligned.
 */
typedef struct ice_alloc_hdr {
	uint64_t	iah_size;
} ice_alloc_hdr_t;

#define	ICE_ALLOC_HDR_SZ	(sizeof (ice_alloc_hdr_t))

/*
 * Attributes for common-code DMA memory.  Matches the i40e model: a single
 * cookie, no byte swapping (the common code converts byte order itself), and
 * streaming access (the target is amd64, which is DMA-coherent).
 */
static const ddi_dma_attr_t ice_dma_attr = {
	DMA_ATTR_V0,			/* dma_attr_version */
	0x0000000000000000ull,		/* dma_attr_addr_lo */
	0xffffffffffffffffull,		/* dma_attr_addr_hi */
	0x00000000ffffffffull,		/* dma_attr_count_max */
	ICE_DMA_ALIGN,			/* dma_attr_align */
	0x00000fff,			/* dma_attr_burstsizes */
	0x00000001,			/* dma_attr_minxfer */
	0xffffffffffffffffull,		/* dma_attr_maxxfer */
	0xffffffffffffffffull,		/* dma_attr_seg */
	1,				/* dma_attr_sgllen */
	0x00000001,			/* dma_attr_granular */
	0				/* dma_attr_flags */
};

static const ddi_device_acc_attr_t ice_acc_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STRICTORDER_ACC
};

dev_info_t *
ice_hw_to_dev(struct ice_hw *hw)
{
	return (OS_DEP(hw)->ios_dip);
}

void
ice_init_lock(struct ice_lock *lock)
{
	mutex_init(&lock->il_mutex, NULL, MUTEX_DRIVER, NULL);
}

void
ice_acquire_lock(struct ice_lock *lock)
{
	mutex_enter(&lock->il_mutex);
}

void
ice_release_lock(struct ice_lock *lock)
{
	mutex_exit(&lock->il_mutex);
}

void
ice_destroy_lock(struct ice_lock *lock)
{
	mutex_destroy(&lock->il_mutex);
}

void *
ice_malloc(struct ice_hw *hw, size_t size)
{
	ice_alloc_hdr_t *hdr;
	size_t total;

	_NOTE(ARGUNUSED(hw));

	if (size > SIZE_MAX - ICE_ALLOC_HDR_SZ)
		return (NULL);

	total = size + ICE_ALLOC_HDR_SZ;
	hdr = kmem_zalloc(total, KM_NOSLEEP);
	if (hdr == NULL)
		return (NULL);

	hdr->iah_size = total;
	return ((void *)(hdr + 1));
}

void *
ice_calloc(struct ice_hw *hw, size_t count, size_t size)
{
	if (count != 0 && size > SIZE_MAX / count)
		return (NULL);

	return (ice_malloc(hw, count * size));
}

void *
ice_memdup(struct ice_hw *hw, const void *src, size_t size,
    enum ice_memcpy_type dir)
{
	void *dst;

	_NOTE(ARGUNUSED(dir));

	dst = ice_malloc(hw, size);
	if (dst != NULL)
		bcopy(src, dst, size);

	return (dst);
}

void
ice_free(struct ice_hw *hw, void *mem)
{
	ice_alloc_hdr_t *hdr;

	_NOTE(ARGUNUSED(hw));

	if (mem == NULL)
		return;

	hdr = (ice_alloc_hdr_t *)mem - 1;
	kmem_free(hdr, hdr->iah_size);
}

void *
ice_alloc_dma_mem(struct ice_hw *hw, struct ice_dma_mem *mem, u64 size)
{
	struct ice_osdep *osdep = OS_DEP(hw);
	ddi_device_acc_attr_t acc_attr = ice_acc_attr;
	ddi_dma_attr_t dma_attr = ice_dma_attr;
	ddi_dma_cookie_t cookie;
	uint_t ncookie;
	size_t len;
	int rc;

	/*
	 * Attribute copies are per allocation because different device
	 * instances may negotiate different FMA capabilities.
	 */
	if (DDI_FM_DMA_ERR_CAP(osdep->ios_ice->ice_fm_caps)) {
		dma_attr.dma_attr_flags = DDI_DMA_FLAGERR;
		acc_attr.devacc_attr_access = DDI_FLAGERR_ACC;
	}

	rc = ddi_dma_alloc_handle(osdep->ios_dip, &dma_attr,
	    DDI_DMA_DONTWAIT, NULL, &mem->idm_dma_handle);
	if (rc != DDI_SUCCESS) {
		mem->idm_dma_handle = NULL;
		return (NULL);
	}

	rc = ddi_dma_mem_alloc(mem->idm_dma_handle, size, &acc_attr,
	    DDI_DMA_STREAMING, DDI_DMA_DONTWAIT, NULL, (caddr_t *)&mem->va,
	    &len, &mem->idm_acc_handle);
	if (rc != DDI_SUCCESS) {
		ddi_dma_free_handle(&mem->idm_dma_handle);
		mem->idm_dma_handle = NULL;
		mem->idm_acc_handle = NULL;
		mem->va = NULL;
		return (NULL);
	}

	bzero(mem->va, len);

	rc = ddi_dma_addr_bind_handle(mem->idm_dma_handle, NULL, mem->va, len,
	    DDI_DMA_RDWR | DDI_DMA_STREAMING, DDI_DMA_DONTWAIT, NULL, &cookie,
	    &ncookie);
	if (rc != DDI_DMA_MAPPED) {
		ddi_dma_mem_free(&mem->idm_acc_handle);
		ddi_dma_free_handle(&mem->idm_dma_handle);
		mem->idm_acc_handle = NULL;
		mem->idm_dma_handle = NULL;
		mem->va = NULL;
		return (NULL);
	}

	/*
	 * A single cookie is requested via dma_attr_sgllen; fail closed
	 * rather than use only the first segment if more are returned.
	 */
	if (ncookie != 1) {
		(void) ddi_dma_unbind_handle(mem->idm_dma_handle);
		ddi_dma_mem_free(&mem->idm_acc_handle);
		ddi_dma_free_handle(&mem->idm_dma_handle);
		mem->idm_acc_handle = NULL;
		mem->idm_dma_handle = NULL;
		mem->va = NULL;
		return (NULL);
	}

	mem->pa = cookie.dmac_laddress;
	mem->idm_bound = B_TRUE;
	mem->size = (size_t)size;

	return (mem->va);
}

void
ice_free_dma_mem(struct ice_hw *hw, struct ice_dma_mem *mem)
{
	_NOTE(ARGUNUSED(hw));

	if (mem->idm_bound) {
		VERIFY3P(mem->idm_dma_handle, !=, NULL);
		(void) ddi_dma_unbind_handle(mem->idm_dma_handle);
		mem->idm_bound = B_FALSE;
	}
	mem->pa = 0;

	if (mem->idm_acc_handle != NULL) {
		ddi_dma_mem_free(&mem->idm_acc_handle);
		mem->idm_acc_handle = NULL;
		mem->va = NULL;
	}

	if (mem->idm_dma_handle != NULL) {
		ddi_dma_free_handle(&mem->idm_dma_handle);
		mem->idm_dma_handle = NULL;
	}

	mem->size = 0;
	ASSERT(!mem->idm_bound);
}

void
ice_usec_delay(u32 time, bool sleep)
{
	if (sleep)
		delay(drv_usectohz(time));
	else
		drv_usecwait(time);
}

void
ice_msec_delay(u32 time, bool sleep)
{
	if (sleep)
		delay(drv_usectohz((clock_t)time * 1000));
	else
		drv_usecwait((clock_t)time * 1000);
}

void
ice_msec_pause(u32 time)
{
	ice_msec_delay(time, true);
}

void
ice_msec_spin(u32 time)
{
	ice_msec_delay(time, false);
}

/*PRINTFLIKE3*/
void
ice_debug(struct ice_hw *hw, u64 mask, char *fmt, ...)
{
	char buf[ICE_LOG_BUFSZ];
	va_list ap;

	_NOTE(ARGUNUSED(hw));

	va_start(ap, fmt);
	(void) vsnprintf(buf, sizeof (buf), fmt, ap);
	va_end(ap);

	DTRACE_PROBE2(ice__debug, uint64_t, mask, char *, buf);
}

void
ice_debug_array(struct ice_hw *hw, u64 mask, u32 rowsize, u32 groupsize,
    u8 *buf, size_t len)
{
	_NOTE(ARGUNUSED(hw, rowsize, groupsize));

	DTRACE_PROBE3(ice__debug__array, uint64_t, mask, u8 *, buf,
	    size_t, len);
}

void
ice_info_fwlog(struct ice_hw *hw, u32 rowsize, u32 groupsize, u8 *buf,
    size_t len)
{
	_NOTE(ARGUNUSED(hw, rowsize, groupsize));

	DTRACE_PROBE2(ice__fwlog, u8 *, buf, size_t, len);
}

/*PRINTFLIKE2*/
void
ice_info(struct ice_hw *hw, char *fmt, ...)
{
	dev_info_t *dip = ice_hw_to_dev(hw);
	char buf[ICE_LOG_BUFSZ];
	va_list ap;

	va_start(ap, fmt);
	(void) vsnprintf(buf, sizeof (buf), fmt, ap);
	va_end(ap);

	if (dip != NULL)
		dev_err(dip, CE_NOTE, "!%s", buf);
	else
		cmn_err(CE_NOTE, "!ice: %s", buf);
}

/*PRINTFLIKE2*/
void
ice_warn(struct ice_hw *hw, char *fmt, ...)
{
	dev_info_t *dip = ice_hw_to_dev(hw);
	char buf[ICE_LOG_BUFSZ];
	va_list ap;

	va_start(ap, fmt);
	(void) vsnprintf(buf, sizeof (buf), fmt, ap);
	va_end(ap);

	if (dip != NULL)
		dev_err(dip, CE_WARN, "%s", buf);
	else
		cmn_err(CE_WARN, "ice: %s", buf);
}
