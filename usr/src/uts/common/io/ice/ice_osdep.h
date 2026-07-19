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
 * ice(4D) operating-system abstraction layer.
 *
 * The Intel "common code" under core/ is OS-independent source vendored
 * byte-for-byte from FreeBSD (see core/README.illumos).  It expects the host
 * OS to supply a small set of primitives: locks, memory and DMA allocation,
 * register access, byte-order helpers, debug logging, and an intrusive linked
 * list.  This header plus ice_osdep.c are that layer for illumos.  All of the
 * illumos adaptation lives here; core/ is never modified.
 */

#ifndef _ICE_OSDEP_H
#define	_ICE_OSDEP_H

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/pci_cap.h>
#include <sys/sysmacros.h>
#include <sys/byteorder.h>
#include <sys/stdbool.h>
#include <sys/queue.h>
#include <sys/note.h>

#include "ice_alloc.h"

#ifdef __cplusplus
extern "C" {
#endif

#define	ICE_INTEL_VENDOR_ID	0x8086

struct ice_hw;

/*
 * Scalar type aliases required by the common code.
 */
typedef uint8_t		u8;
typedef int8_t		s8;
typedef uint16_t	u16;
typedef int16_t		s16;
typedef uint32_t	u32;
typedef int32_t		s32;
typedef uint64_t	u64;
typedef int64_t		s64;

#define	__le16	u16
#define	__le32	u32
#define	__le64	u64
#define	__be16	u16
#define	__be32	u32
#define	__be64	u64

/*
 * The mdb dmod reuses this code but already defines TRUE/FALSE in the module
 * API, so skip them when building the dmod (mirrors i40e_osdep.h).
 */
#ifndef _ICE_MDB_DMOD
#define	FALSE	false
#define	TRUE	true
#endif

/* CSTYLED */
#define	STATIC	static

#define	UNREFERENCED_PARAMETER(x)		_NOTE(ARGUNUSED(x))
#define	UNREFERENCED_1PARAMETER(p)		_NOTE(ARGUNUSED(p))
#define	UNREFERENCED_2PARAMETER(p, q)		_NOTE(ARGUNUSED(p, q))
#define	UNREFERENCED_3PARAMETER(p, q, r)	_NOTE(ARGUNUSED(p, q, r))
#define	UNREFERENCED_4PARAMETER(p, q, r, s)	_NOTE(ARGUNUSED(p, q, r, s))
#define	UNREFERENCED_5PARAMETER(p, q, r, s, t)	_NOTE(ARGUNUSED(p, q, r, s, t))
#define	__ALWAYS_UNUSED				__attribute__((__unused__))

#define	FIELD_SIZEOF(t, f)	(sizeof (((t *)0)->f))
#ifndef	ARRAY_SIZE
#define	ARRAY_SIZE(a)		(sizeof (a) / sizeof ((a)[0]))
#endif
#define	MAKEMASK(m, s)		((m) << (s))
#define	DIVIDE_AND_ROUND_UP	howmany
#define	ROUND_UP		roundup
#define	SNPRINTF		snprintf

/*
 * Byte-order helpers.  The LE_ and BE_ macros from <sys/byteorder.h> convert
 * between the named order and host order, which is symmetric, so both
 * directions map to the same macro.
 */
#define	CPU_TO_LE16(o)	LE_16(o)
#define	CPU_TO_LE32(o)	LE_32(o)
#define	CPU_TO_LE64(o)	LE_64(o)
#define	LE16_TO_CPU(a)	LE_16(a)
#define	LE32_TO_CPU(a)	LE_32(a)
#define	LE64_TO_CPU(a)	LE_64(a)
#define	CPU_TO_BE16(o)	BE_16(o)
#define	CPU_TO_BE32(o)	BE_32(o)
#define	NTOHS(a)	ntohs(a)
#define	NTOHL(a)	ntohl(a)
#define	HTONS(a)	htons(a)
#define	HTONL(a)	htonl(a)

/*
 * The trailing direction/type argument is metadata for other operating
 * systems and is discarded here.  Note bcopy(9F) takes (src, dst, len).
 */
#define	ice_memset(addr, c, len, type)	((void) memset((addr), (c), (len)))
#define	ice_memcpy(dst, src, len, dir)	bcopy((src), (dst), (len))

extern void ice_usec_delay(u32, bool);
extern void ice_msec_delay(u32, bool);
extern void ice_msec_pause(u32);
extern void ice_msec_spin(u32);

/*
 * Bit helpers.  highbit()/highbit64() return the 1-based index of the most
 * significant set bit (0 when the input is 0), matching FreeBSD's flsl()/
 * flsll().
 */
#define	ice_fls(n)	highbit((ulong_t)(n))

static inline u8
ice_popcount64(u64 v)
{
	v -= (v >> 1) & 0x5555555555555555ULL;
	v = (v & 0x3333333333333333ULL) + ((v >> 2) & 0x3333333333333333ULL);
	v = (v + (v >> 4)) & 0x0f0f0f0f0f0f0f0fULL;
	return ((u8)((v * 0x0101010101010101ULL) >> 56));
}
#define	ice_hweight8(x)		ice_popcount64((u8)(x))
#define	ice_hweight16(x)	ice_popcount64((u16)(x))
#define	ice_hweight32(x)	ice_popcount64((u32)(x))
#define	ice_hweight64(x)	ice_popcount64((u64)(x))

static inline int
ice_ilog2(u64 n)
{
	if (n == 0)
		return (0);
	return (highbit64(n) - 1);
}

static inline bool
ice_is_pow2(u64 n)
{
	if (n == 0)
		return (false);
	return (ISP2(n));
}

/*
 * Locking.  illumos uses a single adaptive mutex; the common code only takes
 * these locks from non-interrupt context.
 */
struct ice_lock {
	kmutex_t	il_mutex;
};

extern void ice_init_lock(struct ice_lock *);
extern void ice_acquire_lock(struct ice_lock *);
extern void ice_release_lock(struct ice_lock *);
extern void ice_destroy_lock(struct ice_lock *);

/*
 * Allocation.  The common code frees a bare pointer with no length, so
 * ice_osdep.c stashes the size in a header preceding the returned payload.
 * All allocators return zeroed memory and may fail (callers handle NULL).
 */
extern void *ice_malloc(struct ice_hw *, size_t);
extern void *ice_calloc(struct ice_hw *, size_t, size_t);
extern void *ice_memdup(struct ice_hw *, const void *, size_t,
    enum ice_memcpy_type);
extern void ice_free(struct ice_hw *, void *);

/*
 * DMA memory.  The first three members are read directly by the common code
 * and therefore cannot be renamed; the rest are illumos-private.
 */
struct ice_dma_mem {
	void			*va;
	u64			pa;
	size_t			size;

	ddi_acc_handle_t	idm_acc_handle;
	ddi_dma_handle_t	idm_dma_handle;
	boolean_t		idm_bound;
};

extern void *ice_alloc_dma_mem(struct ice_hw *, struct ice_dma_mem *, u64);
extern void ice_free_dma_mem(struct ice_hw *, struct ice_dma_mem *);

/*
 * Per-instance osdep state, reached from the common code via hw->back.
 */
struct ice_osdep {
	off_t			ios_reg_size;
	ddi_acc_handle_t	ios_reg_handle;
	ddi_acc_handle_t	ios_cfg_handle;
	dev_info_t		*ios_dip;
	struct ice		*ios_ice;
};

#define	OS_DEP(hw)	((struct ice_osdep *)((hw)->back))

/*
 * Register access.  The target is amd64 only, so rd64/wr64 are single
 * operations.  Macros (rather than functions) match i40e and keep the
 * accessors inlined.
 */
#define	wr32(hw, reg, val)	\
	ddi_put32(OS_DEP(hw)->ios_reg_handle,	\
	    (uint32_t *)((uintptr_t)(hw)->hw_addr + (reg)), (val))
#define	rd32(hw, reg)	\
	ddi_get32(OS_DEP(hw)->ios_reg_handle,	\
	    (uint32_t *)((uintptr_t)(hw)->hw_addr + (reg)))
#define	wr64(hw, reg, val)	\
	ddi_put64(OS_DEP(hw)->ios_reg_handle,	\
	    (uint64_t *)((uintptr_t)(hw)->hw_addr + (reg)), (val))
#define	rd64(hw, reg)	\
	ddi_get64(OS_DEP(hw)->ios_reg_handle,	\
	    (uint64_t *)((uintptr_t)(hw)->hw_addr + (reg)))
#define	ICE_WRITE_REG	wr32
#define	ICE_READ_REG	rd32

/*
 * GLGEN_STAT is a read that has no side effects, used to flush posted writes.
 * Presumes a PF driver (see i40e_osdep.h).
 */
#define	ice_flush(hw)	((void) rd32((hw), GLGEN_STAT))

#define	ice_read_pci_cfg(hw, reg)	\
	pci_config_get16(OS_DEP(hw)->ios_cfg_handle, (reg))
#define	ice_write_pci_cfg(hw, reg, val)	\
	pci_config_put16(OS_DEP(hw)->ios_cfg_handle, (reg), (val))

extern dev_info_t *ice_hw_to_dev(struct ice_hw *);
extern void ice_debug(struct ice_hw *, u64, char *, ...);
extern void ice_debug_array(struct ice_hw *, u64, u32, u32, u8 *, size_t);
extern void ice_info_fwlog(struct ice_hw *, u32, u32, u8 *, size_t);
extern void ice_info(struct ice_hw *, char *, ...);
extern void ice_warn(struct ice_hw *, char *, ...);

/*
 * Intrusive linked list, layered on <sys/queue.h> exactly as the FreeBSD
 * osdep layers it, so the common-code call sites are unchanged.
 */
#ifndef __containerof
#define	__containerof(ptr, type, member)	\
	((type *)(void *)((char *)(ptr) - offsetof(type, member)))
#endif

#define	LIST_HEAD_TYPE	ice_list_head
#define	LIST_ENTRY_TYPE	ice_list_node

struct ice_list_node {
	LIST_ENTRY(ice_list_node) entries;
};

LIST_HEAD(ice_list_head, ice_list_node);

#define	INIT_LIST_HEAD		LIST_INIT
#define	LIST_ADD(entry, head)	LIST_INSERT_HEAD(head, entry, entries)
#define	LIST_ADD_AFTER(entry, elem)	LIST_INSERT_AFTER(elem, entry, entries)
#define	LIST_DEL(entry)		LIST_REMOVE(entry, entries)

#define	_osdep_LIST_ENTRY(ptr, type, member)	\
	__containerof(ptr, type, member)
#define	LIST_FIRST_ENTRY(head, type, member)	\
	_osdep_LIST_ENTRY(LIST_FIRST(head), type, member)
#define	LIST_NEXT_ENTRY(ptr, unused, member)	\
	_osdep_LIST_ENTRY(LIST_NEXT(&((ptr)->member), entries),	\
	    __typeof(*(ptr)), member)

#define	LIST_REPLACE_INIT(old_head, new_head)	do {		\
	__typeof(new_head) _new_head = (new_head);		\
	LIST_INIT(_new_head);					\
	LIST_SWAP(old_head, _new_head, ice_list_node, entries);	\
	_NOTE(CONSTCOND)					\
} while (0)

/* BEGIN CSTYLED */
#define	LIST_ENTRY_SAFE(_ptr, _type, _member)			\
	({ __typeof(_ptr) ____ptr = (_ptr);			\
	____ptr ? _osdep_LIST_ENTRY(____ptr, _type, _member) : NULL; })
/* END CSTYLED */

static inline struct ice_list_node *
ice_get_list_tail(struct ice_list_head *head)
{
	struct ice_list_node *node = LIST_FIRST(head);

	if (node == NULL)
		return (NULL);
	while (LIST_NEXT(node, entries) != NULL)
		node = LIST_NEXT(node, entries);

	return (node);
}

#define	LIST_ADD_TAIL(entry, head)	do {			\
	struct ice_list_node *_node = ice_get_list_tail(head);	\
	if (_node == NULL)					\
		LIST_ADD(entry, head);				\
	else							\
		LIST_INSERT_AFTER(_node, entry, entries);	\
	_NOTE(CONSTCOND)					\
} while (0)

#define	LIST_LAST_ENTRY(head, type, member)	\
	LIST_ENTRY_SAFE(ice_get_list_tail(head), type, member)
#define	LIST_FIRST_ENTRY_SAFE(head, type, member)	\
	LIST_ENTRY_SAFE(LIST_FIRST(head), type, member)
#define	LIST_NEXT_ENTRY_SAFE(ptr, member)	\
	LIST_ENTRY_SAFE(LIST_NEXT(&((ptr)->member), entries),	\
	    __typeof(*(ptr)), member)

#define	LIST_FOR_EACH_ENTRY(pos, head, unused, member)			\
	for ((pos) = LIST_FIRST_ENTRY_SAFE(head, __typeof(*(pos)), member); \
	    (pos) != NULL;						\
	    (pos) = LIST_NEXT_ENTRY_SAFE(pos, member))

#define	LIST_FOR_EACH_ENTRY_SAFE(pos, n, head, unused, member)		\
	for ((pos) = LIST_FIRST_ENTRY_SAFE(head, __typeof(*(pos)), member); \
	    (pos) != NULL &&						\
	    ((n) = LIST_NEXT_ENTRY_SAFE(pos, member), true);		\
	    (pos) = (n))

#ifdef __cplusplus
}
#endif

#endif /* _ICE_OSDEP_H */
