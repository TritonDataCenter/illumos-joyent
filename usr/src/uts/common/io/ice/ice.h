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

#ifndef _ICE_H
#define	_ICE_H

#include <sys/types.h>
#include <sys/inttypes.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/debug.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/pci.h>
#include <sys/list.h>
#include <sys/ethernet.h>
#include <sys/mac_provider.h>
#include <sys/mac_ether.h>
#include <sys/ddifm.h>
#include <sys/fm/protocol.h>
#include <sys/fm/util.h>
#include <sys/fm/io/ddi.h>

#include "ice_osdep.h"
#include "ice_type.h"

#ifdef __cplusplus
extern "C" {
#endif

#define	ICE_MODULE_NAME		"ice"

/*
 * reg property index 0 is PCI configuration space; the CSR window (BAR0) is
 * index 1.
 */
#define	ICE_REG_NUMBER		1

/*
 * MSI-X vector 0 is reserved for the "other interrupt cause" (admin queue,
 * link events, and errors); queue vectors begin at 1.
 */
#define	ICE_INTR_MSIX_MIN	2
#define	ICE_MAX_INTR_QUEUES	16

CTASSERT((ICE_MAX_INTR_QUEUES & (ICE_MAX_INTR_QUEUES - 1)) == 0);
CTASSERT(ICE_INTR_MSIX_MIN == 2);

/*
 * Generous hardware sanity ceilings.  Capability counts arrive from firmware
 * over the admin queue; a value beyond these bounds indicates a corrupt or
 * hostile device and is rejected outright (not clamped).  The driver's smaller
 * usable limits are applied where the counts are actually consumed.
 */
#define	ICE_HW_MAX_RXQ		2048
#define	ICE_HW_MAX_TXQ		2048
#define	ICE_HW_MAX_MSIX		2048
#define	ICE_MAX_VSI		768
#define	ICE_MIN_MTU		68		/* conventional minimum MTU */
#define	ICE_MAX_MTU	\
	(ICE_AQ_SET_MAC_FRAME_SIZE_MAX - sizeof (struct ether_vlan_header) - \
	ETHERFCSL)
#define	ICE_MAX_FRAME_SIZE	ICE_AQ_SET_MAC_FRAME_SIZE_MAX
#define	ICE_DEFAULT_MTU		ETHERMTU
#define	ICE_MAX_FUNCS		8

CTASSERT(ICE_MAX_MTU + sizeof (struct ether_vlan_header) + ETHERFCSL ==
    ICE_MAX_FRAME_SIZE);
CTASSERT(ICE_MAX_FRAME_SIZE <= UINT16_MAX);

/* Standard netlb(4I) modes supported by ice_m_ioctl(). */
#define	ICE_LB_NONE		0
#define	ICE_LB_INTERNAL_MAC	1

/*
 * Datapath constants.
 */
#define	ICE_DESC_ALIGN		128		/* descriptor ring base align */
#define	ICE_DMA_ALIGNMENT	0x1000		/* packet buffer alignment */
#define	ICE_TX_MAX_BUFSZ	0x00003fff	/* per-descriptor max (16K-1) */
#define	ICE_TX_MAX_COOKIE	8		/* descs per non-LSO packet */
#define	ICE_TX_LSO_MAX_COOKIE	32		/* descs per LSO packet */
#define	ICE_TX_MAX_LSO_DESC	32		/* data descs per LSO packet */
/* The refetched header is the eighth descriptor in each hardware segment. */
#define	ICE_TX_LSO_SEG_DESCS	7		/* payload descs per segment */
#define	ICE_TX_LSO_MIN_MSS	64
#define	ICE_LSO_MAXLEN		(64 * 1024)
#define	ICE_TX_LSO_BUFSZ	P2ROUNDUP(ICE_MAX_FRAME_SIZE, PAGESIZE)
/*
 * The general tx copy pool must hold any MTU-legal frame in one buffer: a
 * frame that failed to bind has nowhere else to go and would be dropped.
 */
#define	ICE_TX_COPY_BUFSZ	P2ROUNDUP(ICE_MAX_FRAME_SIZE, PAGESIZE)
#define	ICE_TX_SMALL_PKT	512		/* small-copy threshold */

CTASSERT(sizeof (struct ice_tx_ctx_desc) == sizeof (struct ice_tx_desc));
/*
 * ICE_TX_COPY_BUFSZ is page-rounded, so it is >= ICE_MAX_FRAME_SIZE by
 * construction and is not a constant expression a CTASSERT can read.  Assert
 * the part that matters and is constant: a whole frame still fits the length
 * field of a single tx data descriptor.
 */
CTASSERT(ICE_MAX_FRAME_SIZE <= ICE_TX_MAX_BUFSZ);
CTASSERT(ICE_LSO_MAXLEN <= (ICE_TXD_CTX_QW1_TSO_LEN_M >>
    ICE_TXD_CTX_QW1_TSO_LEN_S));
CTASSERT(ICE_TXD_CTX_MAX_MSS <= (ICE_TXD_CTX_QW1_MSS_M >>
    ICE_TXD_CTX_QW1_MSS_S));

#define	ICE_DEF_TX_RING_SIZE	1024
#define	ICE_DEF_RX_RING_SIZE	1024
#define	ICE_MIN_RING_SIZE	64
#define	ICE_MAX_RING_SIZE	4096
#define	ICE_RX_BUF_SIZE		2048		/* posted rx data buffer */
/* ceil(ICE_AQ_SET_MAC_FRAME_SIZE_MAX / ICE_RX_BUF_SIZE) */
#define	ICE_RX_MAX_DESC		5

#define	ICE_ITR_IDX_0		0		/* ITR slot for queue vectors */
#define	ICE_ITR_INDEX_NONE	3		/* "do not update the ITR" */
#define	ICE_ITR_DEFAULT_US	50		/* rx interrupt throttle */
#define	ICE_Q_ENA_MAX_WAIT	50		/* QENA_STAT poll, 20us each */

typedef enum ice_state {
	ICE_STATE_ATTACHED	= 1 << 0,
	ICE_STATE_RESET_PENDING	= 1 << 1,	/* GRST seen; rebuild owed */
	ICE_STATE_ERROR		= 1 << 2,	/* datapath fail-closed */
	ICE_STATE_STARTED	= 1 << 3,
	ICE_STATE_PFR_REQ	= 1 << 4,	/* fatal cause; PFR owed */
	ICE_STATE_RESET_FAILED	= 1 << 5,	/* rebuild failed; terminal */
	ICE_STATE_MDD_PENDING	= 1 << 6	/* MDD latched; decode owed */
} ice_state_t;

/* ice_lse_flags bits (protected by ice_lse_lock). */
#define	ICE_LSE_F_ENABLE	(1 << 0)	/* link status events wanted */
#define	ICE_LSE_F_UPDATING	(1 << 1)	/* an update is in flight */

/*
 * Attach progress.  Each completed attach step records its bit; teardown
 * reverses only the steps that completed.
 */
typedef enum ice_attach_state {
	ICE_ATTACH_FM_INIT	= 1 << 0,
	ICE_ATTACH_PCI_CONFIG	= 1 << 1,
	ICE_ATTACH_REGS_MAP	= 1 << 2,
	ICE_ATTACH_HW_INIT	= 1 << 3,
	ICE_ATTACH_DDP		= 1 << 4,	/* DDP loaded or safe mode */
	ICE_ATTACH_ALLOC_INTR	= 1 << 5,
	ICE_ATTACH_ADD_INTR	= 1 << 6,
	ICE_ATTACH_OICR_TASKQ	= 1 << 7,
	ICE_ATTACH_RESET_TASKQ	= 1 << 8,	/* reset taskq + rebuild lock */
	ICE_ATTACH_ENABLE_INTR	= 1 << 9,
	ICE_ATTACH_VSI		= 1 << 10,
	ICE_ATTACH_RINGS	= 1 << 11,	/* ring DMA allocated */
	ICE_ATTACH_QUEUE_INTR	= 1 << 12,	/* queue->vector wired */
	ICE_ATTACH_BUFS		= 1 << 13,	/* tx copy-buffer pools */
	ICE_ATTACH_STATS	= 1 << 14,	/* hardware stat kstats */
	ICE_ATTACH_MAC		= 1 << 15	/* mac_register done */
} ice_attach_state_t;

/* The driver-chosen software handle for the single PF data VSI. */
#define	ICE_PF_VSI_HANDLE	0

typedef struct ice_mac_filter {
	list_node_t		imf_node;
	uint8_t			imf_addr[ETHERADDRL];
} ice_mac_filter_t;

/*
 * The PF data VSI.  vi_handle is the driver-chosen software index into
 * hw->vsi_ctx[]; vi_hw_num is the firmware-assigned hardware VSI number,
 * stored only after it is range-checked.  vi_nrxq/vi_ntxq record the queue
 * counts this VSI was configured with.
 */
typedef struct ice_vsi {
	boolean_t		vi_added;
	uint16_t		vi_handle;
	uint16_t		vi_hw_num;
	uint16_t		vi_nrxq;
	uint16_t		vi_ntxq;

	kmutex_t		vi_mac_lock;
	list_t			vi_macs;	/* for teardown */

	boolean_t		vi_rss_set;

	uint16_t		vi_max_frame;	/* posted rx frame size */
} ice_vsi_t;

/*
 * A single DMA allocation: descriptor ring or packet buffer.
 */
typedef struct ice_dma_buffer {
	caddr_t			idb_va;
	size_t			idb_len;
	ddi_acc_handle_t	idb_acc_handle;
	ddi_dma_handle_t	idb_dma_handle;
	uint_t			idb_ncookies;
	ddi_dma_cookie_t	idb_cookie;	/* single cookie (sgllen 1) */
} ice_dma_buffer_t;

#define	ICE_DMA_PA(idb)		((idb)->idb_cookie.dmac_laddress)

typedef enum ice_tcb_type {
	ITCB_NOT_USED,
	ITCB_SMALL_COPY,
	ITCB_COPY,
	ITCB_LSO_COPY,
	ITCB_BIND,
	ITCB_LSO_BIND
} ice_tcb_type_t;

typedef struct ice_tx_ctx_t {
	uint64_t		itc_data_cmd;
	uint64_t		itc_data_off;
	boolean_t		itc_use_ctx;
	uint32_t		itc_mss;
	uint32_t		itc_tsolen;
} ice_tx_ctx_t;

struct ice_tx_ring;
typedef struct ice_tx_ctrl_block {
	struct ice_tx_ring	*itcb_ring;
	ice_tcb_type_t		itcb_type;
	uint32_t		itcb_len;
	ice_dma_buffer_t	*itcb_buf;	/* copy buffer (pool) */
	mblk_t			*itcb_mp;
	ddi_dma_handle_t	itcb_dmah;
	ddi_dma_handle_t	itcb_lso_dmah;
} ice_tx_ctrl_block_t;

typedef struct ice_txq_stat {
	kstat_named_t		ictxs_bytes;
	kstat_named_t		ictxs_packets;
	kstat_named_t		ictxs_bind_bytes;
	kstat_named_t		ictxs_bind_frags;
	kstat_named_t		ictxs_copy_bytes;
	kstat_named_t		ictxs_copy_frags;
	kstat_named_t		ictxs_bind_fails;
	kstat_named_t		ictxs_no_pkt_cache;
	kstat_named_t		ictxs_drops;
	kstat_named_t		ictxs_blocked;
	kstat_named_t		ictxs_lso_packets;
	kstat_named_t		ictxs_lso_drops;
	kstat_named_t		ictxs_lso_pullups;
	kstat_named_t		ictxs_lso_nores;
} ice_txq_stat_t;

typedef struct ice_tx_ring {
	struct ice		*itxr_ice;	/* RO */
	uint32_t		itxr_index;	/* absolute HW tx queue index */
	uint32_t		itxr_vec;	/* MSI-X vector index */
	uint32_t		itxr_q_teid;	/* core: from ice_ena_vsi_txq */

	kmutex_t		itxr_lock;
	kcondvar_t		itxr_cv;	/* stop waits for tx drain */
	boolean_t		itxr_quiesce;
	boolean_t		itxr_blocked;
	uint_t			itxr_tx_active;	/* in-flight tx calls */

	mac_ring_handle_t	itxr_mactxring;

	ice_dma_buffer_t	itxr_dma;	/* descriptor ring */
	struct ice_tx_desc	*itxr_descs;
	uint16_t		itxr_size;	/* descriptor count */
	uint16_t		itxr_avail;
	uint16_t		itxr_head;
	uint16_t		itxr_tail;

	ice_tx_ctrl_block_t	*itxr_tcb_area;	/* [itxr_size] backing */
	ice_tx_ctrl_block_t	**itxr_tcbs;	/* [itxr_size], by slot */
	kmutex_t		itxr_tcb_lock;
	ice_tx_ctrl_block_t	**itxr_tcb_free_list;
	uint16_t		itxr_tcb_nfree;

	kstat_t			*itxr_kstat;
	ice_txq_stat_t		itxr_stats;
} ice_tx_ring_t;

typedef enum ice_rcb_state {
	IRXB_FREE,
	IRXB_ONRING,
	IRXB_ONLOAN
} ice_rcb_state_t;

struct ice_rx_ring;
typedef struct ice_rx_ctrl_block {
	mblk_t			*ircb_mp;
	struct ice_rx_ring	*ircb_ring;
	ice_dma_buffer_t	ircb_dma;
	frtn_t			ircb_free_rtn;
	ice_rcb_state_t		ircb_state;
} ice_rx_ctrl_block_t;

typedef struct ice_rxq_stat {
	kstat_named_t		icrxs_bytes;
	kstat_named_t		icrxs_packets;
	kstat_named_t		icrxs_bind_bytes;
	kstat_named_t		icrxs_bind_segs;
	kstat_named_t		icrxs_copy_bytes;
	kstat_named_t		icrxs_copy_segs;
	kstat_named_t		icrxs_desc_error;
	kstat_named_t		icrxs_copy_nomem;
	kstat_named_t		icrxs_no_rcb;
} ice_rxq_stat_t;

typedef struct ice_rx_ring {
	struct ice		*irxr_ice;	/* RO */
	uint32_t		irxr_index;	/* absolute HW rx queue index */
	uint32_t		irxr_vec;	/* MSI-X vector index */
	boolean_t		irxr_shutdown;
	boolean_t		irxr_started;	/* irxr_lock */
	boolean_t		irxr_intr_poll;	/* mac is polling this ring */

	kmutex_t		irxr_lock;
	kcondvar_t		irxr_cv;	/* teardown waits on loans */
	mac_ring_handle_t	irxr_macrxring;
	uint64_t		irxr_rxgen;

	ice_dma_buffer_t	irxr_desc_dma;	/* descriptor ring */
	union ice_32b_rx_flex_desc *irxr_descs;
	ice_rx_ctrl_block_t	**irxr_rcbs;	/* [irxr_size], by slot */
	uint16_t		irxr_size;	/* descriptor count */
	uint16_t		irxr_head;
	uint16_t		irxr_tail;
	uint32_t		irxr_dbuf;	/* posted data buffer size */

	/* Control-block backing + spare free stack for loaned buffers. */
	ice_rx_ctrl_block_t	*irxr_rcb_area;	/* [irxr_nrcb] backing */
	ice_rx_ctrl_block_t	**irxr_free_rcbs;
	uint_t			irxr_nrcb;	/* size + reserve */
	uint_t			irxr_nfree;
	uint_t			irxr_nreserve;	/* loan high-water */
	uint_t			irxr_nloaned;	/* outstanding loans */

	kstat_t			*irxr_kstat;
	ice_rxq_stat_t		irxr_stats;
} ice_rx_ring_t;

/*
 * Physical-port hardware statistics, read from the GLPRT_* MAC counters.  The
 * counters are per logical port and therefore aggregate every VSI and VF on
 * the function, so they describe the wire rather than this interface.
 */
typedef struct ice_pf_kstats {
	kstat_named_t		ipk_rx_bytes;
	kstat_named_t		ipk_rx_unicast;
	kstat_named_t		ipk_rx_multicast;
	kstat_named_t		ipk_rx_broadcast;
	kstat_named_t		ipk_tx_bytes;
	kstat_named_t		ipk_tx_unicast;
	kstat_named_t		ipk_tx_multicast;
	kstat_named_t		ipk_tx_broadcast;
	kstat_named_t		ipk_crc_errors;
	kstat_named_t		ipk_illegal_bytes;
	kstat_named_t		ipk_mac_local_faults;
	kstat_named_t		ipk_mac_remote_faults;
	kstat_named_t		ipk_rx_len_errors;
	kstat_named_t		ipk_rx_undersize;
	kstat_named_t		ipk_rx_fragments;
	kstat_named_t		ipk_rx_oversize;
	kstat_named_t		ipk_rx_jabber;
	kstat_named_t		ipk_tx_dropped_link_down;
	kstat_named_t		ipk_link_xon_rx;
	kstat_named_t		ipk_link_xoff_rx;
	kstat_named_t		ipk_link_xon_tx;
	kstat_named_t		ipk_link_xoff_tx;
} ice_pf_kstats_t;

/*
 * Per-VSI hardware statistics, read from the GLV_* counters for this
 * interface's VSI.  Unlike the port counters these isolate traffic actually
 * switched to this VSI, so a receive that advances the port counters but not
 * these localizes a fault to the switch or VSI configuration.
 */
typedef struct ice_vsi_kstats {
	kstat_named_t		ivk_rx_bytes;
	kstat_named_t		ivk_rx_unicast;
	kstat_named_t		ivk_rx_multicast;
	kstat_named_t		ivk_rx_broadcast;
	kstat_named_t		ivk_rx_discards;
	kstat_named_t		ivk_rx_no_desc;
	kstat_named_t		ivk_rx_errors;
	kstat_named_t		ivk_tx_bytes;
	kstat_named_t		ivk_tx_unicast;
	kstat_named_t		ivk_tx_multicast;
	kstat_named_t		ivk_tx_broadcast;
	kstat_named_t		ivk_tx_errors;
} ice_vsi_kstats_t;

typedef struct ice {
	dev_info_t		*ice_dip;
	int			ice_instance;

	/*
	 * Mutated with atomic_*_32 rather than under ice_lock because it will
	 * be read locklessly from interrupt and MAC-callback context once the
	 * data path exists.
	 */
	uint32_t		ice_state;
	ice_attach_state_t	ice_attach_progress;

	kmutex_t		ice_lock;
	list_node_t		ice_glink;

	int			ice_fm_caps;

	/*
	 * Intel common code, embedded inline.  ice_hw.back points at
	 * ice_osdep and ice_osdep.ios_ice points back here; both are wired
	 * once, early in attach, before any register or config-space access.
	 */
	struct ice_hw		ice_hw;
	struct ice_osdep	ice_osdep;

	int			ice_intr_type;
	int			ice_intr_cap;
	uint_t			ice_intr_pri;
	int			ice_intr_count;
	size_t			ice_intr_size;
	ddi_intr_handle_t	*ice_intr_handles;
	uint16_t		ice_nqueues;

	/* OICR deferred async work; thread context, serialized via ice_lock. */
	ddi_taskq_t		*ice_oicr_taskq;
	ddi_periodic_t		ice_admin_periodic;
	boolean_t		ice_oicr_pending;	/* ice_lock */
	uint32_t		ice_oicr_cause;		/* ice_lock */
	uint8_t			*ice_aqbuf;		/* ARQ scratch buffer */

	/*
	 * Reset rebuild.  ice_rebuild_lock is an adaptive mutex taken only in
	 * thread context and is the outermost driver lock: it serializes a
	 * rebuild against a mac start/stop.  The rebuild runs on its own
	 * single-thread taskq so it never starves the OICR worker's ARQ drain;
	 * ice_reset_pending coalesces dispatches under ice_lock, mirroring
	 * ice_oicr_pending.  ice_attaching and ice_detaching turn a queued
	 * rebuild into a no-op while the instance is not fully constructed:
	 * the rebuild frees and reinitializes scheduler and control-queue
	 * state that the attach thread is still building on, and it reports
	 * link state through a MAC handle detach is about to invalidate.  The
	 * hardware latches are one-shot, so whoever clears one of these flags
	 * must requeue a rebuild owed while it was set.
	 */
	ddi_taskq_t		*ice_reset_taskq;
	boolean_t		ice_reset_pending;	/* ice_lock */
	kmutex_t		ice_rebuild_lock;
	boolean_t		ice_attaching;		/* ice_rebuild_lock */
	boolean_t		ice_detaching;		/* ice_rebuild_lock */

	/*
	 * Link-state cache.  The authoritative state lives in
	 * ice_hw.port_info->phy.link_info, refreshed by the common code; these
	 * are the decoded values MAC will consume once mac_register lands.
	 * Guarded by ice_lse_lock.
	 */
	kmutex_t		ice_lse_lock;
	kcondvar_t		ice_lse_cv;
	uint32_t		ice_lse_flags;
	link_state_t		ice_link_state;
	uint64_t		ice_link_speed;
	link_duplex_t		ice_link_duplex;
	link_flowctrl_t		ice_link_fctl;
	uint16_t		ice_phy_speeds_supp;
	uint16_t		ice_phy_speeds_adv;
	link_fec_t		ice_fec_neg;
	/* Adaptive mutex: loopback transitions run only in thread context. */
	kmutex_t		ice_loopback_lock;
	uint32_t		ice_loopback_mode;

	uint32_t		ice_mtu;
	boolean_t		ice_tx_lso_enable;
	boolean_t		ice_promisc_on;		/* replay on reset */
	ice_vsi_t		ice_pf_vsi;		/* the PF's data VSI */

	/*
	 * Datapath rings.  Counts derive from the VSI queue configuration.
	 */
	uint_t			ice_num_txr;
	uint_t			ice_num_rxr;
	uint_t			ice_num_rx_groups;
	ice_tx_ring_t		*ice_txr;	/* [ice_num_txr] */
	ice_rx_ring_t		*ice_rxr;	/* [ice_num_rxr] */

	uint32_t		ice_tx_ring_size;
	uint32_t		ice_rx_ring_size;

	/* Shared TX copy-buffer pools. */
	kmutex_t		ice_buf_lock;
	ice_dma_buffer_t	*ice_bufs;	/* backing array */
	ice_dma_buffer_t	**ice_dma_bufs;	/* free stack */
	uint_t			ice_buf_sz;
	uint_t			ice_buf_alloc;
	ice_dma_buffer_t	*ice_lso_bufs;
	ice_dma_buffer_t	**ice_dma_lso_bufs;
	uint_t			ice_lso_buf_sz;
	uint_t			ice_lso_buf_alloc;
	kmutex_t		ice_small_buf_lock;
	ice_dma_buffer_t	*ice_small_bufs;
	ice_dma_buffer_t	**ice_dma_small_bufs;
	uint_t			ice_small_buf_sz;
	uint_t			ice_small_buf_alloc;

	/* DDP firmware. */
	/* Attach-only: MAC caches mi_capab at mac_register(). */
	boolean_t		ice_safe_mode;
	enum ice_ddp_state	ice_ddp_state;

	/*
	 * Hardware statistics.  The MAC counters do not reset on a PF reset, so
	 * the common-code helpers subtract a first-read baseline; ice_stat_lock
	 * serializes the kstat and mac_stat readers that share that baseline.
	 */
	kmutex_t		ice_stat_lock;
	boolean_t		ice_stat_port_loaded;
	boolean_t		ice_stat_vsi_loaded;
	hrtime_t		ice_stat_port_last_update;
	struct ice_hw_port_stats ice_stat_port_cur;
	struct ice_hw_port_stats ice_stat_port_prev;
	struct ice_eth_stats	ice_stat_vsi_cur;
	struct ice_eth_stats	ice_stat_vsi_prev;
	kstat_t			*ice_pf_kstat;
	kstat_t			*ice_vsi_kstat;

	mac_handle_t		ice_mac_hdl;	/* set by mac_register() */
} ice_t;

/*
 * ice.c
 */
/*PRINTFLIKE2*/
extern void ice_error(ice_t *, const char *, ...);
extern int ice_check_acc_handle(ddi_acc_handle_t);
extern void ice_update_mtu(ice_t *);
extern int ice_queues_program(ice_t *);
extern void ice_queues_disable(ice_t *);
extern void ice_reset_task(void *);
extern void ice_reset_redispatch(ice_t *);
#ifdef DEBUG
extern void ice_test_request_reset(ice_t *);
#endif

/*
 * ice_intr.c
 */
extern uint_t ice_intr_msix(caddr_t, caddr_t);
extern boolean_t ice_intr_enable(ice_t *);
extern void ice_intr_disable(ice_t *);
extern void ice_intr_oicr_setup(ice_t *, boolean_t);
extern void ice_intr_oicr_disable(ice_t *);
extern boolean_t ice_set_link_events(ice_t *);
extern void ice_link_status_update(ice_t *);
extern void ice_oicr_resync(ice_t *);
extern void ice_admin_periodic_start(ice_t *);
extern void ice_admin_periodic_stop(ice_t *);
extern void ice_setup_link(ice_t *);
extern void ice_phy_caps_update(ice_t *);
extern void ice_reset_dispatch(ice_t *);
extern void ice_link_report(ice_t *, link_state_t);

/*
 * ice_vsi.c
 */
extern boolean_t ice_vsi_init(ice_t *);
extern void ice_vsi_fini(ice_t *);
extern int ice_vsi_rebuild(ice_t *);

/*
 * ice_ddp.c
 */
extern boolean_t ice_ddp_load(ice_t *);

/*
 * ice_dma.c
 */
extern void ice_dma_acc_attr(ice_t *, ddi_device_acc_attr_t *);
extern void ice_dma_ring_attr(ice_t *, ddi_dma_attr_t *);
extern void ice_pkt_dma_attr(ice_t *, ddi_dma_attr_t *);
extern void ice_pkt_txbind_attr(ice_t *, ddi_dma_attr_t *);
extern void ice_pkt_txbind_lso_attr(ice_t *, ddi_dma_attr_t *);
extern boolean_t ice_dma_alloc(ice_t *, ice_dma_buffer_t *, ddi_dma_attr_t *,
    ddi_device_acc_attr_t *, boolean_t, size_t, boolean_t);
extern void ice_dma_free(ice_dma_buffer_t *);
extern int ice_check_dma_handle(ddi_dma_handle_t);
extern ice_dma_buffer_t *ice_buf_alloc(ice_t *);
extern void ice_buf_free(ice_t *, ice_dma_buffer_t *);
extern ice_dma_buffer_t *ice_lso_buf_alloc(ice_t *);
extern void ice_lso_buf_free(ice_t *, ice_dma_buffer_t *);
extern ice_dma_buffer_t *ice_small_buf_alloc(ice_t *);
extern void ice_small_buf_free(ice_t *, ice_dma_buffer_t *);
extern boolean_t ice_buf_init(ice_t *);
extern void ice_buf_fini(ice_t *);

/*
 * ice_tx.c
 */
extern boolean_t ice_tx_rings_alloc(ice_t *);
extern void ice_tx_rings_free(ice_t *);
extern int ice_tx_ring_program(ice_t *, ice_tx_ring_t *);
extern void ice_tx_ring_unprogram(ice_t *, ice_tx_ring_t *);
extern void ice_map_txq_vector(ice_t *, ice_tx_ring_t *);

/*
 * ice_rx.c
 */
extern boolean_t ice_rx_rings_alloc(ice_t *);
extern void ice_rx_rings_free(ice_t *);
extern int ice_rx_ring_program(ice_t *, ice_rx_ring_t *);
extern void ice_rx_ring_unprogram(ice_t *, ice_rx_ring_t *);
extern void ice_map_rxq_vector(ice_t *, ice_rx_ring_t *);
extern void ice_cfg_itr(ice_t *, uint32_t);

/*
 * ice_tx.c -- packet datapath
 */
extern mblk_t *ice_ring_tx(void *, mblk_t *);
extern void ice_tx_start(ice_t *);
extern void ice_tx_quiesce(ice_t *);
extern void ice_tx_reclaim(ice_t *);
extern void ice_tx_stop(ice_t *);
extern void ice_tx_ring_intr(ice_tx_ring_t *);
extern int ice_ring_tx_stat(mac_ring_driver_t, uint_t, uint64_t *);

/*
 * ice_rx.c -- packet datapath
 */
extern void ice_rx_recycle(caddr_t);
extern boolean_t ice_rx_start(ice_t *);
extern boolean_t ice_rx_quiesce(ice_t *);
extern void ice_rx_reclaim(ice_t *);
extern boolean_t ice_rx_stop(ice_t *);
extern boolean_t ice_rx_drain(ice_t *);
extern boolean_t ice_rx_rings_resume(ice_t *);
extern void ice_rx_ring_intr(ice_rx_ring_t *);
extern mblk_t *ice_ring_rx_poll(void *, int);
extern int ice_ring_rx_start(mac_ring_driver_t, uint64_t);
extern void ice_ring_rx_stop(mac_ring_driver_t);
extern int ice_ring_rx_stat(mac_ring_driver_t, uint_t, uint64_t *);
extern int ice_ring_rx_intr_enable(mac_intr_handle_t);
extern int ice_ring_rx_intr_disable(mac_intr_handle_t);

/*
 * ice_gld.c
 */
extern boolean_t ice_mac_register(ice_t *);
extern int ice_mac_unregister(ice_t *);
extern void ice_link_state_publish(ice_t *);
extern int ice_start_datapath(ice_t *);
extern int ice_promisc_apply(ice_t *, boolean_t);

/*
 * Hardware statistics (ice_stats.c).
 */
extern boolean_t ice_stats_init(ice_t *);
extern void ice_stats_fini(ice_t *);
extern void ice_stats_update_port(ice_t *);
extern void ice_stats_update_vsi(ice_t *);
extern int ice_vsi_loopback_set(ice_t *, boolean_t);
extern void ice_link_loopback_update(ice_t *, uint32_t);
extern void ice_loopback_replay(ice_t *);
extern void ice_loopback_fini(ice_t *);

#ifdef __cplusplus
}
#endif

#endif /* _ICE_H */
