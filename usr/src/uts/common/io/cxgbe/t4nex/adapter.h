/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source. A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * This file is part of the Chelsio T4 support code.
 *
 * Copyright (C) 2011-2013 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

/*
 * Copyright 2025 Oxide Computer Company
 */

#ifndef __CXGBE_ADAPTER_H
#define	__CXGBE_ADAPTER_H

#include <sys/ddi.h>
#include <sys/mac_provider.h>
#include <sys/ethernet.h>
#include <sys/list.h>
#include <sys/containerof.h>
#include <sys/ddi_ufm.h>
#include <sys/mac_provider.h>

#include "firmware/t4fw_interface.h"
#include "shared.h"

struct adapter;
struct port_info;
typedef struct adapter adapter_t;
struct sge_fl;

/* See the _Ingress Context Contents_ section of the T4 Programmers Guide. */
typedef enum t4_iq_esize {
	T4_IQ_ESIZE_16B = 0,
	T4_IQ_ESIZE_32B = 1,
	T4_IQ_ESIZE_64B = 2,
	T4_IQ_ESIZE_128B = 3,
} t4_iq_esize_t;

#define	FW_IQ_QSIZE	256
/* At least 64 bytes mandated by the firmware spec */
#define	FW_IQ_ESIZE	T4_IQ_ESIZE_64B

#define	T4_RX_DEF_QSIZE	1024
/* At least 64 so CPL_RX_PKT will fit */
#define	RX_IQ_ESIZE	T4_IQ_ESIZE_64B

/* A flit is an 8 byte quantity. */
#define	FLIT_NUM_BYTES		8
#define	FLITS_TO_BYTES(nflits)	((nflits) * FLIT_NUM_BYTES)

/*
 * Egress Queues (EQ) are made up of units called "host credits". Each credit is
 * always 8 flits (64 bytes) in size. The number of entries in the queue as well
 * as the producer and consumer indexes (pidx/cidx) are phrased in units of
 * credits.
 *
 * A freelist (FL) is a type of EQ. It consists of 16-byte aligned, 8-byte
 * pointers to data buffers meant to hold the data of incoming packets. Since an
 * EQ host credit is always 8 flits, and an FL buffer pointer is a single flit,
 * each credit holds 8 FL buffer pointers.
 *
 */
#define	FLITS_PER_EQ_HC		8
#define	EQ_HC_SIZE		FLITS_PER_EQ_HC * FLIT_NUM_BYTES
#define	FL_BUF_PTR_PER_HC	FLITS_PER_EQ_HC

/*
 * Given a number of host credits, calculate the total number of flits
 * contained in those credits.
 */
#define	EQ_HC_TO_FLITS(num_credits)	((num_credits) * FLITS_PER_EQ_HC)

/*
 * Given a number of flits, calculate how many host credits are needed to hold
 * them.
 */
#define	EQ_FLITS_TO_HC(num_flits)	(howmany(num_flits, FLITS_PER_EQ_HC))

/*
 * We constrain the max "usable" EQ size so that there is always room for the
 * status page, which may require 1-2 host credits.
 */
#define	T4_MAX_EQ_SIZE		(UINT16_MAX - 2)
#define	T4_TX_DEF_QSIZE		1024
#define	TX_SGL_SEGS		36

/* The maximum number of flits/credits a single WR may consume. */
#define	TX_WR_MAX_FLITS		(SGE_MAX_WR_LEN / FLIT_NUM_BYTES)
#define	TX_WR_MAX_CREDITS	(TX_WR_MAX_FLITS / FLITS_PER_EQ_HC)

CTASSERT(TX_WR_MAX_FLITS == 64);
CTASSERT(TX_WR_MAX_CREDITS == 8);

#define	UDBS_SEG_SHIFT	7	/* log2(UDBS_SEG_SIZE) */
#define	UDBS_DB_OFFSET	8	/* offset of the 4B doorbell in a segment */
#define	UDBS_WR_OFFSET	64	/* offset of the work request in a segment */

/*
 * A sentinel to mark when the interrupts for an IQ are being forwarded from
 * another IQ which is receiving the actual interrupt.
 */
#define	INTR_FORWARDED	UINT_MAX

struct fl_desc {
	uint64_t dptr[FL_BUF_PTR_PER_HC];
};

struct fl_sdesc {
	struct rxbuf *rxb;
};

typedef struct t4_eq_host_credit {
	uint64_t flit[8];
} t4_eq_host_credit_t;

struct tx_sdesc {
	mblk_t *mp_head;
	mblk_t *mp_tail;
	uint32_t txb_used;	/* # of bytes of tx copy buffer used */
	uint16_t hdls_used;	/* # of dma handles used */
	uint16_t credits_used;	/* # of EQ host credits used */
	uint64_t _pad;
};

typedef enum t4_iq_flags {
	IQ_ALLOC_HOST	= (1 << 0),	/* host-side resources allocated */
	IQ_ALLOC_DEV	= (1 << 1),	/* device-side resource allocated */
	IQ_INTR		= (1 << 2),	/* iq takes direct interrupt */

	/* Runtime state flags: */
	IQ_ENABLED	= (1 << 3),
	IQ_POLLING	= (1 << 4),
} t4_iq_flags_t;

struct rxbuf_cache_params {
	dev_info_t		*dip;
	ddi_dma_attr_t		dma_attr_rx;
	ddi_device_acc_attr_t	acc_attr_rx;
	size_t			buf_size;
};

struct sge_iq_stats {
	uint64_t sis_processed;	/* # entries processed from IQ */
	uint64_t sis_overflow;	/* # entries bearing overflow flag */
};

/*
 * These values are designed to match up with what is posted to GTS registers
 * when processing an ingress queue.
 *
 * See: t4_iq_update_intr_cfg() and t4_iq_gts_update().
 */
typedef enum t4_gts_config {
	TGC_SE_INTR_ARM		= 1,
	TGC_TIMER0		= (0 << 1),
	TGC_TIMER1		= (1 << 1),
	TGC_TIMER2		= (2 << 1),
	TGC_TIMER3		= (3 << 1),
	TGC_TIMER4		= (4 << 1),
	TGC_TIMER5		= (5 << 1),
	TGC_START_COUNTER	= (6 << 1),
} t4_gts_config_t;

/*
 * Event IQs are used for firmware events, Tx EGR updates, and IQ forwarded
 * interrupts.
 *
 * Ethernet Rx IQs are used for receiving incoming packets.
 */
typedef enum t4_iq_type {
	TIQT_UNINIT,
	TIQT_EVENT,
	TIQT_ETH_RX,
} t4_iq_type_t;

/* Ingress Queue: T4 is producer, driver is consumer. */
typedef struct t4_sge_iq {
	kmutex_t tsi_lock;

	t4_iq_type_t tsi_iqtype; /* Write Once */
	t4_iq_flags_t tsi_flags; /* tsi_lock */

	/*
	 * This field is non-NULL only for Rx queues. It points to the event
	 * queue which receives interrupts on its behalf. The event queue
	 * processes these "forwarded interrupts" in t4_process_event_iq() and
	 * calls into t4_process_rx_iq() for each Rx queue with an interrupt
	 * notification message.
	 */
	struct t4_sge_iq *tsi_intr_evtq; /* Write Once */
	/*
	 * This field is only used by the event queues.
	 *
	 * As the event queue processes forwarded interrupt notification
	 * messages it adds the destination rx queue receving the notification
	 * to this list. After the event queue finishes processing its own
	 * messages, it then uses this list to process the rx queues which have
	 * pending notifications.
	 */
	list_node_t tsi_intr_fwd_node; /* tsi_lock */
	/*
	 * This field is used by both event queues and rx queues.
	 *
	 * For event queues this field holds the interrupt vector assigned to
	 * this queue.
	 *
	 * For rx queues it holds the sentinel value INTR_FORWARDED to indicate
	 * it has its interrupts forwarded by the event queue. In the current
	 * iteration of this driver all rx queues will always have their
	 * interrupts forwarded.
	 */
	uint_t tsi_intr_idx;	/* Write Once */

	ddi_dma_handle_t tsi_desc_dhdl; /* Write Once */
	ddi_acc_handle_t tsi_desc_ahdl; /* Write Once */

	/* KVA of descriptor ring */
	void *tsi_desc;		/* Write Once */
	/* bus address of descriptor ring */
	uint64_t tsi_desc_ba;	/* Write Once */
	/* current descriptor (at CIDX) */
	const void *tsi_cdesc;	/* tsi_lock */

	/* Sizing and status */
	/* size of each entry in the queue */
	t4_iq_esize_t tsi_esize;  /* Write Once */
	/* entry size in bytes */
	uint16_t tsi_esize_bytes; /* Write Once */
	/* number of entries in the queue */
	uint16_t tsi_qsize;	/* Write Once */
	/* number of usable entries in the queue */
	uint16_t tsi_cap;	/* Write Once */
	/* consumer index */
	uint16_t tsi_cidx;	/* tsi_lock */
	/* generation bit */
	uint8_t tsi_gen;	/* tsi_lock */

	/* GTS config to re-arm queue notification */
	t4_gts_config_t tsi_gts_rearm; /* tsi_lock */
	/* packet count threshold index */
	int8_t tsi_intr_pktc_idx; /* tsi_lock */

	/* SGE context ID for IQ */
	uint16_t tsi_cntxt_id;	/* Write Once */
	/* absolute SGE ID for IQ */
	uint16_t tsi_abs_id;	/* Write Once */

	/* associated adapter */
	struct adapter *tsi_adapter; /* Write Once */
	/* associated freelist (if any) */
	struct sge_fl *tsi_fl;	/* Write Once */

	struct sge_iq_stats tsi_stats; /* tsi_lock */
} t4_sge_iq_t;

/* Result of servicing IQ in t4_iq_service() call */
typedef enum t4_iq_result {
	TIR_SUCCESS,	/* All available entries processed successfully */
	TIR_DISABLED,	/* IQ is disabled */
	TIR_POLLING,	/* non-polling service req'd on polling-cfg'd IQ */
	TIR_ALLOC_FAIL,	/* could not allocate packet buffer(s) */
	TIR_BUDGET_MAX,	/* hit budget limit while processing entries */
} t4_iq_result_t;

/*
 * Details used when servicing an IQ as part of polling.
 */
struct t4_poll_req {
	mblk_t	*tpr_mp;
	uint_t	tpr_byte_budget;
};

typedef enum t4_eq_flags {
	/* Initialization state flags: */
	EQ_ALLOC_HOST	= (1 << 0),	/* host-side resources allocated */
	EQ_ALLOC_DEV	= (1 << 1),	/* EQ allocated in device firmware */
	EQ_ALLOC_DESC	= (1 << 2),	/* descriptor inputs allocated */

	/* Runtime state flags: */

	EQ_ENABLED	= (1 << 3),	/* ready for submitted work requests */
	/*
	 * Short on resources (memory and/or descriptors) while attempting to
	 * enqueue work in EQ
	 */
	EQ_CORKED	= (1 << 4),
} t4_eq_flags_t;

/*
 * These are the Egress Queue doorbell methods. They are listed in order of
 * preference (WCWR most preferred, KDB least). This ordering is important as
 * the datapath uses ffs (find first set) to pick the preferred method.
 *
 * The first three are "user space" doorbells. They are mapped in BAR2 and are
 * provided to allow kernel-bypass network stacks. However, they can also be
 * used in the kernel and provide benefits such as write combining and per-queue
 * registers (versus KDB which is a single register).
 *
 * The WCWR, Write Combining Work Request, is the preferred method. It allows
 * the driver to push a WR directly to the device without the need for it to
 * perform a DMA read of the hardware ring (to read the EQ host credit). Instead
 * it comes in via the BAR2/UDB memory space and the device increments the pidx
 * accordingly. However, the WCWR is limited to a single WR. It's use is
 * intended for low latency situations or low rate of work, not for throughput.
 *
 * The maximum WCWR for T4 is 256 bytes. For T5/T6 it is 64-128 bytes, depending
 * on the write-combining size of the platform.
 *
 * T4 Firmware Interface Specification, §9.2 Egress Queues and Work Requests.
 */
typedef enum t4_doorbells {
	DOORBELL_WCWR	= (1 << 0),
	DOORBELL_UDBWC	= (1 << 1),
	DOORBELL_UDB	= (1 << 2),
	DOORBELL_KDB	= (1 << 3),
} t4_doorbells_t;

/* Egress Queue: driver is producer, T4 is consumer. */
typedef struct t4_sge_eq {
	kmutex_t tse_lock;

	t4_eq_flags_t tse_flags;	/* tse_lock */

	ddi_dma_handle_t tse_ring_dhdl; /* Write Once */
	ddi_acc_handle_t tse_ring_ahdl; /* Write Once */

	/*
	 * The ring type is pointer to void because the ring does not consist of
	 * descriptors but rather host credits. These host credits carry
	 * variable length work requests (WR) as well as the status page (SP) at
	 * the end of the ring. We use void* to facilitate the type punning
	 * required to work with these various types of EQ entries.
	 *
	 * In order to access credits and their individual flits we make use to
	 * the t4_eq_host_credit_t type.
	 */
	void *tse_ring;		/* KVA of ring - Write Once */
	uint64_t tse_ring_ba;	/* bus address of ring - Write Once */

	/*
	 * tse_qsize: The number of host credits that may be used for data. This
	 * value is static for the lifetime of the queue.
	 *
	 * tse_qsize_spg: The total number of host credits in the queue. This is
	 * 1-2 more credits than tse_qsize to account for the status page at the
	 * end of the queue. The status page credits cannot be used for sending
	 * data, rather the beginning of the status page is considered the end
	 * of the queue as far as the datapath is concerned.
	 *
	 * tse_avail: The number of host credits that are currently available
	 * for use by the host. This is never more than 'tse_qsize - 1' in order
	 * to avoid 'tse_pidx==tse_cidx' which we use to indicate an empty
	 * queue. This number is updated as credits are used/recycled.
	 *
	 * tse_pending: The number of credits that have been written by the host
	 * but still require a doorbell before the device can consume them. Said
	 * another way, it's the number of credits the host's pidx is ahead of
	 * the device's cidx.
	 */
	uint16_t tse_qsize;	/* Write Once */
	uint16_t tse_qsize_spg;	/* Write Once */
	uint16_t tse_avail;	/* tse_lock */
	uint16_t tse_pending;	/* tse_lock */

	/*
	 * The pidx is the driver's position in the queue, pointing to the next
	 * credit to consume. The cidx is the device's position in the queue,
	 * pointing to the last credit it has consumed as of the last status
	 * update.
	 */
	uint16_t tse_cidx;	/* tse_lock */
	uint16_t tse_pidx;	/* tse_lock */

	/* Doorbell bits */
	t4_doorbells_t tse_doorbells; /* Write Once */
	/* KVA of doorbell (lies within BAR2) */
	caddr_t tse_udb;	/* Write Once */
	/* relative qid within the doorbell page */
	uint_t tse_udb_qid;	/* Write Once */

	struct sge_qstat *tse_spg;	/* status page - Write Once */
	/* IQ that gets egr_update msg for EQ */
	uint16_t tse_iqid;		/* Write Once */
	/* tx channel used by the EQ */
	uint8_t tse_tx_chan;		/* Write Once */
	/* SGE context id for the EQ */
	uint32_t tse_cntxt_id;		/* Write Once */
} t4_sge_eq_t;

typedef enum t4_sfl_flags {
	SFL_STARVING	= (1 << 0),	/* on the list of starving fl's */
	SFL_DOOMED	= (1 << 1),	/* about to be destroyed */
} t4_sfl_flags_t;

struct sge_fl_stats {
	/* These stats describe the receiving of data. */
	uint64_t copy;		/* # of frames copied (allocb) */
	uint64_t copy_fail;	/* # of allocb failures */
	uint64_t wrap;		/* # of frames wrapped (desballoc) */
	uint64_t wrap_fail;	/* # of deballoc failures */

	/* These stats describe the refilling of rx (FL) buffers. */
	uint64_t rxb_recycle;	/* # of rx buffers recycled */
	uint64_t rxb_alloc;	/* # of rx buffers allocated */
	uint64_t rxb_alloc_fail; /* # of rx buffers that failed to allocb */
};

struct sge_fl {
	/*
	 * EQ for passing freelist entries to adapter.
	 * Must be first field in struct
	 */
	t4_sge_eq_t eq;		/* Write Once */

	/*
	 * Index at which new buffers are to be placed in the FL descriptor
	 * which is currently being produced for the device.
	 */
	uint8_t cidx_sdesc;	/* FL_LOCK */
	uint8_t pidx_sdesc;	/* FL_LOCK */

	/* KVA of the software descriptor ring. */
	struct fl_sdesc *sdesc;	/* Write Once */
	/* Total number of buffers in the FL.  */
	uint32_t bufs_cap;	/* Write Once */
	/*
	 * Number of buffers available to receive data, buffers owned by the
	 * device.
	 */
	uint32_t bufs_avail;	 /* FL_LOCK */
	/* Number of buffers at which the FL is considered "starving". */
	uint32_t bufs_lowat;	/* Write Once */
	/* The byte offset in the current FL buffer. */
	uint32_t offset;	/* FL_LOCK */
	/* Any packet smaller or equal to this is copied (allocb). */
	uint16_t copy_threshold; /* Write Once */

	/* Starvation-related state for this freelist. */
	t4_sfl_flags_t sfl_flags; /* adapter->sfl_lock */
	list_node_t sfl_node;	  /* adapter->sfl_lock */

	struct sge_fl_stats stats; /* FL_LOCK */
};

struct sge_txq_stats {
	/* stats for common events first */
	uint64_t txpkts;	/* # of ethernet packets */
	uint64_t txbytes;	/* # of ethernet bytes */
	uint64_t txcsum;	/* # of times hardware assisted with checksum */
	uint64_t tso_wrs;	/* # of IPv4 TSO work requests */
	uint64_t imm_wrs;	/* # of work requests with immediate data */
	uint64_t sgl_wrs;	/* # of work requests with direct SGL */
	uint64_t txpkt_wrs;	/* # of txpkt work requests (not coalesced) */
	uint64_t txpkts_wrs;	/* # of coalesced tx work requests */
	uint64_t txpkts_pkts;	/* # of frames in coalesced tx work requests */
	uint64_t txb_used;	/* # of tx copy buffers used (64 byte each) */
	uint64_t hdl_used;	/* # of DMA handles used */

	/* stats for not-that-common events */
	uint32_t txb_full;	/* txb ran out of space */
	uint32_t dma_hdl_failed; /* couldn't obtain DMA handle */
	uint32_t dma_map_failed; /* couldn't obtain DMA mapping */
	uint32_t qfull;		/* out of hardware descriptors */
	uint32_t pullup_early;	/* # of pullups before starting frame's SGL */
	uint32_t pullup_late;	/* # of pullups while building frame's SGL */
	uint32_t pullup_failed;	/* # of failed pullups */
	uint32_t csum_failed;	/* # of csum reqs we failed to fulfill */
};

/* Ethernet packet transmission queue */
struct sge_txq {
	t4_sge_eq_t eq;

	struct port_info *port;
	struct tx_sdesc *sdesc;	/* KVA of software descriptor ring */

	mac_ring_handle_t ring_handle;

	/* DMA handles used for tx */
	ddi_dma_handle_t *tx_dhdl;
	uint32_t tx_dhdl_total;	/* Total # of handles */
	uint32_t tx_dhdl_pidx;	/* next handle to be used */
	uint32_t tx_dhdl_cidx;	/* reclaimed up to this index */
	uint32_t tx_dhdl_avail;	/* # of available handles */

	/* Copy buffers for tx */
	ddi_dma_handle_t txb_dhdl;
	ddi_acc_handle_t txb_ahdl;
	caddr_t txb_va;		/* KVA of copy buffers area */
	uint64_t txb_ba;	/* bus address of copy buffers area */
	uint32_t txb_size;	/* total size */
	uint32_t txb_next;	/* offset of next useable area in the buffer */
	uint32_t txb_avail;	/* # of bytes available */
	uint16_t copy_threshold; /* anything this size or less is copied up */

	kstat_t *ksp;
	struct sge_txq_stats stats;
};

struct sge_rxq_stats {
	/* stats for common events first */
	uint64_t rxcsum;	/* # of times hardware assisted with checksum */
	uint64_t rxpkts;	/* # of ethernet packets */
	uint64_t rxbytes;	/* # of ethernet bytes */
};

/* Ethernet packet receive queue */
struct sge_rxq {
	t4_sge_iq_t iq;
	struct sge_fl fl;	/* Freelist for packet receive buffers */

	struct port_info *port;

	mac_ring_handle_t ring_handle;
	uint64_t ring_gen_num;

	kstat_t *ksp;
	struct sge_rxq_stats stats;
};

typedef enum t4_port_flags {
	TPF_INIT_DONE	= (1 << 0),
	TPF_OPEN	= (1 << 1),
	TPF_VI_ENABLED	= (1 << 2),
} t4_port_flags_t;

typedef enum t4_port_feat {
	CXGBE_HW_LSO	= (1 << 0),
	CXGBE_HW_CSUM	= (1 << 1),
} t4_port_feat_t;


struct port_info {
	kmutex_t	lock;
	dev_info_t	*dip;
	struct adapter	*adapter;
	uint8_t		port_id;

	t4_port_flags_t	flags;
	t4_port_feat_t	features;

	mac_handle_t	mh;
	int		mtu;
	uint8_t		hw_addr[ETHERADDRL];
	int16_t 	xact_addr_filt; /* index of exact MAC address filter */

	uint16_t	rxq_count;	/* # of RX queues */
	uint16_t	rxq_start;	/* index of first RX queue */
	uint16_t	txq_count;	/* # of TX queues */
	uint16_t	txq_start;	/* index of first TX queue */

	/*
	 * Array of IQs for queue events, such as interrupt forward events
	 * for Rx queue processing and completion events for Tx queues.
	 * Only available when TIP_PER_PORT is selected. The size is based
	 * on adapter.intr_queue_cfg.intr_per_port.
	 */
	t4_sge_iq_t	*intr_iqs;

	kstat_t *ksp_config;
	kstat_t *ksp_info;
	kstat_t *ksp_fec;

	/* Port attributes/data set by common code: */
	uint16_t	viid;
	uint16_t	rss_size;	/* size of VI's RSS table slice */

	uint8_t		port_type;
	int8_t		mdio_addr;
	uint8_t		mod_type;

	uint8_t		lport;
	uint8_t		tx_chan;
	uint8_t		rx_chan;
	uint8_t		rx_cchan;

	uint8_t		rss_mode;

	uint8_t		tmr_idx;
	int8_t		pktc_idx;
	uint8_t		dbq_timer_idx;

	struct link_config link_cfg;
	uint8_t		macaddr_cnt;

	u8 vivld;
	u8 vin;
	u8 smt_idx;

	/* Mirroring bits utilized by common code (unused by our driver) */
	u16 viid_mirror;
	u8 vivld_mirror;
	u8 vin_mirror;
};

struct sge_info {
	uint_t fl_starve_threshold;
	uint64_t dbq_timer_tick;
	uint16_t dbq_timers[SGE_NDBQTIMERS];

	uint_t eq_spg_len;	/* EQ status page length in host credits */
	uint_t pktshift;	/* padding between CPL & packet data */
	uint_t fl_align;	/* response queue message alignment */
	uint8_t fwq_tmr_idx;	/* Intr. coalesce timer for FWQ */
	int8_t fwq_pktc_idx;	/* Intr. coalesce count for FWQ */

	t4_sge_iq_t fwq;	/* Firmware event queue */

	uint_t rxq_count;	/* total RX queues (all ports and the rest) */
	uint_t txq_count;	/* total TX queues (all ports and the rest) */
	struct sge_txq *txq;	/* NIC TX queues */
	struct sge_rxq *rxq;	/* NIC RX queues */

	/*
	 * Adapters uses 16-bit "context IDs" to uniquely identify queues.
	 *
	 * References to the queues, indexed by said context IDs are maintained
	 * here, using the start/end values queried from the adapter.
	 */
	uint_t iqmap_start;	/* IQ context id map start index */
	uint_t rxqmap_start;	/* IQ context id map start index */
	uint_t eqmap_start;	/* EQ context id map start index */
	uint_t iqmap_sz;	/* size of IQ context id map */
	uint_t eqmap_sz;	/* size of EQ context id map */
	t4_sge_iq_t **iqmap;	/* iq->cntxt_id to IQ mapping */
	t4_sge_eq_t **eqmap;	/* eq->cntxt_id to EQ mapping */

	/* Device access and DMA attributes for all the descriptor rings */
	ddi_device_acc_attr_t acc_attr_desc;
	ddi_dma_attr_t	dma_attr_desc;

	/* Device access and DMA attributes for TX buffers */
	ddi_device_acc_attr_t acc_attr_tx;
	ddi_dma_attr_t	dma_attr_tx;

	/* Device access and DMA attributes for RX buffers are in rxb_params */
	kmem_cache_t *rxbuf_cache;
	struct rxbuf_cache_params rxb_params;
};

struct driver_properties {
	uint8_t ethq_tmr_idx;
	int8_t ethq_pktc_idx;
	uint8_t dbq_timer_idx;
	uint8_t fwq_tmr_idx;
	int8_t fwq_pktc_idx;
	uint16_t qsize_txq;
	uint16_t qsize_rxq;

	uint_t holdoff_timer_us[SGE_NTIMERS];
	uint_t holdoff_pktcnt[SGE_NCOUNTERS];

	bool write_combine;
	int t4_fw_install;
};

typedef struct t4_mbox_waiter {
	list_node_t node;
	kthread_t *thread;
} t4_mbox_waiter_t;

typedef enum t4_adapter_flags {
	/* Initialization progress status bits */
	TAF_INIT_DONE	= (1 << 0),
	TAF_FW_OK	= (1 << 1),
	TAF_INTR_ALLOC	= (1 << 2),

	/* State & capability bits */
	TAF_MASTER_PF	= (1 << 8),
	TAF_DBQ_TIMER	= (1 << 9),
} t4_adapter_flags_t;

/* Plan for interrupt allocation */
typedef enum t4_intr_plan {
	/* Everything on a single interrupt */
	TIP_SINGLE,
	/* One for device errors, one FWQ (including forwarded intrs) */
	TIP_ERR_QUEUES,
	/* 1 + 1 for errors and FWQ, with rest divided evenly between ports */
	TIP_PER_PORT,
} t4_intr_plan_t;

struct t4_intrs_queues {
	/* The DDI_INTR_TYPE_* value negotiated. */
	int intr_type;

	/*
	 * The plan for interrupt allocation, based on the interrupt type
	 * and number of interrupts available. See the block comment in
	 * t4_nexus.c for more information.
	 */
	t4_intr_plan_t intr_plan;

	/*
	 * The number of interrupts available (intr_avail) for use vs. the
	 * number of interrupts the driver has decided to make use of
	 * (intr_count). These values may be different depending on the
	 * number available and the port count of the attached part.
	 */
	int intr_avail;
	int intr_count;

	/*
	 * The number of interrupts per port for use with event queues.
	 * These interrupts are used to take delivery of Tx recycling
	 * messages and Rx packet delivery.
	 */
	uint_t intr_per_port;

	/*
	 * Track the number of IQs allocated for use with interrupts. We track
	 * this to know how many IQs we have leftover for Rx queue usage.
	 */
	uint_t num_iqs;

	/* The maximum number of RX/TX queues per port. */
	uint_t port_max_rxq;
	uint_t port_max_txq;
};

/*
 * WO - Write Once at initialization time.
 */
struct adapter {
	list_node_t node;
	dev_info_t *dip;
	dev_t dev;

	unsigned int pf;
	unsigned int mbox;

	unsigned int vpd_busy;
	unsigned int vpd_flag;

	u32 t4_bar0;

	uint_t open;	/* character device is open */

	/* PCI config space access handle */
	ddi_acc_handle_t pci_regh;

	/* MMIO register access handle */
	ddi_acc_handle_t regh;
	caddr_t regp;
	/* BAR2 register access handle */
	ddi_acc_handle_t bar2_hdl;
	caddr_t bar2_ptr;

	/* Interrupt information */
	ddi_intr_handle_t *intr_handle;
	int intr_cap;
	uint_t intr_pri;

	struct driver_properties props;
	kstat_t *ksp;
	kstat_t *ksp_stat;

	struct sge_info sge;

	struct port_info *port[MAX_NPORTS];
	uint8_t chan_map[NCHAN];
	uint32_t filter_mode;

	t4_adapter_flags_t flags;
	t4_doorbells_t doorbells;

	unsigned int cfcsum;
	struct adapter_params params;
	struct t4_intrs_queues intr_queue_cfg;

	kmutex_t lock;
	kcondvar_t cv;

	/*
	 * Starving freelist state
	 *
	 * sfl_lock protects the `sfl_flags` and `sfl_node` fields in all sge_fl
	 * structs owned by this adapter.
	 */
	kmutex_t sfl_lock;
	list_t sfl_list;
	timeout_id_t sfl_timer;

	/* Sensors */
	id_t temp_sensor;
	id_t volt_sensor;

	ddi_ufm_handle_t *ufm_hdl;

	/* support for single-threading access to adapter mailbox registers */
	kmutex_t mbox_lock;
	kcondvar_t mbox_cv;
	list_t mbox_list;
};

#define	ADAPTER_LOCK(sc)		mutex_enter(&(sc)->lock)
#define	ADAPTER_UNLOCK(sc)		mutex_exit(&(sc)->lock)
#define	ADAPTER_LOCK_ASSERT_OWNED(sc)	ASSERT(mutex_owned(&(sc)->lock))
#define	ADAPTER_LOCK_ASSERT_NOTOWNED(sc) ASSERT(!mutex_owned(&(sc)->lock))

#define	PORT_LOCK(pi)			mutex_enter(&(pi)->lock)
#define	PORT_UNLOCK(pi)			mutex_exit(&(pi)->lock)
#define	PORT_LOCK_ASSERT_OWNED(pi)	ASSERT(mutex_owned(&(pi)->lock))
#define	PORT_LOCK_ASSERT_NOTOWNED(pi)	ASSERT(!mutex_owned(&(pi)->lock))

#define	IQ_LOCK(iq)			mutex_enter(&(iq)->tsi_lock)
#define	IQ_UNLOCK(iq)			mutex_exit(&(iq)->tsi_lock)
#define	IQ_LOCK_ASSERT_OWNED(iq)	ASSERT(mutex_owned(&(iq)->tsi_lock))
#define	IQ_LOCK_ASSERT_NOTOWNED(iq)	ASSERT(!mutex_owned(&(iq)->tsi_lock))

#define	EQ_LOCK(eq)			mutex_enter(&(eq)->tse_lock)
#define	EQ_UNLOCK(eq)			mutex_exit(&(eq)->tse_lock)
#define	EQ_LOCK_ASSERT_OWNED(eq)	ASSERT(mutex_owned(&(eq)->tse_lock))
#define	EQ_LOCK_ASSERT_NOTOWNED(eq)	ASSERT(!mutex_owned(&(eq)->tse_lock))

/* Freelist state is protected by its EQ lock */
#define	FL_LOCK(fl)			EQ_LOCK(&(fl)->eq)
#define	FL_UNLOCK(fl)			EQ_UNLOCK(&(fl)->eq)
#define	FL_LOCK_ASSERT_OWNED(fl)	EQ_LOCK_ASSERT_OWNED(&(fl)->eq)
#define	FL_LOCK_ASSERT_NOTOWNED(fl)	EQ_LOCK_ASSERT_NOTOWNED(&(fl)->eq)

#define	TXQ_LOCK(txq)			EQ_LOCK(&(txq)->eq)
#define	TXQ_UNLOCK(txq)			EQ_UNLOCK(&(txq)->eq)
#define	TXQ_LOCK_ASSERT_OWNED(txq)	EQ_LOCK_ASSERT_OWNED(&(txq)->eq)
#define	TXQ_LOCK_ASSERT_NOTOWNED(txq)	EQ_LOCK_ASSERT_NOTOWNED(&(txq)->eq)

#define	for_each_txq(pi, iter, txq) \
	txq = &pi->adapter->sge.txq[pi->txq_start]; \
	for (iter = 0; iter < pi->txq_count; ++iter, ++txq)
#define	for_each_rxq(pi, iter, rxq) \
	rxq = &pi->adapter->sge.rxq[pi->rxq_start]; \
	for (iter = 0; iter < pi->rxq_count; ++iter, ++rxq)

static inline struct port_info *
adap2pinfo(struct adapter *sc, int idx)
{
	return (sc->port[idx]);
}

static inline unsigned int t4_use_ldst(struct adapter *adap)
{
	return (adap->flags & TAF_FW_OK);
}

static inline void t4_db_full(struct adapter *adap) {}
static inline void t4_db_dropped(struct adapter *adap) {}

/* Is chip version equal to specified value? */
static inline bool
t4_cver_eq(const adapter_t *adap, uint8_t ver)
{
	return (CHELSIO_CHIP_VERSION(adap->params.chip) == ver);
}

/* Is chip version greater than or equal to specified value? */
static inline bool
t4_cver_ge(const adapter_t *adap, uint8_t ver)
{
	return (CHELSIO_CHIP_VERSION(adap->params.chip) >= ver);
}

/* t4_nexus.c */
int t4_port_full_init(struct port_info *);

uint32_t t4_read_reg(struct adapter *, uint32_t);
void t4_write_reg(struct adapter *, uint32_t, uint32_t);
uint64_t t4_read_reg64(struct adapter *, uint32_t);
void t4_write_reg64(struct adapter *, uint32_t, uint64_t);

void t4_mbox_waiter_add(struct adapter *, t4_mbox_waiter_t *);
void t4_mbox_waiter_remove(struct adapter *, t4_mbox_waiter_t *);
bool t4_mbox_wait_owner(struct adapter *, uint_t, bool);

/* t4_debug.c */
void t4_debug_init(void);
void t4_debug_fini(void);

/* t4_sge.c */
void t4_sge_init(struct adapter *);
int t4_alloc_evt_iqs(struct adapter *);
void t4_free_evt_iqs(struct adapter *);
void t4_port_kstats_init(struct port_info *);
void t4_port_kstats_fini(struct port_info *);
int t4_port_queues_init(struct port_info *);
void t4_port_queues_fini(struct port_info *);
void t4_port_queues_enable(struct port_info *pi);
void t4_port_queues_disable(struct port_info *pi);
uint_t t4_intr_all(caddr_t, caddr_t);
uint_t t4_intr_err(caddr_t, caddr_t);
uint_t t4_intr_fwq(caddr_t, caddr_t);
uint_t t4_intr_port_queue(caddr_t, caddr_t);
void t4_iq_gts_update(t4_sge_iq_t *, t4_gts_config_t, uint16_t);
void t4_iq_update_intr_cfg(t4_sge_iq_t *, uint8_t, int8_t);
void t4_eq_update_dbq_timer(t4_sge_eq_t *, struct port_info *);

mblk_t *t4_eth_tx(void *, mblk_t *);
t4_iq_result_t t4_process_rx_iq(t4_sge_iq_t *, uint_t, struct t4_poll_req *);

/* t4_mac.c */
void t4_os_link_changed(struct adapter *sc, int idx, int link_stat);
void t4_mac_tx_update(struct port_info *pi, struct sge_txq *txq);
int t4_addmac(void *arg, const uint8_t *ucaddr);
const char **t4_get_priv_props(struct port_info *, size_t *);
uint8_t t4_choose_holdoff_timer(struct adapter *, uint_t);
int8_t t4_choose_holdoff_pktcnt(struct adapter *, int);
uint_t t4_choose_dbq_timer(struct adapter *, uint_t);
extern mac_callbacks_t t4_mac_callbacks;

/* t4_ioctl.c */
int t4_ioctl(struct adapter *sc, int cmd, void *data, int mode);

#endif /* __CXGBE_ADAPTER_H */
