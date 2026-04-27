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
 * Copyright (C) 2010-2013 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

/*
 * Copyright 2025 Oxide Computer Company
 */

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/atomic.h>
#include <sys/dlpi.h>
#include <sys/pattr.h>
#include <sys/strsubr.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <inet/ip.h>
#include <inet/tcp.h>

#include "common/common.h"
#include "common/t4_msg.h"
#include "common/t4_regs.h"
#include "common/t4_regs_values.h"

/* TODO: Tune. */
int rx_buf_size = 8192;
int tx_copy_threshold = 256;
uint16_t rx_copy_threshold = 256;

/* Used to track coalesced tx work request */
struct txpkts {
	mblk_t *tail;		/* head is in the software descriptor */
	uint64_t *flitp;	/* ptr to flit where next pkt should start */
	uint8_t npkt;		/* # of packets in this work request */
	uint8_t nflits;		/* # of flits used by this work request */
	uint16_t plen;		/* total payload (sum of all packets) */
};

/* All information needed to tx a frame */
struct txinfo {
	uint32_t len;		/* Total length of frame */
	uint32_t flags;		/* Checksum and LSO flags */
	uint32_t mss;		/* MSS for LSO */
	uint8_t nsegs;		/* # of segments in the SGL, 0 means imm. tx */
	uint8_t nflits;		/* # of flits needed for the SGL */
	uint8_t hdls_used;	/* # of DMA handles used */
	uint32_t txb_used;	/* txb_space used */
	mac_ether_offload_info_t meoi;	/* pkt hdr info for offloads */
	struct ulptx_sgl sgl __attribute__((aligned(8)));
	struct ulptx_sge_pair reserved[TX_SGL_SEGS / 2];
};

struct rxbuf {
	kmem_cache_t *cache;		/* the kmem_cache this rxb came from */
	ddi_dma_handle_t dhdl;
	ddi_acc_handle_t ahdl;
	caddr_t va;			/* KVA of buffer */
	uint64_t ba;			/* bus address of buffer */
	frtn_t freefunc;
	uint_t buf_size;
	volatile uint_t ref_cnt;
};

static const uint16_t t4_iq_esize_bytes[] = {
	[T4_IQ_ESIZE_16B] = 16,
	[T4_IQ_ESIZE_32B] = 32,
	[T4_IQ_ESIZE_64B] = 64,
	[T4_IQ_ESIZE_128B] = 128,
};

typedef struct t4_iq_params {
	t4_iq_type_t	tip_iq_type;
	uint8_t		tip_tmr_idx;
	int8_t		tip_pktc_idx;
	uint16_t	tip_qsize;
	t4_iq_esize_t	tip_esize;
	uint16_t	tip_fl_qsize;
	int		tip_cong_chan;
	t4_sge_iq_t	*tip_intr_evtq;
	uint_t		tip_intr_idx;
} t4_iq_params_t;

static int t4_alloc_eq_base(struct port_info *, t4_sge_eq_t *);
static void t4_free_iq(struct port_info *, t4_sge_iq_t *);
static int t4_alloc_rxq(struct port_info *, struct sge_rxq *, uint_t);
static void t4_free_rxq(struct port_info *, struct sge_rxq *);
static void t4_free_eq(struct port_info *, t4_sge_eq_t *);
static void t4_alloc_eq_post(struct port_info *, t4_sge_eq_t *);
static int t4_alloc_txq(struct port_info *, struct sge_txq *, int);
static void t4_free_txq(struct port_info *, struct sge_txq *);
static int alloc_dma_memory(struct adapter *sc, size_t len, int flags,
    ddi_device_acc_attr_t *acc_attr, ddi_dma_attr_t *dma_attr,
    ddi_dma_handle_t *dma_hdl, ddi_acc_handle_t *acc_hdl, uint64_t *pba,
    caddr_t *pva);
static int free_dma_memory(ddi_dma_handle_t *dhdl, ddi_acc_handle_t *ahdl);
static int alloc_desc_ring(struct adapter *sc, size_t len, int rw,
    ddi_dma_handle_t *dma_hdl, ddi_acc_handle_t *acc_hdl, uint64_t *pba,
    caddr_t *pva);
static int free_desc_ring(ddi_dma_handle_t *dhdl, ddi_acc_handle_t *ahdl);
static int alloc_tx_copybuffer(struct adapter *sc, size_t len,
    ddi_dma_handle_t *dma_hdl, ddi_acc_handle_t *acc_hdl, uint64_t *pba,
    caddr_t *pva);
static inline bool t4_get_new_rsp(const t4_sge_iq_t *, struct rsp_ctrl *);
static inline void t4_iq_next_entry(t4_sge_iq_t *iq);
static t4_iq_result_t t4_process_event_iq(t4_sge_iq_t *event_iq);
static bool t4_fl_refill(struct sge_fl *, uint_t);
static void t4_sfl_enqueue(struct adapter *, struct sge_fl *);
static void t4_sfl_process(void *);
static void t4_fl_free_bufs(struct sge_fl *fl);
static mblk_t *t4_fl_get_payload(struct sge_fl *, uint32_t, bool);
static int get_frame_txinfo(struct sge_txq *txq, mblk_t **fp,
    struct txinfo *txinfo, int sgl_only);
static inline int fits_in_txb(struct sge_txq *txq, int len, int *waste);
static inline int copy_into_txb(struct sge_txq *txq, mblk_t *m, int len,
    struct txinfo *txinfo);
static inline void add_seg(struct txinfo *txinfo, uint64_t ba, uint32_t len);
static inline int add_mblk(struct sge_txq *txq, struct txinfo *txinfo,
    mblk_t *m, int len);
static void free_txinfo_resources(struct sge_txq *txq, struct txinfo *txinfo);
static int add_to_txpkts(struct sge_txq *txq, struct txpkts *txpkts, mblk_t *m,
    struct txinfo *txinfo);
static void write_txpkts_wr(struct sge_txq *txq, struct txpkts *txpkts);
static int write_txpkt_wr(struct port_info *pi, struct sge_txq *txq, mblk_t *m,
    struct txinfo *txinfo);
static void t4_write_flush_wr(struct sge_txq *);
static inline void write_ulp_cpl_sgl(struct port_info *pi, struct sge_txq *txq,
    struct txpkts *txpkts, struct txinfo *txinfo);
static inline void copy_to_txd(t4_sge_eq_t *eq, caddr_t from, caddr_t *to,
    size_t len);
static void t4_tx_ring_db(struct sge_txq *);
static uint16_t t4_tx_reclaim_credits(struct sge_txq *, uint16_t, mblk_t **);
static void t4_fl_ring_db(struct sge_fl *fl);
static kstat_t *setup_port_config_kstats(struct port_info *pi);
static kstat_t *setup_port_info_kstats(struct port_info *pi);
static kstat_t *setup_rxq_kstats(struct port_info *pi, struct sge_rxq *rxq,
    uint_t idx);
static int update_rxq_kstats(kstat_t *ksp, int rw);
static int update_port_info_kstats(kstat_t *ksp, int rw);
static kstat_t *setup_txq_kstats(struct port_info *pi, struct sge_txq *txq,
    int idx);
static int update_txq_kstats(kstat_t *ksp, int rw);
static void t4_sge_egr_update(t4_sge_iq_t *, const struct rss_header *);
static int t4_handle_cpl_msg(t4_sge_iq_t *, const struct rss_header *,
    mblk_t *);
static int t4_handle_fw_msg(t4_sge_iq_t *, const struct rss_header *);

static kmem_cache_t *rxbuf_cache_create(struct rxbuf_cache_params *);
static struct rxbuf *rxbuf_alloc(kmem_cache_t *, int);
static void rxbuf_free(struct rxbuf *);
static int rxbuf_ctor(void *, void *, int);
static void rxbuf_dtor(void *, void *);

static inline void *
t4_rss_payload(const struct rss_header *rss)
{
	return ((void *)(&rss[1]));
}

static inline t4_sge_iq_t **
t4_iqmap_slot(struct adapter *sc, uint_t cntxt_id)
{
	const uint_t idx = cntxt_id - sc->sge.iqmap_start;
	VERIFY3U(idx, <, sc->sge.iqmap_sz);
	return (&sc->sge.iqmap[idx]);
}

static inline t4_sge_eq_t **
t4_eqmap_slot(struct adapter *sc, uint_t cntxt_id)
{
	const uint_t idx = cntxt_id - sc->sge.eqmap_start;
	VERIFY3U(idx, <, sc->sge.eqmap_sz);
	return (&sc->sge.eqmap[idx]);
}

/*
 * Get the address of the EQ host credit at the provided index.
 */
static inline void *
t4_eq_credit(t4_sge_eq_t *eq, uint16_t idx)
{
	ASSERT3U(idx, <, eq->tse_qsize_spg);
	uint8_t *credits = eq->tse_ring;
	return (&credits[idx * EQ_HC_SIZE]);
}

static inline struct sge_rxq *
t4_iq_to_rxq(t4_sge_iq_t *iq)
{
	if (iq->tsi_iqtype == TIQT_ETH_RX) {
		return (__containerof(iq, struct sge_rxq, iq));
	} else {
		return (NULL);
	}
}

static inline t4_sge_iq_t *
t4_fl_to_iq(struct sge_fl *fl)
{
	/*
	 * Currently, RXQs are the only consumer of sge_fl, and are thus the
	 * only case we need to worry about.
	 */
	struct sge_rxq *rxq = __containerof(fl, struct sge_rxq, fl);
	ASSERT(rxq->iq.tsi_iqtype == TIQT_ETH_RX);

	return (&rxq->iq);
}

void
t4_sge_init(struct adapter *sc)
{
	struct driver_properties *p = &sc->props;
	ddi_dma_attr_t *dma_attr;
	ddi_device_acc_attr_t *acc_attr;
	uint32_t sge_control;

	/*
	 * Device access and DMA attributes for descriptor rings
	 */
	acc_attr = &sc->sge.acc_attr_desc;
	acc_attr->devacc_attr_version = DDI_DEVICE_ATTR_V0;
	acc_attr->devacc_attr_endian_flags = DDI_NEVERSWAP_ACC;
	acc_attr->devacc_attr_dataorder = DDI_STRICTORDER_ACC;

	dma_attr = &sc->sge.dma_attr_desc;
	dma_attr->dma_attr_version = DMA_ATTR_V0;
	dma_attr->dma_attr_addr_lo = 0;
	dma_attr->dma_attr_addr_hi = UINT64_MAX;
	dma_attr->dma_attr_count_max = UINT64_MAX;
	dma_attr->dma_attr_align = 512;
	dma_attr->dma_attr_burstsizes = 0xfff;
	dma_attr->dma_attr_minxfer = 1;
	dma_attr->dma_attr_maxxfer = UINT64_MAX;
	dma_attr->dma_attr_seg = UINT64_MAX;
	dma_attr->dma_attr_sgllen = 1;
	dma_attr->dma_attr_granular = 1;
	dma_attr->dma_attr_flags = 0;

	/*
	 * Device access and DMA attributes for tx buffers
	 */
	acc_attr = &sc->sge.acc_attr_tx;
	acc_attr->devacc_attr_version = DDI_DEVICE_ATTR_V0;
	acc_attr->devacc_attr_endian_flags = DDI_NEVERSWAP_ACC;

	dma_attr = &sc->sge.dma_attr_tx;
	dma_attr->dma_attr_version = DMA_ATTR_V0;
	dma_attr->dma_attr_addr_lo = 0;
	dma_attr->dma_attr_addr_hi = UINT64_MAX;
	dma_attr->dma_attr_count_max = UINT64_MAX;
	dma_attr->dma_attr_align = 1;
	dma_attr->dma_attr_burstsizes = 0xfff;
	dma_attr->dma_attr_minxfer = 1;
	dma_attr->dma_attr_maxxfer = UINT64_MAX;
	dma_attr->dma_attr_seg = UINT64_MAX;
	dma_attr->dma_attr_sgllen = TX_SGL_SEGS;
	dma_attr->dma_attr_granular = 1;
	dma_attr->dma_attr_flags = 0;

	/*
	 * Ingress Padding Boundary and Egress Status Page Size are set up by
	 * t4_fixup_host_params().
	 */
	sge_control = t4_read_reg(sc, A_SGE_CONTROL);
	sc->sge.pktshift = G_PKTSHIFT(sge_control);
	sc->sge.eq_spg_len = (sge_control & F_EGRSTATUSPAGESIZE) ? 2 : 1;

	/* t4_nex uses FLM packed mode */
	const int fl_align = t4_fl_pkt_align(sc, true);
	VERIFY3S(fl_align, >=, 0);
	/*
	 * Minimum alignment for freelist buffer sizes is stated as 16, but in
	 * order to keep bits [3:0] clear for identifying the buffer size
	 * register, we use a minimum of 32.
	 *
	 * See A_SGE_FL_BUFFER_SIZE0 setting below.
	 */
	sc->sge.fl_align = MAX(fl_align, 32);

	/*
	 * Device access and DMA attributes for RX buffers
	 */
	sc->sge.rxb_params.dip = sc->dip;
	sc->sge.rxb_params.buf_size = P2ROUNDUP(rx_buf_size, fl_align);

	acc_attr = &sc->sge.rxb_params.acc_attr_rx;
	acc_attr->devacc_attr_version = DDI_DEVICE_ATTR_V0;
	acc_attr->devacc_attr_endian_flags = DDI_NEVERSWAP_ACC;

	dma_attr = &sc->sge.rxb_params.dma_attr_rx;
	dma_attr->dma_attr_version = DMA_ATTR_V0;
	dma_attr->dma_attr_addr_lo = 0;
	dma_attr->dma_attr_addr_hi = UINT64_MAX;
	dma_attr->dma_attr_count_max = UINT64_MAX;
	dma_attr->dma_attr_align = sc->sge.fl_align;
	dma_attr->dma_attr_burstsizes = 0xfff;
	dma_attr->dma_attr_minxfer = 1;
	dma_attr->dma_attr_maxxfer = UINT64_MAX;
	dma_attr->dma_attr_seg = UINT64_MAX;
	dma_attr->dma_attr_sgllen = 1;
	dma_attr->dma_attr_granular = 1;
	dma_attr->dma_attr_flags = 0;

	sc->sge.rxbuf_cache = rxbuf_cache_create(&sc->sge.rxb_params);

	/*
	 * A FL with <= fl_starve_threshold buffers is starving and a periodic
	 * timer will attempt to refill it.  This needs to be larger than the
	 * SGE's Egress Congestion Threshold.  If it isn't, then we can get
	 * stuck waiting for new packets while the SGE is waiting for us to
	 * give it more Free List entries.  (Note that the SGE's Egress
	 * Congestion Threshold is in units of 2 Free List pointers.) For T4,
	 * there was only a single field to control this.  For T5 there's the
	 * original field which now only applies to Unpacked Mode Free List
	 * buffers and a new field which only applies to Packed Mode Free List
	 * buffers.
	 */

	const uint32_t sge_conm_ctrl = t4_read_reg(sc, A_SGE_CONM_CTRL);
	uint_t egress_threshold;
	switch (CHELSIO_CHIP_VERSION(sc->params.chip)) {
	case CHELSIO_T4:
		egress_threshold = G_EGRTHRESHOLD(sge_conm_ctrl);
		break;
	case CHELSIO_T5:
		egress_threshold = G_EGRTHRESHOLDPACKING(sge_conm_ctrl);
		break;
	case CHELSIO_T6:
	default:
		egress_threshold = G_T6_EGRTHRESHOLDPACKING(sge_conm_ctrl);
	}
	sc->sge.fl_starve_threshold = 2 * egress_threshold + 1;

	/*
	 * Set the size of buffers submitted through freelists.
	 *
	 * Strictly speaking, this is setting one of sixteen possible buffer
	 * sizes, with bits [3:0] of freelist entries designating the size
	 * register (0-15) which contains its corresponding size.
	 *
	 * Our driver does not currently make use of multiple sizes.  Submitted
	 * buffers are at least 16-byte aligned, thus bits [3:0] are 0,
	 * selecting this size register.
	 */
	t4_write_reg(sc, A_SGE_FL_BUFFER_SIZE0, sc->sge.rxb_params.buf_size);

	t4_write_reg(sc, A_SGE_INGRESS_RX_THRESHOLD,
	    V_THRESHOLD_0(p->holdoff_pktcnt[0]) |
	    V_THRESHOLD_1(p->holdoff_pktcnt[1]) |
	    V_THRESHOLD_2(p->holdoff_pktcnt[2]) |
	    V_THRESHOLD_3(p->holdoff_pktcnt[3]));

	t4_write_reg(sc, A_SGE_TIMER_VALUE_0_AND_1,
	    V_TIMERVALUE0(us_to_core_ticks(sc, p->holdoff_timer_us[0])) |
	    V_TIMERVALUE1(us_to_core_ticks(sc, p->holdoff_timer_us[1])));
	t4_write_reg(sc, A_SGE_TIMER_VALUE_2_AND_3,
	    V_TIMERVALUE2(us_to_core_ticks(sc, p->holdoff_timer_us[2])) |
	    V_TIMERVALUE3(us_to_core_ticks(sc, p->holdoff_timer_us[3])));
	t4_write_reg(sc, A_SGE_TIMER_VALUE_4_AND_5,
	    V_TIMERVALUE4(us_to_core_ticks(sc, p->holdoff_timer_us[4])) |
	    V_TIMERVALUE5(us_to_core_ticks(sc, p->holdoff_timer_us[5])));
}

static uint_t
t4_queue_to_intrq(struct adapter *sc, uint_t q_idx)
{
	return (q_idx % sc->intr_queue_cfg.intr_per_port);
}

/*
 * Assign an interrupt event queue to the Rx queue specified by q_idx. If
 * we are in TIP_PER_PORT mode, this is done by multiplexing the Rx queues
 * across the port's interrupt queues. Otherwise, all events are directed
 * to the adapter-wide firmware queue.
 */
static void
t4_rxq_intr_assign(struct port_info *pi, uint_t rxq_idx,
    struct t4_iq_params *iqp)
{
	struct adapter *sc = pi->adapter;
	const struct t4_intrs_queues *iqc = &sc->intr_queue_cfg;

	switch (iqc->intr_plan) {
	case TIP_PER_PORT: {
		uint_t intr_iq_idx = t4_queue_to_intrq(sc, rxq_idx);
		iqp->tip_intr_evtq = &pi->intr_iqs[intr_iq_idx];
		iqp->tip_intr_idx = INTR_FORWARDED;
		break;
	}
	case TIP_SINGLE:
	case TIP_ERR_QUEUES:
	default:
		/* Forward all RXQ interrupts to FWQ */
		iqp->tip_intr_evtq = &sc->sge.fwq;
		iqp->tip_intr_idx = INTR_FORWARDED;
		break;
	}
}

void
t4_port_kstats_init(struct port_info *pi)
{
	ASSERT(pi->ksp_config == NULL);
	ASSERT(pi->ksp_info == NULL);

	pi->ksp_config = setup_port_config_kstats(pi);
	pi->ksp_info = setup_port_info_kstats(pi);
}

void
t4_port_kstats_fini(struct port_info *pi)
{
	if (pi->ksp_config != NULL) {
		kstat_delete(pi->ksp_config);
		pi->ksp_config = NULL;
	}
	if (pi->ksp_info != NULL) {
		kstat_delete(pi->ksp_info);
		pi->ksp_info = NULL;
	}
}

int
t4_port_queues_init(struct port_info *pi)
{
	int rc = 0;
	uint_t q_idx;
	struct adapter *sc = pi->adapter;

	struct sge_rxq *rxq;
	for_each_rxq(pi, q_idx, rxq) {
		if ((rc = t4_alloc_rxq(pi, rxq, q_idx)) != 0) {
			goto cleanup;
		}
	}

	struct sge_txq *txq;
	for_each_txq(pi, q_idx, txq) {
		txq->eq.tse_flags = 0;
		txq->eq.tse_tx_chan = pi->tx_chan;
		txq->eq.tse_qsize = sc->props.qsize_txq;

		if (sc->intr_queue_cfg.intr_plan == TIP_PER_PORT) {
			/*
			 * If we have per port interrupts, then multiplex
			 * TX completion events across them.
			 */
			uint_t intr_iq_idx = t4_queue_to_intrq(sc, q_idx);
			txq->eq.tse_iqid =
			    pi->intr_iqs[intr_iq_idx].tsi_cntxt_id;
		} else {
			/*
			 * Otherwise, handle all TX completion events in
			 * the firmware queue.
			 */
			txq->eq.tse_iqid = sc->sge.fwq.tsi_cntxt_id;
		}

		if ((rc = t4_alloc_txq(pi, txq, q_idx)) != 0) {
			goto cleanup;
		}
	}

	return (0);

cleanup:
	t4_port_queues_fini(pi);
	return (rc);
}

void
t4_port_queues_fini(struct port_info *pi)
{
	uint_t i;

	struct sge_txq *txq;
	for_each_txq(pi, i, txq) {
		t4_free_txq(pi, txq);
	}

	struct sge_rxq *rxq;
	for_each_rxq(pi, i, rxq) {
		t4_free_rxq(pi, rxq);
	}
}

void
t4_port_queues_enable(struct port_info *pi)
{
	ASSERT(pi->flags & TPF_INIT_DONE);

	uint_t i;
	struct adapter *sc = pi->adapter;
	struct sge_rxq *rxq;

	mutex_enter(&sc->sfl_lock);
	for_each_rxq(pi, i, rxq) {
		t4_sge_iq_t *iq = &rxq->iq;

		IQ_LOCK(iq);
		VERIFY0(iq->tsi_flags & IQ_ENABLED);
		iq->tsi_flags |= IQ_ENABLED;

		/*
		 * Freelists which were marked "doomed" by a previous
		 * t4_port_queues_disable() call should clear that status.
		 */
		rxq->fl.sfl_flags &= ~SFL_DOOMED;

		t4_iq_gts_update(iq, iq->tsi_gts_rearm, 0);
		IQ_UNLOCK(iq);
	}
	mutex_exit(&sc->sfl_lock);

	struct sge_txq *txq;
	for_each_txq(pi, i, txq) {
		t4_sge_eq_t *eq = &txq->eq;

		EQ_LOCK(eq);
		eq->tse_flags |= EQ_ENABLED;
		EQ_UNLOCK(eq);
	}
}

void
t4_port_queues_disable(struct port_info *pi)
{
	uint_t i;
	struct adapter *sc = pi->adapter;
	struct sge_rxq *rxq;

	ASSERT(pi->flags & TPF_INIT_DONE);

	for_each_rxq(pi, i, rxq) {
		t4_sge_iq_t *iq = &rxq->iq;

		IQ_LOCK(iq);
		iq->tsi_flags &= ~IQ_ENABLED;
		IQ_UNLOCK(iq);
	}

	mutex_enter(&sc->sfl_lock);
	for_each_rxq(pi, i, rxq) {
		rxq->fl.sfl_flags |= SFL_DOOMED;
	}
	mutex_exit(&sc->sfl_lock);
	/* TODO: need to wait for all fl's to be removed from sc->sfl */

	struct sge_txq *txq;
	for_each_txq(pi, i, txq) {
		t4_sge_eq_t *eq = &txq->eq;

		EQ_LOCK(eq);
		eq->tse_flags &= ~EQ_ENABLED;
		EQ_UNLOCK(eq);
	}
	/*
	 * TODO: issue flush WR to EQs and wait for EGR update to ensure that
	 * all processing has completed.
	 */
}

/*
 * We are counting on the values of t4_gts_config_t matching the register
 * definitions from the shared code.
 */
CTASSERT(TGC_SE_INTR_ARM == F_QINTR_CNT_EN);
CTASSERT(TGC_TIMER0 == V_QINTR_TIMER_IDX(X_TIMERREG_COUNTER0));
CTASSERT(TGC_TIMER5 == V_QINTR_TIMER_IDX(X_TIMERREG_COUNTER5));
CTASSERT(TGC_START_COUNTER == V_QINTR_TIMER_IDX(X_TIMERREG_RESTART_COUNTER));

void
t4_iq_update_intr_cfg(t4_sge_iq_t *iq, uint8_t tmr_idx, int8_t pktc_idx)
{
	ASSERT((pktc_idx >= 0 && pktc_idx < SGE_NCOUNTERS) || pktc_idx == -1);
	IQ_LOCK_ASSERT_OWNED(iq);
	/*
	 * Strictly speaking, the IQ could be programmed with a TimerReg value
	 * of 6 (TICK_START_COUNTER), which is outside the range of SGE_NTIMERS.
	 *
	 * Since we do not currently offer an interface to configure such
	 * behavior, we assert its absence here for now.
	 */
	ASSERT3U(tmr_idx, <, SGE_NTIMERS);

	iq->tsi_gts_rearm = V_QINTR_TIMER_IDX(tmr_idx) |
	    ((pktc_idx != -1) ? TGC_SE_INTR_ARM : 0);

	/* Update IQ for new packet count threshold, but only if enabled */
	if (pktc_idx != iq->tsi_intr_pktc_idx && pktc_idx >= 0) {
		const uint32_t param = V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_DMAQ) |
		    V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_DMAQ_IQ_INTCNTTHRESH) |
		    V_FW_PARAMS_PARAM_YZ(iq->tsi_cntxt_id);
		const uint32_t val = pktc_idx;

		struct adapter *sc = iq->tsi_adapter;
		int rc =
		    -t4_set_params(sc, sc->mbox, sc->pf, 0, 1, &param, &val);
		if (rc != 0) {
			/* report error but carry on */
			cxgb_printf(sc->dip, CE_WARN,
			    "failed to set intr pktcnt index for IQ %d: %d",
			    iq->tsi_cntxt_id, rc);
		}
	}
	iq->tsi_intr_pktc_idx = pktc_idx;
}

void
t4_eq_update_dbq_timer(t4_sge_eq_t *eq, struct port_info *pi)
{
	struct adapter *sc = pi->adapter;

	const uint32_t param = V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_DMAQ) |
	    V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_DMAQ_EQ_TIMERIX) |
	    V_FW_PARAMS_PARAM_YZ(eq->tse_cntxt_id);
	const uint32_t val = pi->dbq_timer_idx;

	int rc = -t4_set_params(sc, sc->mbox, sc->pf, 0, 1, &param, &val);
	if (rc != 0) {
		/* report error but carry on */
		cxgb_printf(sc->dip, CE_WARN,
		    "failed to set DBQ timer index for EQ %d: %d",
		    eq->tse_cntxt_id, rc);
	}
}

/*
 * Update (via GTS) the interrupt/timer config and CIDX value for a specified
 * ingress queue.
 */
void
t4_iq_gts_update(t4_sge_iq_t *iq, t4_gts_config_t cfg, uint16_t cidx_incr)
{
	const uint32_t value =
	    V_INGRESSQID((uint32_t)iq->tsi_cntxt_id) |
	    V_CIDXINC((uint32_t)cidx_incr) |
	    V_SEINTARM((uint32_t)cfg);
	t4_write_reg(iq->tsi_adapter, MYPF_REG(A_SGE_PF_GTS), value);
}

/*
 * Update (via GTS) the CIDX value for a specified ingress queue.
 *
 * This _only_ increments CIDX and does not alter any other timer related state
 * associated with the IQ.
 */
static void
t4_iq_gts_incr(t4_sge_iq_t *iq, uint16_t cidx_incr)
{
	if (cidx_incr == 0) {
		return;
	}

	const uint32_t value =
	    V_INGRESSQID((uint32_t)iq->tsi_cntxt_id) |
	    V_CIDXINC((uint32_t)cidx_incr) |
	    V_SEINTARM((uint32_t)V_QINTR_TIMER_IDX(X_TIMERREG_UPDATE_CIDX));
	t4_write_reg(iq->tsi_adapter, MYPF_REG(A_SGE_PF_GTS), value);
}

uint_t
t4_intr_all(caddr_t arg1, caddr_t arg2)
{
	struct adapter *sc = (struct adapter *)arg1;

	/* handle any device errors */
	t4_write_reg(sc, MYPF_REG(A_PCIE_PF_CLI), 0);
	(void) t4_slow_intr_handler(sc);

	/* process fwq */
	(void) t4_process_event_iq(&sc->sge.fwq);

	return (DDI_INTR_CLAIMED);
}

uint_t
t4_intr_err(caddr_t arg1, caddr_t arg2)
{
	struct adapter *sc = (struct adapter *)arg1;

	/* handle any device errors */
	t4_write_reg(sc, MYPF_REG(A_PCIE_PF_CLI), 0);
	(void) t4_slow_intr_handler(sc);

	return (DDI_INTR_CLAIMED);
}

uint_t
t4_intr_fwq(caddr_t arg1, caddr_t arg2)
{
	struct adapter *sc = (struct adapter *)arg1;

	(void) t4_process_event_iq(&sc->sge.fwq);

	return (DDI_INTR_CLAIMED);
}

uint_t
t4_intr_port_queue(caddr_t arg1, caddr_t arg2)
{
	t4_sge_iq_t *iq = (t4_sge_iq_t *)arg1;

	(void) t4_process_event_iq(iq);

	return (DDI_INTR_CLAIMED);
}

static bool
t4_fl_periodic_refill(struct sge_fl *fl)
{
	FL_LOCK(fl);
	const bool starved = t4_fl_refill(fl, fl->bufs_cap / 8);
	FL_UNLOCK(fl);

	return (starved);
}

/*
 * Convenience struct for tracking entry types while servicing an IQ.
 * Used to communicate said counts through the t4-process-* probes.
 */
struct sge_iq_totals {
	uint_t sit_desc;
	uint_t sit_flbuf;
	uint_t sit_cpl;
	uint_t sit_intr;
	uint_t sit_rx_bytes;
};

/*
 * Process entries on an event Ingress Queue. This type of queue receives
 * firmware events, Tx EGR messages, and Rx forwarded interrupts only. It is
 * used by the firmware queue and the individual port queues.
 */
static t4_iq_result_t
t4_process_event_iq(t4_sge_iq_t *event_iq)
{
	int rc = TIR_SUCCESS;
	struct adapter *sc = event_iq->tsi_adapter;

	const uint_t desc_limit = event_iq->tsi_qsize / 8;
	struct sge_iq_totals totals = { 0 };
	uint_t cidx_incr = 0;
	struct rsp_ctrl ctrl;
	list_t iql_fwd;

	ASSERT3S(event_iq->tsi_iqtype, ==, TIQT_EVENT);
	ASSERT3P(event_iq->tsi_intr_evtq, ==, NULL);

	IQ_LOCK(event_iq);
	if ((event_iq->tsi_flags & IQ_ENABLED) == 0) {
		IQ_UNLOCK(event_iq);
		return (TIR_DISABLED);
	}

	list_create(&iql_fwd, sizeof (t4_sge_iq_t),
	    offsetof(t4_sge_iq_t, tsi_intr_fwd_node));

	while (t4_get_new_rsp(event_iq, &ctrl)) {
		const uint8_t rsp_type = G_RSPD_TYPE(ctrl.u.type_gen);
		const bool overflowed = (ctrl.u.type_gen & F_RSPD_QOVFL) != 0;

		if (overflowed) {
			event_iq->tsi_stats.sis_overflow++;
		}

		const struct rss_header *rss =
		    (const struct rss_header *)event_iq->tsi_cdesc;

		DTRACE_PROBE3(t4__event__iq__entry, t4_sge_iq_t *, event_iq,
		    struct rsp_ctrl *, &ctrl, struct rss_header *, rss);
		ASSERT((rsp_type & (X_RSPD_TYPE_CPL | X_RSPD_TYPE_INTR)) != 0);

		switch (rsp_type) {
		case X_RSPD_TYPE_CPL:
			totals.sit_cpl++;
			(void) t4_handle_cpl_msg(event_iq, rss, NULL);
			break;

		case X_RSPD_TYPE_INTR:
			totals.sit_intr++;
			const uint32_t tgt_qid = BE_32(ctrl.pldbuflen_qid);

			t4_sge_iq_t *tgt_iq = *t4_iqmap_slot(sc, tgt_qid);
			/*
			 * Make sure the forwarded interrupt was sent to the
			 * expected event queue.
			 */
			ASSERT3P(tgt_iq->tsi_intr_evtq, ==, event_iq);

			if (!list_link_active(&tgt_iq->tsi_intr_fwd_node)) {
				list_insert_tail(&iql_fwd, tgt_iq);
			}
			break;

		default:
			cxgb_printf(sc->dip, CE_WARN, "unexpected IQ entry "
			    "type %d on IQ %u of type %d", rsp_type,
			    event_iq->tsi_cntxt_id, event_iq->tsi_iqtype);
			break;
		}

		t4_iq_next_entry(event_iq);
		cidx_incr++;
		totals.sit_desc++;
		event_iq->tsi_stats.sis_processed++;

		if (cidx_incr == desc_limit) {
			rc = TIR_BUDGET_MAX;
			break;
		}
	}

	/*
	 * At this point we may have collected a number of interrupt forwarding
	 * entries for Rx IQs, indicating that they have outstanding data ready
	 * for consumption. We process those now while still in interrupt
	 * context. We remain holding the event IQ's mutex while doing this
	 * work. No additional interrupts should be generated for this event IQ
	 * until after we have finished processing and re-armed the interrupt
	 * via t4_iq_gts_update().
	 *
	 * There is a finite budget for processing each rx queue, and not all
	 * data is guaranteed to be processed as part of this interrupt. Each rx
	 * queue should re-arm its interrupt to trigger a fresh interrupt later
	 * if polling mode has not been enabled.
	 */
	t4_sge_iq_t *rx_iq = NULL;
	while ((rx_iq = list_remove_head(&iql_fwd)) != NULL) {
		(void) t4_process_rx_iq(rx_iq, rx_iq->tsi_qsize / 8, NULL);
	}

	/*
	 * Send an update to the device about the event queue's new cidx and
	 * re-arm its interrupt.
	 */
	ASSERT3U(cidx_incr, >, 0);
	t4_iq_gts_update(event_iq, event_iq->tsi_gts_rearm, cidx_incr);
	IQ_UNLOCK(event_iq);

	DTRACE_PROBE3(t4__event__iq__processed, t4_sge_iq_t *, event_iq,
	    struct sge_iq_totals *, &totals, t4_iq_result_t, rc);
	return (rc);
}

/*
 * Process entries on an Rx Ingress Queue. When called from interrupt context
 * 'desc_budget' should be non-zero and 'tpr' should be NULL. When called from
 * polling context 'desc_budget' should be zero and 'tpr' should be non-NULL.
 */
t4_iq_result_t
t4_process_rx_iq(t4_sge_iq_t *rx_iq, uint_t desc_budget,
    struct t4_poll_req *tpr)
{
	struct adapter *sc = rx_iq->tsi_adapter;
	struct sge_fl *fl = rx_iq->tsi_fl;
	struct sge_rxq *rxq = t4_iq_to_rxq(rx_iq);
	const uint_t byte_limit = (tpr != NULL) ? tpr->tpr_byte_budget : 0;
	mblk_t *mp_head = NULL, **mp_tail = &mp_head;
	struct sge_iq_totals totals = { 0 };
	uint_t cidx_incr = 0;
	struct rsp_ctrl ctrl;
	t4_iq_result_t rc = TIR_SUCCESS;

	ASSERT3S(rx_iq->tsi_iqtype, ==, TIQT_ETH_RX);
	ASSERT3P(rx_iq->tsi_intr_evtq, !=, NULL);
	ASSERT3P(rxq, !=, NULL);
	/* Rx queues require an FL. */
	ASSERT3P(fl, !=, NULL);
	/*
	 * The desc_budget is used only when processing in interrupt context.
	 * The tpr is used only when proessing in polling context.
	 */
	ASSERT(desc_budget == 0 || tpr == NULL);

	IQ_LOCK(rx_iq);
	const bool is_polling = (rx_iq->tsi_flags & IQ_POLLING) != 0;
	if ((rx_iq->tsi_flags & IQ_ENABLED) == 0) {
		IQ_UNLOCK(rx_iq);
		return (TIR_DISABLED);
	} else if (is_polling && tpr == NULL) {
		/*
		 * Skip IQ processing driven from interrupt when port is
		 * configured for polling.
		 */
		IQ_UNLOCK(rx_iq);
		return (TIR_POLLING);
	}

	while (t4_get_new_rsp(rx_iq, &ctrl)) {
		const uint8_t rsp_type = G_RSPD_TYPE(ctrl.u.type_gen);
		const bool overflowed = (ctrl.u.type_gen & F_RSPD_QOVFL) != 0;

		if (overflowed) {
			rx_iq->tsi_stats.sis_overflow++;
		}

		const struct rss_header *rss =
		    (const struct rss_header *)rx_iq->tsi_cdesc;

		DTRACE_PROBE3(t4__rx__iq__entry, t4_sge_iq_t *, rx_iq,
		    struct rsp_ctrl *, &ctrl, struct rss_header *, rss);

		switch (rsp_type) {
		case X_RSPD_TYPE_FLBUF: {
			const uint32_t dlen_nb = BE_32(ctrl.pldbuflen_qid);
			const struct cpl_rx_pkt *cpl = t4_rss_payload(rss);

			if (rss->opcode == CPL_RX_PKT) {
				const uint16_t pkt_len = BE_16(cpl->len);
				const uint_t new_total =
				    totals.sit_rx_bytes + pkt_len;

				if (byte_limit != 0 && new_total > byte_limit) {
					rc = TIR_BUDGET_MAX;
					goto bail;
				}
			}

			const bool newbuf = (dlen_nb & F_RSPD_NEWBUF) != 0;
			const uint32_t data_len = G_RSPD_LEN(dlen_nb);
			mblk_t *mp = t4_fl_get_payload(fl, data_len, newbuf);
			if (mp == NULL) {
				/* Rearm IQ with longer-than-default timer */
				t4_iq_gts_update(rx_iq, TGC_TIMER5, cidx_incr);
				cidx_incr = 0;
				rc = TIR_ALLOC_FAIL;
				goto bail;
			}

			/*
			 * Add this entry to the totals once we are past the
			 * possible bail-outs above.
			 */
			totals.sit_flbuf++;

			if (rss->opcode == CPL_RX_PKT) {
				mp->b_rptr += sc->sge.pktshift;

				uint16_t err_vec;
				if (sc->params.tp.rx_pkt_encap) {
					/* Enabled only in T6 config file */
					err_vec = G_T6_COMPR_RXERR_VEC(
					    ntohs(cpl->err_vec));
				} else {
					err_vec = ntohs(cpl->err_vec);
				}

				const bool csum_ok = cpl->csum_calc && !err_vec;

				if (csum_ok && !cpl->ip_frag) {
					mac_hcksum_set(mp, 0, 0, 0, 0xffff,
					    HCK_FULLCKSUM_OK | HCK_FULLCKSUM |
					    HCK_IPV4_HDRCKSUM_OK);
					rxq->stats.rxcsum++;
				}

				const uint16_t pkt_len = BE_16(cpl->len);
				rxq->stats.rxpkts++;
				rxq->stats.rxbytes += pkt_len;
				totals.sit_rx_bytes += pkt_len;

				*mp_tail = mp;
				mp_tail = &mp->b_next;
			} else {
				(void) t4_handle_cpl_msg(rx_iq, rss, mp);
			}
			break;
		}

		default:
			cxgb_printf(sc->dip, CE_WARN, "unexpected IQ entry "
			    "type %d on IQ %u of type %d", rsp_type,
			    rx_iq->tsi_cntxt_id, rx_iq->tsi_iqtype);
#ifdef DEBUG
			panic("unexpected IQ entry on rx queue");
#endif
			break;
		}

		t4_iq_next_entry(rx_iq);
		cidx_incr++;
		totals.sit_desc++;
		rx_iq->tsi_stats.sis_processed++;

		/*
		 * The desc_budget value is non-zero only when processing in
		 * interrupt context. In this case we honor the desc_limit. In
		 * polling mode we are passed a byte-based budget and disregard
		 * the the desc_limit.
		 */
		if (desc_budget != 0 && cidx_incr == desc_budget) {
			rc = TIR_BUDGET_MAX;
			goto bail;
		}
	}

bail:
	if (tpr != NULL) {
		/*
		 * Do not re-arm interrupts while this IQ is being polled.
		 * Just update the CIDX as necessary.
		 */
		if (cidx_incr != 0) {
			t4_iq_gts_incr(rx_iq, cidx_incr);
		}
	} else {
		/*
		 * Just being extra sure that any future code changes keep this
		 * code path to interrupt processing only.
		 */
		ASSERT3U(desc_budget, >, 0);
		ASSERT3P(tpr, ==, NULL);

		/*
		 * Make sure to re-arm the interrupt for this rx queue.
		 * Remember, the actual interrupt is delivered to the event
		 * queue (rq_iq->tsi_intr_evtq), but the generation of the
		 * forwarded interrupt event requires arming the interrupt on
		 * this rx queue.
		 */
		t4_iq_gts_update(rx_iq, rx_iq->tsi_gts_rearm, cidx_incr);
	}

	/*
	 * Take a snapshot of the ring generation number prior to dropping the
	 * IQ/RXQ lock, in case we need it to pass packets into the mac RX path.
	 */
	const uint64_t ring_gen_num = rxq->ring_gen_num;
	IQ_UNLOCK(rx_iq);

	/*
	 * First we deliver the packets up to mac to give the client a chance to
	 * consume these mblks before the driver attempts to refill them.
	 */
	if (mp_head != NULL) {
		if (tpr != NULL) {
			tpr->tpr_mp = mp_head;
		} else {
			mac_rx_ring(rxq->port->mh, rxq->ring_handle, mp_head,
			    ring_gen_num);
		}
	}

	/*
	 * Next we refill some FL buffers. If the FL is "starving", we enqueue
	 * it on the starving list for further refilling on a background
	 * thread.
	 */
	if (fl != NULL && t4_fl_periodic_refill(fl)) {
		t4_sfl_enqueue(sc, fl);
	}
	DTRACE_PROBE3(t4__rx__iq__processed, t4_sge_iq_t *, rx_iq,
	    struct sge_iq_totals *, &totals, t4_iq_result_t, rc);
	return (rc);
}

/* Per-packet header in a coalesced tx WR, before the SGL starts (in flits) */
#define	TXPKTS_PKT_HDR_FLITS ((\
	sizeof (struct ulp_txpkt) + \
	sizeof (struct ulptx_idata) + \
	sizeof (struct cpl_tx_pkt_core)) / FLIT_NUM_BYTES)

/* Header of a coalesced tx WR, before SGL of first packet (in flits) */
#define	TXPKTS_WR_HDR_FLITS (\
	sizeof (struct fw_eth_tx_pkts_wr) / FLIT_NUM_BYTES + \
	TXPKTS_PKT_HDR_FLITS)

/* Header of a tx WR, before SGL of first packet (in flits) */
#define	TXPKT_WR_HDR_FLITS ((\
	sizeof (struct fw_eth_tx_pkt_wr) + \
	sizeof (struct cpl_tx_pkt_core)) / FLIT_NUM_BYTES)

/* Header of a tx LSO WR, before SGL of first packet (in flits) */
#define	TXPKT_LSO_WR_HDR_FLITS ((\
	sizeof (struct fw_eth_tx_pkt_wr) + \
	sizeof (struct cpl_tx_pkt_lso_core) + \
	sizeof (struct cpl_tx_pkt_core)) / FLIT_NUM_BYTES)

mblk_t *
t4_eth_tx(void *arg, mblk_t *frame)
{
	struct sge_txq *txq = arg;
	struct port_info *pi = txq->port;
	t4_sge_eq_t *eq = &txq->eq;
	mblk_t *next_frame = NULL;
	int coalescing = 0;
	struct txpkts txpkts = {};
	struct txinfo txinfo = {};

	txpkts.npkt = 0; /* indicates there's nothing in txpkts */

	TXQ_LOCK(txq);
	if ((eq->tse_flags & EQ_ENABLED) == 0) {
		/* Apply flow control until EQ is enabled. */
		TXQ_UNLOCK(txq);
		return (frame);
	}

	/* We always strive to send the maximum size WR. */
	if (eq->tse_avail < TX_WR_MAX_CREDITS) {
		(void) t4_tx_reclaim_credits(txq, TX_WR_MAX_CREDITS, NULL);
	}
	for (; frame != NULL; frame = next_frame) {
		int rc = 0;

		if (eq->tse_avail < TX_WR_MAX_CREDITS)
			break;

		next_frame = frame->b_next;
		frame->b_next = NULL;

		if (next_frame != NULL)
			coalescing = 1;

		rc = get_frame_txinfo(txq, &frame, &txinfo, coalescing);
		if (rc != 0) {
			if (rc == ENOMEM) {
				/* Short of resources, suspend tx */
				frame->b_next = next_frame;

				/*
				 * Since we are out of memory for this packet,
				 * rather than TX descriptors, enqueue an
				 * flush work request.  This will ensure that a
				 * completion notification is delivered for this
				 * EQ which will trigger a call to update the
				 * state in mac to continue transmissions.
				 */
				t4_write_flush_wr(txq);
				break;
			}

			/*
			 * Unrecoverable error for this frame, throw it away and
			 * move on to the next.
			 */
			freemsg(frame);
			continue;
		}

		if (coalescing != 0 &&
		    add_to_txpkts(txq, &txpkts, frame, &txinfo) == 0) {
			/* Successfully absorbed into txpkts */
			write_ulp_cpl_sgl(pi, txq, &txpkts, &txinfo);
			goto doorbell;
		}

		/*
		 * We weren't coalescing to begin with, or current frame could
		 * not be coalesced (add_to_txpkts flushes txpkts if a frame
		 * given to it can't be coalesced).  Either way there should be
		 * nothing in txpkts.
		 */
		ASSERT(txpkts.npkt == 0);

		/* We're sending out individual frames now */
		coalescing = 0;

		if (eq->tse_avail < TX_WR_MAX_CREDITS) {
			(void) t4_tx_reclaim_credits(txq, TX_WR_MAX_CREDITS,
			    NULL);
		}

		rc = write_txpkt_wr(pi, txq, frame, &txinfo);
		if (rc != 0) {

			/* Short of hardware descriptors, suspend tx */

			/*
			 * This is an unlikely but expensive failure.  We've
			 * done all the hard work (DMA bindings etc.) and now we
			 * can't send out the frame.  What's worse, we have to
			 * spend even more time freeing up everything in txinfo.
			 */
			txq->stats.qfull++;
			free_txinfo_resources(txq, &txinfo);

			frame->b_next = next_frame;
			break;
		}

doorbell:
		/* Fewer and fewer doorbells as the queue fills up */
		if (eq->tse_pending >=
		    (1 << (fls(eq->tse_qsize - eq->tse_avail) / 2))) {
			txq->stats.txbytes += txinfo.len;
			txq->stats.txpkts++;
			t4_tx_ring_db(txq);
		}
		(void) t4_tx_reclaim_credits(txq, 32, NULL);
	}

	if (txpkts.npkt > 0) {
		write_txpkts_wr(txq, &txpkts);
	}

	if (eq->tse_pending != 0) {
		t4_tx_ring_db(txq);
	}

	if (frame != NULL) {
		eq->tse_flags |= EQ_CORKED;
	}

	(void) t4_tx_reclaim_credits(txq, eq->tse_qsize, NULL);
	TXQ_UNLOCK(txq);

	return (frame);
}

static int
t4_alloc_iq(struct port_info *pi, const t4_iq_params_t *tip, t4_sge_iq_t *iq,
    struct sge_fl *fl)
{
	struct adapter *sc = pi->adapter;
	int rc;

	ASSERT(tip->tip_tmr_idx >= 0 && tip->tip_tmr_idx < SGE_NTIMERS);
	ASSERT(tip->tip_pktc_idx < SGE_NCOUNTERS);
	ASSERT(tip->tip_cong_chan == -1 || tip->tip_cong_chan > 0);

	const bool intr_fwd = (tip->tip_intr_evtq != NULL);
	const uint_t intr_idx =
	    intr_fwd ? tip->tip_intr_evtq->tsi_cntxt_id : tip->tip_intr_idx;

	ASSERT(intr_fwd || intr_idx < sc->intr_queue_cfg.intr_count);

	mutex_init(&iq->tsi_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(DDI_INTR_PRI(sc->intr_pri)));
	iq->tsi_flags = 0;
	iq->tsi_iqtype = tip->tip_iq_type;
	iq->tsi_adapter = sc;
	iq->tsi_gts_rearm = V_QINTR_TIMER_IDX(tip->tip_tmr_idx);
	iq->tsi_intr_pktc_idx = -1;
	if (tip->tip_pktc_idx >= 0) {
		iq->tsi_gts_rearm |= TGC_SE_INTR_ARM;
		iq->tsi_intr_pktc_idx = tip->tip_pktc_idx;
	}

	/*
	 * The tsi_qsize holds the number of total entries in the queue, but the
	 * device requires that this number be a multiple of 16. See the
	 * documentation for FW_IQ_CMD in the Firmware Interface Book.
	 */
	iq->tsi_qsize = P2ROUNDUP(tip->tip_qsize, 16);
	/*
	 * The last entry is always reserved for the status page, even if status
	 * page updates are not being utilized.
	 */
	iq->tsi_cap = iq->tsi_qsize - 1;
	iq->tsi_esize = tip->tip_esize;
	iq->tsi_esize_bytes = t4_iq_esize_bytes[iq->tsi_esize];
	iq->tsi_intr_evtq = intr_fwd ? tip->tip_intr_evtq : NULL;
	iq->tsi_intr_idx = intr_fwd ? INTR_FORWARDED : intr_idx;

	const size_t len = iq->tsi_qsize * iq->tsi_esize_bytes;
	rc = alloc_desc_ring(sc, len, DDI_DMA_READ, &iq->tsi_desc_dhdl,
	    &iq->tsi_desc_ahdl, &iq->tsi_desc_ba, (caddr_t *)&iq->tsi_desc);
	if (rc != 0) {
		mutex_destroy(&iq->tsi_lock);
		return (rc);
	}
	iq->tsi_flags |= IQ_ALLOC_HOST;

	/*
	 * If the coalescing counter is not enabled for this IQ, use the 0
	 * index, rather than populating it with the invalid -1 value.
	 *
	 * The selected index does not matter when the counter is not enabled
	 * through the GTS flags.
	 */
	const uint_t pktc_idx = (iq->tsi_intr_pktc_idx < 0) ? 0 :
	    iq->tsi_intr_pktc_idx;
	const bool is_fwq = (iq == &sc->sge.fwq);

	struct fw_iq_cmd iq_cmd;
	bzero(&iq_cmd, sizeof (iq_cmd));

	iq_cmd.op_to_vfn = BE_32(V_FW_CMD_OP(FW_IQ_CMD) | F_FW_CMD_REQUEST |
	    F_FW_CMD_WRITE | F_FW_CMD_EXEC | V_FW_IQ_CMD_PFN(sc->pf) |
	    V_FW_IQ_CMD_VFN(0));

	iq_cmd.alloc_to_len16 = BE_32(F_FW_IQ_CMD_ALLOC | F_FW_IQ_CMD_IQSTART |
	    FW_LEN16(struct fw_iq_cmd));

	iq_cmd.type_to_iqandstindex = BE_32(
	    /* Special handling for firmware event queue */
	    (is_fwq ? F_FW_IQ_CMD_IQASYNCH : 0) |
	    (intr_fwd ? F_FW_IQ_CMD_IQANDST : 0) |
	    V_FW_IQ_CMD_IQANDSTINDEX(intr_idx) |
	    V_FW_IQ_CMD_TYPE(FW_IQ_TYPE_FL_INT_CAP) |
	    V_FW_IQ_CMD_VIID(pi->viid) |
	    V_FW_IQ_CMD_IQANUD(X_UPDATEDELIVERY_INTERRUPT));

	iq_cmd.iqdroprss_to_iqesize = BE_16(V_FW_IQ_CMD_IQPCIECH(pi->tx_chan) |
	    F_FW_IQ_CMD_IQGTSMODE | V_FW_IQ_CMD_IQINTCNTTHRESH(pktc_idx) |
	    V_FW_IQ_CMD_IQESIZE(iq->tsi_esize));

	iq_cmd.iqsize = BE_16(iq->tsi_qsize);
	iq_cmd.iqaddr = BE_64(iq->tsi_desc_ba);
	iq_cmd.iqns_to_fl0congen = tip->tip_cong_chan == -1 ? 0 :
	    BE_32(F_FW_IQ_CMD_IQFLINTCONGEN);

	/*
	 * This setting currently only pertains to T4/T5 parts with 2 ports, and
	 * its only effect is to correct a bug in setting the IQPCIECH related
	 * to offload queues (Chelsio bug#34516). Therefore, setting it is
	 * irrelevant for our driver. However, we set it anyways in case a
	 * future part or fimrware revision decides to use this information for
	 * other purposes relevant the behavior of our driver.
	 */
	iq_cmd.iqns_to_fl0congen |= BE_32(V_FW_IQ_CMD_IQTYPE(FW_IQ_IQTYPE_NIC));

	if (fl != NULL) {
		t4_sge_eq_t *eq = &fl->eq;

		iq->tsi_fl = fl;
		bzero(&fl->stats, sizeof (fl->stats));

		fl->bufs_cap = tip->tip_fl_qsize;
		eq->tse_flags = 0;
		eq->tse_qsize = EQ_FLITS_TO_HC(fl->bufs_cap);

		if ((rc = t4_alloc_eq_base(pi, eq)) != 0) {
			t4_free_iq(pi, iq);
			return (rc);
		}

		fl->bufs_lowat = P2ROUNDUP(sc->sge.fl_starve_threshold, 8);

		/*
		 * In T6, for egress queue type FL there is internal overhead
		 * of 16B for header going into FLM module.  Hence the maximum
		 * allowed burst size is 448 bytes.  For T4/T5, the hardware
		 * doesn't coalesce fetch requests if more than 64 bytes of
		 * Free List pointers are provided, so we use a 128-byte Fetch
		 * Burst Minimum there (T6 implements coalescing so we can use
		 * the smaller 64-byte value there).
		 */
		const uint_t fbmin = t4_cver_ge(sc, CHELSIO_T6) ?
		    X_FETCHBURSTMIN_64B_T6: X_FETCHBURSTMIN_128B;
		const uint_t fbmax = t4_cver_ge(sc, CHELSIO_T6) ?
		    X_FETCHBURSTMAX_256B : X_FETCHBURSTMAX_512B;
		const uint32_t fl_cong = (tip->tip_cong_chan == -1) ? 0 :
		    (V_FW_IQ_CMD_FL0CNGCHMAP(tip->tip_cong_chan) |
		    F_FW_IQ_CMD_FL0CONGCIF |
		    F_FW_IQ_CMD_FL0CONGEN);

		iq_cmd.iqns_to_fl0congen |= BE_32(
		    V_FW_IQ_CMD_FL0HOSTFCMODE(X_HOSTFCMODE_NONE) |
		    F_FW_IQ_CMD_FL0PACKEN |
		    F_FW_IQ_CMD_FL0PADEN |
		    fl_cong);
		/*
		 * We do not set cidx flushing because we choose to have no cidx
		 * updates for an FL. Instead we track FL usage implicitly by
		 * the incoming CPL messages on the Rx IQ.
		 */
		iq_cmd.fl0dcaen_to_fl0cidxfthresh |= BE_16(
		    V_FW_IQ_CMD_FL0FBMIN(fbmin) |
		    V_FW_IQ_CMD_FL0FBMAX(fbmax));
		iq_cmd.fl0size |= BE_16(eq->tse_qsize_spg);
		iq_cmd.fl0addr |= BE_64(eq->tse_ring_ba);
	}
	if (!intr_fwd) {
		iq->tsi_flags |= IQ_INTR;
	}

	rc = -t4_wr_mbox(sc, sc->mbox, &iq_cmd, sizeof (iq_cmd), &iq_cmd);
	if (rc != 0) {
		cxgb_printf(sc->dip, CE_WARN,
		    "failed to create ingress queue: %d", rc);
		t4_free_iq(pi, iq);
		return (rc);
	}
	iq->tsi_cntxt_id = BE_16(iq_cmd.iqid);
	iq->tsi_abs_id = BE_16(iq_cmd.physiqid);
	iq->tsi_flags |= IQ_ALLOC_DEV;

	iq->tsi_cdesc = iq->tsi_desc;
	iq->tsi_cidx = 0;
	iq->tsi_gen = F_RSPD_GEN;
	iq->tsi_adapter = sc;

	*t4_iqmap_slot(sc, iq->tsi_cntxt_id) = iq;

	if (fl != NULL) {
		t4_sge_eq_t *eq = &fl->eq;

		eq->tse_cntxt_id = BE_16(iq_cmd.fl0id);

		CTASSERT(offsetof(struct sge_fl, eq) == 0);
		*t4_eqmap_slot(sc, eq->tse_cntxt_id) = (t4_sge_eq_t *)fl;
		eq->tse_flags |= EQ_ALLOC_DEV;
		eq->tse_pidx = eq->tse_cidx = 0;
		t4_alloc_eq_post(pi, eq);
		fl->copy_threshold = rx_copy_threshold;

		/* Allocate space for one software descriptor per buffer. */
		const size_t sdesc_sz = fl->bufs_cap * sizeof (struct fl_sdesc);
		fl->sdesc = kmem_zalloc(sdesc_sz, KM_SLEEP);
		eq->tse_flags |= EQ_ALLOC_DESC;

		FL_LOCK(fl);
		(void) t4_fl_refill(fl, fl->bufs_lowat);
		FL_UNLOCK(fl);
	}

	if (t4_cver_ge(sc, CHELSIO_T5) && tip->tip_cong_chan != -1) {
		const uint32_t param = V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_DMAQ) |
		    V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_DMAQ_CONM_CTXT) |
		    V_FW_PARAMS_PARAM_YZ(iq->tsi_cntxt_id);

		const uint_t congmap_log = sc->params.arch.cng_ch_bits_log;
		uint32_t val =
		    V_CONMCTXT_CNGTPMODE(X_CONMCTXT_CNGTPMODE_CHANNEL);
		for (uint_t i = 0; i < 4; i++) {
			if (tip->tip_cong_chan & (1 << i)) {
				val |= (1 << (i << congmap_log));
			}
		}

		rc = -t4_set_params(sc, sc->mbox, sc->pf, 0, 1, &param, &val);
		if (rc != 0) {
			/* report error but carry on */
			cxgb_printf(sc->dip, CE_WARN,
			    "failed to set congestion manager context for "
			    "ingress queue %d: %d", iq->tsi_cntxt_id, rc);
		}
	}

	/* Enable event (and firmware) queues IQs immediately */
	if (iq->tsi_iqtype == TIQT_EVENT) {
		iq->tsi_flags |= IQ_ENABLED;
		t4_iq_gts_update(iq, iq->tsi_gts_rearm, 0);
	}

	return (0);
}

static void
t4_free_iq(struct port_info *pi, t4_sge_iq_t *iq)
{
	struct adapter *sc = iq->tsi_adapter;
	struct sge_fl *fl = iq->tsi_fl;
	t4_sge_eq_t *eq = fl != NULL ? &fl->eq : NULL;

	/*
	 * The onus is placed on the caller to ensure that no further activity
	 * will occur on this IQ.
	 */
	iq->tsi_flags &= ~IQ_ENABLED;

	if (iq->tsi_flags & IQ_ALLOC_DEV) {
		/*
		 * Device-side resources of freelists are allocated in concert
		 * with the device-side resources of their associated IQ.
		 */
		ASSERT(fl == NULL || (eq->tse_flags & EQ_ALLOC_DEV));

		const uint16_t eq_cntxid = fl ? eq->tse_cntxt_id : 0xffff;
		int rc = -t4_iq_free(sc, sc->mbox, sc->pf, 0,
		    FW_IQ_TYPE_FL_INT_CAP, iq->tsi_cntxt_id, eq_cntxid, 0xffff);
		if (rc != 0) {
			cxgb_printf(sc->dip, CE_WARN,
			    "failed to free IQ/FL (%x/%x): %d",
			    iq->tsi_cntxt_id, eq_cntxid, rc);
			/* attempt to complete the rest of clean-up */
		}
		iq->tsi_flags &= ~IQ_ALLOC_DEV;
		if (fl != NULL) {
			eq->tse_flags &= ~EQ_ALLOC_DEV;
		}
	}
	if (iq->tsi_flags & IQ_ALLOC_HOST) {
		(void) free_desc_ring(&iq->tsi_desc_dhdl, &iq->tsi_desc_ahdl);
		iq->tsi_desc = NULL;
		iq->tsi_cdesc = NULL;
		iq->tsi_desc_ba = 0;
		mutex_destroy(&iq->tsi_lock);
		iq->tsi_flags &= ~IQ_ALLOC_HOST;
	}
	iq->tsi_flags &= ~IQ_INTR;
	ASSERT0(iq->tsi_flags);

	iq->tsi_intr_idx = 0;
	iq->tsi_intr_evtq = NULL;
	iq->tsi_iqtype = TIQT_UNINIT;

	if (fl != NULL) {
		if (eq->tse_flags & EQ_ALLOC_DESC) {
			FL_LOCK(fl);
			t4_fl_free_bufs(fl);
			FL_UNLOCK(fl);

			kmem_free(fl->sdesc, fl->bufs_cap *
			    sizeof (struct fl_sdesc));
			fl->sdesc = NULL;

			eq->tse_flags &= ~EQ_ALLOC_DESC;
		}
		t4_free_eq(pi, eq);
		iq->tsi_fl = NULL;

		ASSERT0(eq->tse_flags);
	}
}

int
t4_alloc_evt_iqs(struct adapter *sc)
{
	const t4_intr_plan_t plan = sc->intr_queue_cfg.intr_plan;

	const t4_iq_params_t fwq_iqp = {
		.tip_iq_type	= TIQT_EVENT,
		.tip_tmr_idx	= sc->sge.fwq_tmr_idx,
		.tip_pktc_idx	= sc->sge.fwq_pktc_idx,
		.tip_qsize	= FW_IQ_QSIZE,
		.tip_esize	= FW_IQ_ESIZE,
		.tip_cong_chan	= -1,
		.tip_intr_evtq	= NULL,
		/*
		 * The device error-handling interrupt always occupies the 0th
		 * slot, which the firmware queue will share if no additional
		 * interrupts are available.  Otherwise it uses the next slot
		 * after that.
		 */
		.tip_intr_idx	= (plan == TIP_SINGLE) ? 0 : 1,
	};
	const int rc = t4_alloc_iq(sc->port[0], &fwq_iqp, &sc->sge.fwq, NULL);
	if (rc != 0) {
		cxgb_printf(sc->dip, CE_WARN,
		    "failed to create firmware event queue: %d.", rc);
		return (rc);
	}

	if (plan == TIP_PER_PORT) {
		const uint_t ipp = sc->intr_queue_cfg.intr_per_port;
		const uint_t port_count = sc->params.nports;

		for (uint_t i = 0; i < port_count; i++) {
			struct port_info *port = sc->port[i];

			for (uint_t j = 0; j < ipp; j++) {
				const t4_iq_params_t iqp = {
					.tip_iq_type	= TIQT_EVENT,
					.tip_tmr_idx	= sc->sge.fwq_tmr_idx,
					.tip_pktc_idx	= sc->sge.fwq_pktc_idx,
					.tip_qsize	= FW_IQ_QSIZE,
					.tip_esize	= FW_IQ_ESIZE,
					.tip_cong_chan	= -1,
					.tip_intr_evtq	= NULL,
					.tip_intr_idx	= 2 + (i * ipp) + j,
				};

				const int rc = t4_alloc_iq(port, &iqp,
				    &port->intr_iqs[j], NULL);
				if (rc != 0) {
					cxgb_printf(sc->dip, CE_WARN,
					    "failed to create interrupt event "
					    "queue %u for port %u: %d.", j, i,
					    rc);
					t4_free_evt_iqs(sc);
					return (rc);
				}
			}
		}
	}

	return (0);
}

void
t4_free_evt_iqs(struct adapter *sc)
{
	const uint_t port_count = sc->params.nports;

	for (uint_t i = 0; i < port_count; i++) {
		struct port_info *port = sc->port[i];

		for (uint_t j = 0; j < sc->intr_queue_cfg.intr_per_port; j++) {
			t4_free_iq(port, &port->intr_iqs[j]);
		}
	}

	t4_free_iq(sc->port[0], &sc->sge.fwq);
}

static int
t4_alloc_rxq(struct port_info *pi, struct sge_rxq *rxq, uint_t q_idx)
{
	struct adapter *sc = pi->adapter;

	rxq->port = pi;

	t4_iq_params_t iqp = {
		.tip_iq_type	= TIQT_ETH_RX,
		.tip_tmr_idx	= pi->tmr_idx,
		.tip_pktc_idx	= pi->pktc_idx,
		.tip_qsize	= sc->props.qsize_rxq,
		.tip_esize	= RX_IQ_ESIZE,
		.tip_fl_qsize	= sc->props.qsize_rxq,
		.tip_cong_chan	= t4_get_tp_ch_map(sc, pi->tx_chan),
	};
	t4_rxq_intr_assign(pi, q_idx, &iqp);
	const int rc = t4_alloc_iq(pi, &iqp, &rxq->iq, &rxq->fl);
	if (rc != 0) {
		return (rc);
	}

	rxq->ksp = setup_rxq_kstats(pi, rxq, q_idx);
	return (0);
}

static void
t4_free_rxq(struct port_info *pi, struct sge_rxq *rxq)
{
	if (rxq->ksp != NULL) {
		kstat_delete(rxq->ksp);
		rxq->ksp = NULL;
	}

	t4_free_iq(pi, &rxq->iq);
}

static int
t4_alloc_eq_base(struct port_info *pi, t4_sge_eq_t *eq)
{
	struct adapter *sc = pi->adapter;
	ASSERT0(eq->tse_flags);
	mutex_init(&eq->tse_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(sc->intr_pri));

	/*
	 * Make sure to account for the status page which sits at the end of the
	 * hardware ring and may consume one or two credits.
	 */
	ASSERT3U(eq->tse_qsize, <=, T4_MAX_EQ_SIZE);
	eq->tse_qsize_spg = eq->tse_qsize + sc->sge.eq_spg_len;

	/*
	 * We are allocating the "hardware" ring to hold the host credits, make
	 * sure to use tse_qsize_spg to include the status page credits.
	 */
	const size_t len = eq->tse_qsize_spg * EQ_HC_SIZE;
	int rc = alloc_desc_ring(sc, len, DDI_DMA_WRITE, &eq->tse_ring_dhdl,
	    &eq->tse_ring_ahdl, &eq->tse_ring_ba, (caddr_t *)&eq->tse_ring);
	if (rc != 0) {
		mutex_destroy(&eq->tse_lock);
		return (rc);
	}
	eq->tse_flags |= EQ_ALLOC_HOST;

	/*
	 * We always use one credit less than the technical capacity to avoid
	 * the situation where pidx == cidx which would indicate to the hardware
	 * that the queue is empty.
	 */
	eq->tse_avail = eq->tse_qsize - 1;
	eq->tse_pending = 0;
	eq->tse_pidx = 0;
	eq->tse_cidx = 0;
	eq->tse_spg = t4_eq_credit(eq, eq->tse_qsize);

	return (0);
}

#define	UDB_DBS	(DOORBELL_UDB | DOORBELL_UDBWC | DOORBELL_WCWR)

static void
t4_alloc_eq_post(struct port_info *pi, t4_sge_eq_t *eq)
{
	struct adapter *sc = pi->adapter;
	const boolean_t udb = (sc->doorbells & UDB_DBS) != 0;
	ASSERT(eq->tse_flags & EQ_ALLOC_DEV);

	eq->tse_doorbells = sc->doorbells;
	if (udb) {
		uint64_t udb_offset;
		uint_t udb_qid;

		const int rc = t4_bar2_sge_qregs(sc, eq->tse_cntxt_id,
		    T4_BAR2_QTYPE_EGRESS, 0, &udb_offset, &udb_qid);
		if (rc == 0) {
			eq->tse_udb = sc->bar2_ptr + udb_offset;
			eq->tse_udb_qid = udb_qid;
		} else {
			eq->tse_doorbells &= ~UDB_DBS;
			eq->tse_udb = NULL;
			eq->tse_udb_qid = 0;
		}
	}
}

static int
t4_eq_alloc_eth(struct port_info *pi, t4_sge_eq_t *eq)
{
	struct adapter *sc = pi->adapter;
	int rc;

	if ((rc = t4_alloc_eq_base(pi, eq)) != 0) {
		return (rc);
	}

	struct fw_eq_eth_cmd c = {
		.op_to_vfn = BE_32(
		    V_FW_CMD_OP(FW_EQ_ETH_CMD) |
		    F_FW_CMD_REQUEST | F_FW_CMD_WRITE | F_FW_CMD_EXEC |
		    V_FW_EQ_ETH_CMD_PFN(sc->pf) |
		    V_FW_EQ_ETH_CMD_VFN(0)),
		.alloc_to_len16 = BE_32(
		    F_FW_EQ_ETH_CMD_ALLOC |
		    F_FW_EQ_ETH_CMD_EQSTART |
		    FW_LEN16(struct fw_eq_eth_cmd)),
		.autoequiqe_to_viid = BE_32(
		    F_FW_EQ_ETH_CMD_AUTOEQUIQE |
		    F_FW_EQ_ETH_CMD_AUTOEQUEQE |
		    V_FW_EQ_ETH_CMD_VIID(pi->viid)),
		.fetchszm_to_iqid = BE_32(
		    V_FW_EQ_ETH_CMD_HOSTFCMODE(X_HOSTFCMODE_BOTH) |
		    V_FW_EQ_ETH_CMD_PCIECHN(eq->tse_tx_chan) |
		    F_FW_EQ_ETH_CMD_FETCHRO |
		    V_FW_EQ_ETH_CMD_IQID(eq->tse_iqid)),
		.dcaen_to_eqsize = BE_32(
		    V_FW_EQ_ETH_CMD_FBMIN(X_FETCHBURSTMIN_64B) |
		    V_FW_EQ_ETH_CMD_FBMAX(X_FETCHBURSTMAX_512B) |
		    V_FW_EQ_ETH_CMD_CIDXFTHRESH(X_CIDXFLUSHTHRESH_32) |
		    V_FW_EQ_ETH_CMD_EQSIZE(eq->tse_qsize_spg)),
		.eqaddr = BE_64(eq->tse_ring_ba),
	};

	/*
	 * The T4 is configured to send a notification for every 32 consumed
	 * host credits (X_CIDXFLUSHTHRESH_32). During times of periodic Tx
	 * traffic that threshold may not be reached with regularity, leaving
	 * outstanding credits that cannot be reclaimed until more traffic is
	 * sent. This can result in a situation where the device driver is
	 * unable to shutdown and detach. To alleviate this problem two methods
	 * may be employed:
	 *
	 * 1. The DBQ timer can be configured to arm and deliver a notification
	 *    after the EQ has gone idle for a period of time. This is available
	 *    on T6 and later adapters.
	 *
	 * 2. The CIDXFlushThresholdOverride flag (also documented under
	 *    FCThreshOverride flag in the T6 Programmers Guide) will send a
	 *    notification whenever a consumed credit causes CDIX==PIDX, even if
	 *    the CIDXFlushThreshold has not been reached.
	 *
	 * The DBQ timer is preferred, as it results in less notifications when
	 * the EQ is kept busy with frequent single-credit transmissions.
	 */
	if (sc->flags & TAF_DBQ_TIMER) {
		/* Configure the DBQ timer when it is available */
		c.timeren_timerix = BE_32(
		    F_FW_EQ_ETH_CMD_TIMEREN |
		    V_FW_EQ_ETH_CMD_TIMERIX(pi->dbq_timer_idx));
	} else {
		/* Otherwise fall back to CIDXFlushThresholdOverride */
		c.dcaen_to_eqsize |= BE_32(F_FW_EQ_ETH_CMD_CIDXFTHRESHO);
	}

	rc = -t4_wr_mbox(sc, sc->mbox, &c, sizeof (c), &c);
	if (rc != 0) {
		cxgb_printf(pi->dip, CE_WARN,
		    "failed to create Ethernet egress queue: %d", rc);
		return (rc);
	}
	eq->tse_cntxt_id = G_FW_EQ_ETH_CMD_EQID(BE_32(c.eqid_pkd));
	*t4_eqmap_slot(sc, eq->tse_cntxt_id) = eq;
	eq->tse_flags |= EQ_ALLOC_DEV;

	t4_alloc_eq_post(pi, eq);

	return (0);
}

static void
t4_free_eq(struct port_info *pi, t4_sge_eq_t *eq)
{
	struct adapter *sc = pi->adapter;

	if (eq->tse_flags & EQ_ALLOC_DEV) {
		int rc = -t4_eth_eq_free(sc, sc->mbox, sc->pf, 0,
		    eq->tse_cntxt_id);
		if (rc != 0) {
			cxgb_printf(sc->dip, CE_WARN,
			    "failed to free egress queue: %d", rc);
			/*
			 * Continue on with freeing operation, even though the
			 * device resource will be effectively leaked.
			 */
		}
		eq->tse_flags &= ~EQ_ALLOC_DEV;
	}

	if (eq->tse_flags & EQ_ALLOC_HOST) {
		(void) free_desc_ring(&eq->tse_ring_dhdl, &eq->tse_ring_ahdl);
		eq->tse_ring = NULL;
		eq->tse_ring_ba = 0;
		eq->tse_spg = NULL;
		mutex_destroy(&eq->tse_lock);
		eq->tse_flags &= ~EQ_ALLOC_HOST;
	}

	bzero(eq, sizeof (*eq));
}

static int
t4_alloc_txq(struct port_info *pi, struct sge_txq *txq, int idx)
{
	struct adapter *sc = pi->adapter;
	t4_sge_eq_t *eq = &txq->eq;
	int rc;

	if ((rc = t4_eq_alloc_eth(pi, eq)) != 0) {
		return (rc);
	}

	txq->port = pi;
	txq->sdesc = kmem_zalloc(sizeof (struct tx_sdesc) * eq->tse_qsize,
	    KM_SLEEP);
	txq->copy_threshold = tx_copy_threshold;
	txq->txb_size = eq->tse_qsize * txq->copy_threshold;
	rc = alloc_tx_copybuffer(sc, txq->txb_size, &txq->txb_dhdl,
	    &txq->txb_ahdl, &txq->txb_ba, &txq->txb_va);
	if (rc != 0) {
		txq->txb_size = 0;
		txq->txb_avail = 0;
		return (ENOMEM);
	} else {
		txq->txb_avail = txq->txb_size;
		eq->tse_flags |= EQ_ALLOC_DESC;
	}

	/*
	 * TODO: is this too low?  Worst case would need around 4 times qsize
	 * (all tx descriptors filled to the brim with SGLs, with each entry in
	 * the SGL coming from a distinct DMA handle).  Increase tx_dhdl_total
	 * if you see too many dma_hdl_failed.
	 */
	txq->tx_dhdl_total = eq->tse_qsize * 2;
	txq->tx_dhdl = kmem_zalloc(sizeof (ddi_dma_handle_t) *
	    txq->tx_dhdl_total, KM_SLEEP);
	for (uint_t i = 0; i < txq->tx_dhdl_total; i++) {
		rc = ddi_dma_alloc_handle(sc->dip, &sc->sge.dma_attr_tx,
		    DDI_DMA_SLEEP, 0, &txq->tx_dhdl[i]);
		if (rc != DDI_SUCCESS) {
			cxgb_printf(sc->dip, CE_WARN,
			    "%s: failed to allocate DMA handle (%d)",
			    __func__, rc);
			return (rc == DDI_DMA_NORESOURCES ? ENOMEM : EINVAL);
		}
		txq->tx_dhdl_avail++;
	}

	txq->ksp = setup_txq_kstats(pi, txq, idx);

	return (0);
}

static void
t4_free_txq(struct port_info *pi, struct sge_txq *txq)
{
	t4_sge_eq_t *eq = &txq->eq;

	if (txq->ksp != NULL) {
		kstat_delete(txq->ksp);
		txq->ksp = NULL;
	}

	if (txq->txb_va != NULL) {
		(void) free_desc_ring(&txq->txb_dhdl, &txq->txb_ahdl);
		txq->txb_va = NULL;
	}

	if (txq->sdesc != NULL) {
		ddi_dma_handle_t hdl;

		TXQ_LOCK(txq);
		while (eq->tse_cidx != eq->tse_pidx) {
			struct tx_sdesc *sd = &txq->sdesc[eq->tse_cidx];

			for (uint_t i = sd->hdls_used; i != 0; i--) {
				hdl = txq->tx_dhdl[txq->tx_dhdl_cidx];
				(void) ddi_dma_unbind_handle(hdl);
				if (++txq->tx_dhdl_cidx == txq->tx_dhdl_total)
					txq->tx_dhdl_cidx = 0;
			}

			ASSERT(sd->mp_head);
			freemsgchain(sd->mp_head);
			sd->mp_head = sd->mp_tail = NULL;

			eq->tse_cidx += sd->credits_used;
			if (eq->tse_cidx >= eq->tse_qsize)
				eq->tse_cidx -= eq->tse_qsize;

			txq->txb_avail += sd->txb_used;
		}
		ASSERT(txq->tx_dhdl_cidx == txq->tx_dhdl_pidx);
		ASSERT(txq->txb_avail == txq->txb_size);
		TXQ_UNLOCK(txq);

		kmem_free(txq->sdesc, sizeof (struct tx_sdesc) * eq->tse_qsize);
		txq->sdesc = NULL;
		eq->tse_flags &= ~EQ_ALLOC_DESC;
	}

	if (txq->tx_dhdl != NULL) {
		for (uint_t i = 0; i < txq->tx_dhdl_total; i++) {
			if (txq->tx_dhdl[i] != NULL)
				ddi_dma_free_handle(&txq->tx_dhdl[i]);
		}
		kmem_free(txq->tx_dhdl,
		    sizeof (ddi_dma_handle_t) * txq->tx_dhdl_total);
		txq->tx_dhdl = NULL;
	}

	t4_free_eq(pi, &txq->eq);

	bzero(txq, sizeof (*txq));
}

/*
 * Allocates a block of contiguous memory for DMA.  Can be used to allocate
 * memory for descriptor rings or for tx/rx copy buffers.
 *
 * Caller does not have to clean up anything if this function fails, it cleans
 * up after itself.
 *
 * Caller provides the following:
 * len		length of the block of memory to allocate.
 * flags	DDI_DMA_* flags to use (CONSISTENT/STREAMING, READ/WRITE/RDWR)
 * acc_attr	device access attributes for the allocation.
 * dma_attr	DMA attributes for the allocation
 *
 * If the function is successful it fills up this information:
 * dma_hdl	DMA handle for the allocated memory
 * acc_hdl	access handle for the allocated memory
 * ba		bus address of the allocated memory
 * va		KVA of the allocated memory.
 */
static int
alloc_dma_memory(struct adapter *sc, size_t len, int flags,
    ddi_device_acc_attr_t *acc_attr, ddi_dma_attr_t *dma_attr,
    ddi_dma_handle_t *dma_hdl, ddi_acc_handle_t *acc_hdl,
    uint64_t *pba, caddr_t *pva)
{
	int rc;
	ddi_dma_handle_t dhdl;
	ddi_acc_handle_t ahdl;
	ddi_dma_cookie_t cookie;
	uint_t ccount;
	caddr_t va;
	size_t real_len;

	*pva = NULL;

	/*
	 * DMA handle.
	 */
	rc = ddi_dma_alloc_handle(sc->dip, dma_attr, DDI_DMA_SLEEP, 0, &dhdl);
	if (rc != DDI_SUCCESS) {
		return (rc == DDI_DMA_NORESOURCES ? ENOMEM : EINVAL);
	}

	/*
	 * Memory suitable for DMA.
	 */
	rc = ddi_dma_mem_alloc(dhdl, len, acc_attr,
	    flags & DDI_DMA_CONSISTENT ? DDI_DMA_CONSISTENT : DDI_DMA_STREAMING,
	    DDI_DMA_SLEEP, 0, &va, &real_len, &ahdl);
	if (rc != DDI_SUCCESS) {
		ddi_dma_free_handle(&dhdl);
		return (ENOMEM);
	}

	/*
	 * DMA bindings.
	 */
	rc = ddi_dma_addr_bind_handle(dhdl, NULL, va, real_len, flags, NULL,
	    NULL, &cookie, &ccount);
	if (rc != DDI_DMA_MAPPED) {
		ddi_dma_mem_free(&ahdl);
		ddi_dma_free_handle(&dhdl);
		return (ENOMEM);
	}
	if (ccount != 1) {
		/* unusable DMA mapping */
		(void) free_desc_ring(&dhdl, &ahdl);
		return (ENOMEM);
	}

	bzero(va, real_len);
	*dma_hdl = dhdl;
	*acc_hdl = ahdl;
	*pba = cookie.dmac_laddress;
	*pva = va;

	return (0);
}

static int
free_dma_memory(ddi_dma_handle_t *dhdl, ddi_acc_handle_t *ahdl)
{
	(void) ddi_dma_unbind_handle(*dhdl);
	ddi_dma_mem_free(ahdl);
	ddi_dma_free_handle(dhdl);

	return (0);
}

static int
alloc_desc_ring(struct adapter *sc, size_t len, int rw,
    ddi_dma_handle_t *dma_hdl, ddi_acc_handle_t *acc_hdl,
    uint64_t *pba, caddr_t *pva)
{
	ddi_device_acc_attr_t *acc_attr = &sc->sge.acc_attr_desc;
	ddi_dma_attr_t *dma_attr = &sc->sge.dma_attr_desc;

	return (alloc_dma_memory(sc, len, DDI_DMA_CONSISTENT | rw, acc_attr,
	    dma_attr, dma_hdl, acc_hdl, pba, pva));
}

static int
free_desc_ring(ddi_dma_handle_t *dhdl, ddi_acc_handle_t *ahdl)
{
	return (free_dma_memory(dhdl, ahdl));
}

static int
alloc_tx_copybuffer(struct adapter *sc, size_t len,
    ddi_dma_handle_t *dma_hdl, ddi_acc_handle_t *acc_hdl,
    uint64_t *pba, caddr_t *pva)
{
	ddi_device_acc_attr_t *acc_attr = &sc->sge.acc_attr_tx;
	ddi_dma_attr_t *dma_attr = &sc->sge.dma_attr_desc; /* NOT dma_attr_tx */

	return (alloc_dma_memory(sc, len, DDI_DMA_STREAMING | DDI_DMA_WRITE,
	    acc_attr, dma_attr, dma_hdl, acc_hdl, pba, pva));
}

/*
 * Fetch next valid (if any) response from adapter in IQ.  Returns `true` if
 * rsp_ctrl data read into `ctrl` has generation bit state matching IQ
 * expectation for a new entry.
 *
 * This does not advance cidx, which is left to a subsequent call to
 * t4_iq_next_entry().
 */
static inline bool
t4_get_new_rsp(const t4_sge_iq_t *iq, struct rsp_ctrl *ctrl)
{
	(void) ddi_dma_sync(iq->tsi_desc_dhdl, 0, 0, DDI_DMA_SYNC_FORKERNEL);

	*ctrl = *(struct rsp_ctrl *)
	    ((caddr_t)iq->tsi_cdesc + (iq->tsi_esize_bytes -
	    sizeof (struct rsp_ctrl)));
	return ((ctrl->u.type_gen & F_RSPD_GEN) == iq->tsi_gen);
}

/*
 * Advance IQ consumer index, wrapping (and toggling generation bit) when the
 * end of the ring is reached.
 */
static inline void
t4_iq_next_entry(t4_sge_iq_t *iq)
{
	iq->tsi_cdesc = (void *) ((caddr_t)iq->tsi_cdesc + iq->tsi_esize_bytes);
	if (++iq->tsi_cidx == iq->tsi_cap) {
		iq->tsi_cidx = 0;
		iq->tsi_gen ^= F_RSPD_GEN;
		iq->tsi_cdesc = iq->tsi_desc;
	}
}

static inline bool
t4_fl_running_low(const struct sge_fl *fl)
{
	return (fl->bufs_avail <= fl->bufs_lowat);
}

static inline bool
t4_fl_not_running_low(const struct sge_fl *fl)
{
	return (fl->bufs_avail >= (2 * fl->bufs_lowat));
}

static inline uint_t
t4_fl_advance_cidx(struct sge_fl *fl)
{
	t4_sge_eq_t *eq = &fl->eq;

	FL_LOCK_ASSERT_OWNED(fl);
	ASSERT3U(fl->cidx_sdesc, <, FL_BUF_PTR_PER_HC);
	ASSERT3U(eq->tse_cidx, <, eq->tse_qsize);

	fl->cidx_sdesc++;
	if (fl->cidx_sdesc == FL_BUF_PTR_PER_HC) {
		fl->cidx_sdesc = 0;
		eq->tse_cidx++;
		if (eq->tse_cidx == eq->tse_qsize) {
			eq->tse_cidx = 0;
		}
		return (1);
	}
	return (0);
}

static inline struct fl_sdesc *
t4_fl_sdesc(struct sge_fl *fl, uint_t eq_idx, uint_t sdesc_idx)
{
	ASSERT(sdesc_idx < FL_BUF_PTR_PER_HC);
	const uint_t idx = (eq_idx * FL_BUF_PTR_PER_HC) + sdesc_idx;

	return (&fl->sdesc[idx]);
}

/*
 * Fill up the freelist by upto nbufs and maybe ring its doorbell.
 *
 * Returns non-zero to indicate that it should be added to the list of starving
 * freelists.
 */
static bool
t4_fl_refill(struct sge_fl *fl, uint_t nbufs)
{
	struct adapter *sc = t4_fl_to_iq(fl)->tsi_adapter;
	t4_sge_eq_t *eq = &fl->eq;

	FL_LOCK_ASSERT_OWNED(fl);

	/*
	 * We refill up to nbufs, but maybe less if there are not that many
	 * outstanding.
	 */
	nbufs = MIN(nbufs, fl->bufs_cap - fl->bufs_avail);
	while (nbufs != 0 && eq->tse_avail != 0) {
		struct fl_desc *fld = t4_eq_credit(eq, eq->tse_pidx);
		struct fl_sdesc *sd = t4_fl_sdesc(fl, eq->tse_pidx,
		    fl->pidx_sdesc);

		if (sd->rxb != NULL) {
			if (sd->rxb->ref_cnt == 1) {
				/*
				 * Buffer is available for recycling.  Two ways
				 * this can happen:
				 *
				 * a) All the packets DMA'd into it last time
				 *    around were within the rx_copy_threshold
				 *    and no part of the buffer was ever passed
				 *    up (ref_cnt never went over 1).
				 *
				 * b) Packets DMA'd into the buffer were passed
				 *    up but have all been freed by the upper
				 *    layers by now (ref_cnt went over 1 but is
				 *    now back to 1).
				 *
				 * Either way the bus address in the descriptor
				 * ring is already valid.
				 */
				ASSERT3U(fld->dptr[fl->pidx_sdesc], ==,
				    BE_64(sd->rxb->ba));
				fl->stats.rxb_recycle++;
			} else {
				/*
				 * Buffer still in use and we need a
				 * replacement. But first release our reference
				 * on the existing buffer.
				 */
				rxbuf_free(sd->rxb);
				sd->rxb = NULL;
			}
		}

		if (sd->rxb == NULL) {
			sd->rxb = rxbuf_alloc(sc->sge.rxbuf_cache, KM_NOSLEEP);
			if (sd->rxb == NULL) {
				fl->stats.rxb_alloc_fail++;
				break;
			}
			fl->stats.rxb_alloc++;
		}
		fld->dptr[fl->pidx_sdesc] = BE_64(sd->rxb->ba);

		nbufs--;
		fl->bufs_avail++;
		fl->pidx_sdesc++;
		if (fl->pidx_sdesc == FL_BUF_PTR_PER_HC) {
			/*
			 * The host credit is filled. It is now ready to be
			 * posted to the device.
			 */
			fl->pidx_sdesc = 0;
			eq->tse_pending++;
			eq->tse_avail--;
			eq->tse_pidx++;
			if (eq->tse_pidx == eq->tse_qsize) {
				eq->tse_pidx = 0;
			}
		}
	}

	if (eq->tse_pending != 0) {
		t4_fl_ring_db(fl);
	}

	return (t4_fl_running_low(fl));
}

static clock_t t4_sfl_period_us = 100000;

static void
t4_sfl_reschedule(struct adapter *sc)
{
	ASSERT(MUTEX_HELD(&sc->sfl_lock));
	ASSERT(!list_is_empty(&sc->sfl_list));

	sc->sfl_timer = timeout(t4_sfl_process, sc,
	    drv_usectohz(t4_sfl_period_us));
}

/*
 * Attempt to refill all starving freelists.
 */
static void
t4_sfl_process(void *arg)
{
	struct adapter *sc = arg;

	mutex_enter(&sc->sfl_lock);
	struct sge_fl *fl = list_head(&sc->sfl_list);
	while (fl != NULL) {
		struct sge_fl *next = list_next(&sc->sfl_list, fl);

		FL_LOCK(fl);
		(void) t4_fl_refill(fl, 64);
		if (t4_fl_not_running_low(fl) || fl->sfl_flags & SFL_DOOMED) {
			list_remove(&sc->sfl_list, fl);
			fl->sfl_flags &= ~SFL_STARVING;
		}
		FL_UNLOCK(fl);
		fl = next;
	}

	if (!list_is_empty(&sc->sfl_list)) {
		t4_sfl_reschedule(sc);
	}
	mutex_exit(&sc->sfl_lock);
}

static void
t4_sfl_enqueue(struct adapter *sc, struct sge_fl *fl)
{
	mutex_enter(&sc->sfl_lock);
	FL_LOCK(fl);
	if ((fl->sfl_flags & (SFL_DOOMED | SFL_STARVING)) == 0) {
		const bool was_empty = list_is_empty(&sc->sfl_list);

		fl->sfl_flags |= SFL_STARVING;
		list_insert_tail(&sc->sfl_list, fl);
		if (was_empty) {
			t4_sfl_reschedule(sc);
		}
	}
	FL_UNLOCK(fl);
	mutex_exit(&sc->sfl_lock);
}

static void
t4_fl_free_bufs(struct sge_fl *fl)
{
	t4_sge_eq_t *eq = &fl->eq;

	EQ_LOCK_ASSERT_OWNED(eq);

	for (uint_t i = 0; i < eq->tse_qsize * FL_BUF_PTR_PER_HC; i++) {
		struct fl_sdesc *sd = &fl->sdesc[i];

		if (sd->rxb != NULL) {
			rxbuf_free(sd->rxb);
			sd->rxb = NULL;
		}
	}
}

/*
 * Attempt to create an mblk representing the payload stored at the current
 * offset (fl->offset) in the current FL buffer (fl->cidx_sdesc). If the length
 * of the payload is less than fl->copy_threshold, then allocable a new
 * mblk/dblk to hold the contents and copy it over. Otherwise, attempt to
 * desballoc() the payload. If there is a failure to allocate, then restore the
 * eq->tse_cidx and fl->offset to their original value that they had upon
 * entering this function.
 */
static mblk_t *
t4_fl_get_payload(struct sge_fl *fl, uint32_t len, bool newbuf)
{
	struct adapter *sc = t4_fl_to_iq(fl)->tsi_adapter;
	t4_sge_eq_t *eq = &fl->eq;
	mblk_t *mp = NULL;
	mblk_t *head = NULL, **tailp = &head;
	uint_t bufs_consumed = 0;

	FL_LOCK(fl);
	/*
	 * The SGE won't pack a new frame into the current buffer if the entire
	 * payload doesn't fit in the remaining space.  Move on to the next buf
	 * in that case.
	 */
	const uint16_t rcidx = eq->tse_cidx;
	const uint_t rcidx_sdesc = fl->cidx_sdesc;
	const uint32_t roffset = fl->offset;
	uint_t credits_avail = 0;

	if (fl->offset > 0 && newbuf) {
		/*
		 * The device has moved onto the next buffer. Reset our offset
		 * into the current buffer and advanced the driver's cidx, which
		 * may have freed up an EQ host credit to be refilled by the
		 * driver.
		 */
		fl->offset = 0;
		credits_avail += t4_fl_advance_cidx(fl);
		bufs_consumed++;
	}

	const bool do_copy = (len <= fl->copy_threshold);
	if (do_copy) {
		mp = allocb(len, 0);
		if (mp == NULL) {
			fl->stats.copy_fail++;
			DTRACE_PROBE1(t4__fl_alloc_fail, struct sge_fl *, fl);
			goto restore;
		}
		*tailp = mp;
		tailp = &mp->b_cont;
	}

	uint_t offset = fl->offset;
	while (len != 0) {
		struct rxbuf *rxb =
		    t4_fl_sdesc(fl, eq->tse_cidx, fl->cidx_sdesc)->rxb;
		const uint_t copy_len = MIN(len, rxb->buf_size - offset);

		(void) ddi_dma_sync(rxb->dhdl, 0, 0, DDI_DMA_SYNC_FORKERNEL);

		if (do_copy) {
			bcopy(rxb->va + offset, mp->b_wptr, copy_len);
			fl->stats.copy++;
		} else {
			mp = desballoc((unsigned char *)rxb->va + offset,
			    copy_len, 0, &rxb->freefunc);
			if (mp == NULL) {
				fl->stats.wrap_fail++;
				DTRACE_PROBE1(t4__fl_alloc_fail,
				    struct sge_fl *, fl);
				goto restore;
			}
			atomic_inc_uint(&rxb->ref_cnt);
			*tailp = mp;
			tailp = &mp->b_cont;
			fl->stats.wrap++;
		}
		mp->b_wptr += copy_len;
		len -= copy_len;
		offset += roundup(copy_len, sc->sge.fl_align);

		ASSERT3U(offset, <=, rxb->buf_size);
		if (offset == rxb->buf_size) {
			offset = 0;
			credits_avail += t4_fl_advance_cidx(fl);
			bufs_consumed++;
		}
	}
	fl->offset = offset;
	ASSERT3U(credits_avail, <=, eq->tse_qsize);
	eq->tse_avail += credits_avail;
	/* We can't consume more than are available. */
	ASSERT3U(bufs_consumed, <=, fl->bufs_avail);
	fl->bufs_avail -= bufs_consumed;

	FL_UNLOCK(fl);

	ASSERT(head != NULL);
	return (head);

restore:
	eq->tse_cidx = rcidx;
	fl->cidx_sdesc = rcidx_sdesc;
	fl->offset = roffset;
	FL_UNLOCK(fl);
	freemsgchain(head);

	return (NULL);
}

/*
 * We'll do immediate data tx for non-LSO, but only when not coalescing.  We're
 * willing to use upto 2 hardware descriptors which means a maximum of 96 bytes
 * of immediate data.
 */
#define	IMM_LEN ( \
	2 * EQ_HC_SIZE \
	- sizeof (struct fw_eth_tx_pkt_wr) \
	- sizeof (struct cpl_tx_pkt_core))

/*
 * Returns non-zero on failure, no need to cleanup anything in that case.
 *
 * Note 1: We always try to pull up the mblk if required and return E2BIG only
 * if this fails.
 *
 * Note 2: We'll also pullup incoming mblk if HW_LSO is set and the first mblk
 * does not have the TCP header in it.
 */
static int
get_frame_txinfo(struct sge_txq *txq, mblk_t **fp, struct txinfo *txinfo,
    int sgl_only)
{
	uint32_t flags = 0, len, n;
	mblk_t *m = *fp;
	int rc;

	TXQ_LOCK_ASSERT_OWNED(txq);	/* will manipulate txb and dma_hdls */

	mac_hcksum_get(m, NULL, NULL, NULL, NULL, &flags);
	txinfo->flags = (flags & HCK_TX_FLAGS);

	mac_lso_get(m, &txinfo->mss, &flags);
	txinfo->flags |= (flags & HW_LSO_FLAGS);

	if (flags & HW_LSO)
		sgl_only = 1;	/* Do not allow immediate data with LSO */

	/*
	 * If checksum or segmentation offloads are requested, gather
	 * information about the sizes and types of headers in the packet.
	 */
	if (txinfo->flags != 0) {
		mac_ether_offload_info(m, &txinfo->meoi);
	} else {
		bzero(&txinfo->meoi, sizeof (txinfo->meoi));
	}

start:
	txinfo->nsegs = 0;
	txinfo->hdls_used = 0;
	txinfo->txb_used = 0;
	txinfo->len = 0;

	/* total length and a rough estimate of # of segments */
	n = 0;
	for (; m; m = m->b_cont) {
		len = MBLKL(m);
		n += (len / PAGE_SIZE) + 1;
		txinfo->len += len;
	}
	m = *fp;

	if (n >= TX_SGL_SEGS || ((flags & HW_LSO) && MBLKL(m) < 50)) {
		txq->stats.pullup_early++;
		m = msgpullup(*fp, -1);
		if (m == NULL) {
			txq->stats.pullup_failed++;
			return (E2BIG);	/* (*fp) left as it was */
		}
		freemsg(*fp);
		*fp = m;
		mac_hcksum_set(m, 0, 0, 0, 0, txinfo->flags);
	}

	if (txinfo->len <= IMM_LEN && !sgl_only)
		return (0);	/* nsegs = 0 tells caller to use imm. tx */

	if (txinfo->len <= txq->copy_threshold &&
	    copy_into_txb(txq, m, txinfo->len, txinfo) == 0) {
		goto done;
	}

	for (; m; m = m->b_cont) {

		len = MBLKL(m);

		/*
		 * Use tx copy buffer if this mblk is small enough and there is
		 * room, otherwise add DMA bindings for this mblk to the SGL.
		 */
		if (len > txq->copy_threshold ||
		    (rc = copy_into_txb(txq, m, len, txinfo)) != 0) {
			rc = add_mblk(txq, txinfo, m, len);
		}

		if (rc == E2BIG ||
		    (txinfo->nsegs == TX_SGL_SEGS && m->b_cont)) {

			txq->stats.pullup_late++;
			m = msgpullup(*fp, -1);
			if (m != NULL) {
				free_txinfo_resources(txq, txinfo);
				freemsg(*fp);
				*fp = m;
				mac_hcksum_set(m, 0, 0, 0, 0, txinfo->flags);
				goto start;
			}

			txq->stats.pullup_failed++;
			rc = E2BIG;
		}

		if (rc != 0) {
			free_txinfo_resources(txq, txinfo);
			return (rc);
		}
	}

done:
	ASSERT(txinfo->nsegs > 0 && txinfo->nsegs <= TX_SGL_SEGS);

	/*
	 * Store the # of flits required to hold this frame's SGL in nflits.  An
	 * SGL has a (ULPTX header + len0, addr0) tuple optionally followed by
	 * multiple (len0 + len1, addr0, addr1) tuples.  If addr1 is not used
	 * then len1 must be set to 0.
	 */
	n = txinfo->nsegs - 1;
	txinfo->nflits = (3 * n) / 2 + (n & 1) + 2;
	if (n & 1)
		txinfo->sgl.sge[n / 2].len[1] = cpu_to_be32(0);

	txinfo->sgl.cmd_nsge = cpu_to_be32(V_ULPTX_CMD((u32)ULP_TX_SC_DSGL) |
	    V_ULPTX_NSGE(txinfo->nsegs));

	return (0);
}

static inline int
fits_in_txb(struct sge_txq *txq, int len, int *waste)
{
	if (txq->txb_avail < len)
		return (0);

	if (txq->txb_next + len <= txq->txb_size) {
		*waste = 0;
		return (1);
	}

	*waste = txq->txb_size - txq->txb_next;

	return (txq->txb_avail - *waste < len ? 0 : 1);
}

#define	TXB_CHUNK	64

/*
 * Copies the specified # of bytes into txq's tx copy buffer and updates txinfo
 * and txq to indicate resources used.  Caller has to make sure that those many
 * bytes are available in the mblk chain (b_cont linked).
 */
static inline int
copy_into_txb(struct sge_txq *txq, mblk_t *m, int len, struct txinfo *txinfo)
{
	int waste, n;

	TXQ_LOCK_ASSERT_OWNED(txq);	/* will manipulate txb */

	if (!fits_in_txb(txq, len, &waste)) {
		txq->stats.txb_full++;
		return (ENOMEM);
	}

	if (waste != 0) {
		ASSERT((waste & (TXB_CHUNK - 1)) == 0);
		txinfo->txb_used += waste;
		txq->txb_avail -= waste;
		txq->txb_next = 0;
	}

	for (n = 0; n < len; m = m->b_cont) {
		bcopy(m->b_rptr, txq->txb_va + txq->txb_next + n, MBLKL(m));
		n += MBLKL(m);
	}

	add_seg(txinfo, txq->txb_ba + txq->txb_next, len);

	n = roundup(len, TXB_CHUNK);
	txinfo->txb_used += n;
	txq->txb_avail -= n;
	txq->txb_next += n;
	ASSERT(txq->txb_next <= txq->txb_size);
	if (txq->txb_next == txq->txb_size)
		txq->txb_next = 0;

	return (0);
}

static inline void
add_seg(struct txinfo *txinfo, uint64_t ba, uint32_t len)
{
	ASSERT(txinfo->nsegs < TX_SGL_SEGS);	/* must have room */

	if (txinfo->nsegs != 0) {
		int idx = txinfo->nsegs - 1;
		txinfo->sgl.sge[idx / 2].len[idx & 1] = cpu_to_be32(len);
		txinfo->sgl.sge[idx / 2].addr[idx & 1] = cpu_to_be64(ba);
	} else {
		txinfo->sgl.len0 = cpu_to_be32(len);
		txinfo->sgl.addr0 = cpu_to_be64(ba);
	}
	txinfo->nsegs++;
}

/*
 * This function cleans up any partially allocated resources when it fails so
 * there's nothing for the caller to clean up in that case.
 *
 * EIO indicates permanent failure.  Caller should drop the frame containing
 * this mblk and continue.
 *
 * E2BIG indicates that the SGL length for this mblk exceeds the hardware
 * limit.  Caller should pull up the frame before trying to send it out.
 * (This error means our pullup_early heuristic did not work for this frame)
 *
 * ENOMEM indicates a temporary shortage of resources (DMA handles, other DMA
 * resources, etc.).  Caller should suspend the tx queue and wait for reclaim to
 * free up resources.
 */
static inline int
add_mblk(struct sge_txq *txq, struct txinfo *txinfo, mblk_t *m, int len)
{
	ddi_dma_handle_t dhdl;
	ddi_dma_cookie_t cookie;
	uint_t ccount = 0;
	int rc;

	TXQ_LOCK_ASSERT_OWNED(txq);	/* will manipulate dhdls */

	if (txq->tx_dhdl_avail == 0) {
		txq->stats.dma_hdl_failed++;
		return (ENOMEM);
	}

	dhdl = txq->tx_dhdl[txq->tx_dhdl_pidx];
	rc = ddi_dma_addr_bind_handle(dhdl, NULL, (caddr_t)m->b_rptr, len,
	    DDI_DMA_WRITE | DDI_DMA_STREAMING, DDI_DMA_DONTWAIT, NULL, &cookie,
	    &ccount);
	if (rc != DDI_DMA_MAPPED) {
		txq->stats.dma_map_failed++;

		ASSERT(rc != DDI_DMA_INUSE && rc != DDI_DMA_PARTIAL_MAP);

		return (rc == DDI_DMA_NORESOURCES ? ENOMEM : EIO);
	}

	if (ccount + txinfo->nsegs > TX_SGL_SEGS) {
		(void) ddi_dma_unbind_handle(dhdl);
		return (E2BIG);
	}

	add_seg(txinfo, cookie.dmac_laddress, cookie.dmac_size);
	while (--ccount) {
		ddi_dma_nextcookie(dhdl, &cookie);
		add_seg(txinfo, cookie.dmac_laddress, cookie.dmac_size);
	}

	if (++txq->tx_dhdl_pidx == txq->tx_dhdl_total)
		txq->tx_dhdl_pidx = 0;
	txq->tx_dhdl_avail--;
	txinfo->hdls_used++;

	return (0);
}

/*
 * Releases all the txq resources used up in the specified txinfo.
 */
static void
free_txinfo_resources(struct sge_txq *txq, struct txinfo *txinfo)
{
	int n;

	TXQ_LOCK_ASSERT_OWNED(txq);	/* dhdls, txb */

	n = txinfo->txb_used;
	if (n > 0) {
		txq->txb_avail += n;
		if (n <= txq->txb_next)
			txq->txb_next -= n;
		else {
			n -= txq->txb_next;
			txq->txb_next = txq->txb_size - n;
		}
	}

	for (n = txinfo->hdls_used; n > 0; n--) {
		if (txq->tx_dhdl_pidx > 0)
			txq->tx_dhdl_pidx--;
		else
			txq->tx_dhdl_pidx = txq->tx_dhdl_total - 1;
		txq->tx_dhdl_avail++;
		(void) ddi_dma_unbind_handle(txq->tx_dhdl[txq->tx_dhdl_pidx]);
	}
}

/*
 * Returns 0 to indicate that m has been accepted into a coalesced tx work
 * request.  It has either been folded into txpkts or txpkts was flushed and m
 * has started a new coalesced work request (as the first frame in a fresh
 * txpkts).
 *
 * Returns non-zero to indicate a failure - caller is responsible for
 * transmitting m, if there was anything in txpkts it has been flushed.
 */
static int
add_to_txpkts(struct sge_txq *txq, struct txpkts *txpkts, mblk_t *m,
    struct txinfo *txinfo)
{
	t4_sge_eq_t *eq = &txq->eq;
	int can_coalesce;
	struct tx_sdesc *txsd;
	uint8_t flits;

	TXQ_LOCK_ASSERT_OWNED(txq);
	ASSERT(m->b_next == NULL);

	if (txpkts->npkt > 0) {
		flits = TXPKTS_PKT_HDR_FLITS + txinfo->nflits;
		can_coalesce = (txinfo->flags & HW_LSO) == 0 &&
		    txpkts->nflits + flits <= TX_WR_MAX_FLITS &&
		    txpkts->nflits + flits <= EQ_HC_TO_FLITS(eq->tse_avail) &&
		    txpkts->plen + txinfo->len < 65536;

		if (can_coalesce != 0) {
			txpkts->tail->b_next = m;
			txpkts->tail = m;
			txpkts->npkt++;
			txpkts->nflits += flits;
			txpkts->plen += txinfo->len;

			txsd = &txq->sdesc[eq->tse_pidx];
			txsd->txb_used += txinfo->txb_used;
			txsd->hdls_used += txinfo->hdls_used;

			/*
			 * The txpkts chaining above has already placed `m` at
			 * the end with b_next.  Keep the txsd notion of this
			 * new tail up to date.
			 */
			ASSERT3P(txsd->mp_tail->b_next, ==, m);
			txsd->mp_tail = m;

			return (0);
		}

		/*
		 * Couldn't coalesce m into txpkts.  The first order of business
		 * is to send txpkts on its way.  Then we'll revisit m.
		 */
		write_txpkts_wr(txq, txpkts);
	}

	/*
	 * Check if we can start a new coalesced tx work request with m as
	 * the first packet in it.
	 */

	ASSERT(txpkts->npkt == 0);
	ASSERT(txinfo->len < 65536);

	flits = TXPKTS_WR_HDR_FLITS + txinfo->nflits;

	/*
	 * We can coalesce if this is non-LSO and the number of flits required
	 * is both less than or equal to the maximum flits allowed for a single
	 * WR and less than or equal to the number of flits currently available.
	 */
	can_coalesce = (txinfo->flags & HW_LSO) == 0 &&
	    flits <= EQ_HC_TO_FLITS(eq->tse_avail) && flits <= TX_WR_MAX_FLITS;

	if (can_coalesce == 0)
		return (EINVAL);

	/*
	 * Start a fresh coalesced tx WR with m as the first frame in it.
	 */
	t4_eq_host_credit_t *hc = t4_eq_credit(eq, eq->tse_pidx);
	txpkts->tail = m;
	txpkts->npkt = 1;
	txpkts->nflits = flits;
	txpkts->flitp = &hc->flit[2];
	txpkts->plen = txinfo->len;

	txsd = &txq->sdesc[eq->tse_pidx];
	txsd->mp_head = txsd->mp_tail = m;
	txsd->txb_used = txinfo->txb_used;
	txsd->hdls_used = txinfo->hdls_used;

	return (0);
}

static inline void
t4_tx_incr_pending(struct sge_txq *txq, uint16_t ncredits)
{
	t4_sge_eq_t *eq = &txq->eq;

	TXQ_LOCK_ASSERT_OWNED(txq);
	ASSERT3U(ncredits, !=, 0);
	ASSERT3U(eq->tse_avail, >=, ncredits);

	eq->tse_pending += ncredits;
	eq->tse_avail -= ncredits;
	eq->tse_pidx += ncredits;
	if (eq->tse_pidx >= eq->tse_qsize) {
		eq->tse_pidx -= eq->tse_qsize;
	}

	ASSERT3U(eq->tse_pidx, <, eq->tse_qsize);
	ASSERT3U(eq->tse_pending, <=, eq->tse_qsize - 1);
}

/*
 * Note that write_txpkts_wr() can never run out of host credits (but
 * write_txpkt_wr() can). add_to_txpkts() ensures that a frame is accepted for
 * coalescing only if sufficient host credits are available.
 */
static void
write_txpkts_wr(struct sge_txq *txq, struct txpkts *txpkts)
{
	t4_sge_eq_t *eq = &txq->eq;

	TXQ_LOCK_ASSERT_OWNED(txq);	/* pidx, avail */

	struct fw_eth_tx_pkts_wr *wr = t4_eq_credit(eq, eq->tse_pidx);
	const uint16_t ncredits = EQ_FLITS_TO_HC(txpkts->nflits);
	ASSERT3U(ncredits, <=, eq->tse_avail);

	/* The immdlen value does not matter for this WR. */
	wr->op_pkd = BE_32(V_FW_WR_OP(FW_ETH_TX_PKTS_WR) | V_FW_WR_IMMDLEN(0));

	/*
	 * If all remaining credits are consumed by this WR, then request an EQ
	 * status update to both the EQ status page and the associated ingress
	 * queue entry.
	 *
	 * See §29.10 FW_ETH_TX_PKTS_WR of the T4 Firmware Interface
	 * Specification.
	 */
	const uint32_t update_bits = (eq->tse_avail == ncredits) ?
	    (F_FW_WR_EQUEQ | F_FW_WR_EQUIQ) : 0;
	wr->equiq_to_len16 = BE_32(V_FW_WR_LEN16(howmany(txpkts->nflits, 2)) |
	    update_bits);
	wr->r3 = 0;
	wr->plen = BE_16(txpkts->plen);
	wr->npkt = txpkts->npkt;
	wr->type = 0;

	/* Everything else already written */
	struct tx_sdesc *txsd = &txq->sdesc[eq->tse_pidx];
	txsd->credits_used = ncredits;

	txq->stats.txb_used += txsd->txb_used / TXB_CHUNK;
	txq->stats.hdl_used += txsd->hdls_used;

	t4_tx_incr_pending(txq, ncredits);

	txq->stats.txpkts_pkts += txpkts->npkt;
	txq->stats.txpkts_wrs++;
	txpkts->npkt = 0;	/* emptied */
}

typedef enum {
	COS_SUCCESS,	/* ctrl flit contains proper bits for csum offload */
	COS_IGNORE,	/* no csum offload requested */
	COS_FAIL,	/* csum offload requested, but pkt data missing */
} csum_offload_status_t;
/*
 * Build a ctrl1 flit for checksum offload in CPL_TX_PKT_XT command
 */
static csum_offload_status_t
csum_to_ctrl(const struct txinfo *txinfo, uint32_t chip_version,
    uint64_t *ctrlp)
{
	const mac_ether_offload_info_t *meoi = &txinfo->meoi;
	const uint32_t tx_flags = txinfo->flags;
	const boolean_t needs_l3_csum = ((tx_flags & HW_LSO) != 0 || (tx_flags &
	    HCK_IPV4_HDRCKSUM) != 0) && meoi->meoi_l3proto == ETHERTYPE_IP;
	const boolean_t needs_l4_csum = (tx_flags & HW_LSO) != 0 ||
	    (tx_flags & (HCK_FULLCKSUM | HCK_PARTIALCKSUM)) != 0;

	/*
	 * Default to disabling any checksumming both for cases where it is not
	 * requested, but also if we cannot appropriately interrogate the
	 * required information from the packet.
	 */
	uint64_t ctrl = F_TXPKT_L4CSUM_DIS | F_TXPKT_IPCSUM_DIS;
	if (!needs_l3_csum && !needs_l4_csum) {
		*ctrlp = ctrl;
		return (COS_IGNORE);
	}

	if (needs_l3_csum) {
		/* Only IPv4 checksums are supported (for L3) */
		if ((meoi->meoi_flags & MEOI_L3INFO_SET) == 0) {
			*ctrlp = ctrl;
			return (COS_FAIL);
		}
		ctrl &= ~F_TXPKT_IPCSUM_DIS;
	}

	if (needs_l4_csum) {
		/*
		 * We need at least all of the L3 header to make decisions about
		 * the contained L4 protocol.  If not all of the L4 information
		 * is present, we will leave it to the NIC to checksum all it is
		 * able to.
		 */
		if ((meoi->meoi_flags & MEOI_L3INFO_SET) == 0) {
			*ctrlp = ctrl;
			return (COS_FAIL);
		}

		/*
		 * Since we are parsing the packet anyways, make the checksum
		 * decision based on the L4 protocol, rather than using the
		 * Generic TCP/UDP checksum using start & end offsets in the
		 * packet (like requested with PARTIALCKSUM).
		 */
		int csum_type = -1;
		if (meoi->meoi_l3proto == ETHERTYPE_IP &&
		    meoi->meoi_l4proto == IPPROTO_TCP) {
			csum_type = TX_CSUM_TCPIP;
		} else if (meoi->meoi_l3proto == ETHERTYPE_IPV6 &&
		    meoi->meoi_l4proto == IPPROTO_TCP) {
			csum_type = TX_CSUM_TCPIP6;
		} else if (meoi->meoi_l3proto == ETHERTYPE_IP &&
		    meoi->meoi_l4proto == IPPROTO_UDP) {
			csum_type = TX_CSUM_UDPIP;
		} else if (meoi->meoi_l3proto == ETHERTYPE_IPV6 &&
		    meoi->meoi_l4proto == IPPROTO_UDP) {
			csum_type = TX_CSUM_UDPIP6;
		} else {
			*ctrlp = ctrl;
			return (COS_FAIL);
		}

		ASSERT(csum_type != -1);
		ctrl &= ~F_TXPKT_L4CSUM_DIS;
		ctrl |= V_TXPKT_CSUM_TYPE(csum_type);
	}

	if ((ctrl & F_TXPKT_IPCSUM_DIS) == 0 &&
	    (ctrl & F_TXPKT_L4CSUM_DIS) != 0) {
		/*
		 * If only the IPv4 checksum is requested, we need to set an
		 * appropriate type in the command for it.
		 */
		ctrl |= V_TXPKT_CSUM_TYPE(TX_CSUM_IP);
	}

	ASSERT(ctrl != (F_TXPKT_L4CSUM_DIS | F_TXPKT_IPCSUM_DIS));

	/*
	 * Fill in the requisite L2/L3 header length data.
	 *
	 * The Ethernet header length is recorded as 'size - 14 bytes'
	 */
	const uint8_t eth_len = meoi->meoi_l2hlen - 14;
	if (chip_version >= CHELSIO_T6) {
		ctrl |= V_T6_TXPKT_ETHHDR_LEN(eth_len);
	} else {
		ctrl |= V_TXPKT_ETHHDR_LEN(eth_len);
	}
	ctrl |= V_TXPKT_IPHDR_LEN(meoi->meoi_l3hlen);

	*ctrlp = ctrl;
	return (COS_SUCCESS);
}

static int
write_txpkt_wr(struct port_info *pi, struct sge_txq *txq, mblk_t *m,
    struct txinfo *txinfo)
{
	t4_sge_eq_t *eq = &txq->eq;
	struct cpl_tx_pkt_core *cpl;
	uint32_t ctrl;	/* used in many unrelated places */
	uint64_t ctrl1;
	uint16_t nflits = 0;
	struct tx_sdesc *txsd;
	caddr_t dst;
	const mac_ether_offload_info_t *meoi = &txinfo->meoi;

	TXQ_LOCK_ASSERT_OWNED(txq);	/* pidx, avail */

	/*
	 * Do we have enough flits to send this frame out?
	 */
	ctrl = sizeof (struct cpl_tx_pkt_core);
	if (txinfo->flags & HW_LSO) {
		nflits = TXPKT_LSO_WR_HDR_FLITS;
		ctrl += sizeof (struct cpl_tx_pkt_lso_core);
	} else {
		nflits = TXPKT_WR_HDR_FLITS;
	}
	if (txinfo->nsegs > 0)
		nflits += txinfo->nflits;
	else {
		nflits += howmany(txinfo->len, FLIT_NUM_BYTES);
		ctrl += txinfo->len;
	}

	ASSERT3U(nflits, >, 0);

	const uint16_t ncredits = EQ_FLITS_TO_HC(nflits);
	if (ncredits > eq->tse_avail)
		return (ENOMEM);

	/* Firmware work request header */
	struct fw_eth_tx_pkt_wr *wr = t4_eq_credit(eq, eq->tse_pidx);
	wr->op_immdlen = cpu_to_be32(V_FW_WR_OP(FW_ETH_TX_PKT_WR) |
	    V_FW_WR_IMMDLEN(ctrl));
	ctrl = V_FW_WR_LEN16(howmany(nflits, 2));

	/*
	 * If all remaining credits are consumed by this WR, then request an EQ
	 * status update to both the EQ status page and the associated ingress
	 * queue entry.
	 */
	if (ncredits == eq->tse_avail)
		ctrl |= F_FW_WR_EQUEQ | F_FW_WR_EQUIQ;

	wr->equiq_to_len16 = cpu_to_be32(ctrl);
	wr->r3 = 0;

	if (txinfo->flags & HW_LSO &&
	    (meoi->meoi_flags & MEOI_L4INFO_SET) != 0 &&
	    meoi->meoi_l4proto == IPPROTO_TCP) {
		struct cpl_tx_pkt_lso_core *lso = (void *)(wr + 1);

		ctrl = V_LSO_OPCODE((u32)CPL_TX_PKT_LSO) | F_LSO_FIRST_SLICE |
		    F_LSO_LAST_SLICE;

		if (meoi->meoi_l2hlen > sizeof (struct ether_header)) {
			/*
			 * This presently assumes a standard VLAN header,
			 * without support for Q-in-Q.
			 */
			ctrl |= V_LSO_ETHHDR_LEN(1);
		}

		switch (meoi->meoi_l3proto) {
		case ETHERTYPE_IPV6:
			ctrl |= F_LSO_IPV6;
			/* FALLTHROUGH */
		case ETHERTYPE_IP:
			ctrl |= V_LSO_IPHDR_LEN(meoi->meoi_l3hlen / 4);
			break;
		default:
			break;
		}

		ctrl |= V_LSO_TCPHDR_LEN(meoi->meoi_l4hlen / 4);

		lso->lso_ctrl = cpu_to_be32(ctrl);
		lso->ipid_ofst = cpu_to_be16(0);
		lso->mss = cpu_to_be16(txinfo->mss);
		lso->seqno_offset = cpu_to_be32(0);
		if (t4_cver_eq(pi->adapter, CHELSIO_T4))
			lso->len = cpu_to_be32(txinfo->len);
		else
			lso->len = cpu_to_be32(V_LSO_T5_XFER_SIZE(txinfo->len));

		cpl = (void *)(lso + 1);

		txq->stats.tso_wrs++;
	} else {
		cpl = (void *)(wr + 1);
	}

	/* Checksum offload */
	switch (csum_to_ctrl(txinfo,
	    CHELSIO_CHIP_VERSION(pi->adapter->params.chip), &ctrl1)) {
	case COS_SUCCESS:
		txq->stats.txcsum++;
		break;
	case COS_FAIL:
		/*
		 * Packet will be going out with checksums which are probably
		 * wrong but there is little we can do now.
		 */
		txq->stats.csum_failed++;
		break;
	default:
		break;
	}

	/* CPL header */
	cpl->ctrl0 = cpu_to_be32(V_TXPKT_OPCODE(CPL_TX_PKT_XT) |
	    V_TXPKT_INTF(pi->tx_chan) | V_TXPKT_PF(pi->adapter->pf));
	cpl->pack = 0;
	cpl->len = cpu_to_be16(txinfo->len);
	cpl->ctrl1 = cpu_to_be64(ctrl1);

	/* Software descriptor */
	txsd = &txq->sdesc[eq->tse_pidx];
	txsd->mp_head = txsd->mp_tail = m;
	txsd->txb_used = txinfo->txb_used;
	txsd->hdls_used = txinfo->hdls_used;
	txsd->credits_used = ncredits;

	txq->stats.txb_used += txinfo->txb_used / TXB_CHUNK;
	txq->stats.hdl_used += txinfo->hdls_used;

	t4_tx_incr_pending(txq, ncredits);

	/* SGL */
	dst = (void *)(cpl + 1);
	if (txinfo->nsegs > 0) {
		txq->stats.sgl_wrs++;
		copy_to_txd(eq, (void *)&txinfo->sgl, &dst, txinfo->nflits * 8);

		/* Need to zero-pad to a 16 byte boundary if not on one */
		if ((uintptr_t)dst & 0xf)
			*(uint64_t *)dst = 0;

	} else {
		txq->stats.imm_wrs++;
#ifdef DEBUG
		ctrl = txinfo->len;
#endif
		for (; m; m = m->b_cont) {
			copy_to_txd(eq, (void *)m->b_rptr, &dst, MBLKL(m));
#ifdef DEBUG
			ctrl -= MBLKL(m);
#endif
		}
		ASSERT(ctrl == 0);
	}

	txq->stats.txpkt_wrs++;
	return (0);
}

static void
t4_write_flush_wr(struct sge_txq *txq)
{
	t4_sge_eq_t *eq = &txq->eq;

	EQ_LOCK_ASSERT_OWNED(eq);
	ASSERT3U(eq->tse_avail, >, 0);

	const struct fw_eq_flush_wr wr = {
		.opcode = FW_EQ_FLUSH_WR,
		.equiq_to_len16 = BE_32(
		    V_FW_WR_LEN16(sizeof (struct fw_eq_flush_wr) / 16) |
		    F_FW_WR_EQUEQ | F_FW_WR_EQUIQ),
	};
	*(struct fw_eq_flush_wr *)t4_eq_credit(eq, eq->tse_pidx) = wr;

	const struct tx_sdesc txsd = {
		.mp_head = NULL,
		.mp_tail = NULL,
		.txb_used = 0,
		.hdls_used = 0,
		.credits_used = 1,
	};
	txq->sdesc[eq->tse_pidx] = txsd;

	t4_tx_incr_pending(txq, 1);
}

/*
 * Increment the flit pointer by the given number of bytes.
 */
static inline void *
t4_incr_flit(void *flitp, size_t num_bytes)
{
	/* A flit should always start on an 8-byte boundary. */
	ASSERT0(((uintptr_t)flitp + num_bytes) & 0x7);
	return ((void *)((caddr_t)(flitp) + (num_bytes)));
}

static inline void
write_ulp_cpl_sgl(struct port_info *pi, struct sge_txq *txq,
    struct txpkts *txpkts, struct txinfo *txinfo)
{
	struct ulp_txpkt *ulpmc;
	struct ulptx_idata *ulpsc;
	struct cpl_tx_pkt_core *cpl;
	void *flitp = txpkts->flitp;
	uint64_t ctrl;
	caddr_t dst;
	const uintptr_t end = (uintptr_t)txq->eq.tse_spg;

	ASSERT3U(txpkts->npkt, >, 0);

	/* Checksum offload */
	switch (csum_to_ctrl(txinfo,
	    CHELSIO_CHIP_VERSION(pi->adapter->params.chip), &ctrl)) {
	case COS_SUCCESS:
		txq->stats.txcsum++;
		break;
	case COS_FAIL:
		/*
		 * Packet will be going out with checksums which are probably
		 * wrong but there is little we can do now.
		 */
		txq->stats.csum_failed++;
		break;
	default:
		break;
	}

	/*
	 * The previous packet's SGL must have ended at a 16 byte boundary (this
	 * is required by the firmware/hardware).  It follows that flitp cannot
	 * wrap around between the ULPTX master command and ULPTX subcommand (8
	 * bytes each), and that it can not wrap around in the middle of the
	 * cpl_tx_pkt_core either.
	 */
	ASSERT0((uintptr_t)flitp & 0xf);
	ASSERT3U((uintptr_t)flitp + sizeof (*ulpmc), <=, end);

	/* ULP master command */
	ulpmc = flitp;
	ulpmc->cmd_dest = htonl(V_ULPTX_CMD(ULP_TX_PKT) | V_ULP_TXPKT_DEST(0));
	ulpmc->len = htonl(howmany(sizeof (*ulpmc) + sizeof (*ulpsc) +
	    sizeof (*cpl) + FLITS_TO_BYTES(txinfo->nflits), 16));

	flitp = t4_incr_flit(flitp, sizeof (*ulpmc));

	/* We cannot wrap-around between the ULPTX master and subcommand. */
	ASSERT3U((uintptr_t)flitp, <, end);
	ASSERT3U((uintptr_t)flitp + sizeof (*ulpsc), <=, end);

	/* ULP subcommand */
	ulpsc = flitp;
	ulpsc->cmd_more = cpu_to_be32(V_ULPTX_CMD((u32)ULP_TX_SC_IMM) |
	    F_ULP_TX_SC_MORE);
	ulpsc->len = cpu_to_be32(sizeof (struct cpl_tx_pkt_core));

	flitp = t4_incr_flit(flitp, sizeof (*ulpsc));

	/* If we have reached the end, go back to the start of the ring. */
	if ((uintptr_t)flitp == end)
		flitp = txq->eq.tse_ring;

	/* CPL_TX_PKT_XT */
	cpl = flitp;
	cpl->ctrl0 = cpu_to_be32(V_TXPKT_OPCODE(CPL_TX_PKT_XT) |
	    V_TXPKT_INTF(pi->tx_chan) | V_TXPKT_PF(pi->adapter->pf));
	cpl->pack = 0;
	cpl->len = cpu_to_be16(txinfo->len);
	cpl->ctrl1 = cpu_to_be64(ctrl);

	flitp = t4_incr_flit(flitp, sizeof (*cpl));

	/* The CPL cannot wrap-around the end. */
	ASSERT3U((uintptr_t)flitp, <=, end);

	if ((uintptr_t)flitp == end)
		flitp = txq->eq.tse_ring;

	/* SGL for this frame */
	dst = (caddr_t)flitp;
	copy_to_txd(&txq->eq, (void *)&txinfo->sgl, &dst,
	    FLITS_TO_BYTES(txinfo->nflits));
	flitp = (void *)dst;

	/* Zero pad and advance to a 16 byte boundary if not already at one. */
	if (((uintptr_t)flitp & 0xf) != 0) {
		/* A flit should always be on an 8 byte boundary. */
		ASSERT(((uintptr_t)flitp & 0x7) == 0);

		*(uint64_t *)flitp = 0;
		flitp = t4_incr_flit(flitp, FLIT_NUM_BYTES);
		txpkts->nflits++;
	}

	ASSERT0((uintptr_t)flitp & 0xf);

	/*
	 * The SGL can wrap-around, but lets make sure we stayed within the
	 * ring.
	 */
	ASSERT3U((uintptr_t)flitp, <=, end);

	if ((uintptr_t)flitp == end)
		flitp = txq->eq.tse_ring;

	txpkts->flitp = flitp;
}

static inline void
copy_to_txd(t4_sge_eq_t *eq, caddr_t from, caddr_t *to, size_t len)
{
	/*
	 * Technically the maximum WR size is lower, but this assert is just to
	 * make sure nothing funky is going on with len. We subtract one from
	 * the qsize because you can never totally fill the queue.
	 */
	ASSERT3U(len, <=, FLITS_TO_BYTES(EQ_HC_TO_FLITS(eq->tse_qsize - 1)));

	if ((uintptr_t)(*to) + len <= (uintptr_t)eq->tse_spg) {
		bcopy(from, *to, len);
		(*to) += len;
	} else {
		/*
		 * The number of bytes left before the end of the ring (which is
		 * the status page).
		 */
		size_t portion = (uintptr_t)eq->tse_spg - (uintptr_t)(*to);

		ASSERT3U(portion, <, len);
		bcopy(from, *to, portion);
		from += portion;
		portion = len - portion;	/* remaining */
		bcopy(from, eq->tse_ring, portion);
		(*to) = (caddr_t)eq->tse_ring + portion;
	}
}

static void
t4_tx_ring_db(struct sge_txq *txq)
{
	t4_sge_eq_t *eq = &txq->eq;
	struct adapter *sc = txq->port->adapter;
	int val, db_mode;
	t4_doorbells_t db = eq->tse_doorbells;

	EQ_LOCK_ASSERT_OWNED(eq);

	/*
	 * A Write-Combining Work Request implicitly uses a single credit and
	 * only a single credit. If we have produced more than one credit, then
	 * fallback to the Write-Combining UDB, then plain UDB, and finally KDB.
	 */
	if (eq->tse_pending > 1)
		db &= ~DOORBELL_WCWR;

	(void) ddi_dma_sync(eq->tse_ring_dhdl, 0, 0, DDI_DMA_SYNC_FORDEV);

	membar_producer();

	val = V_PIDX(eq->tse_pending);

	db_mode = (1 << (ffs(db) - 1));
	switch (db_mode) {
		case DOORBELL_WCWR: {
			/*
			 * Queues whose 128B doorbell segment fits in
			 * the page do not use relative qid
			 * (udb_qid is always 0).  Only queues with
			 * doorbell segments can do WCWR.
			 */
			ASSERT(eq->tse_udb_qid == 0 && eq->tse_pending == 1);

			const uint16_t credit_idx = eq->tse_pidx != 0 ?
			    eq->tse_pidx - 1 : eq->tse_qsize - 1;
			uint64_t *src = t4_eq_credit(eq, credit_idx);
			volatile uint64_t *dst =
			    (uint64_t *)(eq->tse_udb + UDBS_WR_OFFSET);

			/*
			 * Copy the 8 flits of the host credit to the UDB WCWR
			 * space (the second 64 bytes of the 128 byte segment).
			 */
			const uint_t flit_count =
			    sizeof (t4_eq_host_credit_t) / sizeof (uint64_t);
			for (uint_t i = 0; i < flit_count; i++) {
				/*
				 * Perform the copy directly through the BAR
				 * mapping, rather than using ddi_put64().
				 *
				 * The latter was found to impose a significant
				 * performance burden when called in this loop.
				 */
				dst[i] = src[i];
			}

			membar_producer();
			break;
		}

		case DOORBELL_UDB:
		case DOORBELL_UDBWC:
			ddi_put32(sc->bar2_hdl,
			    (uint32_t *)(eq->tse_udb + UDBS_DB_OFFSET),
			    LE_32(V_QID(eq->tse_udb_qid) | val));
			membar_producer();
			break;

		case DOORBELL_KDB:
			t4_write_reg(sc, MYPF_REG(A_SGE_PF_KDOORBELL),
			    V_QID(eq->tse_cntxt_id) | val);
			break;
	}

	eq->tse_pending = 0;
}

/*
 * Attempt to reclaim consumed host credits from the given Tx EQ. The number of
 * credits to reclaim is specified by 'howmany', but that value is clamped down
 * to the number of credits available for reclaim if it is too large. The mblks
 * associated with the reclaimed credits are freed inline unless a non-NULL
 * 'defer_freemp' is provided; in that case an mblk chain is provided to the
 * caller who is now responsible for freeing.
 *
 * Returns the number of reclaimed host credits.
 *
 * When debugging/analyzing this code it is important to remember that host
 * credits != mblks.
 */
static uint16_t
t4_tx_reclaim_credits(struct sge_txq *txq, uint16_t howmany,
    mblk_t **defer_freemp)
{
	t4_sge_eq_t *eq = &txq->eq;

	EQ_LOCK_ASSERT_OWNED(eq);

	const uint16_t cur_cidx = BE_16(eq->tse_spg->cidx);
	const uint16_t reclaim_avail = (cur_cidx >= eq->tse_cidx) ?
	    (cur_cidx - eq->tse_cidx) :
	    (cur_cidx + eq->tse_qsize - eq->tse_cidx);

	if (reclaim_avail == 0) {
		return (0);
	}

	uint_t txb_freed = 0, hdl_freed = 0;
	uint16_t reclaimed = 0;

	do {
		struct tx_sdesc *txsd = &txq->sdesc[eq->tse_cidx];
		const uint16_t ncredits = txsd->credits_used;

		/* Firmware doesn't return "partial" credits. */
		ASSERT3U(reclaimed + ncredits, <=, reclaim_avail);

		if (txsd->mp_head != NULL) {
			/*
			 * Even when packet content fits entirely in immediate
			 * buffer, the mblk is kept around until the
			 * transmission completes.
			 */
			if (defer_freemp != NULL) {
				/*
				 * Append the mblk chain from this descriptor
				 * onto the end of the defer list.
				 *
				 * In the case that this is the first mblk we
				 * have processed, the below assignment will
				 * communicate the head of the chain to the
				 * caller.
				 */
				*defer_freemp = txsd->mp_head;
				defer_freemp = &txsd->mp_tail->b_next;
			} else {
				freemsgchain(txsd->mp_head);
			}
			txsd->mp_head = txsd->mp_tail = NULL;
		} else {
			/*
			 * If mblk is NULL, this has to be the software
			 * descriptor for a credit flush work request.
			 */
			ASSERT0(txsd->txb_used);
			ASSERT0(txsd->hdls_used);
			ASSERT3U(ncredits, ==, 1);
		}

		txb_freed += txsd->txb_used;
		hdl_freed += txsd->hdls_used;
		reclaimed += ncredits;

		eq->tse_cidx += ncredits;
		if (eq->tse_cidx >= eq->tse_qsize) {
			eq->tse_cidx -= eq->tse_qsize;
		}
	} while (reclaimed < reclaim_avail && reclaimed < howmany);

	eq->tse_avail += reclaimed;
	txq->txb_avail += txb_freed;
	txq->tx_dhdl_avail += hdl_freed;

	ASSERT3U(eq->tse_avail, <, eq->tse_qsize);
	ASSERT3U(txq->tx_dhdl_avail, <=, txq->tx_dhdl_total);

	for (; hdl_freed; hdl_freed--) {
		(void) ddi_dma_unbind_handle(txq->tx_dhdl[txq->tx_dhdl_cidx]);
		if (++txq->tx_dhdl_cidx == txq->tx_dhdl_total)
			txq->tx_dhdl_cidx = 0;
	}

	return (reclaimed);
}

static int
t4_handle_cpl_msg(t4_sge_iq_t *iq, const struct rss_header *rss, mblk_t *mp)
{
	const uint8_t opcode = rss->opcode;

	DTRACE_PROBE4(t4__cpl_msg, t4_sge_iq_t *, iq, uint8_t, opcode,
	    const struct rss_header *, rss, mblk_t *, mp);

	switch (opcode) {
	case CPL_FW4_MSG:
	case CPL_FW6_MSG:
		ASSERT3P(mp, ==, NULL);
		return (t4_handle_fw_msg(iq, rss));
	case CPL_SGE_EGR_UPDATE:
		ASSERT3P(mp, ==, NULL);
		t4_sge_egr_update(iq, rss);
		return (0);
	case CPL_RX_PKT:
		/*
		 * Packet RX is expected to be handled in t4_process_rx_iq().
		 * CPL messages of such a type should not make it here.
		 */
		cxgb_printf(iq->tsi_adapter->dip, CE_WARN,
		    "unexpected unhandled CPL_RX_PKT msg");
		freemsg(mp);
		return (0);
	default:
		cxgb_printf(iq->tsi_adapter->dip, CE_WARN,
		    "unhandled CPL opcode 0x%02x", opcode);
		if (mp != NULL) {
			freemsg(mp);
		}
		return (0);
	}
}

static int
t4_handle_fw_msg(t4_sge_iq_t *iq, const struct rss_header *rss)
{
	const struct cpl_fw6_msg *cpl = (const void *)(rss + 1);
	const uint8_t msg_type = cpl->type;
	const struct rss_header *rss2;
	struct adapter *sc = iq->tsi_adapter;

	DTRACE_PROBE3(t4__fw_msg, t4_sge_iq_t *, iq, uint8_t, msg_type,
	    const struct rss_header *, rss);

	switch (msg_type) {
	case FW_TYPE_RSSCPL:	/* also synonym for FW6_TYPE_RSSCPL */
		rss2 = (const struct rss_header *)&cpl->data[0];
		return (t4_handle_cpl_msg(iq, rss2, NULL));
	case FW6_TYPE_CMD_RPL:
		return (t4_handle_fw_rpl(sc, &cpl->data[0]));
	default:
		cxgb_printf(sc->dip, CE_WARN,
		    "unhandled fw_msg type 0x%02x", msg_type);
		return (0);
	}
}

static void
t4_fl_ring_db(struct sge_fl *fl)
{
	struct adapter *sc = t4_fl_to_iq(fl)->tsi_adapter;
	t4_sge_eq_t *eq = &fl->eq;

	EQ_LOCK_ASSERT_OWNED(eq);

	(void) ddi_dma_sync(eq->tse_ring_dhdl, 0, 0, DDI_DMA_SYNC_FORDEV);

	membar_producer();

	t4_write_reg(sc, MYPF_REG(A_SGE_PF_KDOORBELL),
	    sc->params.arch.sge_fl_db |
	    V_QID(eq->tse_cntxt_id) |
	    V_PIDX(eq->tse_pending));

	eq->tse_pending = 0;
}

static void
t4_sge_egr_update(t4_sge_iq_t *iq, const struct rss_header *rss)
{
	struct adapter *sc = iq->tsi_adapter;
	const struct cpl_sge_egr_update *cpl = t4_rss_payload(rss);
	const uint_t qid = G_EGR_QID(BE_32(cpl->opcode_qid));
	struct sge_txq *txq = (struct sge_txq *)(*t4_eqmap_slot(sc, qid));
	t4_sge_eq_t *eq = &txq->eq;

	/*
	 * Get a "live" snapshot of the flags and PIDX state from the TXQ.
	 *
	 * This is done without the protection of the TXQ/EQ lock, since the
	 * gathered information is used to avoid contending on that lock for the
	 * reclaim.
	 */
	membar_consumer();
	const uint16_t live_pidx = BE_16(eq->tse_pidx);
	const t4_eq_flags_t live_flags = eq->tse_flags;

	if ((live_flags & EQ_CORKED) == 0 &&
	    (cpl->pidx != cpl->cidx || live_pidx != cpl->cidx)) {
		/*
		 * A reclaim of the ring can be skipped if:
		 *
		 * 1. The EQ is not in the "corked" state, where it was unable
		 *    allocate descriptors (or memory) while attempting to place
		 *    a packet in the TXQ.
		 *
		 * 2. There are outstanding transmit descriptors in the EQ which
		 *    will trigger a subsequent SGE_EGR_UPDATE notification.
		 *
		 * When those conditions are met, it is safe to skip performing
		 * a reclaim here, reducing the chance that we contend with
		 * other transmission activity against the TXQ.
		 */
		DTRACE_PROBE2(t4__elide__reclaim,
		    struct sge_txq *, txq, struct cpl_sge_egr_update *, cpl);
		return;
	}

	mblk_t *freemp = NULL;
	bool do_mac_update = false;

	TXQ_LOCK(txq);
	(void) t4_tx_reclaim_credits(txq, eq->tse_qsize, &freemp);
	if (eq->tse_flags & EQ_CORKED && eq->tse_avail != 0) {
		do_mac_update = true;
		eq->tse_flags &= ~EQ_CORKED;
	}
	TXQ_UNLOCK(txq);

	freemsgchain(freemp);
	if (do_mac_update) {
		t4_mac_tx_update(txq->port, txq);
	}
}

#define	KS_UINIT(x)	kstat_named_init(&kstatp->x, #x, KSTAT_DATA_ULONG)
#define	KS_CINIT(x)	kstat_named_init(&kstatp->x, #x, KSTAT_DATA_CHAR)
#define	KS_U_SET(x, y)	kstatp->x.value.ul = (y)
#define	KS_U_FROM(x, y)	kstatp->x.value.ul = (y)->stats.x
#define	KS_C_SET(x, ...)	\
			(void) snprintf(kstatp->x.value.c, 16,  __VA_ARGS__)

/*
 * cxgbe:X:config
 */
struct cxgbe_port_config_kstats {
	kstat_named_t idx;
	kstat_named_t rxq_count;
	kstat_named_t txq_count;
	kstat_named_t rxq_start;
	kstat_named_t txq_start;
	kstat_named_t controller;
	kstat_named_t factory_mac_address;
};

/*
 * cxgbe:X:info
 */
struct cxgbe_port_info_kstats {
	kstat_named_t transceiver;
	kstat_named_t rx_ovflow0;
	kstat_named_t rx_ovflow1;
	kstat_named_t rx_ovflow2;
	kstat_named_t rx_ovflow3;
	kstat_named_t rx_trunc0;
	kstat_named_t rx_trunc1;
	kstat_named_t rx_trunc2;
	kstat_named_t rx_trunc3;
	kstat_named_t tx_pause;
	kstat_named_t rx_pause;
};

static kstat_t *
setup_port_config_kstats(struct port_info *pi)
{
	kstat_t *ksp;
	struct cxgbe_port_config_kstats *kstatp;
	int ndata;
	dev_info_t *pdip = ddi_get_parent(pi->dip);
	uint8_t *ma = &pi->hw_addr[0];

	ndata = sizeof (struct cxgbe_port_config_kstats) /
	    sizeof (kstat_named_t);

	ksp = kstat_create(T4_PORT_NAME, ddi_get_instance(pi->dip), "config",
	    "net", KSTAT_TYPE_NAMED, ndata, 0);
	if (ksp == NULL) {
		cxgb_printf(pi->dip, CE_WARN, "failed to initialize kstats.");
		return (NULL);
	}

	kstatp = (struct cxgbe_port_config_kstats *)ksp->ks_data;

	KS_UINIT(idx);
	KS_UINIT(rxq_count);
	KS_UINIT(txq_count);
	KS_UINIT(rxq_start);
	KS_UINIT(txq_start);
	KS_CINIT(controller);
	KS_CINIT(factory_mac_address);

	KS_U_SET(idx, pi->port_id);
	KS_U_SET(rxq_count, pi->rxq_count);
	KS_U_SET(txq_count, pi->txq_count);
	KS_U_SET(rxq_start, pi->rxq_start);
	KS_U_SET(txq_start, pi->txq_start);
	KS_C_SET(controller, "%s%d", ddi_driver_name(pdip),
	    ddi_get_instance(pdip));
	KS_C_SET(factory_mac_address, "%02X%02X%02X%02X%02X%02X",
	    ma[0], ma[1], ma[2], ma[3], ma[4], ma[5]);

	/* Do NOT set ksp->ks_update.  These kstats do not change. */

	/* Install the kstat */
	ksp->ks_private = (void *)pi;
	kstat_install(ksp);

	return (ksp);
}

static kstat_t *
setup_port_info_kstats(struct port_info *pi)
{
	kstat_t *ksp;
	struct cxgbe_port_info_kstats *kstatp;
	int ndata;

	ndata = sizeof (struct cxgbe_port_info_kstats) / sizeof (kstat_named_t);

	ksp = kstat_create(T4_PORT_NAME, ddi_get_instance(pi->dip), "info",
	    "net", KSTAT_TYPE_NAMED, ndata, 0);
	if (ksp == NULL) {
		cxgb_printf(pi->dip, CE_WARN, "failed to initialize kstats.");
		return (NULL);
	}

	kstatp = (struct cxgbe_port_info_kstats *)ksp->ks_data;

	KS_CINIT(transceiver);
	KS_UINIT(rx_ovflow0);
	KS_UINIT(rx_ovflow1);
	KS_UINIT(rx_ovflow2);
	KS_UINIT(rx_ovflow3);
	KS_UINIT(rx_trunc0);
	KS_UINIT(rx_trunc1);
	KS_UINIT(rx_trunc2);
	KS_UINIT(rx_trunc3);
	KS_UINIT(tx_pause);
	KS_UINIT(rx_pause);

	/* Install the kstat */
	ksp->ks_update = update_port_info_kstats;
	ksp->ks_private = (void *)pi;
	kstat_install(ksp);

	return (ksp);
}

static int
update_port_info_kstats(kstat_t *ksp, int rw)
{
	struct cxgbe_port_info_kstats *kstatp =
	    (struct cxgbe_port_info_kstats *)ksp->ks_data;
	struct port_info *pi = ksp->ks_private;
	static const char *mod_str[] = { NULL, "LR", "SR", "ER", "TWINAX",
	    "active TWINAX", "LRM" };
	uint32_t bgmap;

	if (rw == KSTAT_WRITE)
		return (0);

	if (pi->mod_type == FW_PORT_MOD_TYPE_NONE)
		KS_C_SET(transceiver, "unplugged");
	else if (pi->mod_type == FW_PORT_MOD_TYPE_UNKNOWN)
		KS_C_SET(transceiver, "unknown");
	else if (pi->mod_type == FW_PORT_MOD_TYPE_NOTSUPPORTED)
		KS_C_SET(transceiver, "unsupported");
	else if (pi->mod_type > 0 && pi->mod_type < ARRAY_SIZE(mod_str))
		KS_C_SET(transceiver, "%s", mod_str[pi->mod_type]);
	else
		KS_C_SET(transceiver, "type %d", pi->mod_type);

#define	GET_STAT(name) t4_read_reg64(pi->adapter, \
	    PORT_REG(pi->port_id, A_MPS_PORT_STAT_##name##_L))
#define	GET_STAT_COM(name) t4_read_reg64(pi->adapter, \
	    A_MPS_STAT_##name##_L)

	bgmap = G_NUMPORTS(t4_read_reg(pi->adapter, A_MPS_CMN_CTL));
	if (bgmap == 0)
		bgmap = (pi->port_id == 0) ? 0xf : 0;
	else if (bgmap == 1)
		bgmap = (pi->port_id < 2) ? (3 << (2 * pi->port_id)) : 0;
	else
		bgmap = 1;

	KS_U_SET(rx_ovflow0, (bgmap & 1) ?
	    GET_STAT_COM(RX_BG_0_MAC_DROP_FRAME) : 0);
	KS_U_SET(rx_ovflow1, (bgmap & 2) ?
	    GET_STAT_COM(RX_BG_1_MAC_DROP_FRAME) : 0);
	KS_U_SET(rx_ovflow2, (bgmap & 4) ?
	    GET_STAT_COM(RX_BG_2_MAC_DROP_FRAME) : 0);
	KS_U_SET(rx_ovflow3, (bgmap & 8) ?
	    GET_STAT_COM(RX_BG_3_MAC_DROP_FRAME) : 0);
	KS_U_SET(rx_trunc0,  (bgmap & 1) ?
	    GET_STAT_COM(RX_BG_0_MAC_TRUNC_FRAME) : 0);
	KS_U_SET(rx_trunc1,  (bgmap & 2) ?
	    GET_STAT_COM(RX_BG_1_MAC_TRUNC_FRAME) : 0);
	KS_U_SET(rx_trunc2,  (bgmap & 4) ?
	    GET_STAT_COM(RX_BG_2_MAC_TRUNC_FRAME) : 0);
	KS_U_SET(rx_trunc3,  (bgmap & 8) ?
	    GET_STAT_COM(RX_BG_3_MAC_TRUNC_FRAME) : 0);

	KS_U_SET(tx_pause, GET_STAT(TX_PORT_PAUSE));
	KS_U_SET(rx_pause, GET_STAT(RX_PORT_PAUSE));

	return (0);

}

/*
 * cxgbe:X:rxqY
 */
struct rxq_kstats {
	kstat_named_t rxcsum;
	kstat_named_t rxpkts;
	kstat_named_t rxbytes;
};

static kstat_t *
setup_rxq_kstats(struct port_info *pi, struct sge_rxq *rxq, uint_t q_idx)
{
	struct kstat *ksp;
	struct rxq_kstats *kstatp;
	int ndata;
	char str[16];

	ndata = sizeof (struct rxq_kstats) / sizeof (kstat_named_t);
	(void) snprintf(str, sizeof (str), "rxq%u", q_idx);

	ksp = kstat_create(T4_PORT_NAME, ddi_get_instance(pi->dip), str, "rxq",
	    KSTAT_TYPE_NAMED, ndata, 0);
	if (ksp == NULL) {
		cxgb_printf(pi->dip, CE_WARN,
		    "%s: failed to initialize rxq kstats for queue %u.",
		    __func__, q_idx);
		return (NULL);
	}

	kstatp = (struct rxq_kstats *)ksp->ks_data;

	KS_UINIT(rxcsum);
	KS_UINIT(rxpkts);
	KS_UINIT(rxbytes);

	ksp->ks_update = update_rxq_kstats;
	ksp->ks_private = (void *)rxq;
	kstat_install(ksp);

	return (ksp);
}

static int
update_rxq_kstats(kstat_t *ksp, int rw)
{
	struct rxq_kstats *kstatp = (struct rxq_kstats *)ksp->ks_data;
	struct sge_rxq *rxq = ksp->ks_private;

	if (rw == KSTAT_WRITE)
		return (0);

	KS_U_FROM(rxcsum, rxq);
	KS_U_FROM(rxpkts, rxq);
	KS_U_FROM(rxbytes, rxq);

	return (0);
}

/*
 * cxgbe:X:txqY
 */
struct txq_kstats {
	kstat_named_t txcsum;
	kstat_named_t tso_wrs;
	kstat_named_t imm_wrs;
	kstat_named_t sgl_wrs;
	kstat_named_t txpkt_wrs;
	kstat_named_t txpkts_wrs;
	kstat_named_t txpkts_pkts;
	kstat_named_t txb_used;
	kstat_named_t hdl_used;
	kstat_named_t txb_full;
	kstat_named_t dma_hdl_failed;
	kstat_named_t dma_map_failed;
	kstat_named_t qfull;
	kstat_named_t pullup_early;
	kstat_named_t pullup_late;
	kstat_named_t pullup_failed;
	kstat_named_t csum_failed;
};

static kstat_t *
setup_txq_kstats(struct port_info *pi, struct sge_txq *txq, int idx)
{
	struct kstat *ksp;
	struct txq_kstats *kstatp;
	int ndata;
	char str[16];

	ndata = sizeof (struct txq_kstats) / sizeof (kstat_named_t);
	(void) snprintf(str, sizeof (str), "txq%u", idx);

	ksp = kstat_create(T4_PORT_NAME, ddi_get_instance(pi->dip), str, "txq",
	    KSTAT_TYPE_NAMED, ndata, 0);
	if (ksp == NULL) {
		cxgb_printf(pi->dip, CE_WARN,
		    "%s: failed to initialize txq kstats for queue %d.",
		    __func__, idx);
		return (NULL);
	}

	kstatp = (struct txq_kstats *)ksp->ks_data;

	KS_UINIT(txcsum);
	KS_UINIT(tso_wrs);
	KS_UINIT(imm_wrs);
	KS_UINIT(sgl_wrs);
	KS_UINIT(txpkt_wrs);
	KS_UINIT(txpkts_wrs);
	KS_UINIT(txpkts_pkts);
	KS_UINIT(txb_used);
	KS_UINIT(hdl_used);
	KS_UINIT(txb_full);
	KS_UINIT(dma_hdl_failed);
	KS_UINIT(dma_map_failed);
	KS_UINIT(qfull);
	KS_UINIT(pullup_early);
	KS_UINIT(pullup_late);
	KS_UINIT(pullup_failed);
	KS_UINIT(csum_failed);

	ksp->ks_update = update_txq_kstats;
	ksp->ks_private = (void *)txq;
	kstat_install(ksp);

	return (ksp);
}

static int
update_txq_kstats(kstat_t *ksp, int rw)
{
	struct txq_kstats *kstatp = (struct txq_kstats *)ksp->ks_data;
	struct sge_txq *txq = ksp->ks_private;

	if (rw == KSTAT_WRITE)
		return (0);

	KS_U_FROM(txcsum, txq);
	KS_U_FROM(tso_wrs, txq);
	KS_U_FROM(imm_wrs, txq);
	KS_U_FROM(sgl_wrs, txq);
	KS_U_FROM(txpkt_wrs, txq);
	KS_U_FROM(txpkts_wrs, txq);
	KS_U_FROM(txpkts_pkts, txq);
	KS_U_FROM(txb_used, txq);
	KS_U_FROM(hdl_used, txq);
	KS_U_FROM(txb_full, txq);
	KS_U_FROM(dma_hdl_failed, txq);
	KS_U_FROM(dma_map_failed, txq);
	KS_U_FROM(qfull, txq);
	KS_U_FROM(pullup_early, txq);
	KS_U_FROM(pullup_late, txq);
	KS_U_FROM(pullup_failed, txq);
	KS_U_FROM(csum_failed, txq);

	return (0);
}

static int rxbuf_ctor(void *, void *, int);
static void rxbuf_dtor(void *, void *);

static kmem_cache_t *
rxbuf_cache_create(struct rxbuf_cache_params *p)
{
	char name[32];

	(void) snprintf(name, sizeof (name), "%s%d_rxbuf_cache",
	    ddi_driver_name(p->dip), ddi_get_instance(p->dip));

	return kmem_cache_create(name, sizeof (struct rxbuf), _CACHE_LINE_SIZE,
	    rxbuf_ctor, rxbuf_dtor, NULL, p, NULL, 0);
}

static struct rxbuf *
rxbuf_alloc(kmem_cache_t *cache, int kmflags)
{
	struct rxbuf *rxb;

	rxb = kmem_cache_alloc(cache, kmflags);
	if (rxb != NULL) {
		rxb->ref_cnt = 1;
		rxb->cache = cache;
	}

	return (rxb);
}

/*
 * This is normally called via the rxb's freefunc, when an mblk referencing the
 * rxb is freed.
 */
static void
rxbuf_free(struct rxbuf *rxb)
{
	if (atomic_dec_uint_nv(&rxb->ref_cnt) == 0)
		kmem_cache_free(rxb->cache, rxb);
}

static int
rxbuf_ctor(void *arg1, void *arg2, int kmflag)
{
	struct rxbuf *rxb = arg1;
	struct rxbuf_cache_params *p = arg2;
	size_t real_len;
	ddi_dma_cookie_t cookie;
	uint_t ccount = 0;
	int (*callback)(caddr_t);
	int rc = ENOMEM;

	if ((kmflag & KM_NOSLEEP) != 0)
		callback = DDI_DMA_DONTWAIT;
	else
		callback = DDI_DMA_SLEEP;

	rc = ddi_dma_alloc_handle(p->dip, &p->dma_attr_rx, callback, 0,
	    &rxb->dhdl);
	if (rc != DDI_SUCCESS)
		return (rc == DDI_DMA_BADATTR ? EINVAL : ENOMEM);

	rc = ddi_dma_mem_alloc(rxb->dhdl, p->buf_size, &p->acc_attr_rx,
	    DDI_DMA_STREAMING, callback, 0, &rxb->va, &real_len, &rxb->ahdl);
	if (rc != DDI_SUCCESS) {
		rc = ENOMEM;
		goto fail1;
	}

	rc = ddi_dma_addr_bind_handle(rxb->dhdl, NULL, rxb->va, p->buf_size,
	    DDI_DMA_READ | DDI_DMA_STREAMING, NULL, NULL, &cookie, &ccount);
	if (rc != DDI_DMA_MAPPED) {
		if (rc == DDI_DMA_INUSE)
			rc = EBUSY;
		else if (rc == DDI_DMA_TOOBIG)
			rc = E2BIG;
		else
			rc = ENOMEM;
		goto fail2;
	}

	if (ccount != 1) {
		rc = E2BIG;
		goto fail3;
	}

	rxb->ref_cnt = 0;
	rxb->buf_size = p->buf_size;
	rxb->freefunc.free_arg = (caddr_t)rxb;
	rxb->freefunc.free_func = rxbuf_free;
	rxb->ba = cookie.dmac_laddress;

	return (0);

fail3:	(void) ddi_dma_unbind_handle(rxb->dhdl);
fail2:	ddi_dma_mem_free(&rxb->ahdl);
fail1:	ddi_dma_free_handle(&rxb->dhdl);
	return (rc);
}

static void
rxbuf_dtor(void *arg1, void *arg2)
{
	struct rxbuf *rxb = arg1;

	(void) ddi_dma_unbind_handle(rxb->dhdl);
	ddi_dma_mem_free(&rxb->ahdl);
	ddi_dma_free_handle(&rxb->dhdl);
}
