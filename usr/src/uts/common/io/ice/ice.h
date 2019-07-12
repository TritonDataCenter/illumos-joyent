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
 */

#ifndef _ICE_H
#define	_ICE_H

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/pci.h>
#include <sys/mac_provider.h>
#include <sys/mac_ether.h>
#include <sys/ethernet.h>
#include <sys/sysmacros.h>
#include <sys/vlan.h>
#include <sys/disp.h>
#include <sys/taskq_impl.h>
#include <sys/random.h>

#include "ice_hw.h"
#include "ice_controlq.h"

/*
 * Intel 100 GbE Ethernet Driver
 */

#ifdef __cplusplus
extern "C" {
#endif

#define	ICE_MODULE_NAME	"ice"

/*
 * The primary memory mapped register set is found in the first bar (0x10 in
 * config space). This is index 1 in the regs tuple. Index 0 is for config
 * space.
 */
#define	ICE_REG_NUMBER	1

/*
 * The minimum alignment required for the control queue entries. This is defined
 * by PF_FW_ATQBAL and PF_FW_ARQBAL descriptions.
 */
#define	ICE_DMA_CONTROLQ_ALIGN	64

/*
 * Several places in the datasheet, Intel indicates that the maximum flash page
 * that we can work with is 4096 bytes and that the various commands cannot
 * cross this sector.
 */
#define	ICE_NVM_SECTOR_SIZE	4096

/*
 * Hardware supports up to 768 VSIs. This is mentioned in Table 1-1. E810
 * Features Summary and several other places in the document.
 */
#define	ICE_MAX_VSIS	768

/*
 * Hardware supports up to 2048 receive queues.
 */
#define	ICE_MAX_RX_QUEUES	2048

/*
 * Hardware supports a larger number of transmit queues; however, a given PF
 * driver may only have up to 256 transmit queues that support TSO. As every
 * transmit queue must support TSO to make sense, we limit the number of TX
 * queues to 256.
 */
#define	ICE_MAX_TX_QUEUES	256

/*
 * These are the logical different kinds of types that a VSI can be.
 */
typedef enum ice_vsi_type {
	ICE_VSI_TYPE_PF,
	ICE_VSI_TYPE_VF,
	ICE_VSI_TYPE_VMDQ2,
	ICE_VSI_TYPE_EMP_MNG
} ice_vsi_type_t;

/*
 * Set up some reasonable defaults for the controlq. There is both an send queue
 * and a receive queue. We post events which are replied to on the send queue.
 * Firmware posts events to us (the driver) on the send queue. Firmware only
 * really processes a single command at any given time, therefore the number of
 * outstanding slots that we need to commands that we send is low. We want just
 * enough events for the receive queue that we'll likely never end up in an
 * overflow situation. In terms of the number of entries, right now Intel
 * defaults to having 64 for both queues in their implementations. We opt to use
 * that for the time being for the receive side. For the send side, we only
 * bother with having a quarter of that.
 *
 * Each entry on the queue may need an associated indirect buffer and all
 * receive queue entries must have one. We always allcoate the contorl queue's
 * maximum size for this.
 */
#define	ICE_CONTROLQ_BUFSIZE	ICE_CQ_MAX_BUF
#define	ICE_CONTROLQ_RQ_NENTS	64
#define	ICE_CONTROLQ_SQ_NENTS	64

/*
 * Wrappers around ddi_dma_sync(). We should never trigger the failure
 * conditions that are documented because we always sync the whole region. We
 * VERIFY this on debug builds and assert it on non-debug.
 */
#ifdef	DEBUG
#define	ICE_DMA_SYNC(dma, flag)	VERIFY0(ddi_dma_sync( \
					    (dma).idb_dma_handle, 0, 0, \
					    (flag)))
#else
#define	ICE_DMA_SYNC(dma, flag)	((void) ddi_dma_sync( \
					    (dma).idb_dma_handle, 0, 0, \
					    (flag)))
#endif

/*
 * Expected major version of the capabilities that we look for.
 */
#define	ICE_CAP_MAJOR_VSI	1
#define	ICE_CAP_MAJOR_RSS	1
#define	ICE_CAP_MAJOR_MTU	1
#define	ICE_CAP_MAJOR_TXQ	1
#define	ICE_CAP_MAJOR_RXQ	1
#define	ICE_CAP_MAJOR_MSI_X	1

/*
 * Interrupt Rate Limiting values. These values are defined in units of 2us;
 * however, the hardware itself operates in either 2us or 4us granularities
 * depending on the aggregate bandwidth, which changes the internal clock
 * granularity. The ITR guarantees a time between interrupts. We write to the
 * registers to basically indicate how many interrupts per second of a given
 * type we'd like to allow.
 *
 * The hardware supports three different classes of ITRs. We opt to use these as
 * one for all RX class interrupts, one for all TX class interrupts, and one for
 * other type interrupts. While different ITR sources may share the same
 * interrupt, this allows us to have a little bit of uniformity.
 *
 * These defaults values are such that the RX ITR allows for up to 20k
 * interrupts/second with a gap of 50us, TX interrupts allow for up to 5k /
 * second with a gap of 200 us, and 1000 interrupts / second for other
 * interrupts with a gap of 1ms between them. While the ITR for RX interrupts is
 * dramatically smaller, than the others, this is in part because we will end up
 * transitioning to polling mode, so we don't want to have that much of a delay.
 */
#define	ICE_ITR_MIN		0x0000
#define	ICE_ITR_MAX		0x0FF0
#define	ICE_ITR_RX_DEFAULT	0x0019
#define	ICE_ITR_TX_DEFAULT	0x0064
#define	ICE_ITR_OTHER_DEFAULT	0x01F4

typedef enum ice_itr_index {
	ICE_ITR_INDEX_RX	= 0x0,
	ICE_ITR_INDEX_TX	= 0x1,
	ICE_ITR_INDEX_OTHER	= 0x2,
	ICE_ITR_INDEX_NONE	= 0x3
} ice_itr_index_t;

#define	ICE_ITR_GRAN		0x2
#define	ICE_ITR_GRAN_25GBE	0x4

/*
 * This is the default MTU that we'll enable on a link.
 */
#define	ICE_MTU_DEFAULT		1500

/*
 * This represents a single logical DMA allocation. At the moment we only use
 * this for entries that a single cookie.  XXX How should we change this when
 * there are more?
 */
typedef struct ice_dma_buffer {
	caddr_t			idb_va;
	size_t			idb_len;
	ddi_acc_handle_t	idb_acc_handle;
	ddi_dma_handle_t	idb_dma_handle;
	uint_t			idb_ncookies;
	ddi_dma_cookie_t	idb_cookie;
} ice_dma_buffer_t;

typedef enum ice_controlq_flags {
	ICE_CONTROLQ_F_ENABLED	= 1 << 0,
	ICE_CONTROLQ_F_BUSY	= 1 << 1,
	ICE_CONTROLQ_F_DEAD	= 1 << 2
} ice_controlq_flags_t;

typedef enum ice_vsi_flags {
	ICE_VSI_F_POOL_ALLOC	= 1 << 0,
	ICE_VSI_F_ACTIVE	= 1 << 1,
	ICE_VSI_F_RSS_SET	= 1 << 2
} ice_vsi_flags_t;

typedef struct ice_vsi {
	list_node_t		ivsi_node;
	boolean_t		ivsi_pool_alloc;
	uint_t			ivsi_id;
	ice_vsi_type_t		ivsi_type;
	ice_vsi_flags_t		ivsi_flags;
	ice_hw_vsi_context_t	ivsi_ctxt;
	uint16_t		ivsi_nrxq;
	uint16_t		ivsi_frxq;
} ice_vsi_t;

/*
 * A controlq structure represents a single communication ring that is used with
 * hardware.
 */
typedef struct ice_controlq {
	kmutex_t		icq_lock;
	kcondvar_t		icq_cv;
	ice_controlq_flags_t	icq_flags;
	uint_t			icq_nents;
	uint16_t		icq_bufsize;
	ice_dma_buffer_t	icq_dma;
	ice_dma_buffer_t	*icq_data_dma;

	/*
	 * Ring registers. These are the appropriate version of the registers
	 * for indicating activity on the ring as these can vary based on
	 * whether it's for the PF, a VF, or a mailbox. We only set up and
	 * enable the PF today.
	 */
	uintptr_t		icq_reg_head;
	uintptr_t		icq_reg_tail;
	uintptr_t		icq_reg_len;
	uintptr_t		icq_reg_base_hi;
	uintptr_t		icq_reg_base_lo;

	/*
	 * Ring state
	 */
	ice_cq_desc_t		*icq_desc;
	uint_t			icq_head;
	uint_t			icq_tail;
} ice_controlq_t;

/*
 * Consolidated information about firmware all in one structure.
 */
typedef struct ice_fw_info {
	uint8_t		ifi_fw_branch;
	uint8_t		ifi_fw_major;
	uint8_t		ifi_fw_minor;
	uint8_t		ifi_fw_patch;
	uint8_t		ifi_aq_branch;
	uint8_t		ifi_aq_major;
	uint8_t		ifi_aq_minor;
	uint8_t		ifi_aq_patch;
	uint32_t	ifi_rom_build;
	uint32_t	ifi_fw_build;
	uint16_t	ifi_nvm_dev_start;
	uint16_t	ifi_nvm_map_ver;
	uint16_t	ifi_nvm_img_ver;
	uint16_t	ifi_nvm_struct_ver;
	uint32_t	ifi_nvm_eetrack;
	uint32_t	ifi_nvm_eetrack_orig;
} ice_fw_info_t;

/*
 * NVM information
 */
typedef enum ice_nvm_flags {
	/*
	 * This bit is used to indicate that the NVM is present and therefore we
	 * can try and perform reads.
	 */
	ICE_NVM_PRESENT	= 0x1 << 0,
	/*
	 * This bit is used to indicate if the NVM is in 'blank' mode or not.
	 * When it's in 'blank' mode, we cannot proceed with accessing it
	 * via the admin queue commands.
	 */
	ICE_NVM_BLANK	= 0x1 << 1,
	/*
	 * This bit is used to track the fact that we have the NVM locked
	 * through the admin queue's NVM request resource command.
	 */
	ICE_NVM_LOCKED	= 0x1 << 2
} ice_nvm_flags_t;

typedef struct ice_nvm {
	kmutex_t in_lock;
	ice_nvm_flags_t	in_flags;
	uint32_t in_sector;
	uint32_t in_size;
} ice_nvm_t;

/*
 * The task structure represents asynchronous work that we need to do based on
 * events that come in. This is meant to be a centralized way to handle issues
 * that have come in via firmware responses or device interrupts.
 */
typedef enum ice_work_task {
	ICE_WORK_NONE			= 0,
	ICE_WORK_CONTROLQ		= 1 << 0,
	ICE_WORK_NEED_RESET		= 1 << 1,
	ICE_WORK_RESET_DETECTED		= 1 << 2,
	ICE_WORK_LINK_STATUS_EVENT	= 1 << 3
} ice_work_task_t;

typedef enum ice_task_status {
	ICE_TASK_S_DISPATCHED	= 1 << 0,
	ICE_TASK_S_RUNNING	= 1 << 1
} ice_task_status_t;

typedef struct ice_task {
	taskq_t			*itk_tq;
	taskq_ent_t		itk_ent;
	kmutex_t		itk_lock;
	ice_task_status_t	itk_state;
	ice_work_task_t		itk_work;
} ice_task_t;

typedef enum ice_lse_state {
	ICE_LSE_STATE_ENABLE	= 0x1 << 0,
	ICE_LSE_STATE_UPDATING	= 0x1 << 1
} ice_lse_state_t;

typedef enum ice_attach_seq {
	ICE_ATTACH_FM		= 0x1 << 0,
	ICE_ATTACH_PCI		= 0x1 << 1,
	ICE_ATTACH_REGS		= 0x1 << 2,
	ICE_ATTACH_CONTROLQ	= 0x1 << 3,
	ICE_ATTACH_NVM		= 0x1 << 4,
	ICE_ATTACH_CAPS		= 0x1 << 5,
	ICE_ATTACH_LSE		= 0x1 << 6,
	ICE_ATTACH_PBA		= 0x1 << 7,
	ICE_ATTACH_INTR_ALLOC	= 0x1 << 8,
	ICE_ATTACH_INTR_HANDLER	= 0x1 << 9,
	ICE_ATTACH_TASK		= 0x1 << 10,
	ICE_ATTACH_VSI		= 0x1 << 11,
	ICE_ATTACH_MAC		= 0x1 << 12,
	ICE_ATTACH_INTR_ENABLE	= 0x1 << 13
} ice_attach_seq_t;

/*
 * This structure is the primary per-physical function state.
 */
typedef struct ice {
	dev_info_t	*ice_dip;
	int		ice_inst;

	/*
	 * This tracks how far we are in attach.
	 */
	ice_attach_seq_t	ice_seq;

	/*
	 * FMA state
	 */
	int			ice_fm_caps;
	ddi_iblock_cookie_t	ice_iblock;

	/*
	 * PCI register handles.
	 */
	ddi_acc_handle_t	ice_pci_hdl;
	off_t			ice_reg_size;
	caddr_t			ice_reg_base;
	ddi_device_acc_attr_t	ice_reg_attr;
	ddi_acc_handle_t	ice_reg_hdl;

	/*
	 * Vendor information for MAC disambiguation, debugging, and others.
	 */
	uint16_t	ice_pci_vid;
	uint16_t	ice_pci_did;
	uint8_t		ice_pci_rev;
	uint16_t	ice_pci_svid;
	uint16_t	ice_pci_sdid;

	/*
	 * Task related state
	 */
	ice_task_t	ice_task;

	/*
	 * Device information
	 */
	ice_fw_info_t		ice_fwinfo;
	ice_nvm_t		ice_nvm;
	uint_t			ice_nfunc_caps;
	ice_capability_t	*ice_func_caps;
	uint_t			ice_ndev_caps;
	ice_capability_t	*ice_dev_caps;
	size_t			ice_pba_len;
	uint8_t			*ice_pba;

	uint_t			ice_max_vsis;
	uint_t			ice_max_mtu;
	uint_t			ice_max_rxq;
	uint_t			ice_first_rxq;
	uint_t			ice_max_txq;
	uint_t			ice_first_txq;
	uint_t			ice_max_msix;
	uint_t			ice_first_msix;

	uint8_t			ice_mac[ETHERADDRL];

	uint_t			ice_num_vsis;
	uint_t			ice_num_rxq_per_vsi;
	uint_t			ice_num_txq;

	uint_t			ice_mtu;
	uint_t			ice_frame_size;

	uint32_t		ice_soc;
	uint_t			ice_itr_gran;
	uint_t			ice_itr_rx;
	uint_t			ice_itr_tx;
	uint_t			ice_itr_other;

	uint_t			ice_pci_bus;
	uint_t			ice_pci_dev;
	uint_t			ice_pci_func;
	uint_t			ice_pf_id;

	/*
	 * Link status tracking and variables drived from it. Everything in this
	 * section is protected by the ice_lse_lock.
	 */
	kmutex_t		ice_lse_lock;
	kcondvar_t		ice_lse_cv;
	ice_lse_state_t		ice_lse_state;
	ice_phy_abilities_t	ice_phy;
	ice_link_status_t	ice_link;
	link_state_t		ice_link_cur_state;
	uint64_t		ice_link_cur_speed;
	link_duplex_t		ice_link_cur_duplex;
	link_flowctrl_t		ice_link_cur_fctl;

	/*
	 * Control Queue
	 */
	ice_controlq_t	ice_asq;
	ice_controlq_t	ice_arq;

	/*
	 * Switch Information
	 */
	uint16_t	ice_port_id;
	uint16_t	ice_port_swid;

	/*
	 * Interrupt Tracking
	 */
	int			ice_intr_type;
	int			ice_nintrs;
	uint_t			ice_intr_pri;
	int			ice_intr_cap;
	size_t			ice_intr_handle_size;
	ddi_intr_handle_t	*ice_intr_handles;

	/*
	 * MAC related bits
	 */
	mac_handle_t	ice_mac_hdl;

	/*
	 * VSI Tracking
	 */
	list_t	ice_vsi;

	/*
	 * TX Scheduler information.
	 *
	 * XXX Replace this with a tree or something of parsed info?
	 */
	uint16_t	ice_sched_nbranches;
	uint8_t	ice_sched_buf[4096];
} ice_t;

/*
 * General functions
 */
extern uint32_t ice_reg_read(ice_t *, uintptr_t);
extern void ice_reg_write(ice_t *, uintptr_t, uint32_t);
extern int ice_regs_check(ice_t *);
extern void ice_error(ice_t *, const char *, ...);
extern void ice_schedule(ice_t *, ice_work_task_t);

extern boolean_t ice_link_status_update(ice_t *);

/*
 * DMA functions
 */
extern void ice_dma_acc_attr(ice_t *, ddi_device_acc_attr_t *);
extern void ice_dma_transfer_controlq_attr(ice_t *, ddi_dma_attr_t *);
extern void ice_dma_free(ice_dma_buffer_t *);
extern boolean_t ice_dma_alloc(ice_t *, ice_dma_buffer_t *, ddi_dma_attr_t *,
    ddi_device_acc_attr_t *, boolean_t, size_t, boolean_t);

/*
 * Control Queue related functions.
 */
extern boolean_t ice_controlq_init(ice_t *);
extern void ice_controlq_fini(ice_t *);

extern ice_work_task_t ice_controlq_rq_process(ice_t *);

extern boolean_t ice_cmd_get_version(ice_t *, ice_fw_info_t *);
extern boolean_t ice_cmd_queue_shutdown(ice_t *, boolean_t);
extern boolean_t ice_cmd_clear_pf_config(ice_t *);
extern boolean_t ice_cmd_clear_pxe(ice_t *);
/*
 * The NVM commands should not be used directly and instead the ice_nvm.c interfaces
 * mentioned below should be used.
 */
extern boolean_t ice_cmd_acquire_nvm(ice_t *, boolean_t);
extern boolean_t ice_cmd_release_nvm(ice_t *);
extern boolean_t ice_cmd_nvm_read(ice_t *, uint16_t, uint32_t, uint16_t *, uint16_t *, boolean_t);

extern boolean_t ice_cmd_get_caps(ice_t *, boolean_t, uint_t *,
    ice_capability_t **);
extern boolean_t ice_cmd_mac_read(ice_t *, uint8_t *);
extern boolean_t ice_cmd_get_phy_abilities(ice_t *, ice_phy_abilities_t *,
    boolean_t);

typedef enum {
	ICE_LSE_NO_CHANGE,
	ICE_LSE_ENABLE,
	ICE_LSE_DISABLE
} ice_lse_t;

extern boolean_t ice_cmd_get_link_status(ice_t *, ice_link_status_t *,
    ice_lse_t);
extern boolean_t ice_cmd_set_event_mask(ice_t *, uint16_t);
extern boolean_t ice_cmd_setup_link(ice_t *, boolean_t);
extern boolean_t ice_cmd_get_switch_config(ice_t *, void *, size_t, uint16_t,
    uint16_t *, uint16_t *);

extern boolean_t ice_cmd_add_vsi(ice_t *, ice_vsi_t *);
extern boolean_t ice_cmd_free_vsi(ice_t *, ice_vsi_t *, boolean_t);

extern boolean_t ice_cmd_set_rss_key(ice_t *, ice_vsi_t *, void *, uint_t);
extern boolean_t ice_cmd_set_rss_lut(ice_t *, ice_vsi_t *, void *, uint_t);

extern boolean_t ice_cmd_get_default_scheduler(ice_t *, void *, size_t,
    uint16_t *);

/*
 * NVM related functions
 */
extern boolean_t ice_nvm_init(ice_t *);
extern void ice_nvm_fini(ice_t *);
extern boolean_t ice_nvm_read16(ice_t *, uint32_t, uint16_t *);
extern boolean_t ice_nvm_read_pba(ice_t *);

/*
 * Hardware related functions (one that manipulate registers)
 */
extern boolean_t ice_pf_reset(ice_t *);

/*
 * Interrupt routines
 */
extern uint_t ice_intr_msix(caddr_t, caddr_t);
extern uint_t ice_intr_msi(caddr_t, caddr_t);
extern uint_t ice_intr_intx(caddr_t, caddr_t);

extern boolean_t ice_intr_hw_init(ice_t *);
extern void ice_intr_hw_fini(ice_t *);

extern void ice_intr_trigger_softint(ice_t *);

/*
 * GLDv3 routines
 */
extern void ice_mac_unregister(ice_t *);
extern boolean_t ice_mac_register(ice_t *);

#ifdef __cplusplus
}
#endif

#endif /* _ICE_H */
