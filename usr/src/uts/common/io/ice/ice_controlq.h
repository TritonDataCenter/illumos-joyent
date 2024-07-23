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

#ifndef _ICE_ADMINQ_H
#define	_ICE_ADMINQ_H

/*
 * This header file describes everything required to drive the ice
 * control queue.  The control queue is the means by which software makes
 * requests to firmware.
 */

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * These are the opcodes that define valid commands. These are a subset of valid
 * opcodes. Not all codes may be listed here and not all of the codes listed
 * here are necessarily wired up.
 */
typedef enum ice_cq_opcode {
	/*
	 * General Commands
	 */
	ICE_CQ_OP_GET_VER = 0x1,
	ICE_CQ_OP_DRIVER_VERSION = 0x2,
	ICE_CQ_OP_QUEUE_SHUTDOWN = 0x3,
	ICE_CQ_OP_SET_PF_CONTEXT = 0x4,
	ICE_CQ_OP_GET_AQ_ERROR = 0x5,
	ICE_CQ_OP_REQUEST_RESOURCE = 0x8,
	ICE_CQ_OP_RELEASE_RESOURCE = 0x9,
	ICE_CQ_OP_DISCOVER_FUNCTION_CAPS = 0xA,
	ICE_CQ_OP_DISCOVER_DEVICE_CAPS = 0xB,
	ICE_CQ_OP_VMVF_RESET = 0xC31,
	/*
	 * MAC address
	 */
	ICE_CQ_OP_MANAGE_MAC_READ = 0x107,
	/*
	 * Receive Queue
	 */
	ICE_CQ_OP_CLEAR_PXE = 0x110,
	/*
	 * Switch configuration
	 */
	ICE_CQ_OP_GET_SWITCH_CONFIG = 0x200,
	/*
	 * VSI commands
	 */
	ICE_CQ_OP_ADD_VSI = 0x0210,
	ICE_CQ_OP_UPDATE_VSI = 0x0211,
	ICE_CQ_OP_GET_VSI = 0x0212,
	ICE_CQ_OP_FREE_VSI = 0x0213,
	/*
	 * Binary Classifier Population
	 */
	ICE_CQ_OP_CLEAR_PF_CONFIGURATION = 0x2a4,
	/*
	 * TX Scheduler Information
	 */
	ICE_CQ_OP_QUERY_DEFAULT_SCHEDULER = 0x400,
	/*
	 * Link Configuration
	 */
	ICE_CQ_OP_SET_PHY_CONFIG = 0x601,
	ICE_CQ_OP_SET_MAC_CONFIG = 0x603,
	ICE_CQ_OP_SETUP_LINK = 0x605,
	ICE_CQ_OP_GET_PHY_ABILITIES = 0x600,
	ICE_CQ_OP_GET_LINK_STATUS = 0x607,
	ICE_CQ_OP_SET_EVENT_MASK = 0x613,
	/*
	 * NVM commands
	 */
	ICE_CQ_OP_NVM_READ = 0x701,
	ICE_CQ_OP_NVM_ERASE = 0x702,
	ICE_CQ_OP_NVM_WRITE = 0x703,
	ICE_CQ_OP_NVM_CONFIG_READ = 0x704,
	ICE_CQ_OP_NVM_CONFIG_WRITE = 0x705,
	ICE_CQ_OP_NVM_CHECKSUM = 0x706,
	ICE_CQ_OP_NVM_WRITE_ACTIVATE = 0x707,
	/*
	 * RSS Commands
	 */
	ICE_CQ_OP_SET_RSS_KEY = 0xB02,
	ICE_CQ_OP_SET_RSS_LUT = 0xB03
} ice_cq_opcode_t;

/*
 * Error codes that are defined to be returned by the hardware.
 */
typedef enum ice_cq_errno {
	ICE_CQ_SUCCESS		= 0,
	ICE_CQ_EPERM		= 1,
	ICE_CQ_ENOENT		= 2,
	ICE_CQ_ESRCH		= 3,
	ICE_CQ_EINTR		= 4,
	ICE_CQ_EIO		= 5,
	ICE_CQ_ENXIO		= 6,
	ICE_CQ_E2BIG		= 7,
	ICE_CQ_EAGAIN		= 8,
	ICE_CQ_ENOMEM		= 9,
	ICE_CQ_EACCESS		= 10,
	ICE_CQ_EFAULT		= 11,
	ICE_CQ_EBUSY		= 12,
	ICE_CQ_EEXIST		= 13,
	ICE_CQ_EINVAL		= 14,
	ICE_CQ_ENOTTY		= 15,
	ICE_CQ_ENOSPC		= 16,
	ICE_CQ_ENOSYS		= 17,
	ICE_CQ_ERANGE		= 18,
	ICE_CQ_EFLUSHED		= 19,
	ICE_CQ_BAD_ADDR		= 20,
	ICE_CQ_EMODE		= 21,
	ICE_CQ_EFBIG		= 22,
	ICE_CQ_ESBCOMP		= 23,
	ICE_CQ_EACCES_BMCU	= 24
} ice_cq_errno_t;

/*
 * This is the value in bytes that indicate when we have a 'large' indirect
 * buffer. When this is true the 'LB' flag must be set.
 */
#define	ICE_CQ_LARGE_BUF	512

/*
 * This is the largest size of an indirect buffer for the control queue.
 */
#define	ICE_CQ_MAX_BUF		4096

/*
 * Get Version
 * Direct Command
 *
 * Requests the firmware version information. On request, this is all empty.
 */
typedef struct ice_cq_cmd_get_version {
	uint32_t	iccgv_rom_build;
	uint32_t	iccgv_fw_build;
	uint8_t		iccgv_fw_branch;
	uint8_t		iccgv_fw_major;
	uint8_t		iccgv_fw_minor;
	uint8_t		iccgv_fw_patch;
	uint8_t		iccgv_aq_branch;
	uint8_t		iccgv_aq_major;
	uint8_t		iccgv_aq_minor;
	uint8_t		iccgv_aq_patch;
} ice_cq_cmd_get_version_t;

/*
 * Shutdown Queue
 * Direct Command
 *
 * Sent by software to indicate that the queue is being shut down.
 */
typedef struct ice_cq_cmd_queue_shutdown {
	uint8_t		iccqs_flags;
	uint8_t		iccqs_reserved[15];
} ice_cq_cmd_queue_shutdown_t;

/*
 * This flag, set in iccqs_flags, indicates that the software driver is
 * intending to unload.
 */
#define	ICE_CQ_CMD_QUEUE_SHUTDOWN_UNLOADING	0x01

typedef struct ice_cq_cmd_clear_pxe {
	uint8_t	icccp_flags;
	uint8_t	icccp_reserved[15];
} ice_cq_cmd_clear_pxe_t;

/*
 * This flag is required to be set in the clear pxe command. Unfortunately the
 * datasheet doesn't say why.
 */
#define	ICE_CQ_CLEAR_PXE_FLAG	0x02

/*
 * This structure is shared by both the acquire and release resource admin queue
 * commands.
 */
typedef struct ice_cq_cmd_request_resource {
	uint16_t	iccrr_res_id;
	uint16_t	iccrr_acc_type;
	uint32_t	iccrr_timeout;
	uint32_t	iccrr_res_number;
	uint16_t	iccrr_status;
	uint16_t	iccrr_reserved;
} ice_cq_cmd_request_resource_t;

#define	ICE_CQ_RESOURCE_NVM		0x01
#define	ICE_CQ_RESOURCE_SPD		0x02
#define	ICE_CQ_RESOURCE_CHANGE_LOCK	0x03
#define	ICE_CQ_RESOURCE_GLOBAL_CONFIG	0x04

#define	ICE_CQ_ACCESS_READ	0x01
#define	ICE_CQ_ACCESS_WRITE	0x02

/*
 * Default timeout values that are suggested by the datasheet for various
 * operations.
 */
#define	ICE_CQ_TIMEOUT_NVM_READ		3000
#define	ICE_CQ_TIMEOUT_NVM_WRITE	18000
#define	ICE_CQ_TIMEOUT_CHANGE_LOCK	1000
#define	ICE_CQ_TIMEOUT_GLOBAL_CONFIG	3000


typedef struct ice_cq_cmd_nvm_read {
	uint8_t		iccnr_offset[3];
	uint8_t		iccnr_flags;
	uint16_t	iccnr_module_type;
	uint16_t	iccnr_length;
	uint32_t	iccnr_data_high;
	uint32_t	iccnr_data_low;
} ice_cq_cmd_nvm_read_t;

#define	ICE_CQ_NVM_READ_LAST_COMMAND	0x01
#define	ICE_CQ_NVM_READ_SKIP_SHADOW	0x80

typedef struct ice_cq_cmd_manage_mac_read {
	uint16_t	iccmmr_flags;
	uint16_t	iccmmr_rsvd;
	uint8_t		iccmmr_count;
	uint8_t		iccmmr_rsvd1[3];
	uint32_t	iccmmr_data_high;
	uint32_t	iccmmr_data_low;
} ice_cq_cmd_manage_mac_read_t;

#define	ICE_CQ_MANAGE_MAC_READ_BUFSIZE	0x18
#define	ICE_CQ_MANAGE_MAC_READ_LAN_VALID	0x0010
#define	ICE_CQ_MANAGE_MAC_READ_WOL_VALID	0x0080
#define	ICE_CQ_MANAGE_MAC_READ_MC_MAG_EN	0x0100
#define	ICE_CQ_MANAGE_MAC_READ_WOL_PRESERVE	0x0200

typedef struct ice_cq_cmd_get_phy_abilities {
	uint16_t	iccgpa_rsvd;
	uint16_t	iccgpa_param0;
	uint32_t	iccgpa_rsvd1;
	uint32_t	iccgpa_data_high;
	uint32_t	iccgpa_data_low;
} ice_cq_cmd_get_phy_abilities_t;

#define	ICE_CQ_GET_PHY_ABILITIES_REPORT_MODS		0x01
#define	ICE_CQ_GET_PHY_ABILITIES_REPORT_WO_MEDIA	0x00
#define	ICE_CQ_GET_PHY_ABILITIES_REPORT_MEDIA		0x02
#define	ICE_CQ_GET_PHY_ABILITIES_REPORT_SW		0x04

typedef struct ice_cq_cmd_get_link_status {
	uint16_t	iccgls_rsvd;
	uint16_t	iccgls_flags;
	uint32_t	iccgls_rsvd1;
	uint32_t	iccgls_data_high;
	uint32_t	iccgls_data_low;
} ice_cq_cmd_get_link_status_t;

#define	ICE_CQ_GET_LINK_STATUS_MASK		0x03
#define	ICE_CQ_GET_LINK_STATUS_LSE_NOP		0
#define	ICE_CQ_GET_LINK_STATUS_LSE_ENABLED	1
#define	ICE_CQ_GET_LINK_STATUS_LSE_DISABLE	2
#define	ICE_CQ_GET_LINK_STATUS_LSE_ENABLE	3

typedef struct ice_cq_cmd_set_event_mask {
	uint64_t	iccsem_rsvd;
	uint16_t	iccsem_mask;
	uint8_t		iccsem_rsvd1[6];
} ice_cq_cmd_set_event_mask_t;

#define	ICE_CQ_SET_EVENT_MASK_LINK_UP		0x0002
#define	ICE_CQ_SET_EVENT_MASK_MEDIA_AVAIL	0x0004
#define	ICE_CQ_SET_EVENT_MASK_LINK_FAULT	0x0008
#define	ICE_CQ_SET_EVENT_MASK_PHY_TEMP		0x0010
#define	ICE_CQ_SET_EVENT_MASK_EXCESSIVE_ERRS	0x0020
#define	ICE_CQ_SET_EVENT_MASK_SIGNAL_DETECT	0x0040
#define	ICE_CQ_SET_EVENT_MASK_AUTONEG		0x0080
#define	ICE_CQ_SET_EVENT_MASK_TX_SUSPEND	0x0100
#define	ICE_CQ_SET_EVENT_MASK_TOPO_CONFLICT	0x0200
#define	ICE_CQ_SET_EVENT_MASK_MEDIA_CONFLICT	0x0400

typedef struct ice_cq_cmd_setup_link {
	uint16_t	iccsl_rsvd;
	uint8_t		iccsl_flags;
	uint8_t		icssl_rsvd1[13];
} ice_cq_cmd_setup_link_t;

#define	ICE_CQ_SETUP_LINK_RESTART_LINK	0x02
#define	ICE_CQ_SETUP_LINK_ENABLE_LINK	0x04

typedef struct ice_cq_cmd_get_switch_config {
	uint16_t	iccgsc_flags;
	uint16_t	iccgsc_next_elt;
	uint16_t	iccgsc_nelts;
	uint16_t	iccgsc_rsvd;
	uint32_t	iccgsc_data_high;
	uint32_t	iccgsc_data_low;
} ice_cq_cmd_get_switch_config_t;

/*
 * Maximum buffer size allowed for the Get Switch Config command.
 */
#define	ICE_CQ_GET_SWITCH_CONFIG_BUF_MAX	2048

typedef struct ice_cq_cmd_add_vsi {
	uint16_t	iccav_vsi;
	uint16_t	iccav_rsvd;
	uint8_t		iccav_vfid;
	uint8_t		iccav_rsvd1;
	uint16_t	iccav_type;
	uint32_t	iccav_data_high;
	uint32_t	iccav_data_low;
} ice_cq_cmd_add_vsi_t;

/*
 * The ADD VSI reply structure is different enough from the input one that it's
 * worth having a separate struct definition for.
 */
typedef struct ice_cq_cmd_add_vsi_reply {
	uint16_t	iccavr_vsi;
	uint16_t	iccavr_ext_status;
	uint16_t	iccavr_vsi_alloc;
	uint16_t	iccavr_vsi_unalloc;
	uint32_t	iccavr_data_high;
	uint32_t	iccavr_data_low;
} ice_cq_cmd_add_vsi_reply_t;

typedef struct ice_cq_cmd_free_vsi {
	uint16_t	iccfv_vsi;
	uint16_t	iccfv_flags;
	uint8_t		iccfv_rsvd[12];
} ice_cq_cmd_free_vsi_t;

#define	ICE_CQ_VSI_VALID	(1 << 15)
#define	ICE_CQ_VSI_MASK		0x03ff

#define	ICE_CQ_VSI_TYPE_VF	0x00
#define	ICE_CQ_VSI_TYPE_VMDQ2	0x01
#define	ICE_CQ_VSI_TYPE_PF	0x02
#define	ICE_CQ_VSI_TYPE_EMP_MNG	0x03

#define	ICE_CQ_VSI_KEEP_ALLOC	(1 << 0)

typedef struct ice_cq_cmd_set_rss_key {
	uint16_t	iccsrk_vsi_id;
	uint8_t		iccsrk_rsvd[6];
	uint32_t	iccsrk_data_high;
	uint32_t	iccsrk_data_low;
} ice_cq_cmd_set_rss_key_t;

typedef struct ice_cq_cmd_set_rss_lut {
	uint16_t	iccsrl_vsi_id;
	uint16_t	iccsrl_flags;
	uint32_t	iccsrl_rsvd;
	uint32_t	iccsrl_data_high;
	uint32_t	iccsrl_data_low;
} ice_cq_cmd_set_rss_lut_t;

#define	ICE_CQ_RSS_LUT_TYPE_VSI		0x00
#define	ICE_CQ_RSS_LUT_TYPE_PF		0x01
#define	ICE_CQ_RSS_LUT_TYPE_GLOBAL	0x02
#define	ICE_CQ_RSS_LUT_SET_TYPE(r, v)	ice_bitset16(r, 1, 0, v)

#define	ICE_CQ_RSS_LUT_SIZE_VSI		0x00
#define	ICE_CQ_RSS_LUT_SIZE_PF_128	0x00
#define	ICE_CQ_RSS_LUT_SIZE_PF_512	0x01
#define	ICE_CQ_RSS_LUT_SIZE_PF_2K	0x02
#define	ICE_CQ_RSS_LUT_SIZE_GLOBAL_128	0x00
#define	ICE_CQ_RSS_LUT_SIZE_GLOBAL_512	0x01
#define	ICE_CQ_RSS_LUT_SET_SIZE(r, v)	ice_bitset16(r, 3, 2, v)
#define	ICE_CQ_RSS_LUT_SET_GLOBAL_INDEX(r, v)	ice_bitset16(r, 7, 4, v)

typedef struct ice_cq_cmd_query_default_scheduler {
	uint8_t		iccqds_rsvd;
	uint8_t		iccqds_nbranches;
	uint16_t	iccqds_rsvd1;
	uint32_t	iccqds_rsvd2;
	uint32_t	iccqds_data_high;
	uint32_t	iccqds_data_low;
} ice_cq_cmd_query_default_scheduler_t;

#define	ICE_CQ_QUERY_DEFAULT_SCHED_BUF_SIZE	4096

/*
 * This is a generic structure of a command that may be used.
 */
typedef struct ice_cq_cmd_generic {
	uint32_t	iccg_param0;
	uint32_t	iccg_param1;
	uint32_t	iccg_data_high;
	uint32_t	iccg_data_low;
} ice_cq_cmd_generic_t;

typedef union ice_cq_cmd {
	uint8_t icc_raw[16];
	ice_cq_cmd_generic_t icc_generic;
	ice_cq_cmd_get_version_t icc_get_version;
	ice_cq_cmd_queue_shutdown_t icc_queue_shutdown;
	ice_cq_cmd_clear_pxe_t icc_clear_pxe;
	ice_cq_cmd_request_resource_t icc_request_resource;
	ice_cq_cmd_nvm_read_t icc_nvm_read;
	ice_cq_cmd_manage_mac_read_t icc_mac_read;
	ice_cq_cmd_get_phy_abilities_t icc_phy_abilities;
	ice_cq_cmd_get_link_status_t icc_get_link_status;
	ice_cq_cmd_set_event_mask_t icc_set_event_mask;
	ice_cq_cmd_setup_link_t icc_setup_link;
	ice_cq_cmd_get_switch_config_t icc_get_switch_config;
	ice_cq_cmd_add_vsi_t icc_add_vsi;
	ice_cq_cmd_add_vsi_reply_t icc_add_vsi_reply;
	ice_cq_cmd_free_vsi_t icc_free_vsi;
	ice_cq_cmd_set_rss_key_t icc_set_rss_key;
	ice_cq_cmd_set_rss_lut_t icc_set_rss_lut;
	ice_cq_cmd_query_default_scheduler_t icc_query_default_scheduler;
} ice_cq_cmd_t;

/*
 * This represents a single entry in the control queue.
 */
typedef struct ice_cq_desc {
	uint16_t	icqd_flags;
	uint16_t	icqd_opcode;
	uint16_t	icqd_data_len;
	uint16_t	icqd_id_ret;
	uint32_t	icqd_cookie_high;
	uint32_t	icqd_cookie_low;
	ice_cq_cmd_t	icqd_command;
} ice_cq_desc_t;

/*
 * This flag is set by firmware to indicate that it is done being processed.
 */
#define	ICE_CQ_DESC_FLAGS_DD	0x0001

/*
 * This flag is set by firmware to indicate that the command completed
 * successfully.
 */
#define	ICE_CQ_DESC_FLAGS_CMP	0x0002

/*
 * This flag is set by firmware to indicate that the command had an error.
 */
#define	ICE_CQ_DESC_FLAGS_ERR	0x0004

/*
 * This flag is set by firmware to indicate it came from a Virtual Function.
 */
#define	ICE_CQ_DESC_FLAGS_VFE	0x0008

/*
 * This flag is set by software to indicate that it has a buffer larger than 512
 * bytes (ICE_CQ_LARGE_BUF).
 */
#define	ICE_CQ_DESC_FLAGS_LB	0x0200

/*
 * This flag is set by software to indicate that the firmware needs to read the
 * indirect buffer members of the descriptor, (icqd_data_high, icqd_data_low).
 * This may be used either when we're using those fields for additional data or
 * when we have an actual indirect descriptor.
 */
#define	ICE_CQ_DESC_FLAGS_RD	0x0400

/*
 * This flag is set by software to indicate that this came from a virtual
 * function.
 */
#define	ICE_CQ_DESC_FLAGS_VFC	0x0800

/*
 * This flag is set by software to indicate that there is an indirect buffer
 * present that needs to be read.
 */
#define	ICE_CQ_DESC_FLAGS_BUF	0x1000

/*
 * This flag is set by software to indicate that it'd like an interrupt when the
 * command in question completes.
 */
#define	ICE_CQ_DESC_FLAGS_SI	0x2000

/*
 * This flag is set by software to indicate that it'd like an interrupt when an
 * error occurs. If this is set, and an error occurs, the value in SI doesn't
 * matter.
 */
#define	ICE_CQ_DESC_FLAGS_EI	0x4000

/*
 * This flag is set by software to indicate that the entry should be flushed if
 * an error occurs on the previous command.
 */
#define	ICE_CQ_DESC_FLAGS_FE	0x8000

/*
 * The return code is split into two uint8_t values. The lower byte is an error
 * constant in the form of an ice_cq_errno_t. However, the upper byte is a
 * private entry that varies based on hardware. The following macros are used to
 * pry these apart.
 */
#define	ICE_CQ_ERR_CODE_MASK		0x00ff
#define	ICE_CQ_ERR_CODE_FW_MASK		0xff00
#define	ICE_CQ_ERR_CODE_FW_SHIFT	8

#ifdef __cplusplus
}
#endif

#endif /* _ICE_ADMINQ_H */
