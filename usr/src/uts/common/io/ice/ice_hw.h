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

#ifndef _ICE_HW_H
#define	_ICE_HW_H

/*
 * This header contains register offsets that are relevant for the ICE driver.
 * These should all come from datasheet Section '13.3.2 Detailed Register
 * Description - PF BAR 0'. Note, not all registers are here, only those that we
 * are currently using.
 *
 * Register names come from the datasheet and simply have ICE_REG prefixed to
 * them.
 */

#include <sys/bitmap.h>

#ifdef __cplusplus
extern "C" {
#endif

static inline uint8_t
ice_bitset8(uint8_t reg, uint_t high, uint_t low, uint8_t val)
{
	uint8_t mask;

	ASSERT3U(high, >=, low);
	ASSERT3U(high, <, 8);
	ASSERT3U(low, <, 8);

	mask = (1LU << (high - low + 1)) - 1;
	ASSERT0(~mask & val);

	reg &= ~(mask << low);
	reg |= val << low;

	return (reg);
}

static inline uint16_t
ice_bitx16(uint16_t reg, uint_t high, uint_t low)
{
	ASSERT3U(high, >=, low);
	ASSERT3U(high, <, 16);
	ASSERT3U(low, <, 16);

	return (BITX(reg, high, low));
}


static inline uint32_t
ice_bitx32(uint32_t reg, uint_t high, uint_t low)
{
	ASSERT3U(high, >=, low);
	ASSERT3U(high, <, 32);
	ASSERT3U(low, <, 32);

	return (BITX(reg, high, low));
}

static inline uint16_t
ice_bitset16(uint16_t reg, uint_t high, uint_t low, uint16_t val)
{
	uint16_t mask;

	ASSERT3U(high, >=, low);
	ASSERT3U(high, <, 16);
	ASSERT3U(low, <, 16);

	mask = (1LU << (high - low + 1)) - 1;
	ASSERT0(~mask & val);

	reg &= ~(mask << low);
	reg |= val << low;

	return (reg);
}

static inline uint32_t
ice_bitset32(uint32_t reg, uint_t high, uint_t low, uint32_t val)
{
	uint32_t mask;

	ASSERT3U(high, >=, low);
	ASSERT3U(high, <, 32);
	ASSERT3U(low, <, 32);

	mask = (1LU << (high - low + 1)) - 1;
	ASSERT0(~mask & val);

	reg &= ~(mask << low);
	reg |= val << low;

	return (reg);
}

/*
 * Control queue registers.
 */
#define	ICE_REG_PF_FW_ATQBAL	0x00080000
#define	ICE_REG_PF_FW_ATQBAH	0x00080100
#define	ICE_REG_PF_FW_ATQLEN	0x00080200
#define	ICE_REG_PC_FW_ATQLEN_ATQLEN_MASK	0x3ff
#define	ICE_REG_PC_FW_ATQLEN_ATQVFE		(1UL << 28)
#define	ICE_REG_PC_FW_ATQLEN_ATQOVFL		(1UL << 29)
#define	ICE_REG_PC_FW_ATQLEN_ATQCRIT		(1UL << 30)
#define	ICE_REG_PC_FW_ATQLEN_ATQENABLE		(1UL << 31)
#define	ICE_REG_PF_FW_ATQH	0x00080300
#define	ICE_REG_PF_FW_ATQT	0x00080400

#define	ICE_REG_PF_FW_ARQBAL	0x00080080
#define	ICE_REG_PF_FW_ARQBAH	0x00080180
#define	ICE_REG_PF_FW_ARQLEN	0x00080280
#define	ICE_REG_PC_FW_ARQLEN_ATQLEN_MASK	0x3ff
#define	ICE_REG_PC_FW_ARQLEN_ATQVFE		(1UL << 28)
#define	ICE_REG_PC_FW_ARQLEN_ATQOVFL		(1UL << 29)
#define	ICE_REG_PC_FW_ARQLEN_ATQCRIT		(1UL << 30)
#define	ICE_REG_PC_FW_ARQLEN_ATQENABLE		(1UL << 31)
#define	ICE_REG_PF_FW_ARQH	0x00080380
#define	ICE_REG_PF_FW_ARQT	0x00080480

/*
 * The ICE_REG_PFGEN_CTRL register is used to control the power on a per-PF
 * basis and tracks when the register in question is resetting.
 */
#define	ICE_REG_PFGEN_CTRL	0x00091000
#define	ICE_REG_PFGEN_CTRL_PFSWR	0x01

/*
 * The ICE_REG_PF_FUNC_RID register contains information about the function ID.
 */
#define	ICE_REG_PF_FUNC_RID	0x0009E880
#define	ICE_REG_PF_FUNC_RID_FUNC(x)	BITX(x, 2, 0)
#define	ICE_REG_PF_FUNC_RID_DEV(x)	BITX(x, 7, 3)
#define	ICE_REG_PF_FUNC_RID_BUS(x)	BITX(x, 15, 8)

/*
 * The ICE_REG_GL_UFUSE_SOC provides information about the hardware chip that
 * we're working with. This is important for properly identifying the hardware
 * for things like ITRs.
 */
#define	ICE_REG_GL_UFUSE_SOC	0x000A400C
#define	ICE_REG_GL_UFUSE_SOC_PORT_MODE(x)	BITX(x, 1, 0)
#define	ICE_REG_GL_UFUSE_SOC_OCTAL_PORT		0
#define	ICE_REG_GL_UFUSE_SOC_QUAD_PORT		1
#define	ICE_REG_GL_UFUSE_SOC_DUAL_PORT		2
#define	ICE_REG_GL_UFUSE_SOC_SINGLE_PORT	3
#define	ICE_REG_GL_UFUSE_SOC_BANDWIDTH(x)	BITX(x, 3, 2)
#define	ICE_REG_GL_UFUSE_SOC_200_GBE		0
#define	ICE_REG_GL_UFUSE_SOC_100_GBE		1
#define	ICE_REG_GL_UFUSE_SOC_50_GBE		2
#define	ICE_REG_GL_UFUSE_SOC_25_GBE		3
#define	ICE_REG_GL_UFUSE_SOC_PE_DISABLE(x)	BITX(x, 4, 4)
#define	ICE_REG_GL_UFUSE_SOC_SWITCH_MODE(x)	BITX(x, 5, 5)
#define	ICE_REG_GL_UFUSE_SOC_CSR_PROTECT(x)	BITX(x, 6, 6)
#define	ICE_REG_GL_UFUSE_SOC_BLOCK_BME_TO_FW(x)	BITX(x, 9, 9)
#define	ICE_REG_GL_UFUSE_SOC_SOC_TYPE(x)	BITX(x, 10, 10)
#define	ICE_REG_GL_UFUSE_SOC_ICX_D		0
#define	ICE_REG_GL_UFUSE_SOC_SNR		1
#define	ICE_REG_GL_UFUSE_SOC_BTS_MODE(x)	BITX(x, 11, 11)

/*
 * Interrupt related registers.
 */
#define	ICE_REG_GLINT_CTL	0x0016CC54

#define	ICE_REG_GLINT_VECT2FUNC_BASE	0x00162000
#define	ICE_REG_GLINT_VECT2FUNC_VF_NUM_SET(r, v) ice_bitset32(r, 7, 0, v)
#define	ICE_REG_GLINT_VECT2FUNC_PF_NUM_SET(r, v) ice_bitset32(r, 14, 12, v)
#define	ICE_REG_GLINT_VECT2FUNC_IS_PF_SET(r, v)	ice_bitset32(r, 16, 16, v)

#define	ICE_REG_GLINT_DYN_CTL_BASE	0x00160000
#define	ICE_REG_GLINT_DYN_CTL_INTENA_SET(r)	ice_bitset32(r, 0, 0, 1)
#define	ICE_REG_GLINT_DYN_CTL_CLEARPBA_SET(r)	ice_bitset32(r, 1, 1, 1)
#define	ICE_REG_GLINT_DYN_CTL_SWINT_TRIG_SET(r)	ice_bitset32(r, 2, 2, 1)
#define	ICE_REG_GLINT_DYN_CTL_ITR_INDX_SET(r, v) ice_bitset32(r, 4, 3, v)
#define	ICE_REG_GLINT_DYN_CTL_INTERVAL_SET(r, v) ice_bitset32(r, 16, 6, v)
#define	ICE_REG_GLINT_DYN_CTL_SW_ITR_INDX_ENA_SET(r) ice_bitset32(r, 24, 24, 1)
#define	ICE_REG_GLINT_DYN_CTL_SW_ITR_INDXA_SET(r, v) ice_bitset32(r, 26, 25, v)
#define	ICE_REG_GLINT_DYN_CTL_SW_WB_ON_ITR_SET(r) ice_bitset32(r, 30, 30, 1)
#define	ICE_REG_GLINT_DYN_CTL_INTENA_MSK_SET(r)	ice_bitset32(r, 31, 31, 1)


#define	ICE_REG_GLINT_ITR_BASE	0x00154000
#define	ICE_REG_GLINT_RATE_BASE	0x0015A000

/*
 * The following macros cover the QINT_RQCTL, QINT_TQCTL, PFINT_FW_CTL, and
 * PFINT_OICR_CTL. This is also true for various VF related registers.
 */
#define	ICE_REG_PFINT_MSIX_INDX(r)		ice_bitx32(r, 10, 0)
#define	ICE_REG_PFINT_MSIX_INDX_SET(r, v)	ice_bitset32(r, 10, 0, v)
#define	ICE_REG_PFINT_ITR_INDX(r)		ice_bitx32(r, 12, 11)
#define	ICE_REG_PFINT_ITR_INDX_SET(r, v)	ice_bitset32(r, 12, 11, v)
#define	ICE_REG_PFINT_CAUSE_ENA(r)		ice_bitx32(r, 30, 30)
#define	ICE_REG_PFINT_CAUSE_ENA_SET(r, v)	ice_bitset32(r, 30, 30, v)

#define	ICE_REG_QINT_RQCTL_BASE	0x00150000
#define	ICE_REG_QINT_TQCTL_BASE	0x00150000
#define	ICE_REG_PFINT_FW_CTL	0x0016C800

#define	ICE_REG_PFINT_OICR	0x0016CA00
#define	ICE_REG_PFINT_OICR_ENA	0x0016C900
#define	ICE_REG_PFINT_OICR_CTL	0x0016CA80
#define	ICE_REG_PFINT_OICR_GET(r, bit)		ice_bitx32(r, bit, bit)
#define	ICE_REG_PFINT_OICR_SET(r, bit, v)	ice_bitset32(r, bit, bit, v)

#define	ICE_REG_OICR_QUEUE		1
#define	ICE_REG_OICR_HH_COMP		10
#define	ICE_REG_OICR_TSYN_TX		11
#define	ICE_REG_OICR_TSYN_EVNT		12
#define	ICE_REG_OICR_TSYN_TGT		13
#define	ICE_REG_OICR_HLP_RDY		14
#define	ICE_REG_OICR_CPM_RDY		15
#define	ICE_REG_OICR_ECC_ERR		16
#define	ICE_REG_OICR_MAL_DETECT	19
#define	ICE_REG_OICR_GRST		20
#define	ICE_REG_OICR_GPIO		22
#define	ICE_REG_OICR_STORM_DETECT	24
#define	ICE_REG_OICR_HMC_ERR		26
#define	ICE_REG_OICR_PE_PUSH		27
#define	ICE_REG_OICR_VFLR		29
#define	ICE_REG_OICR_XLR_HW_DONE	30
#define	ICE_REG_OICR_SWINT		31


/*
 * NVM related registers.
 *
 * GLNVM_GENS contains information about the size of the NVM and its presence.
 */
#define	ICE_REG_GLNVM_GENS	0x000B6100
#define	ICE_REG_GLNVM_GENS_NVM_PRES	0x01
#define	ICE_REG_GLNVM_GENS_SR_SIZE(x)	BITX(x, 7, 5)
#define	ICE_REG_GLNVM_GENS_BANK1VAL(x)	BITX(x, 8, 8)

#define	ICE_REG_GLNVM_FLA	0x000B6108
#define	ICE_REG_GLNVM_FLA_LOCKED(x)	BITX(x, 6, 6)

/*
 * NVM Modules that we may want to read. The module ID is used to describe a
 * region of the NVM.
 */

#define	ICE_NVM_MODULE_TYPE_MEMORY	0x00
#define	ICE_NVM_MODULE_TYPE_PBA		0x16

/*
 * Offsets into NVM shadow memory. These are all for the primary memory offset.
 */
#define	ICE_NVM_DEV_STARTER_VER		0x18
#define	ICE_NVM_MAP_VERSION		0x29
#define	ICE_NVM_IMAGE_VERSION		0x2A
#define	ICE_NVM_STRUCTURE_VERSION	0x2B
#define	ICE_NVM_EETRACK_1		0x2D
#define	ICE_NVM_EETRACK_2		0x2E
#define	ICE_NVM_EETRACK_ORIG_1		0x34
#define	ICE_NVM_EETRACK_ORIG_2		0x35

/*
 * NVM offsets for the PBA, printed board assembly. This assumes that you're
 * using the PBA module type.
 */
#define	ICE_NVM_PBA_LENGTH	0x00
#define	ICE_NVM_PBA_WORD1	0x01
#define	ICE_NVM_PBA_WORD2	0x02
#define	ICE_NVM_PBA_WORD3	0x03
#define	ICE_NVM_PBA_WORD4	0x04
#define	ICE_NVM_PBA_WORD5	0x05

/*
 * Capability structure defined by hardware and the various capability IDs.
 */
typedef struct ice_capability {
	uint16_t	icap_cap;
	uint8_t		icap_major;
	uint8_t		icap_minor;
	uint32_t	icap_number;
	uint32_t	icap_logid;
	uint32_t	icap_physid;
	uint64_t	icap_data1;
	uint64_t	icap_data2;
} ice_capability_t;

typedef enum {
	ICE_CAP_SWITCH_MODE		= 0x1,
	ICE_CAP_MANAGEABILITY_MODE	= 0x2,
	ICE_CAP_OS2BMC			= 0x4,
	ICE_CAP_FUNCTIONS_VALID		= 0x5,
	ICE_CAP_ALTERNAME_RAM		= 0x6,
	ICE_CAP_WOL			= 0x8,
	ICE_CAP_SR_IOV			= 0x12,
	ICE_CAP_VIRTUAL_FUNCTION	= 0x13,
	ICE_CAP_VMDq			= 0x14,
	ICE_CAP_802_1Qbg		= 0x15,
	ICE_CAP_VSI			= 0x17,
	ICE_CAP_DCB			= 0x18,
	ICE_CAP_ISCSI			= 0x22,
	ICE_CAP_RSS			= 0x40,
	ICE_CAP_RX_QUEUES		= 0x41,
	ICE_CAP_TX_QUEUES		= 0x42,
	ICE_CAP_MSI_X			= 0x43,
	ICE_CAP_VF_MSIX			= 0x44,
	ICE_CAP_FLOW_DIRECTOR		= 0x45,
	ICE_CAP_1588			= 0x46,
	ICE_CAP_MAX_MTU			= 0x47,
	ICE_CAP_NVM_VERSIONS		= 0x48,
	ICE_CAP_IWARP			= 0x51,
	ICE_CAP_LED			= 0x61,
	ICE_CAP_SDP			= 0x62,
	ICE_CAP_MDIO			= 0x63,
	ICE_CAP_SKU			= 0x74
} ice_cap_id_t;

/*
 * MAC address data structure
 */
typedef struct ice_hw_mac {
	uint8_t		ihm_rsvd;
	uint8_t		ihm_type;
	uint8_t		ihm_mac[6];
} ice_hw_mac_t;

#define	ICE_HW_MAC_TYPE_LAN	0
#define	ICE_HW_MAC_TYPE_WOL	1

/*
 * Phy Ability data structures
 */
typedef struct ice_phy_module {
	uint8_t	ipm_oui[3];
	uint8_t ipm_rsvd;
	uint8_t ipm_part[16];
	uint8_t ipm_rev[4];
	uint8_t ipm_rsvd1[8];
} ice_phy_module_t;

typedef struct ice_phy_abilities {
	uint8_t	ipa_type[16];
	uint8_t	ipa_caps;
	uint8_t ipa_lpc;
	uint16_t ipa_eee;
	uint16_t ipa_eeer;
	uint8_t ipa_phyid[4];
	uint8_t ipa_phyfw[8];
	uint8_t ipa_link_fec;
	uint8_t ipa_cmte;
	uint8_t ipa_ext_code;
	uint8_t ipa_mod_type;
	uint8_t ipa_qual_mod_count;
	ice_phy_module_t ipa_modules[16];
} ice_phy_abilities_t;

#define	ICE_PHY_CAP_TX_PAUSE_ENABLED	0x01
#define	ICE_PHY_CAP_RX_PAUSE_ENABLED	0x02
#define	ICE_PHY_CAP_LOW_POER_ABILITY	0x04
#define	ICE_PHY_CAP_LINK_ENABLED	0x08
#define	ICE_PHY_CAP_AN_ENABLED		0x10
#define	ICE_PHY_CAP_MOD_QUAL_ENABLED	0x20
#define	ICE_PHY_CAP_LESM_ENABLED	0x40
#define	ICE_PHY_CAP_AUTO_FEC_ENABLED	0x80

#define	ICE_PHY_EEE_100BASE_TX		0x0001
#define	ICE_PHY_EEE_1000BASE_T		0x0002
#define	ICE_PHY_EEE_10GBASE_T		0x0004
#define	ICE_PHY_EEE_1000BASE_KX		0x0008
#define	ICE_PHY_EEE_10GBASE_KR		0x0010
#define	ICE_PHY_EEE_25GBASE_KR		0x0020
#define	ICE_PHY_EEE_50GBASE_KR2		0x0080
#define	ICE_PHY_EEE_50GBASE_KR_PAM4	0x0100
#define	ICE_PHY_EEE_100GBASE_KR4	0x0200
#define	ICE_PHY_EEE_100GBASE_KR2_PAM4	0x0400

/*
 * Link Status data structures
 */
typedef struct ice_link_status {
	uint8_t		ils_media;
	uint8_t		ils_rsvd;
	uint8_t		ils_status;
	uint8_t		ils_autoneg;
	uint8_t		ils_phy_link_tx;
	uint8_t		ils_loopback;
	uint16_t	ils_frame;
	uint8_t		ils_fec;
	uint8_t		ils_extpower;
	uint16_t	ils_curspeed;
	uint32_t	ils_rsvd1;
	uint8_t		ils_phy[16];
} ice_link_status_t;

#define	ICE_LINK_STATUS_LINK_UP			0x01
#define	ICE_LINK_STATUS_LINK_PHY_FAULT		0x02
#define	ICE_LINK_STATUS_LINK_TX_FAULT		0x04
#define	ICE_LINK_STATUS_LINK_RX_FAULT		0x08
#define	ICE_LINK_STATUS_LINK_REMOTE_FAULT	0x10
#define	ICE_LINK_STATUS_EXT_LINK_UP		0x20
#define	ICE_LINK_STATUS_MEDIA_AVAILABLE		0x40
#define	ICE_LINK_STATUS_SIGNAL_DETECT		0x80

#define	ICE_LINK_AUOTNEG_COMPLETE	0x01
#define	ICE_LINK_AUTONEG_PEER_AN	0x02
#define	ICE_LINK_AUTONEG_PARALLEL_FAULT	0x04
#define	ICE_LINK_AUTONEG_FEC_ENABLED	0x08
#define	ICE_LINK_AUTONEG_LOW_POWER	0x10
#define	ICE_LINK_AUTONEG_PAUSE_TX	0x20
#define	ICE_LINK_AUTONEG_PAUSE_RX	0x40
#define	ICE_LINK_AUTONEG_MOD_QUALIFIED	0x80

#define	ICE_LINK_PHY_TEMP_ALARM		0x01
#define	ICE_LINK_EXCESSIVE_LINK		0x02
#define	ICE_LINK_PORT_TX_SUSPEND_MASK	0x0c
#define	ICE_LINK_PORT_TX_ACTIVE		0x00
#define	ICE_LINK_PORT_TX_SUSPEND	0x04
#define	ICE_LINK_PORT_TX_SUSEPD_TC_FLUSH	0x0c

#define	ICE_LINK_PHY_LOOPBACK_ENABLED	0x01
#define	ICE_LINK_PHY_LOOPBACK_REMOTE	0x02
#define	ICE_LINK_MAC_LOOPBACK		0x04
#define	ICE_LINK_PHY_INDEX_MASK		0x38
#define	ICE_LINK_PHY_INDEX_SHIFT	4

#define	ICE_LINK_SPEED_10MB		0x0001
#define	ICE_LINK_SPEED_100MB		0x0002
#define	ICE_LINK_SPEED_1GB		0x0004
#define	ICE_LINK_SPEED_2500MB		0x0008
#define	ICE_LINK_SPEED_5GB		0x0010
#define	ICE_LINK_SPEED_10GB		0x0020
#define	ICE_LINK_SPEED_20GB		0x0040
#define	ICE_LINK_SPEED_25GB		0x0080
#define	ICE_LINK_SPEED_40GB		0x0100
#define	ICE_LINK_SPEED_50GB		0x0200
#define	ICE_LINK_SPEED_100GB		0x0400
#define	ICE_LINK_SPEED_200GB		0x0800

/*
 * PHY types
 *
 * Hardware has an array of bits that maps to specific types of PHYs. Each value
 * below is the bit offset in the PHY map as described by section '3.3.3.2.1
 * Table 3-42. Extended PHY Capabilities 128 Bits Word Structure'.
 */
#define	ICE_PHY_100BASE_TX		0
#define	ICE_PHY_100M_SGMII		1
#define	ICE_PHY_1000BASE_T		2
#define	ICE_PHY_1000BASE_SX		3
#define	ICE_PHY_1000BASE_LX		4
#define	ICE_PHY_1000BASE_KX		5
#define	ICE_PHY_1G_SGMII		6
#define	ICE_PHY_2500BASE_T		7
#define	ICE_PHY_2500BASE_X		8
#define	ICE_PHY_2500BASE_KX		9
#define	ICE_PHY_5GBASE_T		10
#define	ICE_PHY_5GBASE_KR		11
#define	ICE_PHY_10GBASE_T		12
#define	ICE_PHY_10G_SFI_DA		13
#define	ICE_PHY_10GBASE_SR		14
#define	ICE_PHY_10GBASE_LR		15
#define	ICE_PHY_10GBASE_KR_CR1		16
#define	ICE_PHY_10G_SFI_AOC_ACC		17
#define	ICE_PHY_10G_SFI_C2C		18
#define	ICE_PHY_25GBASE_T		19
#define	ICE_PHY_25GBASE_CR		20
#define	ICE_PHY_25GBASE_CR_S		21
#define	ICE_PHY_25GBASE_CR1		22
#define	ICE_PHY_25GBASE_SR		23
#define	ICE_PHY_25GBASE_LR		24
#define	ICE_PHY_25GBASE_KR		25
#define	ICE_PHY_25GBASE_KR_S		26
#define	ICE_PHY_25GBASE_KR1		27
#define	ICE_PHY_25G_AUI_AOC_ACC		28
#define	ICE_PHY_25G_AUI_C2C		29
#define	ICE_PHY_40GBASE_CR4		30
#define	ICE_PHY_40GBASE_SR4		31
#define	ICE_PHY_40GBASE_LR4		32
#define	ICE_PHY_40GBASE_KR4		33
#define	ICE_PHY_40G_XLAUI_AOC_ACC	34
#define	ICE_PHY_40G_XLAUI		35
#define	ICE_PHY_50GBASE_CR2		36
#define	ICE_PHY_50GBASE_SR2		37
#define	ICE_PHY_50GBASE_LR2		38
#define	ICE_PHY_50GBASE_KR2		39
#define	ICE_PHY_50G_LAUI2_AOC_ACC	40
#define	ICE_PHY_50G_LAUI2		41
#define	ICE_PHY_50G_AUI_AOC_ACC		42
#define	ICE_PHY_50G_AUI2		43
#define	ICE_PHY_50GBASE_CP		44
#define	ICE_PHY_50GBASE_SR		45
#define	ICE_PHY_50GBASE_FR		46
#define	ICE_PHY_50GBASE_LR		47
#define	ICE_PHY_50BASE_KR_PAM4		48
#define	ICE_PHY_50G_AUII_AOC_ACC	49
#define	ICE_PHY_50G_AUI1		50
#define	ICE_PHY_100GBASE_CR4		51
#define	ICE_PHY_100GBASE_SR4		52
#define	ICE_PHY_100GBASE_LR4		53
#define	ICE_PHY_100GBASE_KR4		54
#define	ICE_PHY_100G_CAUI4_AOC_ACC	55
#define	ICE_PHY_100G_CAUI4		56
#define	ICE_PHY_100G_AUIT4_AOC_ACC	57
#define	ICE_PHY_100G_AUI4		58
#define	ICE_PHY_100GBASE_CR_PAM4	59
#define	ICE_PHY_100GBASE_KR_PAM4	60
#define	ICE_PHY_100GBASE_CP2		61
#define	ICE_PHY_100GBASE_SR2		62
#define	ICE_PHY_100GBASE_DR		63
#define	ICE_PHY_100GBASE_KR2_PAM4	64
#define	ICE_PHY_100GBASE_CAUI2_AOC_ACC	65
#define	ICE_PHY_100GBASE_CAUI2		66
#define	ICE_PHY_100G_AUI2_AOC_ACC	67
#define	ICE_PHY_100G_AUI2		68
#define	ICE_PHY_200GBASE_CR4_PAM4	69
#define	ICE_PHY_200GBASE_SR4		70
#define	ICE_PHY_200GBASE_FR4		71
#define	ICE_PHY_200GBASE_LR4		72
#define	ICE_PHY_200GBASE_DR4		73
#define	ICE_PHY_200GBASE_KR4_PAM4	74
#define	ICE_PHY_200G_AUI4_AOC_ACC	75
#define	ICE_PHY_200G_AUI4		76
#define	ICE_PHY_200G_AUI8_AOC_ACC	77
#define	ICE_PHY_200G_AUI8		78
#define	ICE_PHY_400G_BASE_FR8		79
#define	ICE_PHY_400G_BASE_LR8		80
#define	ICE_PHY_400GBASE_DR4		81
#define	ICE_PHY_400G_AUI8_AOC_ACC	82
#define	ICE_PHY_400G_AUI8		83

/*
 * This structure represents an instance of the VSI software configuration that
 * is returned from hardware.
 */
#pragma pack(1)
typedef struct ice_hw_switch_config {
	uint16_t	isc_vsi_info;
	uint16_t	isc_swid;
	uint16_t	isc_pfid;
} ice_hw_switch_config_t;
#pragma pack()

#define	ICE_SWITCH_ELT_NUMBER(x)	ice_bitx16(x, 9, 0)
#define	ICE_SWITCH_ELT_TYPE(x)		ice_bitx16(x, 15, 14)
#define	ICE_SWITCH_TYPE_PHYSICAL_PORT	0
#define	ICE_SWITCH_TYPE_VIRTUAL_PORT	1
#define	ICE_SWITCH_TYPE_VSI		2
#define	ICE_SWITCH_TYPE_RESERVED	3
#define	ICE_SWITCH_FUNC_NUMBER(x)	ice_bitx16(x, 14, 0)
#define	ICE_SWITCH_FUNC_VF(x)		ice_bitx16(x, 15, 15)

#pragma pack(1)
typedef struct ice_hw_vsi_context {
	uint16_t	ihvc_sections;
	/*
	 * Switching information
	 */
	uint8_t		ihvc_switch_id;
	uint8_t		ihvc_switch_flags;
	uint8_t		ihvc_switch_flags2;
	uint8_t		ihvc_switch_veb_stats;
	/* Security */
	uint8_t		ihvc_sec_flags;
	uint8_t		ihvc_sec_rsvd;
	/* VLAN Handling */
	uint16_t	ihvc_vlan_id;
	uint8_t		ihvc_vlan_rsvd[2];
	uint8_t		ihvc_vlan_flags;
	uint8_t		ihvc_vlan_port_rsvd[3];
	/* Ingress UP */
	uint32_t	ihvc_ingress_table;
	/* Egress UP */
	uint32_t	ihvc_egress_table;
	/* Outer Tags */
	uint16_t	ihvc_otag_tag;
	uint8_t		ihvc_otag_flags;
	uint8_t		ihvc_otag_rsvd;
	/* Queue Mapping */
	uint8_t		ihvc_queue_method;
	uint8_t		ihvc_queue_rsvd;
	uint16_t	ihvc_queue_mapping[16];
	uint16_t	ihvc_queue_tc[8];
	/* Queue Options */
	uint8_t		ihvc_qopt_rss;
	uint8_t		ihvc_qopt_tc;
	uint8_t		ihvc_qopt_pe;
	uint8_t		ihvc_qopt_rsvd[3];
	/* Outer UP translation */
	uint32_t	ihvc_outer_table;
	/* ACL */
	uint16_t	ihvc_acl;
	/* Flow Director */
	uint16_t	ihvc_fd_flags;
	uint16_t	ihvc_fd_max_dedicated;
	uint16_t	ihvc_fd_max_shared;
	uint16_t	ihvc_fd_def_queue;
	uint16_t	ihvc_fd_report_queue;
	/* PASID Section */
	uint32_t	ihvc_pasid;
	/* Reserved */
	uint8_t		ihvc_reserved[24];
} ice_hw_vsi_context_t;
#pragma pack()

#define	ICE_HW_VSI_SECTION_SWITCHING	(1 << 0)
#define	ICE_HW_VSI_SECTION_SECURITY	(1 << 1)
#define	ICE_HW_VSI_SECTION_VLAN		(1 << 2)
#define	ICE_HW_VSI_SECTION_OUTER_TAG	(1 << 3)
#define	ICE_HW_VSI_SECTION_INGRESS_UP	(1 << 4)
#define	ICE_HW_VSI_SECTION_EGRESS_UP	(1 << 5)
#define	ICE_HW_VSI_SECTION_RX_QUEUE_MAP	(1 << 6)
#define	ICE_HW_VSI_SECTION_QUEUEING	(1 << 7)
#define	ICE_HW_VSI_SECTION_OUTER_UP	(1 << 8)
#define	ICE_HW_VSI_SECTION_ACL		(1 << 10)
#define	ICE_HW_VSI_SECTION_FLOW_DIR	(1 << 11)
#define	ICE_HW_VSI_SECTION_PASID	(1 << 12)

#define	ICE_HW_VSI_SWITCH_ALLOW_LOOPBACK	(1 << 5)
#define	ICE_HW_VSI_SWITCH_ALLOW_LOCAL_LOOPBACK	(1 << 6)
#define	ICE_HW_VSI_SWITCH_APPLY_SOURCE_PRUNE	(1 << 7)
#define	ICE_HW_VSI_SWITCH_EGRESS_PRUNING	(1 << 0)
#define	ICE_HW_VSI_SWITCH_LAN_ENABLE		(1 << 4)

#define	ICE_HW_VSI_STAT_SET_ID(val)	ice_bitset8(0, 4, 0, val)
#define	ICE_HW_VSI_STAT_VALID		(1 << 5)

#define	ICE_HW_VSI_SEC_DEST_OVERRIDE	(1 << 0)
#define	ICE_HW_VSI_SEC_MAC_ANTISPOOF	(1 << 2)
#define	ICE_HW_VSI_SEC_TX_VLAN_ANTISPOOF	(1 << 4)

#define	ICE_HW_VSI_VLAN_UNTAGGED_ONLY	0x01
#define	ICE_HW_VSI_VLAN_TAGGED_ONLY	0x02
#define	ICE_HW_VSI_VLAN_ALL		0x03
#define	ICE_HW_VSI_VLAN_SET_TAG(reg, val)	ice_bitset8(reg, 1, 0, val)
#define	ICE_HW_VSI_VLAN_INSERT_PVID	(1 << 2)
#define	ICE_HW_VSI_VLAN_UP_EXPOSE_ALL	0x00
#define	ICE_HW_VSI_VLAN_UP_HIDE_VLAN	0x01
#define	ICE_HW_VSI_VLAN_UP_HIDE_ALL	0x02
#define	ICE_HW_VSI_VLAN_UP_DO_NONE	0x03
#define	ICE_HW_VSI_VLAN_SET_UP_MODE(reg, val)	ice_bitset8(reg, 4, 3, val)

/*
 * Set a given index of a user priority table in the system. Each index has
 * three bits.
 */
#define	ICE_HW_VSI_UP_TABLE_SET(reg, index, val) \
    ice_bitset32(reg, index * 3 + 2, index * 3, val)

#define	ICE_HW_VSI_OTAG_NOTHING		0x00
#define	ICE_HW_VSI_OTAG_EXTRACT		0x01
#define	ICE_HW_VSI_OTAG_EXPOSE		0x02
#define	ICE_HW_VSI_OTAG_SET_MODE(reg, val)	ice_bitset8(reg, 1, 0, val)
#define	ICE_HW_VSI_OTAG_INSERT_ENABLE	(1 << 4)
#define	ICE_HW_VSI_OTAG_ACCEPT_HOST	(1 << 6)

#define	ICE_HW_VSI_QMAP_CONTIG		0
#define	ICE_HW_VSI_QMAP_SCATTER		(1 << 0)

#define	ICE_HW_VSI_TC_SET_QUEUE_OFF(reg, val)	ice_bitset16(reg, 10, 0, val)
#define	ICE_HW_VSI_TC_SET_NQUEUES(reg, val)	ice_bitset16(reg, 14, 11, val)

#define	ICE_HW_VSI_RSS_LUT_VSI		0x00
#define	ICE_HW_VSI_RSS_PF_LUT		0x02
#define	ICE_HW_VSI_RSS_GLOBAL_LUT	0x03
#define	ICE_HW_VSI_RSS_SET_LUT(reg, val)	ice_bitset8(reg, 1, 0, val)
#define	ICE_HW_VSI_RSS_SET_GLOBAL_LUT(reg, val)	ice_bitset8(reg, 5, 2, val)
#define	ICE_HW_VSI_RSS_SCHEME_TOEPLITZ		0x00
#define	ICE_HW_VSI_RSS_SCHEME_SYMTOEPLITZ	0x01
#define	ICE_HW_VSI_RSS_SCHEME_SIMPLE_XOR	0x02
#define	ICE_HW_VSI_RSS_SET_HASH_SCHEME(reg, val) ice_bitset8(reg, 7, 6, val)
#define	ICE_HW_VSI_TC_SET_OVERRIDE(reg, val)	ice_bitset8(reg, 4, 0, val)
#define	ICE_HW_VSI_TC_PROFILE_OVERRIDE		(1 << 7)
#define	ICE_HW_VSI_PE_FILTER_ENABLE	(1 << 0)

#define	ICE_HW_VSI_ACL_SET_RX_PROFILE_MISS(reg, val) \
	ice_bitset16(reg, 3, 0, val)
#define	ICE_HW_VSI_ACL_SET_RX_TABLE_MISS(reg, val) \
	ice_bitset16(reg, 7, 4, val)
#define	ICE_HW_VSI_ACL_SET_TX_PROFILE_MISS(reg, val) \
	ice_bitset16(reg, 11, 8, val)
#define	ICE_HW_VSI_ACL_SET_TX_TABLE_MISS(reg, val) \
	ice_bitset16(reg, 15, 12, val)

#define	ICE_HW_VSI_FD_ENABLE		(1 << 0)
#define	ICE_HW_VSI_FD_TX_AUTO_EVICT	(1 << 1)
#define	ICE_HW_VSI_FD_PROGRAM_ENABLE	(1 << 3)
#define	ICE_HW_VSI_FD_SET_DEF_QUEUE(reg, val)	ice_bitset16(reg, 10, 0, val)
#define	ICE_HW_VSI_FD_SET_DEF_QGROUP(reg, val)	ice_bitset16(reg, 14, 12, val)
#define	ICE_HW_VSI_FD_SET_REP_QUEUE(reg, val)	ice_bitset16(reg, 10, 0, val)
#define	ICE_HW_VSI_FD_SET_DEF_PRIO(reg, val)	ice_bitset16(reg, 14, 12, val)
#define	ICE_HW_VSI_FD_DEFAULT_DROP	(1 << 15)

#define	ICE_HW_VSI_PASID_SET(reg, val)	ice_bitset32(reg, 19, 0)
#define	ICE_HW_VSI_PASID_VALID		(1 << 31)

/*
 * RSS Information
 *
 * The key length variables indicate the size of the RSS key that should be
 * used.
 */
#define	ICE_RSS_KEY_LENGTH		0x34
#define	ICE_RSS_KEY_STANDARD_LENGTH	0x28
#define	ICE_RSS_LUT_SIZE_VSI		64

/*
 * RX and TX Queue context structures
 *
 * The following two structures and their constants are used to program and
 * initialize the TX and RX queues in the system. These structures are a little
 * werid, unfortunately. These are packed structures and the packing is a bit,
 * off. As a result, we have one version of this struct which fits all of the OS
 * sized data in a sane way. Then we will later come and turn this into its
 * packed byte array.
 */
typedef struct ice_hw_rxq_context {
	uint16_t	ihrc_head;
	uint64_t	ihrc_base;
	uint16_t	ihrc_qlen;
	uint8_t		ihrc_dbuff;
	uint8_t		ihrc_hbuff;
	uint8_t		ihrc_dtype;
	uint8_t		ihrc_dsize;
	uint8_t		ihrc_crcstrip;
	uint8_t		ihrc_l2tsel;
	uint8_t		ihrc_hsplit0;
	uint8_t		ihrc_hsplit1;
	uint8_t		ihrc_showiv;
	uint16_t	ihrc_rxmax;
	uint8_t		ihrc_tphrdesc;
	uint8_t		ihrc_tphwdesc;
	uint8_t		ihrc_tphdata;
	uint8_t		ihrc_tphhead;
	uint8_t		ihrc_lrxqthresh;
	uint8_t		ihrc_req;
} ice_hw_rxq_context_t;

/*
 * The base value is in units of 128 bytes.
 */
#define	ICE_HW_RXQ_CTX_BASE_SHIFT	7
#define	ICE_HW_RXQ_CTX_DBUFF_SHIFT	7
#define	ICE_HW_RXQ_CTX_HBUFF_SHIFT	6

#define	ICE_HW_RXQ_CTX_DTYPE_NOSPLIT		0x00
#define	ICE_HW_RXQ_CTX_DTYPE_HW_SPLIT		0x01
#define	ICE_HW_RXQ_CTX_DTYPE_ALWAYS_SPLIT	0x02

#define	ICE_HW_RXQ_CTX_DSIZE_16B	0x00
#define	ICE_HW_RXQ_CTX_DSIZE_32B	0x01

#define	ICE_HW_RXQ_CTX_HSPLIT0_NONE	0x00
#define	ICE_HW_RXQ_CTX_SPLIT1_NONE	0x00

/*
 * This is the size of the actual buffer in hardware.
 */
#define	ICE_HW_RXQ_CTX_PHYSICAL_SIZE	32

#define	ICE_REG_RXQ_CONTEXT_BASE	0x00280000

#define	ICE_REG_QRX_BASE		0x00290000ull
#define	ICE_QRX_TAIL(idx) 		(ICE_REG_QRX_BASE + ((idx) * 4))

typedef struct ice_hw_txq_context {
	uint64_t	ihtc_base;
	uint8_t		ihtc_port;
	uint8_t		ihtc_cgd;
	uint8_t		ihtc_pf;
	uint16_t	ihtc_vmvf_num;
	uint8_t		ihtc_vmvf_type;
	uint16_t	ihtc_vsi_id;
	uint8_t		ihtc_tsync;
	uint8_t		ihtc_alt_vlan;
	uint8_t		ihtc_cpuid;
	uint8_t		ihtc_wb_mode;
	uint8_t		ihtc_tphrdesc;
	uint8_t		ihtc_tphdrdata;
	uint16_t	ihtc_compq_id;
	uint16_t	ihtc_func_qnum;
	uint8_t		ihtc_itr_mode;
	uint8_t		ihtc_profile;
	uint16_t	ihtc_qlen;
	uint8_t		ihtc_quanta;
	uint8_t		ihtc_tso;
	uint16_t	ihtc_tso_queue;
	uint8_t		ihtc_legacy;
	uint8_t		ihtc_drop;
	uint8_t		ihtc_cache;
	uint8_t		ihtc_pkg_shape;
} ice_hw_txq_context_t;

/*
 * Number of bits to shift the base address by. This also implies that the queue
 * address must be 128 byte aligned.
 */
#define	ICE_HW_TXQ_CTX_BASE_SHIFT	7

#define	ICE_HW_TXQ_CTX_VMVF_TYPE_VF	0x00
#define	ICE_HW_TXQ_CTX_VMVF_TYPE_VM	0x01
#define	ICE_HW_TXQ_CTX_VMVF_TYPE_PF	0x02

#define	ICE_HW_TXQ_CTX_WB_MODE_DESC	0x00
#define	ICE_HW_TXQ_CTX_WB_MODE_COMP	0x01

#define	ICE_HW_TXQ_CTX_ITR_ENABLE	0x00
#define	ICE_HW_TXQ_CTX_ITR_DISABLE	0x01

#define	ICE_HW_TXQ_CTX_LEGACY_ADVANCED	0x00
#define	ICE_HW_TXQ_CTX_LEGACY_LEGACY	0x01

#define	ICE_HW_TXQ_CTX_PHYSICAL_SIZE	22

#define	ICE_QTX_BASE			0x002C0000
#define	ICE_QTX_TAIL(idx) 		(ICE_QTX_BASE + ((idx) * 4))

/*
 * Scheduler Structures returned by hardware.
 */
#pragma pack(1)
typedef struct ice_hw_sched_elem {
	uint32_t	ihse_pteid;
	uint32_t	ihse_teid;
	uint8_t		ihse_etype;
	uint8_t		ihse_valid;
	uint8_t		ihse_generic;
	uint8_t		ihse_flags;
	uint16_t	ihse_cir_bw_id;
	uint16_t	ihse_cir_bw_weight;
	uint16_t	ihse_eir_bw_id;
	uint16_t	ihse_eir_bw_weight;
	uint16_t	ihse_rl_profile;
	uint16_t	ihse_rsvd;
} ice_hw_sched_elem_t;

typedef struct ice_hw_sched_branch {
	uint32_t		ihsb_rsvd;
	uint16_t		ihsb_nelms;
	uint16_t		ihsb_rsvd1;
	ice_hw_sched_elem_t	ihsb_elems[];
} ice_hw_sched_branch_t;
#pragma pack()

#ifdef __cplusplus
}
#endif

#endif /* _ICE_HW_H */
