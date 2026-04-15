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
 * Copyright 2018 Joyent, Inc.
 * Copyright 2026 RackTop Systems, Inc.
 */

#include <mdb/mdb_ctf.h>
#include <sys/mdb_modapi.h>
#include "i40e_sw.h"

#define	RSRC_MAX	0x13
static const char *i40e_switch_rsrc_names[] = {
	"VEBs",
	"VSIs",
	"Perfect Match MAC Addresses",
	"S-Tags",
	"Reserved",
	"Multicast Hash Entries",
	"Reserved",
	"VLANs",
	"VSI Lists",
	"Reserved",
	"VLAN Stat pools",
	"Mirror rules",
	"Queue sets",
	"Inner VLAN Forwarding",
	"Reserved",
	"Inner MACs",
	"IPs",
	"GRE/VN1 Keys",
	"VN2 Keys",
	"Tunnelling Ports"
};

/*
 * i40e mdb dcmds
 */
/* ARGSUSED */
static int
i40e_switch_rsrcs_dcmd(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv)
{
	i40e_t i40e;
	int i;

	if (!(flags & DCMD_ADDRSPEC)) {
		mdb_warn("::i40e_switch_rsrcs does not operate globally\n");
		return (DCMD_USAGE);
	}

	if (mdb_vread(&i40e, sizeof (i40e_t), addr) != sizeof (i40e_t)) {
		mdb_warn("failed to read i40e_t at %p", addr);
		return (DCMD_ERR);
	}

	mdb_printf("%-28s %-12s %-8s %-8s %s\n", "TYPE", "GUARANTEE",
	    "TOTAL", "USED", "UNALLOCED");

	for (i = 0; i < i40e.i40e_switch_rsrc_actual; i++) {
		i40e_switch_rsrc_t rsrc;
		uintptr_t raddr = (uintptr_t)i40e.i40e_switch_rsrcs +
		    i * sizeof (i40e_switch_rsrc_t);
		const char *name;

		if (mdb_vread(&rsrc, sizeof (i40e_switch_rsrc_t), raddr) !=
		    sizeof (i40e_switch_rsrc_t)) {
			mdb_warn("failed to read i40e_switch_rsrc_t %d at %p",
			    i, raddr);
			return (DCMD_ERR);
		}

		if (rsrc.resource_type <= RSRC_MAX) {
			name = i40e_switch_rsrc_names[rsrc.resource_type];
		} else {
			char *buf;
			size_t s = mdb_snprintf(NULL, 0, "Unknown type (%d)",
			    rsrc.resource_type);
			buf = mdb_alloc(s + 1, UM_GC | UM_SLEEP);
			(void) mdb_snprintf(buf, s + 1, "Unknown type (%d)",
			    rsrc.resource_type);
			name = buf;
		}

		mdb_printf("%-28s %-12d %-8d %-8d %d\n", name,
		    LE_16(rsrc.guaranteed), LE_16(rsrc.total), LE_16(rsrc.used),
		    LE_16(rsrc.total_unalloced));
	}

	return (DCMD_OK);
}

typedef struct mdb_i40e_trqpair {
	uint32_t		itrq_tx_ring_size;
	uint32_t		itrq_desc_free;
	uint32_t 		*itrq_desc_wbhead;
	uint32_t		itrq_desc_head;
	uint32_t		itrq_desc_tail;
	i40e_tx_desc_t		*itrq_desc_ring;
	i40e_tx_control_block_t	**itrq_tcb_work_list;
} mdb_i40e_trqpair_t;

#define	CTX_CMD(x) \
	((uint64_t)I40E_TX_CTX_DESC_##x << I40E_TXD_CTX_QW1_CMD_SHIFT)
#define	SWTCH_MASK \
	(I40E_TX_CTX_DESC_SWTCH_NOTAG|I40E_TX_CTX_DESC_SWTCH_UPLINK| \
	I40E_TX_CTX_DESC_SWTCH_LOCAL|I40E_TX_CTX_DESC_SWTCH_VSI)

static const mdb_bitmask_t ctx_cmd_mask[] = {
	{ "TSO", CTX_CMD(TSO), CTX_CMD(TSO) },
	{ "TSYN", CTX_CMD(TSYN), CTX_CMD(TSYN) },
	{ "IL2TAG2", CTX_CMD(IL2TAG2), CTX_CMD(IL2TAG2) },
	{ "IL2TAG_IL2H", CTX_CMD(IL2TAG2_IL2H), CTX_CMD(IL2TAG2_IL2H) },
	{ "SWTCH_NOTAG", SWTCH_MASK, CTX_CMD(SWTCH_NOTAG) },
	{ "SWTCH_UPLINK", SWTCH_MASK, CTX_CMD(SWTCH_UPLINK) },
	{ "SWTCH_LOCAL", SWTCH_MASK, CTX_CMD(SWTCH_LOCAL) },
	{ "SWTCH_VSI", SWTCH_MASK, CTX_CMD(SWTCH_VSI) },
	{ "SWPE", CTX_CMD(SWPE), CTX_CMD(SWPE) },
	{ NULL, 0, 0 }
};

#define DATA_CMD(x) ((uint64_t)I40E_TX_DESC_CMD_##x << I40E_TXD_QW1_CMD_SHIFT)
#define	IIPT_MASK \
	((I40E_TX_DESC_CMD_IIPT_NONIP|I40E_TX_DESC_CMD_IIPT_IPV6| \
	I40E_TX_DESC_CMD_IIPT_IPV4|I40E_TX_DESC_CMD_IIPT_IPV4_CSUM) << \
	I40E_TXD_QW1_CMD_SHIFT)
#define	L4T_MASK \
	((I40E_TX_DESC_CMD_L4T_EOFT_UNK|I40E_TX_DESC_CMD_L4T_EOFT_TCP| \
	I40E_TX_DESC_CMD_L4T_EOFT_SCTP|I40E_TX_DESC_CMD_L4T_EOFT_UDP| \
	I40E_TX_DESC_CMD_L4T_EOFT_EOF_N|I40E_TX_DESC_CMD_L4T_EOFT_EOF_T| \
	I40E_TX_DESC_CMD_L4T_EOFT_EOF_NI|I40E_TX_DESC_CMD_L4T_EOFT_EOF_A) << \
	I40E_TXD_QW1_CMD_SHIFT)
static const mdb_bitmask_t data_cmd_mask[] = {
	{ "EOP", DATA_CMD(EOP), DATA_CMD(EOP) },
	{ "RS", DATA_CMD(RS), DATA_CMD(RS) },
	{ "ICRC", DATA_CMD(ICRC), DATA_CMD(ICRC) },
	{ "IL2TAG1", DATA_CMD(IL2TAG1), DATA_CMD(IL2TAG1) },
	{ "DUMMY", DATA_CMD(DUMMY), DATA_CMD(DUMMY) },
	{ "IIPT_NONIP", IIPT_MASK, DATA_CMD(IIPT_NONIP) },
	{ "IIPT_IPV6", IIPT_MASK, DATA_CMD(IIPT_IPV6) },
	{ "IIPT_IPV4", IIPT_MASK, DATA_CMD(IIPT_IPV4) },
	{ "IIPT_IPV4_CSUM", IIPT_MASK, DATA_CMD(IIPT_IPV4_CSUM) },
	{ "FCOET", DATA_CMD(FCOET), DATA_CMD(FCOET) },
	{ "L4T_EOFT_TCP", L4T_MASK, DATA_CMD(L4T_EOFT_TCP) },
	{ "L4T_EOFT_SCTP", L4T_MASK, DATA_CMD(L4T_EOFT_SCTP) },
	{ "L4T_EOFT_UDP", L4T_MASK, DATA_CMD(L4T_EOFT_UDP) },
	{ "L4T_EOFT_EOF_T", L4T_MASK, DATA_CMD(L4T_EOFT_EOF_T) },
	{ "L4T_EOFT_EOF_NI", L4T_MASK, DATA_CMD(L4T_EOFT_EOF_NI) },
	{ "L4T_EOFT_EOF_A", L4T_MASK, DATA_CMD(L4T_EOFT_EOF_A) },
	{ NULL, 0, 0 }
};

static void
i40e_tx_ring_help()
{
	mdb_printf(
	    "\t -a dump all ring entries\n"
	    "\t or\n"
	    "\t combine -b [start index] with -e [end index] to specify a \n"
	    "\t range of ring entries to print\n"
	    "\t -v show detailed descriptor information\n");
}

static void
add_item(char *str, const char *toadd, size_t len)
{
	if (str == NULL)
		return;

	if (str[0] != '\0')
		(void) strlcat(str, " ", len);

	(void) strlcat(str, toadd, len);
}

#define	MSS(x)	\
	(((x) & I40E_TXD_CTX_QW1_MSS_MASK) >> I40E_TXD_CTX_QW1_MSS_SHIFT)

#define	TSO_LEN(x) \
	(((x) & I40E_TXD_CTX_QW1_TSO_LEN_MASK) >> \
	I40E_TXD_CTX_QW1_TSO_LEN_SHIFT)

#define	EOP(x) (((x) & I40E_TXD_QW1_CMD_MASK) >> I40E_TXD_QW1_CMD_SHIFT)
#define	BUF_SZ(x) (((x) & I40E_TXD_QW1_TX_BUF_SZ_MASK) >> \
	I40E_TXD_QW1_TX_BUF_SZ_SHIFT)

static int
i40e_tx_ring_dcmd(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv)
{
	mdb_i40e_trqpair_t trq;
	i40e_tx_desc_t *descring;
	i40e_tx_control_block_t **wklist;
	uint32_t wbhead;
	size_t ringsz, wklistsz;
	boolean_t opt_a = B_FALSE;
	boolean_t opt_r = B_FALSE;
	boolean_t opt_v = B_FALSE;
	char *opt_b = NULL, *opt_e = NULL;
	uint64_t begin = UINT64_MAX, end = UINT64_MAX;
	uint32_t tso_len = 0;
	uint16_t mss = 0;
	boolean_t is_tso = B_FALSE;

	if (!(flags & DCMD_ADDRSPEC)) {
		mdb_warn("::i40e_tx_ring does not operate globally\n");
		return (DCMD_USAGE);
	}

	if (mdb_getopts(argc, argv,
	    'a', MDB_OPT_SETBITS, B_TRUE, &opt_a,
	    'b', MDB_OPT_STR, &opt_b,
	    'e', MDB_OPT_STR, &opt_e,
	    'r', MDB_OPT_SETBITS, B_TRUE, &opt_r,
	    'v', MDB_OPT_SETBITS, B_TRUE, &opt_v,
	    NULL) != argc)
		return (DCMD_USAGE);

	/*
	 * Verify that a legal combination of -a/-b/-e were used.
	 */
	if (opt_a && (opt_b != NULL || opt_e != NULL)) {
		mdb_warn("-a and -b/-e are mutually exclusive\n");
		return (DCMD_USAGE);
	}
	if (opt_r && (opt_b != NULL || opt_e != NULL)) {
		mdb_warn("-r and -b/-e are mutually exclusive\n");
		return (DCMD_USAGE);
	}
	if (opt_a && opt_r) {
		mdb_warn("-a and -r are mutually exclusive\n");
		return (DCMD_USAGE);
	}
	if (argc > 0 && ! opt_a && ! opt_r &&
	    (opt_b == NULL || opt_e == NULL)) {
		mdb_warn("-b/-e must both be specified\n");
		return (DCMD_USAGE);
	}

	if (mdb_ctf_vread(&trq, "i40e_trqpair_t", "mdb_i40e_trqpair_t", addr,
	    0) == -1) {
		mdb_warn("failed to read i40e_trqpair_t at %p", addr);
		return (DCMD_ERR);
	}

	if (opt_b != NULL)
		begin = mdb_strtoull(opt_b);
	if (opt_e != NULL)
		end = mdb_strtoull(opt_e);
	if (opt_a) {
		begin = 0;
		end = trq.itrq_tx_ring_size - 1;
	}
	if (opt_r) {
		begin = trq.itrq_desc_head;
		end = trq.itrq_desc_tail;
	}

	/*
	 * Verify that the requested range of ring entries makes sense.
	 */
	if (argc > 0 && !opt_r &&
	    (end < begin || begin >= trq.itrq_tx_ring_size ||
	    end >= trq.itrq_tx_ring_size)) {
		mdb_warn("invalid range specified\n");
		return (DCMD_USAGE);
	}

	if (mdb_vread(&wbhead, sizeof (uint32_t),
	    (uintptr_t)trq.itrq_desc_wbhead) != sizeof (uint32_t)) {
		mdb_warn("failed to read trq.itrq_desc_wbhead");
		return (DCMD_ERR);
	}
	mdb_printf("%-20s%d\n", "Ring Size:", trq.itrq_tx_ring_size);
	mdb_printf("%-20s%d\n", "Free Descriptors:", trq.itrq_desc_free);
	mdb_printf("%-20s%d\n", "Writeback Head:", wbhead);
	mdb_printf("%-20s%d\n", "Head:", trq.itrq_desc_head);
	mdb_printf("%-20s%d\n", "Tail:", trq.itrq_desc_tail);

	/*
	 * No arguments were specified, so we're done.
	 */
	if (argc == 0)
		return (DCMD_OK);

	/*
	 * Allocate memory and read in the entire TX descriptor ring and
	 * TCB work list.
	 */
	ringsz = sizeof (i40e_tx_desc_t) * trq.itrq_tx_ring_size;
	descring = mdb_alloc(ringsz, UM_SLEEP);
	if (mdb_vread(descring, ringsz, (uintptr_t)trq.itrq_desc_ring) !=
	    ringsz) {
		mdb_warn("Failed to read in TX decriptor ring\n");
		mdb_free(descring, ringsz);
		return (DCMD_ERR);
	}
	wklistsz = sizeof (i40e_tx_control_block_t *) * trq.itrq_tx_ring_size;
	wklist = mdb_alloc(wklistsz, UM_SLEEP);
	if (mdb_vread(wklist, wklistsz, (uintptr_t)trq.itrq_tcb_work_list) !=
	    wklistsz) {
		mdb_warn("Failed to read in TX TCB work list\n");
		mdb_free(descring, ringsz);
		mdb_free(wklist, wklistsz);
		return (DCMD_ERR);
	}

	mdb_printf("\n%-10s %-10s %-16s %-16s %-10s\n", "Index", "Desc Type",
	    "Desc Ptr", "TCB Ptr", "Other");
	for (uint64_t i = begin; i != end; i++) {
		const char *dtype;
		char dother[64];
		char buf[64];
		i40e_tx_desc_t *dptr;
		i40e_tx_control_block_t *tcbptr;
		uint64_t ctob;

		if (i == trq.itrq_tx_ring_size)
			i = 0;

		dptr = &descring[i];
		tcbptr = wklist[i];
		ctob = LE_64(dptr->cmd_type_offset_bsz);
		if (ctob == 0) {
			dtype = "FREE";
		} else {
			switch (ctob & I40E_TXD_QW1_DTYPE_MASK) {
			case I40E_TX_DESC_DTYPE_CONTEXT:
				dtype = "CONTEXT";
				if ((ctob & I40E_TXD_CTX_QW1_CMD_MASK) ==
				    CTX_CMD(TSO)) {
					is_tso = B_TRUE;
					mss = MSS(ctob);
					tso_len = TSO_LEN(ctob);
				} else {
					is_tso = B_FALSE;
					mss = 0;
					tso_len = 0;
				}
				break;
			case I40E_TX_DESC_DTYPE_DATA:
				dtype = "DATA";
				break;
			case I40E_TX_DESC_DTYPE_FILTER_PROG:
				dtype = "FILTER";
				break;
			case I40E_TX_DESC_DTYPE_DESC_DONE:
				dtype = "DONE";
				break;
			default:
				dtype = "UNKNOWN";
			}
		}
		dother[0] = '\0';
		if (i == wbhead)
			add_item(dother, "WBHEAD", sizeof (dother));

		if (i == trq.itrq_desc_head)
			add_item(dother, "HEAD", sizeof (dother));

		if (i == trq.itrq_desc_tail)
			add_item(dother, "TAIL", sizeof (dother));

		if (!opt_v || ctob == 0)
			goto doprint;

		// pkt_len, desc_count, mss, is_tso
		switch (ctob & I40E_TXD_QW1_DTYPE_MASK) {
		case I40E_TX_DESC_DTYPE_FILTER_PROG:
			break;
		case I40E_TX_DESC_DTYPE_CONTEXT:
			(void) mdb_snprintf(buf, sizeof (buf), "%lb", ctob,
			    ctx_cmd_mask);
			add_item(dother, buf, sizeof (dother));

			if (is_tso) {
				(void) mdb_snprintf(buf, sizeof (buf),
				     "TSO_LEN=%u MSS=%u", tso_len, mss);
				add_item(dother, buf, sizeof (dother));
			}
			break;
		case I40E_TX_DESC_DTYPE_DATA:
			(void) mdb_snprintf(buf, sizeof (buf),
			    "%lb BUF_SIZE=%u", ctob, data_cmd_mask,
			    BUF_SZ(ctob));
			add_item(dother, buf, sizeof (dother));
			break;
		}

doprint:
		mdb_printf("%-10d %-10s %-16p %-16p %-10s\n", i, dtype, dptr,
		    tcbptr, dother);
	}

	mdb_free(descring, ringsz);
	mdb_free(wklist, wklistsz);
	return (DCMD_OK);
}

static const mdb_dcmd_t i40e_dcmds[] = {
	{ "i40e_switch_rsrcs", NULL, "print switch resources",
	    i40e_switch_rsrcs_dcmd, NULL },
	{ "i40e_tx_ring", "[-arv] -b [start index] -e [end index]\n",
	    "dump TX descriptor ring state", i40e_tx_ring_dcmd,
	    i40e_tx_ring_help },
	{ NULL }
};

static const mdb_modinfo_t i40e_modinfo = {
	MDB_API_VERSION, i40e_dcmds, NULL
};

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&i40e_modinfo);
}
