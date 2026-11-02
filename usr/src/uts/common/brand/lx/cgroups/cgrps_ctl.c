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
 * cgroup v2 controllers.
 *
 * We provide the "cpu", "memory" and "pids" controllers. They are listed in
 * cgroup.controllers and can be enabled through cgroup.subtree_control, with
 * the Linux rules: a non-root cgroup with processes in it can not enable
 * controllers for its children ("no internal processes"), a process can not
 * be moved into such a cgroup, and a controller can not be disabled while a
 * child cgroup still has it enabled.
 *
 * Unlike on Linux, the controller interface files exist in every non-root
 * cgroup, whether or not the controller is enabled for it. (cpu.stat is also
 * in the root cgroup, as on Linux.)
 *
 * pids:	pids.current is the number of tasks (threads) in the subtree.
 *		pids.max is enforced if the pids controller is enabled for the
 *		cgroup: creating a process or thread fails with EAGAIN when a
 *		limit would be exceeded. The check is done by the brand library
 *		before it creates the process or thread (B_CGROUP_PIDS_CHECK),
 *		so concurrent creations can exceed the limit slightly.
 *		pids.events counts the failures.
 *
 * memory:	memory.current and memory.stat report the resident memory of
 *		the processes in the subtree. The limits (memory.min, low,
 *		high, max, swap.max) and memory.oom.group can be set and read
 *		back, but are not enforced.
 *
 * cpu:		cpu.stat reports the user and system time of the processes in
 *		the subtree, including processes which have exited (accounted
 *		in lx_proc_exit() via cgrp_ctl_proc_exit()). cpu.weight,
 *		cpu.weight.nice, cpu.max and cpu.idle can be set and read back,
 *		but are not enforced.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/errno.h>
#include <sys/proc.h>
#include <sys/var.h>
#include <sys/zone.h>
#include <sys/sunddi.h>
#include <sys/brand.h>
#include <vm/as.h>
#include <vm/rm.h>

#include "cgrps.h"

static const struct {
	uint_t		cc_mask;
	const char	*cc_name;
} cgrp_ctls[] = {
	{ CGC_CPU,	"cpu" },
	{ CGC_MEMORY,	"memory" },
	{ CGC_PIDS,	"pids" },
};

#define	CGRP_NCTLS	(sizeof (cgrp_ctls) / sizeof (cgrp_ctls[0]))

/*
 * The Linux nice to load weight mapping (sched_prio_to_weight), used to
 * convert between cpu.weight and cpu.weight.nice.
 */
static const uint_t cgrp_nice_weight[40] = {
	/* -20 */ 88761, 71755, 56483, 46273, 36291,
	/* -15 */ 29154, 23254, 18705, 14949, 11916,
	/* -10 */ 9548, 7620, 6100, 4904, 3906,
	/*  -5 */ 3121, 2501, 1991, 1586, 1277,
	/*   0 */ 1024, 820, 655, 526, 423,
	/*   5 */ 335, 272, 215, 172, 137,
	/*  10 */ 110, 87, 70, 56, 45,
	/*  15 */ 36, 29, 23, 18, 15
};

#define	CGRP_WEIGHT_DFL		100
#define	CGRP_WEIGHT_MIN		1
#define	CGRP_WEIGHT_MAX		10000
#define	CGRP_CPU_PERIOD_DFL	100000
#define	CGRP_CPU_PERIOD_MIN	1000
#define	CGRP_CPU_PERIOD_MAX	1000000

boolean_t
cgrp_is_root(cgrp_node_t *cn)
{
	return (cn->cgn_parent == NULL || cn->cgn_parent == cn);
}

/*
 * Initialize the controller settings of a new cgroup v2 cgroup.
 */
void
cgrp_ctl_node_init(cgrp_node_t *cn)
{
	cn->cgn_subtree_ctl = 0;
	cn->cgn_settings[CGS_CPU_WEIGHT] = CGRP_WEIGHT_DFL;
	cn->cgn_settings[CGS_CPU_MAX_QUOTA] = CG_UNLIMITED;
	cn->cgn_settings[CGS_CPU_MAX_PERIOD] = CGRP_CPU_PERIOD_DFL;
	cn->cgn_settings[CGS_CPU_IDLE] = 0;
	cn->cgn_settings[CGS_MEM_MIN] = 0;
	cn->cgn_settings[CGS_MEM_LOW] = 0;
	cn->cgn_settings[CGS_MEM_HIGH] = CG_UNLIMITED;
	cn->cgn_settings[CGS_MEM_MAX] = CG_UNLIMITED;
	cn->cgn_settings[CGS_MEM_SWAP_MAX] = CG_UNLIMITED;
	cn->cgn_settings[CGS_MEM_OOM_GROUP] = 0;
	cn->cgn_settings[CGS_PIDS_MAX] = CG_UNLIMITED;
}

/*
 * The controllers available in cgroup 'dir' (cgroup.controllers).
 */
uint_t
cgrp_ctl_available(cgrp_node_t *dir)
{
	if (cgrp_is_root(dir))
		return (CGC_ALL);
	return (dir->cgn_parent->cgn_subtree_ctl);
}

/*
 * Format the names of the controllers in 'mask' as a cgroup.controllers or
 * cgroup.subtree_control line.
 */
size_t
cgrp_ctl_names(uint_t mask, char *buf, size_t blen)
{
	size_t len = 0;
	int i;

	buf[0] = '\0';
	for (i = 0; i < CGRP_NCTLS; i++) {
		if ((mask & cgrp_ctls[i].cc_mask) == 0)
			continue;
		len += snprintf(buf + len, blen - len, "%s%s",
		    len == 0 ? "" : " ", cgrp_ctls[i].cc_name);
		if (len >= blen - 1)
			break;
	}
	len += snprintf(buf + MIN(len, blen - 1), blen - MIN(len, blen - 1),
	    "\n");
	return (MIN(len, blen - 1));
}

static boolean_t
cgrp_ctl_child_dir(cgrp_dirent_t *dp)
{
	return (dp->cgd_cgrp_node->cgn_type == CG_CGROUP_DIR &&
	    strcmp(dp->cgd_name, ".") != 0 && strcmp(dp->cgd_name, "..") != 0);
}

/*
 * Handle a write to cgroup.subtree_control: a space separated list of
 * "+<controller>" and "-<controller>" tokens.
 */
int
cgrp_wr_subtree_ctl(cgrp_mnt_t *cgm, cgrp_node_t *cn, struct uio *uio)
{
	char buf[256];
	char *p, *tok;
	uint_t enable = 0, disable = 0;
	uint_t cg_id = cn->cgn_parent->cgn_id;
	cgrp_node_t *dir;
	cgrp_dirent_t *dp;
	int error, i;

	if ((error = cgrp_get_wr_str(uio, buf, sizeof (buf))) != 0)
		return (error);

	for (p = buf; *p != '\0'; ) {
		uint_t mask = 0;

		while (*p == ' ' || *p == '\t' || *p == '\n')
			p++;
		if (*p == '\0')
			break;
		tok = p;
		while (*p != '\0' && *p != ' ' && *p != '\t' && *p != '\n')
			p++;
		if (*p != '\0')
			*p++ = '\0';

		if (tok[0] != '+' && tok[0] != '-')
			return (EINVAL);
		for (i = 0; i < CGRP_NCTLS; i++) {
			if (strcmp(tok + 1, cgrp_ctls[i].cc_name) == 0)
				mask = cgrp_ctls[i].cc_mask;
		}
		if (mask == 0)
			return (EINVAL);

		if (tok[0] == '+') {
			enable |= mask;
			disable &= ~mask;
		} else {
			disable |= mask;
			enable &= ~mask;
		}
	}

	mutex_enter(&cgm->cg_contents);
	if ((dir = cgrp_cg_hash_lookup(cgm, cg_id)) == NULL) {
		error = ENODEV;
		goto out;
	}

	if ((enable & ~cgrp_ctl_available(dir)) != 0) {
		error = ENOENT;
		goto out;
	}

	enable &= ~dir->cgn_subtree_ctl;
	disable &= dir->cgn_subtree_ctl;

	/* No internal processes */
	if (enable != 0 && !cgrp_is_root(dir) && dir->cgn_task_cnt > 0) {
		error = EBUSY;
		goto out;
	}

	/* A controller can't be disabled while a child cgroup uses it. */
	if (disable != 0) {
		for (dp = dir->cgn_dir; dp != NULL; dp = dp->cgd_next) {
			cgrp_node_t *child = dp->cgd_cgrp_node;

			if (cgrp_ctl_child_dir(dp) &&
			    (child->cgn_subtree_ctl & disable) != 0) {
				error = EBUSY;
				goto out;
			}
		}
	}

	dir->cgn_subtree_ctl = (dir->cgn_subtree_ctl | enable) & ~disable;

out:
	mutex_exit(&cgm->cg_contents);
	return (error);
}

/*
 * Sum up the resident memory and the CPU time of the processes in the cgroup
 * with ID 'cg_id' and its descendants, including the CPU time of processes
 * which have exited.
 */
static int
cgrp_ctl_usage(cgrp_mnt_t *cgm, uint_t cg_id, uint64_t *rssp,
    uint64_t *utimep, uint64_t *stimep)
{
	zoneid_t zoneid = curproc->p_zone->zone_id;
	pid_t schedpid = curproc->p_zone->zone_zsched->p_pid;
	uint64_t rss = 0, utime = 0, stime = 0;
	cgrp_node_t *dir, *cn;
	int i;

	for (i = 1; i < v.v_proc; i++) {
		proc_t *p;
		lx_lwp_data_t *plwpd;
		lx_proc_data_t *lxpd;
		boolean_t in_cg;

		mutex_enter(&pidlock);
		if ((p = pid_entry(i)) == NULL ||
		    p->p_stat == SIDL || p->p_stat == SZOMB ||
		    (p->p_flag & SSYS) != 0 ||
		    p->p_pid == 0 ||
		    p->p_pid == schedpid ||
		    p->p_brand != &lx_brand ||
		    p->p_zone->zone_id != zoneid) {
			mutex_exit(&pidlock);
			continue;
		}

		mutex_enter(&p->p_lock);
		mutex_exit(&pidlock);

		/* Exited processes are accounted in cgn_dead_[us]time */
		if (p->p_tlist == NULL ||
		    (plwpd = ttolxlwp(p->p_tlist)) == NULL ||
		    ((lxpd = ptolxproc(p)) != NULL &&
		    (lxpd->l_flags & LX_PROC_EXITED) != 0)) {
			mutex_exit(&p->p_lock);
			continue;
		}

		mutex_enter(&cgm->cg_contents);
		in_cg = cgrp_in_subtree(cgm, plwpd->br_cgroupid, cg_id);
		mutex_exit(&cgm->cg_contents);

		if (in_cg) {
			/* p_lock keeps p_as from being freed */
			if (p->p_as != &kas)
				rss += rm_asrss(p->p_as);
			utime += p->p_utime;
			stime += p->p_stime;
		}
		mutex_exit(&p->p_lock);
	}

	mutex_enter(&cgm->cg_contents);
	if ((dir = cgrp_cg_hash_lookup(cgm, cg_id)) == NULL) {
		mutex_exit(&cgm->cg_contents);
		return (ENODEV);
	}
	for (cn = dir; cn != NULL; cn = cgrp_subtree_next(dir, cn)) {
		utime += cn->cgn_dead_utime;
		stime += cn->cgn_dead_stime;
	}
	mutex_exit(&cgm->cg_contents);

	*rssp = rss * PAGESIZE;
	*utimep = TICK_TO_USEC(utime);
	*stimep = TICK_TO_USEC(stime);
	return (0);
}

static int
cgrp_ctl_fmt_max(uint64_t val, char *buf, size_t blen)
{
	if (val == CG_UNLIMITED)
		return (snprintf(buf, blen, "max\n"));
	return (snprintf(buf, blen, "%llu\n", (u_longlong_t)val));
}

/*
 * Convert cpu.weight to cpu.weight.nice, like Linux: find the nice value
 * whose load weight is closest.
 */
static int
cgrp_ctl_weight_to_nice(uint64_t weight)
{
	uint64_t shares = (weight * 1024 + CGRP_WEIGHT_DFL / 2) /
	    CGRP_WEIGHT_DFL;
	uint64_t delta, last_delta;
	int prio;

	last_delta = (shares > cgrp_nice_weight[0]) ?
	    shares - cgrp_nice_weight[0] : cgrp_nice_weight[0] - shares;
	for (prio = 1; prio < 40; prio++) {
		delta = (shares > cgrp_nice_weight[prio]) ?
		    shares - cgrp_nice_weight[prio] :
		    cgrp_nice_weight[prio] - shares;
		if (delta >= last_delta)
			break;
		last_delta = delta;
	}
	return (prio - 1 - 20);
}

/*
 * Read a controller interface file.
 */
int
cgrp_ctl_read(cgrp_mnt_t *cgm, cgrp_node_t *cn, struct uio *uio)
{
	char buf[640];
	size_t len = 0;
	uint_t cg_id = cn->cgn_parent->cgn_id;
	cgrp_node_t *dir;
	uint64_t rss, utime, stime, *set;
	int error;

	switch (cn->cgn_type) {
	case CG_CPU_STAT:
		if ((error = cgrp_ctl_usage(cgm, cg_id, &rss, &utime,
		    &stime)) != 0)
			return (error);
		len = snprintf(buf, sizeof (buf),
		    "usage_usec %llu\nuser_usec %llu\nsystem_usec %llu\n"
		    "nr_periods 0\nnr_throttled 0\nthrottled_usec 0\n"
		    "nr_bursts 0\nburst_usec 0\n",
		    (u_longlong_t)(utime + stime), (u_longlong_t)utime,
		    (u_longlong_t)stime);
		return (cgrp_rd_buf(buf, MIN(len, sizeof (buf) - 1), uio));

	case CG_MEM_CURRENT:
		if ((error = cgrp_ctl_usage(cgm, cg_id, &rss, &utime,
		    &stime)) != 0)
			return (error);
		len = snprintf(buf, sizeof (buf), "%llu\n", (u_longlong_t)rss);
		return (cgrp_rd_buf(buf, MIN(len, sizeof (buf) - 1), uio));

	case CG_MEM_STAT:
		if ((error = cgrp_ctl_usage(cgm, cg_id, &rss, &utime,
		    &stime)) != 0)
			return (error);
		len = snprintf(buf, sizeof (buf),
		    "anon %llu\nfile 0\nkernel 0\nkernel_stack 0\n"
		    "pagetables 0\nsock 0\nshmem 0\nfile_mapped 0\n"
		    "file_dirty 0\nfile_writeback 0\nswapcached 0\n"
		    "inactive_anon 0\nactive_anon %llu\ninactive_file 0\n"
		    "active_file 0\nunevictable 0\npgfault 0\npgmajfault 0\n",
		    (u_longlong_t)rss, (u_longlong_t)rss);
		return (cgrp_rd_buf(buf, MIN(len, sizeof (buf) - 1), uio));

	default:
		break;
	}

	mutex_enter(&cgm->cg_contents);
	if ((dir = cgrp_cg_hash_lookup(cgm, cg_id)) == NULL) {
		mutex_exit(&cgm->cg_contents);
		return (ENODEV);
	}
	set = dir->cgn_settings;

	switch (cn->cgn_type) {
	case CG_CPU_WEIGHT:
		len = snprintf(buf, sizeof (buf), "%llu\n",
		    (u_longlong_t)set[CGS_CPU_WEIGHT]);
		break;
	case CG_CPU_WEIGHT_NICE:
		len = snprintf(buf, sizeof (buf), "%d\n",
		    cgrp_ctl_weight_to_nice(set[CGS_CPU_WEIGHT]));
		break;
	case CG_CPU_MAX:
		if (set[CGS_CPU_MAX_QUOTA] == CG_UNLIMITED) {
			len = snprintf(buf, sizeof (buf), "max %llu\n",
			    (u_longlong_t)set[CGS_CPU_MAX_PERIOD]);
		} else {
			len = snprintf(buf, sizeof (buf), "%llu %llu\n",
			    (u_longlong_t)set[CGS_CPU_MAX_QUOTA],
			    (u_longlong_t)set[CGS_CPU_MAX_PERIOD]);
		}
		break;
	case CG_CPU_IDLE:
		len = snprintf(buf, sizeof (buf), "%llu\n",
		    (u_longlong_t)set[CGS_CPU_IDLE]);
		break;
	case CG_MEM_MIN:
		len = cgrp_ctl_fmt_max(set[CGS_MEM_MIN], buf, sizeof (buf));
		break;
	case CG_MEM_LOW:
		len = cgrp_ctl_fmt_max(set[CGS_MEM_LOW], buf, sizeof (buf));
		break;
	case CG_MEM_HIGH:
		len = cgrp_ctl_fmt_max(set[CGS_MEM_HIGH], buf, sizeof (buf));
		break;
	case CG_MEM_MAX:
		len = cgrp_ctl_fmt_max(set[CGS_MEM_MAX], buf, sizeof (buf));
		break;
	case CG_MEM_SWAP_MAX:
		len = cgrp_ctl_fmt_max(set[CGS_MEM_SWAP_MAX], buf,
		    sizeof (buf));
		break;
	case CG_MEM_OOM_GROUP:
		len = snprintf(buf, sizeof (buf), "%llu\n",
		    (u_longlong_t)set[CGS_MEM_OOM_GROUP]);
		break;
	case CG_MEM_EVENTS:
		len = snprintf(buf, sizeof (buf), "low 0\nhigh 0\nmax 0\n"
		    "oom 0\noom_kill 0\noom_group_kill 0\n");
		break;
	case CG_MEM_SWAP_CURRENT:
		len = snprintf(buf, sizeof (buf), "0\n");
		break;
	case CG_PIDS_CURRENT:
		len = snprintf(buf, sizeof (buf), "%u\n", dir->cgn_subtree_cnt);
		break;
	case CG_PIDS_MAX:
		len = cgrp_ctl_fmt_max(set[CGS_PIDS_MAX], buf, sizeof (buf));
		break;
	case CG_PIDS_EVENTS:
		len = snprintf(buf, sizeof (buf), "max %llu\n",
		    (u_longlong_t)dir->cgn_pids_events);
		break;
	default:
		VERIFY(0);
	}
	mutex_exit(&cgm->cg_contents);

	return (cgrp_rd_buf(buf, MIN(len, sizeof (buf) - 1), uio));
}

/*
 * Parse an unsigned decimal number, optionally (if 'suffix_ok') followed by a
 * K, M, G or T suffix, like the Linux memparse().
 */
static int
cgrp_ctl_parse_num(const char *str, boolean_t suffix_ok, uint64_t *valp)
{
	u_longlong_t val;
	char *end;
	int shift = 0;

	if (*str < '0' || *str > '9')
		return (EINVAL);
	if (ddi_strtoull(str, &end, 10, &val) != 0)
		return (EINVAL);

	if (*end != '\0') {
		if (!suffix_ok || end[1] != '\0')
			return (EINVAL);
		switch (*end) {
		case 'k': case 'K':
			shift = 10;
			break;
		case 'm': case 'M':
			shift = 20;
			break;
		case 'g': case 'G':
			shift = 30;
			break;
		case 't': case 'T':
			shift = 40;
			break;
		default:
			return (EINVAL);
		}
		if (val > (UINT64_MAX >> shift))
			return (ERANGE);
		val <<= shift;
	}

	*valp = val;
	return (0);
}

/*
 * Parse "max" or a number.
 */
static int
cgrp_ctl_parse_max(const char *str, boolean_t suffix_ok, uint64_t *valp)
{
	if (strcmp(str, "max") == 0) {
		*valp = CG_UNLIMITED;
		return (0);
	}
	return (cgrp_ctl_parse_num(str, suffix_ok, valp));
}

/*
 * Write a controller interface file.
 */
int
cgrp_ctl_write(cgrp_mnt_t *cgm, cgrp_node_t *cn, struct uio *uio)
{
	char buf[64];
	uint_t cg_id = cn->cgn_parent->cgn_id;
	cgrp_setting_t setting;
	uint64_t val = 0, val2 = 0;
	boolean_t set2 = B_FALSE;
	cgrp_node_t *dir;
	char *p;
	int error;

	switch (cn->cgn_type) {
	case CG_CPU_STAT:
	case CG_MEM_CURRENT:
	case CG_MEM_EVENTS:
	case CG_MEM_STAT:
	case CG_MEM_SWAP_CURRENT:
	case CG_PIDS_CURRENT:
	case CG_PIDS_EVENTS:
		/* read-only files */
		return (EACCES);
	default:
		break;
	}

	if ((error = cgrp_get_wr_str(uio, buf, sizeof (buf))) != 0)
		return (error);

	switch (cn->cgn_type) {
	case CG_CPU_WEIGHT:
		setting = CGS_CPU_WEIGHT;
		if ((error = cgrp_ctl_parse_num(buf, B_FALSE, &val)) != 0)
			return (error);
		if (val < CGRP_WEIGHT_MIN || val > CGRP_WEIGHT_MAX)
			return (ERANGE);
		break;

	case CG_CPU_WEIGHT_NICE: {
		longlong_t nice;
		char *end;

		setting = CGS_CPU_WEIGHT;
		if (ddi_strtoll(buf, &end, 10, &nice) != 0 || *end != '\0' ||
		    buf[0] == '\0')
			return (EINVAL);
		if (nice < -20 || nice > 19)
			return (ERANGE);
		val = ((uint64_t)cgrp_nice_weight[nice + 20] *
		    CGRP_WEIGHT_DFL + 512) / 1024;
		val = MAX(val, CGRP_WEIGHT_MIN);
		break;
	}

	case CG_CPU_MAX:
		/* "$MAX [$PERIOD]" */
		setting = CGS_CPU_MAX_QUOTA;
		for (p = buf; *p != '\0' && *p != ' '; p++)
			;
		if (*p == ' ') {
			*p++ = '\0';
			if ((error = cgrp_ctl_parse_num(p, B_FALSE,
			    &val2)) != 0)
				return (error);
			if (val2 < CGRP_CPU_PERIOD_MIN ||
			    val2 > CGRP_CPU_PERIOD_MAX)
				return (EINVAL);
			set2 = B_TRUE;
		}
		if ((error = cgrp_ctl_parse_max(buf, B_FALSE, &val)) != 0)
			return (error);
		if (val != CG_UNLIMITED && val < CGRP_CPU_PERIOD_MIN)
			return (EINVAL);
		break;

	case CG_CPU_IDLE:
	case CG_MEM_OOM_GROUP:
		setting = (cn->cgn_type == CG_CPU_IDLE) ? CGS_CPU_IDLE :
		    CGS_MEM_OOM_GROUP;
		if (strcmp(buf, "0") == 0)
			val = 0;
		else if (strcmp(buf, "1") == 0)
			val = 1;
		else
			return (EINVAL);
		break;

	case CG_MEM_MIN:
	case CG_MEM_LOW:
	case CG_MEM_HIGH:
	case CG_MEM_MAX:
	case CG_MEM_SWAP_MAX:
		switch (cn->cgn_type) {
		case CG_MEM_MIN:
			setting = CGS_MEM_MIN;
			break;
		case CG_MEM_LOW:
			setting = CGS_MEM_LOW;
			break;
		case CG_MEM_HIGH:
			setting = CGS_MEM_HIGH;
			break;
		case CG_MEM_MAX:
			setting = CGS_MEM_MAX;
			break;
		default:
			setting = CGS_MEM_SWAP_MAX;
			break;
		}
		if ((error = cgrp_ctl_parse_max(buf, B_TRUE, &val)) != 0)
			return (error);
		/* Like Linux, memory limits are in whole pages. */
		if (val != CG_UNLIMITED)
			val = P2ALIGN(val, (uint64_t)PAGESIZE);
		break;

	case CG_PIDS_MAX:
		setting = CGS_PIDS_MAX;
		if ((error = cgrp_ctl_parse_max(buf, B_FALSE, &val)) != 0)
			return (error);
		if (val != CG_UNLIMITED && val > INT_MAX)
			return (EINVAL);
		break;

	default:
		VERIFY(0);
		return (EINVAL);
	}

	mutex_enter(&cgm->cg_contents);
	if ((dir = cgrp_cg_hash_lookup(cgm, cg_id)) == NULL) {
		mutex_exit(&cgm->cg_contents);
		return (ENODEV);
	}
	dir->cgn_settings[setting] = val;
	if (set2)
		dir->cgn_settings[CGS_CPU_MAX_PERIOD] = val2;
	mutex_exit(&cgm->cg_contents);

	return (0);
}

/*
 * Check whether a task (process or thread) can be created in the cgroup with
 * ID 'cg_id' without exceeding the pids.max limit of the cgroup or of one of
 * its ancestors. Returns EAGAIN if not, like the Linux fork(2).
 */
int
cgrp_pids_check(cgrp_mnt_t *cgm, uint_t cg_id)
{
	cgrp_node_t *cn;
	int error = 0;

	if (!CG_IS_V2(cgm))
		return (0);

	mutex_enter(&cgm->cg_contents);
	for (cn = cgrp_cg_hash_lookup(cgm, cg_id);
	    cn != NULL && !cgrp_is_root(cn); cn = cn->cgn_parent) {
		uint64_t max = cn->cgn_settings[CGS_PIDS_MAX];

		/* The limit applies if the pids controller is enabled. */
		if ((cn->cgn_parent->cgn_subtree_ctl & CGC_PIDS) == 0 ||
		    max == CG_UNLIMITED)
			continue;

		if ((uint64_t)cn->cgn_subtree_cnt + 1 > max) {
			cn->cgn_pids_events++;
			error = EAGAIN;
			break;
		}
	}
	mutex_exit(&cgm->cg_contents);

	return (error);
}

/*
 * Account the CPU time (in ticks) of an exiting process to its cgroup.
 */
void
cgrp_ctl_proc_exit(cgrp_mnt_t *cgm, uint_t cg_id, clock_t utime,
    clock_t stime)
{
	cgrp_node_t *cn;

	if (!CG_IS_V2(cgm))
		return;

	mutex_enter(&cgm->cg_contents);
	if ((cn = cgrp_cg_hash_lookup(cgm, cg_id)) != NULL) {
		cn->cgn_dead_utime += (uint64_t)MAX(utime, 0);
		cn->cgn_dead_stime += (uint64_t)MAX(stime, 0);
	}
	mutex_exit(&cgm->cg_contents);
}
