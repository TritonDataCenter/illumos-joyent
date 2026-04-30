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
 * Copyright 2026 Oxide Computer Company
 */

#ifndef _POSIX_SPAWN_COMMON_H
#define	_POSIX_SPAWN_COMMON_H

/*
 * Common types shared between posix_spawn test programs and the spawn_child
 * helper. The helper is exec()d via posix_spawn and reports its process state
 * back to the parent through a pipe using these fixed-size structures.
 *
 * The helper's argv[1] selects the mode:
 *
 *   fds <fd0> <fd1> ...     Report file descriptor state
 *   ids                     Report uid/euid/gid/egid
 *   sched                   Report scheduling policy and priority
 *   sidpgid                 Report session ID and process group ID
 *   sigmask                 Report the current signal mask
 *   sigs <sig0> <sig1> ...  Report signal dispositions
 */

#include <sys/types.h>
#include <stdbool.h>
#include <signal.h>
#include <spawn.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Both 32-bit and 64-bit child helpers are built. Each test program exercises
 * both to verify posix_spawn works across data models.
 */
#define	POSIX_SPAWN_CHILD_HELPERS	"posix_spawn_child.32", \
					"posix_spawn_child.64"

extern void posix_spawn_find_helper(char *, size_t, const char *);
extern void posix_spawn_pipe_setup(posix_spawn_file_actions_t *, int [2]);
extern bool posix_spawn_run_child(const char *, const char *,
    posix_spawn_file_actions_t *, posix_spawnattr_t *, char *const []);

/*
 * Result of checking a single file descriptor. Written by spawn_child in
 * "fds" mode, one per requested fd.
 */
typedef struct spawn_fd_result {
	int32_t		srf_fd;		/* fd number requested */
	int32_t		srf_open;	/* 1 if open, 0 if not */
	int32_t		srf_flags;	/* O_ACCMODE from F_GETFL, or -1 */
	int32_t		srf_err;	/* errno if not open, 0 otherwise */
} spawn_fd_result_t;

/*
 * Result of checking a single signal's disposition. Written by spawn_child
 * in "sigs" mode, one per requested signal.
 */
typedef struct spawn_sig_result {
	int32_t		ssr_sig;	/* signal number */
	int32_t		ssr_disp;	/* 0=SIG_DFL, 1=SIG_IGN, 2=other */
} spawn_sig_result_t;

/*
 * Result of querying process IDs. Written by spawn_child in "ids" mode.
 */
typedef struct spawn_id_result {
	uid_t		sir_uid;
	uid_t		sir_euid;
	gid_t		sir_gid;
	gid_t		sir_egid;
} spawn_id_result_t;

/*
 * Result of querying scheduling parameters. Written by spawn_child in
 * "sched" mode.
 */
typedef struct spawn_sched_result {
	int32_t		ssr_policy;
	int32_t		ssr_priority;
} spawn_sched_result_t;

/*
 * Result of querying session and process group IDs. Written by spawn_child
 * in "sidpgid" mode.
 */
typedef struct spawn_sidpgid_result {
	pid_t		sspr_sid;	/* session ID */
	pid_t		sspr_pgid;	/* process group ID */
} spawn_sidpgid_result_t;

#ifdef __cplusplus
}
#endif

#endif /* _POSIX_SPAWN_COMMON_H */
