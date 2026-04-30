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

/*
 * Helper program for posix_spawn tests. This is exec()d by the test programs
 * via posix_spawn() and reports back process state through stdout (which the
 * parent has wired to a pipe via file actions).
 *
 * Usage:
 *   posix_spawn_child fds <fd0> [fd1 ...]
 *     Report whether each fd is open and its access mode flags.
 *
 *   posix_spawn_child ids
 *     Report uid, euid, gid, egid.
 *
 *   posix_spawn_child sched
 *     Report scheduling policy and priority.
 *
 *   posix_spawn_child sidpgid
 *     Report session ID and process group ID as raw pid_t values.
 *
 *   posix_spawn_child sigmask
 *     Report the current signal mask as a raw sigset_t.
 *
 *   posix_spawn_child sigs <sig0> [sig1 ...]
 *     Report the disposition (SIG_DFL or SIG_IGN) of each signal.
 */

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <string.h>
#include <errno.h>

#include "posix_spawn_common.h"

static int
do_fds(int argc, char *argv[])
{
	for (int i = 2; i < argc; i++) {
		spawn_fd_result_t res;
		int fd = (int)strtol(argv[i], NULL, 10);
		int flags;

		(void) memset(&res, 0, sizeof (res));
		res.srf_fd = fd;

		flags = fcntl(fd, F_GETFL);
		if (flags == -1) {
			res.srf_open = 0;
			res.srf_flags = -1;
			res.srf_err = errno;
		} else {
			res.srf_open = 1;
			res.srf_flags = flags & O_ACCMODE;
			res.srf_err = 0;
		}

		if (write(STDOUT_FILENO, &res, sizeof (res)) != sizeof (res))
			return (EXIT_FAILURE);
	}

	return (EXIT_SUCCESS);
}

static int
do_ids(void)
{
	spawn_id_result_t res;

	(void) memset(&res, 0, sizeof (res));
	res.sir_uid = getuid();
	res.sir_euid = geteuid();
	res.sir_gid = getgid();
	res.sir_egid = getegid();

	if (write(STDOUT_FILENO, &res, sizeof (res)) != sizeof (res))
		return (EXIT_FAILURE);

	return (EXIT_SUCCESS);
}

static int
do_sched(void)
{
	spawn_sched_result_t res;
	struct sched_param param;

	(void) memset(&res, 0, sizeof (res));
	res.ssr_policy = sched_getscheduler(0);
	if (res.ssr_policy == -1)
		return (EXIT_FAILURE);

	if (sched_getparam(0, &param) != 0)
		return (EXIT_FAILURE);
	res.ssr_priority = param.sched_priority;

	if (write(STDOUT_FILENO, &res, sizeof (res)) != sizeof (res))
		return (EXIT_FAILURE);

	return (EXIT_SUCCESS);
}

static int
do_sidpgid(void)
{
	spawn_sidpgid_result_t res;

	(void) memset(&res, 0, sizeof (res));
	res.sspr_sid = getsid(0);
	res.sspr_pgid = getpgid(0);

	if (write(STDOUT_FILENO, &res, sizeof (res)) != sizeof (res))
		return (EXIT_FAILURE);

	return (EXIT_SUCCESS);
}

static int
do_sigmask(void)
{
	sigset_t mask;

	if (sigprocmask(SIG_BLOCK, NULL, &mask) != 0)
		return (EXIT_FAILURE);

	if (write(STDOUT_FILENO, &mask, sizeof (mask)) != sizeof (mask))
		return (EXIT_FAILURE);

	return (EXIT_SUCCESS);
}

static int
do_sigs(int argc, char *argv[])
{
	for (int i = 2; i < argc; i++) {
		spawn_sig_result_t res;
		struct sigaction sa;
		int sig = (int)strtol(argv[i], NULL, 10);

		(void) memset(&res, 0, sizeof (res));
		res.ssr_sig = sig;

		if (sigaction(sig, NULL, &sa) != 0)
			return (EXIT_FAILURE);

		if (sa.sa_handler == SIG_DFL)
			res.ssr_disp = 0;
		else if (sa.sa_handler == SIG_IGN)
			res.ssr_disp = 1;
		else
			res.ssr_disp = 2;

		if (write(STDOUT_FILENO, &res, sizeof (res)) != sizeof (res))
			return (EXIT_FAILURE);
	}

	return (EXIT_SUCCESS);
}

int
main(int argc, char *argv[])
{
	if (argc < 2)
		return (EXIT_FAILURE);

	if (strcmp(argv[1], "fds") == 0) {
		if (argc < 3)
			return (EXIT_FAILURE);
		return (do_fds(argc, argv));
	}

	if (strcmp(argv[1], "ids") == 0)
		return (do_ids());

	if (strcmp(argv[1], "sched") == 0)
		return (do_sched());

	if (strcmp(argv[1], "sidpgid") == 0)
		return (do_sidpgid());

	if (strcmp(argv[1], "sigmask") == 0)
		return (do_sigmask());

	if (strcmp(argv[1], "sigs") == 0) {
		if (argc < 3)
			return (EXIT_FAILURE);
		return (do_sigs(argc, argv));
	}

	return (EXIT_FAILURE);
}
