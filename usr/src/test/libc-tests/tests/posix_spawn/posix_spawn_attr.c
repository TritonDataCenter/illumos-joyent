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
 * Tests for posix_spawn attributes: SETSIGDEF, SETSIGMASK, SETSIGIGN_NP,
 * NOSIGCHLD_NP, and NOEXECERR_NP.
 *
 * Signal-related tests spawn the posix_spawn_child helper as necessary.
 */

#include <err.h>
#include <stdlib.h>
#include <spawn.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/sysmacros.h>
#include <sys/ccompile.h>
#include <sys/debug.h>
#include <wait.h>
#include <string.h>
#include <fcntl.h>
#include <limits.h>
#include <errno.h>
#include <libgen.h>
#include <signal.h>

#include "posix_spawn_common.h"

typedef struct spawn_attr_test {
	const char	*sat_name;
	bool		(*sat_func)(struct spawn_attr_test *);
	short		sat_flags;
} spawn_attr_test_t;

static char posix_spawn_child_path[PATH_MAX];

/*
 * SETSIGDEF tests: verify that signals are reset to SIG_DFL in the child.
 */
static bool
setsigdef_test(spawn_attr_test_t *test)
{
	const char *desc = test->sat_name;
	int pipes[2];
	posix_spawn_file_actions_t acts;
	posix_spawnattr_t attr;
	sigset_t sigdef;
	struct sigaction sa;
	spawn_sig_result_t res[2];
	ssize_t n;
	bool bret = true;
	char sig1_str[12], sig2_str[12];
	char *argv[] = { posix_spawn_child_path, "sigs", sig1_str, sig2_str,
	    NULL };

	(void) snprintf(sig1_str, sizeof (sig1_str), "%d", SIGUSR1);
	(void) snprintf(sig2_str, sizeof (sig2_str), "%d", SIGUSR2);

	/*
	 * Set SIGUSR1 and SIGUSR2 to SIG_IGN in the parent. Without
	 * SETSIGDEF, the child would inherit SIG_IGN.
	 */
	(void) memset(&sa, 0, sizeof (sa));
	sa.sa_handler = SIG_IGN;
	VERIFY0(sigaction(SIGUSR1, &sa, NULL));
	VERIFY0(sigaction(SIGUSR2, &sa, NULL));

	posix_spawn_pipe_setup(&acts, pipes);

	VERIFY0(posix_spawnattr_init(&attr));
	VERIFY0(posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSIGDEF));
	(void) sigemptyset(&sigdef);
	(void) sigaddset(&sigdef, SIGUSR1);
	(void) sigaddset(&sigdef, SIGUSR2);
	VERIFY0(posix_spawnattr_setsigdefault(&attr, &sigdef));

	if (!posix_spawn_run_child(desc, posix_spawn_child_path,
	    &acts, &attr, argv)) {
		bret = false;
		goto out;
	}

	n = read(pipes[0], res, sizeof (res));
	if (n != sizeof (res)) {
		warnx("TEST FAILED: %s: short read from pipe (%zd)", desc, n);
		bret = false;
		goto out;
	}

	if (res[0].ssr_disp != 0) {
		warnx("TEST FAILED: %s: "
		    "SIGUSR1 disposition is %d, expected SIG_DFL (0)",
		    desc, res[0].ssr_disp);
		bret = false;
	}

	if (res[1].ssr_disp != 0) {
		warnx("TEST FAILED: %s: "
		    "SIGUSR2 disposition is %d, expected SIG_DFL (0)",
		    desc, res[1].ssr_disp);
		bret = false;
	}

out:
	sa.sa_handler = SIG_DFL;
	VERIFY0(sigaction(SIGUSR1, &sa, NULL));
	VERIFY0(sigaction(SIGUSR2, &sa, NULL));

	VERIFY0(posix_spawnattr_destroy(&attr));
	VERIFY0(posix_spawn_file_actions_destroy(&acts));
	VERIFY0(close(pipes[1]));
	VERIFY0(close(pipes[0]));

	return (bret);
}

/*
 * SETSIGDEF with an empty set: no signals should be changed.
 * Parent ignores SIGUSR1; child should still see SIG_IGN.
 */
static bool
setsigdef_empty_test(spawn_attr_test_t *test)
{
	const char *desc = test->sat_name;
	int pipes[2];
	posix_spawn_file_actions_t acts;
	posix_spawnattr_t attr;
	sigset_t sigdef;
	struct sigaction sa;
	spawn_sig_result_t res;
	ssize_t n;
	bool bret = true;
	char sig_str[12];
	char *argv[] = { posix_spawn_child_path, "sigs", sig_str, NULL };

	(void) snprintf(sig_str, sizeof (sig_str), "%d", SIGUSR1);

	(void) memset(&sa, 0, sizeof (sa));
	sa.sa_handler = SIG_IGN;
	VERIFY0(sigaction(SIGUSR1, &sa, NULL));

	posix_spawn_pipe_setup(&acts, pipes);

	VERIFY0(posix_spawnattr_init(&attr));
	VERIFY0(posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSIGDEF));
	(void) sigemptyset(&sigdef);
	VERIFY0(posix_spawnattr_setsigdefault(&attr, &sigdef));

	if (!posix_spawn_run_child(desc, posix_spawn_child_path,
	    &acts, &attr, argv)) {
		bret = false;
		goto out;
	}

	n = read(pipes[0], &res, sizeof (res));
	if (n != sizeof (res)) {
		warnx("TEST FAILED: %s: short read from pipe (%zd)", desc, n);
		bret = false;
		goto out;
	}

	if (res.ssr_disp != 1) {
		warnx("TEST FAILED: %s: "
		    "SIGUSR1 disposition is %d, expected SIG_IGN (1)",
		    desc, res.ssr_disp);
		bret = false;
	}

out:
	sa.sa_handler = SIG_DFL;
	VERIFY0(sigaction(SIGUSR1, &sa, NULL));

	VERIFY0(posix_spawnattr_destroy(&attr));
	VERIFY0(posix_spawn_file_actions_destroy(&acts));
	VERIFY0(close(pipes[1]));
	VERIFY0(close(pipes[0]));

	return (bret);
}

/*
 * SETSIGMASK: set the child's signal mask to block SIGUSR1 and SIGUSR2.
 */
static bool
setsigmask_block_test(spawn_attr_test_t *test)
{
	const char *desc = test->sat_name;
	int pipes[2];
	posix_spawn_file_actions_t acts;
	posix_spawnattr_t attr;
	sigset_t newmask;
	sigset_t childmask;
	ssize_t n;
	bool bret = true;
	char *argv[] = { posix_spawn_child_path, "sigmask", NULL };

	posix_spawn_pipe_setup(&acts, pipes);

	VERIFY0(posix_spawnattr_init(&attr));
	VERIFY0(posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSIGMASK));

	(void) sigemptyset(&newmask);
	(void) sigaddset(&newmask, SIGUSR1);
	(void) sigaddset(&newmask, SIGUSR2);
	VERIFY0(posix_spawnattr_setsigmask(&attr, &newmask));

	if (!posix_spawn_run_child(desc, posix_spawn_child_path,
	    &acts, &attr, argv)) {
		bret = false;
		goto out;
	}

	n = read(pipes[0], &childmask, sizeof (childmask));
	if (n != sizeof (childmask)) {
		warnx("TEST FAILED: %s: short read from pipe (%zd)", desc, n);
		bret = false;
		goto out;
	}

	if (!sigismember(&childmask, SIGUSR1)) {
		warnx("TEST FAILED: %s: SIGUSR1 not in child's signal mask",
		    desc);
		bret = false;
	}

	if (!sigismember(&childmask, SIGUSR2)) {
		warnx("TEST FAILED: %s: SIGUSR2 not in child's signal mask",
		    desc);
		bret = false;
	}

out:
	VERIFY0(posix_spawnattr_destroy(&attr));
	VERIFY0(posix_spawn_file_actions_destroy(&acts));
	VERIFY0(close(pipes[1]));
	VERIFY0(close(pipes[0]));

	return (bret);
}

/*
 * SETSIGMASK: parent blocks SIGUSR1, set child mask to empty. The child
 * should have an empty signal mask regardless of the parent's mask.
 */
static bool
setsigmask_empty_test(spawn_attr_test_t *test)
{
	const char *desc = test->sat_name;
	int pipes[2];
	posix_spawn_file_actions_t acts;
	posix_spawnattr_t attr;
	sigset_t newmask, parentmask;
	sigset_t childmask;
	ssize_t n;
	bool bret = true;
	char *argv[] = { posix_spawn_child_path, "sigmask", NULL };

	(void) sigemptyset(&newmask);
	(void) sigaddset(&newmask, SIGUSR1);
	VERIFY0(sigprocmask(SIG_BLOCK, &newmask, &parentmask));

	posix_spawn_pipe_setup(&acts, pipes);

	VERIFY0(posix_spawnattr_init(&attr));
	VERIFY0(posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSIGMASK));
	(void) sigemptyset(&newmask);
	VERIFY0(posix_spawnattr_setsigmask(&attr, &newmask));

	if (!posix_spawn_run_child(desc, posix_spawn_child_path,
	    &acts, &attr, argv)) {
		bret = false;
		goto out;
	}

	n = read(pipes[0], &childmask, sizeof (childmask));
	if (n != sizeof (childmask)) {
		warnx("TEST FAILED: %s: short read from pipe (%zd)", desc, n);
		bret = false;
		goto out;
	}

	if (sigismember(&childmask, SIGUSR1)) {
		warnx("TEST FAILED: %s: "
		    "SIGUSR1 unexpectedly in child's signal mask", desc);
		bret = false;
	}

out:
	VERIFY0(sigprocmask(SIG_SETMASK, &parentmask, NULL));
	VERIFY0(posix_spawnattr_destroy(&attr));
	VERIFY0(posix_spawn_file_actions_destroy(&acts));
	VERIFY0(close(pipes[1]));
	VERIFY0(close(pipes[0]));

	return (bret);
}

/*
 * SETSIGIGN_NP: set SIGUSR1 to SIG_IGN in the child. The parent has
 * SIG_DFL for SIGUSR1.
 */
static bool
setsigign_test(spawn_attr_test_t *test)
{
	const char *desc = test->sat_name;
	int pipes[2];
	posix_spawn_file_actions_t acts;
	posix_spawnattr_t attr;
	sigset_t sigign;
	spawn_sig_result_t res;
	ssize_t n;
	bool bret = true;
	char sig_str[12];
	char *argv[] = { posix_spawn_child_path, "sigs", sig_str, NULL };

	(void) snprintf(sig_str, sizeof (sig_str), "%d", SIGUSR1);

	posix_spawn_pipe_setup(&acts, pipes);

	VERIFY0(posix_spawnattr_init(&attr));
	VERIFY0(posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSIGIGN_NP));
	(void) sigemptyset(&sigign);
	(void) sigaddset(&sigign, SIGUSR1);
	VERIFY0(posix_spawnattr_setsigignore_np(&attr, &sigign));

	if (!posix_spawn_run_child(desc, posix_spawn_child_path,
	    &acts, &attr, argv)) {
		bret = false;
		goto out;
	}

	n = read(pipes[0], &res, sizeof (res));
	if (n != sizeof (res)) {
		warnx("TEST FAILED: %s: short read from pipe (%zd)", desc, n);
		bret = false;
		goto out;
	}

	if (res.ssr_disp != 1) {
		warnx("TEST FAILED: %s: "
		    "SIGUSR1 disposition is %d, expected SIG_IGN (1)",
		    desc, res.ssr_disp);
		bret = false;
	}

out:
	VERIFY0(posix_spawnattr_destroy(&attr));
	VERIFY0(posix_spawn_file_actions_destroy(&acts));
	VERIFY0(close(pipes[1]));
	VERIFY0(close(pipes[0]));

	return (bret);
}

/*
 * SETSIGIGN_NP + SETSIGDEF on the same signal. SETSIGIGN_NP is processed
 * before SETSIGDEF, so SETSIGDEF wins and the child should see SIG_DFL.
 * The two variants set up the ignore and default sets in different order to
 * verify that the result is independent of the API call sequence.
 */
static bool
sigign_then_sigdef_test(spawn_attr_test_t *test)
{
	const char *desc = test->sat_name;
	int pipes[2];
	posix_spawn_file_actions_t acts;
	posix_spawnattr_t attr;
	sigset_t sigign, sigdef;
	spawn_sig_result_t res;
	ssize_t n;
	bool bret = true;
	char sig_str[12];
	char *argv[] = { posix_spawn_child_path, "sigs", sig_str, NULL };

	(void) snprintf(sig_str, sizeof (sig_str), "%d", SIGUSR1);

	posix_spawn_pipe_setup(&acts, pipes);

	VERIFY0(posix_spawnattr_init(&attr));
	VERIFY0(posix_spawnattr_setflags(&attr,
	    POSIX_SPAWN_SETSIGIGN_NP | POSIX_SPAWN_SETSIGDEF));

	(void) sigemptyset(&sigign);
	(void) sigaddset(&sigign, SIGUSR1);
	VERIFY0(posix_spawnattr_setsigignore_np(&attr, &sigign));

	(void) sigemptyset(&sigdef);
	(void) sigaddset(&sigdef, SIGUSR1);
	VERIFY0(posix_spawnattr_setsigdefault(&attr, &sigdef));

	if (!posix_spawn_run_child(desc, posix_spawn_child_path,
	    &acts, &attr, argv)) {
		bret = false;
		goto out;
	}

	n = read(pipes[0], &res, sizeof (res));
	if (n != sizeof (res)) {
		warnx("TEST FAILED: %s: short read from pipe (%zd)", desc, n);
		bret = false;
		goto out;
	}

	if (res.ssr_disp != 0) {
		warnx("TEST FAILED: %s: "
		    "SIGUSR1 disposition is %d, expected SIG_DFL (0)",
		    desc, res.ssr_disp);
		bret = false;
	}

out:
	VERIFY0(posix_spawnattr_destroy(&attr));
	VERIFY0(posix_spawn_file_actions_destroy(&acts));
	VERIFY0(close(pipes[1]));
	VERIFY0(close(pipes[0]));

	return (bret);
}

/*
 * Same as sigign_then_sigdef_test but set up the sigdefault set before the
 * sigignore set, proving the result doesn't depend on API call order.
 */
static bool
sigdef_then_sigign_test(spawn_attr_test_t *test)
{
	const char *desc = test->sat_name;
	int pipes[2];
	posix_spawn_file_actions_t acts;
	posix_spawnattr_t attr;
	sigset_t sigign, sigdef;
	spawn_sig_result_t res;
	ssize_t n;
	bool bret = true;
	char sig_str[12];
	char *argv[] = { posix_spawn_child_path, "sigs", sig_str, NULL };

	(void) snprintf(sig_str, sizeof (sig_str), "%d", SIGUSR1);

	posix_spawn_pipe_setup(&acts, pipes);

	VERIFY0(posix_spawnattr_init(&attr));
	VERIFY0(posix_spawnattr_setflags(&attr,
	    POSIX_SPAWN_SETSIGIGN_NP | POSIX_SPAWN_SETSIGDEF));

	(void) sigemptyset(&sigdef);
	(void) sigaddset(&sigdef, SIGUSR1);
	VERIFY0(posix_spawnattr_setsigdefault(&attr, &sigdef));

	(void) sigemptyset(&sigign);
	(void) sigaddset(&sigign, SIGUSR1);
	VERIFY0(posix_spawnattr_setsigignore_np(&attr, &sigign));

	if (!posix_spawn_run_child(desc, posix_spawn_child_path,
	    &acts, &attr, argv)) {
		bret = false;
		goto out;
	}

	n = read(pipes[0], &res, sizeof (res));
	if (n != sizeof (res)) {
		warnx("TEST FAILED: %s: short read from pipe (%zd)", desc, n);
		bret = false;
		goto out;
	}

	if (res.ssr_disp != 0) {
		warnx("TEST FAILED: %s: "
		    "SIGUSR1 disposition is %d, expected SIG_DFL (0)",
		    desc, res.ssr_disp);
		bret = false;
	}

out:
	VERIFY0(posix_spawnattr_destroy(&attr));
	VERIFY0(posix_spawn_file_actions_destroy(&acts));
	VERIFY0(close(pipes[1]));
	VERIFY0(close(pipes[0]));

	return (bret);
}

/*
 * Flag used to detect SIGCHLD delivery.
 */
static volatile sig_atomic_t sigchld_received = 0;

static void
sigchld_handler(int sig __unused)
{
	sigchld_received = 1;
}

/*
 * NOSIGCHLD_NP test. When sat_flags includes POSIX_SPAWN_NOSIGCHLD_NP,
 * verify that SIGCHLD is suppressed. Otherwise verify it is delivered.
 */
static bool
nosigchld_test(spawn_attr_test_t *test)
{
	const char *desc = test->sat_name;
	bool use_flag = (test->sat_flags & POSIX_SPAWN_NOSIGCHLD_NP) != 0;
	posix_spawn_file_actions_t acts;
	posix_spawnattr_t attr;
	struct sigaction sa, oldsa;
	sigset_t mask, oldmask;
	pid_t pid;
	siginfo_t sig;
	int ret;
	bool bret = true;

	char *true_path = "/usr/bin/true";
	char *argv[] = { true_path, NULL };

	(void) memset(&sa, 0, sizeof (sa));
	sa.sa_handler = sigchld_handler;
	sa.sa_flags = SA_NOCLDSTOP;
	VERIFY0(sigaction(SIGCHLD, &sa, &oldsa));

	(void) sigemptyset(&mask);
	(void) sigaddset(&mask, SIGCHLD);
	VERIFY0(sigprocmask(SIG_UNBLOCK, &mask, &oldmask));

	sigchld_received = 0;

	if ((ret = posix_spawn_file_actions_init(&acts)) != 0) {
		errc(EXIT_FAILURE, ret, "INTERNAL TEST FAILURE: "
		    "file_actions_init");
	}

	VERIFY0(posix_spawnattr_init(&attr));
	if (use_flag) {
		VERIFY0(posix_spawnattr_setflags(&attr,
		    POSIX_SPAWN_NOSIGCHLD_NP));
	}

	ret = posix_spawn(&pid, true_path, &acts, &attr, argv, NULL);
	if (ret != 0) {
		warnx("TEST FAILED: %s: posix_spawn failed with %s",
		    desc, strerrorname_np(ret));
		bret = false;
		goto out;
	}

	/* waitid() may be interrupted by SIGCHLD. Retry on EINTR */
	while (waitid(P_PID, pid, &sig, WEXITED) != 0) {
		if (errno == EINTR)
			continue;
		err(EXIT_FAILURE, "INTERNAL TEST ERROR: %s: waitid", desc);
	}

	if (use_flag) {
		if (sigchld_received != 0) {
			warnx("TEST FAILED: %s: "
			    "SIGCHLD was delivered despite NOSIGCHLD_NP flag",
			    desc);
			bret = false;
		}
	} else {
		if (sigchld_received == 0) {
			warnx("TEST FAILED: %s: SIGCHLD was NOT delivered",
			    desc);
			bret = false;
		}
	}

out:
	VERIFY0(sigaction(SIGCHLD, &oldsa, NULL));
	VERIFY0(sigprocmask(SIG_SETMASK, &oldmask, NULL));
	VERIFY0(posix_spawnattr_destroy(&attr));
	VERIFY0(posix_spawn_file_actions_destroy(&acts));

	return (bret);
}

/*
 * NOEXECERR_NP test. When sat_flags includes POSIX_SPAWN_NOEXECERR_NP,
 * posix_spawn should return 0 and the child exits 127. Otherwise
 * posix_spawn should return ENOENT directly.
 */
static bool
noexecerr_test(spawn_attr_test_t *test)
{
	const char *desc = test->sat_name;
	bool use_flag = (test->sat_flags & POSIX_SPAWN_NOEXECERR_NP) != 0;
	posix_spawn_file_actions_t acts;
	posix_spawnattr_t attr;
	pid_t pid;
	int ret;
	bool bret = true;

	char *bad_path = "/devices/nonexistent/path";
	char *argv[] = { bad_path, NULL };

	if ((ret = posix_spawn_file_actions_init(&acts)) != 0) {
		errc(EXIT_FAILURE, ret,
		    "INTERNAL TEST FAILURE: file_actions_init");
	}

	VERIFY0(posix_spawnattr_init(&attr));
	if (use_flag) {
		VERIFY0(posix_spawnattr_setflags(&attr,
		    POSIX_SPAWN_NOEXECERR_NP));
	}

	ret = posix_spawn(&pid, bad_path, &acts, &attr, argv, NULL);

	if (use_flag) {
		siginfo_t sig;

		if (ret != 0) {
			warnx("TEST FAILED: %s: "
			    "posix_spawn returned %s, expected 0",
			    desc, strerrorname_np(ret));
			bret = false;
			goto out;
		}

		if (waitid(P_PID, pid, &sig, WEXITED) != 0) {
			err(EXIT_FAILURE, "INTERNAL TEST ERROR: %s: waitid",
			    desc);
		}

		if (sig.si_code != CLD_EXITED) {
			warnx("TEST FAILED: %s: "
			    "child did not exit normally: si_code: %d",
			    desc, sig.si_code);
			bret = false;
			goto out;
		}

		if (sig.si_status != 127) {
			warnx("TEST FAILED: %s: "
			    "child exited with status %d, expected 127",
			    desc, sig.si_status);
			bret = false;
		}
	} else {
		if (ret == 0) {
			siginfo_t sig;

			warnx("TEST FAILED: %s: "
			    "posix_spawn returned 0, expected an error", desc);
			(void) waitid(P_PID, pid, &sig, WEXITED);
			bret = false;
			goto out;
		}

		if (ret != ENOENT) {
			warnx("TEST FAILED: %s: "
			    "posix_spawn returned %s, expected ENOENT",
			    desc, strerrorname_np(ret));
			bret = false;
		}
	}

out:
	VERIFY0(posix_spawnattr_destroy(&attr));
	VERIFY0(posix_spawn_file_actions_destroy(&acts));

	return (bret);
}

/*
 * Test that posix_spawnattr_setflags rejects invalid flag bits.
 */
static bool
bad_flags_test(spawn_attr_test_t *test)
{
	posix_spawnattr_t attr;
	int ret;

	VERIFY0(posix_spawnattr_init(&attr));

	ret = posix_spawnattr_setflags(&attr, (short)0x8000);
	if (ret != EINVAL) {
		warnx("TEST FAILED: %s: "
		    "setflags(0x8000) returned %s, expected EINVAL",
		    test->sat_name, strerrorname_np(ret));
		VERIFY0(posix_spawnattr_destroy(&attr));
		return (false);
	}

	VERIFY0(posix_spawnattr_destroy(&attr));

	return (true);
}

/*
 * Test that setflags rejects a value that has valid bits mixed with invalid
 * bits.
 */
static bool
bad_flags_mixed_test(spawn_attr_test_t *test)
{
	posix_spawnattr_t attr;
	int ret;

	VERIFY0(posix_spawnattr_init(&attr));

	ret = posix_spawnattr_setflags(&attr,
	    POSIX_SPAWN_SETSIGDEF | (short)0x8000);
	if (ret != EINVAL) {
		warnx("TEST FAILED: %s: "
		    "setflags(SETSIGDEF|0x8000) returned %s, expected EINVAL",
		    test->sat_name, strerrorname_np(ret));
		VERIFY0(posix_spawnattr_destroy(&attr));
		return (false);
	}

	VERIFY0(posix_spawnattr_destroy(&attr));

	return (true);
}

/*
 * Verify that caught signals in the parent are reset to SIG_DFL in the child
 * after exec, per POSIX: "Signals set to be caught by the calling process
 * image are set to the default action in the new process image."
 *
 * This does NOT use SETSIGDEF; the reset is a property of exec(2) itself.
 */
static void
sigusr1_nop(int sig __unused)
{
}

static bool
caught_handler_reset_test(spawn_attr_test_t *test)
{
	const char *desc = test->sat_name;
	int pipes[2];
	posix_spawn_file_actions_t acts;
	struct sigaction sa, oldsa;
	spawn_sig_result_t res;
	ssize_t n;
	bool bret = true;
	char sig_str[12];
	char *argv[] = { posix_spawn_child_path, "sigs", sig_str, NULL };

	(void) snprintf(sig_str, sizeof (sig_str), "%d", SIGUSR1);

	/*
	 * Install a real signal handler (not SIG_IGN or SIG_DFL). After
	 * exec the child must see SIG_DFL since caught handlers cannot
	 * survive exec.
	 */
	(void) memset(&sa, 0, sizeof (sa));
	sa.sa_handler = sigusr1_nop;
	VERIFY0(sigaction(SIGUSR1, &sa, &oldsa));

	posix_spawn_pipe_setup(&acts, pipes);

	if (!posix_spawn_run_child(desc, posix_spawn_child_path,
	    &acts, NULL, argv)) {
		bret = false;
		goto out;
	}

	n = read(pipes[0], &res, sizeof (res));
	if (n != sizeof (res)) {
		warnx("TEST FAILED: %s: short read from pipe (%zd)", desc, n);
		bret = false;
		goto out;
	}

	if (res.ssr_disp != 0) {
		warnx("TEST FAILED: %s: "
		    "SIGUSR1 disposition is %d, expected SIG_DFL (0)",
		    desc, res.ssr_disp);
		bret = false;
	}

out:
	VERIFY0(sigaction(SIGUSR1, &oldsa, NULL));

	VERIFY0(posix_spawn_file_actions_destroy(&acts));
	VERIFY0(close(pipes[1]));
	VERIFY0(close(pipes[0]));

	return (bret);
}

static spawn_attr_test_t tests[] = {
	{ .sat_name = "SETSIGDEF: SIGUSR1+SIGUSR2 reset to SIG_DFL",
	    .sat_func = setsigdef_test },
	{ .sat_name = "SETSIGDEF: empty set, no change",
	    .sat_func = setsigdef_empty_test },
	{ .sat_name = "SETSIGMASK: block SIGUSR1+SIGUSR2",
	    .sat_func = setsigmask_block_test },
	{ .sat_name = "SETSIGMASK: parent blocks SIGUSR1, child empty",
	    .sat_func = setsigmask_empty_test },
	{ .sat_name = "SETSIGIGN_NP: SIGUSR1 set to SIG_IGN",
	    .sat_func = setsigign_test },
	{ .sat_name = "SETSIGIGN_NP + SETSIGDEF: SETSIGDEF wins (ign first)",
	    .sat_func = sigign_then_sigdef_test },
	{ .sat_name = "SETSIGIGN_NP + SETSIGDEF: SETSIGDEF wins (def first)",
	    .sat_func = sigdef_then_sigign_test },
	{ .sat_name = "exec resets caught handler to SIG_DFL",
	    .sat_func = caught_handler_reset_test },
	{ .sat_name = "NOSIGCHLD_NP: no SIGCHLD delivered",
	    .sat_func = nosigchld_test,
	    .sat_flags = POSIX_SPAWN_NOSIGCHLD_NP },
	{ .sat_name = "NOSIGCHLD_NP control: SIGCHLD delivered normally",
	    .sat_func = nosigchld_test },
	{ .sat_name = "NOEXECERR_NP: bad path returns 0, child exits 127",
	    .sat_func = noexecerr_test,
	    .sat_flags = POSIX_SPAWN_NOEXECERR_NP },
	{ .sat_name = "NOEXECERR_NP control: bad path returns error",
	    .sat_func = noexecerr_test },
	{ .sat_name = "setflags: reject invalid flag bits",
	    .sat_func = bad_flags_test },
	{ .sat_name = "setflags: reject valid+invalid flag mix",
	    .sat_func = bad_flags_mixed_test },
};

int
main(void)
{
	const char *helpers[] = { POSIX_SPAWN_CHILD_HELPERS };
	int ret = EXIT_SUCCESS;

	for (size_t h = 0; h < ARRAY_SIZE(helpers); h++) {
		posix_spawn_find_helper(posix_spawn_child_path,
		    sizeof (posix_spawn_child_path), helpers[h]);
		(void) printf("--- child helper: %s ---\n", helpers[h]);

		for (size_t i = 0; i < ARRAY_SIZE(tests); i++) {
			if (tests[i].sat_func(&tests[i])) {
				(void) printf("TEST PASSED: %s\n",
				    tests[i].sat_name);
			} else {
				ret = EXIT_FAILURE;
			}
		}
	}

	if (ret == EXIT_SUCCESS)
		(void) printf("All tests passed successfully!\n");

	return (ret);
}
