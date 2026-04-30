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
 * Privileged posix_spawn attribute tests. The scheduler tests require
 * proc_priocntl and the RESETIDS test requires proc_setid.
 */

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <priv.h>
#include <pwd.h>
#include <sched.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <wait.h>
#include <sys/debug.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

#include "posix_spawn_common.h"

typedef struct spawn_priv_test {
	const char	*spt_name;
	bool		(*spt_func)(struct spawn_priv_test *);
	const char	*spt_priv;
} spawn_priv_test_t;

static char posix_spawn_child_path[PATH_MAX];

/*
 * SETSCHEDULER: set the child's scheduling policy to a real-time class with a
 * specific priority. Verify the child sees the correct policy and priority.
 */
static bool
setscheduler_test(spawn_priv_test_t *test)
{
	posix_spawn_file_actions_t acts;
	posix_spawnattr_t attr;
	struct sched_param param;
	spawn_sched_result_t res;
	ssize_t n;
	bool bret = true;
	int orig_policy, new_policy, prio_min;
	char *argv[] = { posix_spawn_child_path, "sched", NULL };
	const char *desc = test->spt_name;
	int pipes[2];

	/*
	 * Pick a real-time class that is not the policy for the current
	 * process.
	 */
	orig_policy = sched_getscheduler(0);
	new_policy = (orig_policy != SCHED_FIFO) ? SCHED_FIFO : SCHED_RR;
	prio_min = sched_get_priority_min(new_policy);
	if (prio_min == -1) {
		warn("TEST FAILED: %s: sched_get_priority_min(%d)",
		    desc, new_policy);
		return (false);
	}

	posix_spawn_pipe_setup(&acts, pipes);

	VERIFY0(posix_spawnattr_init(&attr));
	VERIFY0(posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSCHEDULER));
	VERIFY0(posix_spawnattr_setschedpolicy(&attr, new_policy));
	param.sched_priority = prio_min;
	VERIFY0(posix_spawnattr_setschedparam(&attr, &param));

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

	if (res.ssr_policy != new_policy) {
		warnx("TEST FAILED: %s: "
		    "child policy is %d, expected %d",
		    desc, res.ssr_policy, new_policy);
		bret = false;
	}

	if (res.ssr_priority != prio_min) {
		warnx("TEST FAILED: %s: child priority is %d, expected %d",
		    desc, res.ssr_priority, prio_min);
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
 * SETSCHEDPARAM: set only the priority (not the policy). The child should
 * inherit the parent's scheduling policy but with the specified priority.
 * We first switch to a real-time scheduler so the child's policy can be
 * distinguished from the system default.
 */
static bool
setschedparam_test(spawn_priv_test_t *test)
{
	const char *desc = test->spt_name;
	int pipes[2];
	posix_spawn_file_actions_t acts;
	posix_spawnattr_t attr;
	struct sched_param param, orig_param;
	spawn_sched_result_t res;
	ssize_t n;
	bool bret = true;
	int orig_policy, new_policy, parent_policy, prio_min;
	char *argv[] = { posix_spawn_child_path, "sched", NULL };

	/*
	 * Save the original scheduling policy so we can restore it later.
	 * Don't assume the default is SCHED_OTHER; it may be FSS in a zone.
	 */
	orig_policy = sched_getscheduler(0);
	if (orig_policy == -1) {
		warn("TEST FAILED: %s: sched_getscheduler", desc);
		return (false);
	}
	if (sched_getparam(0, &orig_param) != 0) {
		warn("TEST FAILED: %s: sched_getparam", desc);
		return (false);
	}

	/*
	 * Set ourselves to a real-time class so there is a meaningful priority
	 * range to work with. We pick one that is not the policy for the
	 * current process in case that is the system default - the child's
	 * inherited policy is then distinguishable from any system default.
	 */
	new_policy = (orig_policy != SCHED_FIFO) ? SCHED_FIFO : SCHED_RR;

	prio_min = sched_get_priority_min(new_policy);
	if (prio_min == -1) {
		warn("TEST FAILED: %s: sched_get_priority_min(%d)",
		    desc, new_policy);
		return (false);
	}

	param.sched_priority = prio_min;
	if (sched_setscheduler(0, new_policy, &param) == -1) {
		warn("TEST FAILED: %s: sched_setscheduler(%d) failed",
		    desc, new_policy);
		return (false);
	}

	parent_policy = sched_getscheduler(0);

	posix_spawn_pipe_setup(&acts, pipes);

	VERIFY0(posix_spawnattr_init(&attr));
	VERIFY0(posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSCHEDPARAM));
	param.sched_priority = prio_min + 1;
	VERIFY0(posix_spawnattr_setschedparam(&attr, &param));

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

	if (res.ssr_policy != parent_policy) {
		warnx("TEST FAILED: %s: "
		    "child policy is %d, expected parent's policy (%d)",
		    desc, res.ssr_policy, parent_policy);
		bret = false;
	}

	if (res.ssr_priority != prio_min + 1) {
		warnx("TEST FAILED: %s: child priority is %d, expected %d",
		    desc, res.ssr_priority, prio_min + 1);
		bret = false;
	}

out:
	/*
	 * Restore the original scheduling policy.
	 */
	(void) sched_setscheduler(0, orig_policy, &orig_param);

	VERIFY0(posix_spawnattr_destroy(&attr));
	VERIFY0(posix_spawn_file_actions_destroy(&acts));
	VERIFY0(close(pipes[1]));
	VERIFY0(close(pipes[0]));

	return (bret);
}

/*
 * Look up the 'nobody' user and verify that our current uid is not already
 * nobody, since RESETIDS tests depend on the distinction.
 */
static uid_t
get_nobody_uid(const char *desc)
{
	struct passwd *pwd;

	errno = 0;
	if ((pwd = getpwnam("nobody")) == NULL) {
		err(EXIT_FAILURE,
		    "INTERNAL TEST FAILURE: could not find 'nobody' user");
	}

	if (getuid() == pwd->pw_uid) {
		errx(EXIT_FAILURE,
		    "INTERNAL TEST FAILURE: %s: already running as nobody",
		    desc);
	}

	return (pwd->pw_uid);
}

/*
 * RESETIDS: set euid to nobody, then spawn with RESETIDS. The child should see
 * euid == uid. Requires proc_setid.
 */
static bool
resetids_priv_test(spawn_priv_test_t *test)
{
	const char *desc = test->spt_name;
	int pipes[2];
	posix_spawn_file_actions_t acts;
	posix_spawnattr_t attr;
	spawn_id_result_t res;
	ssize_t n;
	bool bret = true;
	uid_t orig_euid = geteuid();
	uid_t nobody_uid;
	char *argv[] = { posix_spawn_child_path, "ids", NULL };

	nobody_uid = get_nobody_uid(desc);

	/*
	 * Set effective uid to that of 'nobody'. RESETIDS should restore euid
	 * to match uid.
	 */
	if (seteuid(nobody_uid) != 0) {
		warn("TEST FAILED: %s: seteuid(nobody) failed", desc);
		return (false);
	}

	posix_spawn_pipe_setup(&acts, pipes);

	VERIFY0(posix_spawnattr_init(&attr));
	VERIFY0(posix_spawnattr_setflags(&attr, POSIX_SPAWN_RESETIDS));

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

	if (res.sir_uid != res.sir_euid) {
		warnx("TEST FAILED: %s: uid %d != euid %d after RESETIDS",
		    desc, res.sir_uid, res.sir_euid);
		bret = false;
	}

	if (res.sir_uid != getuid()) {
		warnx("TEST FAILED: %s: "
		    "child uid is %d, expected parent's uid %d",
		    desc, res.sir_uid, getuid());
		bret = false;
	}

out:
	(void) seteuid(orig_euid);

	VERIFY0(posix_spawnattr_destroy(&attr));
	VERIFY0(posix_spawn_file_actions_destroy(&acts));
	VERIFY0(close(pipes[1]));
	VERIFY0(close(pipes[0]));

	return (bret);
}

/*
 * RESETIDS with a setuid binary. Create a temporary copy of the child helper
 * owned by 'nobody' with the setuid bit set. The setuid bit is applied by
 * exec(2) after RESETIDS processing, so the child's euid should be nobody
 * in both cases. RESETIDS should not prevent legitimate setuid from working.
 * We verify that uid remains the parent's real uid regardless.
 */
static bool
resetids_suid_test(spawn_priv_test_t *test)
{
	const char *desc = test->spt_name;
	int pipes[2];
	posix_spawn_file_actions_t acts;
	posix_spawnattr_t attr;
	spawn_id_result_t res;
	ssize_t n;
	bool bret = true;
	uid_t nobody_uid;
	uid_t parent_uid = getuid();
	char *argv[] = { posix_spawn_child_path, "ids", NULL };
	char suid_path[PATH_MAX];
	char cmdbuf[PATH_MAX + 64];

	nobody_uid = get_nobody_uid(desc);

	/*
	 * Create a setuid copy of the child helper owned by nobody.
	 */
	(void) snprintf(suid_path, sizeof (suid_path),
	    "/tmp/posix_spawn_suid_child.%d", (int)getpid());
	(void) snprintf(cmdbuf, sizeof (cmdbuf),
	    "cp %s %s", posix_spawn_child_path, suid_path);
	if (system(cmdbuf) != 0) {
		warnx("TEST FAILED: %s: failed to copy child helper", desc);
		return (false);
	}

	if (chown(suid_path, nobody_uid, (gid_t)-1) != 0) {
		warn("TEST FAILED: %s: chown failed", desc);
		(void) unlink(suid_path);
		return (false);
	}

	if (chmod(suid_path, S_ISUID | 0555) != 0) {
		warn("TEST FAILED: %s: chmod failed", desc);
		(void) unlink(suid_path);
		return (false);
	}

	/*
	 * First verify the control case: without RESETIDS, the setuid bit
	 * causes euid to become nobody.
	 */
	posix_spawn_pipe_setup(&acts, pipes);

	argv[0] = suid_path;

	if (!posix_spawn_run_child(desc, suid_path, &acts, NULL, argv)) {
		bret = false;
		VERIFY0(posix_spawn_file_actions_destroy(&acts));
		VERIFY0(close(pipes[1]));
		VERIFY0(close(pipes[0]));
		goto cleanup;
	}

	n = read(pipes[0], &res, sizeof (res));
	if (n != sizeof (res)) {
		warnx("TEST FAILED: %s: control: short read from pipe (%zd)",
		    desc, n);
		bret = false;
	} else if (res.sir_euid != nobody_uid) {
		warnx("TEST FAILED: %s: control: euid is %d, "
		    "expected nobody (%d)",
		    desc, res.sir_euid, nobody_uid);
		bret = false;
	} else if (res.sir_uid != parent_uid) {
		warnx("TEST FAILED: %s: control: uid is %d, "
		    "expected parent uid (%d)",
		    desc, res.sir_uid, parent_uid);
		bret = false;
	}

	VERIFY0(posix_spawn_file_actions_destroy(&acts));
	VERIFY0(close(pipes[1]));
	VERIFY0(close(pipes[0]));

	/*
	 * With RESETIDS: the setuid bit still takes effect (euid = nobody)
	 * because exec applies suid after RESETIDS. The real uid should
	 * remain the parent's real uid.
	 */
	posix_spawn_pipe_setup(&acts, pipes);

	VERIFY0(posix_spawnattr_init(&attr));
	VERIFY0(posix_spawnattr_setflags(&attr, POSIX_SPAWN_RESETIDS));

	if (!posix_spawn_run_child(desc, suid_path, &acts, &attr, argv)) {
		bret = false;
		goto out;
	}

	n = read(pipes[0], &res, sizeof (res));
	if (n != sizeof (res)) {
		warnx("TEST FAILED: %s: short read from pipe (%zd)", desc, n);
		bret = false;
		goto out;
	}

	if (res.sir_euid != nobody_uid) {
		warnx("TEST FAILED: %s: "
		    "euid is %d, expected nobody (%d) (suid > RESETIDS)",
		    desc, res.sir_euid, nobody_uid);
		bret = false;
	}

	if (res.sir_uid != parent_uid) {
		warnx("TEST FAILED: %s: "
		    "uid is %d, expected parent's uid %d",
		    desc, res.sir_uid, parent_uid);
		bret = false;
	}

out:
	VERIFY0(posix_spawnattr_destroy(&attr));
	VERIFY0(posix_spawn_file_actions_destroy(&acts));
	VERIFY0(close(pipes[1]));
	VERIFY0(close(pipes[0]));

cleanup:
	(void) unlink(suid_path);

	return (bret);
}

static spawn_priv_test_t tests[] = {
	{ .spt_name = "SETSCHEDULER: RT SCHED with min priority",
	    .spt_func = setscheduler_test, .spt_priv = PRIV_PROC_PRIOCNTL },
	{ .spt_name = "SETSCHEDPARAM: priority change under RT SCHED",
	    .spt_func = setschedparam_test, .spt_priv = PRIV_PROC_PRIOCNTL },
	{ .spt_name = "RESETIDS: euid reset after seteuid(nobody)",
	    .spt_func = resetids_priv_test, .spt_priv = PRIV_PROC_SETID },
	{ .spt_name = "RESETIDS: setuid binary retains suid euid",
	    .spt_func = resetids_suid_test, .spt_priv = PRIV_PROC_SETID },
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
			if (!priv_ineffect(tests[i].spt_priv)) {
				(void) printf("TEST FAILED: %s: "
				    "requires %s privilege\n",
				    tests[i].spt_name, tests[i].spt_priv);
				ret = EXIT_FAILURE;
			} else if (tests[i].spt_func(&tests[i])) {
				(void) printf("TEST PASSED: %s\n",
				    tests[i].spt_name);
			} else {
				ret = EXIT_FAILURE;
			}
		}
	}

	if (ret == EXIT_SUCCESS)
		(void) printf("All tests passed successfully!\n");

	return (ret);
}
