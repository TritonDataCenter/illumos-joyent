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
 * Common utilities shared across posix_spawn test programs.
 */

#include <err.h>
#include <stdlib.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <wait.h>
#include <sys/debug.h>
#include <fcntl.h>
#include <limits.h>
#include <libgen.h>

#include "posix_spawn_common.h"

/*
 * Locate a helper binary relative to our own executable. The helper is
 * expected to be in the same directory as the test binary.
 */
void
posix_spawn_find_helper(char *buf, size_t bufsz, const char *name)
{
	ssize_t ret;
	char origin[PATH_MAX];

	ret = readlink("/proc/self/path/a.out", origin, PATH_MAX - 1);
	if (ret < 0) {
		err(EXIT_FAILURE, "INTERNAL TEST FAILURE: "
		    "failed to read a.out path");
	}

	origin[ret] = '\0';
	if (snprintf(buf, bufsz, "%s/%s", dirname(origin), name) >= bufsz) {
		errx(EXIT_FAILURE, "INTERNAL TEST FAILURE: "
		    "failed to assemble %s path", name);
	}

	if (access(buf, X_OK) != 0) {
		err(EXIT_FAILURE, "INTERNAL TEST FAILURE: failed to access %s",
		    buf);
	}
}

/*
 * Set up a pipe and standard fd wiring for capturing child output. Stdin and
 * stderr are directed to /dev/null, stdout is wired to the write end of the
 * pipe, and both pipe fds are closed in the child.
 */
void
posix_spawn_pipe_setup(posix_spawn_file_actions_t *acts, int pipes[2])
{
	int ret;

	if (pipe2(pipes, O_NONBLOCK) != 0) {
		err(EXIT_FAILURE,
		    "INTERNAL TEST FAILURE: failed to create a pipe");
	}

	VERIFY3S(pipes[0], >, STDERR_FILENO);
	VERIFY3S(pipes[1], >, STDERR_FILENO);

	if ((ret = posix_spawn_file_actions_init(acts)) != 0) {
		errc(EXIT_FAILURE, ret, "INTERNAL TEST FAILURE: "
		    "failed to initialize posix_spawn file actions");
	}

	if ((ret = posix_spawn_file_actions_addopen(acts, STDIN_FILENO,
	    "/dev/null", O_RDONLY, 0)) != 0) {
		errc(EXIT_FAILURE, ret, "INTERNAL TEST FAILURE: "
		    "failed to add /dev/null open action");
	}

	if ((ret = posix_spawn_file_actions_adddup2(acts, STDIN_FILENO,
	    STDERR_FILENO)) != 0) {
		errc(EXIT_FAILURE, ret, "INTERNAL TEST FAILURE: "
		    "failed to add stderr dup action");
	}

	if ((ret = posix_spawn_file_actions_adddup2(acts, pipes[1],
	    STDOUT_FILENO)) != 0) {
		errc(EXIT_FAILURE, ret, "INTERNAL TEST FAILURE: "
		    "failed to add stdout dup action");
	}

	if ((ret = posix_spawn_file_actions_addclose(acts, pipes[0])) != 0) {
		errc(EXIT_FAILURE, ret, "INTERNAL TEST FAILURE: "
		    "failed to add pipes[0] close action");
	}

	if ((ret = posix_spawn_file_actions_addclose(acts, pipes[1])) != 0) {
		errc(EXIT_FAILURE, ret, "INTERNAL TEST FAILURE: "
		    "failed to add pipes[1] close action");
	}
}

/*
 * Spawn a child process, wait for it to exit, and verify it exited cleanly.
 * Returns true if the child exited with status 0, false otherwise.
 */
bool
posix_spawn_run_child(const char *desc, const char *path,
    posix_spawn_file_actions_t *acts, posix_spawnattr_t *attr,
    char *const argv[])
{
	siginfo_t sig;
	pid_t pid;
	int ret;

	ret = posix_spawn(&pid, path, acts, attr, argv, NULL);
	if (ret != 0) {
		warnx("TEST FAILED: %s: posix_spawn failed with %s",
		    desc, strerrorname_np(ret));
		return (false);
	}

	if (waitid(P_PID, pid, &sig, WEXITED) != 0) {
		err(EXIT_FAILURE, "INTERNAL TEST ERROR: %s: "
		    "failed to wait on child", desc);
	}

	if (sig.si_code != CLD_EXITED) {
		warnx("TEST FAILED: %s: "
		    "child did not exit normally: si_code: %d",
		    desc, sig.si_code);
		return (false);
	}

	if (sig.si_status != 0) {
		warnx("TEST FAILED: %s: child exited with status %d",
		    desc, sig.si_status);
		return (false);
	}

	return (true);
}
