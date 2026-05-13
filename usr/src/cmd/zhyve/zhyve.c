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
 * Copyright (c) 2018, Joyent, Inc.
 * Copyright 2026 Edgecast Cloud LLC.
 */

/*
 * This small 'zhyve' stub is init for the zone: we therefore need to pick up
 * our command-line arguments placed in ZHYVE_CMD_FILE by the boot stub, do a
 * little administration, and exec the real bhyve binary.
 *
 * As an optional escape hatch, if BHYVE_ZONE_PATH exists and is executable
 * inside the zone, exec it instead of the platform's bhyve.  This lets a
 * zone image ship an alternate bhyve (or a wrapper that performs additional
 * setup, e.g. starting swtpm) without requiring a platform image rebuild.
 * A present-but-invalid BHYVE_ZONE_PATH (non-regular, missing exec bit,
 * too short to classify, etc.) is fatal: zhyve exits rather than silently
 * falling back to the platform bhyve, so operator misconfiguration is
 * visible in the zone boot log.
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <libnvpair.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/corectl.h>

extern char **environ;

#define	ZHYVE_CMD_FILE	"/var/run/bhyve/zhyve.cmd"
#define	BHYVE_ZONE_PATH	"/bhyve.zone"

/*
 * Do a read of the specified size or return an error.  Returns 0 on success
 * and -1 on error.  Sets errno to EINVAL if EOF is encountered.  For other
 * errors, see read(2).
 */
static int
full_read(int fd, char *buf, size_t len)
{
	ssize_t nread = 0;
	size_t totread = 0;

	while (totread < len) {
		nread = read(fd, buf + totread, len - totread);
		if (nread == 0) {
			errno = EINVAL;
			return (-1);
		}
		if (nread < 0) {
			if (errno == EINTR || errno == EAGAIN) {
				continue;
			}
			return (-1);
		}
		totread += nread;
	}
	assert(totread == len);

	return (0);
}

/*
 * Reads the command line options from the packed nvlist in the file referenced
 * by path.  On success, 0 is returned and the members of *argv reference memory
 * allocated from an nvlist.  On failure, -1 is returned.
 */

static int
parse_options_file(const char *path, uint_t *argcp, char ***argvp)
{
	int fd = -1;
	struct stat stbuf;
	char *buf = NULL;
	nvlist_t *nvl = NULL;
	int ret;

	if ((fd = open(path, O_RDONLY)) < 0 ||
	    fstat(fd, &stbuf) != 0 ||
	    (buf = malloc(stbuf.st_size)) == NULL ||
	    full_read(fd, buf, stbuf.st_size) != 0 ||
	    nvlist_unpack(buf, stbuf.st_size, &nvl, 0) != 0 ||
	    nvlist_lookup_string_array(nvl, "bhyve_args", argvp, argcp) != 0) {
		nvlist_free(nvl);
		ret = -1;
	} else {
		ret = 0;
	}

	free(buf);
	(void) close(fd);

	(void) printf("Configuration from %s:\n", path);
	nvlist_print(stdout, nvl);

	return (ret);
}

/*
 * Setup to suppress core dumps within the zone.
 */
static void
config_core_dumps()
{
	(void) core_set_options(0x0);
}

/*
 * If BHYVE_ZONE_PATH exists, exec it in place of the platform bhyve.
 * Returns only when BHYVE_ZONE_PATH does not exist; every other failure
 * exits without falling back to the platform bhyve.
 *
 * Symlinks are intentionally followed at open time so an operator can
 * swap candidates by repointing the link.
 *
 * Non-script binaries are exec'd via fexecve(3C) on the open fd, so a
 * concurrent rename, unlink, or symlink swap cannot change what runs.
 * #!-scripts must be exec'd by name because the kernel hands the path
 * to the interpreter, which reopens it; we resolve the fd via
 * /proc/self/path/<fd> to obtain a name to pass to execv, and a small
 * swap window between readlink and execv remains for the script case.
 * Any failure to read /proc/self/path/<fd> (error or truncation) is
 * fatal on both branches: we always want a resolved path for logging,
 * and the script branch needs it for execv.  The operator is responsible
 * for restricting write access to BHYVE_ZONE_PATH and any symlink target.
 */
static void
try_bhyve_override(char **argv)
{
	int fd;
	struct stat st;
	char shebang[2];
	ssize_t slen;
	boolean_t is_script;
	char procpath[PATH_MAX];
	char resolved[PATH_MAX];
	ssize_t rlen;

	fd = open(BHYVE_ZONE_PATH, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		if (errno == ENOENT)
			return;
		(void) fprintf(stderr, "open(%s) failed: %s\n",
		    BHYVE_ZONE_PATH, strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (fstat(fd, &st) != 0) {
		(void) fprintf(stderr, "fstat(%s) failed: %s\n",
		    BHYVE_ZONE_PATH, strerror(errno));
		exit(EXIT_FAILURE);
	}
	if (!S_ISREG(st.st_mode)) {
		(void) fprintf(stderr, "%s: not a regular file\n",
		    BHYVE_ZONE_PATH);
		exit(EXIT_FAILURE);
	}
	if ((st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) == 0) {
		(void) fprintf(stderr, "%s: not executable (mode 0%o)\n",
		    BHYVE_ZONE_PATH, (unsigned int)(st.st_mode & 07777));
		exit(EXIT_FAILURE);
	}

	slen = pread(fd, shebang, sizeof (shebang), 0);
	if (slen < 0) {
		(void) fprintf(stderr, "pread(%s) failed: %s\n",
		    BHYVE_ZONE_PATH, strerror(errno));
		exit(EXIT_FAILURE);
	}
	if (slen < (ssize_t)sizeof (shebang)) {
		(void) fprintf(stderr, "%s: too short to classify "
		    "(%zd byte(s), need 2)\n", BHYVE_ZONE_PATH, slen);
		exit(EXIT_FAILURE);
	}
	is_script = (shebang[0] == '#' && shebang[1] == '!');

	/*
	 * `resolved` is both the script exec target and the log label.
	 * readlink failure or truncation is fatal on both branches.
	 */
	(void) snprintf(procpath, sizeof (procpath),
	    "/proc/self/path/%d", fd);
	rlen = readlink(procpath, resolved, sizeof (resolved) - 1);
	if (rlen < 0) {
		(void) fprintf(stderr, "readlink(%s) failed: %s; "
		    "refusing to exec %s\n",
		    procpath, strerror(errno), BHYVE_ZONE_PATH);
		exit(EXIT_FAILURE);
	}
	if ((size_t)rlen >= sizeof (resolved) - 1) {
		(void) fprintf(stderr,
		    "readlink(%s) result truncated at %zd bytes; "
		    "refusing to exec %s\n",
		    procpath, rlen, BHYVE_ZONE_PATH);
		exit(EXIT_FAILURE);
	}
	resolved[rlen] = '\0';

	if (strcmp(resolved, BHYVE_ZONE_PATH) != 0) {
		(void) fprintf(stderr, "Using bhyve override at %s -> %s\n",
		    BHYVE_ZONE_PATH, resolved);
	} else {
		(void) fprintf(stderr, "Using bhyve override at %s\n",
		    resolved);
	}

	if (is_script) {
		(void) execv(resolved, argv);
		(void) fprintf(stderr, "execv(%s) failed: %s\n",
		    resolved, strerror(errno));
	} else {
		(void) fexecve(fd, argv, environ);
		(void) fprintf(stderr, "fexecve(%s) failed: %s\n",
		    resolved, strerror(errno));
	}
	exit(EXIT_FAILURE);
}

int
main(int argc, char **argv)
{
	char **tmpargs;
	uint_t zargc;
	char **zargv;
	int fd;

	config_core_dumps();

	fd = open("/dev/null", O_WRONLY);
	assert(fd >= 0);
	if (fd != STDIN_FILENO) {
		(void) dup2(fd, STDIN_FILENO);
		(void) close(fd);
	}

	fd = open("/dev/zfd/1", O_WRONLY);
	assert(fd >= 0);
	if (fd != STDOUT_FILENO) {
		(void) dup2(fd, STDOUT_FILENO);
		(void) close(fd);
	}
	setvbuf(stdout, NULL, _IONBF, 0);

	fd = open("/dev/zfd/2", O_WRONLY);
	assert(fd >= 0);
	if (fd != STDERR_FILENO) {
		(void) dup2(fd, STDERR_FILENO);
		(void) close(fd);
	}
	setvbuf(stderr, NULL, _IONBF, 0);

	if (parse_options_file(ZHYVE_CMD_FILE, &zargc, &zargv) != 0) {
		(void) fprintf(stderr, "%s: failed to parse %s: %s\n",
		    argv[0], ZHYVE_CMD_FILE, strerror(errno));
		return (EXIT_FAILURE);
	}

	/*
	 * Annoyingly, we need a NULL at the end.
	 */

	if ((tmpargs = malloc(sizeof (*zargv) * (zargc + 1))) == NULL) {
		perror("malloc failed");
		return (EXIT_FAILURE);
	}

	memcpy(tmpargs, zargv, sizeof (*zargv) * zargc);
	tmpargs[zargc] = NULL;

	try_bhyve_override(tmpargs);

	(void) execv("/usr/sbin/bhyve", tmpargs);

	perror("execv failed");
	return (EXIT_FAILURE);
}
