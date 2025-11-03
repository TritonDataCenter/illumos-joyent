/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2025 Edgecast Cloud LLC.
 */

/*
 * zfscache(8) is a simple front-end to the lone ZFS_IOC_ARC ioctl.
 *
 * This command will force ZFS to adjust its arc_c_min and arc_c_max
 * parameters, and indicate to reaping threads to start 
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <err.h>

#include <sys/types.h>
#include <sys/zfs_ioctl.h>

static int do_ioctl(int, int, uint64_t, uint64_t);

static inline int
do_read(int zfs_fd)
{
	return (do_ioctl(zfs_fd, 0, 0, 0));
}

static inline int
do_write(int zfs_fd, uint64_t min, uint64_t max)
{
	return (do_ioctl(zfs_fd, 1, min, max));
}

static int
do_ioctl(int zfs_fd, int op, uint64_t min, uint64_t max)
{
	zfs_cmd_t zc = { .zc_pad2 = op };
	uint64_t *return_data = (uint64_t *)&zc.zc_name;

	return_data[0] = min;
	return_data[1] = max;
	
	if (ioctl(zfs_fd, ZFS_IOC_ARC, &zc) != 0) {
		switch (errno) {
		case EAGAIN:
			errx(1, "ZFS is busy, please try again.\n");
			break;
		case ERANGE:
			errx(1, "Request forces "
			    "minimum to be more than maximum.\n");
			break;
		case EINVAL:
			errx(1, "Requested minimum %lu is too small.\n", min);
			break;
		case ENOMEM:
			errx(1, "Requested maximum %lu is too large.\n", max);
			break;
		default:
			if (errno >= 1024) {
				/* One of the ZFS errors! */
				errx(1, "ZFS error %d\n", errno);
			} else {
				err(1, "Unexpected ioctl() error");
			}
			break;
		}
	}

	/* Print what the kernel gave us! */
	(void) printf("arc_c_min: %lu\n", return_data[0]);
	(void) printf("arc_c_max: %lu\n", return_data[1]);
	(void) printf("system default arc_c_min: %lu\n", return_data[2]);
	(void) printf("system default arc_c_max: %lu\n", return_data[3]);
	(void) printf("/etc/system zfs_arc_min: %lu\n", return_data[4]);
	(void) printf("/etc/system zfs_arc_max: %lu\n", return_data[5]);

	return (0);
}

int
main(int argc, char *argv[])
{
	int zfs_fd;
	int c;
	uint64_t arc_min = 0, arc_max = 0;

	zfs_fd = open(ZFS_DEV, O_RDWR);
	if (zfs_fd < 0)
		err(1, "failed to open ZFS device (%s)", ZFS_DEV);

	if (argc == 1)
		return (do_read(zfs_fd));

	while ((c = getopt(argc, argv, ":l:u:")) != EOF) {
		switch (c) {
		case 'l':
			arc_min = strtoull(optarg, NULL, 0);
			if (arc_min == UINT64_MAX && errno != 0) {
				(void) fprintf(stderr,
				    "Option -%c requires a number\n",
				    optopt);
				return (1);
			}
			break;
		case 'u':
			arc_max = strtoull(optarg, NULL, 0);
			if (arc_max == UINT64_MAX && errno != 0) {
				(void) fprintf(stderr,
				    "Option -%c requires a number\n",
				    optopt);
				return (1);
			}
			break;
		case ':':
			(void) fprintf(stderr, "Option -%c requires a number\n",
			    optopt);
			return (1);
		case '?':
			(void) fprintf(stderr, "invalid option '%c'\n",
			    optopt);
			return (2);

		}
	}

	return (do_write(zfs_fd, arc_min, arc_max));
}
