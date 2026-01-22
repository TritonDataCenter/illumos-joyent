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
 * parameters, and indicate things can be sent back if shrinking, or
 * available if growing.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <strings.h>
#include <unistd.h>
#include <err.h>

#include <sys/types.h>
#include <sys/zfs_ioctl.h>

/* "allmem", which if non-zero should be compared to other queries of it. */
static uint64_t allmem = 0;
/* We need to query allmem, so the open ZFS device file needs to be global. */
static int zfs_fd;

typedef enum {
	APTYPE_ABSOLUTE = 0,	/* In bytes! */
	/* These start with allmem and massage it. */
	APTYPE_SHIFT,	/* Add or subtract after shift. */
	APTYPE_PERCENT	/* Add or subtract after percentage. */
} arc_profile_type_t;

typedef struct arc_profile {
	const char *ap_name;
	bool ap_clamp_to_min;  /* If max < min, don't error, clamp to min. */
	arc_profile_type_t ap_mintype;
	uint64_t ap_minval;
	int64_t ap_minadj;
	uint64_t ap_minlowcap;
	uint64_t ap_minhicap;
	arc_profile_type_t ap_maxtype;
	uint64_t ap_maxval;
	int64_t ap_maxadj;
	uint64_t ap_maxlowcap;
	uint64_t ap_maxhicap;
	const char *ap_description;
} arc_profile_t;

const arc_profile_t arc_profiles[] = {
	/* See code for arc_init() in $UTS/common/fs/zfs/arc.c */
	{ "illumos", false,
	    APTYPE_SHIFT, 6, 0, 64 << 20, 1 << 30,
	    APTYPE_SHIFT, 0, -(1 << 30), 64 << 20, 0,
	    "  ARC defaults from illumos-gate:\n"
	    "    - Minimum will be either 64MiB, 1GiB, or 1/64 of allowable\n"
	    "      memory if it fits between those two.\n"
	    "    - Maximum will be all allowable memory but 1GiB, or minimum.\n"
	},

	/* Special profiles for resetting, using ioctl min=0, max=SPECIALS */
	{ "reset-system-defaults", false,
	    APTYPE_ABSOLUTE, 0, 0, 0, 0,
	    APTYPE_ABSOLUTE, UINT64_MAX, 0, 0, 0,
	    "  SmartOS ARC defaults: currently the same as illumos-gate.\n"
	},
	{ "reset-etc-system", false,
	    APTYPE_ABSOLUTE, 0, 0, 0, 0,
	    APTYPE_ABSOLUTE, (UINT64_MAX - 1UL), 0, 0, 0,
	    "  Use values in /etc/system tunables zfs_arc_min and zfs_arc_max,"
	    "\n  where 0 means keep the existing value.\n"
	},

	/* 3/4 of available memory for sufficiently small systems. */
	{ "illumos-low", true,
	    APTYPE_SHIFT, 6, 0, 64 << 20, 1 << 30,
	    APTYPE_PERCENT, 75, 0, 64 << 20, 0,
	    "  ARC defaults for lower-allowable-memory situations in illumos,\n"
	    "  or to give some small space to HVMs:\n"
	    "    - Minimum matches \"illumos\" above\n"
	    "    - Maximum is higher of minimum or 75% of allowable memory.\n"
	},
	/* Similar to illumos, but use half-of-memory. */
	{ "balanced", false,
	    APTYPE_SHIFT, 6, 0, 64 << 20, 1 << 30,
	    APTYPE_SHIFT, 1, 0, 64 << 20, 0,
	    "  ARC defaults trying to balance native workloads and HVMs:\n"
	    "    - Minimum matches \"illumos\" above\n"
	    "    - Maximum is higher of minimum or 50% of allowable memory.\n"
	},
	/*
	 * Inspired by Triton Data Center's default value of 15% reserved for
	 * "kernel memory" for a compute node, take 1/8 (12.5%) for the ARC
	 * and the other 2.5% will definitely be eaten. Minimum is the same as
	 * all of the other profiles.
	 *
	 * On very large systems (> 512GiB RAM), we may want a hard cap on
	 * arc_c_max.
	 */
	{ "compute-hvm", true,
	    APTYPE_SHIFT, 6, 0, 64 << 20, 1 << 30,
	    APTYPE_SHIFT, 3, 0, 64 << 20, 0,
	    "  ARC defaults favoring HVMs:\n"
	    "    - Minimum matches \"illumos\" above\n"
	    "    - Maximum is higher of minimum or 1/8 of allowable memory.\n"
	},
	{ "compute-hvm-64", true,
	    APTYPE_SHIFT, 6, 0, 64 << 20, 1 << 30,
	    APTYPE_SHIFT, 3, 0, 64 << 20, 64UL << 30UL,
	    "  ARC defaults favoring HVMs with a 64GiB cap on maximum:\n"
	    "    - Minimum matches \"illumos\" above\n"
	    "    - Maximum is higher of minimum or 1/8 of allowable memory,\n"
	    "      but capped at 64GiB.\n"
	},
	{ NULL } /* Always must be the last one. */
};

static void
usage(void)
{
	(void) fprintf(stderr, "Usage:\n");
	(void) fprintf(stderr,
	    "zfscache                   (prints ZFS ARC parameters)\n");
	(void) fprintf(stderr,
	    "zfscache -h                (prints this message)\n");
	(void) fprintf(stderr,
	    "zfscache -l BYTES -u BYTES (sets ZFS ARC lower-bound/c_min (-l)\n"
	    "                            and upper-bound/c_max (-u) size.\n"
	    "                            NOTE: BYTES is a signed 64-bit\n"
	    "                            value, negative values are reserved)"
	    "\n");
	(void) fprintf(stderr,
	    "zfscache -p                (prints available ZFS ARC profiles)\n");
	(void) fprintf(stderr,
	    "zfscache -p PROFILE        (sets ZFS ARC to PROFILE's specs)\n");
}

/*
 * We assume everything passed-in is sane and sensible here.
 * If we move to populate-table-from-file, we should do severe sanity checks
 * in file-to-table population.
 */
static bool
prof_to_bytes(uint64_t *bytes, arc_profile_type_t ap_type, uint64_t ap_val,
    int64_t ap_adjust, uint64_t ap_lowcap, uint64_t ap_hicap)
{
	uint64_t retbytes, hundredth;
	bool useadj = (ap_adjust != 0);
	zfs_cmd_t zc = { 0 };

	if (ap_type == APTYPE_ABSOLUTE) {
		*bytes = ap_val;
		return (true);
	}

	/*
	 * Unless we introduce new ap_type values, we need arc_init()'s
	 * "allmem". "allmem" as computed by $UTS/commmon/fs/zfs/arc.c is not
	 * readily available via normal interfaces.  We will do an extra read
	 * of the state of things to get arc_init()-time "allmem".
	 */
	if (ioctl(zfs_fd, ZFS_IOC_ARC, &zc) != 0) {
		/* Just err() out, this should rarely/never happen. */
		err(3, "Getting 'allmem' from kernel");
	}
	allmem = ((uint64_t *)&zc)[4];

	/*
	 * NOTE: If a future ap_type cannot use adj, fix "useadj" in its case
	 * handling.
	 */
	switch (ap_type) {
	case APTYPE_SHIFT:
		retbytes = (allmem >> ap_val);
		break;
	case APTYPE_PERCENT:
		hundredth = allmem / 100UL;
		retbytes = hundredth * ap_val;
		if (retbytes < hundredth) {
			errx(3, "Internal corruption, percentage multiply "
			    "allmem is %lu, 1%% is %lu, %ld%% is %lu\n",
			    allmem, hundredth, ap_val, retbytes);
		}
		break;
	default:
		errx(3, "Internal corruption, unknown ap_type %d\n", ap_type);
		break;
	}

	if (useadj) {
		if (ap_adjust > 0) {
			retbytes += (uint64_t)ap_adjust;
		} else {
			uint64_t unsigned_adjust = (uint64_t)(-ap_adjust);

			retbytes -= unsigned_adjust;
		}
	}

	/* Handle hicap/lowcap. */
	if (ap_hicap != 0 && ap_hicap < retbytes)
		retbytes = ap_hicap;
	if (ap_lowcap != 0 && ap_lowcap > retbytes)
		retbytes = ap_lowcap;

	*bytes = retbytes;
	return (true);
}

static bool
do_profile(const char *profname, uint64_t *arc_min, uint64_t *arc_max)
{
	const arc_profile_t *profile;

	for (profile = arc_profiles; profile->ap_name != NULL; profile++) {
		/* strcmp() is safe because we trust arc_profiles entries. */
		if (strcmp(profile->ap_name, profname) == 0)
			break; /* Found it! */
	}

	if (profile->ap_name == NULL) {
		warnx("Profile name \"%s\" not found.\n", profname);
		usage();
		return (false);
	}

	if (!prof_to_bytes(arc_min, profile->ap_mintype, profile->ap_minval,
	    profile->ap_minadj, profile->ap_minlowcap, profile->ap_minhicap))
		return (false);

	if (!prof_to_bytes(arc_max, profile->ap_maxtype, profile->ap_maxval,
	    profile->ap_maxadj, profile->ap_maxlowcap, profile->ap_maxhicap))
		return (false);

	if (*arc_min > *arc_max) {
		if (!profile->ap_clamp_to_min) {
			warnx("Profile \"%s\" computed min is %lu, "
			    "computed max is %lu.\nThis is an error for "
			    "profile \"%s\".\n", profname, *arc_min,
			    *arc_max, profname);
			return (false);
		}
		*arc_max = *arc_min;
	}

	return (true);
}

static int do_ioctl(int, uint64_t, uint64_t);

static inline int
do_read(void)
{
	return (do_ioctl(0, 0, 0));
}

static inline int
do_write(uint64_t min, uint64_t max)
{
	return (do_ioctl(1, min, max));
}

static int
do_ioctl(int op, uint64_t min, uint64_t max)
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
	(void) printf("arc_c_max: %lu\n\n", return_data[1]);
	(void) printf("system default arc_c_min: %lu\n", return_data[2]);
	(void) printf("system default arc_c_max: %lu\n", return_data[3]);
	(void) printf("system arc_init()-time of maximum available memory "
	    "(allmem): %lu\n\n", return_data[4]);
	if (allmem != 0 && allmem != return_data[4]) {
		warnx("first allmem %lu, current allmem %lu\n",
		    allmem, return_data[4]);
	}
	(void) printf("/etc/system zfs_arc_min: %lu\n", return_data[5]);
	(void) printf("/etc/system zfs_arc_max: %lu\n", return_data[6]);

	return (0);
}

static void
profile_info(void)
{
	const arc_profile_t *profile;

	(void) printf("Available profiles\n");
	(void) printf("==================\n");
	for (profile = arc_profiles; profile->ap_name != NULL; profile++) {
		/* Make this better later. puts() is safe for our strings. */
		(void) fprintf(stderr, "%s\n%s\n", profile->ap_name,
		    profile->ap_description);
	}
}

int
main(int argc, char *argv[])
{
	int c;
	uint64_t arc_min = 0, arc_max = 0;
	const char *errstr = NULL;

	zfs_fd = open(ZFS_DEV, O_RDWR);
	if (zfs_fd < 0)
		err(1, "failed to open ZFS device (%s)", ZFS_DEV);

	if (argc == 1)
		return (do_read());

	while ((c = getopt(argc, argv, ":hl:u:p:")) != EOF) {
		switch (c) {
		case 'h':
			usage();
			return (0);
		case 'l':
			errno = 0;
			arc_min = (uint64_t)strtonumx(optarg, INT64_MIN,
			    INT64_MAX, &errstr, 0);
			if (arc_min == 0 && errno != 0) {
				(void) fprintf(stderr,
				    "Option -%c requires a number: %s (%s)\n\n",
				    optopt, errstr, strerror(errno));
				usage();
				return (1);
			}
			break;
		case 'u':
			errno = 0;
			arc_max = (uint64_t)strtonumx(optarg, INT64_MIN,
			    INT64_MAX, &errstr, 0);
			if (arc_max == 0 && errno != 0) {
				(void) fprintf(stderr,
				    "Option -%c requires a number: %s (%s)\n\n",
				    optopt, errstr, strerror(errno));
				usage();
				return (1);
			}
			break;
		case 'p':
			/*
			 * Select a profile. No usage() on failure is intended.
			 */
			if (!do_profile(optarg, &arc_min, &arc_max))
				return (3);
			break;
		case ':':
			if (optopt == 'p') {
				profile_info();
				return (0);
			}
			(void) fprintf(stderr,
			    "Option -%c requires a number\n\n",
			    optopt);
			usage();
			return (1);
		case '?':
			(void) fprintf(stderr, "invalid option '%c'\n\n",
			    optopt);
			usage();
			return (2);

		}
	}

	return (do_write(arc_min, arc_max));
}
