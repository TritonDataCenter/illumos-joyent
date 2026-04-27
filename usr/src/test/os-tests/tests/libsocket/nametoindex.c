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
 * Verify that a few sources all agree on socket index information:
 * getifaddrs(3SOCKET), if_nametoindex(3SOCKET), and manually walking
 * interfaces. if_nametoindex() doesn't always handle the fact that we can have
 * two interfaces (v4 and v6) with the same name. if_nametoindex() prefers v4
 * addresses over v6. So when both are up, we'll need to be careful.
 *
 * This test assumes the set of interfaces isn't changing durings its lifetime.
 */

#include <stdlib.h>
#include <err.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/sockio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/sysmacros.h>

int
main(void)
{
	int ret = EXIT_SUCCESS;
	int s4, s6;
	struct ifaddrs *ifa;

	if ((s4 = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		err(EXIT_FAILURE, "failed to get IPv4 socket");
	}

	if ((s6 = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) {
		err(EXIT_FAILURE, "failed to get IPv6 socket");
	}

	if (getifaddrs(&ifa) != 0) {
		err(EXIT_FAILURE, "failed to get address information");
	}

	for (struct ifaddrs *i = ifa; i != NULL; i = i->ifa_next) {
		struct lifreq lif;
		char name[IF_NAMESIZE];
		sa_family_t fam = i->ifa_addr->sa_family;

		if (fam != AF_INET && fam != AF_INET6) {
			continue;
		}

		/*
		 * First ask the kernel our index.
		 */
		(void) memset(&lif, 0, sizeof (lif));
		if (strlcpy(lif.lifr_name, i->ifa_name,
		    sizeof (lif.lifr_name)) >= sizeof (lif.lifr_name)) {
			errx(EXIT_FAILURE, "INTERNAL TEST FAILURE: encountered "
			    "interface name %s that would overflow struct "
			    "lifreq length!", i->ifa_name);
		}

		if (ioctl(fam == AF_INET ? s4 : s6, SIOCGLIFINDEX, &lif) != 0) {
			warn("TEST FAILED: failed to ask kernel for index of "
			    "interface %s (family 0x%x", i->ifa_name, fam);
			ret = EXIT_FAILURE;
			continue;
		}

		if (if_indextoname(lif.lifr_index, name) == NULL) {
			warn("TEST FAILED: if_indextoname() failed to convert "
			    "index 0x%x back to %s", lif.lifr_index,
			    i->ifa_name);
			ret = EXIT_FAILURE;
			continue;
		}

		if (strcmp(name, i->ifa_name) != 0) {
			warn("TEST FAILED: if_indextoname() returned name %s "
			    "for index 0x%x, but expected %s", name,
			    lif.lifr_index, i->ifa_name);
			ret = EXIT_FAILURE;
		} else {
			(void) printf("TEST PASSED: Mapped %s (fam 0x%x) index "
			    "back to expected name\n", i->ifa_name, fam);
		}

		/*
		 * Now go from the name to the index. In general we expect the
		 * IPv4 and IPv6 interfaces with the same name to share the same
		 * index.
		 */
		uint_t idx = if_nametoindex(i->ifa_name);
		if (idx == 0) {
			warn("TEST FAILED: if_nametoindex() unexpected failed "
			    "on %s (fam 0x%x)", i->ifa_name, fam);
			ret = EXIT_FAILURE;
		} else if (idx != lif.lifr_index) {
			warnx("TEST FAILED: if_nametoindex() on %s (fam 0x%x) "
			    "returned index 0x%x, but expected 0x%x from "
			    "SIOCGLIFINDEX\n", i->ifa_name, fam, idx,
			    lif.lifr_index);
			ret = EXIT_FAILURE;
		} else {
			(void) printf("TEST PASSED: %s (fam 0x%x) name to "
			    "index round tripped successfully\n", i->ifa_name,
			    fam);
		}
	}

	const char *bad_names[] = { "", "nonumber", "thisiswaytoolongforanif0",
	    "bad/char23", "if1234567890123456" };
	for (size_t i = 0; i < ARRAY_SIZE(bad_names); i++) {
		uint_t idx = if_nametoindex(bad_names[i]);
		if (idx != 0) {
			warnx("TEST FAILED: if_nametoindex() returned idx 0x%x "
			    "on invalid name '%s': expected failure", idx,
			    bad_names[i]);
			ret = EXIT_FAILURE;
		} else if (errno != ENXIO) {
			warnx("TEST FAILED: if_nametoindex() returned %s on "
			    "invalid name '%s': expected ENXIO",
			    strerrorname_np(errno), bad_names[i]);
			ret = EXIT_FAILURE;
		} else {
			(void) printf("TEST PASSED: if_nametoindex() failed "
			    "bad name '%s' with ENXIO\n", bad_names[i]);
		}
	}

	freeifaddrs(ifa);
	(void) close(s6);
	(void) close(s4);
	if (ret == EXIT_SUCCESS) {
		(void) printf("All tests passed successfully\n");
	}
	return (ret);
}
