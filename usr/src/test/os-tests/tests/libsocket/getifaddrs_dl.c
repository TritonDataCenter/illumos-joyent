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
 * This is a basic set of sanity checks for getifaddrs(3SOCKET) and its behavior
 * with AF_LINK addresses. This is generally designed around being a regression
 * test for #16383 and #16384 which were missing data entries in both the
 * sockaddr_dl and the struct if_data.  Rather than change the system and see
 * what's there, we instead walk the links in the system assuming there is
 * usually at least one interface present.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <stdlib.h>
#include <err.h>
#include <libdladm.h>
#include <libdllink.h>
#include <string.h>
#include <stdbool.h>
#include <libdlpi.h>

typedef struct {
	const struct ifaddrs *ic_ifa;
	int ic_ret;
	uint32_t ic_nmatch;
} ifaddr_cb_t;

typedef struct {
	bool mc_found;
	bool *mc_pass;
	const char *mc_name;
	const struct ifaddrs *mc_ifa;
} mac_cb_t;

static boolean_t
dladm_walk_mac_cb(void *arg, dladm_macaddr_attr_t *attr)
{
	mac_cb_t *cb = arg;
	const struct ifaddrs *ifa = cb->mc_ifa;
	const struct sockaddr_dl *dl = (struct sockaddr_dl *)ifa->ifa_addr;
	const struct if_data *if_data = ifa->ifa_data;

	if (attr->ma_addrlen != dl->sdl_alen)
		return (B_TRUE);

	if (memcmp(LLADDR(dl), attr->ma_addr, attr->ma_addrlen) != 0) {
		return (B_TRUE);
	}

	cb->mc_found = true;
	if (if_data != NULL && if_data->ifi_addrlen != attr->ma_addrlen) {
		warnx("TEST FAILED: link %s: found if_data address length "
		    "0x%x, but expected 0x%x", cb->mc_name,
		    if_data->ifi_addrlen, attr->ma_addrlen);
		*cb->mc_pass = false;
	}

	return (B_TRUE);
}

static int
dladm_walk_cb(dladm_handle_t hdl, datalink_id_t id, void *arg)
{
	dladm_status_t dlret;
	ifaddr_cb_t *cb = arg;
	char name[MAXLINKNAMELEN];
	char dlerr[DLADM_STRSIZE];
	uint32_t media;
	char buf[DLADM_PROP_VAL_MAX];
	char *valptr[1];
	uint_t valcnt;

	dlret = dladm_datalink_id2info(hdl, id, NULL, NULL, &media, name,
	    sizeof (name));
	if (dlret != DLADM_STATUS_OK) {
		cb->ic_ret = EXIT_FAILURE;
		warnx("INTERNAL TEST FAILURE: failed to get datalink "
		    "information for link 0x%x: %s", id, dladm_status2str(dlret,
		    dlerr));

		return (DLADM_WALK_CONTINUE);
	}

	/*
	 * Before we scan the list looking for this, see if the link is up. In
	 * particular, dladm will see all datalinks; however, if it isn't really
	 * in use by some client, then it's likely that it's not actually in our
	 * getifaddrs() list. If filtering to links that are not in an unknown
	 * state gives us false positives then we can revisit this.
	 */
	valptr[0] = buf;
	valcnt = 1;
	if (dladm_get_linkprop(hdl, id, DLADM_PROP_VAL_CURRENT, "state", valptr,
	    &valcnt) != DLADM_STATUS_OK) {
		warnx("skipping datalink %s as we could not get \"state\" link "
		    "link property", name);
		return (DLADM_WALK_CONTINUE);
	}

	if (strcmp(buf, "up") != 0 && strcmp(buf, "down") != 0) {
		return (DLADM_WALK_CONTINUE);
	}

	for (const struct ifaddrs *i = cb->ic_ifa; i != NULL; i = i->ifa_next) {
		bool pass = true;

		if (strcmp(name, i->ifa_name) != 0)
			continue;
		if (i->ifa_addr->sa_family != AF_LINK)
			continue;

		struct sockaddr_dl *dl = (struct sockaddr_dl *)i->ifa_addr;
		uint_t ift_type = dlpi_iftype(media);

		if (ift_type != dl->sdl_type) {
			pass = false;
			warnx("TEST FAILED: link %s: found type 0x%x, but "
			    "expected type 0x%x (dlpi 0x%x)", name,
			    dl->sdl_type, ift_type, media);
		}

		size_t nlen = strlen(name);
		if (nlen != dl->sdl_nlen) {
			pass = false;
			warnx("TEST FAILED: link %s: name length mismatch: "
			    "found %u, expected %zu", name, dl->sdl_nlen, nlen);
		}

		if (dl->sdl_nlen > 0) {
			if (strncmp(name, &dl->sdl_data[0], dl->sdl_nlen) !=
			    0) {
				pass = false;
				warnx("TEST FAILED: link %s: sockaddr_dl does "
				    "not match name", name);
			}
		}

		/*
		 * Walk device MAC addresses to ensure that this looks right.
		 */
		mac_cb_t mcb = { false, &pass, name, i };
		(void) dladm_walk_macaddr(hdl, id, &mcb, dladm_walk_mac_cb);
		if (!mcb.mc_found) {
			pass = false;
			warnx("TEST FAILED: link %s: failed to find matching "
			    "mac address", name);
		}

		/*
		 * Check a few last aspects of the ifi_data. The ifi_addrlen has
		 * already been filled in. We need to verify the MTU and type.
		 */
		if (i->ifa_data != NULL) {
			struct if_data *data = i->ifa_data;

			if (data->ifi_type != ift_type) {
				pass = false;
				warnx("TEST FAILED: link %s: found if_data "
				    "ifi_type 0x%x, but expected type 0x%x "
				    "(dlpi 0x%x)", name, data->ifi_type,
				    ift_type, media);
			}

			valptr[0] = buf;
			valcnt = 1;
			if (dladm_get_linkprop(hdl, id, DLADM_PROP_VAL_CURRENT,
			    "mtu", valptr, &valcnt) == DLADM_STATUS_OK) {
				/*
				 * Assume libdladm gives us something
				 * reasonable.
				 */
				ulong_t val = strtoul(buf, NULL, 10);
				if (val != data->ifi_mtu) {
					pass = false;
					warnx("TEST FAILED: link %s: found "
					    "MTU %u, expected %lu", name,
					    data->ifi_mtu, val);
				}
			}
		} else {
			pass = false;
			warnx("TEST FAILED: link %s: found NULL ifa_data "
			    "pointer", name);
		}

		if (pass) {
			(void) printf("TEST PASSED: %s AF_LINK entry looks "
			    "right\n", name);
		} else {
			cb->ic_ret = EXIT_FAILURE;
		}

		cb->ic_nmatch++;
		return (DLADM_WALK_CONTINUE);
	}

	warnx("TEST FAILED: failed to find matching ifaddrs entry for datalink "
	    "%s (0x%x)", name, id);
	cb->ic_ret = EXIT_FAILURE;
	return (DLADM_WALK_CONTINUE);
}

int
main(void)
{
	struct ifaddrs *ifa;
	dladm_status_t dlret;
	dladm_handle_t dladm;
	char dlerr[DLADM_STRSIZE];
	ifaddr_cb_t cb;

	if (getifaddrs(&ifa) != 0) {
		err(EXIT_FAILURE, "INTERNAL TEST FAILURE: getifaddrs() failed: "
		    "test cannot proceed");
	}

	dlret = dladm_open(&dladm);
	if (dlret != DLADM_STATUS_OK) {
		errx(EXIT_FAILURE, "INTERNAL TEST FAILURE: failed to "
		    "initialize libdladm handle: %s", dladm_status2str(dlret,
		    dlerr));
	}

	cb.ic_ifa = ifa;
	cb.ic_ret = EXIT_SUCCESS;
	cb.ic_nmatch = 0;
	(void) dladm_walk_datalink_id(dladm_walk_cb, dladm, &cb,
	    DATALINK_CLASS_PHYS | DATALINK_CLASS_VNIC, DATALINK_ANY_MEDIATYPE,
	    DLADM_OPT_ACTIVE);
	dladm_close(dladm);
	freeifaddrs(ifa);

	if (cb.ic_nmatch == 0) {
		cb.ic_ret = EXIT_FAILURE;
		warnx("no AF_LINK entries found");
	}

	if (cb.ic_ret == EXIT_SUCCESS) {
		(void) printf("All tests passed successfully\n");
	}
	return (cb.ic_ret);
}
