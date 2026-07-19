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
 * Copyright 2026 Edgecast Cloud LLC.
 */

/*
 * Dynamic Device Personalization (DDP) package load.
 *
 * The E810 needs a firmware package to enable its full pipeline (flexible
 * descriptors, advanced switch and flow rules).  The package is an opaque blob
 * the common code parses and downloads to the device; the driver only reads the
 * file and hands it over.  If the file is missing or rejected the device runs
 * in "safe mode": the common code reduces the advertised capabilities and the
 * driver still attaches and passes basic traffic, so a missing package is not
 * fatal.  This loads before the VSI is built because safe mode clamps the queue
 * counts the VSI configuration consumes.
 */

#include <sys/firmload.h>

#include "ice.h"
#include "ice_common.h"
#include "ice_ddp_common.h"

#define	ICE_DDP_PKG_FILE	"ice.pkg"

/*
 * Upper bound on the package file we will read into the kernel.  The shipped
 * package is well under this; the cap keeps a corrupt or hostile file from
 * driving an unbounded allocation.
 */
#define	ICE_DDP_PKG_MAX		(16 * 1024 * 1024)

static void
ice_ddp_safe_mode(ice_t *ice)
{
	ice_set_safe_mode_caps(&ice->ice_hw);
	ice->ice_safe_mode = B_TRUE;
}

boolean_t
ice_ddp_load(ice_t *ice)
{
	struct ice_hw *hw = &ice->ice_hw;
	firmware_handle_t fwh;
	off_t size;
	uint8_t *buf;
	enum ice_ddp_state state;

	if (firmware_open(ICE_MODULE_NAME, ICE_DDP_PKG_FILE, &fwh) != 0) {
		ice_ddp_safe_mode(ice);
		return (B_TRUE);
	}

	size = firmware_get_size(fwh);
	if (size <= 0 || size > ICE_DDP_PKG_MAX) {
		ice_error(ice, "!ignoring ice.pkg with bad size %lld",
		    (long long)size);
		(void) firmware_close(fwh);
		ice_ddp_safe_mode(ice);
		return (B_TRUE);
	}

	buf = kmem_alloc((size_t)size, KM_SLEEP);
	if (firmware_read(fwh, 0, buf, (size_t)size) != 0) {
		ice_error(ice, "!failed to read ice.pkg");
		kmem_free(buf, (size_t)size);
		(void) firmware_close(fwh);
		ice_ddp_safe_mode(ice);
		return (B_TRUE);
	}
	(void) firmware_close(fwh);

	/* ice_copy_and_init_pkg() copies into its own DMA; free ours after. */
	state = ice_copy_and_init_pkg(hw, buf, (u32)size);
	kmem_free(buf, (size_t)size);

	ice->ice_ddp_state = state;
	if (!ice_is_init_pkg_successful(state)) {
		ice_error(ice, "!ice.pkg init failed (%d); using safe mode",
		    state);
		ice_ddp_safe_mode(ice);
	} else {
		char name[ICE_PKG_NAME_SIZE + 1];

		/*
		 * The package name is firmware input and need not be
		 * terminated.
		 */
		bcopy(hw->active_pkg_name, name, ICE_PKG_NAME_SIZE);
		name[ICE_PKG_NAME_SIZE] = '\0';
		dev_err(ice->ice_dip, CE_NOTE,
		    "!DDP package active: %s version %u.%u.%u.%u", name,
		    hw->active_pkg_ver.major, hw->active_pkg_ver.minor,
		    hw->active_pkg_ver.update, hw->active_pkg_ver.draft);
	}

	return (B_TRUE);
}
