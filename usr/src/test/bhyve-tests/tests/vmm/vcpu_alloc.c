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
 * Check that vCPUs are allocated by the kernel only as they are first used.
 * We use the existence of kstats as a proxy for detecting allocation.
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <libgen.h>
#include <sys/stat.h>
#include <sys/mkdev.h>
#include <errno.h>
#include <err.h>
#include <kstat.h>
#include <stdbool.h>

#include <sys/vmm.h>
#include <sys/vmm_dev.h>
#include <vmmapi.h>

#include "common.h"

static bool
vcpu_kstat_exists(kstat_ctl_t *kc, int instance, int vcpuid)
{
	char name[32];

	if (kstat_chain_update(kc) == -1)
		err(EXIT_FAILURE, "kstat_chain_update");
	(void) snprintf(name, sizeof (name), "vcpu%d", vcpuid);
	return (kstat_lookup(kc, "vmm", instance, name) != NULL);
}

static void
expect_kstat(kstat_ctl_t *kc, int instance, int vcpuid, bool present)
{
	if (vcpu_kstat_exists(kc, instance, vcpuid) != present) {
		errx(EXIT_FAILURE, "vcpu%d kstat unexpectedly %s", vcpuid,
		    present ? "absent" : "present");
	}
}

static void
touch_vcpu(struct vmctx *ctx, int vcpuid)
{
	struct vcpu *vcpu;
	uint64_t val;

	if ((vcpu = vm_vcpu_open(ctx, vcpuid)) == NULL)
		err(EXIT_FAILURE, "could not open vcpu %d", vcpuid);
	if (vm_get_register(vcpu, VM_REG_GUEST_RAX, &val) != 0)
		err(EXIT_FAILURE, "could not read %%rax on vcpu %d", vcpuid);
	vm_vcpu_close(vcpu);
}

int
main(int argc, char *argv[])
{
	const char *suite_name = basename(argv[0]);
	struct vmctx *ctx;
	kstat_ctl_t *kc;
	struct stat st;
	int instance;

	ctx = create_test_vm(suite_name);
	if (ctx == NULL)
		errx(EXIT_FAILURE, "could not open test VM");

	/* The kstat instance number is the instance minor */
	if (fstat(vm_get_device_fd(ctx), &st) != 0)
		err(EXIT_FAILURE, "could not fstat VM device");
	instance = minor(st.st_rdev);

	if ((kc = kstat_open()) == NULL)
		err(EXIT_FAILURE, "kstat_open");

	/* Nothing has used a vCPU yet, so none should exist */
	expect_kstat(kc, instance, 0, false);
	expect_kstat(kc, instance, 1, false);

	/* Using one vCPU should bring only that vCPU into existence */
	touch_vcpu(ctx, 1);
	expect_kstat(kc, instance, 0, false);
	expect_kstat(kc, instance, 1, true);

	touch_vcpu(ctx, 0);
	expect_kstat(kc, instance, 0, true);
	expect_kstat(kc, instance, 1, true);

	/* The vCPU should remain after the VM is reinitialised */
	if (vm_reinit(ctx, 0) != 0)
		err(EXIT_FAILURE, "could not reinit VM");
	expect_kstat(kc, instance, 0, true);
	expect_kstat(kc, instance, 1, true);

	(void) kstat_close(kc);
	vm_destroy(ctx);
	(void) printf("%s\tPASS\n", suite_name);
	return (EXIT_SUCCESS);
}
