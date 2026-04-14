/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2016 Flavius Anton
 * Copyright (c) 2016 Mihai Tiganus
 * Copyright (c) 2016-2019 Mihai Carabas
 * Copyright (c) 2017-2019 Darius Mihai
 * Copyright (c) 2017-2019 Elena Mihailescu
 * Copyright (c) 2018-2019 Sergiu Weisz
 * All rights reserved.
 * The bhyve-snapshot feature was developed under sponsorships
 * from Matthew Grooms.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY NETAPP, INC ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL NETAPP, INC OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 *
 * Copyright 2026 Edgecast Cloud LLC.
 */

/*
 * Userspace snapshot buffer primitives for bhyve's BHYVE_SNAPSHOT
 * framework.  In FreeBSD these helpers live in sys/amd64/vmm/vmm_snapshot.c
 * and run in kernel context using copyin/copyout.  In this illumos port the
 * kernel half is unused — device save/restore runs entirely in userspace,
 * so the copy primitives collapse to memcpy.
 *
 * See sys/vmm_snapshot.h for the public contract (struct vm_snapshot_meta,
 * SNAPSHOT_VAR_OR_LEAVE, etc.)
 */

#include <sys/types.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>

#include <machine/vmm.h>
#include <sys/vmm_data.h>
#include <sys/vmm_dev.h>
#include <sys/vmm_snapshot.h>

#include <vmmapi.h>

void
vm_snapshot_buf_err(const char *bufname, const enum vm_snapshot_op op)
{
	const char *opstr;

	if (op == VM_SNAPSHOT_SAVE)
		opstr = "save";
	else if (op == VM_SNAPSHOT_RESTORE)
		opstr = "restore";
	else
		opstr = "unknown";

	(void) fprintf(stderr, "%s: snapshot-%s failed for %s\n", __func__,
	    opstr, bufname);
}

int
vm_snapshot_buf(void *data, size_t data_size, struct vm_snapshot_meta *meta)
{
	struct vm_snapshot_buffer *buffer;

	buffer = &meta->buffer;

	if (buffer->buf_rem < data_size) {
		(void) fprintf(stderr, "%s: buffer too small\n", __func__);
		return (E2BIG);
	}

	if (meta->op == VM_SNAPSHOT_SAVE)
		(void) memcpy(buffer->buf, data, data_size);
	else if (meta->op == VM_SNAPSHOT_RESTORE)
		(void) memcpy(data, buffer->buf, data_size);
	else
		return (EINVAL);

	buffer->buf += data_size;
	buffer->buf_rem -= data_size;

	return (0);
}

size_t
vm_get_snapshot_size(struct vm_snapshot_meta *meta)
{
	size_t length;
	struct vm_snapshot_buffer *buffer;

	buffer = &meta->buffer;

	if (buffer->buf_size < buffer->buf_rem) {
		(void) fprintf(stderr,
		    "%s: Invalid buffer: size = %zu, rem = %zu\n",
		    __func__, buffer->buf_size, buffer->buf_rem);
		length = 0;
	} else {
		length = buffer->buf_size - buffer->buf_rem;
	}

	return (length);
}

int
vm_snapshot_buf_cmp(void *data, size_t data_size, struct vm_snapshot_meta *meta)
{
	struct vm_snapshot_buffer *buffer;
	int ret;

	buffer = &meta->buffer;

	if (buffer->buf_rem < data_size) {
		(void) fprintf(stderr, "%s: buffer too small\n", __func__);
		return (E2BIG);
	}

	if (meta->op == VM_SNAPSHOT_SAVE) {
		ret = 0;
		(void) memcpy(buffer->buf, data, data_size);
	} else if (meta->op == VM_SNAPSHOT_RESTORE) {
		ret = memcmp(data, buffer->buf, data_size);
	} else {
		return (EINVAL);
	}

	buffer->buf += data_size;
	buffer->buf_rem -= data_size;

	return (ret);
}

/*
 * Low-level wrappers around the VM_DATA_READ / VM_DATA_WRITE ioctls.
 *
 * These are illumos-specific and have no FreeBSD analogue — FreeBSD's
 * snapshot path uses a single VM_SNAPSHOT_REQ ioctl that takes a
 * vm_snapshot_meta directly.  illumos's vmm kernel exposes per-class
 * data via VDC_* identifiers under VM_DATA_READ / VM_DATA_WRITE; the
 * vm_snapshot_req() bridge below adapts FreeBSD's snapshot_req contract
 * onto these.
 */
int
vm_data_read(struct vmctx *ctx, int vcpuid, uint16_t class,
    uint16_t version, uint32_t flags, void *data, uint32_t len,
    uint32_t *result_len)
{
	struct vm_data_xfer xfer;
	int ret;

	(void) memset(&xfer, 0, sizeof (xfer));
	xfer.vdx_vcpuid = vcpuid;
	xfer.vdx_class = class;
	xfer.vdx_version = version;
	xfer.vdx_flags = flags;
	xfer.vdx_len = len;
	xfer.vdx_data = data;

	ret = ioctl(vm_get_device_fd(ctx), VM_DATA_READ, &xfer);
	if (ret == 0 && result_len != NULL)
		*result_len = xfer.vdx_result_len;

	return (ret);
}

int
vm_data_write(struct vmctx *ctx, int vcpuid, uint16_t class,
    uint16_t version, void *data, uint32_t len)
{
	struct vm_data_xfer xfer;

	(void) memset(&xfer, 0, sizeof (xfer));
	xfer.vdx_vcpuid = vcpuid;
	xfer.vdx_class = class;
	xfer.vdx_version = version;
	xfer.vdx_flags = 0;
	xfer.vdx_len = len;
	xfer.vdx_data = data;

	return (ioctl(vm_get_device_fd(ctx), VM_DATA_WRITE, &xfer));
}

/*
 * Save or restore one (class, vcpuid) pair through the snapshot meta
 * buffer.  Wire format is [uint32_t length][length bytes of data] so a
 * variable-length per-class blob can be reconstructed at restore time
 * without out-of-band metadata.
 */
static int
snapshot_vmm_class(struct vmctx *ctx, int vcpuid, uint16_t class,
    uint16_t version, struct vm_snapshot_meta *meta)
{
	uint8_t scratch[VM_DATA_XFER_LIMIT];
	uint32_t len = 0;
	int ret = 0;

	if (meta->op == VM_SNAPSHOT_SAVE) {
		if (vm_data_read(ctx, vcpuid, class, version,
		    VDX_FLAG_WRITE_COPYOUT, scratch, sizeof (scratch),
		    &len) != 0) {
			return (errno);
		}
		SNAPSHOT_VAR_OR_LEAVE(len, meta, ret, done);
		SNAPSHOT_BUF_OR_LEAVE(scratch, len, meta, ret, done);
	} else {
		SNAPSHOT_VAR_OR_LEAVE(len, meta, ret, done);
		if (len > sizeof (scratch))
			return (EOVERFLOW);
		SNAPSHOT_BUF_OR_LEAVE(scratch, len, meta, ret, done);
		if (vm_data_write(ctx, vcpuid, class, version, scratch,
		    len) != 0) {
			return (errno);
		}
	}

done:
	return (ret);
}

/*
 * Iterate a per-vCPU class across every active vCPU.  ncpus is encoded
 * into the buffer so the restore side can validate.
 */
static int
snapshot_class_per_vcpu(struct vmctx *ctx, uint16_t class,
    uint16_t version, struct vm_snapshot_meta *meta)
{
	int ret = 0;
	int i, ncpus;
	uint16_t sockets, cores, threads, maxcpus;

	if (vm_get_topology(ctx, &sockets, &cores, &threads, &maxcpus) != 0)
		return (errno);
	ncpus = (int)maxcpus;

	SNAPSHOT_VAR_OR_LEAVE(ncpus, meta, ret, done);

	for (i = 0; i < ncpus; i++) {
		ret = snapshot_vmm_class(ctx, i, class, version, meta);
		if (ret != 0)
			goto done;
	}

done:
	return (ret);
}

/*
 * STRUCT_VMCX in FreeBSD packs the per-vCPU execution context (general
 * registers, MSRs, FPU, VMM-arch state) into one snapshot_req.  illumos
 * splits these across four VDC_* classes; we save them in a stable
 * order so the restore side can replay them.
 */
static int
snapshot_vmcx(struct vmctx *ctx, struct vm_snapshot_meta *meta)
{
	int ret = 0;
	int i, ncpus;
	uint16_t sockets, cores, threads, maxcpus;
	static const uint16_t vmcx_classes[] = {
		VDC_REGISTER, VDC_MSR, VDC_FPU, VDC_VMM_ARCH,
	};

	if (vm_get_topology(ctx, &sockets, &cores, &threads, &maxcpus) != 0)
		return (errno);
	ncpus = (int)maxcpus;

	SNAPSHOT_VAR_OR_LEAVE(ncpus, meta, ret, done);

	for (i = 0; i < ncpus; i++) {
		uint_t k;
		for (k = 0;
		    k < sizeof (vmcx_classes) / sizeof (vmcx_classes[0]);
		    k++) {
			ret = snapshot_vmm_class(ctx, i, vmcx_classes[k], 1,
			    meta);
			if (ret != 0)
				goto done;
		}
	}

done:
	return (ret);
}

/*
 * vm_snapshot_req bridges FreeBSD's snapshot_req contract onto illumos's
 * VM_DATA_READ / VM_DATA_WRITE ioctls plus the VDC_* classes.  Callers
 * (the snapshot orchestrator) treat this exactly like the FreeBSD
 * function; the per-class fan-out and per-vCPU iteration is hidden here.
 */
int
vm_snapshot_req(struct vmctx *ctx, struct vm_snapshot_meta *meta)
{
	switch (meta->dev_req) {
	case STRUCT_VIOAPIC:
		return (snapshot_vmm_class(ctx, -1, VDC_IOAPIC, 1, meta));
	case STRUCT_VATPIC:
		return (snapshot_vmm_class(ctx, -1, VDC_ATPIC, 1, meta));
	case STRUCT_VATPIT:
		return (snapshot_vmm_class(ctx, -1, VDC_ATPIT, 1, meta));
	case STRUCT_VHPET:
		return (snapshot_vmm_class(ctx, -1, VDC_HPET, 1, meta));
	case STRUCT_VPMTMR:
		return (snapshot_vmm_class(ctx, -1, VDC_PM_TIMER, 1, meta));
	case STRUCT_VRTC:
		return (snapshot_vmm_class(ctx, -1, VDC_RTC, 1, meta));
	case STRUCT_VM:
		return (snapshot_vmm_class(ctx, -1, VDC_VMM_TIME, 1, meta));
	case STRUCT_VLAPIC:
		return (snapshot_class_per_vcpu(ctx, VDC_LAPIC, 1, meta));
	case STRUCT_VMCX:
		return (snapshot_vmcx(ctx, meta));
	case VM_MEM:
		/* Memory is snapshotted via the GZ agent's mmap path */
		return (EINVAL);
	default:
		return (EINVAL);
	}
}

/*
 * Pause / resume the entire VM (all vCPUs + kernel timer / device state).
 * These map to the kernel-side VM_PAUSE / VM_RESUME ioctls and are the
 * coarsest-grained quiesce primitive we have.  bhyve_control.c uses
 * them around export-state / import-state so the snapshot is taken
 * (or applied) against a consistent kernel state.
 */
int
vm_pause_instance(struct vmctx *ctx)
{
	return (ioctl(vm_get_device_fd(ctx), VM_PAUSE, 0));
}

int
vm_resume_instance(struct vmctx *ctx)
{
	return (ioctl(vm_get_device_fd(ctx), VM_RESUME, 0));
}

int
vm_restore_time(struct vmctx *ctx)
{
	/*
	 * FreeBSD has a dedicated VM_RESTORE_TIME ioctl that re-anchors
	 * the VM clock to host wall-clock after restore.  illumos folds
	 * the equivalent into VDC_VMM_TIME write — so the time class
	 * snapshot itself acts as the trigger.  This is a no-op shim
	 * provided so callers that match FreeBSD's API contract compile.
	 */
	(void) ctx;
	return (0);
}
