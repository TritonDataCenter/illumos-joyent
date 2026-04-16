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
/*
 * VDC_REGISTER and VDC_FPU aren't reachable via VM_DATA_READ on the
 * illumos VMM kernel today — vmm_data_from_class's per-vCPU path
 * panics for VDC_REGISTER and returns ENOTSUP for VDC_FPU.  Instead,
 * general registers round-trip via vm_get/set_register_set with a
 * fixed list (proven in v1's bhyve_migrate.c), and FPU rides VM_GET/
 * SET_FPU directly.  Segment descriptors go through vm_get/set_desc
 * (base/limit/access) and — for non-GDTR/IDTR segs — vm_get/set_register
 * for the VMCS selector field (CS=0 post-import causes VMX entry
 * failure inst_error=7, hence both halves).
 *
 * VDC_MSR and VDC_VMM_ARCH do work via VM_DATA_READ/WRITE and are
 * included at the end of each vCPU's VMCX blob.
 */
static const int vmcx_gpr_regs[] = {
	VM_REG_GUEST_RAX, VM_REG_GUEST_RBX, VM_REG_GUEST_RCX,
	VM_REG_GUEST_RDX, VM_REG_GUEST_RSI, VM_REG_GUEST_RDI,
	VM_REG_GUEST_RBP, VM_REG_GUEST_RSP, VM_REG_GUEST_R8,
	VM_REG_GUEST_R9,  VM_REG_GUEST_R10, VM_REG_GUEST_R11,
	VM_REG_GUEST_R12, VM_REG_GUEST_R13, VM_REG_GUEST_R14,
	VM_REG_GUEST_R15, VM_REG_GUEST_RIP, VM_REG_GUEST_RFLAGS,
	VM_REG_GUEST_CR0, VM_REG_GUEST_CR3, VM_REG_GUEST_CR2,
	VM_REG_GUEST_CR4, VM_REG_GUEST_DR7, VM_REG_GUEST_EFER,
	VM_REG_GUEST_XCR0,
};
#define	N_VMCX_GPR_REGS	\
	(sizeof (vmcx_gpr_regs) / sizeof (vmcx_gpr_regs[0]))

static const int vmcx_seg_descs[] = {
	VM_REG_GUEST_CS,   VM_REG_GUEST_DS,   VM_REG_GUEST_ES,
	VM_REG_GUEST_FS,   VM_REG_GUEST_GS,   VM_REG_GUEST_SS,
	VM_REG_GUEST_TR,   VM_REG_GUEST_LDTR,
	VM_REG_GUEST_GDTR, VM_REG_GUEST_IDTR,
};
#define	N_VMCX_SEG_DESCS \
	(sizeof (vmcx_seg_descs) / sizeof (vmcx_seg_descs[0]))

/*
 * Per-segment wire entry — 28 bytes packed.
 * GDTR/IDTR don't have selector fields so sel is transmitted as 0.
 */
#pragma pack(push, 1)
struct vmcx_seg_entry {
	uint32_t	regid;
	uint64_t	base;
	uint32_t	limit;
	uint32_t	access;
	uint64_t	sel;
};
#pragma pack(pop)
#define	VMCX_SEG_ENTRY_SIZE	28U

#define	VMCX_FPU_BUF_SIZE	8192U

static int
vmcx_get_fpu(struct vmctx *ctx, int vcpuid, void *buf, size_t len)
{
	struct vm_fpu_state fpu = {
		.vcpuid = vcpuid,
		.buf = buf,
		.len = len,
	};
	return (ioctl(vm_get_device_fd(ctx), VM_GET_FPU, &fpu));
}

static int
vmcx_set_fpu(struct vmctx *ctx, int vcpuid, void *buf, size_t len)
{
	struct vm_fpu_state fpu = {
		.vcpuid = vcpuid,
		.buf = buf,
		.len = len,
	};
	return (ioctl(vm_get_device_fd(ctx), VM_SET_FPU, &fpu));
}

/*
 * Save or restore one vCPU's VMCX blob.  Layout (in order):
 *   [25 × uint64_t GPRs]        200 bytes
 *   [10 × struct vmcx_seg_entry]  280 bytes
 *   [VMCX_FPU_BUF_SIZE FPU buf]  8192 bytes
 *   [len-prefixed MSR blob]      via VDC_MSR
 *   [len-prefixed VMM_ARCH blob] via VDC_VMM_ARCH
 *
 * On RESTORE the ordering matches the v1 bhyve_migrate.c file-based
 * import which is known working: registers → segments → FPU → MSR →
 * VMM_ARCH.  The control-socket path previously tried a different
 * order (MSRs first) and produced VMX entry failure inst_error=7;
 * file-based order is the only configuration that resumes cleanly.
 */
/*
 * SAVE path for a single vCPU's VMCX bundle.  The wire format is:
 * GPRs | seg descs | FPU | MSRs | VMM_ARCH | {run_state, sipi_vector}.
 * restore_vmcx_vcpu() reads in the exact same order — keep these two
 * helpers aligned when extending.
 */
static int
save_vmcx_vcpu(struct vmctx *ctx, struct vcpu *vcpu, int vcpuid,
    struct vm_snapshot_meta *meta)
{
	int ret = 0;
	uint_t i;
	uint64_t gprs[N_VMCX_GPR_REGS];
	uint8_t fpubuf[VMCX_FPU_BUF_SIZE];
	enum vcpu_run_state rstate;
	uint8_t sipi_vector;

	/* 1. GPRs. */
	if (vm_get_register_set(vcpu, N_VMCX_GPR_REGS,
	    vmcx_gpr_regs, gprs) != 0)
		return (errno);
	SNAPSHOT_BUF_OR_LEAVE(gprs, sizeof (gprs), meta, ret, done);

	/* 2. Segment descriptors + selectors. */
	for (i = 0; i < N_VMCX_SEG_DESCS; i++) {
		struct vmcx_seg_entry ent;
		int reg = vmcx_seg_descs[i];
		bool is_gx = (reg == VM_REG_GUEST_GDTR ||
		    reg == VM_REG_GUEST_IDTR);

		ent.regid = (uint32_t)reg;
		if (vm_get_desc(vcpu, reg, &ent.base, &ent.limit,
		    &ent.access) != 0)
			return (errno);
		ent.sel = 0;
		if (!is_gx)
			(void) vm_get_register(vcpu, reg, &ent.sel);
		SNAPSHOT_BUF_OR_LEAVE(&ent, VMCX_SEG_ENTRY_SIZE,
		    meta, ret, done);
	}

	/* 3. FPU. */
	(void) memset(fpubuf, 0, sizeof (fpubuf));
	if (vmcx_get_fpu(ctx, vcpuid, fpubuf, sizeof (fpubuf)) != 0)
		return (errno);
	SNAPSHOT_BUF_OR_LEAVE(fpubuf, sizeof (fpubuf), meta, ret, done);

	/* 4. MSRs + 5. VMM_ARCH. */
	if ((ret = snapshot_vmm_class(ctx, vcpuid, VDC_MSR, 1, meta)) != 0)
		return (ret);
	if ((ret = snapshot_vmm_class(ctx, vcpuid, VDC_VMM_ARCH, 1, meta)) != 0)
		return (ret);

	/*
	 * 6. vCPU run state (VRS_RUN / VRS_HALT / VRS_INIT / VRS_SIPI_*).
	 * Without this, dest vCPUs would start in post-init defaults and
	 * lose the source's running-state — v1 file-based migrations saw
	 * vm_run wedge (BSP with valid regs but "not yet runnable").
	 */
	if (vm_get_run_state(vcpu, &rstate, &sipi_vector) != 0) {
		rstate = VRS_HALT;
		sipi_vector = 0;
	}
	SNAPSHOT_VAR_OR_LEAVE(rstate, meta, ret, done);
	SNAPSHOT_VAR_OR_LEAVE(sipi_vector, meta, ret, done);

done:
	return (ret);
}

/*
 * RESTORE path.  Reads the same wire sections save_vmcx_vcpu wrote
 * and applies each to the kernel VMM.  Some sub-steps log on failure
 * and continue because the kernel tolerates partial state (e.g. some
 * segment registers may be uninitialised on certain guests).
 */
static int
restore_vmcx_vcpu(struct vmctx *ctx, struct vcpu *vcpu, int vcpuid,
    struct vm_snapshot_meta *meta)
{
	int ret = 0;
	uint_t i;
	uint64_t gprs[N_VMCX_GPR_REGS];
	uint8_t fpubuf[VMCX_FPU_BUF_SIZE];
	enum vcpu_run_state rstate;
	uint8_t sipi_vector;

	/* 1. GPRs. */
	SNAPSHOT_BUF_OR_LEAVE(gprs, sizeof (gprs), meta, ret, done);
	if (vm_set_register_set(vcpu, N_VMCX_GPR_REGS,
	    vmcx_gpr_regs, gprs) != 0)
		return (errno);

	/* 2. Segment descriptors + selectors. */
	for (i = 0; i < N_VMCX_SEG_DESCS; i++) {
		struct vmcx_seg_entry ent;
		int reg = vmcx_seg_descs[i];
		bool is_gx = (reg == VM_REG_GUEST_GDTR ||
		    reg == VM_REG_GUEST_IDTR);

		SNAPSHOT_BUF_OR_LEAVE(&ent, VMCX_SEG_ENTRY_SIZE,
		    meta, ret, done);
		if (vm_set_desc(vcpu, (int)ent.regid, ent.base, ent.limit,
		    ent.access) != 0) {
			/* Non-fatal; some segs can be uninitialised. */
			(void) fprintf(stderr,
			    "vmcx: vcpu%d reg%u set_desc: %s\n",
			    vcpuid, ent.regid, strerror(errno));
		}
		if (!is_gx) {
			if (vm_set_register(vcpu, (int)ent.regid,
			    ent.sel) != 0) {
				(void) fprintf(stderr,
				    "vmcx: vcpu%d reg%u set_sel: %s\n",
				    vcpuid, ent.regid, strerror(errno));
			}
		}
	}

	/* 3. FPU. */
	SNAPSHOT_BUF_OR_LEAVE(fpubuf, sizeof (fpubuf), meta, ret, done);
	if (vmcx_set_fpu(ctx, vcpuid, fpubuf, sizeof (fpubuf)) != 0) {
		/* Not fatal for resume; log and continue. */
		(void) fprintf(stderr, "vmcx: vcpu%d set_fpu: %s\n",
		    vcpuid, strerror(errno));
	}

	/* 4. MSRs + 5. VMM_ARCH. */
	if ((ret = snapshot_vmm_class(ctx, vcpuid, VDC_MSR, 1, meta)) != 0)
		return (ret);
	if ((ret = snapshot_vmm_class(ctx, vcpuid, VDC_VMM_ARCH, 1, meta)) != 0)
		return (ret);

	/* 6. vCPU run state. */
	SNAPSHOT_VAR_OR_LEAVE(rstate, meta, ret, done);
	SNAPSHOT_VAR_OR_LEAVE(sipi_vector, meta, ret, done);
	if (vm_set_run_state(vcpu, rstate, sipi_vector) != 0) {
		(void) fprintf(stderr,
		    "vmcx: vcpu%d set_run_state(%u,%u): %s\n",
		    vcpuid, (unsigned)rstate, (unsigned)sipi_vector,
		    strerror(errno));
	}

done:
	return (ret);
}

static int
snapshot_vmcx_vcpu(struct vmctx *ctx, int vcpuid,
    struct vm_snapshot_meta *meta)
{
	struct vcpu *vcpu = vm_vcpu_open(ctx, vcpuid);
	if (vcpu == NULL)
		return (errno);

	int ret = (meta->op == VM_SNAPSHOT_SAVE)
	    ? save_vmcx_vcpu(ctx, vcpu, vcpuid, meta)
	    : restore_vmcx_vcpu(ctx, vcpu, vcpuid, meta);

	vm_vcpu_close(vcpu);
	return (ret);
}

static int
snapshot_vmcx(struct vmctx *ctx, struct vm_snapshot_meta *meta)
{
	int ret = 0;
	int i, ncpus;
	uint16_t sockets, cores, threads, maxcpus;

	if (vm_get_topology(ctx, &sockets, &cores, &threads, &maxcpus) != 0)
		return (errno);
	ncpus = (int)maxcpus;

	SNAPSHOT_VAR_OR_LEAVE(ncpus, meta, ret, done);

	for (i = 0; i < ncpus; i++) {
		ret = snapshot_vmcx_vcpu(ctx, i, meta);
		if (ret != 0)
			goto done;
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
/*
 * Cross-host VMM_TIME merge on RESTORE.
 *
 * Naively writing source's vdi_time_info_v1 to dest fails with EPERM
 * from the kernel's vmfreqratio check (FR_SCALING_NOT_SUPPORTED) when
 * the source's captured vt_guest_freq doesn't exactly match dest's
 * host TSC frequency, and bleeds into VHPET's vh_time_base check
 * (future hrtime) via an un-rebased boot_hrtime.
 *
 * v1 handled this by reading dest's live VMM_TIME, rebasing source's
 * boot_hrtime to dest's hrtime reference, taking dest's wall-clock /
 * hres fields, and (on freq mismatch) scaling guest_tsc + replacing
 * guest_freq with dest's.  Algorithm is ported verbatim from
 * bhyve_migrate.c@4f95ad6c98; see that file for the full rationale.
 */
/*
 * Consume [uint32 src_len][src_len bytes] from the snapshot stream.
 * The leading uint32 gates forward-compat: we accept src_len >=
 * sizeof(struct vdi_time_info_v1) and discard any trailing bytes past
 * the known struct so v2 blobs land on a v1 reader cleanly.
 */
static int
read_time_wire(struct vm_snapshot_meta *meta, struct vdi_time_info_v1 *src)
{
	uint32_t src_len = 0;
	int ret = 0;

	SNAPSHOT_VAR_OR_LEAVE(src_len, meta, ret, done);
	if (src_len < sizeof (*src)) {
		(void) fprintf(stderr,
		    "vmm_time: source blob too short (%u < %zu)\n",
		    src_len, sizeof (*src));
		return (EINVAL);
	}
	SNAPSHOT_BUF_OR_LEAVE(src, sizeof (*src), meta, ret, done);
	if (src_len > sizeof (*src)) {
		uint8_t discard[256];
		uint32_t rem = src_len - (uint32_t)sizeof (*src);
		while (rem > 0) {
			uint32_t chunk = rem > sizeof (discard) ?
			    (uint32_t)sizeof (discard) : rem;
			SNAPSHOT_BUF_OR_LEAVE(discard, chunk, meta, ret, done);
			rem -= chunk;
		}
	}

done:
	return (ret);
}

/*
 * Rebase the source's hrtime so the guest's uptime (hrtime -
 * boot_hrtime) stays intact under the destination host's hrtime
 * clock, accounting for the wall-clock drift accumulated during
 * the migration.  vt_hres_{sec,ns} get overwritten with the dest's
 * live wall-clock so subsequent guest time queries match the host
 * wall clock the guest is actually running on.
 *
 * Returns the wall-clock delta in nanoseconds.  The caller uses it
 * to bump TSC by an equivalent amount so guest CLOCK_MONOTONIC
 * advances consistently across the pause.
 */
static int64_t
rebase_hrtime(struct vdi_time_info_v1 *src,
    const struct vdi_time_info_v1 *dst)
{
	int64_t guest_uptime = src->vt_hrtime - src->vt_boot_hrtime;
	uint64_t src_wc_ns = src->vt_hres_sec * 1000000000ULL +
	    src->vt_hres_ns;
	uint64_t dst_wc_ns = dst->vt_hres_sec * 1000000000ULL +
	    dst->vt_hres_ns;
	int64_t migrate_delta_ns = 0;
	if (dst_wc_ns > src_wc_ns)
		migrate_delta_ns = (int64_t)(dst_wc_ns - src_wc_ns);

	src->vt_boot_hrtime = dst->vt_hrtime -
	    (guest_uptime + migrate_delta_ns);
	src->vt_hrtime = dst->vt_hrtime;
	src->vt_hres_sec = dst->vt_hres_sec;
	src->vt_hres_ns = dst->vt_hres_ns;

	return (migrate_delta_ns);
}

/*
 * Rescale the source's guest TSC for any freq mismatch between src
 * and dst hosts, then also bump by the wall-clock delta so guest
 * CLOCK_MONOTONIC (which typically derives from TSC) reflects the
 * real time elapsed during migration.
 *
 * new_tsc = old_tsc * dst_freq / src_freq, computed via quotient +
 * remainder to avoid the 128-bit divide the VMM kernel path would
 * otherwise require.
 */
static void
rescale_tsc(struct vdi_time_info_v1 *src,
    const struct vdi_time_info_v1 *dst, int64_t migrate_delta_ns)
{
	if (src->vt_guest_freq != dst->vt_guest_freq) {
		if (src->vt_guest_freq != 0) {
			uint64_t q = src->vt_guest_tsc / src->vt_guest_freq;
			uint64_t r = src->vt_guest_tsc % src->vt_guest_freq;
			src->vt_guest_tsc = q * dst->vt_guest_freq +
			    r * dst->vt_guest_freq / src->vt_guest_freq;
		}
		src->vt_guest_freq = dst->vt_guest_freq;
	}

	if (migrate_delta_ns > 0 && src->vt_guest_freq > 0) {
		uint64_t ns = (uint64_t)migrate_delta_ns;
		uint64_t q = ns / 1000000000ULL;
		uint64_t r = ns % 1000000000ULL;
		uint64_t tsc_delta = q * src->vt_guest_freq +
		    r * src->vt_guest_freq / 1000000000ULL;
		src->vt_guest_tsc += tsc_delta;
	}
}

static int
snapshot_vmm_time_merge(struct vmctx *ctx, struct vm_snapshot_meta *meta)
{
	struct vdi_time_info_v1 src = { 0 };
	struct vdi_time_info_v1 dst = { 0 };
	uint32_t dst_result_len = 0;
	int ret;

	ret = read_time_wire(meta, &src);
	if (ret != 0)
		return (ret);

	if (vm_data_read(ctx, -1, VDC_VMM_TIME, 1, VDX_FLAG_WRITE_COPYOUT,
	    &dst, sizeof (dst), &dst_result_len) != 0) {
		return (errno);
	}

	int64_t migrate_delta_ns = rebase_hrtime(&src, &dst);
	rescale_tsc(&src, &dst, migrate_delta_ns);

	if (vm_data_write(ctx, -1, VDC_VMM_TIME, 1, &src,
	    sizeof (src)) != 0) {
		return (errno);
	}
	return (0);
}

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
		/* VDC_RTC is version 2 in the illumos VMM — v1 uses it too. */
		return (snapshot_vmm_class(ctx, -1, VDC_RTC, 2, meta));
	case STRUCT_VM:
		/*
		 * RESTORE takes the merge path (read dest live time, rebase
		 * boot_hrtime, apply freq scaling) to avoid the cross-host
		 * EPERM from vmfreqratio + the future-base_time rejection
		 * in VHPET that cascades from an un-rebased boot_hrtime.
		 */
		if (meta->op == VM_SNAPSHOT_RESTORE) {
			return (snapshot_vmm_time_merge(ctx, meta));
		}
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
