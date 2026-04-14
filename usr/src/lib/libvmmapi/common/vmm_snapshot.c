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

#include <sys/vmm_snapshot.h>

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
