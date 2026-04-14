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
 * bhyve control socket — Unix-socket control plane for cross-host
 * live migration.
 *
 * Architecture
 * ============
 *
 * The GZ-side migration agent (services/vmm-migrate-agent) talks to
 * this socket to drive the userspace-state half of a migration.  The
 * agent handles RAM transfer + disk (zfs send/recv) directly via
 * /dev/vmm and ZFS; bhyve only owns the device + kernel state
 * serialisation.  This split keeps the agent compact and lets bhyve
 * stay single-host-shaped.
 *
 * Wire protocol
 * =============
 *
 * Newline-delimited JSON requests, newline-delimited JSON responses.
 * Binary payloads (snapshot blob streams) are framed by a length
 * field in the JSON line and follow the line on the same connection.
 *
 * Commands:
 *   {"command":"status"}
 *     -> {"status":"ok","name":"...","ncpus":N,"memsize":N,"state":"running|paused"}
 *
 *   {"command":"pause"}
 *     -> {"status":"ok"}
 *     Pauses every PCI device (pe_pause callbacks; for blockif this
 *     drains the in-flight queue) then VM_PAUSE.
 *
 *   {"command":"resume"}
 *     -> {"status":"ok"}
 *     VM_RESUME, then per-device pe_resume.
 *
 *   {"command":"export-state"}
 *     -> {"status":"ok","blob_len":N}
 *     Server then writes N bytes of binary blob stream (see "Snapshot
 *     blob format" below).  Caller must have already issued "pause"
 *     so the state is consistent.
 *
 *   {"command":"import-state","blob_len":N}
 *     Caller then writes N bytes of binary blob stream.
 *     -> {"status":"ok"}  on success
 *     -> {"status":"error","msg":"..."} on failure
 *
 *     Restricted: only valid in migrate-listen mode AND only once per
 *     bhyve lifetime (C-1 hardening).  After a successful import,
 *     subsequent import-state requests are rejected.  The destination
 *     bhyve's main thread blocks in bhyve_control_wait_import() until
 *     a successful import; vCPU threads are then started against the
 *     imported state.
 *
 * Snapshot blob format
 * ====================
 *
 * Self-describing TLV stream — no separate manifest.  All multi-byte
 * fields are little-endian (host-endian on amd64).
 *
 *   struct ctl_blob_hdr {
 *       uint32_t magic;          // CTL_BLOB_MAGIC
 *       uint32_t version;        // CTL_BLOB_VERSION
 *       uint32_t num_sections;
 *       uint32_t reserved;
 *   };
 *
 * Followed by num_sections instances of:
 *
 *   struct ctl_section_hdr {
 *       uint8_t  kind;           // CTL_SEC_KERN | CTL_SEC_DEV
 *       uint8_t  kern_req;       // enum snapshot_req if kind == KERN
 *       uint16_t name_len;       // 0..255
 *       uint32_t blob_len;
 *   };
 *   uint8_t name[name_len];
 *   uint8_t blob[blob_len];
 *
 * For SEC_KERN, the blob is the bytes produced by vm_snapshot_req(meta).
 * For SEC_DEV, the blob is the bytes produced by pci_snapshot(meta) for
 * the named device (name format "<bus>:<slot>:<func>").
 *
 * Order matters: VMM time first (so the LAPIC timer rebases against
 * the right hrtime base on restore), then per-vCPU kernel state, then
 * system devices, then PCI devices in pci_next() order.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <assert.h>
#include <fcntl.h>

#include <machine/vmm.h>
#include <sys/vmm_snapshot.h>
#include <vmmapi.h>

#include "config.h"
#include "bhyve_control.h"
#include "pci_emul.h"

/* ---------------------------------------------------------------- */
/* TLV wire format constants					    */
/* ---------------------------------------------------------------- */

#define	CTL_BLOB_MAGIC		0x4D494752U	/* 'MIGR' */
#define	CTL_BLOB_VERSION	1U

#define	CTL_SEC_KERN		1
#define	CTL_SEC_DEV		2

#pragma pack(push, 1)
struct ctl_blob_hdr {
	uint32_t	magic;
	uint32_t	version;
	uint32_t	num_sections;
	uint32_t	reserved;
};

struct ctl_section_hdr {
	uint8_t		kind;
	uint8_t		kern_req;
	uint16_t	name_len;
	uint32_t	blob_len;
};
#pragma pack(pop)

/*
 * Single-section snapshot scratch is bounded by VM_DATA_XFER_LIMIT (8 KB)
 * for any one vm_data_read() round trip, but vm_snapshot_req() can stack
 * many of those (per-vCPU classes).  4 MiB per section is plenty for
 * realistic VMs (256-vCPU LAPIC bundle is ~256 KiB).
 */
#define	CTL_SECTION_BUF_MAX	(4U * 1024U * 1024U)

/* Cap the total stream size to bound memory on RESTORE. */
#define	CTL_BLOB_MAX		(64U * 1024U * 1024U)

/* ---------------------------------------------------------------- */
/* Snapshot section catalog					    */
/* ---------------------------------------------------------------- */

/*
 * Order matters here — VMM time must restore first so subsequent
 * device timer reloads anchor against the right hrtime base.  After
 * VMM time, system-wide kernel devices, then per-vCPU kernel state.
 * PCI devices are appended dynamically via pci_next().
 */
struct ctl_kern_section {
	const char		*name;
	enum snapshot_req	req;
};

static const struct ctl_kern_section ctl_kern_sections[] = {
	{ "vmm_time",	STRUCT_VM	},
	{ "vioapic",	STRUCT_VIOAPIC	},
	{ "vatpic",	STRUCT_VATPIC	},
	{ "vatpit",	STRUCT_VATPIT	},
	{ "vhpet",	STRUCT_VHPET	},
	{ "vpmtmr",	STRUCT_VPMTMR	},
	{ "vrtc",	STRUCT_VRTC	},
	{ "vlapic",	STRUCT_VLAPIC	},
	{ "vmcx",	STRUCT_VMCX	},
};
#define	CTL_N_KERN_SECTIONS \
	(sizeof (ctl_kern_sections) / sizeof (ctl_kern_sections[0]))

/* ---------------------------------------------------------------- */
/* Module-private state						    */
/* ---------------------------------------------------------------- */

static struct vmctx	*ctl_ctx;
static int		ctl_ncpus;
static int		ctl_listenfd = -1;
static char		*ctl_path;
static pthread_t	ctl_listen_tid;
static volatile int	ctl_stop;

/* C-1: import-state may run at most once, and only in migrate-listen */
static pthread_mutex_t	ctl_import_mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t	ctl_import_cv = PTHREAD_COND_INITIALIZER;
static bool		ctl_import_done;

/* ---------------------------------------------------------------- */
/* I/O helpers							    */
/* ---------------------------------------------------------------- */

static ssize_t
read_full(int fd, void *buf, size_t len)
{
	uint8_t *p = buf;
	size_t got = 0;

	while (got < len) {
		ssize_t n = read(fd, p + got, len - got);
		if (n == 0)
			return ((ssize_t)got);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return (-1);
		}
		got += (size_t)n;
	}
	return ((ssize_t)got);
}

static ssize_t
write_full(int fd, const void *buf, size_t len)
{
	const uint8_t *p = buf;
	size_t put = 0;

	while (put < len) {
		ssize_t n = write(fd, p + put, len - put);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return (-1);
		}
		put += (size_t)n;
	}
	return ((ssize_t)put);
}

/*
 * Read one newline-terminated line into buf; consumed bytes after the
 * newline are discarded.  Returns the line length (excluding the \n)
 * or -1 on error / EOF without a complete line.
 */
static ssize_t
read_line(int fd, char *buf, size_t cap)
{
	size_t n = 0;
	while (n < cap - 1) {
		char c;
		ssize_t r = read(fd, &c, 1);
		if (r == 0)
			break;
		if (r < 0) {
			if (errno == EINTR)
				continue;
			return (-1);
		}
		if (c == '\n') {
			buf[n] = '\0';
			return ((ssize_t)n);
		}
		buf[n++] = c;
	}
	return (-1);
}

static void
send_jsonv(int fd, const char *fmt, va_list ap)
{
	char line[256];
	int n = vsnprintf(line, sizeof (line), fmt, ap);
	if (n <= 0 || n >= (int)sizeof (line))
		return;
	if (line[n - 1] != '\n') {
		if (n + 1 >= (int)sizeof (line))
			return;
		line[n++] = '\n';
		line[n] = '\0';
	}
	(void) write_full(fd, line, (size_t)n);
}

static void
send_json(int fd, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	send_jsonv(fd, fmt, ap);
	va_end(ap);
}

static void
send_error(int fd, const char *msg)
{
	send_json(fd, "{\"status\":\"error\",\"msg\":\"%s\"}", msg);
}

static void
send_ok(int fd)
{
	send_json(fd, "{\"status\":\"ok\"}");
}

/* Find `"key":<digits>` in a JSON line.  Returns 0 on success. */
static int
json_get_uint(const char *line, const char *key, uint64_t *out)
{
	char needle[64];
	(void) snprintf(needle, sizeof (needle), "\"%s\":", key);
	const char *p = strstr(line, needle);
	if (p == NULL)
		return (-1);
	p += strlen(needle);
	while (*p == ' ' || *p == '\t')
		p++;
	char *end;
	unsigned long long v = strtoull(p, &end, 10);
	if (end == p)
		return (-1);
	*out = (uint64_t)v;
	return (0);
}

/* ---------------------------------------------------------------- */
/* Snapshot helpers						    */
/* ---------------------------------------------------------------- */

/*
 * Append one section to the SAVE stream by snapshotting through the
 * supplied callback (which fills meta->buffer).  *bufp / *capp / *usedp
 * is the growing TLV stream; we extend it in CTL_SECTION_BUF_MAX-sized
 * scratch slabs as needed.
 */
typedef int (*ctl_sec_save_fn)(struct vm_snapshot_meta *meta, void *arg);

static int
sec_save_kern(struct vm_snapshot_meta *meta, void *arg)
{
	(void) arg;
	return (vm_snapshot_req(ctl_ctx, meta));
}

static int
sec_save_dev(struct vm_snapshot_meta *meta, void *arg)
{
	(void) arg;
	return (pci_snapshot(meta));
}

static int
write_section(uint8_t **streamp, size_t *capp, size_t *usedp,
    uint8_t kind, uint8_t kern_req, const char *name,
    ctl_sec_save_fn fn, void *fn_arg, void *meta_dev_data)
{
	uint8_t *scratch = malloc(CTL_SECTION_BUF_MAX);
	if (scratch == NULL)
		return (ENOMEM);

	struct vm_snapshot_meta meta = {
		.dev_name = name,
		.dev_data = meta_dev_data,
		.buffer = {
			.buf_start = scratch,
			.buf_size = CTL_SECTION_BUF_MAX,
			.buf = scratch,
			.buf_rem = CTL_SECTION_BUF_MAX,
		},
		.op = VM_SNAPSHOT_SAVE,
	};
	if (kind == CTL_SEC_KERN)
		meta.dev_req = (enum snapshot_req)kern_req;

	int ret = fn(&meta, fn_arg);
	if (ret != 0) {
		free(scratch);
		return (ret);
	}

	size_t blob_len = vm_get_snapshot_size(&meta);
	size_t name_len = strlen(name);
	if (name_len > UINT16_MAX) {
		free(scratch);
		return (ENAMETOOLONG);
	}

	size_t need = sizeof (struct ctl_section_hdr) + name_len + blob_len;
	while (*usedp + need > *capp) {
		size_t newcap = (*capp == 0) ? (1U << 20) : (*capp * 2);
		if (newcap > CTL_BLOB_MAX) {
			free(scratch);
			return (E2BIG);
		}
		uint8_t *grow = realloc(*streamp, newcap);
		if (grow == NULL) {
			free(scratch);
			return (ENOMEM);
		}
		*streamp = grow;
		*capp = newcap;
	}

	struct ctl_section_hdr sh = {
		.kind = kind,
		.kern_req = kern_req,
		.name_len = (uint16_t)name_len,
		.blob_len = (uint32_t)blob_len,
	};
	(void) memcpy(*streamp + *usedp, &sh, sizeof (sh));
	*usedp += sizeof (sh);
	(void) memcpy(*streamp + *usedp, name, name_len);
	*usedp += name_len;
	(void) memcpy(*streamp + *usedp, scratch, blob_len);
	*usedp += blob_len;

	free(scratch);
	return (0);
}

static int
build_save_stream(uint8_t **streamp, size_t *lenp)
{
	uint8_t *stream = NULL;
	size_t cap = 0, used = 0;
	int ret;
	uint32_t num_sections = 0;

	/* Reserve space for the leading blob header. */
	cap = 1U << 20;
	stream = malloc(cap);
	if (stream == NULL)
		return (ENOMEM);
	used = sizeof (struct ctl_blob_hdr);

	/* Kernel sections, in order. */
	for (uint_t i = 0; i < CTL_N_KERN_SECTIONS; i++) {
		ret = write_section(&stream, &cap, &used,
		    CTL_SEC_KERN, (uint8_t)ctl_kern_sections[i].req,
		    ctl_kern_sections[i].name, sec_save_kern, NULL, NULL);
		if (ret != 0) {
			(void) fprintf(stderr,
			    "build_save_stream: kern section '%s' "
			    "(req=%d) failed: %s\n",
			    ctl_kern_sections[i].name,
			    (int)ctl_kern_sections[i].req, strerror(ret));
			free(stream);
			return (ret);
		}
		num_sections++;
	}

	/* PCI device sections, in pci_next() order. */
	struct pci_devinst *pdi = NULL;
	while ((pdi = pci_next(pdi)) != NULL) {
		char name[64];
		(void) snprintf(name, sizeof (name), "%u:%u:%u",
		    pdi->pi_bus, pdi->pi_slot, pdi->pi_func);

		ret = write_section(&stream, &cap, &used,
		    CTL_SEC_DEV, 0, name, sec_save_dev, NULL, pdi);
		if (ret == ENOTSUP) {
			/* Device opted out of snapshot — skip silently. */
			continue;
		}
		if (ret != 0) {
			(void) fprintf(stderr,
			    "build_save_stream: dev section '%s' "
			    "(pe_emu=%s) failed: %s\n",
			    name,
			    pdi->pi_d != NULL ? pdi->pi_d->pe_emu : "?",
			    strerror(ret));
			free(stream);
			return (ret);
		}
		num_sections++;
	}

	/* Patch in the blob header. */
	struct ctl_blob_hdr *bh = (struct ctl_blob_hdr *)stream;
	bh->magic = CTL_BLOB_MAGIC;
	bh->version = CTL_BLOB_VERSION;
	bh->num_sections = num_sections;
	bh->reserved = 0;

	*streamp = stream;
	*lenp = used;
	return (0);
}

/*
 * Find the pci_devinst corresponding to a "<bus>:<slot>:<func>" name.
 */
static struct pci_devinst *
find_dev_by_name(const char *name)
{
	unsigned bus, slot, func;
	if (sscanf(name, "%u:%u:%u", &bus, &slot, &func) != 3)
		return (NULL);

	struct pci_devinst *pdi = NULL;
	while ((pdi = pci_next(pdi)) != NULL) {
		if (pdi->pi_bus == bus && pdi->pi_slot == slot &&
		    pdi->pi_func == func)
			return (pdi);
	}
	return (NULL);
}

static int
apply_section(uint8_t kind, uint8_t kern_req, const char *name,
    uint8_t *blob, size_t blob_len)
{
	struct vm_snapshot_meta meta = {
		.dev_name = name,
		.buffer = {
			.buf_start = blob,
			.buf_size = blob_len,
			.buf = blob,
			.buf_rem = blob_len,
		},
		.op = VM_SNAPSHOT_RESTORE,
	};

	if (kind == CTL_SEC_KERN) {
		meta.dev_req = (enum snapshot_req)kern_req;
		return (vm_snapshot_req(ctl_ctx, &meta));
	}

	if (kind != CTL_SEC_DEV)
		return (EINVAL);

	struct pci_devinst *pdi = find_dev_by_name(name);
	if (pdi == NULL) {
		(void) fprintf(stderr,
		    "import-state: unknown device '%s' — skipping\n", name);
		return (0);
	}
	meta.dev_data = pdi;
	int ret = pci_snapshot(&meta);
	if (ret == ENOTSUP) {
		/* Device has no pe_snapshot — fine, skip. */
		return (0);
	}
	return (ret);
}

static int
parse_and_apply_stream(uint8_t *stream, size_t len)
{
	if (len < sizeof (struct ctl_blob_hdr))
		return (EINVAL);
	struct ctl_blob_hdr bh;
	(void) memcpy(&bh, stream, sizeof (bh));
	if (bh.magic != CTL_BLOB_MAGIC || bh.version != CTL_BLOB_VERSION)
		return (EBADMSG);

	size_t off = sizeof (bh);
	for (uint32_t i = 0; i < bh.num_sections; i++) {
		if (off + sizeof (struct ctl_section_hdr) > len)
			return (EBADMSG);
		struct ctl_section_hdr sh;
		(void) memcpy(&sh, stream + off, sizeof (sh));
		off += sizeof (sh);

		if (off + sh.name_len + sh.blob_len > len)
			return (EBADMSG);
		if (sh.name_len >= 64)
			return (EBADMSG);

		char name[64];
		(void) memcpy(name, stream + off, sh.name_len);
		name[sh.name_len] = '\0';
		off += sh.name_len;

		int ret = apply_section(sh.kind, sh.kern_req, name,
		    stream + off, sh.blob_len);
		off += sh.blob_len;

		if (ret != 0) {
			/*
			 * System-wide kernel device classes (VMM_TIME,
			 * VIOAPIC, VATPIC, VATPIT, VHPET, VPMTMR, VRTC)
			 * can all hit cross-host incompatibilities on
			 * restore: VMM_TIME wants a platform-local TSC
			 * rebase; VHPET has a length check against the
			 * kernel's struct-version; others may have their
			 * own quirks.  v1 handled each case individually
			 * (see bhyve_migrate.c); v2's bridge hasn't ported
			 * that yet.
			 *
			 * For now log and continue on kernel-class restore
			 * errors — per-vCPU VMCX state (registers, FPU,
			 * MSRs, VMM_ARCH) and PCI device state are what
			 * actually resume the guest.  A missing HPET tick
			 * source or pre-merged VMM_TIME costs guest clock
			 * accuracy, not guest survival.
			 */
			if (sh.kind == CTL_SEC_KERN &&
			    sh.kern_req != STRUCT_VMCX &&
			    sh.kern_req != STRUCT_VLAPIC) {
				(void) fprintf(stderr,
				    "import-state: kernel section '%s' "
				    "(req=%u) soft-failed (%s); continuing\n",
				    name, sh.kern_req, strerror(ret));
				continue;
			}
			(void) fprintf(stderr,
			    "import-state: section %u (%s) failed: %s\n",
			    i, name, strerror(ret));
			return (ret);
		}
	}
	return (0);
}

/* ---------------------------------------------------------------- */
/* Command handlers						    */
/* ---------------------------------------------------------------- */

static void
cmd_status(int fd)
{
	const char *name = vm_get_name(ctl_ctx);
	size_t lowmem = vm_get_lowmem_size(ctl_ctx);
	size_t highmem = vm_get_highmem_size(ctl_ctx);
	send_json(fd,
	    "{\"status\":\"ok\",\"name\":\"%s\",\"ncpus\":%d,"
	    "\"lowmem\":%zu,\"highmem\":%zu}",
	    name != NULL ? name : "", ctl_ncpus, lowmem, highmem);
}

static int
pause_all_devices(void)
{
	int last_err = 0;
	struct pci_devinst *pdi = NULL;
	while ((pdi = pci_next(pdi)) != NULL) {
		int e = pci_pause(pdi);
		if (e != 0)
			last_err = e;
	}
	return (last_err);
}

static int
resume_all_devices(void)
{
	int last_err = 0;
	struct pci_devinst *pdi = NULL;
	while ((pdi = pci_next(pdi)) != NULL) {
		int e = pci_resume(pdi);
		if (e != 0)
			last_err = e;
	}
	return (last_err);
}

static void
cmd_pause(int fd)
{
	int e = pause_all_devices();
	if (e != 0) {
		send_error(fd, strerror(e));
		return;
	}
	if (vm_pause_instance(ctl_ctx) != 0) {
		send_error(fd, strerror(errno));
		return;
	}
	send_ok(fd);
}

static void
cmd_resume(int fd)
{
	if (vm_resume_instance(ctl_ctx) != 0) {
		send_error(fd, strerror(errno));
		return;
	}
	int e = resume_all_devices();
	if (e != 0) {
		send_error(fd, strerror(e));
		return;
	}
	send_ok(fd);
}

static void
cmd_export_state(int fd)
{
	uint8_t *stream = NULL;
	size_t len = 0;
	int ret = build_save_stream(&stream, &len);
	if (ret != 0) {
		send_error(fd, strerror(ret));
		free(stream);
		return;
	}
	send_json(fd, "{\"status\":\"ok\",\"blob_len\":%zu}", len);
	(void) write_full(fd, stream, len);
	free(stream);
}

static void
cmd_import_state(int fd, const char *line)
{
	uint64_t blob_len_u64 = 0;

	/* C-1: only valid in migrate-listen mode. */
	if (!get_config_bool_default("migrate.listen", false)) {
		send_error(fd, "import-state requires migrate.listen=true");
		return;
	}

	/* C-1: one-shot — reject if a previous import succeeded. */
	(void) pthread_mutex_lock(&ctl_import_mtx);
	if (ctl_import_done) {
		(void) pthread_mutex_unlock(&ctl_import_mtx);
		send_error(fd, "import-state already completed");
		return;
	}
	(void) pthread_mutex_unlock(&ctl_import_mtx);

	if (json_get_uint(line, "blob_len", &blob_len_u64) != 0) {
		send_error(fd, "missing blob_len");
		return;
	}
	if (blob_len_u64 == 0 || blob_len_u64 > CTL_BLOB_MAX) {
		send_error(fd, "invalid blob_len");
		return;
	}
	size_t blob_len = (size_t)blob_len_u64;

	uint8_t *stream = malloc(blob_len);
	if (stream == NULL) {
		send_error(fd, "out of memory");
		return;
	}
	if ((size_t)read_full(fd, stream, blob_len) != blob_len) {
		send_error(fd, "short read");
		free(stream);
		return;
	}

	/* Pause everything before writing state (no-op if already paused). */
	(void) pause_all_devices();
	if (vm_pause_instance(ctl_ctx) != 0) {
		(void) fprintf(stderr,
		    "import-state: vm_pause_instance: %s\n",
		    strerror(errno));
	}

	int ret = parse_and_apply_stream(stream, blob_len);
	free(stream);

	if (ret != 0) {
		send_error(fd, strerror(ret));
		return;
	}

	/*
	 * The per-device RESTORE branch of pci_snapshot_pci_dev
	 * unregisters each BAR at its pre-restore (dest-startup) address
	 * and overwrites pi_bar[] with the source's values.  Re-register
	 * in a second pass so cross-device overlap gets logged and
	 * per-BAR bounds get validated before register_bar commits.
	 * Per-BAR out-of-range is a hard reject (prevents VERIFY_IOPORT
	 * SIGABRT on malformed payload); cross-device overlap is a warn
	 * since register_mem_int silently dedups the same way at runtime.
	 */
	if (pci_restore_bars() != 0) {
		send_error(fd, "BAR restore rejected "
		    "(out-of-range BAR in payload)");
		return;
	}

	/*
	 * Import is done — now flip the VM back to running.  Without
	 * this, vCPU threads (started by the main thread after
	 * bhyve_control_wait_import unblocks) would spin forever in
	 * vm_run's EBUSY retry loop because the VM stays paused from
	 * the vm_pause_instance call above.  pe_resume callbacks kick
	 * viona workers + any other per-device resume logic.
	 */
	if (vm_resume_instance(ctl_ctx) != 0) {
		(void) fprintf(stderr,
		    "import-state: vm_resume_instance: %s\n",
		    strerror(errno));
	}
	(void) resume_all_devices();

	/*
	 * Record success + signal anyone waiting in
	 * bhyve_control_wait_import().  The caller (orchestrator) is
	 * expected to send a separate "resume" once it is ready for the
	 * vCPU threads to make forward progress.
	 */
	(void) pthread_mutex_lock(&ctl_import_mtx);
	ctl_import_done = true;
	(void) pthread_cond_broadcast(&ctl_import_cv);
	(void) pthread_mutex_unlock(&ctl_import_mtx);

	set_config_bool("migrate.restored", true);
	send_ok(fd);
}

/* ---------------------------------------------------------------- */
/* Connection + listener					    */
/* ---------------------------------------------------------------- */

static void
handle_connection(int fd)
{
	char line[1024];

	/*
	 * Agents (Rust BhyveCtl) keep a single connection open across
	 * multiple commands — status -> pause -> export-state etc. on
	 * the same FD.  Loop reading lines until the peer closes.
	 */
	for (;;) {
		ssize_t n = read_line(fd, line, sizeof (line));
		if (n <= 0)
			return;

		if (strstr(line, "\"status\"") != NULL) {
			cmd_status(fd);
		} else if (strstr(line, "\"pause\"") != NULL) {
			cmd_pause(fd);
		} else if (strstr(line, "\"resume\"") != NULL) {
			cmd_resume(fd);
		} else if (strstr(line, "\"export-state\"") != NULL) {
			cmd_export_state(fd);
			/*
			 * export-state writes a large binary blob after
			 * the JSON response.  Close after the blob ships
			 * rather than trying to multiplex another command
			 * on top.
			 */
			return;
		} else if (strstr(line, "\"import-state\"") != NULL) {
			cmd_import_state(fd, line);
			return;	/* same rationale; binary payload consumed */
		} else {
			send_error(fd, "unknown command");
		}
	}
}

static void *
listener_thread(void *arg)
{
	(void) arg;
	while (!ctl_stop) {
		int conn = accept(ctl_listenfd, NULL, NULL);
		if (conn < 0) {
			if (errno == EINTR)
				continue;
			if (ctl_stop)
				break;
			(void) usleep(10000);
			continue;
		}
		handle_connection(conn);
		(void) close(conn);
	}
	return (NULL);
}

/* ---------------------------------------------------------------- */
/* Public API							    */
/* ---------------------------------------------------------------- */

void
bhyve_control_init(struct vmctx *ctx, int ncpus, const char *path)
{
	struct sockaddr_un addr;

	if (ctl_listenfd >= 0)
		return;	/* already initialised */

	ctl_ctx = ctx;
	ctl_ncpus = ncpus;
	ctl_path = strdup(path);
	if (ctl_path == NULL) {
		(void) fprintf(stderr,
		    "bhyve_control_init: strdup failed\n");
		return;
	}

	(void) memset(&addr, 0, sizeof (addr));
	addr.sun_family = AF_UNIX;
	if (strlcpy(addr.sun_path, path, sizeof (addr.sun_path)) >=
	    sizeof (addr.sun_path)) {
		(void) fprintf(stderr,
		    "bhyve_control_init: socket path too long\n");
		free(ctl_path);
		ctl_path = NULL;
		return;
	}

	ctl_listenfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (ctl_listenfd < 0) {
		(void) fprintf(stderr,
		    "bhyve_control_init: socket: %s\n", strerror(errno));
		free(ctl_path);
		ctl_path = NULL;
		return;
	}

	(void) unlink(path);
	if (bind(ctl_listenfd, (struct sockaddr *)&addr,
	    sizeof (addr)) != 0) {
		(void) fprintf(stderr,
		    "bhyve_control_init: bind %s: %s\n",
		    path, strerror(errno));
		(void) close(ctl_listenfd);
		ctl_listenfd = -1;
		free(ctl_path);
		ctl_path = NULL;
		return;
	}
	(void) chmod(path, 0600);

	if (listen(ctl_listenfd, 4) != 0) {
		(void) fprintf(stderr,
		    "bhyve_control_init: listen: %s\n", strerror(errno));
		(void) close(ctl_listenfd);
		ctl_listenfd = -1;
		(void) unlink(path);
		free(ctl_path);
		ctl_path = NULL;
		return;
	}

	if (pthread_create(&ctl_listen_tid, NULL, listener_thread,
	    NULL) != 0) {
		(void) fprintf(stderr,
		    "bhyve_control_init: pthread_create: %s\n",
		    strerror(errno));
		(void) close(ctl_listenfd);
		ctl_listenfd = -1;
		(void) unlink(path);
		free(ctl_path);
		ctl_path = NULL;
		return;
	}
	(void) pthread_setname_np(ctl_listen_tid, "bhyve_ctl");

	(void) fprintf(stderr,
	    "bhyve_control: listening on %s (ncpus=%d)\n",
	    path, ncpus);
}

void
bhyve_control_fini(void)
{
	ctl_stop = 1;
	if (ctl_listenfd >= 0) {
		(void) shutdown(ctl_listenfd, SHUT_RDWR);
		(void) close(ctl_listenfd);
		ctl_listenfd = -1;
	}
	if (ctl_path != NULL) {
		(void) unlink(ctl_path);
		free(ctl_path);
		ctl_path = NULL;
	}
}

void
bhyve_control_wait_import(void)
{
	(void) pthread_mutex_lock(&ctl_import_mtx);
	while (!ctl_import_done)
		(void) pthread_cond_wait(&ctl_import_cv, &ctl_import_mtx);
	(void) pthread_mutex_unlock(&ctl_import_mtx);
}
