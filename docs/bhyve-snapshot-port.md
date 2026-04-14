<!--
This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at https://mozilla.org/MPL/2.0/.

Copyright 2026 Edgecast Cloud LLC.
-->

# bhyve live migration v2 — port plan

This branch (`bhyve-live-migration-v2`) reimplements the live-migration
work from `bhyve-live-migration-nvlist-v1` on top of FreeBSD's
`BHYVE_SNAPSHOT` framework, rather than the nvlist-based framework we
wrote on v1.

The outcome is the same: a working cross-host live migration of a bhyve
guest on SmartOS, driven by the GZ agent in
`mariana-trench/services/vmm-migrate-agent`.  What changes is the
serialization format for VM state (device + kernel) and the userspace
code shape in `usr/src/cmd/bhyve/common/`, to match upstream FreeBSD's
conventions.

## Why v2

- **Easier code review on illumos upstream.**  Landing "this is the
  FreeBSD `BHYVE_SNAPSHOT` feature, ported" reviews more easily than
  "this is 5,100 lines of new illumos-unique save/restore".
- **Ongoing upstream tracking.**  FreeBSD maintains and evolves
  `pe_snapshot` bodies for device emulators we share.  Matching their
  signature and macros means every future device-emulator pickup from
  FreeBSD comes with a working `pe_snapshot` for free.
- **Shared vocabulary.**  `SNAPSHOT_VAR_OR_LEAVE`, `vm_snapshot_meta`,
  `pe_snapshot` — every bhyve contributor familiar with FreeBSD's
  checkpoint knows how to read and extend this code.

## Critical design decisions

### 1. Userspace port only; zero illumos kernel diff

FreeBSD's snapshot is split between kernel and userspace:

- **Kernel side** — `sys/amd64/vmm/vmm_snapshot.c` plus per-struct
  handlers (`vm_snapshot_req`, `vlapic_snapshot`, `vhpet_snapshot`,
  `vioapic_snapshot`, `vatpic_snapshot`, etc.), driven by a single
  `VM_SNAPSHOT_REQ` ioctl that takes a `struct vm_snapshot_meta`
  with a userspace buffer pointer and copyout/copyin per
  `SNAPSHOT_VAR_OR_LEAVE` call.
- **Userspace side** — `usr.sbin/bhyve/snapshot.c` orchestrator plus
  `pe_snapshot` callbacks on every device emulator.

illumos already has the equivalent capability via the existing
`VM_DATA_READ` / `VM_DATA_WRITE` ioctls with per-class IDs
(`VDC_VMM_TIME`, `VDC_LAPIC`, `VDC_IOAPIC`, `VDC_ATPIT`, `VDC_ATPIC`,
`VDC_HPET`, `VDC_PM_TIMER`, `VDC_RTC`, `VDC_REGISTER`, `VDC_MSR`,
`VDC_FPU`, `VDC_VMM_ARCH`).  Everything FreeBSD's kernel snapshot path
produces, illumos's existing ioctls already produce.

We port **the userspace half only** and bridge the kernel state to
illumos's native `VDC_*` interface.  Zero illumos kernel diff.  The
bridge is ~150 LOC in libvmmapi.

### 2. Port API contract verbatim; defer the file format

FreeBSD's `usr.sbin/bhyve/snapshot.c` has two concerns mashed together:

- **The pe_snapshot dispatcher** — IPC socket, per-device iteration,
  meta-buffer allocation.  *We want this.*
- **The file format** — libucl-formatted metadata, two-file
  `kdata`+`vmmem` layout, `struct restore_state` parsing.  *We don't
  need this for live migration.*

Live migration ships the blob over a WebSocket; no file is written.
libucl is not in the illumos-joyent tree and is not worth importing
just for this.

v2 ports the dispatcher plus macros plus `pe_snapshot` callback
contract now.  File-format plumbing is deferred and may never land if
live migration remains the only use case.  If we decide we want a
file-based checkpoint later, we either import libucl or replace the
metadata with a simpler scheme at that point.

### 3. v1's kernel-state class list was correct; keep it

Compare v1's `kern_dev_classes[]` with FreeBSD's `snapshot_kern_structs[]`:

```
/* v1 bhyve_migrate.c */
{ VDC_VMM_TIME, 1, "vmm_time" },
{ VDC_IOAPIC,   1, "ioapic" },
{ VDC_ATPIT,    1, "atpit" },
{ VDC_ATPIC,    1, "atpic" },
...

/* FreeBSD usr.sbin/bhyve/snapshot.c */
{ "vhpet",  STRUCT_VHPET  },
{ "vm",     STRUCT_VM     },
{ "vioapic", STRUCT_VIOAPIC },
{ "vlapic",  STRUCT_VLAPIC  },
...
```

Same pattern, different IDs, different serialization primitive.

v2 keeps v1's `VDC_*` list (correct for the illumos kernel) and
replaces nvlist serialization with FreeBSD's `SNAPSHOT_VAR_OR_LEAVE`
macros against `meta->buffer`.  The dev-state ordering (time first,
then per-vCPU, then system devices, then PCI devices) was arrived at
through v1 testing and matches FreeBSD's convention.

### 4. Carry v1's migration architecture on top

Pieces we carry forward as-is (or with mechanical adjustments):

- `bhyve_control.c` — the JSON-over-Unix-socket control plane
- `migrate-listen` boot mode
- Security hardening (C-1 migrate-listen one-shot; C-2 BAR bounds
  check; C-3 BAR cross-device conflict pre-check)
- The Rust GZ agent entirely
- ZFS send/recv orchestration
- Phased begin/sync/switch/finalize API
- Pause-first single-pass RAM transfer

Pieces we delete:

- `bhyve_migrate.c` (927 LOC) — replaced by FreeBSD's `snapshot.c`
- v1's `pe_pause(pi) / pe_restore(pi, nvl)` on `struct pci_devemu` —
  replaced by FreeBSD's `pe_pause(pi) / pe_resume(pi) / pe_snapshot(meta)`

## snapshot_req → VDC_* mapping

| FreeBSD `enum snapshot_req` | Covers | illumos equivalent |
|---|---|---|
| `STRUCT_VIOAPIC` | I/O APIC | `VDC_IOAPIC` |
| `STRUCT_VM`      | Per-VM state (hostTSC, ...) | `VDC_VMM_TIME` + `VDC_VMM_ARCH` (per-vcpu) |
| `STRUCT_VLAPIC`  | Local APIC (per-vcpu) | `VDC_LAPIC` |
| `VM_MEM`         | Guest memory | mmap via `/dev/vmm/<name>` |
| `STRUCT_VHPET`   | HPET | `VDC_HPET` |
| `STRUCT_VMCX`    | VMX/SVM context (per-vcpu) | `VDC_REGISTER` + `VDC_MSR` + `VDC_FPU` + `VDC_VMM_ARCH` |
| `STRUCT_VATPIC`  | i8259 PIC | `VDC_ATPIC` |
| `STRUCT_VATPIT`  | i8254 PIT | `VDC_ATPIT` |
| `STRUCT_VPMTMR`  | ACPI PM timer | `VDC_PM_TIMER` |
| `STRUCT_VRTC`    | PC RTC | `VDC_RTC` |

`STRUCT_VM` and `STRUCT_VMCX` fan out to multiple `VDC_*` reads in the
userspace bridge (phase 2).

## Phase plan

Each phase is intended to land as a single reviewable commit with a
commit message that points at the FreeBSD origin file (or explicitly
calls out illumos-unique work).

| # | Scope | Source | Net LOC |
|---|---|---|---|
| 1 | `vmm_snapshot.h` — types, macros, buf helpers contract | `sys/amd64/include/vmm_snapshot.h` (verbatim) | ~130 |
| 2 | `vm_snapshot_buf()` + `vm_snapshot_req()` + `vm_snapshot_guest2host_addr()` in libvmmapi; `VDC_*` dispatch bridge | `sys/amd64/vmm/vmm_snapshot.c` adapted for userspace + new illumos bridge | ~250 |
| 3 | `pe_snapshot` / `pe_pause` / `pe_resume` on `pci_devemu`; generic `pci_snapshot_pci_dev` / `pci_snapshot` / `pci_pause` / `pci_resume` helpers | `usr.sbin/bhyve/pci_emul.{c,h}` | ~200 |
| 4 | virtio common helpers: `vi_pci_snapshot_softc` / `_consts` / `_queues` / `vi_pci_snapshot` | `usr.sbin/bhyve/virtio.c` | ~150 |
| 5 | Simple device bodies: `uart_emul.c`, `pci_hostbridge.c`, `pci_virtio_rnd.c` | direct FreeBSD pickup | ~100 total |
| 6 | `block_if.c` + `pci_virtio_block.c` pe_snapshot | FreeBSD, adapted to illumos blockif | ~250 |
| 7 | `pci_nvme.c` pe_snapshot | FreeBSD | ~200 |
| 8 | **viona `pe_snapshot`** (illumos-unique) | v1 viona code rewritten in FreeBSD style | ~300 |
| 9 | `bhyverun.c` — SIGUSR2, checkpoint thread scaffolding, migrate-listen mode carry | FreeBSD + v1 carry | ~400 |
| 10 | `bhyve_control.c` re-plumb: JSON envelope stays, payload switches to `vm_snapshot_meta` blob | v1 rewrite | ~500 |
| 11 | Security hardening re-layer (C-1 / C-2 / C-3) against the v2 API | v1 carry + minor rework | ~300 |
| 12 | Rust agent `codec.rs` wire format: blob + manifest instead of nvlist | mariana-trench side | ~200 |

Expected net total: ~2,800 LOC (≈55% of v1's 5,100).  Of that, ~60% is
"pickup of FreeBSD commit `<SHA>`" provenance for easy review; the
remaining ~40% is illumos-unique work concentrated in 3-4 files
(viona snapshot, libvmmapi bridge, bhyve_control, the Rust agent).

## Risks

- **Kernel bridge correctness** — STRUCT_VM and STRUCT_VMCX fan out
  to multiple `VDC_*` reads.  The bridge must preserve field order
  and handle partial-read failures cleanly.  Test strategy: round-trip
  save → restore on a paused VM and check guest liveness.
- **pe_snapshot body correctness** — round-trip testable in isolation
  (save a blob, restore it, compare VM state).  FreeBSD's code is
  the reference; illumos emulators may have slightly different fields
  (esp. where illumos added features FreeBSD doesn't have).
- **block_if divergence** — illumos's `block_if.c` has drifted from
  FreeBSD.  pe_snapshot references internal blockif state
  (in-flight queue depth, backend type) that may not map 1:1.
- **Security hardening re-layer** — C-2/C-3 are structural (they live
  in PCI BAR restore, not in pe_snapshot itself) so they should carry
  cleanly.  C-1 is a control-socket guard that moves with
  `bhyve_control.c`.  Re-test after each re-layer.
- **Integration risk during the port** — v1 still works.  If v2
  regresses during the port, we diagnose against the v1 tag
  (`bhyve-live-migration-nvlist-v1`).  v1 remains the deployable
  reference while v2 is being built.

## What's intentionally out of scope for v2

- **libucl file format** — defer (see decision #2).
- **bhyvectl `--suspend` CLI** — the FreeBSD tool-side CLI for
  triggering checkpoint from outside the process.  Our production
  trigger is the control socket; bhyvectl integration can come later.
- **Capsicum sandbox integration** — FreeBSD's snapshot.c uses
  Capsicum.  illumos has no Capsicum; sandboxing via zones/privileges
  is illumos's answer, but not required to land the port.
- **Dirty page tracking** — independent follow-up; see
  `services/vmm-migrate-agent/DIRTY-TRACKING.md`.  Layered on top of
  the working migration, regardless of v1 vs v2 base.

## References

- v1 tag: `bhyve-live-migration-nvlist-v1` (commit `4f95ad6c98`)
- FreeBSD source: `~/workspace/freebsd-src` (main branch)
- Key FreeBSD files:
  - `sys/amd64/include/vmm_snapshot.h`
  - `sys/amd64/vmm/vmm_snapshot.c`
  - `usr.sbin/bhyve/snapshot.{c,h}`
  - `usr.sbin/bhyve/pci_emul.{c,h}`
  - `usr.sbin/bhyve/virtio.c`
  - `usr.sbin/bhyve/pci_virtio_rnd.c` (simple example)
- v1 `PRODUCTION-READINESS.md`, `TIMING.md`, `DIRTY-TRACKING.md` in
  `mariana-trench/services/vmm-migrate-agent/` — what ships on top
  of whichever bhyve base we're building against.

## Feature gate

Phase 1 through 8 build but are unreachable without wiring in
phase 9.  Phase 9 introduces the `-C` / checkpoint CLI flag and the
socket listener.  Phase 10+ switch the control socket onto the new
payload.  Throughout, keep the nvlist path compilable (or cleanly
deleted) — never ship a half-converted tree.
