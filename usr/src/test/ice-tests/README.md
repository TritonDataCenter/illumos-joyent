# ice driver source checks

These tests cover safety properties that can regress without requiring an
E810 device. Run them from anywhere in the source tree with:

```
python3 usr/src/test/ice-tests/rx_checksum.py
python3 usr/src/test/ice-tests/jumbo_rx.py
python3 usr/src/test/ice-tests/admin_interrupt.py
python3 usr/src/test/ice-tests/link_state.py
python3 usr/src/test/ice-tests/fma_dma.py
python3 usr/src/test/ice-tests/dma_lifetime.py
python3 usr/src/test/ice-tests/mac_filter.py
python3 usr/src/test/ice-tests/vsi_tx_vlan.py
python3 usr/src/test/ice-tests/loopback.py
python3 usr/src/test/ice-tests/hw_stats.py
python3 usr/src/test/ice-tests/link_speed_caps.py
python3 usr/src/test/ice-tests/lso.py
python3 usr/src/test/ice-tests/rss.py
python3 usr/src/test/ice-tests/reset_oicr.py
python3 usr/src/test/ice-tests/reset_rebuild.py
python3 usr/src/test/ice-tests/reset_serialize.py
python3 usr/src/test/ice-tests/tx_bind_threshold.py
python3 usr/src/test/ice-tests/tx_blocked.py
python3 usr/src/test/ice-tests/tx_doorbell.py
python3 usr/src/test/ice-tests/vlan_rx.py
python3 usr/src/test/ice-tests/pool_locks.py
python3 usr/src/test/ice-tests/jumbo_copy.py
python3 usr/src/test/ice-tests/loan_wait.py
python3 usr/src/test/ice-tests/safe_mode.py
python3 usr/src/test/ice-tests/stale_comments.py
```

`rx_checksum.py` verifies that receive checksum metadata is captured before
the descriptor is reposted and that all hardware-reported L3/L4 checksum error
bits suppress checksum validation.

`jumbo_rx.py` verifies that receive frames are assembled through an
EOP-terminated, bounded descriptor walk; segment and total lengths are checked
separately; only EOP metadata drives RXE and checksum handling; malformed,
DMA-fault, and allocation-failure paths advance the ring; and frame segments
are linked with `b_cont`.

`admin_interrupt.py` verifies that every interrupt on the dedicated admin
vector can schedule a bounded, single-flight ARQ drain without depending on an
OICR cause bit, while packet queues remain on separate vectors.

`link_state.py` verifies that the attach-time link state is published only
after successful MAC registration and that publication is serialized with
asynchronous link updates through the link-state lock. It also verifies that
the cache starts at `LINK_STATE_UNKNOWN`, preserving an honest result if the
initial hardware query fails.

`fma_dma.py` verifies that the driver advertises and preserves the negotiated
DMA-checking capability, applies `DDI_DMA_FLAGERR` to both datapath and
common-code control-queue allocations, and retains datapath handle checks.

`dma_lifetime.py` verifies that common-code DMA ownership is tracked by an
explicit bound flag rather than physical address zero, while preserving the
common-code-visible `va`/`pa`/`size` structure prefix.

`mac_filter.py` verifies identical MAC filter construction for add and remove.

`vsi_tx_vlan.py` verifies that the PF data VSI admits tagged and untagged Tx.

`loopback.py` verifies the standard netlb ioctl surface, its explicit STREAMS
and strsun dependencies, the `PRIV_SYS_NET_CONFIG` gate on mode changes,
adaptive thread-context serialization around the firmware command,
rollback-safe local-VSI permission and MAC-command ordering, the paired
`ALLOW_LB`/`LOCAL_LB` flags with inverse source-pruning transitions,
common-code VSI cache updates, link-state ordering, detach cleanup,
physical-event override, and absence of loopback branches in the packet
datapath.
`ice_loopback.c` is the small userland controller used for hardware validation.
It sends each netlb command through STREAMS `I_STR`, so the driver receives the
inline payload and exact `ioc_count` it validates. Build it on illumos from the
source root with:

```
gcc -Wall -Wextra -Werror -idirafter usr/src/uts/common \
    -o /tmp/ice_loopback usr/src/test/ice-tests/ice_loopback.c
```

`hw_stats.py` verifies the hardware statistics wiring: both counter refreshes
run under the stat lock, the clear-on-read VSI register is serviced through the
common code, attach captures both hardware baselines before exposing the
kstats, the kstat callbacks reject writes and lock correctly, teardown deletes
the kstats before destroying their lock, attach installs stats before MAC while
detach removes them before unmapping registers, and `ice_m_stat` sources the
MAC counters under the stat lock. Port refreshes are rate-limited so a MAC
kstat snapshot reads the hardware counter bank once, and unsupported MAC
statistics do not trigger register reads. Register-access faults from a
supported MAC statistic report degraded service and return `EIO`, while
private-kstat failures retain the established unaffected-service policy.

`link_speed_caps.py` verifies that PHY setup advertises the full media speed
set with automatic FEC, media insertion reapplies that configuration, and the
cached supported and advertised speed/FEC values reach the GLDv3 statistics
and read-only property callbacks.

`lso.py` verifies the dark-by-default LSO capability gate, context descriptor
encoding, hostile-metadata checks, per-segment and per-packet descriptor
limits, LSO bind emission, frame-sized copy fallback, DMA cookie-size guard,
and compile-time descriptor-layout checks. The `tx_lso_enable` integer driver
property remains zero by default and should be set in `/kernel/drv/ice.conf`
only for hardware validation.

`rss.py` verifies that interrupt allocation selects a power-of-two data-queue
count within the property, CPU, firmware queue, MSI-X vector, and driver caps;
that the granted vector count controls the final queue count; that the 1:1
ring-to-vector invariant is asserted at sizing and the MSI-X vector accounting
is logged; that the queue ISR dispatches by vector index rather than scanning
rings; and that the VSI, RSS LUT, and GLDv3 receive-ring interrupt handle use
that multiqueue layout.

`reset_oicr.py` verifies the fatal-cause OICR decode and fail-closed path: the
ISR latches reset and fatal causes, the MDD handler clears every detection
register and fails closed only for a this-function offender, the worker
snapshots the causes and skips the ARQ drain during a reset, and mac start
refuses while a reset failed terminally or a rebuild is owed.

`reset_rebuild.py` verifies the reset prepare/rebuild path: prepare quiesces the
datapath, silences the OICR, marks the link down, and marks the VSI absent while
keeping the tracked MAC list; the rebuild reinitializes only what a reset clears
(hardware, DDP, VSI, RSS, interrupt routing, link) and never re-runs the
one-time attach allocations (interrupts, MAC registration, ring DMA); it clears
`reset_ongoing` before the reinit so the admin queue is usable and clears the
fail-closed and reset-owed state only after every rebuild step; and the terminal
path sets `ICE_STATE_RESET_FAILED` with `DDI_SERVICE_LOST`. It also verifies that
`ice_vsi_rebuild` recreates the VSI, replays the tracked filters, restores RSS,
and re-applies promiscuous mode.

`reset_serialize.py` verifies the reset serialization and detach safety: mac
start/stop bracket the datapath in the outermost `ice_rebuild_lock` and start
goes through the factored `ice_start_datapath`; the taskq worker no-ops while
detaching and takes the rebuild lock only after dropping `ice_lock`; the reset
taskq is destroyed after the interrupt handlers are removed and before the rings
and VSI are freed; detach marks the device detaching under the rebuild lock
before unconfigure; and `ice_reset_dispatch` mirrors the `oicr_pending`
single-flight coalescing.

`tx_bind_threshold.py` verifies the bind-versus-copy decision: a whole packet
up to `ICE_TX_SMALL_PKT` is copied into one small-pool buffer before any
fragment is bound and claims exactly one TCB and one descriptor; an
undeliverable frame is not retried through the bind loop; and a bind failure or
a packet exceeding the `ICE_TX_MAX_COOKIE` budget degrades to a full-packet
copy rather than a drop.

`tx_blocked.py` verifies the transmit back-pressure handshake: `itxr_blocked`
is armed under the ring lock and reclaim is re-driven after arming and before
the lock is dropped, so a fully drained ring that will raise no further
completion interrupt cannot stay blocked at MAC; the chain is returned for MAC
to retry; and both exits of the recycle path own the wakeup.

`tx_doorbell.py` verifies the descriptor-sync and doorbell sequence: only the
descriptors the packet wrote are synced, split at ring wrap with
descriptor-sized offsets; the sync precedes the tail advance and the doorbell;
the doorbell write is FM-checked; there is no per-packet MMIO readback or
whole-ring sync; and the control paths keep their flush while recycle keeps its
`DDI_DMA_SYNC_FORKERNEL` sync.

`vlan_rx.py` verifies that a hardware-stripped VLAN tag is reinserted into the
frame: the tag and its status bit are read only after the consumer barrier, the
donated address pair is bounds-checked before `b_rptr` advances, a failed
tag-header allocation discards the frame instead of delivering it, checksum
metadata lands on the head MAC actually receives, and the 802.1Q header is
emitted in network byte order.

`pool_locks.py` verifies that both transmit copy-buffer pool locks are created
once at the negotiated interrupt priority before first use, destroyed exactly
once after the pools are torn down, and never held across the `ice_buf_fini`
unwind inside `ice_buf_init`.

`jumbo_copy.py` verifies that the transmit copy pool can hold any MTU-legal
frame: the general pool buffer is page-rounded from `ICE_MAX_FRAME_SIZE`, a
whole frame still fits one transmit descriptor, the copy fallback draws from
the small pool then the general pool without depending on LSO, and the former
receive-sized pool constant is too small for a jumbo frame.

`loan_wait.py` verifies that receive teardown never waits unbounded on loaned
buffers: one absolute deadline is computed before the ring loop, the wait is a
`cv_timedwait`, a ring that times out is left fully intact and is neither freed
nor reposted, every control-block free is guarded by the loan count or pool
ownership, a surviving pool is not clobbered on restart, and a single bounded
stop serves both the unplumb and reset callers.

`safe_mode.py` verifies that safe mode withholds the hardware offloads the DDP
package would have provided: the checksum and LSO capabilities are refused
outright rather than advertised with no flags, each guard precedes its
assignment, and the receive path reports no verified checksum when the
descriptor status bits carry no verdict.

`stale_comments.py` verifies that the glue comments describe the driver as it
is actually built: no development milestone labels survive in any glue source,
every `ICE_ATTACH_*` token appearing anywhere in the glue -- in code or in a
comment -- names a progress bit the `ice_attach_state_t` enum actually defines,
and the genuine multi-function limitation on the instance list stays recorded.

## On-hardware datapath acceptance

`datapath_accept.sh` is not a source check: it runs on a host with a live
`ice0` and a physical peer, and is the reproducible functional regression suite
for the datapath. Run it on the device under test with the peer already serving
`iperf -s` on the peer address, once per MTU:

```
datapath_accept.sh 192.0.2.2 1500
datapath_accept.sh 192.0.2.2 9000
```

It asserts the module is bound; the test address plumbs at the requested MTU
and the link comes up; FMA access/DMA/dropped-ereport counters are zero before
and after traffic; small and near-MTU ICMP reach the peer; a four-stream
`iperf` run moves traffic and advances the PF byte counters; MAC and CRC error
counters stay zero; and three plumb/unplumb cycles each bring the link back
with FMA still clean. Exit status is zero only if every check passes. Run it
from both hosts to cover both traffic directions. Validated on boston<->hunter
at MTU 1500 (9.36 Gbps) and 9000 (9.59 Gbps), all checks green.
