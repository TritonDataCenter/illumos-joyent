#!/usr/bin/env python3

"""Check ICE reset prepare/rebuild source invariants."""

from pathlib import Path


REPO = Path(__file__).resolve().parents[4]
ATTACH_SOURCE = REPO / "usr/src/uts/common/io/ice/ice.c"
VSI_SOURCE = REPO / "usr/src/uts/common/io/ice/ice_vsi.c"
TX_SOURCE = REPO / "usr/src/uts/common/io/ice/ice_tx.c"
RX_SOURCE = REPO / "usr/src/uts/common/io/ice/ice_rx.c"


def function(source: str, signature: str, following: str) -> str:
    start = source.index(signature)
    end = source.index(following, start)
    return source[start:end]


def main() -> None:
    attach = ATTACH_SOURCE.read_text(encoding="utf-8")

    # Prepare quiesces the datapath, fences new interrupts, and marks the VSI
    # absent so the rebuild recreates it.  The MAC list is left intact.
    prepare = function(
        attach,
        "ice_prepare_for_reset(ice_t *ice)\n{",
        "\nstatic void\nice_rebuild",
    )
    assert "reset_ongoing = true" in prepare
    assert "ice_rx_stop_reset" not in prepare

    # No packet DMA may be released before the reset completes.  The PFR is not
    # issued until ice_rebuild(), and E810 has no MMIO tx queue disable (only
    # doorbell and context-command registers exist in core/ice_hw_autogen.h),
    # so a tx queue can still master right up to the reset.  Prepare therefore
    # quiesces only; the reclaim moved past the barrier.
    assert "ice_tx_stop(ice)" not in prepare
    assert "ice_rx_stop(ice)" not in prepare
    assert "ice_rx_free_rcbs" not in prepare
    assert "ice_tcb_free" not in prepare
    assert "ice_tx_quiesce(ice)" in prepare
    assert "ice_rx_quiesce(ice)" in prepare

    # Interrupt causes are dissociated before the queues are disabled -- FreeBSD
    # ice_if_stop() does the same and ice_lib.c:1473 documents that an Rx queue
    # may not disable properly otherwise -- and both precede either quiesce, so
    # nothing that can be DMA'd into is touched while a queue can master.
    assert (
        prepare.index("ice_queues_intr_unmap(ice)")
        < prepare.index("ice_queues_disable(ice)")
        < prepare.index("ice_tx_quiesce(ice)")
        < prepare.index("ice_rx_quiesce(ice)")
    )
    # The tx queue disable rides the admin queue, which soft-fails once
    # reset_ongoing is set (core/ice_controlq.c:1034), so it must be issued
    # first -- but the flag still precedes the control-queue shutdown.
    assert prepare.index("ice_queues_disable(ice)") < prepare.index(
        "reset_ongoing = true"
    )
    assert prepare.index("reset_ongoing = true") < prepare.index(
        "ice_shutdown_all_ctrlq(hw, false)"
    )
    assert "ice_intr_oicr_disable(ice)" in prepare
    assert "PFINT_OICR_ENA, 0" in prepare
    assert "LINK_STATE_DOWN" in prepare
    assert "vi_added = B_FALSE" in prepare
    # Prepare cannot fail.  A loan the stack has not returned leaves that ring
    # intact and ice_rx_start() refuses to reuse it, so the rebuild fails soft
    # at ice_start_datapath() instead of taking the NIC terminally offline over
    # buffers that were about to come back.  FreeBSD's ice_prepare_for_reset()
    # returns void for the same reason (if_ice_iflib.c:2510).
    assert "static void\nice_prepare_for_reset(ice_t *ice)" in attach
    assert "static boolean_t\nice_prepare_for_reset" not in attach
    assert "(void) ice_rx_quiesce(ice)" in prepare
    assert "return (drained)" not in prepare
    assert "ice_reset_set_failed" not in prepare
    # It drops the state a reset invalidates, but shuts the control queue down
    # rather than destroying it: a concurrent admin-queue caller must get
    # ICE_ERR_NOT_READY, not a destroyed mutex.  port_info and the VSI contexts
    # are never freed, so concurrent readers stay valid.
    assert "ice_clear_hw_tbls(hw)" in prepare
    assert "ice_sched_cleanup_all(hw)" in prepare
    assert "ice_shutdown_all_ctrlq(hw, false)" in prepare
    assert "ice_destroy_all_ctrlq" not in prepare

    rebuild = function(
        attach,
        "ice_rebuild(ice_t *ice)\n{",
        "\nvoid\nice_reset_task",
    )
    # The rebuild reinitializes only what a reset clears.
    for token in (
        "ice_vsi_rebuild",
        "ice_intr_oicr_setup",
        "ice_queues_intr_map",
        "ice_set_link_events",
        # MAC does not re-drive the per-ring rx start across a reset, so the
        # rebuild must repost buffers and reopen the rings itself.
        "ice_rx_rings_resume",
    ):
        assert token in rebuild, token
    # It must not re-run the one-time attach allocations that survive a reset.
    for token in (
        "ice_alloc_intrs",
        "ice_add_intr_handlers",
        "ice_mac_register",
        "ice_tx_rings_alloc",
        "ice_rx_rings_alloc",
    ):
        assert token not in rebuild, token
    # It must never tear the common code down: port_info, the VSI contexts and
    # the DDP copy have to survive the reset or the readers that serialize on
    # ice_rebuild_lock are left dereferencing freed memory.
    assert "ice_deinit_hw" not in rebuild
    assert "ice_hw_init" not in rebuild
    # ...and with nothing torn down, ICE_ATTACH_HW_INIT stays set throughout.
    assert "ice_attach_progress" not in rebuild
    # The package is replayed from hw->pkg_copy.  ice_ddp_load() would go
    # through ice_copy_and_init_pkg(), which re-duplicates the package and
    # leaks the previous copy now that no ice_free_seg() runs across a reset.
    assert "ice_ddp_load" not in rebuild
    assert "ice_copy_and_init_pkg" not in rebuild
    assert "ice_init_pkg(hw, hw->pkg_copy, hw->pkg_size)" in rebuild
    # ice_init_hw() no longer runs, so the wait for (or issue of) the hardware
    # reset has to be explicit before anything rides the admin queue.
    assert "ice_check_reset(hw)" in rebuild
    assert "ice_reset(hw, ICE_RESET_PFR)" in rebuild
    # Packet DMA is released only once the reset has actually completed: that
    # is the first point at which no queue can master against the old
    # contexts.  Both halves are no-ops when the datapath was already down.
    assert "ice_tx_reclaim(ice)" in rebuild
    assert "ice_rx_reclaim(ice)" in rebuild
    assert (
        rebuild.index("ice_reset(hw, ICE_RESET_PFR)")
        < rebuild.index("ice_tx_reclaim(ice)")
        < rebuild.index("ice_rx_reclaim(ice)")
        < rebuild.index("reset_ongoing = false")
    )
    # The admin queue is usable only once reset_ongoing is cleared, and every
    # rebuild step below rides that queue.
    assert "reset_ongoing = false" in rebuild
    assert rebuild.index("ice_check_reset(hw)") < rebuild.index(
        "reset_ongoing = false"
    )
    # The FreeBSD-ordered partial reinit.
    for token in (
        "ice_init_all_ctrlq(hw)",
        "ice_sched_query_res_alloc(hw)",
        "ice_clear_pf_cfg(hw)",
        "ice_clear_pxe_mode(hw)",
        "ice_get_caps(hw)",
        "ice_sched_init_port(hw->port_info)",
    ):
        assert token in rebuild, token
    assert (
        rebuild.index("reset_ongoing = false")
        < rebuild.index("ice_init_all_ctrlq(hw)")
        < rebuild.index("ice_sched_query_res_alloc(hw)")
        < rebuild.index("ice_clear_pf_cfg(hw)")
        < rebuild.index("ice_clear_pxe_mode(hw)")
        < rebuild.index("ice_get_caps(hw)")
        < rebuild.index("ice_sched_init_port(hw->port_info)")
        < rebuild.index("ice_init_pkg(hw, hw->pkg_copy")
        < rebuild.index("ice_vsi_rebuild")
    )
    # Refreshed capabilities are a bounds gate only: resizing the rings here
    # would race the loaned-buffer accounting the prepare just drained.
    assert "ice_validate_caps(ice)" in rebuild
    for token in ("num_rxq", "num_txq", "num_msix_vectors", "ice_rings_size"):
        assert token not in rebuild, token
    # A global/core reset can zero the MAC counters; drop both baselines.
    assert "ice_stat_port_loaded = B_FALSE" in rebuild
    assert "ice_stat_vsi_loaded = B_FALSE" in rebuild
    # The reset-owed bits clear after the rebuild steps but before the OICR is
    # re-enabled, so a fresh link-change OICR cannot observe a stale
    # RESET_PENDING/PFR_REQ and dispatch a redundant rebuild.
    owed = rebuild.index("~(ICE_STATE_RESET_PENDING | ICE_STATE_PFR_REQ)")
    assert rebuild.index("ice_init_all_ctrlq(hw)") < owed
    assert rebuild.index("ice_vsi_rebuild") < owed
    assert owed < rebuild.index("ice_intr_oicr_setup")
    # The fail-closed bit clears only after the datapath-restoring steps.
    err = rebuild.index("~ICE_STATE_ERROR")
    assert rebuild.index("ice_vsi_rebuild") < err
    assert rebuild.index("ice_queues_intr_map") < err
    # A datapath restart failure is soft (recoverable), not terminal.
    assert "ice_start_datapath(ice)" in rebuild
    # The terminal path fails closed via the shared helper.
    terminal = rebuild[rebuild.index("reset_failed:"):]
    assert "ice_reset_set_failed(ice)" in terminal
    # The failure path quiesces the control queue but leaves port_info and the
    # VSI contexts allocated, so the surviving readers stay valid for the
    # fail-closed life of the instance.
    assert "ice_shutdown_all_ctrlq(hw, false)" in terminal
    assert terminal.index("ice_shutdown_all_ctrlq(hw, false)") < terminal.index(
        "ice_reset_set_failed(ice)"
    )
    fail = function(
        attach,
        "ice_reset_set_failed(ice_t *ice)\n{",
        "\nstatic void\nice_prepare_for_reset",
    )
    assert "ICE_STATE_RESET_FAILED" in fail
    assert "DDI_SERVICE_LOST" in fail

    # The terminal path also re-masks the OICR, since the failure may have come
    # from after ice_intr_oicr_setup() re-armed it mid-rebuild.
    assert "ice_intr_oicr_disable(ice)" in terminal
    assert "wr32(hw, PFINT_OICR_ENA, 0)" in terminal
    assert terminal.index("ice_intr_oicr_disable(ice)") < terminal.index(
        "ice_shutdown_all_ctrlq(hw, false)"
    )

    # ICE_STATE_RESET_FAILED is terminal: the reset taskq refuses to rebuild an
    # instance that is already failed closed, so a later reset cannot bring the
    # rings and link back up while ice_m_start() still refuses to plumb.  The
    # bit is tested under ice_rebuild_lock, the same lock it is set from.
    task = function(attach, "ice_reset_task(void *arg)\n{", "\n#ifdef DEBUG")
    gate = task.index("ICE_STATE_RESET_FAILED")
    assert task.index("mutex_enter(&ice->ice_rebuild_lock)") < gate
    assert gate < task.index("ice_prepare_for_reset(ice)")
    # It is never cleared: ice_m_start()'s gate documents it as surviving until
    # the driver is reloaded, so FreeBSD's clear-at-rebuild-start is not used.
    assert "~ICE_STATE_RESET_FAILED" not in attach
    assert "~(ICE_STATE_RESET_FAILED" not in attach

    # ice_vsi_rebuild recreates the VSI, replays the tracked filters, restores
    # RSS, and re-applies promiscuous mode when it was on.
    vsi = VSI_SOURCE.read_text(encoding="utf-8")
    vrebuild = vsi[vsi.index("ice_vsi_rebuild(ice_t *ice)\n{"):]
    assert "ice_vsi_setup(ice)" in vrebuild
    assert "ice_fltr_entry_init(" in vrebuild
    assert "ice_add_mac(hw, &add)" in vrebuild
    assert "ice_rss_setup(ice)" in vrebuild
    assert "ice->ice_promisc_on" in vrebuild
    assert "ice_promisc_apply(ice, B_TRUE)" in vrebuild

    # The quiesce/reclaim split is behavioural, not cosmetic: the waiting half
    # must release nothing, and the composite the unplumb path uses must still
    # be quiesce-then-reclaim so ice_m_stop() is unchanged.
    tx = TX_SOURCE.read_text(encoding="utf-8")
    tx_quiesce = function(
        tx, "ice_tx_quiesce(ice_t *ice)\n{", "\nvoid\nice_tx_reclaim")
    assert "itxr_quiesce = B_TRUE" in tx_quiesce
    assert "cv_wait(&itr->itxr_cv" in tx_quiesce
    assert "ice_tcb_free" not in tx_quiesce
    tx_reclaim = function(
        tx, "ice_tx_reclaim(ice_t *ice)\n{", "\nvoid\nice_tx_stop")
    assert "ice_tcb_free(itr, itr->itxr_tcbs[slot])" in tx_reclaim
    tx_stop = function(tx, "ice_tx_stop(ice_t *ice)\n{", "\n/*\n")
    assert tx_stop.index("ice_tx_quiesce(ice)") < tx_stop.index(
        "ice_tx_reclaim(ice)"
    )

    rx = RX_SOURCE.read_text(encoding="utf-8")
    rx_quiesce = function(
        rx, "ice_rx_quiesce(ice_t *ice)\n{", "\nvoid\nice_rx_reclaim")
    assert "irxr_shutdown = B_TRUE" in rx_quiesce
    assert "cv_timedwait(&irr->irxr_cv" in rx_quiesce
    assert "ice_rx_free_rcbs" not in rx_quiesce
    assert "return (drained)" in rx_quiesce
    rx_reclaim = function(
        rx, "ice_rx_reclaim(ice_t *ice)\n{", "\nboolean_t\nice_rx_stop")
    # A ring that never drained keeps its pool: freeing it would double free
    # the mblk the stack still holds.  The count is re-tested under the ring
    # lock because a late return can land between the quiesce and here.
    assert "irxr_nloaned == 0" in rx_reclaim
    assert "ice_rx_free_rcbs(irr)" in rx_reclaim
    rx_stop = function(rx, "ice_rx_stop(ice_t *ice)\n{", "\n/*\n")
    assert rx_stop.index("ice_rx_quiesce(ice)") < rx_stop.index(
        "ice_rx_reclaim(ice)"
    )

    # ice_rx_start()'s survivor-pool reclaim is now load-bearing on the reset
    # path too: it is the only reclaim for a ring that timed out.
    rx_start = function(
        rx, "ice_rx_start(ice_t *ice)\n{", "\n/*\n * Tear down every rx ring")
    assert "irxr_nloaned > 0" in rx_start
    assert "ice_rx_free_rcbs(irr)" in rx_start

    print("PASS: ice reset prepare/rebuild source invariants")


if __name__ == "__main__":
    main()
