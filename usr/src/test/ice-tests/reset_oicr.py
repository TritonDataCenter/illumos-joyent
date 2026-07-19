#!/usr/bin/env python3

"""Check ICE fatal-cause OICR decode and fail-closed source invariants."""

from pathlib import Path


REPO = Path(__file__).resolve().parents[4]
HEADER = REPO / "usr/src/uts/common/io/ice/ice.h"
INTR_SOURCE = REPO / "usr/src/uts/common/io/ice/ice_intr.c"
GLD_SOURCE = REPO / "usr/src/uts/common/io/ice/ice_gld.c"
ICE_SOURCE = REPO / "usr/src/uts/common/io/ice/ice.c"


def function(source: str, signature: str, following: str) -> str:
    start = source.index(signature)
    end = source.index(following, start)
    return source[start:end]


def main() -> None:
    header = HEADER.read_text(encoding="utf-8")
    assert "ICE_STATE_PFR_REQ" in header
    assert "ICE_STATE_RESET_FAILED" in header
    assert "uint32_t\t\tice_oicr_cause;" in header
    # MDD needs a persistent carrier of its own: unlike the fatal and reset
    # causes it owes a register decode rather than a reset, so nothing
    # downstream can reconstruct it from the reset-owed bits.
    assert "ICE_STATE_MDD_PENDING" in header

    intr = INTR_SOURCE.read_text(encoding="utf-8")

    # Every fatal and reset cause stays enabled, and the fatal mask names the
    # PFR-triggering causes.
    for cause in (
        "PFINT_OICR_ECC_ERR_M",
        "PFINT_OICR_MAL_DETECT_M",
        "PFINT_OICR_PCI_EXCEPTION_M",
        "PFINT_OICR_HMC_ERR_M",
        "PFINT_OICR_PE_CRITERR_M",
        "PFINT_OICR_GRST_M",
    ):
        assert cause in intr, cause
    fatal_mask = function(intr, "#define\tICE_OICR_FATAL_MASK", "#define\tICE_OICR_CAUSE_MASK")
    for cause in (
        "PFINT_OICR_ECC_ERR_M",
        "PFINT_OICR_PCI_EXCEPTION_M",
        "PFINT_OICR_HMC_ERR_M",
        "PFINT_OICR_PE_CRITERR_M",
    ):
        assert cause in fatal_mask, cause

    # MAL_DETECT must not ride the discardable snapshot: ice_oicr_task()
    # consumes ice_oicr_cause unconditionally, so a run the attach/detach gate
    # swallows would destroy the only record of the event.
    cause_mask = function(
        intr, "#define\tICE_OICR_CAUSE_MASK", "\nstatic void\nice_link_state_set")
    assert "PFINT_OICR_MAL_DETECT_M" not in cause_mask

    # The ISR fails closed and latches causes.  The decode itself is shared
    # with the attach-time harvest so the two cannot drift.
    isr = function(intr, "ice_intr_oicr(ice_t *ice)\n{", "\nstatic uint_t\nice_intr_queue")
    assert "ice_oicr_causes_latch(ice, oicr)" in isr
    latch = function(
        intr,
        "ice_oicr_causes_latch(ice_t *ice, uint32_t oicr)\n{",
        "\nstatic boolean_t\nice_oicr_mdd",
    )
    assert "hw->reset_ongoing = true;" in latch
    assert "ICE_STATE_RESET_PENDING | ICE_STATE_ERROR" in latch
    assert "ICE_STATE_ERROR | ICE_STATE_PFR_REQ" in latch
    assert "ICE_STATE_MDD_PENDING" in latch
    assert "ice->ice_oicr_cause |= oicr & ICE_OICR_CAUSE_MASK;" in isr
    # The admin-vector dispatch and re-arm remain.
    assert "ice->ice_oicr_pending = B_TRUE;" in isr
    assert "ice_intr_oicr_enable(ice);" in isr

    # Clearing the pending bit must not lose a cause the ISR sets concurrently,
    # so it is a CAS, not a read followed by an atomic_and_32.
    testclear = function(
        intr,
        "ice_state_testclear(ice_t *ice, uint32_t bit)\n{",
        "\nstatic void\nice_oicr_causes_latch",
    )
    assert "atomic_cas_32(&ice->ice_state" in testclear

    # The MDD handler clears every detection register and fails closed only when
    # this function is the offender.
    mdd = function(intr, "ice_oicr_mdd(ice_t *ice)\n{", "\nstatic void\nice_oicr_fatal")
    for reg in ("GL_MDET_TX_PQM", "GL_MDET_TX_TCLAN", "GL_MDET_RX",
                "PF_MDET_TX_PQM", "PF_MDET_TX_TCLAN", "PF_MDET_RX"):
        assert reg in mdd, reg
    assert "ICE_STATE_ERROR | ICE_STATE_PFR_REQ" in mdd
    # Reports whether this function was the offender so the caller can gate.
    assert "return (pf_mdd);" in mdd

    # The fatal handler logs and drives the link down only on a this-PF fault.
    # MDD arrives as its own argument, not folded into the cause word, so the
    # foreign-MDD rule (another function's event must not down our link) is
    # still decided by ice_oicr_mdd()'s return.
    fatal = function(intr, "ice_oicr_fatal(ice_t *ice, uint32_t cause, boolean_t mdd)\n{", "\nstatic void\nice_oicr_task")
    assert "if (mdd && ice_oicr_mdd(ice))" in fatal
    assert "ice_link_state_set(ice, LINK_STATE_DOWN);" in fatal
    assert "if (fault) {" in fatal
    assert "LINK_STAT_CHANGE" not in fatal

    # The worker snapshots the causes and skips the drain during reset.
    worker = function(intr, "ice_oicr_task(void *arg)\n{", "\nstatic void\nice_intr_oicr_enable")
    assert "cause = ice->ice_oicr_cause;" in worker
    assert "ice->ice_oicr_cause = 0;" in worker
    assert "ice_oicr_fatal(ice, cause, mdd);" in worker
    assert "hw->reset_ongoing ||" in worker
    assert "ICE_STATE_RESET_PENDING | ICE_STATE_PFR_REQ" in worker

    # The MDD decode sits BELOW the attach/detach gate -- that is the whole
    # point of carrying it as state -- and ABOVE the reset skip, because
    # PF_MDET_* has reset source CORER and a PFR rebuild does not clear it:
    # leaving it latched misattributes another function's next event to us.
    # FreeBSD's admin task orders it the same way (if_ice_iflib.c:2447 precedes
    # the control-queue skip at :2449).
    assert "ICE_STATE_MDD_PENDING" in worker
    mdd_at = worker.index("ICE_STATE_MDD_PENDING")
    assert worker.index("ice->ice_detaching") < mdd_at
    assert mdd_at < worker.index("hw->reset_ongoing ||")

    # The setup read is read-clear.  On attach it must be harvested into state;
    # on the rebuild it must be discarded, or the causes that requested the
    # rebuild just completed would dispatch it again in a loop.
    setup = function(
        intr,
        "ice_intr_oicr_setup(ice_t *ice, boolean_t harvest)\n{",
        "\nstatic uint_t\nice_intr_oicr",
    )
    assert "(void) rd32(hw, PFINT_OICR);" not in setup
    assert "ice_oicr_causes_latch(ice, oicr)" in setup
    # An all-ones read from a severed bus must not synthesise phantom causes.
    assert "ice_check_acc_handle" in setup

    # mac start refuses while a reset failed terminally or a rebuild is owed,
    # so a replumb cannot re-open the datapath on stale hardware.
    gld = GLD_SOURCE.read_text(encoding="utf-8")
    start = function(gld, "ice_m_start(void *arg)\n{", "\nstatic void\nice_m_stop")
    assert "ICE_STATE_RESET_FAILED" in start
    assert "ICE_STATE_PFR_REQ" in start
    assert "ICE_STATE_RESET_PENDING" in start
    assert "return (EIO);" in start
    # Guard: a malicious-driver event on ANOTHER function must not block plumb.
    # Only ice_oicr_mdd() deciding this PF was the offender sets PFR_REQ, which
    # is already in the blocked mask above.
    assert "ICE_STATE_MDD_PENDING" not in start

    # Both latches are one-shot: the ISR arms them and dispatches the worker
    # exactly once, so a lifetime gate that swallows the dispatch owes the
    # rebuild forever.  Every gate that can swallow one has a matching requeue
    # when it lifts.
    ice_c = ICE_SOURCE.read_text(encoding="utf-8")
    assert "ice_reset_redispatch(ice_t *ice)" in ice_c
    for flag in ("ice->ice_attaching = B_FALSE", "ice->ice_detaching = B_FALSE"):
        lift = ice_c.index(flag)
        end = ice_c.index("mutex_exit(&ice->ice_rebuild_lock)", lift)
        assert "ice_reset_redispatch(ice)" in ice_c[lift:end], flag
    # Guard: redispatch drives the RESET taskq, and a foreign-PF MDD owes a
    # register decode rather than a reset.  The decode is re-driven by the
    # admin periodic instead.
    redispatch = function(
        ice_c,
        "ice_reset_redispatch(ice_t *ice)\n{",
        "\nstatic int\nice_attach",
    )
    assert "ICE_STATE_MDD_PENDING" not in redispatch

    # The two call sites carry opposite policy.  Collapsing the rebuild one
    # into a harvest would re-latch the causes that requested the rebuild it
    # just finished.
    attach_fn = function(
        ice_c,
        "ice_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)\n{",
        "\nstatic int\nice_detach",
    )
    rebuild_fn = function(
        ice_c, "ice_rebuild(ice_t *ice)\n{", "\nvoid\nice_reset_task")
    assert "ice_intr_oicr_setup(ice, B_TRUE)" in attach_fn
    assert "ice_intr_oicr_setup(ice, B_FALSE)" in rebuild_fn

    # PFINT_OICR has reset source CORER, so it survives the PF reset
    # ice_init_hw() issues: anything latched before this driver owned the
    # function must be dropped, or the harvest above reports it as ours.
    drain_at = attach_fn.index("(void) rd32(hw, PFINT_OICR);")
    assert attach_fn.index("ICE_ATTACH_HW_INIT") < drain_at
    assert drain_at < attach_fn.index("ice_ddp_load(ice)")

    print("PASS: ice fatal-cause OICR decode source invariants")


if __name__ == "__main__":
    main()
