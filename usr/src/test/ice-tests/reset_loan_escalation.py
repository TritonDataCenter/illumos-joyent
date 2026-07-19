#!/usr/bin/env python3

"""Check that an undrained rx loan cannot take the NIC terminally offline.

A loan is held by the stack, not by the driver: a reassembly queue or a stopped
process's socket buffer holds one for as long as it likes with no driver bug.
Escalating that to ICE_STATE_RESET_FAILED means a routine reset under load
permanently kills the interface until the driver is reloaded.  FreeBSD's
ice_prepare_for_reset() returns void and all three of its RESET_FAILED sites are
hardware or firmware failures (if_ice_iflib.c:2848, :2898, :2952).
"""

from pathlib import Path


REPO = Path(__file__).resolve().parents[4]
ICE = REPO / "usr/src/uts/common/io/ice/ice.c"
RX = REPO / "usr/src/uts/common/io/ice/ice_rx.c"


def function(source: str, signature: str, following: str) -> str:
    start = source.index(signature)
    end = source.index(following, start)
    return source[start:end]


def main() -> None:
    ice = ICE.read_text(encoding="utf-8")
    rx = RX.read_text(encoding="utf-8")

    # The prepare has no failure path at all.
    assert "static void\nice_prepare_for_reset(ice_t *ice)" in ice
    assert "static boolean_t\nice_prepare_for_reset" not in ice
    prepare = function(
        ice,
        "ice_prepare_for_reset(ice_t *ice)\n{",
        "\nstatic void\nice_rebuild",
    )
    assert "(void) ice_rx_quiesce(ice)" in prepare
    assert "boolean_t drained" not in prepare
    assert "return (drained)" not in prepare

    # The worker always proceeds into the rebuild.
    task = function(ice, "ice_reset_task(void *arg)\n{", "\n#ifdef DEBUG")
    assert "ice_reset_set_failed" not in task
    assert "if (!ice_prepare_for_reset" not in task
    assert "ice_prepare_for_reset(ice);" in task
    assert task.index("ice_prepare_for_reset(ice);") < task.index(
        "ice_rebuild(ice)"
    )

    # The terminal state has exactly one source: the rebuild's hardware and
    # firmware failure label.  (The definition line does not match this form.)
    assert ice.count("ice_reset_set_failed(ice)") == 1
    rebuild = function(ice, "ice_rebuild(ice_t *ice)\n{", "\nvoid\nice_reset_task")
    assert "ice_reset_set_failed(ice)" in rebuild[rebuild.index("reset_failed:"):]

    # Dropping the escalation is only safe because the soft path is already
    # enforced downstream, by code this change does not touch: ice_rx_reclaim()
    # will not free a ring that still has loans, and ice_rx_start() refuses to
    # reuse or reallocate that surviving pool, so the rebuild fails at
    # ice_start_datapath() and lands on the recoverable ICE_STATE_ERROR branch.
    reclaim = function(
        rx, "ice_rx_reclaim(ice_t *ice)\n{", "\nboolean_t\nice_rx_stop")
    assert "irxr_nloaned == 0" in reclaim
    start = function(
        rx, "ice_rx_start(ice_t *ice)\n{", "\n/*\n * Tear down every rx ring")
    assert start.index("irxr_nloaned > 0") < start.index("ice_rx_alloc_rcbs")
    assert "ice_start_datapath(ice)" in rebuild
    soft = rebuild[rebuild.index("ice_start_datapath(ice)"):]
    assert "ICE_STATE_ERROR" in soft
    assert soft.index("ICE_STATE_ERROR") < soft.index("reset_failed:")

    # ...and ICE_STATE_ERROR is recoverable: it is not in ice_m_start()'s
    # blocked mask, and a replumb clears it.  That is the recovery story the
    # terminal path did not have.
    gld = (REPO / "usr/src/uts/common/io/ice/ice_gld.c").read_text(
        encoding="utf-8")
    m_start = function(gld, "ice_m_start(void *arg)\n{", "\nstatic void\nice_m_stop")
    blocked = m_start[m_start.index("blocked ="):m_start.index(";", m_start.index("blocked ="))]
    assert "ICE_STATE_ERROR" not in blocked
    assert "~ICE_STATE_ERROR" in m_start

    print("PASS: rx loans never escalate a reset to terminal failure")


if __name__ == "__main__":
    main()
