#!/usr/bin/env python3

"""Check that an rx ring cannot be started twice.

MAC drives the per-ring mr_start callbacks from mac_start_group_and_rings()
after ice_m_start() has already returned and dropped ice_rebuild_lock.  A reset
taskq acquiring the lock in that window sees ICE_STATE_STARTED and runs
ice_rx_rings_resume(), which posts every ring itself.  MAC's mr_state guard
never sees that start, so the driver's own guard has to be authoritative.
"""

from pathlib import Path


REPO = Path(__file__).resolve().parents[4]
RX = REPO / "usr/src/uts/common/io/ice/ice_rx.c"
HEADER = REPO / "usr/src/uts/common/io/ice/ice.h"


def function(source: str, signature: str, following: str) -> str:
    start = source.index(signature)
    end = source.index(following, start)
    return source[start:end]


def main() -> None:
    rx = RX.read_text(encoding="utf-8")
    header = HEADER.read_text(encoding="utf-8")

    # The open flag exists and declares what protects it.  It is deliberately
    # not an overload of irxr_shutdown: that is zero-initialised, so a
    # never-started ring already reads as "not shut down", and ice_rx_quiesce()
    # sets it on rings whose pools it does not free, so B_TRUE does not imply
    # postable either.
    member = [l for l in header.splitlines() if "irxr_started;" in l]
    assert len(member) == 1
    assert "/* irxr_lock */" in member[0]

    opened = function(
        rx,
        "ice_rx_ring_open_locked(ice_rx_ring_t *irr)\n{",
        "\nint\nice_ring_rx_start",
    )
    assert "ASSERT(MUTEX_HELD(&irr->irxr_lock))" in opened
    # The idempotent guard precedes any posting: whichever of mr_start and the
    # rebuild arrives second is a no-op, not a second pass over the ring.
    assert "if (irr->irxr_started)" in opened
    assert opened.index("if (irr->irxr_started)") < opened.index(
        "ice_rx_setup_bufs"
    )
    # ...and the pool precondition is CHECKED, not assumed.  The guard alone
    # does not cover a ring whose pool ice_rx_quiesce()/ice_rx_reclaim() left
    # freed or partly loaned, which a pending mr_start still reaches.
    assert "ice_rx_ring_postable(irr)" in opened
    assert opened.index("ice_rx_ring_postable") < opened.index(
        "ice_rx_setup_bufs"
    )
    assert "return (EIO)" in opened
    # Both halves of the precondition: a pool that exists, with nothing posted
    # or loaned out of it.  nfree >= size would admit a partly posted ring.
    postable = function(
        rx,
        "ice_rx_ring_postable(ice_rx_ring_t *irr)\n{",
        "\nstatic int\nice_rx_ring_open_locked",
    )
    assert "irxr_rcb_area != NULL" in postable
    assert "irxr_nfree == irr->irxr_nrcb" in postable

    # The generation number is recorded before the guard can short-circuit.
    # mac_stop_ring() bumps mr_gen_num and mac_rx_ring() frees any chain that
    # does not match, so a start the rebuild already satisfied must still
    # refresh it -- otherwise the ring reports link up and receives nothing,
    # which is a far worse failure than the panic this replaces.
    entry = function(
        rx,
        "ice_ring_rx_start(mac_ring_driver_t rh, uint64_t gen_num)\n{",
        "\n/*\n * mac(9E) ring stop",
    )
    assert entry.index("irxr_rxgen = gen_num") < entry.index(
        "ice_rx_ring_open_locked"
    )
    # A refused start is reported rather than asserted: MAC unwinds mr_start
    # without calling mi_stop, so ICE_STATE_STARTED stays set with no other
    # visible cause.
    assert "ICE_STATE_ERROR" in entry

    # The rebuild reuses whatever generation the ring already holds.  Reading
    # irxr_rxgen outside irxr_lock and feeding it back in was the old shape.
    resume = rx[rx.index("ice_rx_rings_resume(ice_t *ice)\n{"):]
    assert "ice_rx_ring_open_locked(irr)" in resume
    assert "irxr_rxgen" not in resume
    assert "ice_ring_rx_start" not in resume

    # Every close-or-destroy path clears the flag.
    stop = function(
        rx,
        "ice_ring_rx_stop(mac_ring_driver_t rh)\n{",
        "\nint\nice_ring_rx_stat",
    )
    assert "irxr_started = B_FALSE" in stop

    quiesce = function(
        rx,
        "ice_rx_quiesce(ice_t *ice)\n{",
        "\nvoid\nice_rx_reclaim",
    )
    # Cleared once, in the closing pass, so it covers the rings that drain and
    # the rings that time out alike.
    assert quiesce.count("irxr_started = B_FALSE") == 1
    assert quiesce.index("irxr_started = B_FALSE") < quiesce.index(
        "cv_timedwait"
    )

    # The clear lives in the pool destructor rather than at each call site, so
    # "no pool implies not started" holds for the realloc inside ice_rx_start()
    # and its unwind path too.  Without this the rebuild would no-op on a ring
    # whose pool it had just reallocated and leave hardware an empty ring.
    freercb = function(
        rx,
        "ice_rx_free_rcbs(ice_rx_ring_t *irr)\n{",
        "\n/*\n * Fill every",
    )
    assert "irxr_started = B_FALSE" in freercb

    # Those four bodies are the only places the flag is touched.  A fifth site
    # is not necessarily wrong, but it has to be reviewed for lock coverage and
    # for whether it breaks "no pool implies not started", so it trips here.
    assert rx.count("irxr_started") == (
        opened.count("irxr_started")
        + stop.count("irxr_started")
        + quiesce.count("irxr_started")
        + freercb.count("irxr_started")
    )

    # Reachability of the contract: ice_rx_setup_bufs() has exactly one caller,
    # and that caller checks ice_rx_ring_postable() first, so the assertion
    # below is unreachable by construction.  That is the whole claim.
    assert rx.count("ice_rx_setup_bufs(irr)") == 1
    setup = function(
        rx,
        "ice_rx_setup_bufs(ice_rx_ring_t *irr)\n{",
        "\n/*\n * Advance a ring index",
    )
    assert "ASSERT3P(rcb, !=, NULL)" in setup

    print("PASS: ice rx rings cannot be double started")


if __name__ == "__main__":
    main()
