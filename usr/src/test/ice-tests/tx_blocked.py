#!/usr/bin/env python3

"""Check the ice transmit back-pressure arm/wakeup source invariants."""

from pathlib import Path


REPO = Path(__file__).resolve().parents[4]
TX_SOURCE = REPO / "usr/src/uts/common/io/ice/ice_tx.c"


def function(source: str, signature: str, following: str) -> str:
    start = source.index(signature)
    end = source.index(following, start)
    return source[start:end]


def main() -> None:
    tx = TX_SOURCE.read_text(encoding="utf-8")

    one = function(
        tx,
        "ice_tx_one(ice_tx_ring_t *itr, mblk_t *mp)\n{",
        "\nmblk_t *\nice_ring_tx",
    )
    nores = one[
        one.index("if (res == ICE_TX_BUILD_NORES)"):
        one.index("if (res == ICE_TX_BUILD_DROP)")
    ]

    # blocked is armed under the ring lock ...
    enter = nores.index("mutex_enter(&itr->itxr_lock)")
    arm = nores.index("itr->itxr_blocked = B_TRUE")
    assert enter < arm

    # ... and reclaim is re-driven after arming, before dropping the lock
    recycle = nores.index("ice_tx_recycle(itr)")
    exit_ = nores.index("mutex_exit(&itr->itxr_lock)")
    assert arm < recycle < exit_

    # the caller still keeps the chain for MAC to retry
    assert "return (B_FALSE);" in nores

    # the sibling arm path still recycles before arming
    sibling = one[one.index("if (itr->itxr_avail <= ndesc)"):]
    assert sibling.index("ice_tx_recycle(itr)") < sibling.index(
        "itr->itxr_blocked = B_TRUE")

    # recycle still owns the wakeup in both of its exits
    rec = function(
        tx,
        "ice_tx_recycle(ice_tx_ring_t *itr)\n{",
        "\nstatic boolean_t\nice_tx_one",
    )
    assert rec.count("mac_tx_ring_update(") == 2
    assert rec.count("itr->itxr_blocked = B_FALSE") == 2
    assert "ASSERT(MUTEX_HELD(&itr->itxr_lock));" in rec

    print("PASS: ice tx back-pressure source invariants")


if __name__ == "__main__":
    main()
