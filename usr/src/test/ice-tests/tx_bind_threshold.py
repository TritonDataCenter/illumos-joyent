#!/usr/bin/env python3

"""Check the ice transmit bind-versus-copy source invariants."""

from pathlib import Path


REPO = Path(__file__).resolve().parents[4]
ICE_HEADER = REPO / "usr/src/uts/common/io/ice/ice.h"
TX_SOURCE = REPO / "usr/src/uts/common/io/ice/ice_tx.c"


def function(source: str, signature: str, following: str) -> str:
    start = source.index(signature)
    end = source.index(following, start)
    return source[start:end]


def main() -> None:
    header = ICE_HEADER.read_text(encoding="utf-8")
    assert "#define\tICE_TX_SMALL_PKT\t512" in header

    tx = TX_SOURCE.read_text(encoding="utf-8")
    build = function(
        tx,
        "ice_tx_build_tcbs(ice_tx_ring_t *itr, mblk_t *mp, size_t msglen,",
        "\nstatic void\nice_tx_free_tcbs",
    )

    # a whole small packet is copied before any fragment is bound
    short_circuit = build.index("msglen <= ICE_TX_SMALL_PKT")
    bind = build.index("ice_tx_bind_fragment(")
    assert short_circuit < bind
    assert build.index("ice_tx_copy_packet(") < bind

    # an undeliverable frame is not retried through the bind loop
    assert "if (res == ICE_TX_BUILD_DROP)" in build
    assert build.index("if (res == ICE_TX_BUILD_DROP)") < bind

    # the short-circuit only claims one descriptor for one TCB
    head = build[short_circuit:bind]
    assert "*ntcbp = 1;" in head
    assert "*ndescp = 1;" in head

    # bind failure still degrades to a full copy rather than dropping
    assert "goto force_copy;" in build[bind:]
    assert "force_copy:" in build
    assert build.index("ndesc + ncookies > ICE_TX_MAX_COOKIE") > bind

    print("PASS: ice tx bind/copy source invariants")


if __name__ == "__main__":
    main()
