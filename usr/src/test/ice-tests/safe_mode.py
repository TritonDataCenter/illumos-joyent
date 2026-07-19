#!/usr/bin/env python3

"""Check that safe mode withholds the hardware offload capabilities."""

from pathlib import Path


REPO = Path(__file__).resolve().parents[4]
GLUE_DIR = REPO / "usr/src/uts/common/io/ice"
GLD_SOURCE = GLUE_DIR / "ice_gld.c"
DDP_SOURCE = GLUE_DIR / "ice_ddp.c"
ICE_SOURCE = GLUE_DIR / "ice.c"


def function(source: str, signature: str, following: str) -> str:
    start = source.index(signature)
    end = source.index(following, start)
    return source[start:end]


def main() -> None:
    ddp = DDP_SOURCE.read_text(encoding="utf-8")
    assert "ice->ice_safe_mode = B_TRUE" in ddp

    gld = GLD_SOURCE.read_text(encoding="utf-8")

    hck = function(
        gld,
        "case MAC_CAPAB_HCKSUM: {",
        "case MAC_CAPAB_TRANSCEIVER:",
    )
    assert "ice->ice_safe_mode" in hck
    # The capability must be refused outright, not advertised with no flags.
    assert "return (B_FALSE)" in hck
    # The guard must precede the assignment, not follow it.
    assert hck.index("ice->ice_safe_mode") < hck.index(
        "*txflags = HCKSUM_INET_PARTIAL")

    lso = function(gld, "case MAC_CAPAB_LSO: {", "\n\tdefault:")
    assert "ice->ice_safe_mode" in lso
    assert lso.index("ice->ice_safe_mode") < lso.index("LSO_TX_BASIC_TCP_IPV4")

    # The rx half: without the DDP package the descriptor status bits carry no
    # checksum verdict, so ice_rx_hcksum() must not report a verified checksum.
    rx = (REPO / "usr/src/uts/common/io/ice/ice_rx.c").read_text(encoding="utf-8")
    hck = function(
        rx,
        "ice_rx_hcksum(ice_rx_ring_t *irr, mblk_t *mp, uint16_t status0,",
        "\nstatic mblk_t *",
    )
    assert "irr->irxr_ice->ice_safe_mode" in hck
    assert hck.index("irr->irxr_ice->ice_safe_mode") < hck.index("HCK_IPV4_HDRCKSUM_OK")

    # Safe mode is a MAC-contract decision, not a hardware fact: it must be
    # made before mac_register() caches mi_capab.  A mid-life transition cannot
    # withdraw the TX offloads the stack is already using, so the rebuild must
    # not attempt one.
    ice = ICE_SOURCE.read_text(encoding="utf-8")
    rebuild = function(ice, "ice_rebuild(ice_t *ice)\n{", "\nvoid\nice_reset_task")
    assert "ice_set_safe_mode_caps" not in rebuild
    assert "ice_safe_mode = B_TRUE" not in rebuild
    assert "ice_ddp_load" not in rebuild

    # A failed DDP reload must reach the terminal path rather than fall
    # through and keep serving traffic with no parser profiles.
    ddp_replay = function(
        rebuild, "if (!ice->ice_safe_mode)", "if (ice_vsi_rebuild(ice)")
    assert "ice_is_init_pkg_successful" in ddp_replay
    assert "goto reset_failed" in ddp_replay
    # A missing package copy must not silently skip the reload either.
    assert "hw->pkg_copy == NULL" in ddp_replay

    # Exactly one writer of the flag, and it is the attach-only DDP path.
    writers = sorted(p.name for p in GLUE_DIR.glob("*.c")
                     if "ice_safe_mode = " in p.read_text(encoding="utf-8"))
    assert writers == ["ice_ddp.c"], writers

    # If a mid-life transition is ever reintroduced, it must also renegotiate
    # with MAC -- which mac_capab_update() explicitly cannot do safely.
    assert ("ice_safe_mode = " not in ice) or ("mac_capab_update" in ice)

    print("PASS: ice safe mode offload invariants")


if __name__ == "__main__":
    main()
