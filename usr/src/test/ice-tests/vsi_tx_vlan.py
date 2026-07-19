#!/usr/bin/env python3

"""Check the PF data VSI transmit VLAN admission invariants."""

from pathlib import Path


REPO = Path(__file__).resolve().parents[4]
VSI_SOURCE = REPO / "usr/src/uts/common/io/ice/ice_vsi.c"


def function(source: str, signature: str, following: str) -> str:
    start = source.index(signature)
    end = source.index(following, start)
    return source[start:end]


def main() -> None:
    source = VSI_SOURCE.read_text(encoding="utf-8")
    body = function(
        source,
        "ice_vsi_ctx_fill(ice_t *ice, struct ice_vsi_ctx *ctx)\n{",
        "\n/*\n * Permit or reject local loopback",
    )

    assert "inner_vlan_flags" in body
    assert "ICE_AQ_VSI_INNER_VLAN_TX_MODE_ALL" in body
    assert "ICE_AQ_VSI_PROP_VLAN_VALID" in body

    print("PASS: PF data VSI transmit VLAN admission is configured")


if __name__ == "__main__":
    main()
