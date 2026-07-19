#!/usr/bin/env python3

"""Check ordering and error coverage in the ice receive checksum path."""

from pathlib import Path
import re


REPO = Path(__file__).resolve().parents[4]
SOURCE = REPO / "usr/src/uts/common/io/ice/ice_rx.c"


def function(source: str, signature: str, following: str) -> str:
    start = source.index(signature)
    end = source.index(following, start)
    return source[start:end]


def main() -> None:
    source = SOURCE.read_text(encoding="utf-8")
    frame = function(
        source,
        "ice_ring_rx_frame(ice_rx_ring_t *irr, uint32_t *total_lenp,",
        "\n/*\n * Drain the rx ring",
    )
    checksum = function(
        source,
        "ice_rx_hcksum(ice_rx_ring_t *irr, mblk_t *mp, uint16_t status0,",
        "\n/*\n * Re-post every descriptor",
    )

    snapshot = frame.index("desc->wb.ptype_flex_flags0")
    assert frame.count("desc->wb.ptype_flex_flags0") == 1
    assert snapshot < frame.index("ice_rx_bind(irr, h")
    assert snapshot < frame.index("ice_rx_reset_desc(irr, h")

    compact = re.sub(r"\s+", "", checksum)
    assert (
        "BIT(ICE_RX_FLEX_DESC_STATUS0_XSUM_IPE_S)|"
        "BIT(ICE_RX_FLEX_DESC_STATUS0_XSUM_EIPE_S)" in compact
    )
    assert (
        "BIT(ICE_RX_FLEX_DESC_STATUS0_XSUM_L4E_S)|"
        "BIT(ICE_RX_FLEX_DESC_STATUS0_XSUM_EUDPE_S)" in compact
    )


if __name__ == "__main__":
    main()
