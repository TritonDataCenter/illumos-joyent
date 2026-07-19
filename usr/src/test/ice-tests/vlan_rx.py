#!/usr/bin/env python3

"""Check that the ice receive path reinserts a hardware-stripped VLAN tag."""

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
    insert = function(
        source,
        "ice_rx_vlan_insert(mblk_t *mp, mblk_t *vmp, uint16_t tci)\n{",
        "\n/*\n * Validate one complete frame",
    )

    # The tag and its status bit must both be consumed.
    tag = frame.index("desc->wb.l2tag1")
    assert frame.count("desc->wb.l2tag1") == 1
    assert "ICE_RX_FLEX_DESC_STATUS0_L2TAG1P_S" in frame

    # Writeback fields are only trusted after the consumer barrier.
    assert frame.index("membar_consumer()") < tag

    # The donated ether header is bounds-checked before b_rptr advances.
    check = frame.index("seglens[0] < sizeof (struct ether_header)")
    assert check < frame.index("ice_rx_vlan_insert(")
    assert "mp->b_rptr += sizeof (struct ether_header)" in insert
    assert insert.index("bcopy(mp->b_rptr") < insert.index("mp->b_rptr +=")

    # mac_strip_vlan_tag() asserts the head holds a full tagged ether header,
    # so the original ethertype has to be carried up into it.
    assert "2 * ETHERADDRL + VLAN_TAGSZ" not in frame
    assert "mp->b_rptr += 2 * ETHERADDRL" not in insert
    assert "bcopy(mp->b_rptr + 2 * ETHERADDRL, p, sizeof (uint16_t))" in insert
    assert "ASSERT3U(MBLKL(mp), >=, sizeof (struct ether_header))" in insert
    assert (
        "ASSERT3U(MBLKL(vmp), >=, sizeof (struct ether_vlan_header))" in insert
    )

    # An emptied head is freed rather than left in the chain.
    empty = insert.index("if (MBLKL(mp) == 0)")
    assert insert.index("mp->b_rptr +=") < empty
    assert "vmp->b_cont = mp->b_cont;" in insert
    assert "freeb(mp);" in insert

    # A failed tag-header allocation drops the frame instead of delivering it.
    alloc = frame.index("allocb(sizeof (struct ether_vlan_header)")
    nomem = frame.index("icrxs_copy_nomem", alloc)
    assert frame.index("ice_rx_discard_frame", alloc) < nomem
    assert alloc < frame.index("Pass B")

    # Checksum metadata lands on the head mac actually receives.
    assert frame.index("ice_rx_vlan_insert(") < frame.index("ice_rx_hcksum(")

    # The 802.1Q header is emitted in network byte order.
    compact = re.sub(r"\s+", "", insert)
    assert "*p++=(ETHERTYPE_VLAN>>8)&0xff;*p++=ETHERTYPE_VLAN&0xff;" in compact
    assert "*p++=(tci>>8)&0xff;*p++=tci&0xff;" in compact


if __name__ == "__main__":
    main()
