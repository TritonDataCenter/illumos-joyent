#!/usr/bin/env python3

"""Check bounded jumbo receive and MTU plumbing in the ice driver."""

from pathlib import Path
import re


REPO = Path(__file__).resolve().parents[4]
HEADER = REPO / "usr/src/uts/common/io/ice/ice.h"
SOURCE = REPO / "usr/src/uts/common/io/ice/ice_rx.c"
ICE_SOURCE = REPO / "usr/src/uts/common/io/ice/ice.c"
GLD_SOURCE = REPO / "usr/src/uts/common/io/ice/ice_gld.c"


def function(source: str, signature: str, following: str) -> str:
    start = source.index(signature)
    end = source.index(following, start)
    return source[start:end]


def braced_block(source: str, start: int) -> str:
    opening = source.index("{", start)
    depth = 0
    for end in range(opening, len(source)):
        if source[end] == "{":
            depth += 1
        elif source[end] == "}":
            depth -= 1
            if depth == 0:
                return source[opening : end + 1]
    raise AssertionError("unterminated C block")


def main() -> None:
    header = HEADER.read_text(encoding="utf-8")
    source = SOURCE.read_text(encoding="utf-8")
    ice_source = ICE_SOURCE.read_text(encoding="utf-8")
    gld_source = GLD_SOURCE.read_text(encoding="utf-8")
    discard = function(
        source,
        "ice_rx_discard_frame(ice_rx_ring_t *irr, uint16_t nsegs)\n{",
        "\n/*\n * Validate one complete frame",
    )
    frame = function(
        source,
        "ice_ring_rx_frame(ice_rx_ring_t *irr, uint32_t *total_lenp,",
        "\n/*\n * Drain the rx ring",
    )
    rx_program = function(
        source,
        "ice_rx_ring_program(ice_t *ice, ice_rx_ring_t *irr)\n{",
        "\n/*\n * Disable an rx queue",
    )
    validate_caps = function(
        ice_source,
        "ice_validate_caps(ice_t *ice)\n{",
        "\nvoid\nice_update_mtu",
    )
    setprop = function(
        gld_source,
        "ice_m_setprop(void *arg, const char *pr_name, mac_prop_id_t pr_num,",
        "\nstatic int\nice_m_getprop",
    )
    mtu_setprop = braced_block(setprop, setprop.index("case MAC_PROP_MTU:"))
    propinfo = function(
        gld_source,
        "ice_m_propinfo(void *arg, const char *pr_name, mac_prop_id_t pr_num,",
        "\nstatic mac_callbacks_t ice_m_callbacks",
    )
    mtu_propinfo_start = propinfo.index("case MAC_PROP_MTU:")
    mtu_propinfo = propinfo[
        mtu_propinfo_start : propinfo.index("default:", mtu_propinfo_start)
    ]
    mac_register = function(
        gld_source,
        "ice_mac_register(ice_t *ice)\n{",
        "\n/*\n * Returns the mac_unregister() status",
    )

    max_mtu_expression = re.search(
        r"#define\s+ICE_MAX_MTU(?:\s|\\)*\(\s*"
        r"ICE_AQ_SET_MAC_FRAME_SIZE_MAX\s*-\s*"
        r"sizeof\s*\(struct ether_vlan_header\)\s*-\s*"
        r"(?:\\\s*)?ETHERFCSL\s*\)",
        header,
    )
    assert max_mtu_expression or re.search(
        r"#define\s+ICE_MAX_MTU\s+9706\b", header
    )
    assert re.search(
        r"#define\s+ICE_MAX_FRAME_SIZE\s+"
        r"ICE_AQ_SET_MAC_FRAME_SIZE_MAX\b",
        header,
    )
    assert "c->max_mtu > ICE_MAX_FRAME_SIZE" in validate_caps
    assert "c->max_mtu > ICE_MAX_MTU" not in validate_caps

    assert "rlan.rxmax = ice->ice_pf_vsi.vi_max_frame;" in rx_program
    assert "rlan.rxmax = MIN(" not in rx_program

    assert re.search(
        r"if\s*\(ice->ice_state\s*&\s*ICE_STATE_STARTED\)\s*"
        r"return\s*\(EBUSY\);",
        mtu_setprop,
    )
    assert "mac_maxsdu_update(ice->ice_mac_hdl, mtu)" in mtu_setprop
    assert re.search(
        r"mac_prop_info_set_range_uint32\s*\(prh,\s*ICE_MIN_MTU,\s*"
        r"ICE_MAX_MTU\s*\);",
        mtu_propinfo,
    )
    assert "MAC_PROP_PERM_READ" not in mtu_propinfo
    assert "mac->m_max_sdu = ice->ice_mtu;" in mac_register

    assert "ICE_RX_FLEX_DESC_STATUS0_EOF_S" in frame
    assert re.search(r"\btotal\s*\+=\s*seglen\s*;", frame)
    assert "*total_lenp = total;" in frame
    assert not re.search(r"\*total_lenp\s*=\s*seglen\s*;", frame)

    assert re.search(r"seglen\s*==\s*0", frame)
    assert re.search(r"seglen\s*>\s*irr->irxr_dbuf", frame)

    assert re.search(r"#define\s+ICE_RX_MAX_DESC\s+5\b", header)
    assert frame.count("ICE_RX_MAX_DESC") >= 3
    assert "total > ice->ice_pf_vsi.vi_max_frame" in frame

    eof = frame.index("ICE_RX_FLEX_DESC_STATUS0_EOF_S")
    eop_block = braced_block(frame, eof)
    assert "eop_status0 = status0;" in eop_block
    assert "desc->wb.ptype_flex_flags0" in eop_block
    assert frame.count("desc->wb.ptype_flex_flags0") == 1
    assert frame.count("ICE_RX_FLEX_DESC_STATUS0_RXE_S") == 1
    assert re.search(
        r"eop_status0\s*&\s*"
        r"BIT\(ICE_RX_FLEX_DESC_STATUS0_RXE_S\)",
        frame,
    )
    assert frame.count("ice_rx_hcksum(") == 1
    assemble = frame.index("/* Pass B:")
    segment_loop = frame.index("for (i = 0; i < nsegs; i++)", assemble)
    assert "ice_rx_hcksum(" not in braced_block(frame, segment_loop)
    assert frame.index("ice_rx_hcksum(") > segment_loop

    assert "ice_rx_reset_desc(irr, h, irr->irxr_rcbs[h])" in discard
    assert "h = ice_rx_next(irr, h);" in discard
    assert "irr->irxr_head = h;" in discard
    assert frame.count("ice_rx_discard_frame(irr, nsegs)") >= 2
    bad_path = braced_block(frame, frame.index("if (bad)"))
    assert "ice_rx_discard_frame(irr, nsegs)" in bad_path
    failure_path = frame[frame.index("assemble_fail:") :]
    assert "freemsg(mp_head)" in failure_path
    assert "ice_rx_discard_frame(irr, nsegs)" in failure_path
    assert re.search(
        r"if \(mp == NULL\)\s*goto assemble_fail;", frame
    )
    assert "mp_tail->b_cont = mp;" in frame


if __name__ == "__main__":
    main()
