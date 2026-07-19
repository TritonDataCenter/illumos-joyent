#!/usr/bin/env python3

"""Check ICE MAC filter add/remove construction invariants."""

from pathlib import Path


REPO = Path(__file__).resolve().parents[4]
GLD_SOURCE = REPO / "usr/src/uts/common/io/ice/ice_gld.c"
VSI_SOURCE = REPO / "usr/src/uts/common/io/ice/ice_vsi.c"


def function(source: str, signature: str, following: str) -> str:
    start = source.index(signature)
    end = source.index(following, start)
    return source[start:end]


def main() -> None:
    gld = GLD_SOURCE.read_text(encoding="utf-8")
    gld_init = function(
        gld,
        "ice_gld_fltr_init(struct ice_fltr_list_entry *e, uint16_t handle,",
        "\nstatic ice_mac_filter_t *",
    )
    assert "e->fltr_info.flag = ICE_FLTR_TX;" in gld_init

    # The filter construction lives in the _locked routine; the thin
    # ice_gld_set_mac wrapper brackets it in the outermost rebuild lock.
    gld_set = function(
        gld,
        "ice_gld_set_mac_locked(ice_t *ice, const uint8_t *addr, boolean_t add)\n{",
        "\n/*\n * ice_rebuild_lock is the outermost",
    )
    gld_construct = gld_set.index("ice_gld_fltr_init(&e,")
    assert gld_set.count("ice_gld_fltr_init(&e,") == 1
    assert gld_construct < gld_set.index("ice_add_mac(hw, &m_list)")
    assert gld_construct < gld_set.index("ice_remove_mac(hw, &m_list)")
    assert gld.count("ice_gld_fltr_init(") == 2

    vsi = VSI_SOURCE.read_text(encoding="utf-8")
    vsi_init = function(
        vsi,
        "ice_fltr_entry_init(struct ice_fltr_list_entry *e, uint16_t handle,",
        "\nstatic void\nice_mac_filter_track",
    )
    assert "e->fltr_info.flag = ICE_FLTR_TX;" in vsi_init

    vsi_add = function(
        vsi,
        "ice_add_mac_filters(ice_t *ice)\n{",
        "\nstatic int\nice_rss_setup",
    )
    assert vsi_add.count("ice_fltr_entry_init(") == 2
    assert vsi_add.index("ice_fltr_entry_init(") < vsi_add.index(
        "ice_add_mac(hw, &m_list)"
    )

    vsi_remove = function(
        vsi,
        "ice_vsi_teardown(ice_t *ice)\n{",
        "\n/*\n * Build the VSI context",
    )
    assert vsi_remove.count("ice_fltr_entry_init(") == 1
    assert vsi_remove.index("ice_fltr_entry_init(") < vsi_remove.index(
        "ice_remove_mac(hw, &rm)"
    )
    # Definition, teardown, the two attach filters, and the rebuild replay.
    assert vsi.count("ice_fltr_entry_init(") == 5


if __name__ == "__main__":
    main()
