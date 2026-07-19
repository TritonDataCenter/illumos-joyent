#!/usr/bin/env python3

"""Check ICE PHY advertisement and GLDv3 link capabilities."""

from pathlib import Path


REPO = Path(__file__).resolve().parents[4]
ATTACH_SOURCE = REPO / "usr/src/uts/common/io/ice/ice.c"
HEADER = REPO / "usr/src/uts/common/io/ice/ice.h"
INTR_SOURCE = REPO / "usr/src/uts/common/io/ice/ice_intr.c"
GLD_SOURCE = REPO / "usr/src/uts/common/io/ice/ice_gld.c"


def function(source: str, signature: str, following: str) -> str:
    start = source.index(signature)
    end = source.index(following, start)
    return source[start:end]


def main() -> None:
    intr = INTR_SOURCE.read_text(encoding="utf-8")
    setup = function(
        intr,
        "ice_setup_link(ice_t *ice)\n{",
        "\n/*\n * Ask firmware to deliver link and media events",
    )
    assert "ice_fw_supports_report_dflt_cfg" in setup
    assert (
        "ICE_AQC_REPORT_DFLT_CFG" in setup
        or "ICE_AQC_REPORT_TOPO_CAP_MEDIA" in setup
    )
    assert "ice_cfg_phy_fec" in setup
    assert "ICE_AQC_REPORT_ACTIVE_CFG" not in setup

    oicr = function(
        intr,
        "ice_oicr_task(void *arg)\n{",
        "\nstatic void\nice_intr_oicr_enable",
    )
    assert "media_inserted" in oicr
    assert "ice_setup_link(ice)" in oicr
    assert "ice_phy_caps_update(ice)" in oicr
    assert "ice_update_phy_type" in intr

    attach_source = ATTACH_SOURCE.read_text(encoding="utf-8")
    attach = function(
        attach_source,
        "ice_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)\n{",
        "\nstatic int\nice_detach",
    )
    setup_at = attach.index("ice_setup_link(ice)")
    refresh_at = attach.index("ice_phy_caps_update(ice)", setup_at)
    assert setup_at < refresh_at

    gld = GLD_SOURCE.read_text(encoding="utf-8")
    mstat = function(
        gld,
        "ice_m_stat(void *arg, uint_t stat, uint64_t *val)\n{",
        "\n/*\n * SFF module",
    )
    for rate in ("25G", "40G", "100G"):
        assert f"ETHER_STAT_CAP_{rate}FDX" in mstat
        assert f"ETHER_STAT_ADV_CAP_{rate}FDX" in mstat
    assert "ice->ice_phy_speeds_adv & speed" in mstat
    assert "ice->ice_phy_speeds_supp & speed" in mstat

    getprop = function(
        gld,
        "ice_m_getprop(void *arg, const char *pr_name, mac_prop_id_t pr_num,",
        "\nstatic void\nice_m_propinfo",
    )
    assert "MAC_PROP_ADV_40GFDX_CAP" in getprop
    assert "advertised = pr_num == MAC_PROP_ADV_40GFDX_CAP" in getprop
    assert "ice->ice_phy_speeds_adv &" in getprop
    assert "ice->ice_phy_speeds_supp &" in getprop
    adv_fec = function(
        getprop,
        "case MAC_PROP_ADV_FEC_CAP:",
        "\tcase MAC_PROP_EN_FEC_CAP:",
    )
    assert "ice->ice_fec_neg" in adv_fec
    en_fec = function(
        getprop,
        "case MAC_PROP_EN_FEC_CAP:",
        "\tcase MAC_PROP_FLOWCTRL:",
    )
    assert "LINK_FEC_AUTO" in en_fec

    propinfo = function(
        gld,
        "ice_m_propinfo(void *arg, const char *pr_name, mac_prop_id_t pr_num,",
        "\nstatic mac_callbacks_t",
    )
    autoneg = propinfo.index("case MAC_PROP_AUTONEG:")
    autoneg_default = propinfo.index(
        "mac_prop_info_set_default_uint8(prh, 1)", autoneg
    )
    assert autoneg < autoneg_default
    assert "mac_prop_info_set_default_fec" in propinfo
    assert "ice->ice_phy_speeds_adv & phy_speed" in propinfo
    assert "ice->ice_phy_speeds_supp & phy_speed" in propinfo

    header = HEADER.read_text(encoding="utf-8")
    assert "ice_phy_speeds_supp" in header
    assert "ice_phy_speeds_adv" in header
    assert "ice_fec_neg" in header


if __name__ == "__main__":
    main()
