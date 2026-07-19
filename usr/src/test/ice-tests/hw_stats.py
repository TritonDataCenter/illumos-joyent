#!/usr/bin/env python3

"""Check ICE hardware statistics wiring and read serialization."""

from pathlib import Path


REPO = Path(__file__).resolve().parents[4]
ATTACH_SOURCE = REPO / "usr/src/uts/common/io/ice/ice.c"
GLD_SOURCE = REPO / "usr/src/uts/common/io/ice/ice_gld.c"
STATS_SOURCE = REPO / "usr/src/uts/common/io/ice/ice_stats.c"
RX_SOURCE = REPO / "usr/src/uts/common/io/ice/ice_rx.c"
MAKEFILE = REPO / "usr/src/uts/common/Makefile.files"


def function(source: str, signature: str, following: str) -> str:
    start = source.index(signature)
    end = source.index(following, start)
    return source[start:end]


def main() -> None:
    stats = STATS_SOURCE.read_text(encoding="utf-8")

    # Both refresh routines must run under the shared stat lock.
    for name, following in (
        ("ice_stats_update_port(ice_t *ice)\n{", "\nvoid\nice_stats_update_vsi"),
        ("ice_stats_update_vsi(ice_t *ice)\n{", "\nstatic void\nice_stats_check_acc"),
    ):
        body = function(stats, name, following)
        assert "ASSERT(MUTEX_HELD(&ice->ice_stat_lock))" in body

    # The VSI clear-on-read register is serviced through the common code.
    vsi = function(
        stats,
        "ice_stats_update_vsi(ice_t *ice)\n{",
        "\nstatic void\nice_stats_check_acc",
    )
    assert "ice_stat_update_repc(hw, handle, loaded, cur)" in vsi

    # kstat update callbacks take the lock and refuse writes.
    for name, following in (
        ("ice_pf_kstat_update(kstat_t *ksp, int rw)\n{", "\nstatic int\nice_vsi_kstat_update"),
        ("ice_vsi_kstat_update(kstat_t *ksp, int rw)\n{", "\nstatic boolean_t\nice_pf_kstat_init"),
    ):
        body = function(stats, name, following)
        assert "if (rw == KSTAT_WRITE)" in body
        assert "return (EACCES)" in body
        assert "mutex_enter(&ice->ice_stat_lock)" in body

    # Capture both baselines under the lock before kstat_install can expose a
    # reader.  This also clears GLV_REPC at attach rather than first use.
    init = function(stats, "ice_stats_init(ice_t *ice)\n{", "\nvoid\nice_stats_fini")
    lock = init.index("mutex_enter(&ice->ice_stat_lock)")
    port = init.index("ice_stats_update_port(ice)", lock)
    vsi = init.index("ice_stats_update_vsi(ice)", port)
    unlock = init.index("mutex_exit(&ice->ice_stat_lock)", vsi)
    check = init.index("ice_stats_check_acc(ice)", unlock)
    install = init.index("ice_pf_kstat_init(ice)", check)
    assert lock < port < vsi < unlock < check < install

    # Teardown deletes kstats before destroying the lock they take.
    fini = stats[stats.index("ice_stats_fini(ice_t *ice)\n{"):]
    delete = fini.index("kstat_delete(ice->ice_pf_kstat)")
    destroy = fini.index("mutex_destroy(&ice->ice_stat_lock)")
    assert delete < destroy

    # Attach installs stats before MAC; detach removes them before the
    # register mapping is torn down.
    attach = ATTACH_SOURCE.read_text(encoding="utf-8")
    a = function(
        attach,
        "ice_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)\n{",
        "\nstatic int\nice_detach",
    )
    assert a.index("ice_stats_init(ice)") < a.index("ice_mac_register(ice)")

    unconf = function(attach, "ice_unconfigure(ice_t *ice)\n{", "\nstatic int\nice_detach")
    assert unconf.index("ice_stats_fini(ice)") < unconf.index(
        "ddi_regs_map_free(&ice->ice_osdep.ios_reg_handle)"
    )

    # The MAC stat entry point refreshes port counters under the stat lock.
    gld = GLD_SOURCE.read_text(encoding="utf-8")
    mstat = function(gld, "ice_m_stat(void *arg, uint_t stat, uint64_t *val)\n{", "\n/*")
    assert "ice_stats_update_port(ice)" in mstat
    assert "mutex_enter(&ice->ice_stat_lock)" in mstat
    locked = mstat[mstat.index("mutex_enter(&ice->ice_stat_lock)") :]
    assert locked.index("switch (stat)") < locked.index("ice_stats_update_port(ice)")
    assert locked.count("ice_stats_update_port(ice)") == 14
    assert locked.rindex("ice_stats_update_port(ice)") < locked.index("default:")
    unlock = mstat.index("mutex_exit(&ice->ice_stat_lock)", mstat.index("mutex_enter"))
    acc = mstat.index("ice_check_acc_handle", unlock)
    degraded = mstat.index("DDI_SERVICE_DEGRADED", acc)
    io_error = mstat.index("return (EIO)", degraded)
    assert unlock < acc < degraded < io_error
    for stat in ("MAC_STAT_RBYTES", "MAC_STAT_IPACKETS", "MAC_STAT_OBYTES",
                 "MAC_STAT_OPACKETS", "MAC_STAT_IERRORS"):
        assert stat in mstat

    # A MAC kstat snapshot invokes m_stat once per field.  Bound those calls to
    # one hardware refresh window and do not read registers for unsupported
    # fields.
    port_update = function(
        stats,
        "ice_stats_update_port(ice_t *ice)\n{",
        "\nvoid\nice_stats_update_vsi",
    )
    assert "ICE_STATS_MIN_UPDATE_NS" in stats
    assert "ice_stat_port_last_update" in port_update
    assert "now - ice->ice_stat_port_last_update" in port_update

    # The new object is built.
    assert "ice_stats.o" in MAKEFILE.read_text(encoding="utf-8")

    # Per-ring rx counters are published as named kstats (mirroring tx_ring_*)
    # and torn down with the ring.
    rx = RX_SOURCE.read_text(encoding="utf-8")
    init = function(rx, "ice_rx_kstat_init(ice_t *ice, ice_rx_ring_t *irr)\n{",
        "\nstatic boolean_t\nice_rx_ring_alloc")
    assert '"rx_ring_%u"' in init
    assert "kstat_install(irr->irxr_kstat)" in init
    for field in ("rx_bytes", "rx_packets", "rx_desc_error", "rx_no_rcb"):
        assert '"' + field + '"' in init, field
    free = function(rx, "ice_rx_ring_free(ice_rx_ring_t *irr)\n{",
        "\nstatic boolean_t\nice_rx_kstat_init")
    assert "kstat_delete(irr->irxr_kstat)" in free


if __name__ == "__main__":
    main()
