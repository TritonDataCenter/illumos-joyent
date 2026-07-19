#!/usr/bin/env python3

"""Check ICE internal MAC loopback control and isolation invariants."""

import re
from pathlib import Path


REPO = Path(__file__).resolve().parents[4]
ATTACH_SOURCE = REPO / "usr/src/uts/common/io/ice/ice.c"
GLD_SOURCE = REPO / "usr/src/uts/common/io/ice/ice_gld.c"
VSI_SOURCE = REPO / "usr/src/uts/common/io/ice/ice_vsi.c"
INTR_SOURCE = REPO / "usr/src/uts/common/io/ice/ice_intr.c"
RX_SOURCE = REPO / "usr/src/uts/common/io/ice/ice_rx.c"
TX_SOURCE = REPO / "usr/src/uts/common/io/ice/ice_tx.c"
TOOL_SOURCE = REPO / "usr/src/test/ice-tests/ice_loopback.c"


def function(source: str, signature: str, following: str) -> str:
    start = source.index(signature)
    end = source.index(following, start)
    return source[start:end]


def main() -> None:
    gld = GLD_SOURCE.read_text(encoding="utf-8")
    assert "#include <sys/stream.h>" in gld
    assert "#include <sys/strsun.h>" in gld
    assert "MC_IOCTL | MC_GETCAPAB" in gld
    assert ".mc_ioctl = ice_m_ioctl" in gld
    for command in ("LB_GET_INFO_SIZE", "LB_GET_INFO", "LB_GET_MODE", "LB_SET_MODE"):
        assert command in gld

    ioctl = function(
        gld,
        "ice_m_ioctl(void *arg, queue_t *q, mblk_t *mp)\n{",
        "\n/*\n * MAC callbacks.",
    )
    set_mode = ioctl[ioctl.index("case LB_SET_MODE:") : ioctl.index("default:")]
    privilege = set_mode.index("secpolicy_net_config(iocp->ioc_cr, B_FALSE)")
    payload = set_mode.index("ice_loopback_payload", privilege)
    transition = set_mode.index("ice_loopback_mode_set", payload)
    assert privilege < payload < transition

    enable = function(
        gld,
        "ice_loopback_enable(ice_t *ice)\n{",
        "\nstatic int\nice_loopback_disable",
    )
    permit = enable.index("ice_vsi_loopback_set(ice, B_TRUE)")
    mac_enable = enable.index("ice_aq_set_mac_loopback", permit)
    rollback = enable.index("ice_vsi_loopback_set(ice, B_FALSE)", mac_enable)
    assert permit < mac_enable < rollback

    disable = function(
        gld,
        "ice_loopback_disable(ice_t *ice)\n{",
        "\nstatic int\nice_loopback_mode_set",
    )
    mac_disable = disable.index("ice_aq_set_mac_loopback")
    revoke = disable.index("ice_vsi_loopback_set(ice, B_FALSE)", mac_disable)
    rollback = disable.index("ice_aq_set_mac_loopback", revoke)
    assert mac_disable < revoke < rollback

    # The loopback transition logic lives in the _locked routine; the thin
    # ice_loopback_mode_set wrapper brackets it in the outermost rebuild lock.
    setter = function(
        gld,
        "ice_loopback_mode_set_locked(ice_t *ice, uint32_t mode)\n{",
        "\n/*\n * ice_rebuild_lock is the outermost",
    )
    transition = setter.index("ice_loopback_enable(ice)")
    publish = setter.index("ice_link_loopback_update", transition)
    refresh = setter.index("ice_link_status_update", publish)
    lock_enter = setter.index("mutex_enter(&ice->ice_loopback_lock)")
    lock_exit = setter.rindex("mutex_exit(&ice->ice_loopback_lock)")
    assert "ice->ice_lock" not in setter
    assert lock_enter < transition < publish < refresh < lock_exit

    wrapper = function(
        gld,
        "ice_loopback_mode_set(ice_t *ice, uint32_t mode)\n{",
        "\nvoid\nice_loopback_fini",
    )
    assert "mutex_enter(&ice->ice_rebuild_lock)" in wrapper
    assert "ice_loopback_mode_set_locked(ice, mode)" in wrapper

    # A rebuild must restore loopback, or stop claiming it.  ice_vsi_setup()
    # recreates the VSI from ice_vsi_ctx_fill()'s SRC_PRUNE default and the PF
    # reset drops the firmware loopback setting, so both halves are lost.
    lb_replay = function(
        gld,
        "ice_loopback_replay(ice_t *ice)\n{",
        "\nvoid\nice_loopback_fini",
    )
    assert "ASSERT(MUTEX_HELD(&ice->ice_rebuild_lock))" in lb_replay
    lb_enter = lb_replay.index("mutex_enter(&ice->ice_loopback_lock)")
    lse_enter = lb_replay.index("mutex_enter(&ice->ice_lse_lock)", lb_enter)
    lse_exit = lb_replay.index("mutex_exit(&ice->ice_lse_lock)", lse_enter)
    apply_at = lb_replay.index("ice_loopback_enable(ice)", lse_exit)
    fallback = lb_replay.index(
        "ice_link_loopback_update(ice, ICE_LB_NONE)", apply_at)
    lb_exit = lb_replay.rindex("mutex_exit(&ice->ice_loopback_lock)")
    assert lb_enter < lse_enter < lse_exit < apply_at < fallback < lb_exit
    # ice_lse_lock must not be held across a blocking admin-queue command:
    # ice_link_status_update_impl() waits on ice_lse_cv under that lock.
    assert "ice_loopback_enable" not in lb_replay[lse_enter:lse_exit]
    assert "ice_aq_" not in lb_replay[lse_enter:lse_exit]
    # A failed replay downgrades; it must not take the instance offline.
    assert "ice_reset_set_failed" not in lb_replay
    assert "ICE_STATE_RESET_FAILED" not in lb_replay
    assert "ice_loopback_replay" in (
        REPO / "usr/src/uts/common/io/ice/ice.h").read_text(encoding="utf-8")

    vsi = VSI_SOURCE.read_text(encoding="utf-8")
    vsi_set = function(
        vsi,
        "ice_vsi_loopback_set(ice_t *ice, boolean_t enable)\n{",
        "\nstatic int\nice_vsi_setup",
    )
    assert "ASSERT(MUTEX_HELD(&ice->ice_loopback_lock))" in vsi_set
    assert "ICE_AQ_VSI_PROP_SW_VALID" in vsi_set
    assert "flags |= ICE_AQ_VSI_SW_FLAG_ALLOW_LB |" in vsi_set
    assert "flags &= ~(ICE_AQ_VSI_SW_FLAG_ALLOW_LB |" in vsi_set
    assert vsi_set.count("ICE_AQ_VSI_SW_FLAG_LOCAL_LB") == 2
    prune_disable = vsi_set.index(
        "flags &= ~ICE_AQ_VSI_SW_FLAG_SRC_PRUNE"
    )
    prune_restore = vsi_set.index(
        "flags |= ICE_AQ_VSI_SW_FLAG_SRC_PRUNE", prune_disable
    )
    assert prune_disable < prune_restore
    update = vsi_set.index("ice_update_vsi")
    cache = vsi_set.index("cached->info.sw_flags = flags", update)
    assert update < cache

    # ice_add_vsi() refreshes only vsi_num on a context that survived a reset,
    # so the cached copy keeps pre-reset switch flags and ice_vsi_loopback_set()
    # -- which reads that cache as authoritative -- would silently no-op.
    setup = function(
        vsi,
        "ice_vsi_setup(ice_t *ice)\n{",
        "\nstatic int\nice_add_mac_filters",
    )
    add_at = setup.index("ice_add_vsi(hw, vsi->vi_handle, &ctx, NULL)")
    resync = setup.index("->info = ctx.info", add_at)
    assert "ice_get_vsi_ctx(hw, vsi->vi_handle)" in setup[add_at:resync]
    # The info section only: a struct-wide copy would clobber and leak the
    # lan_q_ctx[]/rdma_q_ctx[] pointers the common code allocated.
    assert "= ctx;" not in setup

    # The fresh-VSI switch and VLAN defaults are unchanged: loopback stays an
    # overlay applied by ice_vsi_loopback_set(), and the tx VLAN mode is
    # hardware-validated.
    fill = function(
        vsi,
        "ice_vsi_ctx_fill(ice_t *ice, struct ice_vsi_ctx *ctx)\n{",
        "\n/*\n * Permit or reject local loopback",
    )
    assert "ctx->info.sw_flags = ICE_AQ_VSI_SW_FLAG_SRC_PRUNE;" in fill
    assert ("ctx->info.inner_vlan_flags = "
            "ICE_AQ_VSI_INNER_VLAN_TX_MODE_ALL;") in fill
    assert "ICE_AQ_VSI_SW_FLAG_ALLOW_LB" not in fill
    assert "ice_loopback_mode" not in fill

    attach = ATTACH_SOURCE.read_text(encoding="utf-8")

    # The replay sits after the VSI rebuild (which recreates the VSI with
    # SRC_PRUNE and resyncs the cached context) and after the reset barrier
    # (both admin-queue commands soft-fail while reset_ongoing is set), but
    # before the link refresh, which decides LINK_STATE_UP from the mode.
    rebuild = function(
        attach,
        "ice_rebuild(ice_t *ice)\n{",
        "\nvoid\nice_reset_task",
    )
    # Exactly one call, so an extra replay before the barrier (where both
    # admin-queue commands soft-fail) cannot hide behind the correct one.
    assert rebuild.count("ice_loopback_replay(ice)") == 1
    reset_done = rebuild.index("hw->reset_ongoing = false")
    vsi_at = rebuild.index("ice_vsi_rebuild(ice)")
    replay_at = rebuild.index("ice_loopback_replay(ice)")
    link_at = rebuild.index("ice_link_status_update(ice)")
    publish_at = rebuild.index("ice_link_state_publish(ice)")
    assert reset_done < vsi_at < replay_at < link_at < publish_at

    # The terminal path must stop reporting a loopback the reset destroyed,
    # before the fail-closed link-down report.
    tail = rebuild[rebuild.index("reset_failed:"):]
    clear_at = tail.index("ice_link_loopback_update(ice, ICE_LB_NONE)")
    assert clear_at < tail.index("ice_reset_set_failed(ice)")

    # ...but ice_reset_set_failed() itself must not clear the mode: it is the
    # shared terminal helper and must stay usable from a pre-reset caller,
    # where the hardware may genuinely still be looped back.
    failed = function(
        attach,
        "ice_reset_set_failed(ice_t *ice)\n{",
        "\nstatic void\nice_prepare_for_reset",
    )
    assert "ice_link_loopback_update" not in failed

    assert "mutex_init(&ice->ice_loopback_lock, NULL, MUTEX_DRIVER, NULL)" in attach
    assert "mutex_destroy(&ice->ice_loopback_lock)" in attach
    detach_start = attach.index(
        "ice_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)\n{"
    )
    detach = attach[detach_start:]
    unregister = detach.index("ice_mac_unregister(ice)")
    cleanup = detach.index("ice_loopback_fini(ice)", unregister)
    assert unregister < cleanup

    intr = INTR_SOURCE.read_text(encoding="utf-8")
    decode = function(
        intr,
        "ice_link_prop_update(ice_t *ice)\n{",
        "\n/*\n * Refresh the cached link state",
    )
    override = decode.index("ice->ice_loopback_mode == ICE_LB_INTERNAL_MAC")
    physical_down = decode.index("(li->link_info & ICE_AQ_LINK_UP) == 0")
    assert override < physical_down

    rx = RX_SOURCE.read_text(encoding="utf-8")
    tx = TX_SOURCE.read_text(encoding="utf-8")
    assert "loopback" not in rx.lower()
    assert "loopback" not in tx.lower()

    tool = TOOL_SOURCE.read_text(encoding="utf-8")
    assert "#include <sys/stropts.h>" in tool
    assert "ioctl(fd, I_STR, &str)" in tool
    assert re.search(r"\bioctl\(fd, LB_", tool) is None
    for command in ("LB_GET_INFO_SIZE", "LB_GET_INFO", "LB_GET_MODE", "LB_SET_MODE"):
        assert f"netlb_ioctl(fd, {command}" in tool


if __name__ == "__main__":
    main()
