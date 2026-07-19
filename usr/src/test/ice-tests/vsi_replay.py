#!/usr/bin/env python3

"""Check that the VSI rebuild drains the stale switch filter bookkeeping.

A reset clears the switch rules in hardware but leaves the common code's
record of them intact, and the partial rebuild frees no common-code state.
Replaying the tracked MAC filters on top of that record makes broadcast
return ICE_ERR_ALREADY_EXISTS and silently skips the station unicast, so
the rebuild must move the stale entries aside first and discard them on
every path out.
"""

from pathlib import Path


REPO = Path(__file__).resolve().parents[4]
VSI_SOURCE = REPO / "usr/src/uts/common/io/ice/ice_vsi.c"


def function(source: str, signature: str) -> str:
    start = source.index(signature)
    depth = 0
    i = source.index("{", start)
    for pos in range(i, len(source)):
        if source[pos] == "{":
            depth += 1
        elif source[pos] == "}":
            depth -= 1
            if depth == 0:
                return source[start:pos + 1]
    raise AssertionError("unterminated function " + signature)


def main() -> None:
    vsi = VSI_SOURCE.read_text(encoding="utf-8")
    rebuild = function(vsi, "ice_vsi_rebuild(ice_t *ice)\n{")

    drain = "ice_replay_pre_init(hw, hw->switch_info)"
    discard = "ice_rm_all_sw_replay_rule_info(hw)"

    assert drain in rebuild, "rebuild never drains filt_rules"
    assert discard in rebuild, "rebuild never frees the moved filter entries"

    # The drain has to precede every rule-programming call, otherwise the
    # replay collides with the pre-reset entries.
    drain_at = rebuild.index(drain)
    for token in ("ice_add_mac(hw", "ice_rss_setup(ice)", "ice_promisc_apply"):
        assert token in rebuild, "rebuild no longer calls " + token
        assert rebuild.index(token) > drain_at, token + " runs before the drain"

    # ice_replay_pre_init() must come after the VSI exists again: the replay
    # and the promisc/RSS restore all reference the re-added VSI handle.
    assert rebuild.index("ice_vsi_setup(ice)") < drain_at

    # Exactly one discard, reached from a single exit label, so the failure
    # paths cannot leak the moved list.
    assert rebuild.count(discard) == 1
    tail = rebuild[rebuild.index(discard):]
    assert "return (status)" in tail
    assert rebuild.count("done:") == 1
    assert rebuild.index("done:") < rebuild.index(discard)

    # Every failure after the drain must branch to the label rather than
    # returning directly.
    body = rebuild[drain_at + len(drain):]
    body = body[body.index("\n"):]
    for line in body.splitlines():
        stripped = line.strip()
        if stripped.startswith("return (") and stripped != "return (status);":
            raise AssertionError("early return after the drain: " + stripped)
    # The drain itself can fail after having already moved the entries, so
    # its error path must go through the label as well: one branch for it,
    # one for the MAC replay, one for the RSS restore.
    assert body.count("goto done;") >= 3

    # vi_macs stays the authoritative driver-side record: the common code's
    # own filter replay is deliberately not used, so it must not appear.
    for token in ("ice_replay_vsi(", "ice_replay_post(",
                  "ice_replay_vsi_all_fltr("):
        assert token not in vsi, "unexpected common-code replay call " + token

    print("vsi_replay: ok")


if __name__ == "__main__":
    main()
