#!/usr/bin/env python3

"""Check that glue comments describe the driver as it is actually built."""

import re
from pathlib import Path


REPO = Path(__file__).resolve().parents[4]
GLUE_DIR = REPO / "usr/src/uts/common/io/ice"

# The driver's own sources.  core/ and firmware/ are vendored from Intel and
# are deliberately not held to these rules.
GLUE = (
    "ice.c",
    "ice.h",
    "ice_gld.c",
    "ice_intr.c",
    "ice_rx.c",
    "ice_tx.c",
    "ice_vsi.c",
    "ice_stats.c",
    "ice_dma.c",
    "ice_ddp.c",
    "ice_osdep.c",
    "ice_osdep.h",
)

# "M5", "M6a" and friends: development milestone labels that outlived the
# development that named them.
MILESTONE_LABEL = re.compile(r"\bM[0-9][a-z]?\b")

ATTACH_TOKEN = re.compile(r"\bICE_ATTACH_[A-Z0-9_]+")

# One enumerator per line, tolerating arbitrary whitespace, an optional
# initializer, and a trailing comment.
ENUMERATOR = re.compile(
    r"^\s*(ICE_ATTACH_[A-Z0-9_]+)\s*(?:=[^,}]*)?,?\s*(?:/\*.*)?$"
)


def attach_states(header: str) -> set:
    """Parse the ice_attach_state_t enumerators out of ice.h."""
    start = header.index("ICE_ATTACH_FM_INIT")
    end = header.index("}", start)
    states = set()
    for line in header[start:end].splitlines():
        match = ENUMERATOR.match(line)
        if match is not None:
            states.add(match.group(1))
    return states


def main() -> None:
    sources = {}
    for name in GLUE:
        path = GLUE_DIR / name
        assert path.is_file(), name
        sources[name] = path.read_text(encoding="utf-8")

    # 1. No milestone vocabulary survives anywhere in the glue.
    for name, text in sources.items():
        label = MILESTONE_LABEL.search(text)
        assert label is None, "%s: stale milestone label %r" % (
            name, label.group(0))
        assert "milestone" not in text.lower(), "%s: stale milestone" % name

    # 2. Every ICE_ATTACH_* token in the glue -- in code or in a comment --
    # names a progress bit that actually exists.  A comment naming a bit the
    # enum never defined is describing a driver that was never built.
    states = attach_states(sources["ice.h"])
    assert "ICE_ATTACH_FM_INIT" in states
    assert "ICE_ATTACH_MAC" in states
    for name, text in sources.items():
        for token in ATTACH_TOKEN.findall(text):
            assert token in states, "%s: no such progress bit %s" % (
                name, token)

    # 3. The multi-PF limitation is genuine and must stay recorded: the
    # instance list has no consumer yet.
    assert "multi-function" in sources["ice.c"]

    print("PASS: ice glue comments match the implemented driver")


if __name__ == "__main__":
    main()
