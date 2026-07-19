#!/usr/bin/env python3

"""Check the ice admin-vector dispatch and coalescing invariants."""

from pathlib import Path


REPO = Path(__file__).resolve().parents[4]
SOURCE = REPO / "usr/src/uts/common/io/ice/ice_intr.c"


def function(source: str, signature: str, following: str) -> str:
    start = source.index(signature)
    end = source.index(following, start)
    return source[start:end]


def main() -> None:
    source = SOURCE.read_text(encoding="utf-8")
    handler = function(
        source,
        "ice_intr_oicr(ice_t *ice)\n{",
        "\nstatic uint_t\nice_intr_queue",
    )
    entry = function(
        source,
        "ice_intr_msix(caddr_t arg1, caddr_t arg2)\n{",
        "\nboolean_t\nice_intr_enable",
    )
    worker = function(
        source,
        "ice_oicr_task(void *arg)\n{",
        "\nstatic void\nice_intr_oicr_enable",
    )

    assert "if (oicr == 0)" not in handler
    assert "if (!ice->ice_oicr_pending)" in handler
    assert "ice->ice_oicr_pending = B_TRUE" in handler
    assert "ddi_taskq_dispatch" in handler
    assert "guard < ICE_ARQ_MAX_ELEMS" in worker
    assert "if (vector == ICE_OICR_VECTOR)" in entry
    assert "return (ice_intr_queue(ice, vector))" in entry


if __name__ == "__main__":
    main()
