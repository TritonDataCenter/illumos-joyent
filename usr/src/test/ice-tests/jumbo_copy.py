#!/usr/bin/env python3

"""Check that the ice tx copy pool can hold any MTU-legal frame."""

import re
from pathlib import Path


REPO = Path(__file__).resolve().parents[4]
HEADER = REPO / "usr/src/uts/common/io/ice/ice.h"
DMA_SOURCE = REPO / "usr/src/uts/common/io/ice/ice_dma.c"
TX_SOURCE = REPO / "usr/src/uts/common/io/ice/ice_tx.c"
ADMINQ_HEADER = REPO / "usr/src/uts/common/io/ice/core/ice_adminq_cmd.h"

PAGESIZE = 4096


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


def p2roundup(value: int, align: int) -> int:
    return (value + align - 1) & ~(align - 1)


def main() -> None:
    header = HEADER.read_text(encoding="utf-8")
    dma_source = DMA_SOURCE.read_text(encoding="utf-8")
    tx_source = TX_SOURCE.read_text(encoding="utf-8")
    adminq = ADMINQ_HEADER.read_text(encoding="utf-8")

    assert re.search(
        r"#define\s+ICE_TX_COPY_BUFSZ\s+"
        r"P2ROUNDUP\(ICE_MAX_FRAME_SIZE,\s*PAGESIZE\)",
        header,
    )
    # ICE_TX_COPY_BUFSZ is page-rounded, so it is >= ICE_MAX_FRAME_SIZE by
    # construction and is not a constant expression a CTASSERT can evaluate
    # (PAGESIZE is not compile-time constant in the kernel).  The constant
    # invariant that matters is that a whole frame fits one tx descriptor.
    assert re.search(
        r"CTASSERT\(ICE_MAX_FRAME_SIZE\s*<=\s*ICE_TX_MAX_BUFSZ\);",
        header,
    )

    buf_init = function(
        dma_source,
        "ice_buf_init(ice_t *ice)\n{",
        "\nvoid\nice_buf_fini",
    )
    general = braced_block(buf_init, buf_init.index("for (i = 0; i < n; i++)"))
    assert "ice->ice_dma_bufs[i] = &ice->ice_bufs[i];" in general
    assert re.search(
        r"ice_dma_alloc\(ice,\s*&ice->ice_bufs\[i\],[^;]*"
        r"ICE_TX_COPY_BUFSZ",
        general,
    )
    # rx data buffers are allocated in ice_rx.c, not from these pools.
    assert "ICE_RX_BUF_SIZE" not in dma_source

    copy_packet = braced_block(
        tx_source,
        tx_source.index(
            "ice_tx_copy_packet(ice_tx_ring_t *itr, mblk_t *mp, size_t msglen,"
        ),
    )
    small = copy_packet.index("ice_small_buf_alloc(ice)")
    assert copy_packet.index("ice_buf_alloc(ice)", small) > small
    # The general pool must be usable with ice_tx_lso_enable off.
    assert "ice_lso_buf_alloc(" not in copy_packet

    max_frame = re.search(
        r"#define\s+ICE_AQ_SET_MAC_FRAME_SIZE_MAX\s+(\d+)", adminq
    )
    assert max_frame is not None
    frame_size = int(max_frame.group(1))
    assert re.search(
        r"#define\s+ICE_MAX_FRAME_SIZE\s+ICE_AQ_SET_MAC_FRAME_SIZE_MAX\b",
        header,
    )
    copy_bufsz = p2roundup(frame_size, PAGESIZE)
    assert copy_bufsz >= frame_size
    rx_bufsz = re.search(r"#define\s+ICE_RX_BUF_SIZE\s+(\d+)", header)
    assert rx_bufsz is not None
    # The defect: the old general-pool size cannot hold a jumbo frame.
    assert int(rx_bufsz.group(1)) < frame_size

    max_bufsz = re.search(r"#define\s+ICE_TX_MAX_BUFSZ\s+(0x[0-9a-f]+)", header)
    assert max_bufsz is not None
    assert copy_bufsz <= int(max_bufsz.group(1), 16)

    print("PASS: ice tx copy pool holds a full-size frame")


if __name__ == "__main__":
    main()
