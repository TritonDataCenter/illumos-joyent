#!/usr/bin/env python3

"""Check the ice transmit segmentation-offload source invariants."""

from pathlib import Path


REPO = Path(__file__).resolve().parents[4]
ICE_HEADER = REPO / "usr/src/uts/common/io/ice/ice.h"
ATTACH_SOURCE = REPO / "usr/src/uts/common/io/ice/ice.c"
DMA_SOURCE = REPO / "usr/src/uts/common/io/ice/ice_dma.c"
GLD_SOURCE = REPO / "usr/src/uts/common/io/ice/ice_gld.c"
TX_SOURCE = REPO / "usr/src/uts/common/io/ice/ice_tx.c"


def function(source: str, signature: str, following: str) -> str:
    start = source.index(signature)
    end = source.index(following, start)
    return source[start:end]


def main() -> None:
    header = ICE_HEADER.read_text(encoding="utf-8")
    assert "#define\tICE_TX_LSO_SEG_DESCS\t7" in header
    assert "#define\tICE_TX_MAX_LSO_DESC\t32" in header
    assert "sizeof (struct ice_tx_ctx_desc) ==" in header
    assert "sizeof (struct ice_tx_desc)" in header
    assert "ICE_TXD_CTX_QW1_TSO_LEN_M >>" in header
    assert "ICE_TXD_CTX_QW1_MSS_M >>" in header

    attach = ATTACH_SOURCE.read_text(encoding="utf-8")
    assert '"tx_lso_enable", 0) != 0' in attach

    dma = DMA_SOURCE.read_text(encoding="utf-8")
    assert "dma_attr_count_max = ICE_TX_MAX_BUFSZ - 1" in dma
    assert "ICE_TX_LSO_BUFSZ" in dma
    assert "ice_lso_buf_alloc" in dma

    gld = GLD_SOURCE.read_text(encoding="utf-8")
    cap = function(gld, "case MAC_CAPAB_LSO: {", "\n\tdefault:")
    assert "mac_capab_lso_t" in cap
    assert "!ice->ice_tx_lso_enable" in cap
    assert "LSO_TX_BASIC_TCP_IPV4" in cap
    assert "LSO_TX_BASIC_TCP_IPV6" in cap
    assert cap.count("lso_max = ICE_LSO_MAXLEN") == 2

    tx = TX_SOURCE.read_text(encoding="utf-8")
    context = function(
        tx,
        "ice_tx_context(ice_t *ice, mblk_t *mp, ice_tx_ctx_t *ctx)\n{",
        "\n/*\n * Build the TCB chain",
    )
    assert "mac_lso_get(mp, &mss, &lsoflags)" in context
    assert "chkflags == 0 && lsoflags == 0" in context
    # Hostile-metadata bounds: reject headers that overflow the descriptor
    # MACLEN/IPLEN/L4LEN fields before they are packed.
    assert "ICE_TXD_MACLEN_MAX" in context
    assert "ICE_TXD_IPLEN_MAX" in context
    assert "ICE_TXD_L4LEN_MAX" in context

    writer = function(
        tx,
        "ice_tx_write_ctx_desc(ice_tx_ring_t *itr, uint16_t slot,",
        "\n/*\n * Translate requested offloads",
    )
    assert "ICE_TX_CTX_DESC_TSO" in writer
    assert "ICE_TXD_CTX_QW1_TSO_LEN_S" in writer
    assert "ICE_TXD_CTX_QW1_MSS_S" in writer

    emit = function(
        tx,
        "ice_tx_emit(ice_tx_ring_t *itr, ice_tx_ctrl_block_t **tcbs,",
        "\nstatic boolean_t\nice_tx_desc_done",
    )
    assert "else if (tcb->itcb_type == ITCB_LSO_BIND)" in emit
    assert "ice_tx_write_ctx_desc" in emit

    lso_build = function(
        tx,
        "ice_tx_lso_build(ice_tx_ring_t *itr, mblk_t *mp,",
        "\n/*\n * Fragmentation can make",
    )
    assert "ICE_TX_LSO_SEG_DESCS" in lso_build
    assert "ICE_TX_MAX_LSO_DESC" in lso_build
    # Frame-sized copy fallback for an over-fragmented segment.
    assert "force_copy" in lso_build
    # Runtime DMA cookie-size guard: a cookie must not exceed the descriptor
    # length field even after the count_max fix.
    assert "dmac_size > ICE_TX_MAX_BUFSZ" in lso_build
    assert "msgpullup(mp, -1)" in tx

    print("PASS: ice LSO source invariants")


if __name__ == "__main__":
    main()
