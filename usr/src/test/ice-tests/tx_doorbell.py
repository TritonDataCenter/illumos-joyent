#!/usr/bin/env python3

"""Check the ice transmit doorbell and descriptor-sync source invariants."""

from pathlib import Path


REPO = Path(__file__).resolve().parents[4]
TX_SOURCE = REPO / "usr/src/uts/common/io/ice/ice_tx.c"


def function(source: str, signature: str, following: str) -> str:
    start = source.index(signature)
    end = source.index(following, start)
    return source[start:end]


def main() -> None:
    tx = TX_SOURCE.read_text(encoding="utf-8")

    emit = function(
        tx,
        "ice_tx_emit(ice_tx_ring_t *itr,",
        "\nstatic boolean_t\nice_tx_desc_done",
    )

    # the doorbell is still rung, and still FM-checked
    assert "wr32(hw, QTX_COMM_DBELL(itr->itxr_index), tail);" in emit
    assert "ice_check_acc_handle(ice->ice_osdep.ios_reg_handle)" in emit

    # no per-packet MMIO readback
    assert "ice_flush(" not in emit

    # no whole-ring sync; only the descriptors written are pushed
    assert "ddi_dma_sync(itr->itxr_dma.idb_dma_handle, 0, 0" not in emit
    assert "ice_tx_sync_descs(itr, itr->itxr_tail, written);" in emit
    assert "ice_check_dma_handle(itr->itxr_dma.idb_dma_handle)" in emit

    # the sync happens before the doorbell, and before itxr_tail advances
    sync = emit.index("ice_tx_sync_descs(itr, itr->itxr_tail, written);")
    advance = emit.index("itr->itxr_tail = tail;")
    doorbell = emit.index("wr32(hw, QTX_COMM_DBELL(")
    assert sync < advance < doorbell

    # the helper covers wrap and uses descriptor-sized offsets
    helper = function(
        tx,
        "ice_tx_sync_descs(ice_tx_ring_t *itr,",
        "\nstatic void\nice_tx_write_desc",
    )
    assert "sizeof (struct ice_tx_desc)" in helper
    assert helper.count("ddi_dma_sync(") == 2
    assert "DDI_DMA_SYNC_FORDEV" in helper
    assert "itr->itxr_size - start" in helper

    # control paths keep their flush; recycle keeps its FORKERNEL sync
    mapq = function(tx, "ice_map_txq_vector(ice_t *ice,", "\nstatic boolean_t")
    assert "ice_flush(hw);" in mapq
    rec = function(tx, "ice_tx_recycle(ice_tx_ring_t *itr)", "\n/*")
    assert "DDI_DMA_SYNC_FORKERNEL" in rec

    print("PASS: ice tx doorbell source invariants")


if __name__ == "__main__":
    main()
