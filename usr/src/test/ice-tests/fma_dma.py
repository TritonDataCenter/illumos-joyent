#!/usr/bin/env python3

"""Check ice FMA DMA capability, attributes, and handle checks."""

from pathlib import Path


REPO = Path(__file__).resolve().parents[4]
ATTACH_SOURCE = REPO / "usr/src/uts/common/io/ice/ice.c"
DMA_SOURCE = REPO / "usr/src/uts/common/io/ice/ice_dma.c"
OSDEP_SOURCE = REPO / "usr/src/uts/common/io/ice/ice_osdep.c"
RX_SOURCE = REPO / "usr/src/uts/common/io/ice/ice_rx.c"
TX_SOURCE = REPO / "usr/src/uts/common/io/ice/ice_tx.c"


def function(source: str, signature: str, following: str) -> str:
    start = source.index(signature)
    end = source.index(following, start)
    return source[start:end]


def main() -> None:
    attach_source = ATTACH_SOURCE.read_text(encoding="utf-8")
    fm_init = function(
        attach_source,
        "ice_fm_init(ice_t *ice)\n{",
        "\nstatic void\nice_fm_fini",
    )
    assert fm_init.count("DDI_FM_DMACHK_CAPABLE") == 2

    dma_source = DMA_SOURCE.read_text(encoding="utf-8")
    assert dma_source.count("DDI_FM_DMA_ERR_CAP(ice->ice_fm_caps)") >= 3
    assert dma_source.count("DDI_DMA_FLAGERR") >= 2

    osdep_source = OSDEP_SOURCE.read_text(encoding="utf-8")
    allocator = function(
        osdep_source,
        "ice_alloc_dma_mem(struct ice_hw *hw, struct ice_dma_mem *mem, u64 size)\n{",
        "\nvoid\nice_free_dma_mem",
    )
    assert "ddi_dma_attr_t dma_attr = ice_dma_attr" in allocator
    assert "ddi_device_acc_attr_t acc_attr = ice_acc_attr" in allocator
    gate = allocator.index("DDI_FM_DMA_ERR_CAP(osdep->ios_ice->ice_fm_caps)")
    dma_flag = allocator.index("dma_attr.dma_attr_flags = DDI_DMA_FLAGERR", gate)
    acc_flag = allocator.index("acc_attr.devacc_attr_access = DDI_FLAGERR_ACC", gate)
    allocate = allocator.index("ddi_dma_alloc_handle(osdep->ios_dip, &dma_attr", gate)
    assert gate < dma_flag < allocate
    assert gate < acc_flag < allocate
    assert "ddi_dma_mem_alloc(mem->idm_dma_handle, size, &acc_attr" in allocator

    rx_source = RX_SOURCE.read_text(encoding="utf-8")
    tx_source = TX_SOURCE.read_text(encoding="utf-8")
    assert rx_source.count("ice_check_dma_handle(") >= 2
    assert tx_source.count("ice_check_dma_handle(") >= 3


if __name__ == "__main__":
    main()
