#!/usr/bin/env python3

"""Check common-code DMA binding ownership and structure layout."""

from pathlib import Path


REPO = Path(__file__).resolve().parents[4]
HEADER = REPO / "usr/src/uts/common/io/ice/ice_osdep.h"
SOURCE = REPO / "usr/src/uts/common/io/ice/ice_osdep.c"


def function(source: str, signature: str, following: str) -> str:
    start = source.index(signature)
    end = source.index(following, start)
    return source[start:end]


def main() -> None:
    header = HEADER.read_text(encoding="utf-8")
    dma_mem = function(
        header,
        "struct ice_dma_mem {\n",
        "\n};\n\nextern void *ice_alloc_dma_mem",
    )
    va = dma_mem.index("*va")
    pa = dma_mem.index("pa", va)
    size = dma_mem.index("size", pa)
    acc_handle = dma_mem.index("idm_acc_handle", size)
    dma_handle = dma_mem.index("idm_dma_handle", acc_handle)
    bound = dma_mem.index("idm_bound", dma_handle)
    assert va < pa < size < acc_handle < dma_handle < bound

    source = SOURCE.read_text(encoding="utf-8")
    allocator = function(
        source,
        "ice_alloc_dma_mem(struct ice_hw *hw, struct ice_dma_mem *mem, u64 size)\n{",
        "\nvoid\nice_free_dma_mem",
    )
    cookie_check = allocator.index("if (ncookie != 1)")
    pa_assign = allocator.index("mem->pa = cookie.dmac_laddress", cookie_check)
    bound_set = allocator.index("mem->idm_bound = B_TRUE", pa_assign)
    assert cookie_check < pa_assign < bound_set

    release = function(
        source,
        "ice_free_dma_mem(struct ice_hw *hw, struct ice_dma_mem *mem)\n{",
        "\nvoid\nice_usec_delay",
    )
    assert "if (mem->pa != 0)" not in release
    bound_check = release.index("if (mem->idm_bound)")
    unbind = release.index("ddi_dma_unbind_handle", bound_check)
    bound_clear = release.index("mem->idm_bound = B_FALSE", unbind)
    pa_clear = release.index("mem->pa = 0", bound_clear)
    assert bound_check < unbind < bound_clear < pa_clear


if __name__ == "__main__":
    main()
