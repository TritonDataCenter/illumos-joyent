#!/usr/bin/env python3

"""Check ICE multiqueue and RSS source invariants."""

import re
from pathlib import Path


REPO = Path(__file__).resolve().parents[4]
HEADER = REPO / "usr/src/uts/common/io/ice/ice.h"
ATTACH_SOURCE = REPO / "usr/src/uts/common/io/ice/ice.c"
VSI_SOURCE = REPO / "usr/src/uts/common/io/ice/ice_vsi.c"
GLD_SOURCE = REPO / "usr/src/uts/common/io/ice/ice_gld.c"
INTR_SOURCE = REPO / "usr/src/uts/common/io/ice/ice_intr.c"


def function(source: str, signature: str, following: str) -> str:
    start = source.index(signature)
    end = source.index(following, start)
    return source[start:end]


def main() -> None:
    header = HEADER.read_text(encoding="utf-8")
    maximum = re.search(r"#define\s+ICE_MAX_INTR_QUEUES\s+(\d+)", header)
    assert maximum is not None
    queue_cap = int(maximum.group(1))
    assert queue_cap > 0 and queue_cap & (queue_cap - 1) == 0
    assert "uint16_t\t\tice_nqueues;" in header
    assert "ICE_MAX_INTR_QUEUES - 1)) == 0);" in header
    assert "CTASSERT(ICE_INTR_MSIX_MIN == 2);" in header

    progress = [
        header.index("ICE_ATTACH_HW_INIT"),
        header.index("ICE_ATTACH_DDP"),
        header.index("ICE_ATTACH_ALLOC_INTR"),
        header.index("ICE_ATTACH_ADD_INTR"),
        header.index("ICE_ATTACH_OICR_TASKQ"),
        header.index("ICE_ATTACH_ENABLE_INTR"),
    ]
    assert progress == sorted(progress)

    attach = ATTACH_SOURCE.read_text(encoding="utf-8")
    attach_fn = function(
        attach,
        "ice_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)\n{",
        "\nstatic int\nice_detach",
    )
    ddp_load = attach_fn.index("if (!ice_ddp_load(ice))")
    ddp_progress = attach_fn.index(
        "ice->ice_attach_progress |= ICE_ATTACH_DDP;"
    )
    intr_alloc = attach_fn.index("if (!ice_alloc_intrs(ice))")
    assert ddp_load < ddp_progress < intr_alloc
    unconfigure = function(
        attach,
        "ice_unconfigure(ice_t *ice)\n{",
        "\nstatic uint32_t\nice_prop_get_num_queues",
    )
    intr_teardown = unconfigure.index("ICE_ATTACH_ALLOC_INTR")
    hw_teardown = unconfigure.index("ICE_ATTACH_HW_INIT")
    assert intr_teardown < hw_teardown
    allocator = function(
        attach,
        "ice_alloc_intrs(ice_t *ice)\n{",
        "\nstatic void\nice_rem_intr_handlers",
    )
    assert '"num_queues"' in attach
    rounded = allocator.index(
        "nreq = (nreq < 1) ? 1 : (1u << ice_ilog2(nreq));"
    )
    requested = allocator.index("request = (int)(1 + nreq);")
    assert rounded < requested
    assert "ddi_intr_alloc" in allocator
    actual_guard = allocator.index("if (actual < ICE_INTR_MSIX_MIN)")
    final_count = allocator.index("ice->ice_nqueues")
    assert allocator.index("ddi_intr_alloc") < actual_guard < final_count
    assert re.search(
        r"ice->ice_nqueues\s*=.*ice_ilog2\(\(uint32_t\)actual - 1\)",
        allocator,
        re.DOTALL,
    )
    # The direct-index ISR dispatch requires a 1:1 ring<->vector map; the
    # sizing site must assert it so a future vector-cap change fails loudly.
    assert re.search(
        r"ASSERT3U\(\(uint_t\)ice->ice_nqueues,\s*<=,"
        r"\s*\(uint_t\)ice->ice_intr_count - 1\)",
        allocator,
    )
    # Vector accounting must be logged so the scaling ceiling is observable.
    assert "MSI-X vectors: fw=" in allocator

    vsi_source = VSI_SOURCE.read_text(encoding="utf-8")
    setup = function(
        vsi_source,
        "ice_vsi_setup(ice_t *ice)\n{",
        "\nstatic int\nice_add_mac_filters",
    )
    assert "vsi->vi_nrxq = ice->ice_nqueues;" in setup
    assert "vsi->vi_ntxq = ice->ice_nqueues;" in setup
    assert "vsi->vi_nrxq = 1;" not in setup
    assert "vsi->vi_ntxq = 1;" not in setup

    context = function(
        vsi_source,
        "ice_vsi_ctx_fill(ice_t *ice, struct ice_vsi_ctx *ctx)\n{",
        "\n/*\n * Permit or reject local loopback",
    )
    assert "VERIFY(" not in context
    assert "nq == 0" in context
    assert "hw->func_caps.common_cap.num_rxq" in context
    assert "hw->func_caps.common_cap.num_txq" in context
    assert "return (ICE_ERR_CFG);" in context
    assert "ice_fls(nq - 1)" in context
    fill = setup.index("status = ice_vsi_ctx_fill(ice, &ctx);")
    fill_error = setup.index("if (status != ICE_SUCCESS)", fill)
    add_vsi = setup.index("status = ice_add_vsi", fill)
    assert fill < fill_error < add_vsi

    rss = function(
        vsi_source,
        "ice_rss_setup(ice_t *ice)\n{",
        "\nboolean_t\nice_vsi_init",
    )
    assert "lut[i] = (uint8_t)(i % vsi->vi_nrxq);" in rss
    assert "lp.lut_type = ICE_LUT_PF;" in rss
    assert "lut_size > ICE_LUT_PF_SIZE" in rss

    gld_source = GLD_SOURCE.read_text(encoding="utf-8")
    rx_ring = function(
        gld_source,
        "ice_fill_rx_ring(void *arg, mac_ring_type_t rtype,",
        "\nstatic void\nice_fill_tx_ring",
    )
    assert re.search(
        r"if \(\(ice->ice_intr_type & DDI_INTR_TYPE_MSIX\) != 0\) \{\s*"
        r"infop->mri_intr\.mi_ddi_handle\s*=\s*"
        r"ice->ice_intr_handles\[rxr->irxr_vec\];\s*\}",
        rx_ring,
    )

    intr_source = INTR_SOURCE.read_text(encoding="utf-8")
    queue_isr = function(
        intr_source,
        "ice_intr_queue(ice_t *ice, uint_t vector)\n{",
        "\nuint_t\nice_intr_msix",
    )
    assert "uint_t idx = vector - 1;" in queue_isr
    assert "ice->ice_rxr[idx]" in queue_isr
    assert "ice->ice_txr[idx]" in queue_isr
    assert "idx < ice->ice_num_rxr" in queue_isr
    assert "idx < ice->ice_num_txr" in queue_isr
    assert "irxr_vec == vector" not in queue_isr
    assert "itxr_vec == vector" not in queue_isr
    assert "for (i = 0; i < ice->ice_num_rxr" not in queue_isr

    dispatch = function(
        intr_source,
        "ice_intr_msix(caddr_t arg1, caddr_t arg2)\n{",
        "\nboolean_t\nice_intr_enable",
    )
    assert "vector >= (uint_t)ice->ice_intr_count" in dispatch

    print("PASS: ice multiqueue and RSS source invariants")


if __name__ == "__main__":
    main()
