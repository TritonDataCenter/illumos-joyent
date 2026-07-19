#!/usr/bin/env python3

"""Check initial ice link-state publication and serialization."""

from pathlib import Path


REPO = Path(__file__).resolve().parents[4]
ATTACH_SOURCE = REPO / "usr/src/uts/common/io/ice/ice.c"
INTR_SOURCE = REPO / "usr/src/uts/common/io/ice/ice_intr.c"
GLD_SOURCE = REPO / "usr/src/uts/common/io/ice/ice_gld.c"


def function(source: str, signature: str, following: str) -> str:
    start = source.index(signature)
    end = source.index(following, start)
    return source[start:end]


def main() -> None:
    attach_source = ATTACH_SOURCE.read_text(encoding="utf-8")
    attach = function(
        attach_source,
        "ice_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)\n{",
        "\nstatic int\nice_detach",
    )
    unknown = attach.index("ice->ice_link_state = LINK_STATE_UNKNOWN")
    query = attach.index("ice_link_status_update(ice)", unknown)
    register = attach.index("ice_mac_register(ice)", query)
    assert unknown < query < register

    intr_source = INTR_SOURCE.read_text(encoding="utf-8")
    publisher = function(
        intr_source,
        "ice_link_state_publish(ice_t *ice)\n{",
        "\n/*\n * Decode the firmware-supplied link_info",
    )
    assert publisher.index("mutex_enter(&ice->ice_lse_lock)") < publisher.index(
        "ice_link_state_set(ice, ice->ice_link_state)"
    ) < publisher.index("mutex_exit(&ice->ice_lse_lock)")

    gld_source = GLD_SOURCE.read_text(encoding="utf-8")
    registration = function(
        gld_source,
        "ice_mac_register(ice_t *ice)\n{",
        "\n/*\n * Returns the mac_unregister() status",
    )
    register = registration.index("status = mac_register(mac, &ice->ice_mac_hdl)")
    failure = registration.index("if (status != 0)", register)
    publish = registration.index("ice_link_state_publish(ice)", failure)
    success = registration.index("return (B_TRUE)", publish)
    assert register < failure < publish < success


if __name__ == "__main__":
    main()
