"""Per-config (not just per-scheme) core capability checks."""

from __future__ import annotations

import json

import pytest

from xray_forge.core import healthcheck as hc
from xray_forge.core.cores import get_core, iter_cores
from xray_forge.core.parser import export_to_clash, export_to_singbox, parse_target
from tests.fixtures import VLESS_TLS_WS

U = "13b8ac3f-e8de-4b2d-82db-e9130d288a54"
XHTTP = f"vless://{U}@1.2.3.4:443?security=tls&sni=a.com&type=xhttp&mode=auto&path=%2Fp#xh"


def test_xhttp_is_xray_only():
    out = parse_target(XHTTP)
    assert get_core("xray").supports(out) is True
    assert get_core("singbox").supports(out) is False
    assert get_core("mihomo").supports(out) is False


def test_ws_still_runs_everywhere():
    out = parse_target(VLESS_TLS_WS)
    assert all(c.supports(out) for c in iter_cores())


def test_exporters_skip_instead_of_emitting_a_wrong_plain_tcp_proxy():
    sb = json.loads(export_to_singbox([XHTTP, VLESS_TLS_WS]))
    assert [o["tag"] for o in sb["outbounds"]] == ["CF worker"]
    assert "CF worker" in export_to_clash([XHTTP, VLESS_TLS_WS])
    assert "xh" not in export_to_clash([XHTTP])


def test_singbox_refuses_to_build_a_config_it_cannot_run():
    with pytest.raises(ValueError):
        get_core("singbox").build_client_config([parse_target(XHTTP)], 10808)


def test_auto_core_never_picks_a_core_that_cannot_run_the_config(monkeypatch):
    for c in iter_cores():
        monkeypatch.setattr(c, "find_binary",
                            (lambda: "/bin/true") if c.name == "singbox" else (lambda: ""))
    assert hc._core_context(parse_target(XHTTP), "auto") is None
    assert hc._core_context(parse_target(VLESS_TLS_WS), "auto") is not None


def test_xray_xhttp_config_is_built():
    cfg = get_core("xray").build_client_config([parse_target(XHTTP)], 10808)
    ss = cfg["outbounds"][0]["streamSettings"]
    assert ss["network"] == "xhttp" and ss["xhttpSettings"]["mode"] == "auto"
