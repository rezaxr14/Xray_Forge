"""Core adapter tests: capabilities, client configs, and bridge compat."""

from __future__ import annotations

import pytest

from xray_forge.core.cores import get_core, iter_cores, core_names
from xray_forge.core.models import Outbound
from xray_forge.core.parser import parse_target
from tests.fixtures import VLESS_TLS_WS, VLESS_REALITY, VMESS_B64, SS_SIP002


def test_registry():
    assert set(core_names()) >= {"xray", "singbox", "mihomo"}
    assert get_core("xray").name == "xray"
    assert get_core("bogus") is None
    assert len(iter_cores()) >= 3


def test_capability_sets():
    xray = get_core("xray").supported_protocols()
    assert {"vless", "vmess", "trojan", "ss"} <= xray
    assert "wireguard" in xray
    assert "hysteria2" not in xray          # xray cannot run hysteria2
    assert "tuic" not in xray

    for core_name in ("singbox", "mihomo"):
        caps = get_core(core_name).supported_protocols()
        assert {"vless", "vmess", "trojan", "ss", "hysteria2", "tuic"} <= caps


def test_xray_client_config_vless():
    xray = get_core("xray")
    out = parse_target(VLESS_TLS_WS)
    cfg = xray.build_client_config([out], 10808, frag_on=True)
    assert cfg["inbounds"][0]["port"] == 10808
    protos = [o["protocol"] for o in cfg["outbounds"]]
    assert protos[0] == "vless"
    assert "freedom" in protos  # direct (+ optional frag)
    proxy = cfg["outbounds"][0]
    stream = proxy["streamSettings"]
    assert stream["network"] == "ws"
    assert stream["security"] == "tls"
    assert stream["tlsSettings"]["serverName"] == "edgestuff.pages.dev"
    assert stream["sockopt"]["dialerProxy"] == "frag"


def test_xray_reality_config():
    xray = get_core("xray")
    out = parse_target(VLESS_REALITY)
    cfg = xray.build_client_config([out], 10808, frag_on=False)
    rs = cfg["outbounds"][0]["streamSettings"]["realitySettings"]
    assert rs["publicKey"] == "SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc"
    assert rs["shortId"] == "6ba85179"
    assert rs["serverName"] == "www.microsoft.com"


def test_xray_vmess_and_ss_outbounds():
    xray = get_core("xray")
    vm = parse_target(VMESS_B64)
    cfg = xray.build_client_config([vm], 10808)
    assert cfg["outbounds"][0]["protocol"] == "vmess"
    ss = parse_target(SS_SIP002)
    cfg = xray.build_client_config([ss], 10808)
    assert cfg["outbounds"][0]["protocol"] == "shadowsocks"
    server = cfg["outbounds"][0]["settings"]["servers"][0]
    assert server["method"] == "aes-256-gcm"
    assert server["password"] == "seekrit-password"


def test_xray_unsupported_scheme_raises():
    xray = get_core("xray")
    hy2 = Outbound(scheme="hysteria2", name="h", host="1.1.1.1", port="443",
                   credential="pw")
    with pytest.raises(ValueError):
        xray.build_client_config([hy2], 10808)


def test_singbox_client_config():
    sb = get_core("singbox")
    out = parse_target(VLESS_TLS_WS)
    cfg = sb.build_client_config([out], 2080)
    assert cfg["inbounds"][0]["listen_port"] == 2080
    ob = cfg["outbounds"][0]
    assert ob["type"] == "vless"
    assert ob["transport"]["type"] == "ws"
    assert ob["tls"]["utls"]["fingerprint"] == "chrome"


def test_mihomo_client_config():
    mh = get_core("mihomo")
    out = parse_target(VLESS_TLS_WS)
    cfg = mh.build_client_config([out], 7890)
    assert cfg["mixed-port"] == 7890
    assert cfg["proxies"][0]["type"] == "vless"
    assert cfg["rules"] == ["MATCH,FORGE"]


def test_bridge_compat_wrapper():
    """xray_bridge.build_xray_config keeps its old signature/behaviour."""
    from xray_forge.core.xray_bridge import build_xray_config
    cfg = build_xray_config(VLESS_TLS_WS, 10808, True)
    assert cfg["outbounds"][0]["protocol"] == "vless"
    with pytest.raises(Exception):
        build_xray_config("gopher://nope", 1, False)


def test_render_outbound_none_for_unsupported():
    xray = get_core("xray")
    hy2 = Outbound(scheme="hysteria2", name="h", host="1.1.1.1", port="443",
                   credential="pw")
    assert xray.render_outbound(hy2) is None
    assert not xray.supports(hy2)
