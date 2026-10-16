"""Protocol handler tests: parsing, share-link round-trips, per-core rendering."""

from __future__ import annotations

import pytest

from xray_forge.core.models import Outbound
from xray_forge.core.protocols import (
    handler_for, iter_handlers, supported_schemes,
)
from xray_forge.core.parser import parse_target
from tests.fixtures import (
    VLESS_TLS_WS, VLESS_REALITY, VMESS_B64, TROJAN_TLS, SS_SIP002,
    HYSTERIA2, TUIC,
)


def test_registry_complete():
    schemes = supported_schemes()
    for needed in ("vless", "vmess", "trojan", "ss", "hysteria2", "tuic",
                   "wireguard"):
        assert needed in schemes
    assert len(iter_handlers()) >= 7
    assert handler_for("nope") is None


def test_vless_reality_roundtrip():
    out = parse_target(VLESS_REALITY)
    h = handler_for("vless")
    uri = h.to_uri(out)
    out2 = h.parse(uri)
    assert out2 is not None
    assert out2.public_key == out.public_key
    assert out2.short_id == out.short_id
    assert out2.flow == out.flow
    assert out2.sni == out.sni
    assert out2.host == out.host and out2.port == out.port


def test_vless_xhttp_mode_roundtrip():
    """xhttp ``mode=`` survives parse -> to_uri -> parse (editor round-trip)."""
    uri = ("vless://uid@1.2.3.4:443?security=tls&sni=x.example&type=xhttp"
           "&path=%2Fxh&mode=stream-one#xh")
    out = parse_target(uri)
    assert out.transport == "xhttp"
    assert out.extra["mode"] == "stream-one"
    out2 = handler_for("vless").parse(handler_for("vless").to_uri(out))
    assert out2.transport == "xhttp"
    assert out2.extra["mode"] == "stream-one"


def test_vless_header_type_and_insecure_roundtrip():
    uri = ("vless://uid@1.2.3.4:80?type=tcp&headerType=http&security=none"
           "&allowInsecure=1#obfs")
    out = parse_target(uri)
    assert out.header_type == "http"
    assert out.allow_insecure is True
    out2 = handler_for("vless").parse(handler_for("vless").to_uri(out))
    assert out2.header_type == "http"
    assert out2.allow_insecure is True


def test_trojan_xhttp_mode_roundtrip():
    uri = ("trojan://pw@1.2.3.4:443?security=tls&sni=t.example&type=xhttp"
           "&path=%2Ft&mode=packet-up#tx")
    out = parse_target(uri)
    assert out.transport == "xhttp"
    assert out.extra["mode"] == "packet-up"
    out2 = handler_for("trojan").parse(handler_for("trojan").to_uri(out))
    assert out2.transport == "xhttp"
    assert out2.extra["mode"] == "packet-up"


def test_vless_tls_ws_roundtrip():
    out = parse_target(VLESS_TLS_WS)
    h = handler_for("vless")
    out2 = h.parse(h.to_uri(out))
    assert out2.host_header == "edgestuff.pages.dev"
    assert out2.path == "/channel"
    assert out2.transport == "ws"
    assert out2.security == "tls"


def test_vmess_roundtrip():
    out = parse_target(VMESS_B64)
    h = handler_for("vmess")
    out2 = h.parse(h.to_uri(out))
    assert out2 is not None
    assert out2.credential == out.credential
    assert out2.host == out.host
    assert out2.transport == "ws"
    assert out2.encryption == "auto"


def test_trojan_roundtrip():
    out = parse_target(TROJAN_TLS)
    h = handler_for("trojan")
    out2 = h.parse(h.to_uri(out))
    assert out2.credential == "passw0rd"
    assert out2.path == "/tj"
    assert out2.sni == "trojan.example.com"


def test_ss_roundtrip():
    out = parse_target(SS_SIP002)
    h = handler_for("ss")
    out2 = h.parse(h.to_uri(out))
    assert out2.ss_method == "aes-256-gcm"
    assert out2.credential == "seekrit-password"
    assert out2.host == "198.51.100.7"


def test_hysteria2_fields_and_roundtrip():
    out = parse_target(HYSTERIA2)
    assert out.scheme == "hysteria2"
    assert out.credential == "hy2pass"
    assert out.allow_insecure is True
    assert out.extra["obfs"] == "salamander"
    h = handler_for("hysteria2")
    out2 = h.parse(h.to_uri(out))
    assert out2.credential == "hy2pass"
    assert out2.extra["obfs"] == "salamander"
    assert out2.allow_insecure is True


def test_tuic_fields_and_roundtrip():
    out = parse_target(TUIC)
    assert out.scheme == "tuic"
    assert out.credential == "tuic-uuid"
    assert out.extra["password"] == "tuicpass"
    assert out.extra["congestion_control"] == "bbr"
    h = handler_for("tuic")
    out2 = h.parse(h.to_uri(out))
    assert out2.credential == "tuic-uuid"
    assert out2.extra["password"] == "tuicpass"


def test_wireguard_renderings():
    h = handler_for("wireguard")
    out = Outbound(
        scheme="wireguard", name="WARP", host="162.159.192.1", port="2408",
        extra={"private_key": "PRIV=", "peer_public_key": "PUB=",
               "ipv4": "172.16.0.2/32", "ipv6": "2606:4700:110::1/128",
               "client_id": "a1b2c3", "mtu": 1280})
    x = h.xray_outbound(out)
    assert x["protocol"] == "wireguard"
    assert x["settings"]["secretKey"] == "PRIV="
    assert x["settings"]["peers"][0]["endpoint"] == "162.159.192.1:2408"
    assert x["settings"]["reserved"] == [0xA1, 0xB2, 0xC3]

    sb = h.singbox_outbound(out)
    assert sb["type"] == "wireguard"
    assert sb["private_key"] == "PRIV="
    assert "172.16.0.2/32" in sb["local_address"]

    cl = h.clash_proxy(out)
    assert cl["type"] == "wireguard"
    assert cl["ip"] == "172.16.0.2"

    with pytest.raises(NotImplementedError):
        h.to_uri(out)


def test_core_capabilities_from_renderers():
    vless = handler_for("vless")
    assert vless.supports_core("xray")
    assert vless.supports_core("singbox")
    assert vless.supports_core("mihomo")
    hy2 = handler_for("hysteria2")
    assert not hy2.supports_core("xray")     # xray has no hysteria2
    assert hy2.supports_core("singbox")
    assert hy2.supports_core("mihomo")


def test_parse_rejects_garbage():
    assert parse_target("") is None
    assert parse_target("hello world") is None
    assert parse_target("http://example.com") is None
    assert parse_target("vless://no-creds") is None
