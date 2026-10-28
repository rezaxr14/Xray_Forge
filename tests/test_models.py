"""Tests for the typed Outbound model and its legacy dict-compat layer."""

from __future__ import annotations

import pytest

from xray_forge.core.models import Outbound, vmess_json_to_outbound
from tests.fixtures import VMESS_PAYLOAD, VLESS_TLS_WS, VLESS_REALITY


def test_basic_fields():
    out = Outbound(scheme="vless", name="n", host="1.1.1.1", port="443",
                   credential="uuid-x", transport="ws", security="tls",
                   sni="s.com", host_header="h.com", path="/p")
    assert out.endpoint == "1.1.1.1:443"
    assert out.effective_sni == "s.com"
    assert out.is_tls() and not out.is_reality()
    assert not Outbound(scheme="vless").is_tls()


def test_reality_flags():
    out = Outbound(scheme="vless", security="reality")
    assert out.is_reality() and out.is_tls()


def test_legacy_dict_access():
    out = Outbound(scheme="vless", credential="u", host_header="h",
                   transport="grpc", fingerprint="firefox")
    assert out["uuid"] == "u"
    assert out["hdr"] == "h"
    assert out["type"] == "grpc"
    assert out["fp"] == "firefox"
    assert out["host"] == ""
    assert out.get("uuid") == "u"
    assert out.get("missing", "dflt") == "dflt"
    assert "uuid" in out
    assert "nope" not in out
    with pytest.raises(KeyError):
        out["nope"]


def test_extra_params_visible():
    out = Outbound(extra={"cs": "TLS_AES_128_GCM_SHA256"})
    assert out["cs"] == "TLS_AES_128_GCM_SHA256"
    assert out.get("cs") == "TLS_AES_128_GCM_SHA256"


def test_ss_split():
    # canonical: credential = password, ss_method = method
    o = Outbound(scheme="ss", credential="pw", ss_method="chacha20-ietf-poly1305")
    assert o.ss_split() == ("chacha20-ietf-poly1305", "pw")
    # legacy: credential = "method:password"
    o = Outbound(scheme="ss", credential="aes-256-gcm:pw")
    assert o.ss_split() == ("aes-256-gcm", "pw")
    # legacy + method set (should strip duplicated method prefix)
    o = Outbound(scheme="ss", credential="aes-256-gcm:pw", ss_method="aes-256-gcm")
    assert o.ss_split() == ("aes-256-gcm", "pw")
    # fallback default
    o = Outbound(scheme="ss", credential="pw")
    assert o.ss_split() == ("aes-256-gcm", "pw")


def test_dict_roundtrip():
    out = Outbound(scheme="trojan", name="t", host="h", port="1",
                   credential="pw", extra={"x": "1"})
    out2 = Outbound.from_dict(out.to_dict())
    assert out2 == out


def test_copy_with():
    out = Outbound(scheme="ss", credential="pw", ss_method="m")
    out2 = out.copy_with(host="9.9.9.9")
    assert out2.host == "9.9.9.9" and out2.credential == "pw"


def test_vmess_json_payload():
    import base64, json
    payload = base64.b64encode(json.dumps(VMESS_PAYLOAD).encode()).decode()
    out = vmess_json_to_outbound(payload, "vmess://" + payload)
    assert out is not None
    assert out.scheme == "vmess"
    assert out.name == "vm-test"
    assert out.host == "104.18.1.1"
    assert out.credential == "b831381d-6324-4d53-ad4f-8cda48b30811"
    assert out.transport == "ws"
    assert out.security == "tls"
    assert out.path == "/vmray"


def test_vmess_garbage_returns_none():
    import base64
    bad = base64.b64encode(b"{not json").decode()
    assert vmess_json_to_outbound(bad) is None
    assert vmess_json_to_outbound("!!!") is None


def test_parse_targets_still_dict_compatible():
    """Existing call-sites use t['...'] indexing — must keep working."""
    from xray_forge.core.parser import parse_target
    t = parse_target(VLESS_TLS_WS)
    assert t["scheme"] == "vless"
    assert t["uuid"].startswith("13b8ac3f")
    assert t["hdr"] == "edgestuff.pages.dev"
    assert t["type"] == "ws"
    assert t["fp"] == "chrome"


def test_reality_fields_on_model():
    from xray_forge.core.parser import parse_target
    t = parse_target(VLESS_REALITY)
    assert t.security == "reality"
    assert t.public_key == "SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc"
    assert t.short_id == "6ba85179"
    assert t.flow == "xtls-rprx-vision"
    assert t.is_reality()
