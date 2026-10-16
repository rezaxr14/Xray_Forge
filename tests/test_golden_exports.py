"""Golden tests: export output structure for Clash/Mihomo and sing-box.

The expected structures are compared against *parsed* output (not raw text)
so YAML formatting differences across PyYAML versions cannot break CI.
"""

from __future__ import annotations

import json

import yaml

from xray_forge.core.parser import export_to_clash, export_to_singbox, parse_target
from tests.fixtures import (
    VLESS_TLS_WS, VLESS_REALITY, VMESS_B64, TROJAN_TLS, SS_SIP002,
    HYSTERIA2, TUIC,
)


def _clash_of(line):
    return yaml.safe_load(export_to_clash([line]))["proxies"][0]


def _singbox_of(line):
    return json.loads(export_to_singbox([line]))["outbounds"][0]


# --------------------------------------------------------------- VLESS+TLS+ws

def test_golden_vless_tls_ws_clash():
    px = _clash_of(VLESS_TLS_WS)
    assert px == {
        "name": "CF worker",
        "type": "vless",
        "server": "188.114.97.6",
        "port": 443,
        "uuid": "13b8ac3f-e8de-4b2d-82db-e9130d288a54",
        "cipher": "auto",
        "tls": True,
        "servername": "edgestuff.pages.dev",
        "client-fingerprint": "chrome",
        "skip-cert-verify": False,
        "network": "ws",
        "ws-opts": {"path": "/channel",
                    "headers": {"Host": "edgestuff.pages.dev"}},
    }


def test_golden_vless_tls_ws_singbox():
    ob = _singbox_of(VLESS_TLS_WS)
    assert ob["type"] == "vless"
    assert ob["server_port"] == 443
    assert ob["uuid"] == "13b8ac3f-e8de-4b2d-82db-e9130d288a54"
    assert ob["tls"]["server_name"] == "edgestuff.pages.dev"
    assert ob["tls"]["utls"] == {"enabled": True, "fingerprint": "chrome"}
    assert ob["transport"] == {"type": "ws", "path": "/channel",
                               "headers": {"Host": "edgestuff.pages.dev"}}


# ------------------------------------------------------------------- REALITY

def test_golden_reality_clash():
    """Reality exports must carry real public-key/short-id (regression test:
    these used to be exported as empty strings, producing broken configs)."""
    px = _clash_of(VLESS_REALITY)
    assert px["tls"] is True
    assert px["cipher"] == "none"
    assert px["flow"] == "xtls-rprx-vision"
    assert px["reality-opts"] == {
        "public-key": "SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc",
        "short-id": "6ba85179",
    }


def test_golden_reality_singbox():
    ob = _singbox_of(VLESS_REALITY)
    reality = ob["tls"]["reality"]
    assert reality["enabled"] is True
    assert reality["public_key"] == "SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc"
    assert reality["short_id"] == "6ba85179"
    assert "utls" not in ob["tls"]  # reality carries its own fingerprint


# ------------------------------------------------------------------ VMess/SS

def test_golden_vmess_clash():
    px = _clash_of(VMESS_B64)
    assert px["type"] == "vmess"
    assert px["uuid"] == "b831381d-6324-4d53-ad4f-8cda48b30811"
    assert px["alterId"] == 0
    assert px["cipher"] == "auto"
    assert px["ws-opts"]["path"] == "/vmray"


def test_golden_ss_clash():
    px = _clash_of(SS_SIP002)
    assert px["type"] == "ss"
    assert px["cipher"] == "aes-256-gcm"
    assert px["password"] == "seekrit-password"


def test_golden_ss_singbox():
    ob = _singbox_of(SS_SIP002)
    assert ob["method"] == "aes-256-gcm"
    assert ob["password"] == "seekrit-password"


# ------------------------------------------------------- Hysteria2 / TUIC

def test_golden_hysteria2_singbox():
    ob = _singbox_of(HYSTERIA2)
    assert ob["type"] == "hysteria2"
    assert ob["password"] == "hy2pass"
    assert ob["obfs"] == {"type": "salamander", "password": "obfspass"}
    assert ob["tls"]["insecure"] is True


def test_golden_tuic_clash():
    px = _clash_of(TUIC)
    assert px["type"] == "tuic"
    assert px["uuid"] == "tuic-uuid"
    assert px["password"] == "tuicpass"
    assert px["congestion-controller"] == "bbr"


def test_golden_multi_export():
    lines = [VLESS_TLS_WS, TROJAN_TLS, SS_SIP002]
    proxies = yaml.safe_load(export_to_clash(lines))["proxies"]
    assert [p["type"] for p in proxies] == ["vless", "trojan", "ss"]
    obs = json.loads(export_to_singbox(lines))["outbounds"]
    assert [o["type"] for o in obs] == ["vless", "trojan", "ss"]


def test_export_skips_unparsable_lines():
    out = export_to_clash(["garbage", VLESS_TLS_WS])
    proxies = yaml.safe_load(out)["proxies"]
    assert len(proxies) == 1
