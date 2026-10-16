"""
Unit tests for Xray Forge core features.
"""
import base64
import os

import pytest

from xray_forge.core.dedup import dedup_configs
from xray_forge.core.subscription import decode_subscription, is_base64_config
from xray_forge.core.settings import load_settings, save_settings, settings_path
from xray_forge.core.parser import (
    convert_block,
    export_to_clash,
    export_to_singbox,
    export_to_sub,
    parse_target,
)


@pytest.fixture(autouse=True)
def clean_settings():
    """Remove settings.json before/after each test to avoid state leakage."""
    sp = settings_path()
    if os.path.exists(sp):
        os.remove(sp)
    yield
    if os.path.exists(sp):
        os.remove(sp)


def test_dedup_removes_duplicates():
    lines = [
        "vless://u1@1.1.1.1:443?security=tls#a",
        "vless://u1@1.1.1.1:443?security=tls#b",  # duplicate uuid+host+port
        "vless://u2@2.2.2.2:443?security=tls#c",
    ]
    out, removed = dedup_configs(lines)
    assert removed == 1
    assert len(out) == 2


def test_dedup_keeps_non_proxy_lines():
    lines = ["not a proxy line", "vless://u1@1.1.1.1:443#a"]
    out, removed = dedup_configs(lines)
    assert removed == 0
    assert len(out) == 2


def test_subscription_base64_detection():
    plain = "vless://uuid@1.1.1.1:443#test"
    b64 = base64.b64encode(plain.encode()).decode()
    assert is_base64_config(b64)
    assert not is_base64_config(plain)
    assert decode_subscription(b64) == [plain]


def test_settings_roundtrip():
    save_settings({"k": "v"})
    assert load_settings().get("k") == "v"


def test_convert_and_exports():
    text = (
        "vless://13b8ac3f-e8de-4b2d-82db-e9130d288a54@"
        "188.114.97.6:443?security=tls&sni=x&fp=chrome&type=ws&"
        "host=x&path=%2Fchannel#t"
    )
    lines, names, c = convert_block(
        text, "chrome", "", "", False, True, "{id}_{sub}", 1)
    assert c["fixed"] == 1
    assert names
    assert parse_target(lines[0]) is not None

    clash = export_to_clash(lines)
    assert "proxies" in clash and "vless" in clash

    singbox = export_to_singbox(lines)
    assert "outbounds" in singbox

    sub = export_to_sub(lines)
    assert base64.b64decode(sub).decode().startswith("vless://")


def test_parse_target_fields():
    t = parse_target(
        "vless://uuid123@1.1.1.1:443?security=tls&sni=example.com&"
        "type=ws&path=/x&host=example.com#my name")
    assert t["scheme"] == "vless"
    assert t["uuid"] == "uuid123"
    assert t["host"] == "1.1.1.1"
    assert t["port"] == "443"
    assert t["name"] == "my name"
