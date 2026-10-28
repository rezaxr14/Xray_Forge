"""Subscription pipeline tests: format sniffing, conversion, SourceManager."""

from __future__ import annotations

import base64
import json

import pytest

from xray_forge.core.subscription import (
    sniff_format, text_to_lines, decode_subscription, is_base64_config,
)
from xray_forge.core.sub_source import Source, SourceManager
from xray_forge.core.parser import parse_target
from tests.fixtures import VLESS_TLS_WS, VMESS_B64, TROJAN_TLS, SS_SIP002


# ------------------------------------------------------------- format sniff

def test_sniff_base64_and_plain():
    b64 = base64.b64encode(f"{VLESS_TLS_WS}\n{TROJAN_TLS}".encode()).decode()
    assert sniff_format(b64) == "base64"
    assert sniff_format(f"{VLESS_TLS_WS}\n{TROJAN_TLS}") == "plain"


def test_sniff_clash_and_singbox():
    clash = "proxies:\n  - name: a\n    type: ss\n    server: 1.1.1.1\n    port: 443\n"
    assert sniff_format(clash) == "clash"
    sb = json.dumps({"outbounds": [{"type": "vless", "tag": "t",
                                    "server": "1.1.1.1", "server_port": 443}]})
    assert sniff_format(sb) == "singbox"


def test_text_to_lines_base64():
    b64 = base64.b64encode(f"{VLESS_TLS_WS}\n{TROJAN_TLS}".encode()).decode()
    lines = text_to_lines(b64)
    assert lines == [VLESS_TLS_WS, TROJAN_TLS]


def test_text_to_lines_clash():
    clash = """
proxies:
  - name: hy
    type: hysteria2
    server: 3.3.3.3
    port: 443
    password: hpw
    sni: h.com
"""
    lines = text_to_lines(clash)
    assert len(lines) == 1
    out = parse_target(lines[0])
    assert out.scheme == "hysteria2"
    assert out.credential == "hpw"
    assert out.host == "3.3.3.3"


def test_text_to_lines_singbox():
    sb = json.dumps({"outbounds": [
        {"type": "ss", "tag": "s1", "server": "2.2.2.2", "server_port": 8388,
         "method": "aes-256-gcm", "password": "ppp"},
        {"type": "direct", "tag": "direct"},
    ]})
    lines = text_to_lines(sb)
    assert len(lines) == 1
    out = parse_target(lines[0])
    assert out.scheme == "ss"
    assert out.ss_method == "aes-256-gcm"
    assert out.credential == "ppp"


# ------------------------------------------------------------ legacy helpers

def test_legacy_decode_subscription():
    b64 = base64.b64encode(VLESS_TLS_WS.encode()).decode()
    assert is_base64_config(b64)
    assert decode_subscription(b64) == [VLESS_TLS_WS]
    assert decode_subscription("") == []


# ------------------------------------------------------------ SourceManager

@pytest.fixture
def mgr(tmp_path):
    return SourceManager(state_path=str(tmp_path / "sources.json"),
                         cache_dir=str(tmp_path / "cache"))


def test_source_add_remove_persist(mgr):
    s = mgr.add("https://example.com/sub", "test")
    assert s.name == "test"
    assert mgr.add("https://example.com/sub").url == s.url  # no duplicate
    assert len(mgr.list_sources()) == 1
    # persisted to disk
    mgr2 = SourceManager(state_path=mgr.state_path, cache_dir=mgr.cache_dir)
    assert len(mgr2.list_sources()) == 1
    assert mgr.remove("https://example.com/sub")
    assert not mgr.remove("https://example.com/sub")


def test_source_fetch_etag_cache(mgr, monkeypatch):
    src = mgr.add("https://example.com/sub")
    text = base64.b64encode(VLESS_TLS_WS.encode()).decode()
    calls = []

    def fake_get(url, etag="", timeout=15.0):
        calls.append(etag)
        if len(calls) == 1:
            return 200, text, '"etag-1"'
        return 304, "", '"etag-1"'

    monkeypatch.setattr(mgr, "_http_get", fake_get)
    lines = mgr.fetch(src)
    assert lines == [VLESS_TLS_WS]
    assert src.etag == '"etag-1"'
    assert src.last_count == 1

    # second fetch: 304 -> served from cache, etag resent
    lines = mgr.fetch(src)
    assert lines == [VLESS_TLS_WS]
    assert calls[1] == '"etag-1"'
    assert src.last_status == "304 not modified"


def test_source_fetch_failure_falls_back_to_cache(mgr, monkeypatch):
    src = mgr.add("https://example.com/sub")
    text = base64.b64encode(VLESS_TLS_WS.encode()).decode()

    def fake_get(url, etag="", timeout=15.0):
        if not etag:
            return 200, text, '"e1"'
        raise OSError("network down")

    monkeypatch.setattr(mgr, "_http_get", fake_get)
    assert mgr.fetch(src)
    lines = mgr.fetch(src)  # network fails -> cache used
    assert lines == [VLESS_TLS_WS]
    assert "error" in src.last_status


def test_fetch_all_skips_disabled(mgr, monkeypatch):
    mgr.add("https://a.example/sub")
    mgr.add("https://b.example/sub")
    mgr.set_enabled("https://b.example/sub", False)
    monkeypatch.setattr(
        mgr, "_http_get",
        lambda url, etag="", timeout=15.0: (
            200, base64.b64encode(VMESS_B64.encode()).decode(), '"e"'))
    out = mgr.fetch_all()
    assert set(out.keys()) == {"https://a.example/sub"}


def test_combined_lines_dedup(mgr, monkeypatch):
    mgr.add("https://a.example/sub")
    monkeypatch.setattr(
        mgr, "_http_get",
        lambda url, etag="", timeout=15.0: (
            200, f"{SS_SIP002}\n{SS_SIP002}", '"e"'))
    mgr.fetch_all()
    lines, removed = mgr.combined_lines(dedupe=True)
    assert len(lines) == 1
    assert removed == 1
