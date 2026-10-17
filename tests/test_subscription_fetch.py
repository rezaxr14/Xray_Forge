"""fetch_subscription / SourceManager hardening (real local server, no mocks
of the transport)."""

from __future__ import annotations

import base64
import json

import pytest

pytest.importorskip("cryptography")

from xray_forge.core import probe, subscription as sub           # noqa: E402
from xray_forge.core.probe import ProbeError                      # noqa: E402
from xray_forge.core.sub_source import SourceManager              # noqa: E402
from tests.fixtures import VLESS_TLS_WS, TROJAN_TLS               # noqa: E402
from tests.localserver import LocalServer                         # noqa: E402

SINGBOX = json.dumps({"outbounds": [{
    "type": "vless", "tag": "sb-node", "server": "198.51.100.9",
    "server_port": 443, "uuid": "13b8ac3f-e8de-4b2d-82db-e9130d288a54",
    "tls": {"enabled": True, "server_name": "front.example.com"},
    "transport": {"type": "ws", "path": "/x",
                  "headers": {"Host": "front.example.com"}}}]})


def _urlsafe_payload() -> str:
    """A base64url subscription that really contains '-' or '_'."""
    lines = f"{VLESS_TLS_WS}\n{TROJAN_TLS}\nvless://u@1.1.1.1:443#éèêÿþ"
    enc = base64.urlsafe_b64encode(lines.encode()).decode().rstrip("=")
    assert "-" in enc or "_" in enc, "test premise: need url-safe characters"
    return enc


@pytest.fixture
def server(tmp_path, monkeypatch):
    monkeypatch.setattr(probe, "doh_resolve", lambda host, timeout=4.0: [])
    routes = {
        "/singbox": (200, {}, SINGBOX.encode(), True),
        "/urlsafe": (200, {}, _urlsafe_payload().encode(), True),
        "/big": (200, {}, b"A" * 50_000, True),
    }
    srv = LocalServer(str(tmp_path), routes, tls=True)
    real = probe.direct_get_text
    # trust the throw-away CA for these tests only
    monkeypatch.setattr(sub, "direct_get_text",
                        lambda url, **kw: real(url, cafile=srv.cafile, **kw))
    yield srv
    srv.close()


def test_singbox_json_subscription_is_fetched(server):
    """Used to return [] (the dict was str()-ed into Python repr)."""
    lines = sub.fetch_subscription(server.base + "/singbox")
    assert len(lines) == 1 and lines[0].startswith("vless://")
    assert "198.51.100.9" in lines[0]


def test_urlsafe_base64_subscription_is_decoded(server):
    lines = sub.fetch_subscription(server.base + "/urlsafe")
    assert VLESS_TLS_WS in lines and TROJAN_TLS in lines and len(lines) == 3


def test_urlsafe_base64_decoding_directly():
    assert sub.is_base64_config(_urlsafe_payload())
    assert len(sub.decode_subscription(_urlsafe_payload())) == 3


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://example.com/s",
                                 "gopher://x/y", "/just/a/path"])
def test_non_http_subscription_urls_are_rejected(url):
    with pytest.raises(ProbeError, match="http"):
        sub.fetch_subscription(url)


def test_oversized_subscription_is_rejected(server):
    with pytest.raises(ProbeError) as ei:
        sub.fetch_subscription(server.base + "/big", max_bytes=1000)
    assert ei.value.stage == "sub"


# ------------------------------------------------------------ SourceManager

def _manager(tmp_path):
    return SourceManager(state_path=str(tmp_path / "sources.json"),
                         cache_dir=str(tmp_path / "cache"))


def test_source_cache_survives_a_captive_portal_response(tmp_path, monkeypatch):
    mgr = _manager(tmp_path)
    src = mgr.add("https://example.com/sub")
    good = f"{VLESS_TLS_WS}\n{TROJAN_TLS}"
    monkeypatch.setattr(mgr, "_http_get", lambda url, etag="", timeout=15.0:
                        (200, good, "etag-1"))
    assert mgr.fetch(src, force=True) == [VLESS_TLS_WS, TROJAN_TLS]

    # next fetch: HTTP 200 with a block/captive page -> must keep the cache
    monkeypatch.setattr(mgr, "_http_get", lambda url, etag="", timeout=15.0:
                        (200, "<html>Access denied</html>", "etag-2"))
    again = mgr.fetch(src, force=True)
    assert again == [VLESS_TLS_WS, TROJAN_TLS]
    assert src.last_status.startswith("error")
    assert src.etag == "etag-1"                       # not advanced to the bad one
    assert mgr.combined_lines()[0] == [VLESS_TLS_WS, TROJAN_TLS]


def test_source_manager_refuses_non_http_urls(tmp_path):
    mgr = _manager(tmp_path)
    with pytest.raises(ValueError, match="http"):
        mgr._http_get("file:///etc/passwd")
