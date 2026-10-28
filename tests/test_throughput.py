"""Throughput stage: real validation, fresh session per direction."""

from __future__ import annotations

import os

from xray_forge.core import healthcheck as hc
from xray_forge.core import probe
from xray_forge.core.parser import parse_target
from tests.fixtures import VLESS_TLS_WS as _URI

VLESS_TLS_WS = parse_target(_URI)


def _slow_mask(payload: bytes, mask: bytes) -> bytes:
    return bytes(b ^ mask[i & 3] for i, b in enumerate(payload))


def test_xor_mask_matches_reference():
    for n in (0, 1, 3, 4, 5, 1000, 65537):
        data = os.urandom(n)
        mask = os.urandom(4)
        assert probe._xor_mask(data, mask) == _slow_mask(data, mask)


def test_ws_frame_roundtrip_masked():
    frame = probe.ws_frame(2, b"hello world")
    assert frame[1] & 0x80  # client frames must be masked
    mask = frame[2:6]
    assert _slow_mask(frame[6:], mask) == b"hello world"


def _patch(monkeypatch, get=None, post=None):
    monkeypatch.setattr(hc, "VlessTunnel", lambda *a, **k: object())
    if get:
        monkeypatch.setattr(hc, "tunnel_http_get", get)
    if post:
        monkeypatch.setattr(hc, "tunnel_http_post", post)


def test_download_short_body_fails(monkeypatch):
    _patch(monkeypatch, get=lambda *a, **k: (100.0, "HTTP/1.1 200 OK", b"x" * 1000))
    r = hc.probe_throughput(VLESS_TLS_WS, object(), None, "download",
                            bytes_count=262144)
    assert not r.ok and "short body" in r.detail


def test_download_http_error_fails(monkeypatch):
    _patch(monkeypatch, get=lambda *a, **k: (100.0, "HTTP/1.1 403 Forbidden",
                                              b"x" * 262144))
    r = hc.probe_throughput(VLESS_TLS_WS, object(), None, "download")
    assert not r.ok and "403" in r.detail


def test_download_ok_reports_bps(monkeypatch):
    _patch(monkeypatch, get=lambda *a, **k: (500.0, "HTTP/1.1 200 OK", b"x" * 262144))
    r = hc.probe_throughput(VLESS_TLS_WS, object(), None, "download")
    assert r.ok and r.data["bytes"] == 262144
    assert r.data["bps"] == round(262144 / 0.5)


def test_upload_requires_server_ack(monkeypatch):
    _patch(monkeypatch, post=lambda *a, **k: (300.0, "HTTP/1.1 502 Bad Gateway", b""))
    r = hc.probe_throughput(VLESS_TLS_WS, object(), None, "upload")
    assert not r.ok and "502" in r.detail


def test_upload_default_is_at_least_one_mib(monkeypatch):
    seen = {}

    def post(tun, host, path, nbytes, timeout, stop):
        seen["n"] = nbytes
        return 400.0, "HTTP/1.1 200 OK", b""
    _patch(monkeypatch, post=post)
    r = hc.probe_throughput(VLESS_TLS_WS, object(), None, "upload")
    assert r.ok and seen["n"] >= 1024 * 1024


def test_upload_uses_fresh_session(monkeypatch):
    made, closed = [], []

    class Sock:
        def close(self):
            closed.append(1)

    def factory():
        made.append(1)
        return object(), Sock()
    _patch(monkeypatch, post=lambda *a, **k: (10.0, "HTTP/1.1 200 OK", b""))
    r = hc.probe_throughput(VLESS_TLS_WS, object(), None, "upload",
                            tunnel_factory=factory)
    assert r.ok and made == [1] and closed == [1]


def test_probe_error_is_a_failed_stage(monkeypatch):
    def boom(*a, **k):
        raise probe.ProbeError("net", "reset")
    _patch(monkeypatch, post=boom)
    r = hc.probe_throughput(VLESS_TLS_WS, object(), None, "upload")
    assert not r.ok and "reset" in r.detail
