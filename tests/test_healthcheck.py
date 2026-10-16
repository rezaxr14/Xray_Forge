"""Staged health-check pipeline tests (all network probes monkeypatched)."""

from __future__ import annotations

import base64

import pytest

from xray_forge.core import healthcheck as hc
from xray_forge.core.models import Outbound
from tests.fixtures import VLESS_TLS_WS, TROJAN_TLS


class FakeTLS:
    """Stand-in for probe.TLSClient: records writes, returns canned reads."""

    def __init__(self, reply: bytes = b"HTTP/1.1 101 Switching Protocols\r\n\r\n"):
        self.written: list[bytes] = []
        self._reply = reply

    def write(self, data: bytes) -> None:
        self.written.append(data)

    def read(self, n: int = 16384, deadline=None) -> bytes:
        chunk, self._reply = self._reply, b""
        return chunk


@pytest.fixture
def wired(monkeypatch):
    """Wire every probe to deterministic offline fakes."""
    # dns
    monkeypatch.setattr("xray_forge.core.probe.doh_resolve",
                        lambda host, timeout=4.0: ["188.114.97.6"])
    # tcp + jitter
    monkeypatch.setattr(hc, "tcp_ping",
                        lambda host, port, timeout=5.0, attempts=2, stop=None: 42.0)
    # tls
    def fake_tls_connect(host, port, sni=None, frag=None, timeout=6.0, stop=None, **kw):
        return FakeTLS(), object(), {"tls_ms": 55.0, "ver": "TLSv1.3"}
    monkeypatch.setattr(hc, "tls_connect", fake_tls_connect)
    # request (ws upgrade)
    def fake_ws_upgrade(tc, host_hdr, path, timeout, stop, **kw):
        return "HTTP/1.1 101 Switching Protocols", 70.0
    monkeypatch.setattr(hc, "ws_upgrade", fake_ws_upgrade)
    # native tunnel throughput
    class FakeTunnel:
        def __init__(self, *a, **k):
            pass
        def send(self, data: bytes) -> None:
            pass
    monkeypatch.setattr(hc, "VlessTunnel", FakeTunnel)
    monkeypatch.setattr(hc, "tunnel_http_get",
                        lambda tun, host, path, timeout, stop, **kw: (
                            120.0, "HTTP/1.1 200 OK", b"x" * 262144))
    # socks throughput
    monkeypatch.setattr(hc, "fetch_via_socks",
                        lambda ip, port, host, p, path, timeout=8.0,
                        method="GET", body=None: (90.0, "HTTP/1.1 200 OK",
                                                  b"y" * 262144))


def test_pipeline_full_success(wired):
    rep = hc.run_health_check(VLESS_TLS_WS)
    names = [s.name for s in rep.stages]
    assert names == ["dns", "tcp", "tls", "request", "download", "upload"]
    assert all(s.ok for s in rep.stages)
    assert rep.passed()
    assert rep.score >= 100 - 0.01 or rep.score <= 100  # capped at 100
    assert rep.score == 100.0  # all stages + latency bonus, capped
    assert any(t.startswith("fragment:") for t in rep.techniques)


def test_pipeline_tcp_failure_shortcircuits(wired, monkeypatch):
    monkeypatch.setattr(hc, "tcp_ping", lambda *a, **k: None)
    rep = hc.run_health_check(VLESS_TLS_WS)
    assert not rep.stage("tcp").ok
    assert not rep.passed()
    assert rep.score < 50


def test_pipeline_fragment_variant_tagging(wired, monkeypatch):
    """First frag variant fails, second succeeds -> tagged with the winner."""
    calls = {"n": 0}

    def flaky_tls(host, port, sni=None, frag=None, timeout=6.0, stop=None, **kw):
        calls["n"] += 1
        if calls["n"] == 1:  # variant "off"
            raise hc.ProbeError("tls", "reset by DPI")
        return FakeTLS(), object(), {"tls_ms": 60.0, "ver": "TLSv1.3"}
    monkeypatch.setattr(hc, "tls_connect", flaky_tls)
    rep = hc.run_health_check(VLESS_TLS_WS)
    assert rep.stage("tls").ok
    assert "fragment:5,94,1@2" in rep.techniques


def test_pipeline_unparsable():
    rep = hc.run_health_check("not a proxy line")
    assert not rep.stages[0].ok
    assert rep.score == 0


def test_pipeline_native_tunnel_unsupported(wired):
    """trojan configs can't use the native vless tunnel -> request fails."""
    rep = hc.run_health_check(TROJAN_TLS)
    assert not rep.stage("request").ok
    assert not rep.passed()


def test_score_weights():
    rep = hc.HealthReport(line="x")
    rep.stages = [
        hc.StageResult("dns", True), hc.StageResult("tcp", True),
        hc.StageResult("tls", True), hc.StageResult("request", True, ms=150),
    ]
    # 5+10+20+30 + 10 latency bonus = 75
    assert hc.score_report(rep) == 75.0


def test_rank_and_export_best(wired):
    lines = [VLESS_TLS_WS, TROJAN_TLS]
    reports = [hc.run_health_check(l) for l in lines]
    ranked = hc.rank_reports(reports)
    assert ranked[0].line == VLESS_TLS_WS  # trojan fails the request stage
    sub = hc.export_best_subscription(reports, top_n=5)
    decoded = base64.b64decode(sub).decode()
    assert VLESS_TLS_WS in decoded
    assert TROJAN_TLS not in decoded  # failing configs are excluded


def test_tagged_lines_includes_technique(wired, monkeypatch):
    monkeypatch.setattr(hc, "tls_connect", lambda host, port, sni=None,
                        frag=None, timeout=6.0, stop=None, **kw: (
                            FakeTLS(), object(), {"tls_ms": 50, "ver": "1.3"}))
    rep = hc.run_health_check(VLESS_TLS_WS)
    tags = hc.tagged_lines([rep])
    assert tags and "[fragment:" in tags[0]


def test_stage_result_throughput_bps(wired):
    res = hc.probe_throughput(Outbound(), None, None, "download",
                              socks_port=None)
    assert not res.ok  # no transport available
    assert "no transport" in res.detail
