"""Staged health-check pipeline tests (all network probes monkeypatched)."""

from __future__ import annotations

import base64
import contextlib
import json

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
    monkeypatch.setattr(hc, "tunnel_http_post",
                        lambda tun, host, path, nbytes, timeout, stop: (
                            200.0, "HTTP/1.1 200 OK", b""))
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
    from xray_forge.core.parser import parse_target
    assert tags and "[fragment:" in parse_target(tags[0]).name


def test_stage_result_throughput_bps(wired):
    res = hc.probe_throughput(Outbound(), None, None, "download",
                              socks_port=None)
    assert not res.ok  # no transport available
    assert "no transport" in res.detail


# ===========================================================================
# Core-backed stages (request/throughput via a real core's SOCKS inbound)
# ===========================================================================

GEO_BODY = json.dumps({"status": "success", "countryCode": "de",
                       "query": "5.6.7.8"}).encode()


@contextlib.contextmanager
def fake_core_ctx(out, core, binary=None):
    yield 19876


def test_probe_request_socks_ok(wired, monkeypatch):
    monkeypatch.setattr(hc, "fetch_via_socks",
                        lambda *a, **k: (88.0, "HTTP/1.1 200 OK", GEO_BODY))
    res = hc.probe_request_socks(19876)
    assert res.ok
    assert res.data["cc"] == "DE"
    assert res.data["exit_ip"] == "5.6.7.8"


def test_probe_request_socks_bad_status(wired, monkeypatch):
    monkeypatch.setattr(hc, "fetch_via_socks",
                        lambda *a, **k: (30.0, "HTTP/1.1 502 Bad Gateway", b""))
    res = hc.probe_request_socks(19876)
    assert not res.ok


def test_probe_request_socks_error(wired, monkeypatch):
    def boom(*a, **k):
        raise hc.ProbeError("socks", "connection refused")
    monkeypatch.setattr(hc, "fetch_via_socks", boom)
    res = hc.probe_request_socks(19876)
    assert not res.ok
    assert "refused" in res.detail


def test_core_context_none_cases(wired, monkeypatch):
    assert hc._core_context(Outbound(), None) is None
    assert hc._core_context(Outbound(), "nosuchcore") is None
    from xray_forge.core.cores import get_core
    monkeypatch.setattr(get_core("xray"), "find_binary", lambda: "")
    out = Outbound(scheme="trojan", name="t", host="203.0.113.10", port="443",
                   credential="pw")
    assert hc._core_context(out, "xray") is None


def test_core_context_auto_picks_installed_core(wired, monkeypatch):
    """auto: with a (fake) binary found, a supporting core is selected."""
    from xray_forge.core.cores import iter_cores
    for c in iter_cores():
        monkeypatch.setattr(c, "find_binary", lambda: "/fake/bin",
                            raising=False)
    out = Outbound(scheme="trojan", name="t", host="203.0.113.10", port="443",
                   credential="pw")
    ctx = hc._core_context(out, "auto")
    assert ctx is not None


def test_pipeline_core_backed_request(wired, monkeypatch):
    """A trojan config (no native tunnel) passes fully via a spawned core."""
    monkeypatch.setattr(hc, "_core_context",
                        lambda out, core, binary=None:
                        fake_core_ctx(out, core, binary))
    rep = hc.run_health_check(TROJAN_TLS, core="xray")
    names = [s.name for s in rep.stages]
    assert names == ["dns", "tcp", "tls", "request", "download", "upload"]
    assert rep.passed()
    assert all(s.ok for s in rep.stages)


def test_pipeline_core_backed_country_in_request(wired, monkeypatch):
    monkeypatch.setattr(hc, "fetch_via_socks",
                        lambda *a, **k: (90.0, "HTTP/1.1 200 OK", GEO_BODY))
    monkeypatch.setattr(hc, "_core_context",
                        lambda out, core, binary=None:
                        fake_core_ctx(out, core, binary))
    rep = hc.run_health_check(TROJAN_TLS, core="xray")
    assert rep.stage("request").data.get("cc") == "DE"


def test_pipeline_core_unavailable_keeps_native_failure(wired, monkeypatch):
    """No usable core -> request stage still fails (native unsupported)."""
    monkeypatch.setattr(hc, "_core_context", lambda out, core, binary=None: None)
    rep = hc.run_health_check(TROJAN_TLS, core="xray")
    assert not rep.stage("request").ok
    assert not rep.passed()


def test_run_health_checks_progress_and_stop(wired):
    seen = []
    reports = hc.run_health_checks([VLESS_TLS_WS, TROJAN_TLS], workers=2,
                                   progress=lambda d, t: seen.append((d, t)))
    assert len(reports) == 2
    assert seen[-1] == (2, 2)
    stop_seen = []
    hc.run_health_checks([VLESS_TLS_WS, TROJAN_TLS], workers=1,
                         progress=lambda d, t: stop_seen.append(d),
                         stop=__import__("threading").Event())
    # stop never set -> everything still reported
    assert stop_seen == [1, 2]


def _report(line, score, request_ok):
    r = hc.HealthReport(line=line, name=line[-6:], scheme="vless", score=score)
    r.stages.append(hc.StageResult("tls", True, ms=10.0))
    r.stages.append(hc.StageResult("request", request_ok, ms=20.0))
    return r


def test_best_n_counts_only_working_configs():
    """A failing config that outscores working ones must not use up a slot
    (it used to: the top N were taken first and failures dropped afterwards,
    so best-1 here exported nothing)."""
    failing_high = _report("vless://a@1.1.1.1:443#aaaaaa", 70.0, request_ok=False)
    ok_low = _report("vless://b@2.2.2.2:443#bbbbbb", 60.0, request_ok=True)
    ok_lower = _report("vless://c@3.3.3.3:443#cccccc", 50.0, request_ok=True)
    reports = [failing_high, ok_lower, ok_low]
    got = base64.b64decode(hc.export_best_subscription(reports, top_n=1)).decode()
    assert got == ok_low.line
    got2 = base64.b64decode(hc.export_best_subscription(reports, top_n=5)).decode().split("\n")
    assert got2 == [ok_low.line, ok_lower.line]
    assert hc.export_best_subscription([failing_high], top_n=3) == ""


def _tagged_report(line, techniques):
    r = hc.HealthReport(line=line, name="x", scheme="vless", score=90.0,
                        techniques=list(techniques))
    r.stages.append(hc.StageResult("request", True, ms=10.0))
    return r


def test_tagged_lines_tag_the_name_and_leave_the_link_intact():
    """The tag used to be appended to the URL *query* (path became
    '/channel [fragment:5,94,1@2]'), corrupting the config."""
    from xray_forge.core.parser import parse_target
    before = parse_target(VLESS_TLS_WS)
    tagged = hc.tagged_lines([_tagged_report(VLESS_TLS_WS, ["fragment:5,94,1@2"])])[0]
    after = parse_target(tagged)
    assert after.name == "CF worker [fragment:5,94,1@2]"
    for field in ("host", "port", "credential", "path", "sni", "host_header",
                  "transport", "security", "fingerprint"):
        assert getattr(after, field) == getattr(before, field), field
    assert " " not in tagged.split("#", 1)[0]          # no stray space inside the URL


def test_tagged_lines_vmess_and_ipv6_and_idempotence():
    from tests.fixtures import VMESS_B64
    from xray_forge.core.parser import parse_target
    v6 = "vless://u@[2001:db8::1]:443?security=tls&type=ws&path=%2Fp#six"
    for line in (VMESS_B64, v6):
        once = hc.tagged_lines([_tagged_report(line, ["fake-sni"])])[0]
        out = parse_target(once)
        assert out is not None and out.name.endswith(" [fake-sni]")
        assert parse_target(line).path == out.path
        assert hc.tagged_lines([_tagged_report(once, ["fake-sni"])])[0] == once
    assert hc.tagged_lines([_tagged_report(VLESS_TLS_WS, [])])[0] == VLESS_TLS_WS
