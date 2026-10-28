"""Regression tests for health-check robustness (stop, empty variants, core failure)."""

from __future__ import annotations

import contextlib
import threading
import time

from xray_forge.core import healthcheck as hc
from xray_forge.core.models import Outbound
from tests.fixtures import VLESS_TLS_WS


def test_stop_cancels_queued_probes(monkeypatch):
    """Pressing stop must not still run every queued config."""
    calls: list[str] = []

    def slow_probe(line, **kw):
        calls.append(line)
        time.sleep(0.05)
        return hc.HealthReport(line=line)

    monkeypatch.setattr(hc, "run_health_check", slow_probe)
    stop = threading.Event()

    def progress(done, total):
        if done == 2:
            stop.set()

    reports = hc.run_health_checks([f"vless://x{i}" for i in range(40)],
                                   workers=2, progress=progress, stop=stop)
    assert len(reports) < 40
    # 2 finished + at most a few already running when stop fired
    assert len(calls) <= 8, f"{len(calls)} probes still ran after stop"


def test_stop_event_reaches_in_flight_probes(monkeypatch):
    seen: list[object] = []

    def probe(line, **kw):
        seen.append(kw.get("stop"))
        return hc.HealthReport(line=line)

    monkeypatch.setattr(hc, "run_health_check", probe)
    stop = threading.Event()
    hc.run_health_checks(["a", "b"], workers=1, stop=stop)
    assert seen == [stop, stop]


def test_probe_tls_with_no_variants_fails_cleanly():
    res, session, tag = hc.probe_tls(Outbound(host="203.0.113.1"), frag_variants=())
    assert res.ok is False and res.name == "tls"
    assert session == (None, None)
    assert tag == ""


def test_core_start_failure_keeps_earlier_stages(monkeypatch):
    class FakeSock:
        def close(self):
            pass

    monkeypatch.setattr(hc, "probe_dns",
                        lambda host, timeout=4.0: hc.StageResult("dns", True, ms=5.0))
    monkeypatch.setattr(hc, "probe_tcp",
                        lambda host, port, timeout=5.0: hc.StageResult("tcp", True, ms=9.0))
    monkeypatch.setattr(hc, "probe_tls",
                        lambda out, variants, timeout=6.0, stop=None: (
                            hc.StageResult("tls", True, ms=20.0,
                                           data={"variant": "off"}),
                            (object(), FakeSock()), "fragment:off"))
    monkeypatch.setattr(hc, "probe_request",
                        lambda out, tc, sock, timeout=8.0, stop=None: hc.StageResult(
                            "request", False, detail="native tunnel unsupported"))

    @contextlib.contextmanager
    def dying_core():
        raise RuntimeError("xray exited: bad config")
        yield  # pragma: no cover

    monkeypatch.setattr(hc, "_core_context",
                        lambda out, core, binary=None: dying_core())

    rep = hc.run_health_check(VLESS_TLS_WS, core="xray")
    names = [s.name for s in rep.stages]
    assert names[:3] == ["dns", "tcp", "tls"]       # nothing was thrown away
    core = rep.stage("core")
    assert core is not None and not core.ok and "xray exited" in core.detail
    assert rep.passed() is False
