"""Resumable scan session tests (probes monkeypatched, offline)."""

from __future__ import annotations

import threading

import pytest

from xray_forge.core.scan_session import ScanSession, ScanResult


class FakeProbeError(Exception):
    pass


@pytest.fixture
def wired(monkeypatch):
    monkeypatch.setattr("xray_forge.core.scan_session.sample_cidr",
                        lambda cidr, count: [f"1.2.3.{i}" for i in range(1, count + 1)])
    monkeypatch.setattr("xray_forge.core.scan_session.tcp_jitter",
                        lambda ip, port, attempts=2, timeout=3.0, **kw:
                        (40.0, 3.0) if ip.endswith(("1", "2", "3")) else (None, 0.0))
    def fake_tls_connect(ip, port, sni=None, frag=None, timeout=5.0, stop=None, **kw):
        if ip.endswith(("1", "2", "3")):
            return object(), object(), {"tls_ms": 50.0, "ver": "TLSv1.3"}
        raise FakeProbeError("tcp", "timeout (filtered or dead)")
    import xray_forge.core.probe as probe_mod
    monkeypatch.setattr(probe_mod, "tls_connect", fake_tls_connect)
    # scan_session imported tls_connect by name — patch there too
    import xray_forge.core.scan_session as scan_mod
    monkeypatch.setattr(scan_mod, "tls_connect", fake_tls_connect)
    monkeypatch.setattr("xray_forge.core.scan_session.ip_meta",
                        lambda ip: ("US", "Cloudflare, Inc."))
    # curl probe unused (use_curl=False by default)


def test_targets_sampling(wired, tmp_path):
    s = ScanSession("t1", state_dir=str(tmp_path))
    assert s.set_targets(["1.2.3.0/24"], count=10) == 10
    assert len(s.pending) == 10


def test_run_marks_alive_with_meta(wired, tmp_path):
    s = ScanSession("t2", state_dir=str(tmp_path))
    s.set_targets(["1.2.3.0/24"], count=5)
    new = s.run(port="443", workers=4, geo=True)
    assert len(new) == 5
    alive = s.alive()
    assert len(alive) == 3
    assert all(r.cc == "US" and r.isp == "Cloudflare, Inc." for r in alive)
    assert alive[0].ms <= alive[-1].ms  # sorted by latency
    assert all(r.jitter == 3.0 for r in alive)


def test_resume_across_sessions(wired, tmp_path):
    s1 = ScanSession("t3", state_dir=str(tmp_path))
    s1.set_targets(["1.2.3.0/24"], count=6)
    stop = threading.Event()
    # stop before anything scans: pending stays untouched
    stop.set()
    s1.run(port="443", workers=2, stop=stop)
    assert len(s1.pending) == 6
    # resume in a fresh session object (as a restarted process would)
    s2 = ScanSession("t3", state_dir=str(tmp_path))
    assert len(s2.pending) == 6
    s2.run(port="443", workers=4, stop=None)
    assert s2.pending == []
    assert len(s2.alive()) == 3
    # a third session loads the finished state
    s3 = ScanSession("t3", state_dir=str(tmp_path))
    assert len(s3.results) == 6


def test_export_csv_json(wired, tmp_path):
    s = ScanSession("t4", state_dir=str(tmp_path))
    s.set_targets(["1.2.3.0/24"], count=4)
    s.run(port="443", workers=4)
    csv_path = s.export_csv(str(tmp_path / "out.csv"))
    json_path = s.export_json(str(tmp_path / "out.json"))
    import csv as csv_mod, json
    with open(csv_path, newline="", encoding="utf-8") as f:
        rows = list(csv_mod.reader(f))
    assert rows[0][:3] == ["ip", "port", "alive"]
    assert len(rows) == 5  # header + 4
    data = json.load(open(json_path, encoding="utf-8"))
    assert len(data["results"]) == 4


def test_by_isp_grouping(wired, tmp_path):
    s = ScanSession("t5", state_dir=str(tmp_path))
    s.set_targets(["1.2.3.0/24"], count=4)
    s.run(port="443", workers=4)
    groups = s.by_isp()
    assert list(groups) == ["Cloudflare, Inc."]
    assert len(groups["Cloudflare, Inc."]) == 3


def test_scanresult_roundtrip():
    r = ScanResult(ip="1.1.1.1", port="443", alive=True, ms=10.0)
    assert ScanResult.from_dict(r.to_dict()) == r
