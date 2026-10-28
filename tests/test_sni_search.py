"""SNI / fronting-host search tests (probes monkeypatched, offline)."""

from __future__ import annotations

import json
import threading

import pytest

from xray_forge.core.sni_search import (
    SniHit, SniSearch, DEFAULT_SNI_CANDIDATES, targets_from_scan,
)
from xray_forge.core.probe import ProbeError


class FakeTLS:
    def __init__(self, answer: bytes = b""):
        self._answer = answer

    def write(self, data: bytes) -> None:
        pass

    def read(self, n: int = 16384, deadline=None) -> bytes:
        return self._answer


def _wired(monkeypatch, http_answer: bytes = b"HTTP/1.1 400 Bad Request\r\n"):
    """tls_connect succeeds for IPs ending in 1-3, fails otherwise."""

    def fake_tls_connect(ip, port, sni=None, frag=None, timeout=5.0,
                         stop=None, **kw):
        if ip.endswith(("1", "2", "3")):
            if sni == "blocked.example":
                raise ProbeError("tls", "reset by DPI")
            return FakeTLS(http_answer), object(), {"tls_ms": 42.0,
                                                    "ver": "TLSv1.3"}
        raise ProbeError("tcp", "timeout (filtered or dead)")

    import xray_forge.core.sni_search as mod
    monkeypatch.setattr(mod, "tls_connect", fake_tls_connect)


def test_parse_list_dedups_and_splits():
    assert SniSearch.parse_list(
        "a.com, b.com\nb.com c.com") == ["a.com", "b.com", "c.com"]
    assert SniSearch.parse_list("") == []


def test_set_targets_builds_product(tmp_path, monkeypatch):
    _wired(monkeypatch)
    s = SniSearch("s1", state_dir=str(tmp_path))
    n = s.set_targets(["1.1.1.1", "2.2.2.2"], ["a.com", "b.com"])
    assert n == 4
    assert sorted(s.pending) == [("1.1.1.1", "a.com"), ("1.1.1.1", "b.com"),
                                 ("2.2.2.2", "a.com"), ("2.2.2.2", "b.com")]


def test_run_records_hits_and_failures(tmp_path, monkeypatch):
    _wired(monkeypatch)
    s = SniSearch("s2", state_dir=str(tmp_path))
    s.set_targets(["1.0.0.1", "9.9.9.9"], ["good.example"])
    new = s.run(port="443", workers=4, http_check=True)
    assert len(new) == 2
    good = s.results[("1.0.0.1", "good.example")]
    assert good.ok and good.http_ok
    assert good.tls_ms == 42.0 and good.tls_ver == "TLSv1.3"
    dead = s.results[("9.9.9.9", "good.example")]
    assert not dead.ok and not dead.http_ok
    assert "tcp" in dead.info
    # ranking: working pairs first
    hits = s.hits()
    assert hits[0].ip == "1.0.0.1"


def test_blocked_sni_fails_on_clean_ip(tmp_path, monkeypatch):
    """The whole point: a censored SNI fails even on a clean IP."""
    _wired(monkeypatch)
    s = SniSearch("s3", state_dir=str(tmp_path))
    s.set_targets(["1.0.0.1"], ["good.example", "blocked.example"])
    s.run(port="443", workers=2)
    assert s.results[("1.0.0.1", "good.example")].ok
    assert not s.results[("1.0.0.1", "blocked.example")].ok


def test_resume_across_sessions(tmp_path, monkeypatch):
    _wired(monkeypatch)
    s1 = SniSearch("s4", state_dir=str(tmp_path))
    s1.set_targets(["1.0.0.1", "1.0.0.2"], ["a.com", "b.com"])
    stop = threading.Event()
    stop.set()
    s1.run(port="443", workers=2, stop=stop)
    assert len(s1.pending) == 4
    s2 = SniSearch("s4", state_dir=str(tmp_path))
    assert len(s2.pending) == 4
    s2.run(port="443", workers=4)
    assert s2.pending == []
    assert len(s2.results) == 4
    # resume=True with a finished session falls through to the new targets
    s3 = SniSearch("s4", state_dir=str(tmp_path))
    assert s3.set_targets(["1.0.0.1"], ["c.com"], resume=True) == 1
    # ...but resume with actual pending work keeps the pending list
    s3b = SniSearch("s4", state_dir=str(tmp_path))
    s3b.pending = [("9.9.9.9", "x.com")]
    assert s3b.set_targets(["1.0.0.1"], ["c.com"], resume=True) == 1


def test_already_probed_pairs_not_requeued(tmp_path, monkeypatch):
    _wired(monkeypatch)
    s = SniSearch("s5", state_dir=str(tmp_path))
    s.set_targets(["1.0.0.1"], ["a.com"])
    s.run(port="443", workers=2)
    assert s.set_targets(["1.0.0.1"], ["a.com"]) == 0


def test_export_csv_json(tmp_path, monkeypatch):
    _wired(monkeypatch)
    s = SniSearch("s6", state_dir=str(tmp_path))
    s.set_targets(["1.0.0.1"], ["a.com", "blocked.example"])
    s.run(port="443", workers=2)
    csv_path = s.export_csv(str(tmp_path / "out.csv"))
    json_path = s.export_json(str(tmp_path / "out.json"))
    import csv as csv_mod
    with open(csv_path, newline="", encoding="utf-8") as f:
        rows = list(csv_mod.reader(f))
    assert rows[0][:4] == ["ip", "port", "sni", "ok"]
    assert len(rows) == 3  # header + 2
    data = json.load(open(json_path, encoding="utf-8"))
    assert len(data["results"]) == 2


def test_snihit_roundtrip():
    h = SniHit(ip="1.1.1.1", port="443", sni="a.com", ok=True, http_ok=True,
               tls_ms=12.0, tls_ver="TLSv1.3")
    assert SniHit.from_dict(h.to_dict()) == h


def test_targets_from_scan(tmp_path, monkeypatch):
    from xray_forge.core.scan_session import ScanSession, ScanResult
    s = ScanSession("snisrc", state_dir=str(tmp_path))
    for i in range(3):
        s.results[f"203.0.113.{i + 1}"] = ScanResult(
            ip=f"203.0.113.{i + 1}", port="443", alive=(i < 2), ms=10.0 + i)
    s.save()
    ips = targets_from_scan("snisrc", state_dir=str(tmp_path))
    assert ips == ["203.0.113.1", "203.0.113.2"]


def test_default_candidates_usable():
    assert len(DEFAULT_SNI_CANDIDATES) >= 5
    assert all(" " not in d and "." in d for d in DEFAULT_SNI_CANDIDATES)


def test_stop_leaves_pairs_pending(tmp_path, monkeypatch):
    _wired(monkeypatch)
    s = SniSearch("s7", state_dir=str(tmp_path))
    s.set_targets(["1.0.0.1", "1.0.0.2"], ["a.com"])
    stop = threading.Event()
    stop.set()
    s.run(port="443", workers=2, stop=stop)
    assert len(s.pending) == 2
    assert len(s.results) == 0
