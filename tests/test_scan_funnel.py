"""Large-scan behaviour of ScanSession.run (offline, probes faked).

Covers: bounded in-flight work, a stop that really stops, cheap saves, atomic
state files, separate TCP/TLS timeouts and TCP retries.
"""

from __future__ import annotations

import json
import os
import socket
import threading
import time

import pytest

import xray_forge.core.scan_session as scan_mod
from xray_forge.core.scan_session import ScanSession
from xray_forge.core.scanner import tcp_jitter


class Probe(Exception):
    pass


class Fakes:
    """Thread-safe call recorder wired into scan_session."""

    def __init__(self, monkeypatch, n=300, alive=lambda ip: True, delay=0.0):
        self.lock = threading.Lock()
        self.tcp_calls: list[dict] = []
        self.tls_calls: list[dict] = []
        self.on_tcp = None
        self.alive = alive
        self.delay = delay
        monkeypatch.setattr(scan_mod, "sample_cidr",
                            lambda cidr, count: [f"10.0.{i // 250}.{i % 250 + 1}" for i in range(count)])
        monkeypatch.setattr(scan_mod, "tcp_jitter", self._tcp)
        monkeypatch.setattr(scan_mod, "tls_connect", self._tls)
        monkeypatch.setattr(scan_mod, "ip_meta", lambda ip: ("US", "Test ISP"))
        self.n = n

    def _tcp(self, ip, port, attempts=2, timeout=3.0, **kw):
        with self.lock:
            self.tcp_calls.append({"ip": ip, "timeout": timeout, **kw})
            n = len(self.tcp_calls)
        if self.delay:
            time.sleep(self.delay)
        if self.on_tcp:
            self.on_tcp(n)
        return (20.0, 2.0) if self.alive(ip) else (None, 0.0)

    def _tls(self, ip, port, sni=None, frag=None, timeout=5.0, stop=None, **kw):
        with self.lock:
            self.tls_calls.append({"ip": ip, "timeout": timeout})
        return object(), type("S", (), {"close": lambda self: None})(), {"tls_ms": 30.0, "ver": "TLSv1.3"}


def session(tmp_path, fakes, n=300, name="s"):
    s = ScanSession(name, state_dir=str(tmp_path))
    assert s.set_targets(["10.0.0.0/8"], count=n) == n
    return s


# ---- stop must stop ------------------------------------------------------------

def test_stop_does_not_probe_the_whole_queue(monkeypatch, tmp_path):
    f = Fakes(monkeypatch, delay=0.002)
    s = session(tmp_path, f)
    stop = threading.Event()
    f.on_tcp = lambda n: stop.set() if n == 5 else None
    t0 = time.monotonic()
    s.run(workers=2, stop=stop, save_interval=0)
    assert len(f.tcp_calls) <= 5 + 2, f"{len(f.tcp_calls)} probes ran after stop"   # only the in-flight ones finish
    assert time.monotonic() - t0 < 5


def test_results_finished_before_stop_are_kept_and_the_rest_stays_pending(monkeypatch, tmp_path):
    f = Fakes(monkeypatch, delay=0.002)
    s = session(tmp_path, f)
    stop = threading.Event()
    seen = []

    def on_result(r):
        seen.append(r.ip)
        if len(seen) == 7:
            stop.set()
    s.run(workers=2, stop=stop, on_result=on_result, save_interval=0)
    assert len(s.results) >= 7
    assert set(s.pending).isdisjoint(s.results)
    assert len(s.pending) + len(s.results) == 300
    on_disk = ScanSession("s", state_dir=str(tmp_path))          # what a resume would see
    assert set(on_disk.results) == set(s.results) and on_disk.pending == s.pending


def test_resume_after_stop_finishes_exactly_the_rest(monkeypatch, tmp_path):
    f = Fakes(monkeypatch, delay=0.001)
    s = session(tmp_path, f, n=120)
    stop = threading.Event()
    f.on_tcp = lambda n: stop.set() if n == 10 else None
    s.run(workers=3, stop=stop, save_interval=0)
    first = set(s.results)
    f.on_tcp = None
    again = ScanSession("s", state_dir=str(tmp_path))
    again.run(workers=3)
    assert len(again.results) == 120 and again.pending == []
    probed_twice = [c["ip"] for c in f.tcp_calls if c["ip"] in first]
    assert len(probed_twice) == len(first), "finished IPs must not be probed again"


def test_in_flight_work_is_bounded(monkeypatch, tmp_path):
    f = Fakes(monkeypatch)
    s = session(tmp_path, f, n=400)
    peak = [0]
    live = [0]
    lock = threading.Lock()
    real = scan_mod.ThreadPoolExecutor

    class Counting(real):
        def submit(self, fn, *a, **k):
            with lock:
                live[0] += 1
                peak[0] = max(peak[0], live[0])

            def wrapped(*aa, **kk):
                try:
                    return fn(*aa, **kk)
                finally:
                    with lock:
                        live[0] -= 1
            return super().submit(wrapped, *a, **k)
    monkeypatch.setattr(scan_mod, "ThreadPoolExecutor", Counting)
    s.run(workers=4)
    assert len(s.results) == 400
    assert peak[0] <= 4 * 4 + 4, f"{peak[0]} tasks were queued at once"


# ---- state file: cheap and atomic ---------------------------------------------------

def _count_saves(monkeypatch):
    calls = [0]
    real = ScanSession.save

    def counting(self):
        calls[0] += 1
        return real(self)
    monkeypatch.setattr(ScanSession, "save", counting)
    return calls


def test_saves_are_rate_limited(monkeypatch, tmp_path):
    f = Fakes(monkeypatch)
    s = session(tmp_path, f, n=500)
    calls = _count_saves(monkeypatch)
    s.run(workers=8, batch_size=10, save_interval=3600)
    assert calls[0] <= 2, f"{calls[0]} saves for 500 results"      # final save only (plus slack)
    assert ScanSession("s", state_dir=str(tmp_path)).pending == []


def test_save_interval_zero_saves_every_batch(monkeypatch, tmp_path):
    f = Fakes(monkeypatch)
    s = session(tmp_path, f, n=100)
    calls = _count_saves(monkeypatch)
    s.run(workers=4, batch_size=10, save_interval=0)
    assert 9 <= calls[0] <= 12, calls[0]


def test_failed_save_keeps_the_previous_state_file(tmp_path, monkeypatch):
    s = ScanSession("a", state_dir=str(tmp_path))
    s.pending = ["1.1.1.1"]
    s.save()
    before = (tmp_path / "a.json").read_text()
    s.pending = ["2.2.2.2"]
    monkeypatch.setattr(scan_mod.json, "dumps", lambda *a, **k: (_ for _ in ()).throw(ValueError("boom")))
    s.save()                                    # best effort: logs, does not raise
    assert (tmp_path / "a.json").read_text() == before
    assert [p for p in os.listdir(tmp_path) if p.startswith(".tmp")] == []


def test_state_file_is_valid_json_after_every_save(monkeypatch, tmp_path):
    f = Fakes(monkeypatch)
    s = session(tmp_path, f, n=60)
    path = tmp_path / "s.json"
    bad = []

    def check(n):
        if n % 7 == 0 and path.exists():
            try:
                json.loads(path.read_text())
            except ValueError as e:
                bad.append(str(e))
    f.on_tcp = check
    s.run(workers=6, batch_size=1, save_interval=0)
    assert bad == []


# ---- accuracy of counters ----------------------------------------------------------------

def test_pending_shrinks_and_progress_reaches_total(monkeypatch, tmp_path):
    f = Fakes(monkeypatch, alive=lambda ip: not ip.endswith("5"))
    s = session(tmp_path, f, n=50)
    seen = []
    new = s.run(workers=5, progress=lambda d, t: seen.append((d, t)))
    assert len(new) == 50 and s.pending == []
    assert [d for d, _ in seen] == list(range(1, 51)) and {t for _, t in seen} == {50}
    assert 0 < len(s.alive()) < 50


def test_a_crashing_probe_does_not_lose_the_ip_or_the_run(monkeypatch, tmp_path):
    f = Fakes(monkeypatch)
    s = session(tmp_path, f, n=20)
    real = f._tcp

    def flaky(ip, port, **kw):
        if ip.endswith(".3"):
            raise RuntimeError("socket exploded")
        return real(ip, port, **kw)
    monkeypatch.setattr(scan_mod, "tcp_jitter", flaky)
    s.run(workers=4)
    assert len(s.results) + len(s.pending) == 20
    assert all(not r.alive for r in s.results.values() if r.ip.endswith(".3"))
    assert any(r.ip.endswith(".3") for r in s.results.values()), "failed IP must be recorded, not silently dropped"


# ---- stage timeouts ------------------------------------------------------------------------

def test_timeout_is_the_default_for_both_stages(monkeypatch, tmp_path):
    f = Fakes(monkeypatch)
    s = session(tmp_path, f, n=3)
    s.run(workers=1, timeout=7.5)
    assert {c["timeout"] for c in f.tcp_calls} == {7.5} and {c["timeout"] for c in f.tls_calls} == {7.5}


def test_tcp_and_tls_timeouts_are_independent(monkeypatch, tmp_path):
    f = Fakes(monkeypatch)
    s = session(tmp_path, f, n=3)
    s.run(workers=1, timeout=9.0, tcp_timeout=1.5, tls_timeout=4.0)
    assert {c["timeout"] for c in f.tcp_calls} == {1.5} and {c["timeout"] for c in f.tls_calls} == {4.0}
    s2 = ScanSession("only_tcp", state_dir=str(tmp_path))
    s2.set_targets(["10.0.0.0/8"], count=3)
    f.tcp_calls.clear(); f.tls_calls.clear()
    s2.run(workers=1, timeout=9.0, tcp_timeout=2.0)
    assert {c["timeout"] for c in f.tcp_calls} == {2.0} and {c["timeout"] for c in f.tls_calls} == {9.0}


def test_tcp_retries_reach_the_probe(monkeypatch, tmp_path):
    f = Fakes(monkeypatch)
    s = session(tmp_path, f, n=2)
    s.run(workers=1)
    assert {c["retries"] for c in f.tcp_calls} == {1}               # default = old behaviour
    s2 = ScanSession("r0", state_dir=str(tmp_path))
    s2.set_targets(["10.0.0.0/8"], count=2)
    f.tcp_calls.clear()
    s2.run(workers=1, tcp_retries=0)
    assert {c["retries"] for c in f.tcp_calls} == {0}


def test_stop_is_passed_to_the_tcp_probe(monkeypatch, tmp_path):
    f = Fakes(monkeypatch)
    s = session(tmp_path, f, n=2)
    stop = threading.Event()
    s.run(workers=1, stop=stop)
    assert all(c["stop"] is stop for c in f.tcp_calls)


# ---- tcp_jitter itself ------------------------------------------------------------------------

class FakeConn:
    def close(self):
        pass


def _connect_script(monkeypatch, outcomes):
    """create_connection that succeeds/fails per the scripted outcomes (True = ok)."""
    calls = []
    it = iter(outcomes)

    def fake(addr, timeout=None):
        calls.append(timeout)
        if next(it, False):
            return FakeConn()
        raise OSError("refused")
    monkeypatch.setattr(socket, "create_connection", fake)
    return calls


def test_tcp_jitter_dead_host_default_tries_twice_like_before(monkeypatch):
    calls = _connect_script(monkeypatch, [False] * 10)
    assert tcp_jitter("192.0.2.1", "443", attempts=2, timeout=0.5) == (None, 0.0)
    assert calls == [0.5, 0.5]


def test_tcp_jitter_without_retries_gives_up_after_one_try(monkeypatch):
    calls = _connect_script(monkeypatch, [False] * 10)
    assert tcp_jitter("192.0.2.1", "443", attempts=2, timeout=0.5, retries=0) == (None, 0.0)
    assert len(calls) == 1


def test_tcp_jitter_more_retries_try_more_times(monkeypatch):
    calls = _connect_script(monkeypatch, [False] * 10)
    tcp_jitter("192.0.2.1", "443", attempts=2, timeout=0.5, retries=3)
    assert len(calls) == 4


def test_tcp_jitter_retry_recovers_a_lossy_first_connect(monkeypatch):
    _connect_script(monkeypatch, [False, True, True])
    best, jitter = tcp_jitter("192.0.2.1", "443", attempts=2, timeout=0.5, retries=1)
    assert best is not None and jitter >= 0


def test_tcp_jitter_alive_host_takes_the_requested_samples(monkeypatch):
    calls = _connect_script(monkeypatch, [True] * 10)
    best, jitter = tcp_jitter("192.0.2.1", "443", attempts=3, timeout=0.5)
    assert len(calls) == 3 and best is not None and jitter >= 0


def test_tcp_jitter_stops_when_asked(monkeypatch):
    calls = _connect_script(monkeypatch, [True] * 10)
    stop = threading.Event()
    stop.set()
    assert tcp_jitter("192.0.2.1", "443", attempts=3, timeout=0.5, stop=stop) == (None, 0.0)
    assert calls == []


def test_ip_interrupted_by_stop_is_not_recorded_as_filtered(monkeypatch, tmp_path):
    f = Fakes(monkeypatch)
    s = session(tmp_path, f, n=5)
    stop = threading.Event()

    def interrupted(ip, port, attempts=2, timeout=3.0, retries=1, stop=None):
        stop.set()                      # the user pressed stop while this IP was connecting
        return None, 0.0                # tcp_jitter's answer when it was cut short
    monkeypatch.setattr(scan_mod, "tcp_jitter", interrupted)
    s.run(workers=1, stop=stop, save_interval=0)
    assert not [r for r in s.results.values() if r.info in ("tcp filtered", "stopped")]
    assert len(s.results) + len(s.pending) == 5 and len(s.pending) >= 4
    again = ScanSession("s", state_dir=str(tmp_path))
    assert set(again.pending) | set(again.results) == set(s.pending) | set(s.results)


def test_stop_set_before_the_run_probes_nothing(monkeypatch, tmp_path):
    f = Fakes(monkeypatch)
    s = session(tmp_path, f, n=40)
    stop = threading.Event()
    stop.set()
    assert s.run(workers=4, stop=stop) == []
    assert f.tcp_calls == [] and f.tls_calls == []
    assert len(s.pending) == 40 and s.results == {}
