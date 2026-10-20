"""Subscriptions over the engine API: sub.check, health run store, best-N and
technique-tagged exports, fetch totals (step 5.4)."""

from __future__ import annotations

import base64

import pytest

from tests.fixtures import SS_SIP002, TROJAN_TLS, VLESS_REALITY, VLESS_TLS_WS
from tests.test_engine import Client
from xray_forge.core import healthcheck as hc
from xray_forge.core.sub_source import SourceManager

A, B, C, D = (f"vless://u{i}@10.0.0.{i}:443?security=tls&type=ws#n{i}" for i in range(1, 5))
SCORES = {A: (90.0, True, ["fragment:5,94,1@2"]), B: (70.0, True, []),
          C: (95.0, False, []),                         # highest score but the request failed
          D: (40.0, True, ["fake-sni"])}


def fake_check(line, **kw):
    score, ok, tech = SCORES.get(line, (10.0, False, []))
    r = hc.HealthReport(line=line, name=line.rsplit("#", 1)[-1], scheme="vless",
                        score=score, techniques=list(tech))
    r.stages.append(hc.StageResult("request", ok, ms=100.0 - score))
    return r


@pytest.fixture
def run_checks(monkeypatch):
    monkeypatch.setattr(hc, "run_health_check", fake_check)

    def go(c, lines, **kw):
        job = c.result("health.run", lines=lines, workers=2, **kw)["job"]
        assert c.wait_job(job)["type"] == "done"
        return job
    return go


def decode(content):
    return base64.b64decode(content).decode().splitlines() if content else []


# --------------------------------------------------------------- best-N
def test_export_best_ranks_working_configs_only(run_checks):
    c = Client()
    job = run_checks(c, [A, B, C, D])
    r = c.result("health.export_best", job=job, top_n=2)
    assert decode(r["content"]) == [A, B] and r["count"] == 2     # C failed: not in the top 2
    r = c.result("health.export_best", job=job, top_n=10)
    assert decode(r["content"]) == [A, B, D] and r["count"] == 3
    assert c.result("health.export_best", job=job)["count"] == 3  # default top_n=10


def test_export_best_with_nothing_working(run_checks):
    c = Client()
    job = run_checks(c, [C])
    assert c.result("health.export_best", job=job) == {"content": "", "count": 0}


@pytest.mark.parametrize("top_n", [0, -1, 1001, "5", 2.5, True, None])
def test_export_best_validates_top_n(run_checks, top_n):
    c = Client()
    job = run_checks(c, [A])
    assert c.call("health.export_best", job=job, top_n=top_n)["error"]["code"] == -32602


def test_tagged_lines_carry_the_techniques_that_worked(run_checks):
    from xray_forge.core.parser import parse_target
    c = Client()
    job = run_checks(c, [A, B, C, D])
    lines = c.result("health.tagged", job=job)["lines"]
    names = [parse_target(x).name for x in lines]
    assert names == ["n1 [fragment:5,94,1@2]", "n2", "n4 [fake-sni]"]   # best first; C failed
    assert [parse_target(x).host for x in lines] == ["10.0.0.1", "10.0.0.2", "10.0.0.4"]
    assert c.result("health.tagged", job=job, min_score=80)["lines"] == lines[:1]
    for bad in (-1, 101, "x", True):
        assert c.call("health.tagged", job=job, min_score=bad)["error"]["code"] == -32602


# ------------------------------------------------------------ run store
def test_unknown_job_is_a_clear_error():
    c = Client()
    for method in ("health.export_best", "health.tagged"):
        r = c.call(method, job="nope")
        assert r["error"]["code"] == -32602 and "no results for that run" in r["error"]["message"]
    assert c.call("health.export_best", job=5)["error"]["code"] == -32602


def test_only_the_last_runs_are_kept(run_checks):
    from xray_forge.engine import methods
    c = Client()
    jobs = [run_checks(c, [A]) for _ in range(methods.KEEP_RUNS + 2)]
    for old in jobs[:2]:
        assert c.call("health.tagged", job=old)["error"]["code"] == -32602
    for recent in jobs[2:]:
        assert c.result("health.tagged", job=recent)["lines"]


def test_runs_are_independent(run_checks):
    c = Client()
    j1 = run_checks(c, [A])
    j2 = run_checks(c, [B, D])
    assert decode(c.result("health.export_best", job=j1)["content"]) == [A]
    assert decode(c.result("health.export_best", job=j2)["content"]) == [B, D]


def test_export_works_on_a_cancelled_run(monkeypatch):
    import threading
    started, release = threading.Event(), threading.Event()

    def slow(line, stop=None, **kw):
        if line == B:
            started.set()
            release.wait(3)
        return fake_check(line)
    monkeypatch.setattr(hc, "run_health_check", slow)
    c = Client()
    job = c.result("health.run", lines=[A, B, D], workers=1)["job"]
    assert started.wait(2)
    c.result("job.cancel", job=job)
    release.set()
    done = c.wait_job(job)
    assert done["cancelled"] is True
    got = decode(c.result("health.export_best", job=job)["content"])
    assert got and set(got) <= {A, B, D}


# -------------------------------------------------- health.run validation
@pytest.mark.parametrize("params", [
    dict(workers=0), dict(workers=65), dict(workers="8"), dict(workers=True),
    dict(timeout=0), dict(timeout=500), dict(timeout="6"), dict(timeout=True),
])
def test_health_run_validates_workers_and_timeout(params):
    resp = Client().call("health.run", lines=[VLESS_TLS_WS], **params)
    assert resp["error"]["code"] == -32602, resp


# ---------------------------------------------------------------- sub.check
def make_sources(tmp_path, lines):
    mgr = SourceManager(state_path=str(tmp_path / "s.json"), cache_dir=str(tmp_path / "cache"))
    mgr.add("https://a.example/s")
    mgr.combined_lines = lambda dedupe=True: (list(lines), 3)
    return mgr


def test_sub_check_runs_the_cached_configs(tmp_path, run_checks):
    c = Client(sources=make_sources(tmp_path, [A, B, C]))
    r = c.result("sub.check", workers=2, timeout=3)
    assert r["total"] == 3 and r["removed"] == 3
    done = c.wait_job(r["job"])
    assert done["result"] == {"total": 3, "passed": 2}
    assert len(c.job_events(r["job"], "item")) == 3
    assert decode(c.result("health.export_best", job=r["job"], top_n=1)["content"]) == [A]


def test_sub_check_without_cached_configs_says_what_to_do(tmp_path):
    c = Client(sources=make_sources(tmp_path, []))
    r = c.call("sub.check")
    assert r["error"]["code"] == -32602 and "fetch the sources first" in r["error"]["message"]


def test_sub_check_validates_like_health_run(tmp_path):
    c = Client(sources=make_sources(tmp_path, [A]))
    assert c.call("sub.check", workers=0)["error"]["code"] == -32602
    assert c.call("sub.check", core="zzz")["error"]["code"] == -32602


# ----------------------------------------------------------- fetch totals
def test_sub_fetch_reports_totals_and_duplicates(tmp_path, monkeypatch):
    mgr = SourceManager(state_path=str(tmp_path / "s.json"), cache_dir=str(tmp_path / "cache"))
    mgr.add("https://a.example/s")
    mgr.add("https://b.example/s")
    monkeypatch.setattr(mgr, "fetch", lambda src, force=False, timeout=15.0: [A])
    monkeypatch.setattr(mgr, "combined_lines", lambda dedupe=True: ([A, B], 1))
    c = Client(sources=mgr)
    done = c.wait_job(c.result("sub.fetch")["job"])
    assert done["result"]["total"] == 2 and done["result"]["removed"] == 1
    assert done["result"]["counts"] == {"https://a.example/s": 1, "https://b.example/s": 1}
