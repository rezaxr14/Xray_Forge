"""Engine API: JSON-RPC dispatch, methods, jobs and the stdio transport."""

from __future__ import annotations

import io
import json
import threading
import time

from xray_forge.core import healthcheck as hc
from xray_forge.core.sub_source import SourceManager
from xray_forge.engine import methods
from xray_forge.engine.server import serve
from tests.fixtures import VLESS_TLS_WS


class Client:
    """In-process client over build(): collects notifications."""

    def __init__(self, sources=None):
        self.events: list[dict] = []
        self.lock = threading.Lock()
        self.d, self.jobs = methods.build(self._emit, sources=sources)
        self._id = 0

    def _emit(self, msg):
        with self.lock:
            self.events.append(msg["params"])

    def call(self, method, **params):
        self._id += 1
        resp = self.d.handle({"jsonrpc": "2.0", "id": self._id,
                              "method": method, "params": params})
        return resp

    def result(self, method, **params):
        resp = self.call(method, **params)
        assert "error" not in resp, resp
        return resp["result"]

    def wait_job(self, job, timeout=5.0):
        end = time.time() + timeout
        while time.time() < end:
            with self.lock:
                for e in self.events:
                    if e["job"] == job and e["type"] in ("done", "error"):
                        return e
            time.sleep(0.01)
        raise AssertionError("job did not finish")

    def job_events(self, job, type_):
        with self.lock:
            return [e for e in self.events if e["job"] == job and e["type"] == type_]


# ------------------------------------------------------------------ rpc
def test_unknown_method_and_bad_request():
    c = Client()
    assert c.call("nope")["error"]["code"] == -32601
    assert c.d.handle({"id": 1, "method": "engine.info"})["error"]["code"] == -32600
    assert c.d.handle({"jsonrpc": "2.0", "id": 1, "method": 5})["error"]["code"] == -32600


def test_params_validation():
    c = Client()
    assert c.call("config.parse", bogus=1)["error"]["code"] == -32602
    assert c.call("config.parse")["error"]["code"] == -32602
    r = c.d.handle({"jsonrpc": "2.0", "id": 1, "method": "config.parse",
                    "params": ["x"]})
    assert r["error"]["code"] == -32602


def test_notification_gets_no_response():
    c = Client()
    assert c.d.handle({"jsonrpc": "2.0", "method": "engine.info"}) is None


def test_domain_exception_becomes_error_not_crash(monkeypatch):
    c = Client()
    monkeypatch.setattr(methods, "parse_target",
                        lambda line: (_ for _ in ()).throw(RuntimeError("boom")))
    r = c.call("config.parse", line="x")
    assert r["error"]["code"] == -32000 and "boom" in r["error"]["message"]


# --------------------------------------------------------------- methods
def test_engine_info():
    info = Client().result("engine.info")
    assert info["protocol"] == 1 and "vless" in info["schemes"]
    assert "config.render" in info["methods"] and "health.run" in info["methods"]


def test_parse_reports_core_support():
    r = Client().result("config.parse", line=VLESS_TLS_WS)
    assert r["ok"] and r["outbound"]["scheme"] == "vless"
    assert "raw" not in r["outbound"]
    assert r["supports"]["xray"] is True


def test_parse_garbage():
    assert Client().result("config.parse", line="not a link")["ok"] is False


def test_render_roundtrip_with_edit():
    c = Client()
    ob = c.result("config.parse", line=VLESS_TLS_WS)["outbound"]
    ob["name"] = "renamed"
    ob["port"] = "8443"
    r = c.result("config.render", outbound=ob)
    assert r["roundtrip_ok"] and r["uri"].startswith("vless://")
    again = c.result("config.parse", line=r["uri"])["outbound"]
    assert again["name"] == "renamed" and again["port"] == "8443"


def test_render_rejects_unknown_fields_and_scheme():
    c = Client()
    assert c.call("config.render", outbound={"scheme": "vless", "zzz": 1})["error"]["code"] == -32602
    assert c.call("config.render", outbound={"scheme": "nope"})["error"]["code"] == -32602


def test_render_preserves_extra_params():
    c = Client()
    base, _, frag = VLESS_TLS_WS.partition("#")
    line = base + "&ech=abc" + ("#" + frag if frag else "")
    ob = c.result("config.parse", line=line)["outbound"]
    assert ob["extra_params"].get("ech") == "abc"
    assert "ech=abc" in c.result("config.render", outbound=ob)["uri"]


def test_convert_and_dedup():
    c = Client()
    r = c.result("config.convert", text=VLESS_TLS_WS + "\n" + VLESS_TLS_WS, dedup=True)
    assert len(r["lines"]) == 1 and r["removed"] == 1
    assert r["counts"]["fixed"] + r["counts"]["unchanged"] == 2


def test_export_formats():
    c = Client()
    for fmt in ("clash", "singbox", "sub"):
        r = c.result("config.export", lines=[VLESS_TLS_WS], format=fmt)
        assert r["count"] == 1 and r["content"]
    assert c.call("config.export", lines=[VLESS_TLS_WS], format="x")["error"]["code"] == -32602
    assert c.call("config.export", lines="nope", format="clash")["error"]["code"] == -32602


# ----------------------------------------------------------------- subs
def test_sub_crud_and_validation(tmp_path):
    mgr = SourceManager(state_path=str(tmp_path / "s.json"),
                        cache_dir=str(tmp_path / "cache"))
    c = Client(sources=mgr)
    assert c.call("sub.add", url="file:///etc/passwd")["error"]["code"] == -32602
    c.result("sub.add", url="https://example.com/sub", name="ex")
    assert [s["url"] for s in c.result("sub.list")] == ["https://example.com/sub"]
    c.result("sub.set_enabled", url="https://example.com/sub", enabled=False)
    assert c.result("sub.list")[0]["enabled"] is False
    assert c.result("sub.remove", url="https://example.com/sub") is True
    assert c.result("sub.list") == []


def test_sub_fetch_job_streams_items(tmp_path, monkeypatch):
    mgr = SourceManager(state_path=str(tmp_path / "s.json"),
                        cache_dir=str(tmp_path / "cache"))
    mgr.add("https://a.example/s")
    mgr.add("https://b.example/s")
    monkeypatch.setattr(mgr, "fetch", lambda src, force=False, timeout=15.0: [VLESS_TLS_WS])
    c = Client(sources=mgr)
    job = c.result("sub.fetch")["job"]
    done = c.wait_job(job)
    assert done["type"] == "done"
    assert len(c.job_events(job, "item")) == 2
    assert done["result"]["counts"] == {"https://a.example/s": 1, "https://b.example/s": 1}
    assert c.job_events(job, "progress")[-1]["done"] == 2


# --------------------------------------------------------------- health
def _fake_report(line, **kw):
    r = hc.HealthReport(line=line, name="n", scheme="vless", score=50.0)
    r.stages.append(hc.StageResult("request", True, ms=10.0))
    return r


def test_health_job_streams_reports(monkeypatch):
    monkeypatch.setattr(hc, "run_health_check", _fake_report)
    c = Client()
    job = c.result("health.run", lines=[VLESS_TLS_WS] * 3, workers=2)["job"]
    done = c.wait_job(job)
    assert done["result"] == {"total": 3, "passed": 3}
    items = c.job_events(job, "item")
    assert len(items) == 3 and items[0]["data"]["passed"] is True
    assert c.job_events(job, "progress")[-1]["done"] == 3


def test_health_job_cancel(monkeypatch):
    started = threading.Event()

    def slow(line, stop=None, **kw):
        started.set()
        stop.wait(5)
        return _fake_report(line)
    monkeypatch.setattr(hc, "run_health_check", slow)
    c = Client()
    job = c.result("health.run", lines=[VLESS_TLS_WS] * 4, workers=1)["job"]
    assert started.wait(2)
    assert c.result("job.cancel", job=job) is True
    done = c.wait_job(job)
    assert done["type"] == "done" and done["cancelled"] is True
    assert c.result("job.cancel", job=job) is False


def test_health_param_validation():
    c = Client()
    assert c.call("health.run", lines=[VLESS_TLS_WS], workers=0)["error"]["code"] == -32602
    assert c.call("health.run", lines=[VLESS_TLS_WS], core="zzz")["error"]["code"] == -32602
    assert c.call("health.run", lines=[1])["error"]["code"] == -32602


def test_job_error_is_reported(monkeypatch):
    c = Client()
    monkeypatch.setattr(c.jobs, "_emit", c.jobs._emit)

    def boom(ctx):
        raise RuntimeError("bad job")
    job = c.jobs.start("x", boom)
    done = c.wait_job(job)
    assert done["type"] == "error" and "bad job" in done["message"]


# ---------------------------------------------------------------- stdio
def test_stdio_transport_roundtrip():
    msgs = [
        {"jsonrpc": "2.0", "id": 1, "method": "engine.info"},
        {"jsonrpc": "2.0", "id": 2, "method": "config.parse", "params": {"line": VLESS_TLS_WS}},
        {"jsonrpc": "2.0", "id": 3, "method": "missing"},
    ]
    stdin = io.StringIO("\n".join(json.dumps(m) for m in msgs) + "\nnot json\n[1]\n\n")
    stdout = io.StringIO()
    assert serve(stdin, stdout) == 0
    out = [json.loads(l) for l in stdout.getvalue().splitlines()]
    by_id = {o.get("id"): o for o in out if o.get("id") is not None}
    assert by_id[1]["result"]["protocol"] == 1
    assert by_id[2]["result"]["ok"] is True
    assert by_id[3]["error"]["code"] == -32601
    codes = sorted(o["error"]["code"] for o in out if o.get("id") is None)
    assert codes == [-32700, -32600] or codes == [-32700, -32600][::-1]
    assert all("\n" not in l for l in stdout.getvalue().rstrip("\n").splitlines())
