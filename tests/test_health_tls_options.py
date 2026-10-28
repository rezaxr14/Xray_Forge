"""Anti-DPI options of the health check (fake SNI, record fragmentation,
ClientHello padding, fronting Host header, custom fragment variants): ported
from the retired Tk tester (step 5.7)."""

from __future__ import annotations

import pytest

from tests.fixtures import VLESS_TLS_WS
from tests.test_engine import Client
from xray_forge.core import healthcheck as hc
from xray_forge.core.models import Outbound


class FakeTC:
    def __init__(self):
        self.writes = []

    def write(self, b):
        self.writes.append(b)


@pytest.fixture
def seen(monkeypatch):
    calls = {"tls": [], "ws": []}

    def tls(host, port, sni=None, frag=None, timeout=5.0, stop=None, **kw):
        calls["tls"].append({"sni": sni, "frag": frag, **kw})
        return FakeTC(), object(), {"tls_ms": 5.0, "ver": "TLSv1.3"}

    def ws(tc, host_hdr, path, timeout, stop, front_domain=None):
        calls["ws"].append({"host_hdr": host_hdr, "front_domain": front_domain})
        return "HTTP/1.1 101 Switching Protocols", 3.0
    monkeypatch.setattr(hc, "tls_connect", tls)
    monkeypatch.setattr(hc, "ws_upgrade", ws)
    return calls


OUT = Outbound(scheme="vless", host="203.0.113.1", port="443", transport="ws",
               path="/p", sni="real.example", host_header="real.example",
               credential="13b8ac3f-e8de-4b2d-82db-e9130d288a54")


def test_defaults_change_nothing(seen):
    res, _s, tag = hc.probe_tls(OUT, ("5,94,1@2",))
    assert res.ok and tag == "fragment:5,94,1@2"
    assert seen["tls"] == [{"sni": "real.example", "frag": ("list", [5, 94, 1], 2.0)}]
    hc.probe_request(OUT, FakeTC(), object())
    assert seen["ws"] == [{"host_hdr": "real.example", "front_domain": None}]


def test_tls_options_reach_the_handshake(seen):
    opts = hc.TlsOptions(fake_sni="www.microsoft.com", record_frag=True, pad_hello=True)
    hc.probe_tls(OUT, ("off",), opts=opts)
    call = seen["tls"][0]
    assert (call["fake_sni"], call["record_frag"], call["pad_hello"]) == ("www.microsoft.com", True, True)
    assert call["sni"] == "real.example"        # the real name is still the verified/effective one


def test_front_host_reaches_the_websocket_upgrade(seen):
    opts = hc.TlsOptions(front_host="front.example")
    hc.probe_request(OUT, FakeTC(), object(), opts=opts)
    assert seen["ws"][0]["front_domain"] == "front.example"


def test_throughput_sessions_use_the_same_options(seen):
    opts = hc.TlsOptions(fake_sni="f.example", record_frag=True, front_host="h.example")
    make = hc.native_tunnel_factory(OUT, "5,94,1@2", 3.0, None, opts=opts)
    make()
    assert seen["tls"][0]["fake_sni"] == "f.example" and seen["tls"][0]["record_frag"] is True
    assert seen["ws"][0]["front_domain"] == "h.example"


def test_run_health_check_threads_options_through_every_stage(seen, monkeypatch):
    monkeypatch.setattr(hc, "probe_dns", lambda host, timeout=4.0: hc.StageResult("dns", True, ms=1.0))
    monkeypatch.setattr(hc, "probe_tcp", lambda host, port, timeout=5.0: hc.StageResult("tcp", True, ms=1.0))
    opts = hc.TlsOptions(fake_sni="f.example", front_host="h.example")
    hc.run_health_check(VLESS_TLS_WS, do_throughput=False, tls_opts=opts,
                        frag_variants=("off",))
    assert seen["tls"] and all(c.get("fake_sni") == "f.example" for c in seen["tls"])
    assert seen["ws"][0]["front_domain"] == "h.example"


def test_options_object_is_inert_by_default():
    assert not hc.TlsOptions().active()
    assert hc.TlsOptions(pad_hello=True).active()


# ------------------------------------------------------------------ engine
@pytest.fixture
def captured(monkeypatch):
    got = []

    def fake(line, **kw):
        got.append(kw)
        r = hc.HealthReport(line=line, name="n", scheme="vless")
        r.stages.append(hc.StageResult("tcp", False))
        return r
    monkeypatch.setattr(hc, "run_health_check", fake)
    return got


def run(c, method="health.run", **params):
    r = c.result(method, **params)
    assert c.wait_job(r["job"])["type"] == "done"


def test_engine_forwards_validated_options(captured):
    c = Client()
    run(c, lines=[VLESS_TLS_WS], fake_sni="www.microsoft.com", front_host="front.example",
        record_frag=True, pad_hello=True, frag_variants=["5,94,1@2", "off"])
    kw = captured[0]
    assert kw["frag_variants"] == ("5,94,1@2", "off")
    assert kw["tls_opts"] == hc.TlsOptions("www.microsoft.com", True, True, "front.example")


def test_engine_without_options_passes_the_defaults(captured):
    run(Client(), lines=[VLESS_TLS_WS])
    kw = captured[0]
    assert "frag_variants" not in kw and kw.get("tls_opts") is None


def test_engine_rejects_bad_options():
    c = Client()
    bad = [
        {"fake_sni": 5}, {"fake_sni": "bad host"}, {"fake_sni": "a" * 300},
        {"fake_sni": "http://x"}, {"front_host": ["x"]}, {"front_host": "x y"},
        {"record_frag": "yes"}, {"pad_hello": 1},
        {"frag_variants": "off"}, {"frag_variants": []}, {"frag_variants": [5]},
        {"frag_variants": ["x" * 65]}, {"frag_variants": ["off"] * 9},
    ]
    for extra in bad:
        r = c.call("health.run", lines=[VLESS_TLS_WS], **extra)
        assert r["error"]["code"] == -32602, extra


def test_sub_check_accepts_the_same_options(captured, tmp_path):
    from xray_forge.core.sub_source import SourceManager
    c = Client()
    c.result("sub.add", url="http://127.0.0.1:9/s")
    mgr = SourceManager()
    src = mgr.list_sources()[0]
    mgr._write_cache(src.url, VLESS_TLS_WS + "\n")
    run(c, "sub.check", fake_sni="f.example", pad_hello=True)
    assert captured[0]["tls_opts"].fake_sni == "f.example" and captured[0]["tls_opts"].pad_hello
