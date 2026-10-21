"""Per-stage timeouts: the health pipeline, scan.run, health.run and sub.check."""

from __future__ import annotations

import pytest

from xray_forge.core import healthcheck as hc
from xray_forge.core import scan_session
from tests.fixtures import VLESS_TLS_WS
from tests.test_engine import Client
from tests.test_healthcheck import wired  # noqa: F401  (fixture: offline fakes for every probe)


# --------------------------------------------------------------- core pipeline
@pytest.fixture
def seen(wired, monkeypatch):  # noqa: F811
    """Record the timeout each stage of the pipeline was given."""
    got: dict[str, list[float]] = {k: [] for k in ("dns", "tcp", "tls", "request", "download", "upload")}

    real_dns, real_tcp = hc.probe_dns, hc.probe_tcp
    monkeypatch.setattr(hc, "probe_dns", lambda host, timeout=4.0: (got["dns"].append(timeout), real_dns(host, timeout))[1])
    monkeypatch.setattr(hc, "probe_tcp", lambda host, port, timeout=5.0: (got["tcp"].append(timeout), real_tcp(host, port, timeout))[1])

    real_tls = hc.tls_connect
    monkeypatch.setattr(hc, "tls_connect", lambda *a, timeout=6.0, **k: (got["tls"].append(timeout), real_tls(*a, timeout=timeout, **k))[1])

    real_ws = hc.ws_upgrade
    monkeypatch.setattr(hc, "ws_upgrade", lambda tc, h, p, timeout, stop, **k: (got["request"].append(timeout), real_ws(tc, h, p, timeout, stop, **k))[1])

    real_get, real_post = hc.tunnel_http_get, hc.tunnel_http_post
    monkeypatch.setattr(hc, "tunnel_http_get", lambda tun, h, p, timeout, stop, **k: (got["download"].append(timeout), real_get(tun, h, p, timeout, stop, **k))[1])
    monkeypatch.setattr(hc, "tunnel_http_post", lambda tun, h, p, n, timeout, stop: (got["upload"].append(timeout), real_post(tun, h, p, n, timeout, stop))[1])
    return got


def _flat(got):
    return {k: sorted(set(v)) for k, v in got.items() if v}


def test_without_overrides_every_stage_uses_timeout_and_dns_keeps_its_default(seen):
    rep = hc.run_health_check(VLESS_TLS_WS, timeout=6.0)
    assert rep.passed()
    assert _flat(seen) == {"dns": [4.0], "tcp": [6.0], "tls": [6.0], "request": [6.0],
                           "download": [6.0], "upload": [6.0]}


def test_each_stage_gets_its_own_timeout(seen):
    rep = hc.run_health_check(VLESS_TLS_WS, timeout=6.0,
                              timeouts={"dns": 7.0, "tcp": 1.5, "tls": 2.5, "request": 3.5, "transfer": 20.0})
    assert rep.passed()
    # the upload stage opens its own TLS + WebSocket session; that setup is part of the
    # transfer stage and so is bounded by "transfer", not by "tls"/"request"
    assert _flat(seen) == {"dns": [7.0], "tcp": [1.5], "tls": [2.5, 20.0], "request": [3.5, 20.0],
                           "download": [20.0], "upload": [20.0]}
    assert seen["tls"][0] == 2.5 and seen["request"][0] == 3.5     # the first TLS / upgrade are the real stages


def test_unlisted_stages_fall_back_to_timeout(seen):
    hc.run_health_check(VLESS_TLS_WS, timeout=9.0, timeouts={"tcp": 2.0})
    assert _flat(seen) == {"dns": [4.0], "tcp": [2.0], "tls": [9.0], "request": [9.0],
                           "download": [9.0], "upload": [9.0]}


def test_dns_override_applies_even_when_timeout_is_default(seen):
    hc.run_health_check(VLESS_TLS_WS, timeouts={"dns": 1.0})
    assert seen["dns"] == [1.0]


def test_unknown_stage_name_is_rejected_by_the_core(seen):
    with pytest.raises(ValueError, match="bogus"):
        hc.run_health_check(VLESS_TLS_WS, timeouts={"bogus": 1.0})


def test_transfer_timeout_also_reaches_the_native_upload_tunnel_factory(wired, monkeypatch):  # noqa: F811
    got = []
    real = hc.native_tunnel_factory
    monkeypatch.setattr(hc, "native_tunnel_factory",
                        lambda out, variant, timeout, stop, **kw: (got.append(timeout), real(out, variant, timeout, stop, **kw))[1])
    hc.run_health_check(VLESS_TLS_WS, timeout=6.0, timeouts={"transfer": 33.0, "tls": 2.0})
    assert got == [33.0]


def test_request_timeout_reaches_the_socks_fallback(wired, monkeypatch):  # noqa: F811
    got = []
    monkeypatch.setattr(hc, "ws_upgrade", lambda *a, **k: ("HTTP/1.1 403 Forbidden", 5.0))
    monkeypatch.setattr(hc, "probe_request_socks",
                        lambda port, timeout=8.0, stop=None: (got.append(timeout), hc.StageResult("request", True, ms=1.0))[1])
    hc.run_health_check(VLESS_TLS_WS, socks_port=1080, do_throughput=False, timeouts={"request": 4.5})
    assert got == [4.5]


# ------------------------------------------------------------------ scan.run
@pytest.fixture
def scan_seen(monkeypatch):
    got = {"tcp": [], "tls": [], "retries": []}

    def jitter(ip, port, attempts=2, timeout=5.0, retries=1, stop=None):
        got["tcp"].append(timeout)
        got["retries"].append(retries)
        return 10.0, 1.0

    class _Sock:
        def close(self):
            pass

    def tls(ip, port, timeout=5.0, **kw):
        got["tls"].append(timeout)
        return object(), _Sock(), {"tls_ms": 5.0, "ver": "TLSv1.3"}
    monkeypatch.setattr(scan_session, "tcp_jitter", jitter)
    monkeypatch.setattr(scan_session, "tls_connect", tls)
    return got


def _scan(c, **kw):
    r = c.result("scan.run", cidrs=["10.9.0.0/29"], count=3, workers=1, **kw)
    assert c.wait_job(r["job"])["type"] == "done"


def test_scan_stage_timeouts_and_retries_reach_the_scanner(scan_seen):
    _scan(Client(), timeout=8, tcp_timeout=1.5, tls_timeout=4, tcp_retries=0)
    assert set(scan_seen["tcp"]) == {1.5} and set(scan_seen["tls"]) == {4.0} and set(scan_seen["retries"]) == {0}


def test_scan_defaults_are_unchanged(scan_seen):
    _scan(Client())
    assert set(scan_seen["tcp"]) == {5.0} and set(scan_seen["tls"]) == {5.0} and set(scan_seen["retries"]) == {1}


def test_scan_stage_timeout_defaults_to_timeout(scan_seen):
    _scan(Client(), timeout=7, tls_timeout=2)
    assert set(scan_seen["tcp"]) == {7.0} and set(scan_seen["tls"]) == {2.0}


def test_scan_null_stage_timeouts_mean_default(scan_seen):
    _scan(Client(), timeout=7, tcp_timeout=None, tls_timeout=None)
    assert set(scan_seen["tcp"]) == {7.0} and set(scan_seen["tls"]) == {7.0}


BAD_TIMEOUTS = [0, 0.1, -1, 121, "5", True, [1], {}, float("nan"), float("inf")]


@pytest.mark.parametrize("field", ["timeout", "tcp_timeout", "tls_timeout"])
def test_scan_rejects_bad_timeouts(field):
    c = Client()
    for bad in BAD_TIMEOUTS:
        r = c.call("scan.run", cidrs=["10.9.0.0/30"], **{field: bad})
        assert r["error"]["code"] == -32602, (field, bad, r)
        assert field in r["error"]["message"] or "timeout" in r["error"]["message"]


def test_scan_rejects_bad_retries():
    c = Client()
    for bad in (-1, 6, "1", True, 1.5, None, [1]):
        assert c.call("scan.run", cidrs=["10.9.0.0/30"], tcp_retries=bad)["error"]["code"] == -32602, bad


def test_scan_accepts_the_range_limits(scan_seen):
    _scan(Client(), tcp_timeout=0.2, tls_timeout=120, tcp_retries=5)
    assert set(scan_seen["tcp"]) == {0.2} and set(scan_seen["tls"]) == {120.0} and set(scan_seen["retries"]) == {5}


def test_a_rejected_scan_creates_no_session(tmp_path):
    c = Client()
    assert c.call("scan.run", cidrs=["10.9.0.0/30"], session="nope", tcp_timeout=0)["error"]
    assert c.result("scan.sessions") == []


# ------------------------------------------------------- health.run / sub.check
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


def test_health_run_passes_stage_timeouts(captured):
    c = Client()
    r = c.result("health.run", lines=[VLESS_TLS_WS], throughput=False,
                 timeouts={"tcp": 1, "tls": 2.5, "transfer": 30, "dns": 3, "request": 4})
    c.wait_job(r["job"])
    assert captured[0]["timeouts"] == {"tcp": 1.0, "tls": 2.5, "transfer": 30.0, "dns": 3.0, "request": 4.0}


def test_health_run_without_timeouts_passes_none_or_nothing(captured):
    c = Client()
    c.wait_job(c.result("health.run", lines=[VLESS_TLS_WS], throughput=False)["job"])
    assert not captured[0].get("timeouts")


def test_health_run_accepts_null_and_empty_timeouts(captured):
    c = Client()
    for v in (None, {}):
        c.wait_job(c.result("health.run", lines=[VLESS_TLS_WS], timeouts=v)["job"])
    assert all(not kw.get("timeouts") for kw in captured)


@pytest.mark.parametrize("bad", [
    "5", 5, [1], {"tcp": 0}, {"tcp": 0.4}, {"tcp": 121}, {"tcp": "5"}, {"tcp": True}, {"tcp": None},
    {"tcp": float("nan")}, {"upload": 5}, {"bogus": 5}, {"": 5}, {"tcp": 1, "extra": 2}])
def test_health_run_rejects_bad_timeouts(bad):
    r = Client().call("health.run", lines=[VLESS_TLS_WS], timeouts=bad)
    assert r["error"]["code"] == -32602, (bad, r)


def test_sub_check_validates_and_passes_stage_timeouts(tmp_path, captured):
    from tests.test_engine_subs import make_sources, A
    c = Client(sources=make_sources(tmp_path, [A]))
    r = c.result("sub.check", timeouts={"tls": 2, "transfer": 25})
    c.wait_job(r["job"])
    assert captured[0]["timeouts"] == {"tls": 2.0, "transfer": 25.0}
    for bad in ({"tcp": 0}, {"nope": 5}, "x"):
        assert c.call("sub.check", timeouts=bad)["error"]["code"] == -32602, bad
