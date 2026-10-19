"""IP-finder extras over the engine API: net.resolve and net.geo (step 5.3)."""

from __future__ import annotations

import threading

import pytest

from tests.test_engine import Client
from xray_forge.core import scanner


@pytest.fixture
def fakes(monkeypatch):
    calls = {"resolve": [], "geo": []}

    def resolve(host):
        calls["resolve"].append(host)
        return {"104.16.1.1": {"DoH:cloudflare-dns.com", "system"},
                "10.10.34.34": {"UDP:shecan"}}

    def geo(ip=""):
        calls["geo"].append(ip)
        return f"{ip or '5.6.7.8'}  —  Berlin, Germany\nHetzner  ·  Europe/Berlin"

    monkeypatch.setattr(scanner, "resolve_dns_all", resolve)
    monkeypatch.setattr(scanner, "geo_lookup", geo)
    return calls


# ------------------------------------------------------------------ resolve
def test_resolve_reports_every_answer_with_its_sources(fakes):
    r = Client().result("net.resolve", host="Example.com ")
    assert r["host"] == "Example.com"
    assert {a["ip"]: a["sources"] for a in r["answers"]} == {
        "104.16.1.1": ["DoH:cloudflare-dns.com", "system"],
        "10.10.34.34": ["UDP:shecan"]}
    assert fakes["resolve"] == ["Example.com"]


def test_resolve_with_no_answers_is_an_empty_list(monkeypatch):
    monkeypatch.setattr(scanner, "resolve_dns_all", lambda h: {})
    assert Client().result("net.resolve", host="nx.example.com")["answers"] == []


@pytest.mark.parametrize("ip", ["9.9.9.9", "2001:db8::1"])
def test_resolve_of_an_ip_literal_does_not_query_dns(fakes, ip):
    r = Client().result("net.resolve", host=ip)
    assert r["answers"] == [{"ip": ip, "sources": ["literal"]}]
    assert fakes["resolve"] == []


@pytest.mark.parametrize("host", [
    "", "   ", "localhost", "a b.com", "a.com/x", "a.com?x=1", "a.com#f",
    "http://a.com", "-bad.example.com", "a..com", "x" * 300 + ".com",
])
def test_resolve_rejects_bad_hosts(fakes, host):
    resp = Client().call("net.resolve", host=host)
    assert resp["error"]["code"] == -32602, resp
    assert fakes["resolve"] == []


def test_resolve_requires_a_string(fakes):
    assert Client().call("net.resolve", host=5)["error"]["code"] == -32602
    assert Client().call("net.resolve")["error"]["code"] == -32602


# ---------------------------------------------------------------------- geo
def test_geo_without_ip_looks_up_this_machine(fakes):
    r = Client().result("net.geo")
    assert r == {"query": "", "ok": True,
                 "text": "5.6.7.8  —  Berlin, Germany\nHetzner  ·  Europe/Berlin"}
    assert fakes["geo"] == [""]


@pytest.mark.parametrize("q", ["1.1.1.1", "2606:4700::1111", "one.one.one.one"])
def test_geo_accepts_ips_and_domains(fakes, q):
    assert Client().result("net.geo", ip=q)["query"] == q
    assert fakes["geo"] == [q]


def test_geo_failure_is_reported_not_raised(monkeypatch):
    monkeypatch.setattr(scanner, "geo_lookup", lambda ip="": scanner.GEO_FAILED)
    r = Client().result("net.geo", ip="1.1.1.1")
    assert r["ok"] is False and r["text"] == scanner.GEO_FAILED


@pytest.mark.parametrize("ip", [
    "1.1.1.1/../../x", "a.com/json", "1.1.1.1?token=1", "foo bar",
    "1.1.1.1@evil.example", "localhost", ["1.1.1.1"], 7,
])
def test_geo_rejects_values_that_could_alter_the_provider_url(fakes, ip):
    resp = Client().call("net.geo", ip=ip)
    assert resp["error"]["code"] == -32602, resp
    assert fakes["geo"] == []


def test_surrounding_whitespace_is_trimmed(fakes):
    assert Client().result("net.resolve", host=" a.com\n")["host"] == "a.com"
    assert Client().result("net.geo", ip="\t1.1.1.1 ")["query"] == "1.1.1.1"


def test_geo_failure_constant_matches_what_geo_lookup_returns(monkeypatch):
    monkeypatch.setattr(scanner, "fetch_json", lambda *a, **k: (_ for _ in ()).throw(OSError("x")))
    assert scanner.geo_lookup("1.1.1.1") == scanner.GEO_FAILED


# --------------------------------------------------------------- concurrency
def test_a_slow_lookup_does_not_block_other_calls(monkeypatch):
    """The stdio server runs requests on worker threads; model that here."""
    gate = threading.Event()
    monkeypatch.setattr(scanner, "geo_lookup", lambda ip="": (gate.wait(5), "x")[1])
    c = Client()
    t = threading.Thread(target=lambda: c.call("net.geo"))
    t.start()
    try:
        assert c.result("engine.info")["protocol"] == 1     # answered meanwhile
    finally:
        gate.set()
        t.join(5)
