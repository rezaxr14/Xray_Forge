"""Engine methods for scanners, SNI search, WARP and MITM-DF."""

from __future__ import annotations

import json
import time

import pytest

from xray_forge.core import scan_session, warp
from xray_forge.core.sni_search import SniHit, SniSearch
from tests.test_engine import Client


def _fake_scan(monkeypatch, alive_octets=(1, 2)):
    def jitter(ip, port, attempts=2, timeout=5.0):
        ok = int(ip.rsplit(".", 1)[1]) in alive_octets
        return (10.0, 1.0) if ok else (None, None)

    class _Sock:
        def close(self):
            pass
    monkeypatch.setattr(scan_session, "tcp_jitter", jitter)
    monkeypatch.setattr(scan_session, "tls_connect",
                        lambda ip, port, **kw: (object(), _Sock(), {"tls_ms": 33.0, "ver": "TLSv1.3"}))


# ------------------------------------------------------------------ scan
def test_scan_job_streams_and_persists(monkeypatch):
    _fake_scan(monkeypatch)
    c = Client()
    r = c.result("scan.run", cidrs=["10.0.0.0/29"], count=6, workers=2, session="t1")
    assert r["session"] == "t1" and r["targets"] == 6
    done = c.wait_job(r["job"])
    assert done["type"] == "done"
    assert done["result"]["total"] == 6 and done["result"]["alive"] == 2
    assert len(c.job_events(r["job"], "item")) == 6
    assert c.job_events(r["job"], "progress")[-1]["done"] == 6

    sessions = c.result("scan.sessions")
    assert sessions == [{"name": "t1", "total": 6, "alive": 2, "pending": 0}]
    got = c.result("scan.get", session="t1")
    assert [x["alive"] for x in got["results"]][:2] == [True, True]
    assert len(got["results"]) == 6
    csv_out = c.result("scan.export", session="t1", format="csv")["content"]
    assert csv_out.splitlines()[0].startswith("ip,port,alive")
    assert json.loads(c.result("scan.export", session="t1", format="json")["content"])["name"] == "t1"


def test_scan_cancel_keeps_rest_pending(monkeypatch):
    import threading
    gate = threading.Event()
    started = threading.Event()

    def jitter(ip, port, attempts=2, timeout=5.0):
        started.set()
        gate.wait(3)
        return (None, None)
    monkeypatch.setattr(scan_session, "tcp_jitter", jitter)
    c = Client()
    r = c.result("scan.run", cidrs=["10.1.0.0/24"], count=40, workers=1, session="cx")
    assert started.wait(2)
    c.result("job.cancel", job=r["job"])
    gate.set()
    done = c.wait_job(r["job"])
    assert done["cancelled"] is True
    assert done["result"]["pending"] > 0


def test_scan_validation():
    c = Client()
    for bad in ({"cidrs": []}, {"cidrs": ["10.0.0.0/30"], "port": "99999"},
                {"cidrs": ["10.0.0.0/30"], "workers": 0},
                {"cidrs": ["10.0.0.0/30"], "session": "../evil"},
                {"cidrs": ["10.0.0.0/30"], "session": "a/b"},
                {"cidrs": ["not-a-cidr"]}, {"cidrs": "10.0.0.0/30"}):
        assert c.call("scan.run", **bad)["error"]["code"] == -32602, bad
    assert c.call("scan.get", session="../../etc/passwd")["error"]["code"] == -32602
    assert c.call("scan.export", session="x", format="xml")["error"]["code"] == -32602


# ------------------------------------------------------------------- sni
def test_sni_job_and_from_scan(monkeypatch):
    _fake_scan(monkeypatch)
    c = Client()
    c.wait_job(c.result("scan.run", cidrs=["10.0.0.0/29"], count=6, session="base")["job"])

    def probe(self, ip, sni, port="443", frag=None, timeout=5.0, http_check=True, stop=None):
        good = sni == "good.example"
        return SniHit(ip=ip, port=port, sni=sni, ok=good, http_ok=good,
                      tls_ms=20.0 if good else None, tls_ver="TLSv1.3" if good else "",
                      info="HTTP/1.1 200 OK" if good else "tls: reset")
    monkeypatch.setattr(SniSearch, "probe", probe)
    r = c.result("sni.run", ips=[], snis=["good.example", "bad.example"],
                 from_scan="base", session="s1", workers=2)
    assert r["pairs"] == 4          # 2 alive IPs x 2 SNIs
    done = c.wait_job(r["job"])
    assert done["result"]["working"] == 2 and done["result"]["total"] == 4
    assert len(c.job_events(r["job"], "item")) == 4
    got = c.result("sni.get", session="s1")
    assert {h["sni"] for h in got["results"]} == {"good.example"}
    assert c.result("sni.sessions")[0]["working"] == 2
    assert "ip,port" in c.result("sni.export", session="s1")["content"].splitlines()[0]


def test_sni_presets_and_validation():
    c = Client()
    assert "www.cloudflare.com" in c.result("sni.presets")
    assert c.call("sni.run", ips=[], snis=[])["error"]["code"] == -32602
    assert c.call("sni.run", ips=["1.1.1.1"], snis=["a"], session="bad name")["error"]["code"] == -32602
    assert c.call("sni.run", ips=["1.1.1.1"], snis=["a"], port="0")["error"]["code"] == -32602


# ------------------------------------------------------------------ warp
def _account():
    return warp.WarpAccount(device_id="dev-0123456789abcdef", token="tok",
                            private_key="cHJpdmF0ZS1rZXktZm9yLXRlc3Rpbmctb25seS0wMDE=",
                            public_key="cHVi", peer_public_key="cGVlcg==",
                            client_id="abcdef", ipv4="172.16.0.2/32",
                            endpoint="162.159.192.1:2408")


def test_warp_status_and_config_without_account():
    c = Client()
    assert c.result("warp.status") == {"registered": False}
    assert c.call("warp.config")["error"]["code"] == -32602


def test_warp_status_hides_secrets(monkeypatch):
    c = Client()
    warp.save_account(_account())
    st = c.result("warp.status")
    assert st["registered"] and st["device_id"] == "dev-01234567"
    blob = json.dumps(st)
    assert "tok" not in blob.replace("endpoint", "") and "private" not in blob.lower()
    assert "cHJpdmF0ZS" not in blob


def test_warp_config_formats():
    c = Client()
    warp.save_account(_account())
    sb = json.loads(c.result("warp.config", endpoint="1.2.3.4:500")["content"])
    assert "wireguard" in json.dumps(sb) and "1.2.3.4" in json.dumps(sb)
    for core in ("xray", "singbox", "mihomo"):
        assert c.result("warp.config", format=core)["content"]
    assert c.call("warp.config", format="uri")["error"]["code"] == -32602


def test_warp_register_uses_core_and_saves(monkeypatch):
    c = Client()
    monkeypatch.setattr(warp, "register_account", lambda *a, **k: _account())
    st = c.result("warp.register")
    assert st["registered"] is True
    assert warp.load_account().token == "tok"


def test_warp_register_failure_is_rpc_error(monkeypatch):
    c = Client()
    monkeypatch.setattr(warp, "register_account",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("blocked")))
    r = c.call("warp.register")
    assert r["error"]["code"] == -32000 and "blocked" in r["error"]["message"]


def test_warp_scan_job(monkeypatch):
    monkeypatch.setattr(warp, "scan_endpoints",
                        lambda count, workers, progress=None, stop=None:
                        [("1.1.1.1:2408", 12.5), ("2.2.2.2:500", 30.0)])
    c = Client()
    job = c.result("warp.scan", count=5, workers=2)["job"]
    done = c.wait_job(job)
    assert done["result"] == {"responsive": 2}
    assert [i["data"]["endpoint"] for i in c.job_events(job, "item")] == ["1.1.1.1:2408", "2.2.2.2:500"]
    assert c.call("warp.scan", count=0)["error"]["code"] == -32602


# ------------------------------------------------------------------ mitm
def test_mitm_groups_and_build():
    c = Client()
    g = c.result("mitm.groups")
    assert {"google", "meta", "fastly"} <= set(g["groups"])
    assert g["min_xray_version"]
    cfg = json.loads(c.result("mitm.build", groups=["google"])["content"])
    assert "inbounds" in cfg and "outbounds" in cfg
    assert c.call("mitm.build", groups=["nope"])["error"]["code"] == -32602
    assert c.call("mitm.build", use_generated_ca=True)["error"]["code"] == -32602


def test_mitm_generate_ca_and_use_it():
    pytest.importorskip("cryptography")
    c = Client()
    assert c.result("mitm.ca_paths")["exists"] is False
    r = c.result("mitm.generate_ca", cn="Test CA", permitted_domains=["example.com"])
    assert r["constrained"] is True
    import os
    assert os.path.isfile(r["cert"]) and os.path.isfile(r["key"])
    assert "BEGIN" not in json.dumps(r)             # key material never returned
    assert c.result("mitm.ca_paths")["exists"] is True
    built = c.result("mitm.build", groups=["google"], use_generated_ca=True)["content"]
    assert r["cert"].replace("\\", "\\\\") in built or r["cert"] in built


def test_mitm_guide_and_validation():
    c = Client()
    assert "MITM-DomainFronting setup" in c.result("mitm.guide", platform="windows")["content"]
    assert c.call("mitm.guide", platform="beos")["error"]["code"] == -32602
    assert c.call("mitm.generate_ca", cn="")["error"]["code"] == -32602
