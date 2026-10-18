"""core.detect / core.set_path and the health.run core precheck."""

from __future__ import annotations

import stat
import sys

import pytest

from xray_forge.core.cores import discover
from tests.test_engine import Client

posix = pytest.mark.skipif(sys.platform.startswith("win"), reason="shell-script fake cores")


def _fake(path, banner="v1.2.3", code=0):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"#!/bin/sh\necho '{banner}'\nexit {code}\n")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return str(path)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch, tmp_path):
    for spec in discover.SPECS.values():
        monkeypatch.delenv(spec["env"], raising=False)
    monkeypatch.setenv("PATH", str(tmp_path / "emptybin"))
    monkeypatch.setenv("HOME", str(tmp_path / "h"))
    monkeypatch.setenv("APPDATA", str(tmp_path / "h" / "AppData"))
    monkeypatch.chdir(tmp_path)


def test_detect_reports_all_cores_even_when_missing():
    rows = Client().result("core.detect")
    assert [r["name"] for r in rows] == ["xray", "singbox", "mihomo"]
    assert all(not r["found"] and r["version"] == "" for r in rows)


@posix
def test_set_path_validates_persists_and_clears(tmp_path):
    c = Client()
    exe = _fake(tmp_path / "x" / "xray", banner="Xray 25.9.9")
    r = c.result("core.set_path", name="xray", path=exe)
    assert r["found"] and r["ok"] and r["version"] == "Xray 25.9.9" and r["source"] == "settings"
    assert [x for x in c.result("core.detect") if x["name"] == "xray"][0]["path"] == exe
    cleared = c.result("core.set_path", name="xray", path="")
    assert not cleared["found"]


@posix
def test_set_path_rejects_bad_input(tmp_path):
    c = Client()
    plain = tmp_path / "plain"
    plain.write_text("x")
    broken = _fake(tmp_path / "broken", banner="oops", code=1)
    for params in ({"name": "nope", "path": "/bin/true"},
                   {"name": "xray", "path": "relative/xray"},
                   {"name": "xray", "path": str(tmp_path / "missing")},
                   {"name": "xray", "path": str(plain)},
                   {"name": "xray", "path": broken},
                   {"name": "xray", "path": 5}):
        assert c.call("core.set_path", **params)["error"]["code"] == -32602, params
    assert not c.result("core.detect")[0]["found"]          # nothing was saved


def test_health_run_with_missing_core_explains():
    c = Client()
    line = "vless://13b8ac3f-e8de-4b2d-82db-e9130d288a54@127.0.0.1:9?security=tls&type=ws#t"
    for core in ("auto", "xray"):
        r = c.call("health.run", lines=[line], core=core)
        assert r["error"]["code"] == -32602 and "Cores tab" in r["error"]["message"]


@posix
def test_health_run_accepts_an_installed_core(tmp_path, monkeypatch):
    from xray_forge.core import healthcheck as hc
    monkeypatch.setattr(hc, "run_health_check", lambda line, **kw: hc.HealthReport(line=line))
    c = Client()
    c.result("core.set_path", name="xray", path=_fake(tmp_path / "xray"))
    job = c.result("health.run", lines=["vless://u@h:1#x"], core="xray")["job"]
    assert c.wait_job(job)["type"] == "done"
