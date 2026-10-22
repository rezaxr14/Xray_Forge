"""masque.* engine methods (the fork is played by tests/test_masque.py's fake core)."""

from __future__ import annotations

import json
import sys

import pytest

from xray_forge.core import masque
from xray_forge.core.cores import discover
from tests.test_engine import Client
from tests.test_masque import core  # noqa: F401  (fixture: fake sing-box-extended executable)

posix = pytest.mark.skipif(sys.platform.startswith("win"), reason="python-script fake core")


@pytest.fixture(autouse=True)
def clean_env(monkeypatch, tmp_path):
    for spec in discover.SPECS.values():
        monkeypatch.delenv(spec["env"], raising=False)
    monkeypatch.setenv("PATH", str(tmp_path / "emptybin"))
    monkeypatch.setenv("HOME", str(tmp_path / "h"))
    monkeypatch.setenv("APPDATA", str(tmp_path / "h" / "AppData"))
    monkeypatch.chdir(tmp_path)


def test_methods_are_advertised():
    info = Client().result("engine.info")
    assert {"masque.status", "masque.set_path", "masque.config", "masque.probe"} <= set(info["methods"])


def test_the_fork_is_not_a_registered_core():
    c = Client()
    assert [r["name"] for r in c.result("core.detect")] == ["xray", "singbox", "mihomo"]
    assert c.call("core.set_path", name="singbox_extended", path="/bin/true")["error"]["code"] == -32602


def test_status_without_a_binary():
    r = Client().result("masque.status")
    assert r["found"] is False and r["supported"] is False and "not found" in r["detail"]


@posix
def test_set_path_persists_and_status_checks_masque_support(core):
    c = Client()
    r = c.result("masque.set_path", path=core.binary)
    assert r["found"] and r["ok"] and "extended" in r["version"] and r["source"] == "settings"
    s = c.result("masque.status")
    assert s["found"] and s["path"] == core.binary and s["supported"] is True and s["detail"] == ""
    assert discover.configured_path("singbox_extended") == core.binary
    assert discover.configured_path("singbox") == ""              # the official sing-box slot is untouched
    cleared = c.result("masque.set_path", path="")
    assert cleared["found"] is False


@posix
def test_status_explains_an_ordinary_sing_box(core, monkeypatch):
    c = Client()
    c.result("masque.set_path", path=core.binary)
    monkeypatch.setenv("FAKE_MODE", "unsupported")
    s = c.result("masque.status")
    assert s["found"] and s["supported"] is False and "sing-box-extended" in s["detail"]


@posix
def test_set_path_rejects_bad_input(tmp_path):
    c = Client()
    plain = tmp_path / "plain"
    plain.write_text("x")
    for path in ("relative/sing-box", str(tmp_path / "missing"), str(plain), 5, None):
        assert c.call("masque.set_path", path=path)["error"]["code"] == -32602, path


def test_config_returns_plain_json_with_secrets_redacted_by_default():
    c = Client()
    r = c.result("masque.config", options={"use_http2": True, "auth_token": "TOKEN-SECRET", "profile_id": "pid"}, socks_port=7000)
    cfg = json.loads(r["content"])
    ob = next(o for o in cfg["outbounds"] if o["type"] == "masque")
    assert ob["use_http2"] is True and ob["profile"]["id"] == "pid" and ob["profile"]["auth_token"] == "***"
    assert cfg["inbounds"][0]["listen_port"] == 7000 and r["redacted"] is True
    full = c.result("masque.config", options={"auth_token": "TOKEN-SECRET"}, include_secrets=True)
    assert json.loads(full["content"])["outbounds"][1]["profile"]["auth_token"] == "TOKEN-SECRET" and full["redacted"] is False


@pytest.mark.parametrize("params", [
    {"options": {"bogus": 1}}, {"options": "x"}, {"options": {"port": 443}}, {"options": {"use_http2": "yes"}},
    {"socks_port": 0}, {"socks_port": 70000}, {"socks_port": "1080"}, {"socks_port": True}, {"include_secrets": "yes"},
])
def test_config_validates(params):
    assert Client().call("masque.config", **params)["error"]["code"] == -32602, params


@posix
def test_probe_job_reports_the_exit(core):
    c = Client()
    c.result("masque.set_path", path=core.binary)
    r = c.result("masque.probe", options={"use_l4_proxy": True})
    done = c.wait_job(r["job"], timeout=20)
    assert done["type"] == "done" and done["result"]["status"] == "core ok" and done["result"]["cc"] == "DE"
    assert c.job_events(r["job"], "item")[0]["data"]["exit_ip"] == "203.0.113.9"
    run = [x for x in core.calls() if x["cmd"] == "run"][0]
    assert next(o for o in run["cfg"]["outbounds"] if o["type"] == "masque")["use_l4_proxy"] is True


@posix
def test_probe_job_with_an_ordinary_sing_box_says_what_is_needed(core, monkeypatch):
    c = Client()
    c.result("masque.set_path", path=core.binary)
    monkeypatch.setenv("FAKE_MODE", "unsupported")
    done = c.wait_job(c.result("masque.probe")["job"], timeout=20)
    assert done["result"]["real"] is None and "sing-box-extended" in done["result"]["status"]


@posix
def test_cancelling_a_probe_stops_the_core(core, monkeypatch):
    import time
    monkeypatch.setenv("FAKE_DELAY", "30")
    c = Client()
    c.result("masque.set_path", path=core.binary)
    job = c.result("masque.probe", start_timeout=60)["job"]
    time.sleep(0.7)
    c.result("job.cancel", job=job)
    done = c.wait_job(job, timeout=10)
    assert done["cancelled"] is True and "cancel" in done["result"]["status"]


def test_probe_without_a_binary_fails_fast_with_advice():
    r = Client().call("masque.probe")
    assert r["error"]["code"] == -32602 and "set its path" in r["error"]["message"]


@pytest.mark.parametrize("params", [
    {"timeout": 0}, {"timeout": 500}, {"timeout": "5"}, {"timeout": True},
    {"start_timeout": 0}, {"start_timeout": 301}, {"start_timeout": "x"}, {"options": {"auth_token": "a\nb"}},
])
@posix
def test_probe_validates_before_starting(params, core):
    c = Client()
    c.result("masque.set_path", path=core.binary)
    assert c.call("masque.probe", **params)["error"]["code"] == -32602, params
    assert not c.jobs.active()


@posix
def test_set_path_rejects_a_relative_path_even_when_the_file_exists(core, tmp_path):
    import os
    import shutil
    here = tmp_path / "sing-box-extended"
    shutil.copy(core.binary, here)
    os.chmod(here, 0o755)
    r = Client().call("masque.set_path", path="sing-box-extended")        # cwd is tmp_path
    assert r["error"]["code"] == -32602 and "absolute" in r["error"]["message"]
