"""core.release / core.install engine methods (fake GitHub fetcher, no network)."""

from __future__ import annotations

import os
import sys
import threading
import time

import pytest

from xray_forge.core.cores import discover, install
from tests.test_core_install import SCRIPT, FakeFetcher, asset, make_zip, make_targz  # noqa: F401
from tests.test_engine import Client

posix = pytest.mark.skipif(os.name == "nt", reason="runs the extracted fake binary")


@pytest.fixture(autouse=True)
def env(monkeypatch, tmp_path):
    for spec in discover.SPECS.values():
        monkeypatch.delenv(spec["env"], raising=False)
    monkeypatch.setenv("PATH", str(tmp_path / "emptybin"))
    monkeypatch.setenv("HOME", str(tmp_path / "h"))
    (tmp_path / "cwd").mkdir()
    monkeypatch.chdir(tmp_path / "cwd")
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(install, "platform_key", lambda plat=None, machine=None: ("linux", "amd64"))


def serve(monkeypatch, name, body, repo="XTLS/Xray-core", **kw):
    a, blobs = asset(name, body, repo, **kw)
    fetcher = FakeFetcher([a], blobs)
    monkeypatch.setattr(install, "GitHubFetcher", lambda *a, **k: fetcher)
    return fetcher


def test_methods_are_advertised():
    assert {"core.release", "core.install"} <= set(Client().result("engine.info")["methods"])


def test_release_describes_the_download_without_fetching_it(monkeypatch):
    body = make_zip({"xray": SCRIPT})
    f = serve(monkeypatch, "Xray-linux-64.zip", body)
    r = Client().result("core.release", name="xray")
    assert r["tag"] == "v1.2.3" and r["asset"] == "Xray-linux-64.zip" and r["repo"] == "XTLS/Xray-core"
    assert r["size"] == len(body) and len(r["sha256"]) == 64 and r["url"].startswith("https://github.com/XTLS/Xray-core/")
    assert not [u for u in f.urls if u[0] == "download"]


@pytest.mark.parametrize("name", ["psiphon", "nope", "", None, 5, ["xray"]])
def test_release_and_install_reject_unknown_cores(name):
    c = Client()
    assert c.call("core.release", name=name)["error"]["code"] == -32602
    assert c.call("core.install", name=name)["error"]["code"] == -32602
    assert not c.jobs.active()


def test_release_failures_come_back_as_application_errors(monkeypatch):
    serve(monkeypatch, "Xray-linux-64.zip", make_zip({"xray": SCRIPT}), digest=False)
    r = Client().call("core.release", name="xray")
    assert r["error"]["code"] == -32000 and r["error"]["message"].startswith("the release has no sha256 digest")   # clean text, no exception class


@posix
def test_install_job_downloads_verifies_and_remembers_the_binary(monkeypatch):
    body = make_zip({"xray": SCRIPT, "geoip.dat": b"g"})
    serve(monkeypatch, "Xray-linux-64.zip", body)
    c = Client()
    job = c.result("core.install", name="xray")["job"]
    done = c.wait_job(job, timeout=20)
    res = done["result"]
    assert done["type"] == "done" and res["ok"] is True and "fake 9.9.9" in res["version"] and res["tag"] == "v1.2.3"
    assert discover.configured_path("xray") == res["path"] and os.access(res["path"], os.X_OK)
    prog = c.job_events(job, "progress")
    assert prog and prog[-1]["done"] == prog[-1]["total"] == len(body)
    assert [r["name"] for r in c.result("core.detect") if r["name"] == "xray"] and next(r for r in c.result("core.detect") if r["name"] == "xray")["found"]


@posix
def test_the_extended_fork_installs_into_its_own_slot(monkeypatch):
    body = make_targz({"x/sing-box": SCRIPT})
    serve(monkeypatch, "sing-box-extended-1.12.1-linux-amd64.tar.gz", body, repo="shtorm-7/sing-box-extended")
    c = Client()
    done = c.wait_job(c.result("core.install", name="singbox_extended")["job"], timeout=20)
    assert done["result"]["ok"] and discover.configured_path("singbox_extended") == done["result"]["path"]
    assert discover.configured_path("singbox") == ""
    assert c.result("masque.status")["found"] is True


@posix
def test_a_binary_that_does_not_run_is_not_remembered(monkeypatch):
    body = make_zip({"xray": b"#!/bin/sh\nexit 3\n"})
    serve(monkeypatch, "Xray-linux-64.zip", body)
    c = Client()
    done = c.wait_job(c.result("core.install", name="xray")["job"], timeout=20)
    assert done["type"] == "done" and done["result"]["ok"] is False
    assert discover.configured_path("xray") == ""


def test_install_failures_are_job_errors_and_leave_settings_alone(monkeypatch):
    body = make_zip({"xray": SCRIPT})
    serve(monkeypatch, "Xray-linux-64.zip", body, digest="sha256:" + "0" * 64)
    c = Client()
    done = c.wait_job(c.result("core.install", name="xray")["job"], timeout=20)
    assert done["type"] == "error" and "checksum" in done["message"]
    assert discover.configured_path("xray") == ""


def test_install_can_be_cancelled(monkeypatch):
    body = make_zip({"xray": SCRIPT + b"#" * 300_000})
    f = serve(monkeypatch, "Xray-linux-64.zip", body)
    real = f.download
    gate = threading.Event()

    def slow(url, fileobj, progress=None, stop=None, limit=None):
        gate.set()
        for _ in range(200):
            if stop is not None and stop.is_set():
                raise install.Cancelled()
            time.sleep(0.02)
        return real(url, fileobj, progress, stop, limit)
    f.download = slow
    c = Client()
    job = c.result("core.install", name="xray")["job"]
    assert gate.wait(5)
    c.result("job.cancel", job=job)
    done = c.wait_job(job, timeout=10)
    assert done["cancelled"] is True and done["result"]["status"] == "cancelled"
    assert discover.configured_path("xray") == ""
