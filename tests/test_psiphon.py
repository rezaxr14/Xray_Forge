"""Psiphon through a user-supplied ConsoleClient binary and config file.

A fake executable plays ConsoleClient, so these tests prove Xray Forge's side
(config handling, port rebinding, secrets, probe, cancel, engine, CLI) and not
that the real Psiphon network works.  No Psiphon Labs values appear here."""

from __future__ import annotations

import json
import os
import shutil
import sys
import threading
import time

import pytest

from xray_forge.cli import main
from xray_forge.core import psiphon
from xray_forge.core.cores import discover
from tests.fakebin import WATCHDOG, make_exe
from tests.test_engine import Client


FAKE = '''\
#!{python}
import json, os, socket, stat, sys, threading, time
if sys.argv[1:] == ["-version"]:
    print("psiphon fake 2.0.0"); sys.exit(0)
assert sys.argv[1] == "-config"
{watchdog}
cfg_path = sys.argv[2]
cfg = json.load(open(cfg_path))
log = os.environ.get("FAKE_LOG")
if log:
    with open(log, "a") as f:
        f.write(json.dumps({{"mode_bits": oct(stat.S_IMODE(os.stat(cfg_path).st_mode)), "cwd": os.getcwd(), "cfg": cfg}}) + "\\n")
if os.environ.get("FAKE_MODE") == "crash":
    sys.stderr.write("no server entries available\\n"); sys.exit(1)
time.sleep(float(os.environ.get("FAKE_DELAY", "0")))
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", cfg["LocalSocksProxyPort"])); srv.listen(8)
body = json.dumps({{"status": "success", "countryCode": "NL", "query": "198.51.100.7"}}).encode()
def serve(c):
    try:
        c.recv(262); c.sendall(b"\\x05\\x00")
        hdr = c.recv(4); atyp = hdr[3]
        if atyp == 3: n = c.recv(1)[0]; c.recv(n + 2)
        elif atyp == 1: c.recv(6)
        else: c.recv(18)
        c.sendall(b"\\x05\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00")
        c.recv(4096)
        c.sendall(b"HTTP/1.1 200 OK\\r\\nContent-Length: %d\\r\\nConnection: close\\r\\n\\r\\n" % len(body) + body)
    finally:
        c.close()
while True:
    c, _ = srv.accept(); threading.Thread(target=serve, args=(c,), daemon=True).start()
'''

USER_CFG = {"PropagationChannelId": "CHAN-USER", "SponsorId": "SPON-USER", "LocalSocksProxyPort": 1080,
            "LocalHttpProxyPort": 8080, "RemoteServerListSignaturePublicKey": "KEY-USER"}


@pytest.fixture(autouse=True)
def clean_env(monkeypatch, tmp_path):
    for spec in discover.SPECS.values():
        monkeypatch.delenv(spec["env"], raising=False)
    monkeypatch.setenv("PATH", str(tmp_path / "emptybin"))
    monkeypatch.setenv("HOME", str(tmp_path / "h"))
    monkeypatch.setenv("APPDATA", str(tmp_path / "h" / "AppData"))
    (tmp_path / "cwd").mkdir()
    monkeypatch.chdir(tmp_path / "cwd")           # discovery searches the cwd, so keep the fake out of it
    monkeypatch.delenv("FAKE_MODE", raising=False)
    monkeypatch.delenv("FAKE_DELAY", raising=False)


@pytest.fixture
def fake(tmp_path, monkeypatch):
    path = make_exe(tmp_path, "ConsoleClient", FAKE.format(python=sys.executable, watchdog=WATCHDOG))
    cfg = tmp_path / "client.config"
    cfg.write_text(json.dumps(USER_CFG))
    log = tmp_path / "calls.jsonl"
    monkeypatch.setenv("FAKE_LOG", str(log))

    class F:
        binary, config = path, str(cfg)

        @staticmethod
        def calls():
            return [json.loads(x) for x in log.read_text().splitlines()] if log.exists() else []
    return F


# --------------------------------------------------------------- config file
def test_load_config_accepts_the_users_file_and_never_invents_values(fake):
    cfg = psiphon.load_config(fake.config)
    assert cfg["PropagationChannelId"] == "CHAN-USER"


@pytest.mark.parametrize("content,msg", [
    ("not json", "JSON"), ("[]", "object"), ("{}", "PropagationChannelId"),
    (json.dumps({"PropagationChannelId": "a"}), "SponsorId"),
    (json.dumps({"PropagationChannelId": 5, "SponsorId": "b"}), "PropagationChannelId"),
])
def test_load_config_rejects_unusable_files(tmp_path, content, msg):
    p = tmp_path / "c.json"
    p.write_text(content)
    with pytest.raises(ValueError, match=msg):
        psiphon.load_config(str(p))


def test_load_config_rejects_missing_and_huge_files(tmp_path):
    with pytest.raises(ValueError, match="cannot read"):
        psiphon.load_config(str(tmp_path / "missing"))
    big = tmp_path / "big"
    big.write_text(" " * (2 * 1024 * 1024))
    with pytest.raises(ValueError, match="too large"):
        psiphon.load_config(str(big))


def test_run_config_rebinds_ports_and_isolates_the_data_directory():
    src = dict(USER_CFG)
    out = psiphon.run_config(src, 7001, 7002, "/tmp/data")
    assert out["LocalSocksProxyPort"] == 7001 and out["LocalHttpProxyPort"] == 7002
    assert out["DataRootDirectory"] == "/tmp/data" and out["SponsorId"] == "SPON-USER"
    assert src == USER_CFG                                              # the input is not mutated


# --------------------------------------------------------------------- probe
def test_probe_runs_the_binary_on_a_rewritten_private_copy(fake):
    r = psiphon.probe(fake.binary, fake.config, timeout=3.0, start_timeout=10.0)
    assert r["status"] == "core ok" and r["cc"] == "NL" and r["exit_ip"] == "198.51.100.7"
    call = fake.calls()[0]
    assert os.name == "nt" or call["mode_bits"] == "0o600"
    assert call["cfg"]["LocalSocksProxyPort"] not in (1080, 0) and call["cfg"]["SponsorId"] == "SPON-USER"
    assert os.path.isdir(call["cfg"]["DataRootDirectory"]) is False       # cleaned up afterwards


def test_probe_reports_a_crash(fake, monkeypatch):
    monkeypatch.setenv("FAKE_MODE", "crash")
    r = psiphon.probe(fake.binary, fake.config, timeout=3.0, start_timeout=10.0)
    assert r["real"] is None and "core exited" in r["status"]


def test_probe_can_be_cancelled_while_connecting(fake, monkeypatch):
    monkeypatch.setenv("FAKE_DELAY", "30")
    stop = threading.Event()
    threading.Timer(0.5, stop.set).start()
    t0 = time.monotonic()
    r = psiphon.probe(fake.binary, fake.config, timeout=3.0, start_timeout=120.0, stop=stop)
    assert time.monotonic() - t0 < 10 and "cancel" in r["status"]


def test_probe_with_a_bad_config_never_starts_the_binary(fake, tmp_path):
    bad = tmp_path / "bad"
    bad.write_text("{}")
    with pytest.raises(ValueError):
        psiphon.probe(fake.binary, str(bad))
    assert fake.calls() == []


# -------------------------------------------------------------------- engine
def test_engine_status_set_paths_and_probe(fake):
    c = Client()
    assert "psiphon.status" in c.result("engine.info")["methods"]
    assert [r["name"] for r in c.result("core.detect")] == ["xray", "singbox", "mihomo"]
    s = c.result("psiphon.status")
    assert s["found"] is False and s["config_ok"] is False
    s = c.result("psiphon.set_path", path=fake.binary)
    assert s["found"] and "fake" in s["version"] and s["source"] == "settings"
    s = c.result("psiphon.set_config", path=fake.config)
    assert s["config_ok"] is True and s["config_path"] == fake.config
    assert "CHAN-USER" not in json.dumps(s) and "SPON-USER" not in json.dumps(s)     # values never echoed
    done = c.wait_job(c.result("psiphon.probe", start_timeout=10)["job"], timeout=20)
    assert done["result"]["status"] == "core ok" and done["result"]["cc"] == "NL"


@pytest.mark.skipif(os.name == "nt", reason="uses a /bin/sh script")
def test_engine_set_path_does_not_require_a_version_command(tmp_path):
    odd = tmp_path / "odd"
    odd.write_text("#!/bin/sh\nexit 3\n")
    odd.chmod(0o755)
    s = Client().result("psiphon.set_path", path=str(odd))
    assert s["found"] is True and s["ok"] is False


def test_engine_validation(fake, tmp_path):
    c = Client()
    for method, params in [("psiphon.set_path", {"path": "rel"}), ("psiphon.set_path", {"path": 5}),
                           ("psiphon.set_path", {"path": str(tmp_path / "nope")}),
                           ("psiphon.set_config", {"path": "rel"}), ("psiphon.set_config", {"path": None}),
                           ("psiphon.set_config", {"path": str(tmp_path / "nope")}),
                           ("psiphon.probe", {})]:
        assert c.call(method, **params)["error"]["code"] == -32602, (method, params)
    c.result("psiphon.set_path", path=fake.binary)
    assert c.call("psiphon.probe", timeout=0)["error"]["code"] == -32602
    shutil.copy(fake.binary, "ConsoleClient")                        # exists and is executable, but relative
    shutil.copy(fake.config, "client.config")
    for method, key in (("psiphon.set_path", "ConsoleClient"), ("psiphon.set_config", "client.config")):
        r = c.call(method, path=key)
        assert r["error"]["code"] == -32602 and "absolute" in r["error"]["message"], method
    assert "set its config" in c.call("psiphon.probe")["error"]["message"]
    bad = tmp_path / "bad.json"
    bad.write_text("{}")
    assert "PropagationChannelId" in c.call("psiphon.set_config", path=str(bad))["error"]["message"]
    assert c.result("psiphon.set_config", path="")["config_ok"] is False     # clears


def test_engine_cancel_kills_the_client(fake, monkeypatch):
    monkeypatch.setenv("FAKE_DELAY", "30")
    c = Client()
    c.result("psiphon.set_path", path=fake.binary)
    c.result("psiphon.set_config", path=fake.config)
    job = c.result("psiphon.probe", start_timeout=120)["job"]
    time.sleep(0.7)
    c.result("job.cancel", job=job)
    done = c.wait_job(job, timeout=10)
    assert done["cancelled"] is True and "cancel" in done["result"]["status"]


# ----------------------------------------------------------------------- cli
def test_cli_status_and_probe(fake, capsys, monkeypatch):
    assert main(["psiphon", "status", "--binary", fake.binary, "--config", fake.config]) == 0
    assert "config ok" in capsys.readouterr().out
    assert main(["psiphon", "probe", "--binary", fake.binary, "--config", fake.config,
                 "--timeout", "3", "--start-timeout", "10"]) == 0
    assert "core ok" in capsys.readouterr().out
    monkeypatch.setenv("FAKE_MODE", "crash")
    assert main(["psiphon", "probe", "--binary", fake.binary, "--config", fake.config,
                 "--timeout", "3", "--start-timeout", "10"]) == 1
    assert "core exited" in capsys.readouterr().out
    assert main(["psiphon", "probe", "--config", fake.config]) == 1          # no binary anywhere
    assert "not found" in capsys.readouterr().out
    assert main(["psiphon", "probe", "--binary", fake.binary]) == 1           # no config
    assert "config" in capsys.readouterr().out
