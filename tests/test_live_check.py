"""tools/live_check.py: the report a local agent sends back (offline, with fake binaries)."""

from __future__ import annotations

import importlib.util
import json
import pathlib
import sys

import pytest

from tests.fakebin import WATCHDOG, make_exe
from tests.test_psiphon import FAKE as PSI_FAKE, USER_CFG  # noqa: F401
from tests.test_masque import core as masque_core  # noqa: F401

ROOT = pathlib.Path(__file__).resolve().parents[1]
SECRET_LINK = ("vless://13b8ac3f-e8de-4b2d-82db-e9130d288a54@127.0.0.1:1"
               "?security=tls&sni=secret-sni.example.com&type=ws&host=secret-host.example.com&path=%2Fsecret#nm")


@pytest.fixture
def live():
    spec = importlib.util.spec_from_file_location("live_check", ROOT / "tools" / "live_check.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(autouse=True)
def env(monkeypatch, tmp_path):
    from xray_forge.core.cores import discover
    for spec in discover.SPECS.values():
        monkeypatch.delenv(spec["env"], raising=False)
    monkeypatch.setenv("PATH", str(tmp_path / "emptybin"))
    monkeypatch.setenv("HOME", str(tmp_path / "h"))
    monkeypatch.setenv("APPDATA", str(tmp_path / "h" / "AppData"))
    (tmp_path / "cwd").mkdir()
    monkeypatch.chdir(tmp_path / "cwd")


def run(live, tmp_path, *argv):
    out = tmp_path / "report.json"
    code = live.main([*argv, "--out", str(out)])
    return code, json.loads(out.read_text())


def test_environment_only_report_is_well_formed(live, tmp_path):
    code, rep = run(live, tmp_path, "env")
    assert code == 0 and rep["schema"] == 1
    assert rep["env"]["python"] and rep["env"]["platform"] and rep["env"]["xray_forge"]
    assert {c["name"] for c in rep["env"]["cores"]} >= {"xray", "singbox", "mihomo", "singbox_extended", "psiphon"}
    assert rep["checks"] == []


def test_masque_and_psiphon_checks_pass_with_fake_binaries(live, tmp_path, masque_core, monkeypatch):
    p = make_exe(tmp_path, "ConsoleClient", PSI_FAKE.format(python=sys.executable, watchdog=WATCHDOG))
    cfg = tmp_path / "client.config"
    cfg.write_text(json.dumps(USER_CFG))
    monkeypatch.setenv("FAKE_LOG", str(tmp_path / "x.log"))
    code, rep = run(live, tmp_path, "masque", "psiphon", "--masque-binary", masque_core.binary,
                    "--psiphon-binary", p, "--psiphon-config", str(cfg), "--timeout", "3", "--start-timeout", "10")
    by = {c["name"]: c for c in rep["checks"]}
    assert code == 0 and by["masque"]["ok"] and by["psiphon"]["ok"]
    assert by["masque"]["cc"] == "DE" and by["psiphon"]["cc"] == "NL"
    text = json.dumps(rep)
    for secret in ("CHAN-USER", "SPON-USER", "KEY-USER", "198.51.100.7", "203.0.113.9"):   # incl. the exit IPs
        assert secret not in text


def test_failures_are_reported_with_a_nonzero_exit_code(live, tmp_path, masque_core, monkeypatch):
    monkeypatch.setenv("FAKE_MODE", "unsupported")
    code, rep = run(live, tmp_path, "masque", "--masque-binary", masque_core.binary)
    assert code == 1 and rep["checks"][0]["ok"] is False and "sing-box-extended" in rep["checks"][0]["detail"]


def test_missing_inputs_are_skipped_not_failed(live, tmp_path):
    code, rep = run(live, tmp_path, "masque", "psiphon", "vless")
    assert code == 0
    assert {c["name"]: c["status"] for c in rep["checks"]} == {"masque": "skipped", "psiphon": "skipped", "vless": "skipped"}
    assert all(c["ok"] is None and c["detail"] for c in rep["checks"])


def test_vless_report_never_contains_the_link_or_the_endpoint(live, tmp_path, monkeypatch):
    link = tmp_path / "link.txt"
    link.write_text(SECRET_LINK + "\n")
    code, rep = run(live, tmp_path, "vless", "--link-file", str(link), "--timeout", "1")
    chk = rep["checks"][0]
    assert code == 1 and chk["ok"] is False and chk["detail"] and chk["stages"] and chk["stages"][0]["name"] == "dns"
    text = json.dumps(rep)
    for secret in ("13b8ac3f", "secret-sni", "secret-host", "/secret", "127.0.0.1"):
        assert secret not in text


def test_vless_endpoint_only_with_explicit_flag(live, tmp_path):
    link = tmp_path / "link.txt"
    link.write_text(SECRET_LINK)
    _, rep = run(live, tmp_path, "vless", "--link-file", str(link), "--timeout", "1", "--include-endpoint")
    assert "127.0.0.1:1" in json.dumps(rep) and "13b8ac3f" not in json.dumps(rep)


def test_bad_arguments(live, tmp_path, capsys):
    with pytest.raises(SystemExit):
        live.main(["nonsense"])
    assert live.main(["vless", "--link-file", str(tmp_path / "missing")]) == 2
