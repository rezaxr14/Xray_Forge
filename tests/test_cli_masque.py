"""`masque` CLI subcommand (fake sing-box-extended from tests/test_masque.py)."""

from __future__ import annotations

import json
import sys

import pytest

from xray_forge.cli import build_parser, main
from xray_forge.core.cores import discover
from tests.test_masque import core  # noqa: F401

posix = pytest.mark.skipif(sys.platform.startswith("win"), reason="python-script fake core")


@pytest.fixture(autouse=True)
def clean_env(monkeypatch, tmp_path):
    for spec in discover.SPECS.values():
        monkeypatch.delenv(spec["env"], raising=False)
    monkeypatch.setenv("PATH", str(tmp_path / "emptybin"))
    monkeypatch.chdir(tmp_path)


def test_parser_knows_masque():
    assert build_parser().parse_args(["masque", "config"]).cmd == "masque"


def test_config_prints_json_and_flags_map_to_options(capsys):
    assert main(["masque", "config", "--http2", "--l4-proxy", "--address", "162.159.198.1", "--port", "443",
                 "--profile-id", "pid", "--socks-port", "7001"]) == 0
    cfg = json.loads(capsys.readouterr().out)
    ob = next(o for o in cfg["outbounds"] if o["type"] == "masque")
    assert ob["use_http2"] is True and ob["use_l4_proxy"] is True and ob["profile"]["id"] == "pid"
    assert cfg["inbounds"][0]["listen_port"] == 7001


def test_config_rejects_bad_options(capsys):
    assert main(["masque", "config", "--port", "443"]) == 2          # port needs an address
    assert "address" in capsys.readouterr().err


@posix
def test_check_reports_support(core, monkeypatch, capsys):
    assert main(["masque", "check", "--binary", core.binary]) == 0
    assert "supported" in capsys.readouterr().out
    monkeypatch.setenv("FAKE_MODE", "unsupported")
    assert main(["masque", "check", "--binary", core.binary]) == 1
    assert "sing-box-extended" in capsys.readouterr().out


def test_check_without_a_binary_says_so(capsys):
    assert main(["masque", "check"]) == 1
    assert "not found" in capsys.readouterr().out


@posix
def test_probe_prints_the_exit_and_sets_the_exit_code(core, monkeypatch, capsys):
    assert main(["masque", "probe", "--binary", core.binary, "--timeout", "3"]) == 0
    out = capsys.readouterr().out
    assert "core ok" in out and "DE" in out and "203.0.113.9" in out
    monkeypatch.setenv("FAKE_MODE", "crash")
    assert main(["masque", "probe", "--binary", core.binary, "--timeout", "3"]) == 1
    assert "core exited" in capsys.readouterr().out
