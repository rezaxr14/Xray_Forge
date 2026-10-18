"""Core binary discovery (nothing could find a core before this existed)."""

from __future__ import annotations

import os
import stat
import sys

import pytest

from xray_forge.core import settings
from xray_forge.core.cores import discover, get_core, iter_cores

posix = pytest.mark.skipif(sys.platform.startswith("win"), reason="shell-script fake cores")


def _fake_core(path, banner="Xray 25.1.1 (fake)", code=0):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"#!/bin/sh\necho '{banner}'\nexit {code}\n")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return str(path)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch, tmp_path):
    for spec in discover.SPECS.values():
        monkeypatch.delenv(spec["env"], raising=False)
    monkeypatch.setenv("PATH", str(tmp_path / "emptybin"))     # nothing on PATH
    monkeypatch.setenv("HOME", str(tmp_path / "h"))
    monkeypatch.setenv("APPDATA", str(tmp_path / "h" / "AppData"))
    monkeypatch.chdir(tmp_path)


def test_every_registered_core_has_a_spec():
    assert {c.name for c in iter_cores()} <= set(discover.SPECS)


def test_nothing_found_by_default():
    for c in iter_cores():
        assert c.find_binary() == ""


@posix
def test_env_var_finds_core(tmp_path, monkeypatch):
    exe = _fake_core(tmp_path / "somewhere" / "xray")
    monkeypatch.setenv("XRAY_CORE", exe)
    assert get_core("xray").find_binary() == exe
    assert discover.find("xray") == (exe, "env")


@posix
def test_settings_path_beats_env(tmp_path, monkeypatch):
    a = _fake_core(tmp_path / "a" / "sing-box")
    b = _fake_core(tmp_path / "b" / "sing-box")
    monkeypatch.setenv("SINGBOX_CORE", b)
    discover.save_path("singbox", a)
    assert get_core("singbox").find_binary() == a
    discover.save_path("singbox", "")
    assert get_core("singbox").find_binary() == b


@posix
def test_v2rayn_layout_and_local_bin(tmp_path, monkeypatch):
    exe = _fake_core(tmp_path / "h" / "AppData" / "v2rayN" / "bin" / "mihomo" / "mihomo")
    assert discover.find("mihomo") == (exe, "v2rayN")
    local = _fake_core(tmp_path / "bin" / "xray" / "xray")
    assert discover.find("xray") == (local, "local")


@posix
def test_found_on_path(tmp_path, monkeypatch):
    d = tmp_path / "pathbin"
    exe = _fake_core(d / "sing-box")
    monkeypatch.setenv("PATH", str(d))
    assert discover.find("singbox") == (exe, "PATH")


@posix
def test_non_executable_and_missing_paths_are_ignored(tmp_path, monkeypatch):
    f = tmp_path / "xray"
    f.write_text("x")
    monkeypatch.setenv("XRAY_CORE", str(f))
    assert discover.find_binary("xray") == ""
    monkeypatch.setenv("XRAY_CORE", str(tmp_path / "nope"))
    assert discover.find_binary("xray") == ""


@posix
def test_version_ok_and_failures(tmp_path):
    good = _fake_core(tmp_path / "ok")
    assert discover.version("xray", good) == (True, "Xray 25.1.1 (fake)")
    bad = _fake_core(tmp_path / "bad", banner="boom", code=3)
    ok, text = discover.version("xray", bad)
    assert not ok and text == "boom"
    assert discover.version("xray", str(tmp_path / "missing"))[0] is False
    assert discover.version("nope", good) == (False, "unknown core")


def test_corrupt_core_paths_setting_is_ignored():
    settings.save_settings({"core_paths": "garbage"})
    assert discover.configured_path("xray") == ""
    settings.save_settings({"core_paths": {"xray": 5}})
    assert discover.configured_path("xray") == ""


@posix
def test_health_pipeline_can_now_start_a_core(tmp_path, monkeypatch):
    """_core_context used to return None because find_binary() was always ''."""
    from xray_forge.core import healthcheck as hc
    from xray_forge.core.parser import parse_target
    from tests.fixtures import VLESS_TLS_WS
    exe = _fake_core(tmp_path / "xray")
    monkeypatch.setenv("XRAY_CORE", exe)
    seen = {}
    monkeypatch.setattr(hc, "running_core",
                        lambda adapter, outs, binary=None: seen.update(binary=binary) or "CTX")
    assert hc._core_context(parse_target(VLESS_TLS_WS), "xray") == "CTX"
    assert seen["binary"] == exe
