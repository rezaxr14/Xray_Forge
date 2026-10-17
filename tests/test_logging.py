"""Logging replaces silent failure on persistence and core start."""

from __future__ import annotations

import logging

from xray_forge.core import log as xlog
from xray_forge.core import settings


def test_library_is_silent_by_default(capsys):
    xlog.get_logger("xray_forge.core.x").warning("boom")
    out = capsys.readouterr()
    assert out.out == "" and out.err == ""


def test_get_logger_namespaces():
    assert xlog.get_logger("foo").name == "xray_forge.foo"
    assert xlog.get_logger("xray_forge.core.a").name == "xray_forge.core.a"


def test_level_resolution(monkeypatch):
    monkeypatch.delenv("XRAY_FORGE_LOG", raising=False)
    assert xlog._level(False, None) == logging.INFO
    assert xlog._level(True, None) == logging.DEBUG
    assert xlog._level(False, "warning") == logging.WARNING
    monkeypatch.setenv("XRAY_FORGE_LOG", "error")
    assert xlog._level(True, "debug") == logging.ERROR
    monkeypatch.setenv("XRAY_FORGE_LOG", "nonsense")
    assert xlog._level(False, None) == logging.INFO


def test_corrupt_settings_logged_not_silent(tmp_path, monkeypatch, caplog):
    p = tmp_path / "settings.json"
    p.write_text("{not json")
    monkeypatch.setattr(settings, "settings_path", lambda: str(p))
    with caplog.at_level(logging.WARNING, logger="xray_forge"):
        assert settings.load_settings() == {}
    assert any("not valid JSON" in r.getMessage() for r in caplog.records)


def test_unwritable_settings_logged(tmp_path, monkeypatch, caplog):
    monkeypatch.setattr(settings, "settings_path",
                        lambda: str(tmp_path / "missing_dir" / "s.json"))
    monkeypatch.setattr("xray_forge.core.fsutil.write_private",
                        lambda *a, **k: (_ for _ in ()).throw(OSError("denied")))
    with caplog.at_level(logging.WARNING, logger="xray_forge"):
        settings.save_settings({"a": 1})
    assert any("cannot save settings" in r.getMessage() for r in caplog.records)


def test_corrupt_scan_session_logged(tmp_path, caplog):
    from xray_forge.core.scan_session import ScanSession
    (tmp_path / "scan.json").write_text("][")
    with caplog.at_level(logging.WARNING, logger="xray_forge"):
        ScanSession("scan", state_dir=str(tmp_path))
    assert any("cannot load scan session" in r.getMessage() for r in caplog.records)
