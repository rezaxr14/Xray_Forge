"""tools/ scripts used by the release workflow."""

from __future__ import annotations

import importlib.util
import pathlib
import subprocess
import sys

from xray_forge import __version__

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "tools" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_check_version_accepts_matching_tag():
    cv = _load("check_version")
    assert cv.check(f"v{__version__}") == []
    assert cv.check(__version__) == []


def test_check_version_rejects_other_tag():
    cv = _load("check_version")
    errs = cv.check("v9.9.9")
    assert len(errs) == 2 and all("9.9.9" in e for e in errs)


def test_package_versions_agree():
    cv = _load("check_version")
    assert len(set(cv.versions().values())) == 1


def test_smoke_engine_passes_on_python_engine():
    se = _load("smoke_engine")
    assert se.smoke([sys.executable, "-m", "xray_forge", "serve"], timeout=60) == []


def test_smoke_engine_reports_a_broken_engine():
    se = _load("smoke_engine")
    problems = se.smoke([sys.executable, "-c", "print('hello'); import sys; sys.exit(3)"], timeout=30)
    assert any("non-JSON" in p for p in problems)
    assert any("no engine.info" in p for p in problems)
    assert any("exited with 3" in p for p in problems)


def test_smoke_cli_usage_without_separator():
    r = subprocess.run([sys.executable, str(ROOT / "tools" / "smoke_engine.py")],
                       capture_output=True, text=True)
    assert r.returncode == 2
