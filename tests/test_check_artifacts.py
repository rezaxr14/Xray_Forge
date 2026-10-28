"""tools/check_artifacts.py: what a release build leaves in electron-builder's *-unpacked
directory (the exact tree the installer / AppImage is made from).

Offline, on fake trees.  This proves the checker catches a missing engine, a missing or altered
license, a non-executable engine and a broken engine.  It does not prove that electron-builder
produces this layout (only a real build shows that) or that the installer installs."""

from __future__ import annotations

import importlib.util
import os
import pathlib
import shutil
import subprocess
import sys

import pytest

from tests.fakebin import make_exe

ROOT = pathlib.Path(__file__).resolve().parent.parent
POSIX = pytest.mark.skipif(sys.platform == "win32", reason="needs POSIX file modes and shebang executables")


def _load():
    spec = importlib.util.spec_from_file_location("check_artifacts", ROOT / "tools" / "check_artifacts.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["check_artifacts"] = mod
    spec.loader.exec_module(mod)
    return mod


ca = _load()

ENGINE_SRC = '''#!{python}
import sys
sys.path.insert(0, {root!r})
from xray_forge.cli import main
sys.exit(main(sys.argv[1:]))
'''
BROKEN_SRC = '#!{python}\nimport sys\nsys.stderr.write("boom")\nsys.exit(3)\n'


def tree(tmp_path, platform="linux", *, engine_src=None, name=None):
    d = tmp_path / (name or f"{platform}-unpacked")
    res = d / "resources"
    (res / "engine").mkdir(parents=True)
    (res / "legal").mkdir()
    (res / "app.asar").write_bytes(b"asar")
    exe = "xray-forge-engine" + (".exe" if platform == "win" else "")
    if engine_src is not None and sys.platform != "win32":
        made = make_exe(res / "engine", "engine-src", engine_src.format(python=sys.executable, root=str(ROOT)))
        os.replace(made, res / "engine" / exe)
    else:
        (res / "engine" / exe).write_bytes(b"#!/bin/sh\n")
    if platform == "linux":
        (res / "engine" / exe).chmod(0o755)
        top = d / "xray-forge-ui"
        top.write_bytes(b"elf")
        top.chmod(0o755)
    else:
        (d / "Xray Forge.exe").write_bytes(b"MZ")
    for f in ("LICENSE", "NOTICE"):
        shutil.copyfile(ROOT / f, res / "legal" / f)
    return d


def problems(d, platform=None):
    return ca.check_unpacked(d, root=ROOT, platform=platform)


@pytest.mark.parametrize("platform", ["linux", "win"])
def test_a_complete_tree_is_clean(tmp_path, platform):
    assert problems(tree(tmp_path, platform)) == []


def test_platform_is_inferred_from_the_directory_name(tmp_path):
    assert problems(tree(tmp_path, "win")) == []
    assert any("platform" in p for p in problems(tree(tmp_path / "x", "linux", name="mystery-dir")))
    assert problems(tree(tmp_path / "y", "linux", name="mystery-dir"), platform="linux") == []


def test_a_missing_directory_is_reported(tmp_path):
    out = problems(tmp_path / "nope", platform="linux")
    assert out and "not a directory" in out[0]


@pytest.mark.parametrize("platform, rel, needle", [
    ("linux", "resources/app.asar", "application code"),
    ("win", "resources/app.asar", "application code"),
    ("linux", "resources/engine/xray-forge-engine", "engine"),
    ("win", "resources/engine/xray-forge-engine.exe", "engine"),
    ("linux", "resources/legal/LICENSE", "LICENSE"),
    ("win", "resources/legal/NOTICE", "NOTICE"),
    ("win", "Xray Forge.exe", ".exe"),
    ("linux", "xray-forge-ui", "executable"),
])
def test_each_missing_part_is_reported(tmp_path, platform, rel, needle):
    d = tree(tmp_path, platform)
    (d / rel).unlink()
    out = problems(d)
    assert any(needle in p for p in out), (rel, out)


def test_an_unpacked_app_directory_instead_of_an_asar_is_fine(tmp_path):
    d = tree(tmp_path)
    (d / "resources" / "app.asar").unlink()
    (d / "resources" / "app").mkdir()
    assert problems(d) == []


def test_the_windows_engine_must_be_an_exe_and_the_linux_one_must_not_be(tmp_path):
    d = tree(tmp_path, "win")
    (d / "resources/engine/xray-forge-engine.exe").rename(d / "resources/engine/xray-forge-engine")
    assert any("engine" in p for p in problems(d))


@pytest.mark.parametrize("name", ["LICENSE", "NOTICE"])
def test_an_altered_legal_file_is_reported(tmp_path, name):
    d = tree(tmp_path)
    f = d / "resources" / "legal" / name
    f.write_text(f.read_text(encoding="utf-8") + "\nextra\n", encoding="utf-8")
    assert any(name in p and "differs" in p for p in problems(d))


def test_crlf_legal_files_from_a_windows_checkout_are_accepted(tmp_path):
    d = tree(tmp_path, "win")
    for name in ("LICENSE", "NOTICE"):
        f = d / "resources" / "legal" / name
        f.write_bytes(f.read_bytes().replace(b"\n", b"\r\n"))
    assert problems(d) == []


def test_the_license_shipped_is_the_gpl(tmp_path):
    assert b"GNU GENERAL PUBLIC LICENSE" in (tree(tmp_path) / "resources/legal/LICENSE").read_bytes()


@POSIX
def test_a_non_executable_linux_engine_is_reported(tmp_path):
    d = tree(tmp_path)
    (d / "resources/engine/xray-forge-engine").chmod(0o644)
    assert any("executable" in p and "engine" in p for p in problems(d))


@POSIX
def test_smoke_passes_for_a_working_engine(tmp_path):
    d = tree(tmp_path, engine_src=ENGINE_SRC)
    assert ca.smoke_problems(d, platform="linux") == []


@POSIX
def test_smoke_reports_a_broken_engine(tmp_path):
    d = tree(tmp_path, engine_src=BROKEN_SRC)
    out = ca.smoke_problems(d, platform="linux")
    assert out and any("engine" in p.lower() for p in out)


def run_cli(*args):
    return subprocess.run([sys.executable, str(ROOT / "tools" / "check_artifacts.py"), *args],
                          capture_output=True, text=True, timeout=120)


def test_cli_ok_and_failure_exit_codes(tmp_path):
    good = tree(tmp_path / "g")
    r = run_cli(str(good))
    assert r.returncode == 0 and "ok" in r.stdout and str(good) in r.stdout
    bad = tree(tmp_path / "b")
    (bad / "resources/engine/xray-forge-engine").unlink()
    r = run_cli(str(bad))
    assert r.returncode == 1 and "::error::" in r.stdout


def test_cli_with_no_directory_fails_loudly(tmp_path):
    r = run_cli()
    assert r.returncode == 2
    r = run_cli(str(tmp_path / "missing-*-unpacked"))          # an unmatched glob is passed through literally by bash
    assert r.returncode in (1, 2) and "unpacked" in (r.stdout + r.stderr)


def test_cli_checks_every_directory_given(tmp_path):
    good, bad = tree(tmp_path / "a"), tree(tmp_path / "b", "win")
    (bad / "Xray Forge.exe").unlink()
    r = run_cli(str(good), str(bad))
    assert r.returncode == 1 and str(bad) in r.stdout


@POSIX
def test_cli_smoke_flag_runs_the_engine(tmp_path):
    assert run_cli("--smoke", str(tree(tmp_path / "ok", engine_src=ENGINE_SRC))).returncode == 0
    r = run_cli("--smoke", str(tree(tmp_path / "bad", engine_src=BROKEN_SRC)))
    assert r.returncode == 1 and "::error::" in r.stdout
