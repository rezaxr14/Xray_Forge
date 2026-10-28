#!/usr/bin/env python3
"""Check what a desktop build leaves in electron-builder's ``*-unpacked`` directory.

    python tools/check_artifacts.py electron/release/*-unpacked
    python tools/check_artifacts.py --smoke electron/release/linux-unpacked

The unpacked directory is the exact tree the installer / AppImage is made from, so
checking it catches an installer that would ship without the engine, without the
license files, or with an engine that does not start.  For every directory it checks:

* the application code is present (``resources/app.asar`` or ``resources/app``);
* ``resources/engine/xray-forge-engine`` (``.exe`` on Windows) exists, and on Linux is
  executable;
* ``resources/legal/LICENSE`` and ``NOTICE`` are the repository's files (line endings
  ignored), so the GPL text and the source offer ship with every installer;
* there is a launcher (a top-level ``.exe`` on Windows, an executable file on Linux).

``--smoke`` additionally starts the engine from that tree (``tools/smoke_engine.py``).

What this cannot show: that the installer installs or the app window opens (only
running it does), or the layout of a platform it was not told about.
``::error::`` lines are GitHub annotations; the exit code is 1 when anything is wrong,
2 when no directory was given.
"""

from __future__ import annotations

import importlib.util
import os
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
LEGAL_FILES = ("LICENSE", "NOTICE")


def platform_of(app_dir: pathlib.Path) -> str | None:
    name = pathlib.Path(app_dir).name.lower()
    if "linux" in name:
        return "linux"
    if name.startswith("win"):
        return "win"
    return None


def engine_path(app_dir: pathlib.Path, platform: str) -> pathlib.Path:
    return pathlib.Path(app_dir) / "resources" / "engine" / ("xray-forge-engine.exe" if platform == "win" else "xray-forge-engine")


def _lf(data: bytes) -> bytes:
    return data.replace(b"\r\n", b"\n")


def check_unpacked(app_dir, root: pathlib.Path = ROOT, platform: str | None = None) -> list[str]:
    d = pathlib.Path(app_dir)
    if not d.is_dir():
        return [f"{d} is not a directory (did electron-builder write a different *-unpacked name?)"]
    plat = platform or platform_of(d)
    if plat not in ("win", "linux"):
        return [f"cannot tell the platform of '{d.name}': expected a win-unpacked or linux-unpacked directory"]
    found: list[str] = []
    res = d / "resources"

    if not ((res / "app.asar").is_file() or (res / "app").is_dir()):
        found.append("application code missing (neither resources/app.asar nor resources/app)")

    engine = engine_path(d, plat)
    if not engine.is_file():
        found.append(f"engine missing: {engine.relative_to(d).as_posix()}")
    elif plat == "linux" and not os.access(engine, os.X_OK):
        found.append(f"engine is not executable: {engine.relative_to(d).as_posix()}")

    for name in LEGAL_FILES:
        shipped = res / "legal" / name
        if not shipped.is_file():
            found.append(f"{name} missing from resources/legal")
        elif _lf(shipped.read_bytes()) != _lf((pathlib.Path(root) / name).read_bytes()):
            found.append(f"{name} in resources/legal differs from the repository's {name}")

    if plat == "win":
        if not any(p.suffix.lower() == ".exe" for p in d.iterdir() if p.is_file()):
            found.append(f"no .exe application launcher in {d.name}")
    elif not any(p.is_file() and os.access(p, os.X_OK) for p in d.iterdir()):
        found.append(f"no executable launcher in {d.name}")
    return found


def smoke_problems(app_dir, platform: str | None = None) -> list[str]:
    """Start the packaged engine and talk to it (tools/smoke_engine.py)."""
    d = pathlib.Path(app_dir)
    plat = platform or platform_of(d)
    exe = engine_path(d, plat or "linux")
    if not exe.is_file():
        return [f"engine missing: {exe}"]
    spec = importlib.util.spec_from_file_location("smoke_engine", pathlib.Path(__file__).with_name("smoke_engine.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return [f"engine smoke test: {p}" for p in mod.smoke([str(exe), "serve"])]


def main(argv: list[str]) -> int:
    args = list(argv[1:])
    smoke = "--smoke" in args
    args = [a for a in args if a != "--smoke"]
    root = ROOT
    if "--root" in args:
        i = args.index("--root")
        root = pathlib.Path(args[i + 1])
        del args[i:i + 2]
    if not args:
        print("check_artifacts: give at least one *-unpacked directory (the glob matched nothing?)", file=sys.stderr)
        print(__doc__)
        return 2
    bad = 0
    for arg in args:
        found = check_unpacked(arg, root=root)
        if smoke and not found:
            found = smoke_problems(arg)
        for p in found:
            print(f"::error::{arg}: {p}")
        if found:
            bad += 1
        else:
            print(f"check_artifacts: ok {arg}" + (" (engine started)" if smoke else ""))
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
