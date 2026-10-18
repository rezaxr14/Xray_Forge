#!/usr/bin/env python3
"""Release version helpers.

    check_version.py v2.1.0          # tag must match the package version
    check_version.py v2.1.0-rc1      # pre-release suffixes (-rcN, -betaN, -alphaN) are allowed
    check_version.py --package       # print the package version (read from files, no import)

A tag matches when its ``X.Y.Z`` core equals both ``xray_forge.__version__``
and ``pyproject.toml``; the optional suffix lets you rehearse a release with a
throw-away tag such as ``v2.1.0-rc1`` without bumping the version.
"""

from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
TAG_RE = re.compile(r"^v?(\d+\.\d+\.\d+)(-(?:rc|beta|alpha)\.?\d+)?$")


def versions() -> dict[str, str]:
    init = (ROOT / "xray_forge" / "__init__.py").read_text(encoding="utf-8")
    proj = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    return {
        "xray_forge.__version__": re.search(r'__version__\s*=\s*"([^"]+)"', init).group(1),
        "pyproject.toml": re.search(r'(?m)^version\s*=\s*"([^"]+)"', proj).group(1),
    }


def package_version() -> str:
    found = set(versions().values())
    if len(found) != 1:
        raise SystemExit(f"::error::package versions disagree: {versions()}")
    return found.pop()


def is_prerelease(tag: str) -> bool:
    m = TAG_RE.match(tag)
    return bool(m and m.group(2))


def check(tag: str) -> list[str]:
    m = TAG_RE.match(tag)
    if not m:
        return [f"tag {tag!r} is not vX.Y.Z or vX.Y.Z-(rc|beta|alpha)N"]
    core = m.group(1)
    return [f"tag {tag} does not match {k} ({v})" for k, v in versions().items() if v != core]


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "--package":
        print(package_version())
        raise SystemExit(0)
    if len(sys.argv) != 2:
        print(__doc__)
        raise SystemExit(2)
    errs = check(sys.argv[1])
    for e in errs:
        print(f"::error::{e}")
    if not errs:
        print("version check ok:", sys.argv[1])
    raise SystemExit(1 if errs else 0)
