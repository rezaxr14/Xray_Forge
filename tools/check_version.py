#!/usr/bin/env python3
"""Fail unless the git tag (argv[1], e.g. v2.1.0) equals the package versions."""

from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent


def versions() -> dict[str, str]:
    init = (ROOT / "xray_forge" / "__init__.py").read_text(encoding="utf-8")
    proj = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    return {
        "xray_forge.__version__": re.search(r'__version__\s*=\s*"([^"]+)"', init).group(1),
        "pyproject.toml": re.search(r'(?m)^version\s*=\s*"([^"]+)"', proj).group(1),
    }


def check(tag: str) -> list[str]:
    want = tag[1:] if tag.startswith("v") else tag
    return [f"tag {tag} does not match {k} ({v})" for k, v in versions().items() if v != want]


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        raise SystemExit(2)
    errs = check(sys.argv[1])
    for e in errs:
        print(f"::error::{e}")
    if not errs:
        print("version check ok:", sys.argv[1])
    raise SystemExit(1 if errs else 0)
