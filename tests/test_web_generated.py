"""Files generated into web/src/engine must match their Python sources."""

from __future__ import annotations

import importlib.util
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]


@pytest.mark.skipif(sys.version_info[:2] != (3, 13), reason="tables are generated with Python 3.13")
def test_unicode_tables_are_current():
    spec = importlib.util.spec_from_file_location("gen_web_unicode", ROOT / "tools" / "gen_web_unicode.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.main(["--check"]) == 0


def test_web_dns_catalog_is_current():
    spec = importlib.util.spec_from_file_location("gen_web_dns", ROOT / "tools" / "gen_web_dns.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.main(["--check"]) == 0
