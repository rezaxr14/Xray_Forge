"""The project is Apache-2.0: LICENSE is the unmodified official text and every
place that states a license says the same thing."""

from __future__ import annotations

import hashlib
import json
import pathlib
import re
import subprocess

ROOT = pathlib.Path(__file__).resolve().parent.parent
# SHA-256 of the official https://www.apache.org/licenses/LICENSE-2.0.txt
APACHE_2_SHA256 = "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"


def text(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def test_license_file_is_the_unmodified_apache_2_text():
    data = (ROOT / "LICENSE").read_bytes().replace(b"\r\n", b"\n")      # a Windows checkout may convert line endings
    assert hashlib.sha256(data).hexdigest() == APACHE_2_SHA256


def test_license_and_notice_are_pinned_to_lf_in_git():
    attrs = text(".gitattributes")
    for name in ("LICENSE", "NOTICE"):
        assert re.search(rf"(?m)^{name}\s+text\s+eol=lf\s*$", attrs), name


def test_notice_names_the_project_and_the_copyright_holder():
    notice = text("NOTICE")
    assert notice.startswith("Xray Forge")
    assert re.search(r"Copyright 20\d\d Reza Nadimi", notice)


def test_python_package_declares_apache_2():
    proj = text("pyproject.toml")
    assert re.search(r'(?m)^license\s*=\s*\{\s*text\s*=\s*"Apache-2\.0"\s*\}', proj)
    assert "License :: OSI Approved :: Apache Software License" in proj


def test_electron_package_declares_apache_2():
    pkg = json.loads(text("electron/package.json"))
    assert pkg["license"] == "Apache-2.0"


def test_readme_and_agents_state_apache_2():
    assert "Apache License, Version 2.0" in text("README.md")
    assert "Apache-2.0" in text("AGENTS.md")


def test_no_file_still_claims_cc_by():
    offenders = []
    tracked = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True).stdout.split()
    for rel in tracked:
        if rel.endswith((".png", ".ico", ".lock", "package-lock.json")) or rel == "tests/test_license.py":
            continue
        try:
            body = text(rel)
        except (UnicodeDecodeError, FileNotFoundError):
            continue
        if re.search(r"CC BY|creativecommons|Creative Commons", body):
            offenders.append(rel)
    assert offenders == [], f"stale CC BY mentions: {offenders}"


def test_gpl_constraint_is_still_documented_with_the_right_reason():
    agents = text("AGENTS.md")
    assert "Never copy code from GPL" in agents
    assert "Apache-2.0" in agents and "GPL" in agents


def test_release_archives_ship_license_and_notice():
    wf = text(".github/workflows/release.yml")
    assert wf.count("LICENSE NOTICE") >= 2          # CLI zip packaging on both platforms
