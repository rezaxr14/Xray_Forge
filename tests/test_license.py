"""The project is GPL-3.0-only: LICENSE is the unmodified official text and every
place that states a license says the same thing."""

from __future__ import annotations

import hashlib
import json
import pathlib
import re
import subprocess

ROOT = pathlib.Path(__file__).resolve().parent.parent
# SHA-256 of the official https://www.gnu.org/licenses/gpl-3.0.txt (same bytes as Debian's
# /usr/share/common-licenses/GPL-3; the project was relicensed from Apache-2.0 on the owner's decision)
GPL_3_SHA256 = "3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986"
SOURCE_URL = "https://github.com/rezaxr14/Xray_Forge"


def text(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def test_license_file_is_the_unmodified_gpl_3_text():
    data = (ROOT / "LICENSE").read_bytes().replace(b"\r\n", b"\n")      # a Windows checkout may convert line endings
    assert hashlib.sha256(data).hexdigest() == GPL_3_SHA256


def test_license_and_notice_are_pinned_to_lf_in_git():
    attrs = text(".gitattributes")
    for name in ("LICENSE", "NOTICE"):
        assert re.search(rf"(?m)^{name}\s+text\s+eol=lf\s*$", attrs), name


def test_notice_names_the_project_the_holder_the_license_and_where_the_source_is():
    notice = text("NOTICE")
    assert notice.startswith("Xray Forge")
    assert re.search(r"Copyright 20\d\d Reza Nadimi", notice)
    assert "GNU General Public License, version 3" in notice
    assert SOURCE_URL in notice                    # GPL section 6: binaries must point at the source
    assert "without any warranty" in " ".join(notice.split()).lower()
    assert "Apache" not in notice


def test_notice_keeps_third_party_programs_separate():
    notice = text("NOTICE")
    for core in ("Xray-core", "sing-box", "mihomo"):
        assert core in notice
    assert "not part of this work" in notice


def test_python_package_declares_gpl_3():
    proj = text("pyproject.toml")
    assert re.search(r'(?m)^license\s*=\s*\{\s*text\s*=\s*"GPL-3\.0-only"\s*\}', proj)
    assert "License :: OSI Approved :: GNU General Public License v3 (GPLv3)" in proj
    assert "Apache" not in proj


def test_electron_package_declares_gpl_3():
    pkg = json.loads(text("electron/package.json"))
    assert pkg["license"] == "GPL-3.0-only"


def test_readme_agents_and_about_page_state_gpl_3():
    readme = text("README.md")
    assert "GNU General Public License, version 3" in readme and "Apache" not in readme
    assert "GPL-3.0" in text("AGENTS.md")
    about = text("electron/renderer/index.html")
    assert "GPL-3.0" in about and "Apache" not in about


def test_no_stale_apache_claim_for_this_project_remains():
    stale = re.compile(r"(Xray Forge|project|repo|this work)\s+(is|stays)\s+Apache|Apache-2\.0\s*\(relicensed|licensed under the Apache",
                       re.I)
    tracked = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True).stdout.split()
    offenders = []
    for rel in tracked:
        if rel.endswith((".png", ".ico", ".lock", "package-lock.json")) or rel in ("tests/test_license.py", "LICENSE"):
            continue
        try:
            body = text(rel)
        except (UnicodeDecodeError, FileNotFoundError):
            continue
        if stale.search(body):
            offenders.append(rel)
    assert offenders == [], f"files still call the project Apache: {offenders}"


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


def test_agents_documents_the_licensing_rules():
    agents = text("AGENTS.md")
    assert "GPL-3.0-only" in agents
    assert "GPL-incompatible" in agents                   # what must still never be copied in
    assert "out of scope" in agents.lower()              # the declined helpers stay declined
    assert "SNI-spoofing" in agents


def test_release_archives_ship_license_and_notice():
    wf = text(".github/workflows/release.yml")
    assert wf.count("LICENSE NOTICE") >= 2          # CLI zip packaging on both platforms
