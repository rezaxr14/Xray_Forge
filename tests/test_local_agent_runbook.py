"""The runbook must only tell the agent to run things that exist."""

from __future__ import annotations

import importlib.util
import pathlib
import re
import shlex

ROOT = pathlib.Path(__file__).resolve().parents[1]
TEXT = (ROOT / "docs" / "local-agent-runbook.md").read_text(encoding="utf-8")


def _live_check():
    spec = importlib.util.spec_from_file_location("live_check", ROOT / "tools" / "live_check.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _commands(prefix: str) -> list[list[str]]:
    out = []
    for line in TEXT.splitlines():
        s = line.strip()
        if s.startswith(prefix):
            out.append(shlex.split(s))
    return out


def test_every_live_check_command_parses_with_the_real_cli():
    parser = _live_check().build_parser()
    cmds = _commands("python tools/live_check.py")
    assert len(cmds) >= 5
    seen = set()
    for argv in cmds:
        ns = parser.parse_args(argv[2:])          # raises SystemExit on any unknown flag or check name
        seen.update(ns.checks)
    assert {"env", "masque", "psiphon", "vless", "warp-scan"} <= seen


def test_referenced_repo_files_exist():
    for path in ("tools/update_locks.sh", "tools/live_check.py", "docs/packaging.md",
                 ".github/workflows/release.yml"):
        assert path in TEXT and (ROOT / path).is_file(), path
    for m in re.findall(r"`((?:tools|docs)/[\w./-]+)`", TEXT):
        assert (ROOT / m).exists(), m


def test_runbook_tells_the_agent_not_to_leak_secrets():
    low = TEXT.lower()
    for phrase in ("never paste secrets", "--link-file", "do not edit code to make a"):
        assert phrase in low
