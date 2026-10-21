"""tools/check_workflows.py: static policy checks for .github/workflows/*.yml.

These run offline.  They prove the *rules* are enforced and that the real
workflows obey them; they do not prove a workflow runs on a GitHub runner.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import subprocess
import sys
import textwrap

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SHA = "11bd71901bbe5b1630ceea73d27597364c9af683"
SHA2 = "a26af69be951a213d495a4c3e4e4022e16d87065"


def _load():
    spec = importlib.util.spec_from_file_location("check_workflows", ROOT / "tools" / "check_workflows.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["check_workflows"] = mod
    spec.loader.exec_module(mod)
    return mod


cw = _load()

GOOD = f"""\
name: T
on: [push]
permissions:
  contents: read
jobs:
  t:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - uses: actions/checkout@{SHA} # v4.2.2
      - run: echo hi
"""


def errs(text: str) -> list[str]:
    return cw.check_workflow_text(textwrap.dedent(text), "t.yml")


def test_good_workflow_is_clean():
    assert errs(GOOD) == []


# ---- pinning ---------------------------------------------------------------

def test_tag_pinned_action_is_flagged():
    out = errs(GOOD.replace(f"@{SHA} # v4.2.2", "@v4"))
    assert any("actions/checkout@v4" in e and "40-hex" in e for e in out), out


def test_branch_pinned_action_is_flagged():
    assert errs(GOOD.replace(f"@{SHA} # v4.2.2", "@main"))


def test_sha_without_version_comment_is_flagged():
    out = errs(GOOD.replace(" # v4.2.2", ""))
    assert any("version comment" in e for e in out), out


def test_short_sha_is_flagged():
    assert errs(GOOD.replace(SHA, SHA[:12]))


def test_local_action_is_allowed():
    text = GOOD.replace(f"actions/checkout@{SHA} # v4.2.2", "./.github/actions/local")
    assert errs(text) == []


def test_docker_action_needs_digest():
    bad = GOOD.replace(f"actions/checkout@{SHA} # v4.2.2", "docker://alpine:3.20")
    assert errs(bad)
    ok = GOOD.replace(f"actions/checkout@{SHA} # v4.2.2", "docker://alpine@sha256:" + "a" * 64)
    assert errs(ok) == []


def test_every_use_is_checked_not_only_the_first():
    text = GOOD + f"      - uses: actions/setup-python@v5\n"
    out = errs(text)
    assert len(out) == 1 and "setup-python@v5" in out[0], out


# ---- permissions -----------------------------------------------------------

def test_missing_top_level_permissions_is_flagged():
    out = errs(GOOD.replace("permissions:\n  contents: read\n", ""))
    assert any("permissions" in e for e in out), out


def test_top_level_write_is_flagged():
    out = errs(GOOD.replace("contents: read", "contents: write"))
    assert any("write" in e for e in out), out


def test_write_all_is_flagged():
    assert errs(GOOD.replace("permissions:\n  contents: read\n", "permissions: write-all\n"))


def test_release_action_requires_job_level_write():
    text = GOOD + f"      - uses: softprops/action-gh-release@{SHA2} # v2.6.2\n"
    out = errs(text)
    assert any("contents: write" in e for e in out), out
    fixed = text.replace("    timeout-minutes: 5\n", "    timeout-minutes: 5\n    permissions:\n      contents: write\n")
    assert errs(fixed) == []


# ---- script injection and secrets -----------------------------------------

@pytest.mark.parametrize("expr", ["github.head_ref", "github.event.pull_request.title",
                                  "inputs.x", "steps.a.outputs.b", "secrets.TOKEN"])
def test_untrusted_expression_in_run_is_flagged(expr):
    out = errs(GOOD.replace("echo hi", "echo ${{ %s }}" % expr))
    assert any("run" in e and expr.split(".")[0] in e for e in out), out


def test_matrix_and_runner_in_run_are_allowed():
    assert errs(GOOD.replace("echo hi", "echo ${{ matrix.os }} ${{ runner.temp }}")) == []


def test_secret_in_step_env_is_allowed_but_not_in_job_or_workflow_env():
    step_env = GOOD + "        env:\n          T: ${{ secrets.TOKEN }}\n"
    assert errs(step_env) == []
    job_env = GOOD.replace("    timeout-minutes: 5\n", "    timeout-minutes: 5\n    env:\n      T: ${{ secrets.TOKEN }}\n")
    assert any("secrets" in e for e in errs(job_env))
    wf_env = GOOD.replace("jobs:", "env:\n  T: ${{ secrets.TOKEN }}\njobs:")
    assert any("secrets" in e for e in errs(wf_env))


# ---- shells, timeouts, needs ------------------------------------------------

def test_pwsh_step_is_flagged():
    out = errs(GOOD + "        shell: pwsh\n")
    assert any("pwsh" in e for e in out), out


def test_matrix_os_job_needs_bash_default():
    text = GOOD.replace("runs-on: ubuntu-latest", "runs-on: ${{ matrix.os }}")
    assert any("bash" in e for e in errs(text))
    fixed = text.replace("    timeout-minutes: 5\n", "    timeout-minutes: 5\n    defaults:\n      run:\n        shell: bash\n")
    assert errs(fixed) == []


def test_job_without_timeout_is_flagged():
    out = errs(GOOD.replace("    timeout-minutes: 5\n", ""))
    assert any("timeout-minutes" in e for e in out), out


def test_unknown_needs_is_flagged():
    out = errs(GOOD.replace("    timeout-minutes: 5\n", "    timeout-minutes: 5\n    needs: [ghost]\n"))
    assert any("ghost" in e for e in out), out


def test_invalid_yaml_is_reported_not_raised():
    assert errs("jobs: [unclosed")


# ---- npm / pip ---------------------------------------------------------------

@pytest.mark.parametrize("cmd", ["npm install", "npm i", "npm install --no-save playwright", "npm install playwright@^1.5.0",
                                 "npm install electron-builder"])
def test_floating_npm_install_is_flagged(cmd):
    out = errs(GOOD.replace("echo hi", cmd))
    assert any("npm" in e for e in out), (cmd, out)


@pytest.mark.parametrize("cmd", ["npm ci", "npm install --no-save playwright@1.56.0", "npm test"])
def test_reproducible_npm_commands_are_allowed(cmd):
    assert errs(GOOD.replace("echo hi", cmd)) == []


def test_unpinned_pip_installs_are_advisory_only():
    text = GOOD.replace("      - run: echo hi\n", (
        "      - run: |\n"
        "          python -m pip install --upgrade pip\n"
        "          pip install -r requirements.txt pyinstaller 'x==1.0' -e .\n"))
    assert errs(text) == []
    adv = cw.advisories_text(textwrap.dedent(text), "t.yml")
    assert len(adv) == 1 and "pyinstaller" in adv[0], adv


# ---- repo-level consistency ---------------------------------------------------

def _repo(tmp_path, *, release=None, pkg=None, lock=None):
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    (tmp_path / "electron").mkdir()
    (tmp_path / "tools").mkdir()
    (tmp_path / "tools" / "check_version.py").write_text("# stub\n")
    (tmp_path / ".github" / "workflows" / "release.yml").write_text(release or REL)
    pkg = pkg or {"devDependencies": {"electron": "^33.0.0"},
                  "build": {"win": {"target": ["nsis"]}, "linux": {"target": ["AppImage"]}}}
    (tmp_path / "electron" / "package.json").write_text(json.dumps(pkg))
    lock = lock or {"lockfileVersion": 3, "packages": {"": {"devDependencies": {"electron": "^33.0.0"}}}}
    (tmp_path / "electron" / "package-lock.json").write_text(json.dumps(lock))
    return tmp_path


REL = f"""\
name: R
on: [push]
permissions:
  contents: read
jobs:
  build:
    runs-on: ${{{{ matrix.os }}}}
    timeout-minutes: 5
    strategy:
      matrix:
        include:
          - os: ubuntu-latest
            artifact: cli-linux
    defaults:
      run:
        shell: bash
    steps:
      - if: startsWith(github.ref, 'refs/tags/v')
        run: python tools/check_version.py "$GITHUB_REF_NAME"
  desktop:
    runs-on: ${{{{ matrix.os }}}}
    timeout-minutes: 5
    strategy:
      matrix:
        include:
          - os: windows-latest
            artifact: desk-win
            pattern: "*.exe"
          - os: ubuntu-latest
            artifact: desk-linux
            pattern: "*.AppImage"
    defaults:
      run:
        shell: bash
    steps:
      - if: startsWith(github.ref, 'refs/tags/v')
        run: python tools/check_version.py "$GITHUB_REF_NAME"
  release:
    needs: [build, desktop]
    runs-on: ubuntu-latest
    timeout-minutes: 5
    if: startsWith(github.ref, 'refs/tags/v')
    permissions:
      contents: write
    steps:
      - uses: softprops/action-gh-release@{SHA2} # v2.6.2
        with:
          files: |
            dist/*.zip
            dist/*.exe
            dist/*.AppImage
            dist/*.sha256
            dist/*.sha256.sig
"""


def test_consistent_repo_is_clean(tmp_path):
    assert cw.check_release_consistency(_repo(tmp_path)) == []


def test_installer_pattern_must_match_builder_target(tmp_path):
    out = cw.check_release_consistency(_repo(tmp_path, release=REL.replace('"*.exe"', '"*.msi"')))
    assert any("exe" in e for e in out), out


def test_release_files_must_cover_every_installer_type(tmp_path):
    out = cw.check_release_consistency(_repo(tmp_path, release=REL.replace("            dist/*.AppImage\n", "")))
    assert any("AppImage" in e for e in out), out


def test_release_files_must_cover_checksums_and_signatures(tmp_path):
    for glob in ("dist/*.sha256.sig", "dist/*.sha256", "dist/*.zip"):
        out = cw.check_release_consistency(_repo(tmp_path / glob.replace("/", "_").replace("*", "x"),
                                                 release=REL.replace(f"            {glob}\n", "")))
        assert any(glob in e for e in out), (glob, out)


def test_release_job_must_wait_for_both_builds_and_only_run_on_tags(tmp_path):
    out = cw.check_release_consistency(_repo(tmp_path, release=REL.replace("needs: [build, desktop]", "needs: [build]")))
    assert any("desktop" in e for e in out), out
    out = cw.check_release_consistency(_repo(tmp_path / "b", release=REL.replace(
        "    if: startsWith(github.ref, 'refs/tags/v')\n    permissions", "    permissions")))
    assert any("tag" in e for e in out), out


def test_tag_check_must_run_in_both_build_jobs(tmp_path):
    one = REL.replace('python tools/check_version.py "$GITHUB_REF_NAME"', "echo skip", 1)
    out = cw.check_release_consistency(_repo(tmp_path, release=one))
    assert any("check_version" in e and "build" in e for e in out), out


def test_artifact_names_must_be_unique(tmp_path):
    out = cw.check_release_consistency(_repo(tmp_path, release=REL.replace("desk-linux", "cli-linux")))
    assert any("cli-linux" in e for e in out), out


def test_referenced_tools_must_exist(tmp_path):
    repo = _repo(tmp_path)
    (repo / "tools" / "check_version.py").unlink()
    out = cw.check_release_consistency(repo)
    assert any("tools/check_version.py" in e for e in out), out


def test_unknown_builder_target_is_flagged(tmp_path):
    pkg = {"devDependencies": {}, "build": {"win": {"target": ["squirrel"]}}}
    lock = {"lockfileVersion": 3, "packages": {"": {"devDependencies": {}}}}
    out = cw.check_release_consistency(_repo(tmp_path, pkg=pkg, lock=lock))
    assert any("squirrel" in e for e in out), out


def test_npm_lock_must_match_package_json(tmp_path):
    lock = {"lockfileVersion": 3, "packages": {"": {"devDependencies": {"electron": "^32.0.0"}}}}
    out = cw.check_release_consistency(_repo(tmp_path, lock=lock))
    assert any("package-lock.json" in e and "electron" in e for e in out), out


# ---- the real repository ----------------------------------------------------------

def test_real_workflows_obey_the_policy():
    found = cw.check_repo(ROOT)
    assert found == [], "\n".join(found)


def test_cli_exit_codes(tmp_path):
    ok = subprocess.run([sys.executable, str(ROOT / "tools" / "check_workflows.py"), "--root", str(ROOT)],
                        capture_output=True, text=True)
    assert ok.returncode == 0, ok.stdout + ok.stderr
    bad_root = _repo(tmp_path, release=REL.replace("*.exe", "*.msi"))
    bad = subprocess.run([sys.executable, str(ROOT / "tools" / "check_workflows.py"), "--root", str(bad_root)],
                         capture_output=True, text=True)
    assert bad.returncode == 1 and "::error::" in bad.stdout
