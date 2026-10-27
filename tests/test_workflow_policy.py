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


# ---- pip: only hash-locked installs ----------------------------------------------

def _pip(cmd: str) -> list[str]:
    """Policy errors that mention pip for a workflow whose single run step is ``cmd``."""
    body = "      - run: |\n" + "".join(f"          {ln}\n" for ln in cmd.splitlines())
    return [e for e in errs(GOOD.replace("      - run: echo hi\n", body)) if "pip" in e]


@pytest.mark.parametrize("cmd", [
    "pip install --require-hashes -r requirements-ci.lock",
    "python -m pip install --require-hashes -r requirements.lock",
    "python3 -m pip install --require-hashes --no-deps -r requirements-ci.lock",
    "pip3 install -r requirements-ci.lock --require-hashes",
    "pip install --require-hashes \\\n  -r requirements-ci.lock",       # backslash continuation
    "pip install --no-deps --no-build-isolation -e .",
    "pip install --no-build-isolation --no-deps .",
    "python -m pip install --upgrade pip",
    "python -m pip install --upgrade pip\npip install --require-hashes -r requirements-ci.lock\npip install --no-deps --no-build-isolation -e .",
    "pip --version",
    "pip install --require-hashes -r requirements-ci.lock && echo done",     # stops at the shell operator
    "pip install --require-hashes -r requirements-ci.lock | tee pip.log",
    "pip install --require-hashes -r requirements-ci.lock; python -m pytest tests",
    "pip install --no-deps --no-build-isolation -e . # the project itself",
    "pip install --require-hashes -rrequirements-ci.lock",                   # attached -rFILE form
    "pip install --require-hashes --requirement=requirements-ci.lock",
    "pip install --require-hashes --no-cache-dir -q -r requirements.lock",
    "pip install --require-hashes -r requirements.lock -r requirements-ci.lock",
])
def test_hash_locked_pip_commands_are_allowed(cmd):
    assert _pip(cmd) == []


@pytest.mark.parametrize("cmd", [
    "pip install -r requirements.txt",
    "pip install pytest",
    "pip install pytest==9.1.1",                                # pinned but not hash-verified
    "pip install pytest pytest-cov ruff cryptography",
    "python -m pip install pyinstaller",
    "pip install -r requirements-ci.lock",                      # lock without --require-hashes
    "pip install --require-hashes -r requirements.txt",         # hashes required but input is not a lock
    "pip install --require-hashes -r requirements-ci.lock pyinstaller",   # extra unlocked package
    "pip install --require-hashes requirements-ci.lock",        # forgot -r: installs a package of that name
    "pip install -e .",                                         # would resolve dependencies unpinned
    "pip install .",
    "pip install --no-deps -e .",                               # build isolation downloads setuptools unhashed
    "pip install --no-build-isolation -e .",                    # dependencies would resolve unpinned
    "pip install --no-deps --no-build-isolation -e . -e ./other",
    "pip install --no-deps git+https://example.invalid/x.git",
    "pip install --no-deps ./vendored",
    "pip install --require-hashes --no-deps -r requirements-ci.lock extra",
    "pip install --index-url https://example.invalid/simple --require-hashes -r requirements-ci.lock",
    "pip install --extra-index-url https://example.invalid/simple --require-hashes -r requirements-ci.lock",
    "pip install --upgrade pip setuptools",                     # only pip itself may float
    "pip install --require-hashes \\\n  -r requirements.txt",
    "pip install pytest && echo done",
    "python -m pip install pytest | tee log",
    "pip install --require-hashes -rrequirements.txt",
    "pip install --require-hashes --requirement=requirements.txt",
    "pip install --require-hashes -r requirements-ci.lock -r requirements.txt",
    "pip install --require-hashes -r requirements-ci.lock -e .",
    "pip install --require-hashes --find-links ./wheels -r requirements-ci.lock",
    "pip install --upgrade pip --index-url https://example.invalid/simple",
    "pip install --upgrade -r requirements.txt",
    "pip install pip",                                          # not the self-upgrade form
    "pip install --upgrade pip==99.0",                          # only the bare name is allowed
    "pip install --no-deps --no-build-isolation ./vendored",    # a local path other than the project
    "pip install --no-deps --no-build-isolation -e ../other",
    "pip install --no-deps --no-build-isolation . ./vendored",
])
def test_unlocked_pip_installs_are_errors(cmd):
    out = _pip(cmd)
    assert out, cmd
    assert all("t.yml" in e for e in out)


def test_pip_error_names_the_step_and_offers_the_fix():
    out = _pip("pip install -r requirements.txt")
    assert len(out) == 1
    assert "t/" in out[0] and "--require-hashes" in out[0] and ".lock" in out[0], out


def test_each_pip_command_on_a_line_is_judged_separately():
    out = _pip("pip install --require-hashes -r requirements-ci.lock\npip install pytest")
    assert len(out) == 1 and "pytest" in out[0], out


SETUP_PY = (
    "      - uses: actions/setup-python@{sha} # v5.6.0\n"
    "        with:\n"
    "          python-version: '3.12'\n"
    "{extra}"
    "      - run: echo hi\n"
)


def _setup(extra: str) -> list[str]:
    body = SETUP_PY.format(sha=SHA2, extra=extra)
    return [e for e in errs(GOOD.replace("      - run: echo hi\n", body)) if "cache" in e]


def test_pip_cache_must_be_keyed_on_a_lock_file():
    assert _setup("          cache: pip\n          cache-dependency-path: requirements-ci.lock\n") == []
    assert _setup("") == []                                     # no cache at all is fine
    assert _setup("          cache: pip\n          cache-dependency-path: requirements.txt\n")
    assert _setup("          cache: pip\n")                    # default key globs requirements*.txt
    assert _setup("          cache: pip\n          cache-dependency-path: |\n            requirements.lock\n            requirements.txt\n")


def test_pip_cache_may_list_several_lock_files():
    assert _setup("          cache: pip\n          cache-dependency-path: |\n"
                  "            requirements.lock\n            requirements-ci.lock\n") == []


# ---- browser-install jobs must not float on a runner image ---------------------------

PW_RUN = "npx playwright install --with-deps chromium"


def _pw(runs_on: str, run: str = PW_RUN) -> list[str]:
    block = "|\n" + "".join(f"          {ln}\n" for ln in run.splitlines())
    text = GOOD.replace("runs-on: ubuntu-latest", f"runs-on: {runs_on}").replace("run: echo hi\n", f"run: {block}")
    return [e for e in errs(text) if "playwright" in e.lower()]


@pytest.mark.parametrize("runs_on", ["ubuntu-24.04", "ubuntu-22.04", "windows-2022", "[self-hosted, linux]",
                                     "ubuntu-24.04-latestish", "ubuntu-24.04-arm"])
def test_pinned_runner_may_install_playwright_browsers(runs_on):
    assert _pw(runs_on) == []


@pytest.mark.parametrize("runs_on", ["ubuntu-latest", "windows-latest", "macos-latest", "ubuntu-slim-latest",
                                     "ubuntu-latest-8-cores", "latest"])
def test_playwright_browser_install_on_a_floating_runner_is_flagged(runs_on):
    out = _pw(runs_on)
    assert len(out) == 1 and "-latest" in out[0] and "ubuntu-24.04" in out[0], out


def test_floating_runner_is_fine_when_no_browser_is_installed():
    assert _pw("ubuntu-latest", "npm test") == []
    assert _pw("ubuntu-latest", "npm install --no-save playwright@1.56.0") == []


def test_playwright_install_is_found_in_any_form():
    for run in ["npx playwright install chromium", "python -m playwright install --with-deps",
                "playwright install\necho done", "npx  playwright  install-deps"]:
        assert _pw("ubuntu-latest", run), run


def test_matrix_runner_for_playwright_is_flagged_when_it_can_float(tmp_path):
    text = GOOD.replace("runs-on: ubuntu-latest",
                        "runs-on: ${{ matrix.os }}\n    strategy:\n      matrix:\n        os: [ubuntu-latest]"
                        ).replace("run: echo hi", "run: " + PW_RUN)
    assert any("playwright" in e.lower() for e in errs("defaults:\n  run:\n    shell: bash\n" + text))


def test_matrix_include_runners_are_checked_too():
    wf = GOOD.replace("runs-on: ubuntu-latest",
                      "runs-on: ${{ matrix.os }}\n    strategy:\n      matrix:\n        include:\n"
                      "          - os: ubuntu-24.04\n          - os: windows-latest"
                      ).replace("run: echo hi", "run: " + PW_RUN)
    out = [e for e in errs("defaults:\n  run:\n    shell: bash\n" + wf) if "playwright" in e.lower()]
    assert len(out) == 1 and "windows-latest" in out[0] and "ubuntu-24.04" not in out[0].split("floating runner")[1].split(";")[0], out


def test_shell_scripts_are_pinned_to_lf_line_endings():
    attrs = (ROOT / ".gitattributes").read_text(encoding="utf-8").splitlines()
    assert "*.sh text eol=lf" in [ln.strip() for ln in attrs]


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


# ---- Python lock files ---------------------------------------------------------------

H1 = "sha256:" + "a" * 64
H2 = "sha256:" + "b" * 64


def _entry(name, version, *, marker="", hashes=(H1,), via="-r requirements.txt"):
    head = f"{name}=={version}" + (f" ; {marker}" if marker else "")
    lines = [head + " \\"]
    for i, h in enumerate(hashes):
        lines.append(f"    --hash={h}" + (" \\" if i < len(hashes) - 1 else ""))
    lines.append(f"    # via {via}")
    return "\n".join(lines) + "\n"


RUNTIME_LOCK = (_entry("certifi", "2026.10.19") + _entry("pyyaml", "6.0.3")
                + _entry("pycparser", "3.11", marker="python_full_version < '3.11'", hashes=(H1, H2))
                + _entry("pycparser", "3.12", marker="python_full_version >= '3.11'"))
CI_LOCK = RUNTIME_LOCK + _entry("pytest", "9.1.1") + _entry("cryptography", "50.0.2")

CI_YML = f"""\
name: C
on: [push]
permissions:
  contents: read
jobs:
  t:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - uses: actions/setup-python@{SHA2} # v5.6.0
        with:
          python-version: "3.12"
          cache: pip
          cache-dependency-path: requirements-ci.lock
      - run: pip install --require-hashes -r requirements-ci.lock
"""


def _py_repo(tmp_path, **files):
    root = _repo(tmp_path)
    base = {
        "requirements.txt": "PyYAML>=6.0\ncertifi\n# optional: x\n# cryptography>=42.0\n",
        "requirements-ci.in": "-r requirements.txt\npytest\ncryptography\n",
        "requirements.lock": RUNTIME_LOCK,
        "requirements-ci.lock": CI_LOCK,
    }
    base.update(files)
    for name, text in base.items():
        if text is not None:
            (root / name).write_text(text)
    (root / ".github" / "workflows" / "ci.yml").write_text(CI_YML)
    return root


def test_consistent_python_locks_are_clean(tmp_path):
    assert cw.check_python_locks(_py_repo(tmp_path)) == []


def test_lock_entry_without_a_hash_is_flagged(tmp_path):
    bad = RUNTIME_LOCK.replace(f"pyyaml==6.0.3 \\\n    --hash={H1}\n", "pyyaml==6.0.3\n")
    assert bad != RUNTIME_LOCK
    out = cw.check_python_locks(_py_repo(tmp_path, **{"requirements.lock": bad, "requirements-ci.lock": bad + CI_LOCK[len(RUNTIME_LOCK):]}))
    assert any("pyyaml" in e and "hash" in e for e in out), out


def test_malformed_hash_is_flagged(tmp_path):
    bad = RUNTIME_LOCK.replace("a" * 64, "z" * 64, 1)
    out = cw.check_python_locks(_py_repo(tmp_path, **{"requirements.lock": bad, "requirements-ci.lock": bad + CI_LOCK[len(RUNTIME_LOCK):]}))
    assert any("hash" in e for e in out), out


@pytest.mark.parametrize("line", ["-e .", "git+https://example.invalid/x.git#egg=x", "https://example.invalid/x.whl",
                                  "pytest>=9", "pytest"])
def test_lock_may_only_contain_pinned_hashed_requirements(tmp_path, line):
    extra = "\n" + line + "\n"
    out = cw.check_python_locks(_py_repo(tmp_path, **{"requirements-ci.lock": CI_LOCK + extra}))
    assert any(line.split()[0] in e or "pinned" in e for e in out), (line, out)


def test_package_missing_from_the_lock_is_flagged(tmp_path):
    out = cw.check_python_locks(_py_repo(tmp_path, **{"requirements.txt": "PyYAML>=6.0\ncertifi\nrequests\n"}))
    assert any("requests" in e and "requirements.lock" in e for e in out), out


def test_name_matching_ignores_case_and_separators(tmp_path):
    lock = _entry("curl-cffi", "0.16.3") + RUNTIME_LOCK
    ci = lock + CI_LOCK[len(RUNTIME_LOCK):]
    out = cw.check_python_locks(_py_repo(tmp_path, **{"requirements.txt": "curl_cffi>=0.5.10\nPyYAML>=6.0\ncertifi\n",
                                                      "requirements.lock": lock, "requirements-ci.lock": ci}))
    assert out == [], out


def test_pinned_version_must_satisfy_the_minimum(tmp_path):
    out = cw.check_python_locks(_py_repo(tmp_path, **{"requirements.txt": "PyYAML>=7.0\ncertifi\n"}))
    assert any("pyyaml" in e.lower() and "7.0" in e and "6.0.3" in e for e in out), out


def test_exact_and_upper_bound_specifiers_are_checked(tmp_path):
    out = cw.check_python_locks(_py_repo(tmp_path, **{"requirements.txt": "PyYAML==6.0.2\ncertifi\n"}))
    assert any("pyyaml" in e.lower() and "6.0.2" in e for e in out), out
    out = cw.check_python_locks(_py_repo(tmp_path / "b", **{"requirements.txt": "PyYAML<6\ncertifi\n"}))
    assert any("pyyaml" in e.lower() for e in out), out


def test_ci_input_packages_must_be_in_the_ci_lock(tmp_path):
    out = cw.check_python_locks(_py_repo(tmp_path, **{"requirements-ci.in": "-r requirements.txt\npytest\nruff\n"}))
    assert any("ruff" in e and "requirements-ci.lock" in e for e in out), out


def test_ci_lock_must_contain_every_runtime_pin_unchanged(tmp_path):
    drift = CI_LOCK.replace("pyyaml==6.0.3", "pyyaml==6.0.2")
    out = cw.check_python_locks(_py_repo(tmp_path, **{"requirements-ci.lock": drift}))
    assert any("pyyaml" in e and "6.0.2" in e and "6.0.3" in e for e in out), out
    missing = CI_LOCK.replace(_entry("certifi", "2026.10.19"), "")
    out = cw.check_python_locks(_py_repo(tmp_path / "b", **{"requirements-ci.lock": missing}))
    assert any("certifi" in e for e in out), out


def test_marker_variants_of_one_package_are_kept_apart(tmp_path):
    dropped = CI_LOCK.replace(_entry("pycparser", "3.12", marker="python_full_version >= '3.11'"), "")
    out = cw.check_python_locks(_py_repo(tmp_path, **{"requirements-ci.lock": dropped}))
    assert any("pycparser" in e and "3.12" in e for e in out), out


@pytest.mark.parametrize("spec, ok", [
    (">=6.0.3", True), (">6.0.3", False), (">=6.0.4", False), (">6.0.2", True),
    ("<=6.0.3", True), ("<6.0.3", False), ("<6.0.4", True), ("<=6.0.2", False),
    ("==6.0.3", True), ("==6.0.*", True), ("==6.1.*", False), ("!=6.0.3", False), ("!=6.0.2", True),
    ("~=6.0", True), ("~=6.0.1", True), ("~=6.1", False), (">=6.0,<7", True), (">=6.0,<6.0.3", False),
])
def test_version_specifier_boundaries(tmp_path, spec, ok):
    out = cw.check_python_locks(_py_repo(tmp_path, **{"requirements.txt": f"PyYAML{spec}\ncertifi\n"}))
    assert (out == []) is ok, (spec, out)


def test_ci_input_includes_are_followed_to_any_depth(tmp_path):
    root = _py_repo(tmp_path, **{"requirements-ci.in": "-r requirements.txt\n-r extra.txt\n", "extra.txt": "-r more.txt\n",
                                 "more.txt": "ruff\n"})
    out = cw.check_python_locks(root)
    assert any("more.txt" in e and "ruff" in e and "requirements-ci.lock" in e for e in out), out


def test_missing_included_input_file_is_flagged(tmp_path):
    root = _py_repo(tmp_path, **{"requirements-ci.in": "-r requirements.txt\n-r gone.txt\n"})
    assert any("gone.txt" in e and "missing" in e for e in cw.check_python_locks(root))


def test_dropping_the_first_marker_variant_is_flagged(tmp_path):
    first = _entry("pycparser", "3.11", marker="python_full_version < '3.11'", hashes=(H1, H2))
    assert first in CI_LOCK
    out = cw.check_python_locks(_py_repo(tmp_path, **{"requirements-ci.lock": CI_LOCK.replace(first, "")}))
    assert any("pycparser" in e and "3.11" in e for e in out), out


def test_missing_lock_file_is_flagged(tmp_path):
    out = cw.check_python_locks(_py_repo(tmp_path, **{"requirements-ci.lock": None}) if False else _py_repo(tmp_path))
    assert out == []
    root = _py_repo(tmp_path / "b")
    (root / "requirements-ci.lock").unlink()
    out = cw.check_python_locks(root)
    assert any("requirements-ci.lock" in e and "missing" in e for e in out), out


def test_workflow_must_reference_existing_lock_files(tmp_path):
    root = _py_repo(tmp_path)
    (root / ".github" / "workflows" / "ci.yml").write_text(CI_YML.replace("requirements-ci.lock", "requirements-gone.lock"))
    out = cw.check_repo(root)
    assert any("requirements-gone.lock" in e and "does not exist" in e for e in out), out


def test_check_repo_includes_the_lock_checks(tmp_path):
    root = _py_repo(tmp_path, **{"requirements.txt": "PyYAML>=6.0\ncertifi\nrequests\n"})
    assert any("requests" in e for e in cw.check_repo(root))


def test_repo_without_python_requirements_skips_lock_checks(tmp_path):
    assert cw.check_python_locks(_repo(tmp_path)) == []


def test_real_python_locks_are_consistent():
    out = cw.check_python_locks(ROOT)
    assert out == [], "\n".join(out)


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
