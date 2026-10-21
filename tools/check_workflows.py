#!/usr/bin/env python3
"""Static policy checks for ``.github/workflows/*.yml`` and release consistency.

    python tools/check_workflows.py            # check the repository this file lives in
    python tools/check_workflows.py --root DIR # check another checkout

Prints ``::error::`` lines (GitHub annotation syntax) and exits 1 when a rule
is broken; ``::warning::`` lines are advisories and never fail the run.

What this is: a *static* check.  It cannot prove that a workflow runs on a
GitHub runner; it catches the mistakes that are cheap to catch offline:

* every ``uses:`` is pinned to a full 40-hex commit SHA and carries a
  ``# vX.Y.Z`` comment (so a human, and Dependabot, can see the version);
* the workflow token is read-only by default, and write access is granted at
  job level only to the job that publishes the release;
* no untrusted ``${{ ... }}`` expression is spliced into a ``run:`` script,
  and secrets are only ever exposed through a single step's ``env:``;
* every job has a timeout; Windows-capable jobs use bash (never PowerShell);
* ``needs:`` points at real jobs; ``npm install`` never floats (use ``npm ci``);
* the release job's upload globs cover what electron-builder emits
  (``electron/package.json``), checksums and signatures, and the job only
  runs on tags after both builds; the tag check runs in both build jobs;
* ``electron/package-lock.json`` is in sync with ``electron/package.json``
  (``npm ci`` fails otherwise).

Unpinned ``pip install`` arguments are reported as advisories until a Python
lock file exists (see docs/packaging.md).
"""

from __future__ import annotations

import fnmatch
import json
import pathlib
import re
import shlex
import sys

try:
    import yaml
except ImportError:  # pragma: no cover - PyYAML is a project dependency
    yaml = None

ROOT = pathlib.Path(__file__).resolve().parent.parent

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
DOCKER_DIGEST_RE = re.compile(r"^docker://\S+@sha256:[0-9a-f]{64}$")
VERSION_COMMENT_RE = re.compile(r"^v\d+(?:\.\d+){0,2}(?:[-+.\w]*)$")
EXPR_RE = re.compile(r"\$\{\{\s*(.*?)\s*\}\}", re.S)
SAFE_EXPR_ROOTS = {"matrix", "runner", "env", "strategy"}
SHELLS_BANNED = {"pwsh", "powershell", "cmd"}
RELEASE_ACTION = "softprops/action-gh-release"

# electron-builder target -> file extension of the artifact it writes
TARGET_EXT = {
    "win": {"nsis": "exe", "portable": "exe", "msi": "msi", "zip": "zip"},
    "linux": {"AppImage": "AppImage", "deb": "deb", "rpm": "rpm", "snap": "snap"},
}
RUNNER_TO_PLATFORM = (("windows", "win"), ("ubuntu", "linux"))


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _load_yaml(text: str):
    return yaml.safe_load(text)


def _jobs(doc) -> dict:
    jobs = doc.get("jobs") if isinstance(doc, dict) else None
    return jobs if isinstance(jobs, dict) else {}


def _steps(job) -> list[dict]:
    steps = job.get("steps") if isinstance(job, dict) else None
    return [s for s in steps if isinstance(s, dict)] if isinstance(steps, list) else []


def _run_texts(doc) -> list[tuple[str, str]]:
    """(``job/step`` label, run script) for every shell step."""
    out = []
    for jname, job in _jobs(doc).items():
        for i, step in enumerate(_steps(job)):
            if isinstance(step.get("run"), str):
                out.append((f"{jname}/{step.get('name') or i}", step["run"]))
    return out


def _walk_strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from _walk_strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from _walk_strings(v)


def _uses(doc) -> list[str]:
    return [s["uses"] for job in _jobs(doc).values() for s in _steps(job) if isinstance(s.get("uses"), str)]


def _version_comment(text: str, uses: str) -> str | None:
    m = re.search(r"uses:\s*" + re.escape(uses) + r"[ \t]*(?:#[ \t]*(\S+))?", text)
    return m.group(1) if m else None


# ---------------------------------------------------------------------------
# single workflow
# ---------------------------------------------------------------------------

def check_workflow_text(text: str, name: str) -> list[str]:
    try:
        doc = _load_yaml(text)
    except yaml.YAMLError as exc:
        return [f"{name}: not valid YAML: {str(exc).splitlines()[0]}"]
    if not isinstance(doc, dict) or not _jobs(doc):
        return [f"{name}: no jobs found"]
    errs: list[str] = []

    # -- pinning ----------------------------------------------------------------
    for uses in _uses(doc):
        if uses.startswith("./"):
            continue
        if uses.startswith("docker://"):
            if not DOCKER_DIGEST_RE.match(uses):
                errs.append(f"{name}: {uses} must be pinned by @sha256: digest")
            continue
        ref = uses.rpartition("@")[2] if "@" in uses else ""
        if not SHA_RE.match(ref):
            errs.append(f"{name}: {uses} is not pinned to a full 40-hex commit SHA")
            continue
        comment = _version_comment(text, uses)
        if not comment or not VERSION_COMMENT_RE.match(comment):
            errs.append(f"{name}: {uses} needs a trailing version comment such as '# v4.2.2'")

    # -- permissions --------------------------------------------------------------
    perms = doc.get("permissions")
    if perms is None:
        errs.append(f"{name}: no top-level 'permissions:' (the token defaults to broad access)")
    elif isinstance(perms, str):
        errs.append(f"{name}: top-level permissions: {perms} is too broad; use a read-only mapping")
    elif isinstance(perms, dict):
        for scope, level in perms.items():
            if level == "write":
                errs.append(f"{name}: top-level permissions grants {scope}: write; grant it on the job that needs it")
    for jname, job in _jobs(doc).items():
        if any(str(s.get("uses", "")).startswith(RELEASE_ACTION + "@") for s in _steps(job)):
            jp = job.get("permissions")
            if not (isinstance(jp, dict) and jp.get("contents") == "write"):
                errs.append(f"{name}: job '{jname}' publishes a release and needs 'permissions: contents: write'")

    # -- injection and secrets -------------------------------------------------------
    for label, script in _run_texts(doc):
        for expr in EXPR_RE.findall(script):
            root = re.split(r"[.\[\s]", expr, maxsplit=1)[0]
            if root not in SAFE_EXPR_ROOTS:
                errs.append(f"{name}: {label}: '${{{{ {expr} }}}}' inside run: is spliced into the shell; pass it through env:")
    for where, env in [("workflow", doc.get("env"))] + [(f"job '{j}'", job.get("env")) for j, job in _jobs(doc).items()]:
        if any("secrets." in s for s in _walk_strings(env)):
            errs.append(f"{name}: secrets exposed in {where} env:; expose them in the one step that needs them")

    # -- shells ----------------------------------------------------------------------
    wf_shell = ((doc.get("defaults") or {}).get("run") or {}).get("shell")
    for jname, job in _jobs(doc).items():
        job_shell = (((job.get("defaults") or {}).get("run") or {}).get("shell")) or wf_shell
        runs_on = " ".join(_walk_strings(job.get("runs-on")))
        if ("matrix.os" in runs_on or "windows" in runs_on) and job_shell != "bash":
            errs.append(f"{name}: job '{jname}' can run on Windows; set defaults.run.shell: bash")
        for step in _steps(job):
            if (str(step.get("shell") or "").split() or [""])[0] in SHELLS_BANNED:
                errs.append(f"{name}: job '{jname}' uses shell: {step['shell']} (PowerShell breaks globs/heredocs; use bash)")

    # -- timeouts, needs -----------------------------------------------------------------
    names = set(_jobs(doc))
    for jname, job in _jobs(doc).items():
        if "timeout-minutes" not in job:
            errs.append(f"{name}: job '{jname}' has no timeout-minutes")
        needs = job.get("needs") or []
        for dep in [needs] if isinstance(needs, str) else needs:
            if dep not in names:
                errs.append(f"{name}: job '{jname}' needs unknown job '{dep}'")

    # -- npm -------------------------------------------------------------------------------
    for label, script in _run_texts(doc):
        for m in re.finditer(r"\bnpm\s+(?:install|i)\b([^\n&|;]*)", script):
            args = m.group(1).split()
            flags = [a for a in args if a.startswith("-")]
            pkgs = [a for a in args if not a.startswith("-")]
            exact = bool(pkgs) and all(re.search(r"@\d+\.\d+\.\d+$", p) for p in pkgs)
            if not (exact and "--no-save" in flags):
                errs.append(f"{name}: {label}: 'npm install{m.group(1).rstrip()}' floats versions; use 'npm ci' "
                            "(or '--no-save pkg@X.Y.Z' for a tool that is not a dependency)")
    return errs


def advisories_text(text: str, name: str) -> list[str]:
    """Things worth fixing that must not fail the build (unpinned pip installs)."""
    try:
        doc = _load_yaml(text)
    except yaml.YAMLError:
        return []
    out: list[str] = []
    for label, script in _run_texts(doc):
        for m in re.finditer(r"\bpip\s+install\b([^\n&|;]*)", script):
            try:
                toks = shlex.split(m.group(1))
            except ValueError:
                toks = m.group(1).split()
            skip = False
            for tok in toks:
                if skip:
                    skip = False
                    continue
                if tok in ("-r", "-c", "-e", "--requirement", "--constraint", "--editable"):
                    skip = True
                    continue
                if tok.startswith("-") or tok in (".", "pip"):  # 'pip' = upgrading pip itself
                    continue
                if "==" not in tok:
                    out.append(f"{name}: {label}: pip install {tok} is not pinned (needs the Python lock file)")
    return out


# ---------------------------------------------------------------------------
# release consistency
# ---------------------------------------------------------------------------

def _platform_of(runner: str) -> str | None:
    for needle, plat in RUNNER_TO_PLATFORM:
        if needle in runner:
            return plat
    return None


def _builder_extensions(pkg: dict) -> tuple[dict[str, set[str]], list[str]]:
    errs: list[str] = []
    exts: dict[str, set[str]] = {}
    build = pkg.get("build") or {}
    for plat, table in TARGET_EXT.items():
        for target in (build.get(plat) or {}).get("target", []):
            tname = target if isinstance(target, str) else target.get("target", "")
            if tname not in table:
                errs.append(f"electron/package.json: build.{plat}.target '{tname}' is unknown to tools/check_workflows.py; "
                            "add it to TARGET_EXT with the file extension it produces")
            else:
                exts.setdefault(plat, set()).add(table[tname])
    return exts, errs


def check_release_consistency(root: pathlib.Path) -> list[str]:
    root = pathlib.Path(root)
    errs: list[str] = []
    wf = root / ".github" / "workflows" / "release.yml"
    pkg_path = root / "electron" / "package.json"
    lock_path = root / "electron" / "package-lock.json"
    if not wf.is_file():
        return [".github/workflows/release.yml is missing"]
    doc = _load_yaml(wf.read_text(encoding="utf-8"))
    jobs = _jobs(doc)
    pkg = json.loads(pkg_path.read_text(encoding="utf-8")) if pkg_path.is_file() else {}
    exts, e = _builder_extensions(pkg)
    errs += e

    # installer globs per platform must match what electron-builder writes
    desktop = jobs.get("desktop") or {}
    matrix = ((desktop.get("strategy") or {}).get("matrix") or {}).get("include") or []
    for entry in matrix:
        plat = _platform_of(str(entry.get("os", "")))
        want = exts.get(plat or "", set())
        pattern = str(entry.get("pattern", ""))
        for ext in sorted(want):
            if not fnmatch.fnmatch(f"XrayForge-1.0.0-{plat}-x64.{ext}", pattern):
                errs.append(f"release.yml: desktop matrix pattern '{pattern}' ({entry.get('os')}) "
                            f"does not match the .{ext} installer electron-builder produces")

    # the release job publishes every installer type, checksum and signature
    release = jobs.get("release") or {}
    files: list[str] = []
    for step in _steps(release):
        if str(step.get("uses", "")).startswith(RELEASE_ACTION + "@"):
            files = [ln.strip() for ln in str((step.get("with") or {}).get("files", "")).splitlines() if ln.strip()]
    needed = {"dist/*.zip", "dist/*.sha256", "dist/*.sha256.sig"}
    needed |= {f"dist/*.{ext}" for s in exts.values() for ext in s}
    for glob in sorted(needed - set(files)):
        errs.append(f"release.yml: the release job does not upload {glob}")
    deps = release.get("needs") or []
    deps = [deps] if isinstance(deps, str) else deps
    for job in ("build", "desktop"):
        if job not in deps:
            errs.append(f"release.yml: the release job must need '{job}'")
    if "refs/tags/" not in str(release.get("if", "")):
        errs.append("release.yml: the release job must only run for tags (if: startsWith(github.ref, 'refs/tags/v'))")

    # tag/version check in both build jobs
    for job in ("build", "desktop"):
        ok = any("check_version.py" in str(s.get("run", "")) and "refs/tags/" in str(s.get("if", ""))
                 for s in _steps(jobs.get(job) or {}))
        if not ok:
            errs.append(f"release.yml: job '{job}' does not run tools/check_version.py on tags")

    # artifact names are unique across jobs
    seen: dict[str, str] = {}
    for jname in ("build", "desktop"):
        include = ((((jobs.get(jname) or {}).get("strategy") or {}).get("matrix")) or {}).get("include") or []
        for entry in include:
            art = entry.get("artifact")
            if art in seen:
                errs.append(f"release.yml: artifact name '{art}' is used by both '{seen[art]}' and '{jname}'")
            seen[art] = jname

    # scripts the workflows call exist
    for label, script in _run_texts(doc):
        for rel in sorted(set(re.findall(r"\b(tools/[\w./-]+\.py)\b", script))):
            if not (root / rel).is_file():
                errs.append(f"release.yml: {label} runs {rel}, which does not exist")

    # npm ci needs an in-sync lock file
    if pkg_path.is_file() and lock_path.is_file():
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        rootpkg = (lock.get("packages") or {}).get("") or {}
        for field in ("dependencies", "devDependencies"):
            want, have = pkg.get(field) or {}, rootpkg.get(field) or {}
            for dep in sorted(set(want) | set(have)):
                if want.get(dep) != have.get(dep):
                    errs.append(f"electron/package-lock.json is out of sync with package.json: {field}.{dep} "
                                f"is {have.get(dep)!r} in the lock, {want.get(dep)!r} in package.json (run npm install)")
    elif pkg_path.is_file():
        errs.append("electron/package-lock.json is missing (npm ci needs it)")
    return errs


# ---------------------------------------------------------------------------
# whole repository
# ---------------------------------------------------------------------------

def _workflow_files(root: pathlib.Path) -> list[pathlib.Path]:
    d = pathlib.Path(root) / ".github" / "workflows"
    return sorted(list(d.glob("*.yml")) + list(d.glob("*.yaml"))) if d.is_dir() else []


def check_repo(root: pathlib.Path = ROOT) -> list[str]:
    errs: list[str] = []
    for path in _workflow_files(root):
        errs += check_workflow_text(path.read_text(encoding="utf-8"), path.name)
    return errs + check_release_consistency(root)


def advisories(root: pathlib.Path = ROOT) -> list[str]:
    out: list[str] = []
    for path in _workflow_files(root):
        out += advisories_text(path.read_text(encoding="utf-8"), path.name)
    return out


def main(argv: list[str]) -> int:
    root = ROOT
    if len(argv) == 3 and argv[1] == "--root":
        root = pathlib.Path(argv[2])
    elif len(argv) != 1:
        print(__doc__)
        return 2
    if yaml is None:
        print("::error::PyYAML is required (pip install -r requirements.txt)")
        return 2
    errs = check_repo(root)
    for e in errs:
        print(f"::error::{e}")
    for a in advisories(root):
        print(f"::warning::{a}")
    if not errs:
        print("workflow policy ok")
    return 1 if errs else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
