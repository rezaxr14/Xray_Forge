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
  (``npm ci`` fails otherwise);
* a job that installs Playwright browsers runs on a pinned runner image (``ubuntu-24.04``),
  never a floating ``*-latest`` label (a new image can break ``--with-deps`` overnight);
* every ``pip install`` is hash-locked: ``pip install --require-hashes -r X.lock``
  (the project itself only as ``pip install --no-deps -e .``, pip itself only as
  ``pip install --upgrade pip``), and a ``cache: pip`` step is keyed on lock files;
* the Python lock files are well formed (every pin has sha256 hashes), cover
  everything ``requirements.txt`` / ``requirements-ci.in`` ask for at a version that
  satisfies it, and ``requirements-ci.lock`` pins the runtime packages identically.

Not checked: that the pins resolve for every Python/OS (that needs PyPI; see
``tools/update_locks.sh`` and docs/local-agent-runbook.md) and that the locks are
the freshest ones the inputs allow.
"""

from __future__ import annotations

import fnmatch
import json
import pathlib
import re
import shlex
import sys
from collections import defaultdict

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

HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
LOCK_PIN_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?==([A-Za-z0-9][A-Za-z0-9.!+_-]*)\s*(?:;\s*(.*\S))?\s*$")
SPEC_RE = re.compile(r"^(~=|==|!=|<=|>=|<|>)\s*([A-Za-z0-9][A-Za-z0-9.*!+_-]*)$")
REQ_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*([^;]*?)\s*(?:;.*)?$")
RUNTIME_INPUT, CI_INPUT = "requirements.txt", "requirements-ci.in"
RUNTIME_LOCK, CI_LOCK = "requirements.lock", "requirements-ci.lock"
# pip options that take a separate value (so the value is not mistaken for a package)
PIP_VALUE_FLAGS = {"-i", "--index-url", "--extra-index-url", "-f", "--find-links", "-c", "--constraint", "-t", "--target",
                   "--prefix", "--root", "--python", "--platform", "--implementation", "--abi", "--python-version",
                   "--trusted-host", "--proxy", "--cache-dir", "--log", "--report", "--progress-bar", "--root-user-action"}
PIP_INDEX_FLAGS = {"-i", "--index-url", "--extra-index-url", "-f", "--find-links", "--trusted-host"}
PIP_HINT = ("use 'pip install --require-hashes -r requirements-ci.lock' (the project itself: 'pip install --no-deps --no-build-isolation -e .'; "
            "pip itself: 'pip install --upgrade pip')")

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


def _job_runs(jname: str, job) -> list[tuple[str, str]]:
    return [(f"{jname}/{st.get('name') or i}", st["run"]) for i, st in enumerate(_steps(job))
            if isinstance(st.get("run"), str)]


def _runner_labels(job) -> list[str]:
    """Runner labels a job can land on, expanding ``${{ matrix.os }}`` into the matrix values."""
    labels = [x for x in _walk_strings(job.get("runs-on")) if "${{" not in x]
    if "matrix.os" in " ".join(_walk_strings(job.get("runs-on"))):
        matrix = (job.get("strategy") or {}).get("matrix") or {}
        oses = matrix.get("os")
        labels += [str(o) for o in (oses if isinstance(oses, list) else [oses] if oses else [])]
        labels += [str(e["os"]) for e in matrix.get("include") or [] if isinstance(e, dict) and "os" in e]
    return labels


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

    # -- browser installs need a pinned runner image ----------------------------------------------
    for jname, job in _jobs(doc).items():
        if not any(re.search(r"\bplaywright\s+install", script) for _l, script in _job_runs(jname, job)):
            continue
        floating = sorted(lbl for lbl in _runner_labels(job) if re.search(r"(?:^|-)latest(?:$|-)", lbl))
        if floating:
            errs.append(f"{name}: job '{jname}' installs Playwright browsers on floating runner {', '.join(floating)}; "
                        "pin the image (e.g. ubuntu-24.04): a new -latest image can break 'playwright install --with-deps'")

    # -- pip: only hash-locked installs ---------------------------------------------------------
    for label, args, ok, _files in _pip_installs(doc):
        if not ok:
            errs.append(f"{name}: {label}: 'pip install {' '.join(args)}' is not hash-locked; {PIP_HINT}")
    errs += _pip_cache_errors(doc, name)
    return errs


def _logical_lines(script: str) -> list[str]:
    """Shell lines with backslash continuations joined."""
    return re.sub(r"\\[ \t]*\r?\n", " ", script).splitlines()


def _pip_commands(script: str) -> list[list[str]]:
    """Argument lists of every ``pip install`` in a run script (up to the next shell operator).

    A text scan, not a shell parser: ``echo pip install x`` is reported too, which is
    the safe direction for a policy check.
    """
    found: list[list[str]] = []
    for line in _logical_lines(script):
        for m in re.finditer(r"(?<![\w./-])pip3?\s+install\b(.*)", line):
            rest = m.group(1)
            try:
                lex = shlex.shlex(rest, posix=True, punctuation_chars=True)
                lex.whitespace_split = True
                toks = list(lex)
            except ValueError:
                toks = rest.split()
            args: list[str] = []
            for tok in toks:
                if tok and all(c in "();<>|&" for c in tok):
                    break
                args.append(tok)
            found.append(args)
    return found


def _classify_pip(args: list[str]) -> tuple[bool, list[str]]:
    """(ok, requirement files) for one ``pip install`` argument list."""
    flags: set[str] = set()
    reqfiles: list[str] = []
    editable: list[str] = []
    positional: list[str] = []
    i = 0
    while i < len(args):
        tok = args[i]
        nxt = args[i + 1] if i + 1 < len(args) else ""
        if tok in ("-r", "--requirement"):
            reqfiles.append(nxt)
            i += 2
            continue
        if tok.startswith("--requirement="):
            reqfiles.append(tok.split("=", 1)[1])
        elif tok.startswith("-r") and not tok.startswith("--") and len(tok) > 2:
            reqfiles.append(tok[2:])
        elif tok in ("-e", "--editable"):
            editable.append(nxt)
            i += 2
            continue
        elif tok.startswith("--editable="):
            editable.append(tok.split("=", 1)[1])
        elif tok.startswith("-"):
            flags.add(tok.split("=", 1)[0])
            if tok in PIP_VALUE_FLAGS:
                i += 2
                continue
        else:
            positional.append(tok)
        i += 1
    if flags & PIP_INDEX_FLAGS:
        return False, reqfiles
    upgrade = bool(flags & {"--upgrade", "-U"})
    if positional == ["pip"] and upgrade and not reqfiles and not editable:
        return True, reqfiles
    if reqfiles:
        ok = ("--require-hashes" in flags and not positional and not editable
              and all(f.endswith(".lock") for f in reqfiles))
        return ok, reqfiles
    local = positional + editable
    # --no-build-isolation: isolation would download the build backend from PyPI without hashes;
    # the locked setuptools (a PyInstaller dependency) is used instead.
    if (local and set(local) == {"."} and {"--no-deps", "--no-build-isolation"} <= flags
            and len(positional) + len(editable) == 1):
        return True, reqfiles
    return False, reqfiles


def _pip_installs(doc) -> list[tuple[str, list[str], bool, list[str]]]:
    """(label, args, ok, requirement files) for every ``pip install`` in a workflow."""
    out = []
    for label, script in _run_texts(doc):
        for args in _pip_commands(script):
            ok, files = _classify_pip(args)
            out.append((label, args, ok, files))
    return out


def _pip_cache_errors(doc, name: str) -> list[str]:
    errs: list[str] = []
    for jname, job in _jobs(doc).items():
        for step in _steps(job):
            if not str(step.get("uses", "")).startswith("actions/setup-python@"):
                continue
            with_ = step.get("with") or {}
            if str(with_.get("cache", "")).strip() != "pip":
                continue
            paths = [ln.strip() for ln in str(with_.get("cache-dependency-path", "")).splitlines() if ln.strip()]
            if not paths or not all(p.endswith(".lock") for p in paths):
                errs.append(f"{name}: job '{jname}': setup-python 'cache: pip' must set cache-dependency-path to the "
                            "Python lock file(s) (e.g. requirements-ci.lock), so the cache key changes with the pins")
    return errs


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
# Python lock files
# ---------------------------------------------------------------------------

def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _ver(text: str) -> tuple[int, ...]:
    """Release segment of a version as ints ('6.0.3rc1' -> (6, 0, 3)); pre/post tags are ignored."""
    m = re.match(r"\d+(?:\.\d+)*", text)
    return tuple(int(x) for x in m.group(0).split(".")) if m else ()


def _cmp(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    n = max(len(a), len(b))
    a, b = a + (0,) * (n - len(a)), b + (0,) * (n - len(b))
    return (a > b) - (a < b)


def _satisfies(version: str, op: str, wanted: str) -> bool:
    v, w = _ver(version), _ver(wanted.rstrip(".*"))
    if op == "==":
        return v[:len(w)] == w if wanted.endswith("*") else _cmp(v, w) == 0
    if op == "!=":
        return not (v[:len(w)] == w if wanted.endswith("*") else _cmp(v, w) == 0)
    if op == "~=":
        return _cmp(v, w) >= 0 and v[:max(len(w) - 1, 1)] == w[:max(len(w) - 1, 1)]
    c = _cmp(v, w)
    return {">=": c >= 0, ">": c > 0, "<=": c <= 0, "<": c < 0}[op]


def _parse_inputs(text: str) -> tuple[list[tuple[str, list[tuple[str, str]]]], list[str]]:
    """((name, [(op, version)...]) per package, included files) of a requirements input file."""
    pkgs: list[tuple[str, list[tuple[str, str]]]] = []
    includes: list[str] = []
    for raw in _logical_lines(text):
        line = re.sub(r"(^|\s)#.*$", "", raw).strip()
        if not line:
            continue
        if line.startswith(("-r ", "--requirement ")):
            includes.append(line.split(None, 1)[1].strip())
            continue
        if line.startswith("-"):
            continue
        m = REQ_RE.match(line)
        if not m:
            continue
        specs = []
        for part in filter(None, (x.strip() for x in m.group(2).split(","))):
            sm = SPEC_RE.match(part)
            if sm:
                specs.append((sm.group(1), sm.group(2)))
        pkgs.append((_norm(m.group(1)), specs))
    return pkgs, includes


def _parse_lock(text: str, label: str) -> tuple[dict[str, set[str]], list[str]]:
    """({name: {versions}}, errors) for a hash-pinned lock file."""
    pins: dict[str, set[str]] = defaultdict(set)
    errs: list[str] = []
    for raw in _logical_lines(text):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        head, *hashes = re.split(r"\s+(?=--hash=)", line)
        m = LOCK_PIN_RE.match(head)
        if not m:
            errs.append(f"{label}: {line!r} is not a pinned 'name==version' requirement; regenerate with tools/update_locks.sh")
            continue
        name, version = _norm(m.group(1)), m.group(2)
        pins[name].add(version)
        values = [h[len("--hash="):] for h in hashes if h.startswith("--hash=")]
        if not values or len(values) != len(hashes):
            errs.append(f"{label}: {name}=={version} has no --hash=sha256:... (pip --require-hashes would refuse the file)")
        for h in values:
            if not HASH_RE.match(h):
                errs.append(f"{label}: {name}=={version} has a malformed hash {h!r}")
    return dict(pins), errs


def _check_inputs_against_lock(root: pathlib.Path, inputs: list[str], lock_name: str,
                               pins: dict[str, set[str]]) -> list[str]:
    errs: list[str] = []
    seen: set[str] = set()
    queue = list(inputs)
    while queue:
        fname = queue.pop(0)
        if fname in seen:
            continue
        seen.add(fname)
        path = root / fname
        if not path.is_file():
            errs.append(f"{fname} is missing (referenced by the Python requirements)")
            continue
        pkgs, includes = _parse_inputs(path.read_text(encoding="utf-8"))
        queue += includes
        for name, specs in pkgs:
            versions = pins.get(name)
            if not versions:
                errs.append(f"{fname}: '{name}' is not in {lock_name}; run tools/update_locks.sh")
                continue
            if not any(all(_satisfies(v, op, w) for op, w in specs) for v in versions):
                need = ",".join(f"{op}{w}" for op, w in specs)
                have = ", ".join(sorted(versions))
                errs.append(f"{lock_name} pins {name}=={have}, which does not satisfy '{name}{need}' from {fname}; "
                            "run tools/update_locks.sh")
    return errs


def check_python_locks(root: pathlib.Path) -> list[str]:
    root = pathlib.Path(root)
    if not (root / RUNTIME_INPUT).is_file():
        return []
    errs: list[str] = []
    locks: dict[str, dict[str, set[str]]] = {}
    for lock_name, source in ((RUNTIME_LOCK, RUNTIME_INPUT), (CI_LOCK, CI_INPUT)):
        if lock_name == CI_LOCK and not (root / CI_INPUT).is_file():
            continue
        path = root / lock_name
        if not path.is_file():
            errs.append(f"{lock_name} is missing (generate it with tools/update_locks.sh); workflows install from it")
            continue
        pins, e = _parse_lock(path.read_text(encoding="utf-8"), lock_name)
        errs += e
        locks[lock_name] = pins
        errs += _check_inputs_against_lock(root, [source], lock_name, pins)
    runtime, ci = locks.get(RUNTIME_LOCK), locks.get(CI_LOCK)
    if runtime is not None and ci is not None:
        for name, versions in sorted(runtime.items()):
            for v in sorted(versions - ci.get(name, set())):
                have = ", ".join(sorted(ci[name])) if name in ci else "nothing"
                errs.append(f"{RUNTIME_LOCK} pins {name}=={v} but {CI_LOCK} pins {have}; "
                            f"the two locks must agree (regenerate both with tools/update_locks.sh)")
    return errs


def _check_workflow_lock_refs(root: pathlib.Path) -> list[str]:
    errs: list[str] = []
    for path in _workflow_files(root):
        try:
            doc = _load_yaml(path.read_text(encoding="utf-8"))
        except yaml.YAMLError:
            continue
        for label, _args, _ok, files in _pip_installs(doc):
            for f in files:
                if f and not (pathlib.Path(root) / f).is_file():
                    errs.append(f"{path.name}: {label}: {f} does not exist")
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
    return errs + check_release_consistency(root) + _check_workflow_lock_refs(root) + check_python_locks(root)


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
    if not errs:
        print("workflow policy ok")
    return 1 if errs else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
