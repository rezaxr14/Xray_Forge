"""Dry-run the shell steps of .github/workflows/release.yml.

The ``run:`` scripts are taken from the workflow file itself, their
``${{ matrix.* }}`` placeholders are rendered, and they are executed with bash
(``bash --noprofile --norc -eo pipefail``, like a runner) on fake build output.

What this proves: the packaging / checksum / signing / version-selection shell
logic does what it claims, and the files it produces match the globs the
release job uploads.  What it does NOT prove: that PyInstaller or
electron-builder succeed, that Windows' Git Bash behaves like this one, that
the GitHub actions themselves run, or that a release is created.  Only a run on
real runners shows that.
"""

from __future__ import annotations

import fnmatch
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOW = yaml.safe_load((ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8"))

pytestmark = pytest.mark.skipif(
    sys.platform == "win32" or shutil.which("bash") is None or shutil.which("sha256sum") is None,
    reason="needs bash and coreutils (the release steps themselves run under bash)")

SIGN = "Sign checksums (GPG, optional)"


# ---------------------------------------------------------------------------
# harness
# ---------------------------------------------------------------------------

def matrix(job: str) -> list[dict]:
    return WORKFLOW["jobs"][job]["strategy"]["matrix"]["include"]


LINUX = next(e["os"] for e in matrix("build") if e["os"].startswith("ubuntu"))
WINDOWS = next(e["os"] for e in matrix("build") if e["os"].startswith("windows"))


def entry(job: str, os_name: str) -> dict:
    return next(e for e in matrix(job) if e["os"] == os_name)


def find_step(job: str, name: str) -> dict:
    return next(s for s in WORKFLOW["jobs"][job]["steps"] if s.get("name") == name)


def render(script: str, mx: dict) -> str:
    def sub(m):
        key = m.group(1)
        if not key.startswith("matrix."):
            raise AssertionError(f"unexpected expression in a run: script: {m.group(0)}")
        return str(mx[key.split(".", 1)[1]])
    out = re.sub(r"\$\{\{\s*(.*?)\s*\}\}", sub, script)
    assert "${{" not in out
    return out


class Runner:
    """Executes workflow steps in a scratch checkout."""

    def __init__(self, tmp: pathlib.Path):
        self.repo = tmp / "repo"
        self.repo.mkdir(parents=True)
        self.bin = tmp / "bin"
        self.bin.mkdir(parents=True)
        (self.bin / "python").symlink_to(sys.executable)   # runners have `python`; the sandbox may not
        self.home = tmp / "home"
        self.home.mkdir(parents=True)
        shutil.copy(ROOT / "README.md", self.repo / "README.md")
        shutil.copy(ROOT / "LICENSE", self.repo / "LICENSE")
        shutil.copy(ROOT / "NOTICE", self.repo / "NOTICE")
        shutil.copy(ROOT / "pyproject.toml", self.repo / "pyproject.toml")
        (self.repo / "tools").mkdir()
        shutil.copy(ROOT / "tools" / "check_version.py", self.repo / "tools" / "check_version.py")
        (self.repo / "xray_forge").mkdir()
        shutil.copy(ROOT / "xray_forge" / "__init__.py", self.repo / "xray_forge" / "__init__.py")
        (self.repo / "electron").mkdir()
        for name in ("package.json", "package-lock.json"):         # check_version also compares the desktop app's version
            shutil.copy(ROOT / "electron" / name, self.repo / "electron" / name)

    def write(self, rel: str, data: bytes | str = b"x", mode: int | None = None) -> pathlib.Path:
        p = self.repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data if isinstance(data, bytes) else data.encode())
        if mode is not None:
            p.chmod(mode)
        return p

    def step(self, job: str, name: str, mx: dict | None = None, env: dict | None = None):
        s = find_step(job, name)
        script = render(s["run"], mx or {})
        e = {"PATH": f"{self.bin}:{os.environ['PATH']}", "HOME": str(self.home), "LANG": "C.UTF-8"}
        for key, val in (s.get("env") or {}).items():
            e[key] = "" if "secrets." in str(val) else str(val)   # an unset secret is an empty string
        e.update(env or {})
        cwd = self.repo / s.get("working-directory", WORKFLOW["jobs"][job].get("working-directory", "."))
        return subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", script],
                              cwd=cwd, env=e, capture_output=True, text=True, timeout=120)


@pytest.fixture
def run(tmp_path):
    return Runner(tmp_path)


def ok(r: subprocess.CompletedProcess) -> subprocess.CompletedProcess:
    assert r.returncode == 0, f"exit {r.returncode}\nSTDOUT:\n{r.stdout}\nSTDERR:\n{r.stderr}"
    return r


# ---------------------------------------------------------------------------
# CLI build job: package + checksums
# ---------------------------------------------------------------------------

def test_cli_package_linux_zip_has_executable_readme_and_license(run):
    mx = entry("build", LINUX)
    run.write(f"dist/{mx['exe']}", b"\x7fELF fake", mode=0o644)
    ok(run.step("build", "Package (Linux)", mx))
    z = zipfile.ZipFile(run.repo / "dist" / f"{mx['artifact']}.zip")
    assert sorted(z.namelist()) == sorted([mx["exe"], "LICENSE", "NOTICE", "README.md"])
    assert (z.getinfo(mx["exe"]).external_attr >> 16) & 0o111, "the binary lost its executable bit"


def test_cli_package_windows_zip_uses_stdlib_archiver(run):
    mx = entry("build", WINDOWS)
    run.write(f"dist/{mx['exe']}", b"MZ fake")
    ok(run.step("build", "Package (Windows)", mx))
    z = zipfile.ZipFile(run.repo / "dist" / f"{mx['artifact']}.zip")
    assert sorted(z.namelist()) == sorted([mx["exe"], "LICENSE", "NOTICE", "README.md"])


@pytest.mark.parametrize("missing", ["LICENSE", "NOTICE"])
def test_cli_package_fails_when_a_legal_file_is_missing(run, missing):
    mx = entry("build", WINDOWS)
    run.write(f"dist/{mx['exe']}", b"MZ fake")
    (run.repo / missing).unlink()
    r = run.step("build", "Package (Windows)", mx)
    assert r.returncode != 0 and missing in r.stderr, "an archive without its license must not be published"


@pytest.mark.parametrize("os_name", [LINUX, WINDOWS])
def test_cli_checksum_file_verifies_from_the_download_directory(run, os_name):
    mx = entry("build", os_name)
    run.write(f"dist/{mx['artifact']}.zip", b"zip bytes")
    ok(run.step("build", "Checksums", mx))
    line = (run.repo / "dist" / f"{mx['artifact']}.zip.sha256").read_text()
    assert line.split()[1] == f"{mx['artifact']}.zip", "checksum must name the bare file, not a path"
    ok(subprocess.run(["sha256sum", "-c", f"{mx['artifact']}.zip.sha256"], cwd=run.repo / "dist",
                      capture_output=True, text=True))


def test_missing_artifact_fails_the_checksum_step_loudly(run):
    mx = entry("build", LINUX)
    (run.repo / "dist").mkdir()
    assert run.step("build", "Checksums", mx).returncode != 0


# ---------------------------------------------------------------------------
# GPG signing (real gpg, throwaway key)
# ---------------------------------------------------------------------------

needs_gpg = pytest.mark.skipif(shutil.which("gpg") is None, reason="gpg not installed")


@pytest.fixture
def gnupg_dirs():
    made = []

    def make() -> str:
        d = tempfile.mkdtemp(prefix="gh", dir="/tmp")     # short: gpg-agent sockets have a path limit
        os.chmod(d, 0o700)
        made.append(d)
        return d
    yield make
    for d in made:
        subprocess.run(["gpgconf", "--homedir", d, "--kill", "all"], capture_output=True)
        shutil.rmtree(d, ignore_errors=True)


def _secret_key(make_home, passphrase: str) -> str:
    home = make_home()
    base = ["gpg", "--batch", "--homedir", home, "--pinentry-mode", "loopback", "--passphrase", passphrase]
    subprocess.run(base + ["--quick-generate-key", "Release Test <release@example.invalid>", "default", "default", "never"],
                   check=True, capture_output=True)
    return subprocess.run(base + ["--armor", "--export-secret-keys"], check=True, capture_output=True, text=True).stdout


def _signing_dir(job: str) -> str:
    return "dist" if job == "build" else "out"


@pytest.mark.parametrize("job", ["build", "desktop"])
def test_signing_is_skipped_without_a_key(run, job):
    d = _signing_dir(job)
    run.write(f"{d}/a.zip.sha256", b"deadbeef  a.zip\n")
    r = ok(run.step(job, SIGN))
    assert "skipping signing" in r.stdout
    assert not list((run.repo / d).glob("*.sig"))


@needs_gpg
@pytest.mark.parametrize("passphrase", ["", "correct horse"])
@pytest.mark.parametrize("job", ["build", "desktop"])
def test_signing_produces_verifiable_signatures(run, gnupg_dirs, job, passphrase):
    d = _signing_dir(job)
    key = _secret_key(gnupg_dirs, passphrase)
    sums = ["one.zip.sha256", "two.exe.sha256"]
    for s in sums:
        run.write(f"{d}/{s}", f"abc  {s[:-7]}\n")
    run.write(f"{d}/two.exe", b"installer")          # non-checksum files must be left alone
    home = gnupg_dirs()
    ok(run.step(job, SIGN, env={"GPG_PRIVATE_KEY": key, "GPG_PASSPHRASE": passphrase, "GNUPGHOME": home}))
    sigs = sorted(p.name for p in (run.repo / d).glob("*.sig"))
    assert sigs == sorted(s + ".sig" for s in sums)
    for s in sums:
        v = subprocess.run(["gpg", "--homedir", home, "--batch", "--verify", f"{d}/{s}.sig", f"{d}/{s}"],
                           cwd=run.repo, capture_output=True, text=True)
        assert v.returncode == 0 and "Good signature" in v.stderr, v.stderr


@needs_gpg
def test_tampering_with_a_signed_checksum_is_detected(run, gnupg_dirs):
    key = _secret_key(gnupg_dirs, "")
    run.write("dist/a.zip.sha256", b"abc  a.zip\n")
    home = gnupg_dirs()
    ok(run.step("build", SIGN, env={"GPG_PRIVATE_KEY": key, "GNUPGHOME": home}))
    (run.repo / "dist" / "a.zip.sha256").write_text("evil  a.zip\n")
    v = subprocess.run(["gpg", "--homedir", home, "--batch", "--verify", "dist/a.zip.sha256.sig", "dist/a.zip.sha256"],
                       cwd=run.repo, capture_output=True, text=True)
    assert v.returncode != 0


# ---------------------------------------------------------------------------
# desktop job
# ---------------------------------------------------------------------------

def test_stage_engine_replaces_a_stale_copy(run):
    run.write("electron/engine-dist/stale.txt", b"old")
    run.write("dist/xray-forge-engine/xray-forge-engine", b"bin")
    run.write("dist/xray-forge-engine/_internal/lib.so", b"lib")
    ok(run.step("desktop", "Stage the engine for electron-builder"))
    staged = run.repo / "electron" / "engine-dist"
    assert not (staged / "stale.txt").exists()
    assert (staged / "xray-forge-engine").read_bytes() == b"bin" and (staged / "_internal" / "lib.so").exists()


def test_installer_gets_license_and_notice_staged_where_electron_builder_reads_them(run):
    ok(run.step("desktop", "Stage license files for the installer"))
    legal = run.repo / "electron" / "legal"
    assert (legal / "LICENSE").read_bytes() == (ROOT / "LICENSE").read_bytes()
    assert (legal / "NOTICE").read_bytes() == (ROOT / "NOTICE").read_bytes()
    import json
    extra = json.loads((ROOT / "electron" / "package.json").read_text())["build"]["extraResources"]
    assert {"from": "legal", "to": "legal"} in extra


def test_license_staging_fails_without_the_files(run):
    (run.repo / "NOTICE").unlink()
    assert run.step("desktop", "Stage license files for the installer").returncode != 0


def test_license_staging_runs_before_the_installer_is_built():
    names = [s.get("name") for s in WORKFLOW["jobs"]["desktop"]["steps"]]
    assert names.index("Stage license files for the installer") < names.index("Build the installer")


UNPACKED = "Check the unpacked app (layout, license files, engine starts)"


def _unpacked_tree(run: Runner, **kw) -> pathlib.Path:
    from tests.test_check_artifacts import ENGINE_SRC, tree
    for tool in ("check_artifacts.py", "smoke_engine.py"):
        shutil.copy(ROOT / "tools" / tool, run.repo / "tools" / tool)
    return tree(run.repo / "electron" / "release", "linux", engine_src=kw.pop("engine_src", ENGINE_SRC), **kw)


def test_unpacked_app_check_step_passes_on_a_complete_tree_and_expands_the_glob(run):
    d = _unpacked_tree(run)
    r = ok(run.step("desktop", UNPACKED, entry("desktop", LINUX)))
    assert "check_artifacts: ok" in r.stdout and d.name in r.stdout and "engine started" in r.stdout


def test_unpacked_app_check_step_fails_when_the_engine_is_missing(run):
    d = _unpacked_tree(run)
    (d / "resources" / "engine" / "xray-forge-engine").unlink()
    r = run.step("desktop", UNPACKED, entry("desktop", LINUX))
    assert r.returncode != 0 and "engine missing" in r.stdout


def test_unpacked_app_check_step_fails_when_the_packaged_engine_does_not_start(run):
    from tests.test_check_artifacts import BROKEN_SRC
    _unpacked_tree(run, engine_src=BROKEN_SRC)
    r = run.step("desktop", UNPACKED, entry("desktop", LINUX))
    assert r.returncode != 0 and "engine smoke test" in r.stdout


def test_unpacked_app_check_step_fails_when_electron_builder_wrote_no_unpacked_dir(run):
    for tool in ("check_artifacts.py", "smoke_engine.py"):
        shutil.copy(ROOT / "tools" / tool, run.repo / "tools" / tool)
    (run.repo / "electron" / "release").mkdir()
    assert run.step("desktop", UNPACKED, entry("desktop", LINUX)).returncode != 0


def test_unpacked_app_check_runs_between_the_build_and_the_checksums():
    names = [s.get("name") for s in WORKFLOW["jobs"]["desktop"]["steps"]]
    assert names.index("Build the installer") < names.index(UNPACKED) < names.index("Checksums")


def _stub_npx(run: Runner) -> pathlib.Path:
    log = run.repo / "npx.log"
    stub = run.bin / "npx"
    stub.write_text(f'#!/bin/bash\nprintf "%s\\n" "$*" >> "{log}"\nmkdir -p release\n')
    stub.chmod(0o755)
    return log


def _builder_version(log: pathlib.Path) -> str:
    line = log.read_text().strip()
    assert line.startswith("electron-builder --publish never"), line
    return re.search(r"-c\.extraMetadata\.version=(\S+)", line).group(1)


def test_installer_version_comes_from_the_tag(run):
    log = _stub_npx(run)
    (run.repo / "electron").mkdir(exist_ok=True)
    env = {"GITHUB_REF_TYPE": "tag", "GITHUB_REF_NAME": "v2.1.0"}
    ok(run.step("desktop", "Build the installer", env=env))
    assert _builder_version(log) == "2.1.0"


def test_prerelease_tag_keeps_its_suffix_in_the_installer_version(run):
    log = _stub_npx(run)
    (run.repo / "electron").mkdir(exist_ok=True)
    ok(run.step("desktop", "Build the installer", env={"GITHUB_REF_TYPE": "tag", "GITHUB_REF_NAME": "v2.1.0-rc1"}))
    assert _builder_version(log) == "2.1.0-rc1"


def test_branch_build_uses_the_package_version_and_never_signs(run):
    from xray_forge import __version__
    log = _stub_npx(run)
    (run.repo / "electron").mkdir(exist_ok=True)
    ok(run.step("desktop", "Build the installer", env={"GITHUB_REF_TYPE": "branch", "GITHUB_REF_NAME": "feat/x"}))
    assert _builder_version(log) == __version__
    assert find_step("desktop", "Build the installer")["env"]["CSC_IDENTITY_AUTO_DISCOVERY"] == "false"


@pytest.mark.parametrize("job", ["build", "desktop"])
def test_tag_check_step_accepts_the_package_version_and_rejects_others(run, job):
    from xray_forge import __version__
    name = "Check tag matches package version"
    ok(run.step(job, name, env={"GITHUB_REF_NAME": f"v{__version__}"}))
    ok(run.step(job, name, env={"GITHUB_REF_NAME": f"v{__version__}-rc1"}))
    bad = run.step(job, name, env={"GITHUB_REF_NAME": "v9.9.9"})
    assert bad.returncode == 1 and "does not match" in bad.stdout


def test_desktop_checksums_keep_only_the_installer_of_that_platform(run):
    for os_name, wanted, other in ((WINDOWS, "XrayForge-2.1.0-win-x64.exe", "XrayForge-2.1.0-x86_64.AppImage"),
                                   (LINUX, "XrayForge-2.1.0-x86_64.AppImage", "XrayForge-2.1.0-win-x64.exe")):
        mx = entry("desktop", os_name)
        sub = Runner(pathlib.Path(tempfile.mkdtemp(prefix="dk")))
        sub.write(f"electron/release/{wanted}", b"installer")
        sub.write(f"electron/release/{other}", b"other platform")
        sub.write("electron/release/builder-debug.yml", b"junk")
        sub.write("electron/release/win-unpacked/app.exe", b"junk")
        ok(sub.step("desktop", "Checksums", mx))
        out = sorted(p.name for p in (sub.repo / "out").iterdir())
        assert out == sorted([wanted, wanted + ".sha256"]), out
        ok(subprocess.run(["sha256sum", "-c", wanted + ".sha256"], cwd=sub.repo / "out", capture_output=True, text=True))


def test_desktop_checksums_fail_when_no_installer_matches(run):
    run.write("electron/release/builder-debug.yml", b"junk")
    assert run.step("desktop", "Checksums", entry("desktop", WINDOWS)).returncode != 0


# ---------------------------------------------------------------------------
# the whole contract: what the jobs produce is what the release job uploads
# ---------------------------------------------------------------------------

@needs_gpg
def test_release_globs_match_exactly_what_the_build_jobs_produce(run, gnupg_dirs, tmp_path):
    from xray_forge import __version__
    key = _secret_key(gnupg_dirs, "")
    merged = tmp_path / "merged"            # what download-artifact (merge-multiple) puts in dist/
    merged.mkdir()

    for os_name in (LINUX, WINDOWS):          # CLI build job
        mx = entry("build", os_name)
        job_run = Runner(tmp_path / f"cli-{os_name}")
        job_run.write(f"dist/{mx['exe']}", b"bin")
        ok(job_run.step("build", "Package (Linux)" if os_name.startswith("ubuntu") else "Package (Windows)", mx))
        ok(job_run.step("build", "Checksums", mx))
        ok(job_run.step("build", SIGN, env={"GPG_PRIVATE_KEY": key, "GNUPGHOME": gnupg_dirs()}))
        uploaded = [(job_run.repo / p) for p in _render_paths(find_step_upload("build"), mx)]
        for src in uploaded:
            assert src.exists(), f"upload-artifact path {src.relative_to(job_run.repo)} is never produced"
            shutil.copy(src, merged / src.name)

    installer_ext = {WINDOWS: "exe", LINUX: "AppImage"}
    for os_name in (LINUX, WINDOWS):          # desktop job
        mx = entry("desktop", os_name)
        job_run = Runner(tmp_path / f"desk-{os_name}")
        job_run.write(f"electron/release/XrayForge-{__version__}-x64.{installer_ext[os_name]}", b"installer")
        ok(job_run.step("desktop", "Checksums", mx))
        ok(job_run.step("desktop", SIGN, env={"GPG_PRIVATE_KEY": key, "GNUPGHOME": gnupg_dirs()}))
        for src in sorted((job_run.repo / "out").iterdir()):     # upload-artifact path: out/*
            shutil.copy(src, merged / src.name)

    release_step = next(s for s in WORKFLOW["jobs"]["release"]["steps"] if "action-gh-release" in s.get("uses", ""))
    globs = [g.strip() for g in release_step["with"]["files"].splitlines() if g.strip()]
    names = sorted(p.name for p in merged.iterdir())
    for g in globs:
        pattern = g.split("/", 1)[1]
        assert any(fnmatch.fnmatch(n, pattern) for n in names), f"release glob {g} matches nothing; produced: {names}"
    orphans = [n for n in names if not any(fnmatch.fnmatch(n, g.split("/", 1)[1]) for g in globs)]
    assert orphans == [], f"files the jobs upload but the release never attaches: {orphans}"
    assert len(names) == 12, names     # 2 zips + 2 installers, each with .sha256 and .sha256.sig


def find_step_upload(job: str) -> list[str]:
    step = next(s for s in WORKFLOW["jobs"][job]["steps"] if s.get("uses", "").startswith("actions/upload-artifact@"))
    return [p.strip() for p in step["with"]["path"].splitlines() if p.strip()]


def _render_paths(paths: list[str], mx: dict) -> list[str]:
    return [render(p, mx) for p in paths]
