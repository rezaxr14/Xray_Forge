# Packaging the desktop app

The desktop app is Electron + a frozen copy of the Python engine:

```
XrayForge (installer / AppImage)
└── resources/engine/xray-forge-engine[.exe]   <- PyInstaller one-folder build, `serve` mode
```

`electron/engine-path.js` picks the engine at runtime:
`XRAY_FORGE_ENGINE` (explicit) → bundled engine (packaged app) → `python -m xray_forge serve` (development).

## Build locally

```bash
pip install --require-hashes -r requirements-ci.lock   # same locked set CI uses
pyinstaller --noconfirm --onedir --name xray-forge-engine \
  --exclude-module tkinter --collect-submodules xray_forge \
  --hidden-import cryptography Xray_Forge.py
python tools/smoke_engine.py -- dist/xray-forge-engine/xray-forge-engine serve   # must print "passed"

rm -rf electron/engine-dist && cp -r dist/xray-forge-engine electron/engine-dist
cd electron && npm install && npx electron-builder --publish never
# -> electron/release/XrayForge-<version>-<os>-<arch>.{exe,AppImage}
```

**Windows:** electron-builder unpacks a code-signing helper cache that contains macOS symlinks; without
symlink rights it fails with "Cannot create symbolic link : A required privilege is not held by the client"
and no installer is produced (the `win-unpacked` folder still works). Enable Developer Mode (Settings -> System ->
For developers) or build from an elevated shell. GitHub's Windows runners are not affected. This was seen on a
real machine, not reproduced in CI.

`tools/smoke_engine.py` is the gate: it starts the frozen engine, asks for
`engine.info`, parses a link and checks the scan/MITM methods are present
(a missing module in the bundle shows up here, not in front of a user).

## Release

Pushing a `v*` tag runs `.github/workflows/release.yml`:
`build` (CLI zips, as before) and `desktop` (Windows installer + Linux
AppImage) must both pass before `release` attaches everything, with SHA-256
files and, when `GPG_PRIVATE_KEY` is configured, detached signatures.

Tags: `vX.Y.Z` must equal `xray_forge.__version__` and `pyproject.toml`
(`tools/check_version.py`). To rehearse without bumping the version, push
`vX.Y.Z-rc1` (also `-betaN`, `-alphaN`): the core must still match, and the
GitHub release is created as a *pre-release*. Installers take their version
from the tag (or from the package files when run from a branch).

Release builds run on **pinned runner images** (`ubuntu-24.04`, `windows-2022`), not `-latest`:
a Linux binary built on a newer glibc does not start on older distributions, and a runner
migration (`ubuntu-latest` became Ubuntu 26.04 on 2026-10-19) must not change a release silently.
`tools/check_workflows.py` fails the build of the repo if a release build job floats.

After electron-builder, the `desktop` job runs `tools/check_artifacts.py --smoke
electron/release/*-unpacked`: electron-builder's unpacked folder is exactly what the installer /
AppImage is made from, so this checks that the engine and the app code are in it, that
`resources/legal/LICENSE` and `NOTICE` are the repository's (GPL-3.0 text and source offer ship
with every installer), that the Linux engine is executable, and that the packaged engine starts
and answers (`tools/smoke_engine.py`). It does not install or launch the app window.

Manual runs: `workflow_dispatch` only works once `release.yml` exists on the
**default branch**; the run uses the workflow file of the ref you dispatch on,
so keep both copies in sync until the feature branch is merged. Without merging, rehearse by
pushing a pre-release tag on the feature branch head (`v2.1.0-rc1`, the core must equal the
package version): the tag runs the workflow file at that commit and creates a *pre-release*.

### Known risks of the shipped artifacts (not yet checked on our build)

* **Windows:** the installer is unsigned, so SmartScreen shows "Windows protected your PC": More
  info -> Run anyway. Code signing needs a certificate (`CSC_*` secrets); none is configured.
* **Linux AppImage:** needs FUSE 2 (`libfuse2`, `libfuse2t64` on Ubuntu 24.04) or run it with
  `--appimage-extract-and-run`. On Ubuntu 24.04+ AppArmor can block Chromium's sandbox (unprivileged
  user namespaces) and the app exits at start with a sandbox error. `--no-sandbox` works around it but
  removes a security layer, so it is not set by default; allow the app in AppArmor or enable user
  namespaces for it instead.
* **Python 3.15** builds the engine (PyInstaller 6.22.3 worked locally on 3.15.2); PyYAML has no
  3.15 wheel yet, so the lock install builds it from the hash-pinned sdist.

## Status

**Re-verification needed.** The run below predates Python 3.15 / Node 24 builds, the pinned runner
images, the hash-locked installs, the GPL relicense (new `LICENSE`/`NOTICE` in the installers) and the
`check_artifacts` step. Rehearse with an `-rc` tag (see above) and runbook Job 7.

Verified on real runners (run 39136895263, head 8efd63e): CLI build and
desktop build on Windows and Linux are green; artifacts were a 88 MB Windows
installer and a 130 MB Linux AppImage. Three bugs only a real run exposed
(missing pytest, version read from the wrong directory, no `zip` on Windows)
are fixed; `tools/check_version.py --package` now reads the version from files.

## Supply-chain hardening

* **Actions are pinned by commit SHA** (`uses: owner/repo@<40 hex> # vX.Y.Z`) and the
  workflow token is read-only (`permissions: contents: read`); only the `release` job
  gets `contents: write`. `electron/package-lock.json` is committed and the desktop job
  uses `npm ci`.
* **`tools/check_workflows.py`** enforces those rules offline (also run by
  `tests/test_workflow_policy.py`, so CI fails when someone adds `uses: x@v4`, a
  `pwsh` step, an untrusted `${{ }}` inside `run:`, a floating `npm install`, a missing
  timeout, installer globs that no longer match `electron/package.json`, or a lock file
  that drifted from `package.json`). Any `pip install` that is not hash-locked is an
  error (see the Python lock files item below).
* **`tests/test_release_dryrun.py`** executes the real `run:` scripts of `release.yml`
  (packaging, checksums, GPG signing with a throw-away key, installer-version choice,
  tag check) under bash on fake build output, and checks that what the jobs produce is
  exactly what the release job uploads. It cannot show that PyInstaller or
  electron-builder succeed, or that the actions run: only a real runner does.
* **Python lock files.** `requirements.lock` (runtime) and `requirements-ci.lock` (runtime +
  pytest, ruff, cryptography, pyinstaller) are generated by `tools/update_locks.sh`
  (`uv pip compile --universal --generate-hashes`, one file for Linux/Windows and every
  supported Python). Both workflows install with
  `pip install --require-hashes -r requirements-ci.lock`; the project itself with
  `pip install --no-deps --no-build-isolation -e .` (build isolation would download a
  build backend without hashes; the locked setuptools is used instead); `actions/setup-python`
  caches pip keyed on `requirements-ci.lock`. `tools/check_workflows.py` fails on any other
  `pip install` form, on a pip cache not keyed on a lock file, and on lock files that are
  malformed (a pin without sha256 hashes), miss a package from `requirements.txt` /
  `requirements-ci.in`, pin a version that violates the input's specifier, or disagree
  between the two locks. It cannot prove the pins resolve on every Python/OS or are the
  newest allowed: only a real install does (runbook Job 1b).
  To bump a dependency: edit `requirements.txt` / `requirements-ci.in`, run
  `tools/update_locks.sh`, review and commit both locks.
* Updating a pin: look up the tag's commit (`git ls-remote --tags <repo> 'refs/tags/vX.Y.Z*'`;
  for an annotated tag use the `^{}` line), replace the SHA and the comment together.

## Icons and legal files

* `electron/assets/icon.png` (512x512) and `icon.ico` (16..256) are drawn by
  `tools/make_icons.py electron/assets` (needs Pillow; output is committed and a
  test fails if it goes stale). They live in `assets/`, not `build/`, because
  `build/` is gitignored. electron-builder reads them via
  `directories.buildResources`; the window uses the PNG at runtime. Not yet
  seen in a built installer: nobody has launched one.
* Release archives and installers ship `LICENSE` and `NOTICE` (GPL-3.0-only); the
  desktop job stages them into `electron/legal/` for `extraResources`.

## Still open

- Windows installers are **unsigned**: SmartScreen will warn. Code signing
  needs a certificate (`CSC_LINK`, `CSC_KEY_PASSWORD`).
- Linux AppImage: some distributions disable unprivileged user namespaces,
  which Chromium's sandbox needs; the app then needs `--no-sandbox`.
- macOS is not built (no macOS engine testing).
- The engine keeps its data in `~/.xray_forge` (accounts, sessions, logs).
  Uninstalling the app does not remove it.
- The installers have not been launched by a human yet; CI only proves they
  build and that the bundled engine answers the smoke test.
