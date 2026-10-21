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
pip install -r requirements.txt cryptography pyinstaller
pyinstaller --noconfirm --onedir --name xray-forge-engine \
  --exclude-module tkinter --collect-submodules xray_forge \
  --hidden-import cryptography Xray_Forge.py
python tools/smoke_engine.py -- dist/xray-forge-engine/xray-forge-engine serve   # must print "passed"

rm -rf electron/engine-dist && cp -r dist/xray-forge-engine electron/engine-dist
cd electron && npm install && npx electron-builder --publish never
# -> electron/release/XrayForge-<version>-<os>-<arch>.{exe,AppImage}
```

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

Manual runs: `workflow_dispatch` only works once `release.yml` exists on the
**default branch**; the run uses the workflow file of the ref you dispatch on,
so keep both copies in sync until the feature branch is merged.

## Status

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
  that drifted from `package.json`). Unpinned `pip install` arguments are printed as
  warnings only.
* **`tests/test_release_dryrun.py`** executes the real `run:` scripts of `release.yml`
  (packaging, checksums, GPG signing with a throw-away key, installer-version choice,
  tag check) under bash on fake build output, and checks that what the jobs produce is
  exactly what the release job uploads. It cannot show that PyInstaller or
  electron-builder succeed, or that the actions run: only a real runner does.
* **Python lock file: not generated yet.** The sandbox this was written in cannot reach
  PyPI. `requirements-ci.in` + `tools/update_locks.sh` are ready: run the script once
  with network access, commit `requirements.lock` / `requirements-ci.lock`, then change
  the workflows to `pip install --require-hashes -r requirements-ci.lock` (and the pip
  cache key to the lock file). Until then the advisory warnings remain.
* Updating a pin: look up the tag's commit (`git ls-remote --tags <repo> 'refs/tags/vX.Y.Z*'`;
  for an annotated tag use the `^{}` line), replace the SHA and the comment together.

## Icons and legal files

* `electron/assets/icon.png` (512x512) and `icon.ico` (16..256) are drawn by
  `tools/make_icons.py electron/assets` (needs Pillow; output is committed and a
  test fails if it goes stale). They live in `assets/`, not `build/`, because
  `build/` is gitignored. electron-builder reads them via
  `directories.buildResources`; the window uses the PNG at runtime. Not yet
  seen in a built installer: nobody has launched one.
* Release archives and installers ship `LICENSE` and `NOTICE` (Apache-2.0); the
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
