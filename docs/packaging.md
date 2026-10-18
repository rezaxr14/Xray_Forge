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
The tag must equal `xray_forge.__version__` and `pyproject.toml`
(`tools/check_version.py`); the installer takes its version from the package.

## Not verified yet (needs a real run on CI or your machine)

- The PyInstaller build and the electron-builder run have never been executed
  by the author of this change: the sandbox it was written in cannot reach
  PyPI/npm. First tag push (or `workflow_dispatch`) is the real test; start
  with a throw-away tag such as `v2.1.0-rc1` on a branch whose version matches.
- `electron/package-lock.json` does not exist yet. Run `npm install` once in
  `electron/` and commit the lock file, then switch the workflow to `npm ci`.
- Windows installers are **unsigned**: SmartScreen will warn. Code signing
  needs a certificate (`CSC_LINK`, `CSC_KEY_PASSWORD`) and is out of scope here.
- Linux AppImage: some distributions disable unprivileged user namespaces,
  which Chromium's sandbox needs; the app then needs `--no-sandbox`.
- macOS is not built (no macOS engine testing).
- Default Electron icon; add `build/icon.png` (512x512) and `build/icon.ico`.
- The engine keeps its data in `~/.xray_forge` (accounts, sessions, logs).
  Uninstalling the app does not remove it.
