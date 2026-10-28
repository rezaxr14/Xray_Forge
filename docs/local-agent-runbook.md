# Local agent runbook

Things the cloud sandbox cannot do (PyPI/npm/other hosts blocked, no real
network, no display, no Windows build). Give this file to your local agent. It
runs the jobs on your machine and returns the **reports** named below. Do the
jobs in order and stop at the first one that fails to set up; report what
happened rather than working around it.

## Ground rules for the agent

- Work in a **fresh clone** of `rezaxr14/Xray_Forge`, branch `feat/roadmap-v2-1`. Never run these
  against a checkout with uncommitted work.
- **Never paste secrets into reports**: share links, UUIDs, tokens, Psiphon config values, license keys,
  server addresses. `tools/live_check.py` already leaves them out; keep it that way for anything you add.
- Put share links in a file (`--link-file`) or the `XF_LIVE_LINK` variable, never on a command line.
- Download third-party binaries only from the project's official release page, check the published
  checksum if there is one, keep them in a scratch folder and do not install them system-wide.
- Report **exact** command output for failures. Do not retry until green and do not edit code to make a
  check pass: send back the failure.

## Job 0: setup

    git clone https://github.com/rezaxr14/Xray_Forge.git && cd Xray_Forge
    git checkout feat/roadmap-v2-1
    python -m venv .venv          # then activate it
    pip install -r requirements.txt cryptography pytest ruff
    python -m pytest -q
    cd electron && npm ci && npm test && cd ..

Report: Python/Node versions, OS, pass/fail counts.

## Job 1: Python lock files

Needs network and [uv](https://docs.astral.sh/uv/).

    tools/update_locks.sh          # Windows: run it from Git Bash
    git diff --stat

Report: the new `requirements.lock` and `requirements-ci.lock` (attach the files, they contain only
public package names and hashes). Do not edit the workflows (they already install from the locks;
Job 1b checks that). Run this job only when the maintainer asks for new locks.

## Job 1b: install from the lock files (what CI now does)

CI and the release build now install only from the hash-pinned locks. This job proves those exact
commands work on a real machine, before a runner is asked to. Use a **new, empty virtual environment
for each Python you have** (3.10, 3.12, 3.13 and 3.15 are the CI matrix; any subset is useful):

    python -m venv .venv-lock && .venv-lock/Scripts/activate      # Linux/macOS: source .venv-lock/bin/activate
    python -m pip install --upgrade pip
    pip install --require-hashes -r requirements-ci.lock
    pip install --no-deps --no-build-isolation -e .
    pip check
    python -m xray_forge --help
    python -m pytest -q
    ruff check --select E9,F63,F7,F82 .
    python tools/check_workflows.py

Report per Python version: OS, `python --version`, and for each command pass/fail. For a failure paste
the **exact** output (a hash mismatch, "no matching distribution", or a build error is the finding: do
not retry with other flags, do not remove `--require-hashes`, do not regenerate the locks). Also report
`pip list --format=freeze` for the first venv (package names and versions only).

## Job 2: live checks

    python tools/live_check.py env --out report-env.json
    python tools/live_check.py warp-scan --out report-warp.json
    python tools/live_check.py vless --link-file my_link.txt --out report-vless.json
    python tools/live_check.py masque --masque-binary /path/to/sing-box-extended --out report-masque.json
    python tools/live_check.py psiphon --psiphon-binary /path/to/ConsoleClient --psiphon-config /path/to/client.config --out report-psiphon.json

- `vless`: the owner's own server link, one link in the file. This is the throughput-validation check.
- `masque`: needs the `sing-box-extended` build from the fork's official releases. The first run may
  create a Cloudflare device profile and can take a minute.
- `psiphon`: needs a `ConsoleClient` binary and a client config the owner obtained from Psiphon Labs.
  Xray Forge ships none and never prints the config values.
- Skip any check whose input the owner has not provided; the tool reports it as `skipped`.

Report: each JSON file as is, plus a one-line note on anything odd (captive portal, VPN running,
corporate proxy, antivirus prompts).

## Job 3: desktop build (Windows, then macOS/Linux if available)

Follow "Build locally" in `docs/packaging.md` exactly (PyInstaller engine, `tools/smoke_engine.py` gate,
copy to `electron/engine-dist`, `npx electron-builder --publish never`), and first stage the license
files the way `.github/workflows/release.yml` does (`mkdir -p electron/legal && cp LICENSE NOTICE
electron/legal/`). The workflow is the source of truth if the two ever differ.

Report: whether each step passed (with the exact error text for any that did not), the installer's file
name and size, and the result of installing and launching it (window opens, the engine answers, the icon
shows, `LICENSE` and `NOTICE` are under the app's `resources/legal`). Screenshots are welcome; make sure
no personal data is visible.

## Job 4: the Electron shell by hand

With the app running (`cd electron && npm start`): open each tab, use the real file open/save dialogs
(import a links file, export results), restart the app and confirm settings persisted, run a small scan
against a CIDR you own, press Stop mid-scan.

Also check the MASQUE / Psiphon tab: set a binary and (for Psiphon) your own config through the real
Browse dialogs, run "Test connection", press Cancel during a slow one, restart and confirm the MASQUE
options came back.

Main-process hardening (only a fake Electron has exercised these so far), in the real app:

- start a second copy: it must exit at once and the first window must come to the front;
- open DevTools (Ctrl+Shift+I) in the packaged build or `npm start` and run
  `await navigator.mediaDevices.getUserMedia({audio:true})` and `await Notification.requestPermission()`:
  both must be denied with no prompt;
- click any external https link (e.g. one inside a guide text): it opens in the default browser and the
  app window does not navigate away.

Report: a short list of what worked and what did not, with the exact visible error text.

## Job 4b: real core downloads

The downloader's asset-name rules were written without access to live release data, so this is the first
real test. In the app (Cores tab, and the Download button on the MASQUE / Psiphon tab) or with the engine:

- For each of xray, sing-box, mihomo and sing-box-extended: press Download, read the review line (tag, asset,
  size, sha256, repo), then confirm. Report per core: the exact review line, whether install succeeded, the
  version shown, and the exact error text if it refused ("no matching ... download", "more than one ...",
  "no sha256 digest ..." are the expected refusal reasons: copy them verbatim plus the release tag).
- If a core refuses, list that release's asset file names (from its GitHub releases page) so the rules can be fixed.
- Check that nothing outside `~/.xray_forge/cores/` was written and no temp `.dl-*` folders remain.
- Note whether GitHub was reachable at all from your network (api.github.com and release downloads).

## Job 5: Windows test suite and fake-core fixtures

    python -m pytest -q

Tests that use fake external cores (`tests/test_masque.py`, `test_psiphon.py`, `test_live_check.py`,
`test_engine_masque.py`, `test_cli_masque.py`) run on Windows through `.cmd` wrappers (`tests/fakebin.py`).
That path has only been run on Linux so far. Report the full list of failures with their output; do not
skip or edit tests to get green.

Also run, on the machine you checked MASQUE on:

    python -m xray_forge masque config --dns auto
    python -m xray_forge masque config --dns doh

and use the printed config with the real `sing-box-extended` (`check`, then `run` and fetch an HTTPS page
through its SOCKS port with `--bind-interface` absent). Then `python tools/live_check.py masque`. Report whether
`auto` picked DoH on your fake-IP TUN setup and whether the probe now succeeds with HTTP/2
(`masque probe --http2`) and without.

## Job 7: release rehearsal (installer and AppImage)

Proves the GitHub Actions release build and the artifacts it makes. Needs push rights to the repository.

1. On the maintainer's say-so, from a clean checkout of the pushed `feat/roadmap-v2-1` head:
   `git tag v2.1.0-rc1 && git push origin v2.1.0-rc1` (the version must equal `xray_forge.__version__`;
   this creates a GitHub *pre-release*, not a release). Open the run in the Actions tab and wait for it.
2. Report per job (`Build ubuntu-24.04`, `Build windows-2022`, `Desktop app ...`, `Attach binaries ...`):
   green/red, duration, and for a red job the **exact** text of the failing step. Include the output of the
   step "Check the unpacked app (layout, license files, engine starts)" for both platforms.
3. Download the artifacts from the pre-release. Check each against its `.sha256` file
   (`sha256sum -c` / `Get-FileHash`). Report the file names and sizes.
4. **Windows:** run the installer (SmartScreen: More info -> Run anyway; it is unsigned). Report: installs?
   app starts? The About tab must show the version, "GPL-3.0" and an engine line ("engine v... . 3 cores").
   Click both About links once: each must open in your default browser (nothing opens inside the app).
   Uninstall and report whether anything is left in the install folder.
5. **Linux** (Ubuntu or WSL2 with WSLg): `chmod +x XrayForge-*.AppImage && ./XrayForge-*.AppImage`; if FUSE is
   missing use `--appimage-extract-and-run`. Report the first lines of output verbatim, including any
   sandbox error (Ubuntu 24.04+ AppArmor). Do **not** add `--no-sandbox` and report that it was needed instead.
6. Delete the pre-release and the tag afterwards only if the maintainer says so.

Never include secrets or signing keys in the report.

## What to send back

One message containing: Job 0 summary, the lock files, the report JSON files, the build/installer notes
(Job 7 for the release rehearsal), and the hand-testing list. The maintainer's assistant turns failures into fixes and tests.
