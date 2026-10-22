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
public package names and hashes). Do not edit the workflows; the maintainer switches them to
`pip install --require-hashes -r requirements-ci.lock` afterwards.

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

Report: a short list of what worked and what did not, with the exact visible error text.

## What to send back

One message containing: Job 0 summary, the lock files, the report JSON files, the build/installer notes,
and the hand-testing list. The maintainer's assistant turns failures into fixes and tests.
