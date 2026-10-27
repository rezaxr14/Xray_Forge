# Xray Forge Roadmap

Status legend: ✅ done · 🟡 partial (what remains is listed) · ⬜ not started

Tracking issue-style notes live here; implementation lives on `main`.

---

## Sprint 0 — Correctness and security hardening ✅

Found by reviewing `feat/roadmap-v2-1`; each item was reproduced first and
ships with a regression test that fails on the old code.

- ✅ Health check: Stop actually stops the pool; empty fragmentation variants
  and core start failures become failed stages instead of crashes.
- ✅ TLS: DoH and direct fetches verify certificates (CERT_REQUIRED, IP SANs,
  certifi); direct HTTPS GET really sends its request; redirects and body
  size are bounded.
- ✅ Subscriptions: raw-text fetch, URL-safe base64, http(s) only, size cap;
  a 200 with no configs keeps the cache and ETag.
- ✅ Share links: lossless round trips (`extra_params`), `type` defaults to
  `tcp`, `raw`/`splithttp` aliases, VLESS `encryption` preserved.
- ✅ Cores: XHTTP/KCP are Xray-only; sing-box/Clash no longer export them as
  plain TCP.
- ✅ Throughput: upload POSTs >= 1 MiB and waits for the server; 2xx and
  >= 90% body required; a fresh session per direction.
- ✅ Secrets: WARP account, settings and MITM CA key are written 0600;
  CA validity 1 year, optional name constraints.
- ✅ Release workflow: signing secrets scoped to the signing step, `.sig`
  names match the upload globs, tag must equal the package version.

Still open from the review (next sprints):

- ⬜ ~~Split `app.py`~~ — superseded by Phase 7 (Tk GUI will be retired).
- ✅ Large scans and per-stage timeouts (step 7.6):
  - ✅ 6.1 `ScanSession.run` funnel: bounded in-flight window (`workers * 4`),
    a stop that cancels queued work instead of probing the whole list, IPs cut
    short by stop stay pending (they used to be recorded as "tcp filtered"),
    time-gated atomic state saves (were a full rewrite every 10 results),
    O(1) pending bookkeeping, separate `tcp_timeout` / `tls_timeout`,
    `tcp_retries`. Offline tests with fake probes only; no real large scan was
    run, and there is no separate TLS pool (threads only).
  - ✅ 6.2 Engine: `scan.run` `tcp_timeout` / `tls_timeout` / `tcp_retries` and
    validation of `timeout`; `health.run` / `sub.check` `timeouts`
    (`dns`, `tcp`, `tls`, `request`, `transfer`).
  - ✅ 6.3 UI: IP scanner "Timeouts and retries" (TCP/TLS timeout, TCP
    retries) and Health / Subscriptions-check "Stage timeouts" (DNS, TCP, TLS,
    Request, Transfer). Blank = engine default and nothing is sent; values are
    remembered via `ui.settings_*`. Verified by Playwright e2e against the real
    engine (what is sent, engine validation messages, restart); not exercised:
    a scan or check that actually hits a timeout on a real network.
- ✅ License: Apache-2.0 (relicensed; the sole author agreed). `LICENSE` is the official text,
  `NOTICE` and the package metadata agree (`tests/test_license.py`); release
  archives and installers ship both files.
- ⛔ SNI-spoofing helper: out of scope for this project's assistant-built work; not built.
- ✅ MASQUE (opt-in): `core/masque.py`, `masque.*` engine methods and
  `xray_forge masque config|check|probe`, driving the `sing-box-extended` fork
  with the schema from its own example. Gated by the binary's `check`; secrets
  are redacted by default and never taken from argv. Tested with a fake fork
  executable (config, gating, probe, cancel, redaction); **not** exercised: the
  real fork, Cloudflare enrollment, a live tunnel.
- ✅ Psiphon (bring your own): `core/psiphon.py`, `psiphon.*` engine methods and
  `xray_forge psiphon status|probe` run the user's `ConsoleClient` and their own
  Psiphon Labs config as a separate process, on a private rewritten config copy.
  Nothing from Psiphon is bundled or invented, so the project stays Apache-2.0
  (GPL-3.0 applies to their binary, not to this code). Tested with a fake client;
  **not** exercised: the real client or network. Whether to *bundle* the binary
  is the owner's licensing call (would need GPL source-offer terms for it).
- ✅ MASQUE DNS/interface defaults from a real-machine report: on a TUN/fake-IP
  setup the system resolver hands out 198.18.0.0/15 addresses and the core hangs, while DoH
  over an IP literal worked. New `dns` option (`auto` = DoH only when the resolver is
  fake-IP, `system`, `doh`); `route.auto_detect_interface` is now opt-in (`bind_interface`)
  because it broke HTTP/2 in the agent's runs (small sample: 0/3 vs 3/3). Fake-core test
  fixtures now work on Windows via `.cmd` wrappers (`tests/fakebin.py`), not yet run on Windows.
- ✅ **MASQUE / Psiphon tab** in the Electron UI: set/browse/clear the binary (and the Psiphon
  config), MASQUE options (HTTP/2, TCP-only, IPv6, DNS mode, interface binding, endpoint, SNI,
  profile id; remembered across restarts), redacted config view, and cancellable connection tests.
  Verified by Playwright e2e against the real engine with `/bin/sh` fake binaries (POSIX only);
  not exercised: the real fork/client, native dialogs in the packaged app. No token fields exist
  and Psiphon values are never displayed.
- ✅ **Electron main-process glue tested**: the logic moved from `main.js` into an injectable
  `electron/app-shell.js` (`main.js` is now thin wiring), tested with a fake `electron`
  (`test/app-shell.test.js`): window security options, navigation/window-open policy (https only),
  IPC argument validation, job forwarding, quit/activate order. New hardening: IPC accepted only from
  our own window's local page, all permission requests denied, webviews blocked, single-instance lock.
  `test/packaging-files.test.js` fails if a module loaded at startup is missing from `build.files`.
  Still **not** exercised: real Electron (windows, dialogs, installer), only the fake.
- ✅ **Field-report fixes** (first real-machine run, `docs/field-reports/2026-10-23/`): fake-IP detection
  probes the dialed host (split DNS), DoH order/`doh_servers` configurable, MASQUE auth token and license key
  fields (password inputs; sent, never saved or shown), IP-literal links pass the DNS stage, Windows python
  default, desktop version synced (2.1.0) and checked by `check_version.py`. Verified on that machine so far: unit/e2e
  suites (661 + 69), the frozen engine build and app launch, real dialogs, single-instance, permission denial,
  external links, scan+stop, MASQUE tab. **Not** achievable from that network: MASQUE registration, VLESS
  tests (Cloudflare endpoints filtered). Installer build blocked by Windows symlink rights (environmental).
- ✅ **In-app core downloads** (`core/cores/install.py`, `core.release` / `core.install`, Download buttons on the
  Cores and MASQUE tabs): official GitHub release only, https + GitHub hosts + checked redirects, the asset must sit under the
  core's official repo, GitHub's sha256 digest is required and verified, size caps, only known file names are written
  (archive paths ignored), nothing executed until the user confirms and the binary answers its version command. Tested with a
  fake fetcher and a mutation-checked policy; **not** exercised against live GitHub, so the asset-name rules
  (Xray-*, sing-box-*, mihomo-*) are unverified (see runbook Job 4b). Psiphon is not downloadable (no official standalone
  build was verified).
- ✅ **Real-release findings** (agent run on Windows, commit 981f8b5): downloads of xray v26.10.21, sing-box
  v1.14.4 and sing-box-extended v1.14.3-extended-2.7.3 installed and ran with matching digests (the asset-name
  rules are now verified for those three on Windows x64). mihomo failed because its zip member is
  `mihomo-windows-amd64.exe`: fixed (member pattern). The failed install had left its download behind
  because the archive stayed open (Windows can't delete it): archives are now closed first and stale `.dl-*`
  staging folders older than an hour are swept. Fake-IP detection also treats loopback (127.x, seen as 127.165.0.x)
  and 240.0.0.0/4 answers as fake. `LICENSE`/`NOTICE` are pinned to LF in `.gitattributes` and the license test
  tolerates CRLF checkouts. Psiphon detection also looks for `psiphon-tunnel-core`. Linux/macOS asset names for
  all four cores remain unverified.
- ✅ `tools/live_check.py` + `docs/local-agent-runbook.md`: a redacted JSON report
  for env / masque / psiphon / vless throughput / warp-scan, and the jobs a local
  agent runs (locks, live checks, desktop build, shell hand-test). Offline tests
  cover the report shape, redaction and that every runbook command parses.
- ✅ Structured logging (`core/log.py`, CLI `-v`, GUI log file); silent
  state-corruption resets now log a warning.
- ⬜ Pin third-party Actions by commit SHA (needs a maintainer to look up
  the SHAs).
- ⬜ Validate the throughput probe against a live VLESS server;
  `speed.cloudflare.com:80` may redirect, in which case the stage fails
  loudly rather than reporting a speed.

---

## Phase 7 — Electron UI 🟡

Decision: keep the Python `core/` as the engine and replace Tk with an
Electron front end that talks to it over JSON-RPC on stdio (no network port).
See `docs/engine-api.md`.

- ✅ Step 1: engine API (`xray-forge serve`): parse/render/convert/export/
  dedup, subscription sources, streamed + cancellable health-check jobs.
- ✅ Step 2: `electron/` shell (contextIsolation, sandbox, CSP, no
  innerHTML) with Configs (+ editor, export), Convert, Health check and
  Subscriptions tabs. Playwright e2e tests drive the real renderer against
  the real engine (`cd electron && npm test`; CI job `ui`).
  Not covered by tests: the ~40-line `main.js`/`preload.js` glue (needs the
  Electron binary).
- ✅ Step 3: IP scanner, SNI search, WARP and MITM-fronting tabs with their
  engine methods (streamed, cancellable jobs; saved sessions; resume).
  Verified offline with fakes in Python tests and, in the browser, against a
  closed local port; live WARP registration/scan and a real alive-host scan
  are not exercised by CI.
- 🟡 Step 4: packaging. Written: engine resolver (`electron/engine-path.js`),
  electron-builder config, PyInstaller one-folder engine, release workflow
  `desktop` job (Windows installer, Linux AppImage, checksums, optional GPG),
  `tools/smoke_engine.py` gate, `tools/check_version.py`; see
  `docs/packaging.md`. `docs/packaging.md` records a green real-runner build
  (run 39136895263, head 8efd63e); the installers were never launched by a
  human and are unsigned.
  - ✅ 4.1 Hardening (static + dry-run only; **not** run on a runner): all
    actions pinned by commit SHA, read-only workflow token with
    `contents: write` on the `release` job only, 15-min timeout on it,
    `npm ci` in the desktop job; `tools/check_workflows.py` +
    `tests/test_workflow_policy.py` enforce those rules and the
    release.yml/electron-builder/lock-file consistency;
    `tests/test_release_dryrun.py` runs release.yml's shell steps under bash
    (packaging, checksums, GPG signing, version choice).
  - ✅ 4.3 App icons (`electron/assets`, generator `tools/make_icons.py`) wired
    into electron-builder and the window; unverified in a real installer.
  - 🟡 4.2 Python lock files: generated on the maintainer's machine and committed;
    `ci.yml` / `release.yml` now install with `pip install --require-hashes -r
    requirements-ci.lock` (project: `--no-deps --no-build-isolation -e .`, pip cache keyed
    on the lock). `tools/check_workflows.py` makes any other `pip install` an error and
    checks the locks against `requirements.txt` / `requirements-ci.in` (hashes present,
    versions satisfy the specifiers, both locks agree). **Not yet run on a real runner
    or with real PyPI**: runbook Job 1b (fresh venv on Windows py3.10/3.12/3.13) first,
    then the first CI run.
- ✅ Cores tab: detect xray/sing-box/mihomo (saved path, env, v2rayN, ./bin, PATH), set/clear path; `health.run` explains a missing core.
- ✅ Step 5: reach parity with the Tk GUI, then retire it (`app.py`, `ui/`,
  GUI tests, CI steps). In order:
  - ✅ 5.1 Converter rules UI: mode (full / IP only / custom), fp/cs/fm
    switches and values, only-TLS, rename + template + start #, FORCE IP /
    PORT with live validation, names list + copy names / config / output,
    tag `[CC]` (Health tab, from the exit country a core reports).
    Verified by Python tests and Playwright e2e against the real engine; the
    `[CC]` button is e2e-tested with simulated rows because no proxy core runs
    in CI.
  - ✅ 5.2 Fuller config editor: grouped form (basic / transport / security /
    reality·vmess·cs) with xhttp mode, header_type, allowInsecure, reality
    keys, VMess scy/alterId, SS method; fields that do not apply to the link
    are greyed out and keep their value; raw JSON pane (form → JSON,
    JSON → form via `config.from_json`); Copy link; unmodelled link params
    (`extra_params`) survive every edit. Payloads are now validated by the
    engine. Also fixed: the 5.1 copy fallback used an inline style that the
    renderer CSP blocks (now covered by a test).
  - ✅ 5.3 IP-finder extras: `net.resolve` (DNS answers per resolver) and
    `net.geo` (geo/ISP, my IP) with a Lookup panel on the IP scanner tab;
    select a scan row, resolve answer or SNI hit to copy its IP (double-click)
    or use it as FORCE IP in the converter. Engine side is unit-tested with
    faked network; the UI is e2e-tested with those two engine calls stubbed, so
    **no real geo provider or resolver was contacted by any test**.
    Also fixed: automatic scan/SNI session names had one-second resolution, so
    two runs started within a second shared a session and the second failed
    with "no scannable IPs" (found as a flaky e2e test; now unique, with a
    regression test).
  - ✅ 5.4 Subscriptions: best-N export, check-all-sources. `sub.check` runs the
    health pipeline over the cached configs of all enabled sources inside the
    engine; `health.export_best` / `health.tagged` use the engine's own scores
    (the last 4 runs are kept). Core fixes found on the way, which also change
    the Tk GUI and the CLI: best-N used to take the top N *then* drop failures
    (so it could return fewer than N, or none); technique tags were appended
    inside the URL query and corrupted links -- they now go into the name
    (VMess: the `ps` field). Tests: Python + 2 e2e (the export/tag UI test stubs
    only those two engine methods, since CI has no reachable working server).
  - ✅ 5.5 File open/save dialogs, settings persistence. Native dialogs run in
    the Electron main process (`electron/files.js`; the renderer names a file
    *kind*, never a path or dialog filter; saves are owner-only, opens capped at
    8 MB): open links (Configs, Convert), save Convert output / export
    (YAML/JSON/TXT) / best-N subscription / scan and SNI CSV, browse for a core
    binary. Form values (convert rules, health/check options, scan, SNI, WARP,
    MITM) persist through `ui.settings_get/set` to `~/.xray_forge/ui_settings.json`
    (pasted links and results are deliberately not saved). `files.js` is unit
    tested and exercised end to end through the renderer with a scripted dialog;
    the three `ipcMain.handle` lines in `main.js` and the real native dialog
    windows are **not** exercised (no Electron binary here). Also fixed a 1-in-70
    flaky scan test of mine (re-sampling the same /29 could leave no fresh IPs).
  - ✅ 5.6 Retire the Tk GUI. Parity audit first (5.6a): added fragment spec on
    scan/SNI (validated by the engine), range presets, JSON export, result
    clearing, Retest selected / Copy link. Then removed `app.py`, `ui/`,
    `tests/test_gui.py`, the screenshots, the dead `core/prober_utils.py`, and the
    Tk/xvfb/GUI steps in CI. `python -m xray_forge gui` now exits 2 with a pointer
    to the desktop app; no subcommand prints help (it used to open a window).
    Also fixed: `python -m xray_forge` dropped main()'s exit code (always 0).
    **Not ported at the time** (Tk-only manual knobs of the legacy tester, which
    the staged health pipeline supersedes by trying fragment variants itself):
    free-form fragment string, fake SNI, domain-front header, TLS record
    fragmentation / ClientHello padding toggles, the xray-only "via core" test with
    its fragment switch, and the ★ best marker (health is sorted by score). The
    library code behind them (`core/probe.py`) is still there if they are wanted
    as `health.run` options.
  - ✅ 5.7 Tester knobs ported after all: `health.run` / `sub.check` take
    `fake_sni`, `front_host`, `record_frag`, `pad_hello` and `frag_variants`
    (validated; `core.healthcheck.TlsOptions`), carried through the TLS,
    request and throughput stages; UI under "Anti-DPI options" on the Health
    tab and the Subscriptions check panel (remembered between runs). Still not
    ported: the xray-only "via core" fragment switch (use `--core`) and the ★
    marker. Native probes only: core-backed checks build their own TLS.

---

## Phase 0 — Foundation ✅

Goal: a trustworthy base the rest of the plan can build on.

- ✅ Real CI matrix: ubuntu + windows × Python 3.10/3.12/3.13, bash shell
  everywhere (PowerShell can't expand globs / heredocs), compile + ruff
  (E9,F63,F7,F82) + full pytest run + headless CLI smoke + xvfb GUI smoke.
- ✅ `from __future__ import annotations` everywhere + `requires-python >= 3.10`
  (the codebase uses PEP-604 unions at runtime).
- ✅ Headless CLI: `cli.py` never imports tkinter; GUI imports are lazy.
- ✅ Typed `Outbound` model (`core/models.py`) replaces the `parse_target`
  dict, with legacy `t["uuid"]`-style access kept working.
- ✅ README CLI section documents the actual subcommands (was drifted).
- ✅ Reality export fixed: `pbk`/`sid` are parsed and written to Clash
  `reality-opts` and sing-box `reality` (used to emit empty strings →
  broken configs). Regression-tested in golden tests.
- ✅ PyYAML declared as a real dependency (Clash export used to
  silently rely on it being installed).

## Phase 1 — Protocol model + core abstraction ✅

Goal: one config model, many protocols, many cores; capabilities derived
from code, never hard-coded.

- ✅ Protocol registry (`core/protocols/`): VLESS, VMess (base64 + plain),
  Trojan, Shadowsocks (SIP002 + legacy), Hysteria2, TUIC, WireGuard/WARP —
  each with parse, `to_uri`, and per-core renderers.
- ✅ Core adapters (`core/cores/`): Xray-core, sing-box, Mihomo — each
  builds full client configs (socks inbound + outbounds) and reports which
  protocols it can actually run (`supported_protocols()` derived from
  renderers).
- ✅ Stream settings builder shared across protocols (ws / grpc /
  httpupgrade / tcp / **xhttp**, TLS/Reality with fingerprint, alpn,
  cipherSuites, spiderX, flow, front-domain override).
- ✅ `xray_bridge` kept as a compat façade; old call-sites unchanged.
- ✅ GUI **✎ Editor** tab: pick any output config and edit its fields —
  Reality (pbk / sid / spx), XHTTP (`type` + `mode`), flow, fp/alpn/cs,
  transport, security — plus a raw-JSON pane that round-trips through
  `Outbound.from_dict` (extra protocol params included). "apply" regenerates
  the share link via the protocol handler and rewrites that output line,
  the names list and the tester targets. Round-trip fidelity fixes that
  fell out of it: `headerType` / `allowInsecure` are parsed again (query
  keys are lowercased — they were silently dropped) and `mode=` / those
  params survive `to_uri` for vless + trojan.

## Phase 2 — patterniha-style techniques 🟡

- ✅ **MITM-DomainFronting generator** (`core/domainfront.py`): builds the
  Xray-core ≥ 26.2.6 config (tunnel inbounds with `usage: issue`
  personal-CA certificates, `tls-repack-*` outbounds with
  `verifyPeerCertByName: "fromMitM"`, fakedns, happy-eyeballs, service
  groups google/meta/fastly, DoH repack), optional per-user CA generation
  (`cryptography`) with openssl fallback, and Windows/Android/Firefox
  setup guides. Re-implemented from public documentation — no GPL code.
  `xray_forge mitm --gen-cert --guide`.
- ✅ **PattN/PattNG editor fields**: `unsafe` fingerprint and
  `cipherSuites` (`cs=`) flow through the model, share links and exports.
- ⬜ **Non-encrypted VLESS/Trojan "public-address" mode**: needs a written
  spec or documentation of the exact config and core support. Not started;
  reading GPL-3.0 upstream sources would require relicensing first (decision
  for the owner, not needed for anything built so far).
- ⛔ **SNI-Spoofing (raw TCP fake packets)**: not built here (out of scope).

## Phase 3 — Subscription pipeline ✅

Goal: test subscriptions **on the user's own network** — a CI-published
list can't know what works from inside Iran, and upload-throttled networks
pass latency checks while being unusable.

- ✅ Source manager (`core/sub_source.py`): URL list, ETag conditional
  requests, cache under `~/.xray_forge/cache/`, format auto-detection
  (base64 / plain / Clash YAML / sing-box JSON / raw GitHub), cross-source
  de-duplication, persisted state.
- ✅ Staged health checks (`core/healthcheck.py`):
  DNS (DoH) → TCP (latency+jitter) → TLS with **fragmentation variants**
  (winning variant recorded as a technique tag) → real request through the
  tunnel → **download + upload throughput** (the upload-throttle case).
- ✅ Ranking + outputs: 0-100 score with stage weights, best-N base64
  subscription export, technique-tagged lines (`name [fragment:5,94,1@2]`).
  `xray_forge subs add|list|fetch|check --top N --out sub.txt`.
- ✅ GUI "Subscriptions" tab: source management (add/remove/enable), fetch-all,
  ranked results with score / request latency / down+up throughput /
  technique tags, best-N subscription export, "send working → Configs tab".
- ✅ Core-backed stages: the request/throughput pipeline falls back to a
  locally spawned core (`--core auto|xray|singbox|mihomo`) through its SOCKS
  inbound, so trojan / vmess / ss / hysteria2 / tuic / wireguard configs get
  full checks too (native VLESS/WS tunnel remains the fast path).

## Phase 4 — Scanner upgrades 🟡

- ✅ Resumable scan sessions (`core/scan_session.py`): state files under
  `~/.xray_forge/scans/`, stop/resume across processes, batched saves.
- ✅ Latency + jitter measurement, optional country/ISP tagging per result.
- ✅ CSV/JSON export, per-ISP grouping, known-ranges additions (Fastly).
- ✅ CLI: `xray_forge scan CIDR --resume NAME --csv out.csv --json out.json --geo`.
- ✅ GUI: IP Finder runs named resumable sessions (shared state with the CLI
  under `~/.xray_forge/scans/`), with load/⟳, geo-tag toggle and CSV/JSON
  export buttons; results tree shows jitter + exit country.
- ✅ SNI / fronting-host search mode: probe candidate SNIs (built-in preset
  list or custom) against clean IPs — fragmented TLS handshake + optional
  plain-GET check per (ip, sni) pair. Resumable sessions under
  `~/.xray_forge/sni_search/`, CSV/JSON export, `--from-scan` reuses alive
  IPs of a saved scan session. CLI `xray_forge snisearch`; GUI "🎯 SNI
  Search" tab with ⤴ from-results / presets / stop / copy ip+sni.

## Phase 5 — New cores and transports 🟡

- ✅ **WireGuard / WARP** (`core/warp.py`): pure-python RFC 7748 X25519
  (validated against RFC vectors), device registration via the Cloudflare
  client API, account persistence, endpoint heuristics scan, and outbound
  rendering for Xray / sing-box / Mihomo (incl. `reserved` from client_id).
  `xray_forge warp register|config|scan-endpoints`.
- ✅ **MASQUE** (opt-in, via the `sing-box-extended` fork): see Phase 4 notes;
  needs a real-fork live check by the user.
- ⬜ **Psiphon**: a separate core (subprocess behind `CoreAdapter`), needs
  binary shipping/licensing decisions. Scope last.

## Phase 6 — Quality 🟡

- ✅ Test suite: 137 tests — per-protocol fixtures + round-trips, core
  capability/client-config tests, golden export structure tests,
  subscription pipeline (ETag/cache/dedup), staged health-check pipeline
  (offline, monkeypatched; incl. core-backed stages), scan sessions
  (resume/export), WARP RFC 7748 vectors, MITM-DF structure, seeded
  URI-parser fuzzing, CLI end-to-end, GUI interaction tests (incl. the
  per-config Editor: Reality fields, JSON round-trip, xhttp mode).
- ✅ Release workflow (`.github/workflows/release.yml`): on `v*` tags, runs
  tests, builds Windows/Linux single-file executables with PyInstaller,
  generates SHA-256 checksums, attaches to a GitHub Release.
- 🟡 Signed releases: GPG detached signatures of the `.sha256` files are
  produced by the workflow **when** repo secrets `GPG_PRIVATE_KEY`
  (+ optional `GPG_PASSPHRASE`) are configured; checksums exist either way.
- ✅ Coverage report: CI runs pytest with `--cov=xray_forge`
  (term-missing + `coverage.xml` artifact, ubuntu/py3.12) and README has a
  CI badge.
- ✅ GUI test harness: `tests/test_gui.py` drives the real App headlessly
  (module-scoped root, xvfb-run on Linux CI) — tabs, converter round-trip,
  tester rows, subscriptions lists, scan-session load.

---

## Risks / decisions to keep in view

- **Licensing**: patterniha repos are GPL-3.0; Xray Forge is Apache-2.0.
  Everything from those projects is re-implemented from documented behavior
  (`AGENTS.md` → Licensing constraints). If GPL code is ever required, the
  project must relicense first.
- **External-core features** (MASQUE, Psiphon) depend on cores that may not
  support them yet — verify upstream before designing.
- **WARP API is undocumented** and can change without notice; registration
  errors are surfaced, never swallowed.
- **SNI-spoofing** needs raw-socket privileges and is best delivered as a
  separate helper binary — do not absorb it into the app process.
