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

- ⬜ Split `app.py` (~1.2k lines) into per-tab modules; add structured logging.
- ⬜ Async/pooled funnel for large scans; per-stage timeouts in settings.
- ⬜ License decision (CC BY 4.0 is unusual for software) before the next
  release.
- ⬜ SNI-spoofing helper binary (separate process, raw sockets).
- ⬜ MASQUE and Psiphon spikes: verify upstream core support first.
- ⬜ Pin third-party Actions by commit SHA (needs a maintainer to look up
  the SHAs).
- ⬜ Validate the throughput probe against a live VLESS server;
  `speed.cloudflare.com:80` may redirect, in which case the stage fails
  loudly rather than reporting a speed.

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
- ⬜ **Non-encrypted VLESS/Trojan "public-address" mode**: verify the
  exact config + core support in patched Xray-core sources before building.
- ⬜ **SNI-Spoofing (raw TCP fake packets)**: needs raw sockets/WinDivert +
  admin rights. Design as a separate helper process the app launches, not
  in-app code. Read upstream `injecter.py` / `fake_tcp.py` before designing.

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
- ⬜ **MASQUE**: needs a core that actually supports it — verify current
  sing-box/Xray support before designing anything.
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

- **Licensing**: patterniha repos are GPL-3.0; Xray Forge is CC BY 4.0.
  Everything from those projects is re-implemented from documented behavior
  (`AGENTS.md` → Licensing constraints). If GPL code is ever required, the
  project must relicense first.
- **External-core features** (MASQUE, Psiphon) depend on cores that may not
  support them yet — verify upstream before designing.
- **WARP API is undocumented** and can change without notice; registration
  errors are surfaced, never swallowed.
- **SNI-spoofing** needs raw-socket privileges and is best delivered as a
  separate helper binary — do not absorb it into the app process.
