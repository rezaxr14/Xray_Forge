# ⚡ Xray Forge (Modular Edition)

[![CI](https://github.com/rezaxr14/Xray_Forge/actions/workflows/ci.yml/badge.svg)](https://github.com/rezaxr14/Xray_Forge/actions/workflows/ci.yml)

A full-featured, modular Python utility for managing, fixing, testing, and exporting **VLESS / VMess / Trojan / Shadowsocks / Hysteria2 / TUIC / WireGuard-WARP** proxy configurations — with DPI-resistant probing, real core integration (Xray-core / sing-box / Mihomo), exit-country analytics, resumable IP scanning, a staged subscription health-check pipeline, and multi-format export.

> 🇮🇷 Designed with anti-DPI and censorship-resistance in mind: fragmented ClientHello probes, fake SNI, domain fronting, a local MITM-DomainFronting generator, DoH-over-IP DNS, and real-tunnel exit-IP detection.

---

## 📦 Project Structure

```
Xray_Forge/
├── Xray_Forge.py             # root launcher (CLI) → xray_forge.cli:main
├── electron/                 # desktop app (Electron UI over the engine, JSON-RPC on stdio)
├── AGENTS.md                 # instructions for AI agents / contributors
├── ROADMAP.md                # phased plan + status
├── pyproject.toml            # pip-installable package config (py ≥ 3.10)
├── requirements.txt          # dependencies (curl_cffi, PyYAML)
├── .github/workflows/        # ci.yml (test matrix) · release.yml (exe builds)
└── xray_forge/               # Modular Python package
    ├── __main__.py           # Entry point: `python -m xray_forge`
    ├── cli.py                # Headless CLI (subcommands)
    ├── engine/               # JSON-RPC engine API used by the desktop app (`serve`)
    ├── core/
    │   ├── models.py         # Outbound dataclass — the config representation
    │   ├── config.py         # Constants, fingerprints, ranges, presets
    │   ├── parser.py         # URI fixing, naming engine, exporters (Clash/Sing-box/sub)
    │   ├── protocols/        # Protocol registry: vless, vmess, trojan, ss,
    │   │                     #   hysteria2, tuic, wireguard (+ share-link builders)
    │   ├── cores/            # Core adapters: Xray-core, sing-box, Mihomo
    │   ├── xray_bridge.py    # Backwards-compatible Xray bridge
    │   ├── probe.py          # DPI-resistant TLS, WebSocket, VLESS tunnel, DoH
    │   ├── socks.py          # SOCKS5 client + HTTP-through-socks
    │   ├── scanner.py        # DNS resolution, GeoIP, CIDR sampling, jitter
    │   ├── scan_session.py   # Resumable scan sessions (CSV/JSON, per-ISP)
    │   ├── sni_search.py    # SNI / fronting-host search (candidates × clean IPs)
    │   ├── subscription.py   # Sub fetch + multi-format decode (b64/Clash/sing-box)
    │   ├── sub_source.py     # Subscription source manager (ETag cache, dedup)
    │   ├── healthcheck.py    # Staged pipeline: dns→tcp→tls→request→throughput
    │   ├── domainfront.py    # MITM-DomainFronting config generator + CA tools
    │   ├── warp.py           # WARP accounts, X25519, endpoint scanning
    │   ├── settings.py       # Settings + per-user data dir (~/.xray_forge)
    │   └── dedup.py          # Config deduplication
```

---

## 🚀 Installation

```bash
# Clone or extract, then:
pip install -r requirements.txt

# Use the CLI
python -m xray_forge --help

# Desktop app (Electron; needs Node 22+)
cd electron && npm install && npm start
```

Install as a package (adds the `xray-forge` command):

```bash
pip install .
xray-forge --help
```

Optional extras:

```bash
pip install ".[mitm]"     # cryptography, for MITM-DomainFronting CA generation
```

---

## 🖥️ Desktop app

The UI is an Electron app (`electron/`) that talks to the Python engine
(`python -m xray_forge serve`, see `docs/engine-api.md`); release builds bundle
the engine. The old Tkinter GUI has been retired.

| Tab | Purpose |
|-----|---------|
| **Configs** | Paste or open links → table with the editor (Reality, XHTTP, headers, raw JSON round-trip), dedup, export to Clash / sing-box / subscription |
| **Convert** | Live rules: fingerprint / cipher / fragment injection, renaming templates, forced IP / port, duplicate removal |
| **Health** | Staged checks with scoring, technique tags, `[CC]` exit-country tags, retest selected rows |
| **Subscriptions** | Source manager, check all sources, best-N export, tagged lines |
| **IP scanner** | Geo / DNS lookup, resumable CIDR scans (range presets, fragment spec), CSV/JSON export |
| **SNI search** | (ip, sni) pairs your network lets through |
| **WARP · MITM · Cores** | WARP device and config, MITM-DomainFronting generator, proxy-core detection |

### 5. Real Core Bridge (probe through actual engines)
- Auto-detects `xray` from v2rayN, PATH, env `XRAY_CORE`
- Generic SOCKS probe runner shared by Xray / sing-box / Mihomo adapters
- Spawns the real engine, tests through its local SOCKS, reports exit IP + country

### 6. IP Finder & Scanner (resumable sessions)
- CIDR sampling (Cloudflare **and Fastly** ranges built in) with configurable count/workers
- Latency **and jitter** measurement; SNI modes: config SNI / no SNI / custom
- **Scan sessions** persist to `~/.xray_forge/scans/` — stop and resume later, even from a new process
- CSV/JSON export and per-ISP grouping for comparing scans over time
- Anti-hijack DNS: DoH (1.1.1.1, 8.8.8.8, shecan, 403) + Iranian UDP resolvers + system DNS
- One-click "use as FORCE IP" from scan results (desktop app)

### 7. Subscription Pipeline (test on YOUR network)
- **Source manager:** any number of subscription URLs with ETag-based caching, auto-detection of base64 / plain text / **Clash YAML** / **sing-box JSON**, and de-duplication across sources
- **Staged health checks:** DNS (DoH) → TCP (latency + jitter) → TLS with **fragmentation variants** (the working variant is tagged) → real request through the tunnel → **download + upload throughput**; protocols the native tunnel can't run (trojan, vmess, hysteria2, tuic, wireguard…) are checked through a locally spawned core (`--core auto`)
- Why throughput: many Iranian networks throttle upload to foreign IPs — a config that passes a latency check can still be unusable; testing runs locally, on your own connection
- **Ranking & output:** 0–100 score per config, best-N base64 subscription export, technique-tagged names (`name [fragment:5,94,1@2]`)

### 8. WireGuard / WARP
- Device registration via Cloudflare's client API (pure-python RFC 7748 X25519 — no heavy crypto dependency)
- Config generation for Xray / sing-box / Mihomo (incl. the WARP `reserved` field)
- Heuristic WARP endpoint scanning (UDP reachability across known ranges/ports)

### 9. Multi-Format Export
- **Clash Meta (Mihomo) YAML** — proxies section ready for Clash/Mihomo, with correct Reality options
- **Sing-box JSON** — outbounds with TLS/uTLS/Reality/transport
- **Base64 subscription** — standard `sub://` compatible link

### 10. Deduplication · Filtering · Best-Config Marking · Settings Persistence
- Duplicate removal (scheme + credential + host + port); the desktop app remembers its form values between runs

---

## 🧪 Development

```bash
pip install -r requirements.txt -r <(echo pytest; echo ruff)   # or: pip install ".[dev]"
python -m pytest tests -q          # 107 offline tests (network probes monkeypatched)
ruff check --select E9,F63,F7,F82 .
```

See [`AGENTS.md`](AGENTS.md) for the full contributor/agent handbook and
[`ROADMAP.md`](ROADMAP.md) for the phased plan and current status.

Releases are built automatically: pushing a `v*` tag runs the test suite,
builds Windows/Linux single-file executables with PyInstaller, and attaches
them (with SHA-256 checksums) to a GitHub Release.

---

## 📄 License

Xray Forge is licensed under the **Apache License, Version 2.0**.

You may use, modify and distribute it, including commercially, as long as you
keep the license and the [`NOTICE`](NOTICE) file, state significant changes, and
do not use the project's name to endorse derived products. The license also
grants a patent license from contributors.

See [`LICENSE`](LICENSE) for the full legal text.

---

## ⚠️ Disclaimer

This tool is for educational and network-diagnostic purposes. Users are responsible for complying with their local laws and regulations regarding proxy/circumvention software. The authors are not responsible for any misuse.

## Electron UI (preview)

The new front end lives in `electron/` and drives the Python engine over
stdio (`python -m xray_forge serve`, protocol in `docs/engine-api.md`).

```bash
cd electron
npm install
npm start          # needs python3 with this package's requirements on PATH
npm test           # Playwright e2e (npm i --no-save playwright first)
```

Set `XRAY_FORGE_PYTHON` to use a specific interpreter.
