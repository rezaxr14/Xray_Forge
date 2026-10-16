# ⚡ Xray Forge (Modular Edition)

A full-featured, modular Python utility for managing, fixing, testing, and exporting **VLESS / Trojan / VMess / Shadowsocks** proxy configurations — with DPI-resistant probing, real Xray-core integration, exit-country analytics, IP scanning, and multi-format export.

> 🇮🇷 Designed with anti-DPI and censorship-resistance in mind: fragmented ClientHello probes, DoH-over-IP DNS, and real-tunnel exit-IP detection.

---

## 📦 Project Structure

```
Xray_Forge/
├── pyproject.toml          # pip-installable package config
├── requirements.txt        # Python dependencies
├── README.md               # This file
├── LICENSE                 # CC BY 4.0
├── .gitignore              # Git ignore rules
├── .gitattributes          # Git line-ending rules
├── Xray_Forge.py           # Original single-file version (preserved)
└── xray_forge/             # Modular Python package
    ├── __main__.py         # Entry point: `python -m xray_forge`
    ├── app.py              # Main App: GUI + CLI + all logic wiring
    ├── core/
    │   ├── __init__.py
    │   ├── config.py       # Constants, fingerprints, defaults, ranges
    │   ├── parser.py       # URI fixing, naming engine, exporters (Clash/Sing-box/sub)
    │   ├── probe.py        # DPI-resistant TLS, WebSocket, VLESS tunnel, DoH
    │   ├── scanner.py      # CIDR scanner, DNS resolution, GeoIP
    │   ├── xray_bridge.py  # Xray-core SOCKS5 runner, config builder
    │   ├── settings.py     # GUI settings persistence (JSON)
    │   ├── subscription.py # Remote subscription fetch + base64 decode
    │   ├── dedup.py        # Config deduplication
    │   └── prober_utils.py # Shared formatting helpers
    └── ui/
        ├── __init__.py
        ├── widgets.py      # Tooltip, animated Switch toggle
        └── tabs/
            ├── __init__.py
            ├── converter_tab.py   # Fix / rename / mass-override UI
            ├── tester_tab.py      # Fragmented probe + exit-country UI
            ├── xray_tab.py        # Core detection + real-engine testing UI
            └── scanner_tab.py     # IP Finder / CIDR scan UI
```

---

## 🚀 Installation

```bash
# Clone or extract, then:
pip install -r requirements.txt

# Run the GUI
python -m xray_forge

# Or use the CLI
python -m xray_forge --help
```

Install as a package (adds `xray-forge` command):

```bash
pip install .
xray-forge --help
```

---

## 🖥️ GUI Tabs

| Tab | Purpose |
|-----|---------|
| **⚙ Configs** | Paste raw configs → live-convert with fingerprint/cipher/fragment injection, renaming, and mass IP/port override |
| **📡 Tester** | Fragmented TLS + WebSocket 101 + REAL delay through tunnel + exit-country detection |
| **🧩 Xray Core** | Auto-detect/verify `xray.exe` (v2rayN, PATH, etc.) and test configs through the real engine via local SOCKS |
| **🌐 IP Finder** | Geo lookup, anti-hijack DNS resolution (DoH + Iranian UDP + system), CIDR scanning with fragmented probes |

## 📸 Screenshots

| Converter (fix · rename · mass override) | Tester (fragmented TLS · ws 101 · exit country) |
|---|---|
| ![Converter](screenshots/01_converter.png) | ![Tester](screenshots/02_tester.png) |
| Xray Core (real engine via local SOCKS) | IP Finder (geo · DNS resolve · CIDR scan) |
| ![Xray Core](screenshots/03_xray_core.png) | ![IP Finder](screenshots/04_ip_finder.png) |

---

## 🔧 CLI Usage

```bash
# Convert & fix configs
python -m xray_forge in.txt out.txt --fp chrome --ip 1.2.3.4 --port 443

# IP-only mode (no injection)
python -m xray_forge in.txt out.txt --ip-only

# Test configs through real Xray-core
python -m xray_forge in.txt --test --core /path/to/xray.exe

# Export to Clash Meta YAML
python -m xray_forge in.txt --export-clash clash.yaml

# Export to Sing-box JSON
python -m xray_forge in.txt --export-singbox singbox.json

# Export to base64 subscription
python -m xray_forge in.txt --export-sub sub.txt

# Scan a CIDR for alive TLS IPs
python -m xray_forge --scan 104.16.0.0/13 --sni edgestuff.pages.dev --count 200

# Geo-lookup an IP
python -m xray_forge --geo 1.1.1.1
```

### CLI Options

| Option | Description |
|--------|-------------|
| `--ip` | Force endpoint IP/domain on every config |
| `--port` | Force endpoint port on every config |
| `--fp` | Fingerprint value (default: `chrome`) |
| `--template` | Naming template (default: `{id:02d}_{sub}_{path}`) |
| `--start` | Starting index for names |
| `--no-rename` | Keep original config names |
| `--ip-only` | Inject nothing — only override/rename |
| `--no-fp / --no-cs / --no-fm` | Skip fingerprint / ciphers / fragment mask |
| `--all-security` | Also touch non-TLS configs |
| `--test` | Live-test every config after converting |
| `--core` | Path to xray core for real-engine testing |
| `--frag` | ClientHello fragment spec (default: `5,94,1@2`) |
| `--no-real` | Skip VLESS real-delay stage |
| `--no-cc` | Skip exit-country detection |
| `--scan CIDR` | Scan a CIDR range for alive IPs |
| `--count` | Number of IPs to sample from CIDR |
| `--sni` | SNI to use during scan |
| `--no-sni` | Scan with empty SNI (raw IP aliveness) |
| `--sport` | Scan port (default: 443) |
| `--workers` | Parallel workers |
| `--timeout` | Connection timeout in seconds |
| `--geo IP` | Geo-lookup an IP (empty = your own IP) |
| `--export-clash FILE` | Export to Clash Meta YAML |
| `--export-singbox FILE` | Export to Sing-box JSON |
| `--export-sub FILE` | Export to base64 subscription |

---

## ✨ Key Features

### 1. Config Conversion & Fixing
- **Three modes:** Full fix (fp + cs + fm), IP-only, Custom
- **Expanded uTLS fingerprints:** chrome, firefox, safari, edge, ios, android, opera, brave, vivaldi, qq, sogou, random, randomized, unsafe
- **Cipher suite injection** (`cs=`) with customizable lists
- **Fragment mask injection** (`fm=`) for DPI-resistant ClientHello
- **Smart naming engine** with template keys: `{id}`, `{sub}`, `{path}`, `{ip}`, `{port}`, `{host}`, `{net}`, `{sni}`, `{proto}`, `{old}`
- **Mass endpoint override** — force one IP:port on every config
- **Live auto-convert** as you type/paste

### 2. Transport Protocol Support
- **WebSocket (ws)** with path + Host header
- **gRPC (grpc)** with service name
- **HTTPUpgrade** with path + host
- **Trojan** password-based configs
- **Reality** support with serverName and fingerprint

### 3. DPI-Resistant Testing (heavy censorship)
- Fragmented ClientHello (same as `fm=` mask) — `5,94,1@2` / random presets
- **Fake / decoy Client Hello** with benign SNI (MMDF "instant certificate" style, patterniha)
- **TLS record-layer fragmentation** — split SNI extension across records
- **Domain fronting** — connect to a front domain, request the real host inside the tunnel
- **SNI case mixing**, TLS padding, noise packets, TCP Fast Open, User-Agent rotation
- TCP ping + TLS handshake + WebSocket 101 upgrade
- REAL delay measurement through the tunnel
- Exit-country detection via geo APIs tunneled through the proxy
- Edge-IP country fallback (marked `*`)

### 4. Real Xray-Core Bridge
- Auto-detects `xray.exe` from v2rayN, PATH, env `XRAY_CORE`
- Spawns real Xray-core processes with local SOCKS5
- Tests through the actual engine — works for Trojan and odd UUIDs
- Reports exit IP + country through the tunnel

### 5. IP Finder & Scanner
- CIDR sampling with configurable count/workers
- Fragmented TLS probes (keep ON in Iran)
- SNI modes: config SNI / no SNI / custom
- Optional `curl_cffi` browser-impersonation hello
- Anti-hijack DNS: DoH (1.1.1.1, 8.8.8.8, shecan, 403) + Iranian UDP resolvers + system DNS
- One-click "use as FORCE IP" from scan results

### 6. Multi-Format Export
- **Clash Meta (Mihomo) YAML** — proxies section ready for Clash/Mihomo
- **Sing-box JSON** — outbounds format with TLS/uTLS/transport
- **Base64 subscription** — standard `sub://` compatible link

### 7. Remote Subscription Import
- Paste a subscription URL in the GUI → Fetch → configs appended to input
- Auto-detects base64-encoded vs plain-text subscriptions

### 8. Deduplication
- Removes duplicate configs (same scheme + UUID + host + port)
- Available as a button and as "auto-dedupe on convert"

### 9. Filtering & Best-Config Marking
- Text filter on the tester list (name, endpoint, country, status)
- "★ mark best" highlights the lowest-latency working config

### 10. Settings Persistence
- Window size, positions, and all form values saved to `settings.json`
- Restored automatically on next launch

---

## 📄 License

This project is licensed under the **Creative Commons Attribution 4.0 International (CC BY 4.0)**.

You are free to:
- **Share** — copy and redistribute the material in any medium or format
- **Adapt** — remix, transform, and build upon the material for any purpose, even commercially

As long as you give appropriate credit, provide a link to the license, and indicate if changes were made.

See [`LICENSE`](LICENSE) for the full legal text.

---

## ⚠️ Disclaimer

This tool is for educational and network-diagnostic purposes. Users are responsible for complying with their local laws and regulations regarding proxy/circumvention software. The authors are not responsible for any misuse.
