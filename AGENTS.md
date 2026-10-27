# AGENTS.md — working on Xray Forge

Instructions for AI agents (and humans) contributing to this repository.
Read this fully before changing code.

## What this project is

Xray Forge is a Python utility for managing, fixing, testing and exporting
proxy configurations (VLESS / VMess / Trojan / Shadowsocks / Hysteria2 /
TUIC / WireGuard-WARP) with DPI-resistance features: fragmented TLS probes,
fake SNI, domain fronting, and a local MITM-DomainFronting config generator.
It ships an Electron desktop app (UI over the Python engine, JSON-RPC on stdio;
see `docs/engine-api.md`) and a fully headless CLI. The Tkinter GUI is retired.

License: **Apache-2.0**. Do not paste GPL-licensed code into this repo
(see *Licensing constraints* below).

## Commands

```bash
# run all tests (offline; network probes are monkeypatched in tests)
python -m pytest tests -q

# lint (CI uses this exact selection: syntax errors + undefined names only)
ruff check --select E9,F63,F7,F82 .

# compile check
python -m compileall -q xray_forge Xray_Forge.py

# CLI (headless)
python -m xray_forge --help
python -m xray_forge convert in.txt out.txt
python -m xray_forge export in.txt out.yaml --format clash

# workflow policy (pinned actions, permissions, release consistency, hash-locked pip)
python tools/check_workflows.py

# Python deps: edit requirements.txt / requirements-ci.in, then regenerate both locks
tools/update_locks.sh        # needs uv + network; workflows install with --require-hashes

# desktop app tests (Node 22+; Playwright for the end-to-end tests)
cd electron && npm test
```

CI (`.github/workflows/ci.yml`) runs on ubuntu-latest and windows-latest ×
Python 3.10/3.12/3.13, always with **bash** as the shell (PowerShell cannot
expand `*.py` globs or run heredocs — never add `shell: pwsh` steps or
heredocs outside a `bash` default). It compiles, lints, runs pytest, then
CLI and GUI smoke tests.

## Layout

```
Xray_Forge.py            root launcher -> xray_forge.cli:main
xray_forge/
  cli.py                 headless CLI (argparse subcommands)
  engine/                JSON-RPC engine API for the Electron app (methods, jobs, rpc)
  core/
    models.py            Outbound dataclass — THE config representation
    config.py            constants (fingerprints, ranges, ports, presets)
    parser.py            share-link parsing, fix_uri/convert_block, exporters
                         (parse_target -> Outbound; out_to_clash/out_to_singbox)
    protocols/           protocol registry: one handler per protocol
      base.py            ProtocolHandler + xray streamSettings builders
      vless.py vmess.py trojan.py shadowsocks.py hysteria2.py tuic.py wireguard.py
    cores/               core adapters (what can actually RUN a config)
      base.py            CoreAdapter + run_socks_probe (spawn binary, test socks)
      xray_core.py singbox_core.py mihomo_core.py
    xray_bridge.py       backwards-compat façade over cores.xray_core
    socks.py             SOCKS5 client + HTTP-through-socks helper
    probe.py             low-level DPI-resistant probes (TLS/WS/VLESS tunnel/DoH)
    scanner.py           DNS (DoH/UDP/system), geo lookup, CIDR sampling, jitter
    scan_session.py      resumable scan sessions (state, CSV/JSON, per-ISP)
    sni_search.py        SNI/fronting-host search (candidates x clean IPs)
    subscription.py      subscription fetch + multi-format decode (b64/plain/
                         Clash YAML/sing-box JSON) + conversions back to URIs
    sub_source.py        subscription SOURCE manager (ETag cache, dedup, state)
    healthcheck.py       staged pipeline: dns→tcp→tls→request→download→upload,
                         scoring, ranking, best-N subscription export
    domainfront.py       MITM-DomainFronting Xray config generator + CA tools
    warp.py              pure-python X25519, WARP account API, endpoint scan
    settings.py          settings.json (core paths) + data_dir() (~/.xray_forge)
    dedup.py             config de-duplication
electron/                desktop app (main/preload/files.js, renderer/, test/)
tests/                   pytest suite (offline; see Testing rules)
.github/workflows/       ci.yml, release.yml (PyInstaller builds + checksums)
```

## Non-negotiable conventions

1. **`from __future__ import annotations` at the top of every module**
   that defines functions/classes (right after the module docstring).
   Runtime PEP-604 unions (`str | None`) otherwise break older interpreters.
2. **CLI and engine stay headless.** `xray_forge/cli.py` and `xray_forge/engine/`
   must never import `tkinter` or any UI toolkit. Entry points (`Xray_Forge.py`,
   `__main__.py`) import from `xray_forge.cli`.
3. **`parse_target` returns an `Outbound`** (`core/models.py`), never a dict.
   `Outbound` implements `__getitem__`/`get` with the legacy keys
   (`uuid`, `hdr`, `type`, `fp`) for backwards compatibility — do not add new
   dict keys; add dataclass fields.
   - For Shadowsocks: `credential` holds the *password*, `ss_method` the
     method (use `out.ss_split()` to get the pair).
4. **Protocol support = a handler in `core/protocols/`.** To add a protocol:
   create `core/protocols/<name>.py` with a `ProtocolHandler` subclass
   (implement `parse` via `parse_target`, `to_uri`, and the per-core
   renderers — return `None` for cores that cannot run it), then
   `register()` it in `core/protocols/__init__.py`.
   Core capability lists are *derived* from the renderers
   (`CoreAdapter.supported_protocols()`), so never hard-code them elsewhere.
5. **Core support = an adapter in `core/cores/`.** To add a core: subclass
   `CoreAdapter`, implement `render_outbound`, `build_client_config`,
   `find_binary`, register it in `core/cores/__init__.py`.
6. **Windows console safety**: CLI output must survive cp1252. `main()`
   reconfigures stdout/stderr to UTF-8; avoid introducing prints before that.
7. **User data goes to `settings.data_dir()`** (`~/.xray_forge/`): source
   state, caches, scan sessions, WARP accounts. Never write user state into
   the package directory (except the legacy `settings.json`).
8. **Tests are offline.** Anything touching the network must be
   monkeypatched. `tests/conftest.py` redirects `data_dir`/`settings_path`
   into tmp dirs automatically. Deterministic seeds for fuzz tests.
9. **Windows paths in CI**: workflows must use bash; quote `$RUNNER_TEMP`
   paths; remember `%` must be escaped as `%%` in printf of URLs.

## Testing rules

- New feature → new tests. Fix → regression test first.
- Golden export tests (`tests/test_golden_exports.py`) compare *parsed*
  structures, not raw text, so PyYAML version drift can't break them.
- X25519 implementation is verified against RFC 7748 test vectors — if you
  touch `core/warp.py::x25519`, those tests must still pass exactly.
- Run the full suite before committing: `python -m pytest tests -q`.
- After touching `electron/`, run `cd electron && npm test`.

## Licensing constraints (important)

- This repo is Apache-2.0. **Never copy code from GPL-licensed projects**
  (patterniha/*): GPL code cannot be combined into an Apache-2.0 work without
  relicensing the whole project. Xray-core is Apache-2.0 and fine to *read*
  for API shape. Keep `LICENSE` byte-identical to the official text (a test
  checks its hash) and keep `NOTICE` shipped with every release archive.
- External cores and tools (xray, sing-box, mihomo, sing-box-extended, Psiphon's
  `ConsoleClient`) are **separate programs the user supplies**; we spawn them and
  never link or copy their code, so their licences (some GPL-3.0) do not apply to
  this repo. Bundling one in an installer is a separate licensing decision.
- Techniques are re-implemented from public documentation. When implementing
  from an upstream repo, write original code and note the documented source
  in the docstring (see `core/domainfront.py` for the pattern).

## Security notes

- The MITM-DF generator creates a **personal** CA: the code and the printed
  guides must keep warning users to never share `mycert.key` / reuse
  someone else's certificate.
- `core/warp.py` performs best-effort calls to Cloudflare's undocumented
  client API — treat responses as untrusted input; validate before use.
- The app spawns external core binaries with user-provided config JSON —
  keep using temp files + `CREATE_NO_WINDOW` on Windows (see
  `cores/base.run_socks_probe`).

## Release process

1. Update `__version__` in `xray_forge/__init__.py` and `pyproject.toml`.
2. Ensure CI is green on `main`.
3. Tag `vX.Y.Z` and push the tag — `.github/workflows/release.yml` builds
   Windows/Linux single-file executables, runs the test suite, computes
   SHA-256 checksums, and attaches everything to a GitHub Release.
