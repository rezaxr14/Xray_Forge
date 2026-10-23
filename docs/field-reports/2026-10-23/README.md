# Field report 2026-10-23 (Windows 11, TUN/fake-IP VPN, Iran-side filtering)

Redacted `tools/live_check.py` output from the owner's machine, kept as evidence for the fixes made after it.
The VLESS sample used the public list (no owner link), so its failures reflect the network, not the code.

Findings and what changed:

- `--dns auto` missed split-horizon fake-IP (cloudflare.com real, api.cloudflareclient.com fake): detection now
  probes the host the core dials first, plus two more names.
- 1.1.1.1:443 is blackholed there and the fork does not fall through to the next DoH server: default order is
  now 8.8.8.8 then 1.1.1.1, and `doh_servers` is configurable (engine, UI).
- MASQUE registration (`api.cloudflareclient.com`) is unreachable on that network whatever the DNS mode; a profile
  registered elsewhere can be supplied (id + auth token fields, never saved or displayed).
- IP-literal share links permanently failed the DNS stage; it now passes with `ip literal`.
- The e2e harness defaulted to `python3` (Microsoft Store stub on Windows): the default is `python` there.
- `electron/package.json` said 0.1.0 while the engine was 2.1.0: versions are synced and `tools/check_version.py` checks them.
- electron-builder's winCodeSign cache needs symlink rights on Windows: see `docs/packaging.md`.
