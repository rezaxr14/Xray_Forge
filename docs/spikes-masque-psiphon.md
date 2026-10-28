# Spike notes: MASQUE and Psiphon (verified 2026-10-18)

Goal: decide what Xray Forge can honestly support before writing adapters.
Only what a source confirmed is marked **confirmed**; everything else is open.

## MASQUE (Cloudflare WARP over HTTP/3)

- **Confirmed:** Cloudflare ships MASQUE in its own WARP/1.1.1.1 apps
  (announced 2023, iOS beta first). It runs over QUIC/HTTP-3 on port 443.
  Source: Cloudflare blog "MASQUE: building a new protocol into Cloudflare WARP".
- **Confirmed:** the `sing-box-extended` fork (mirror of `shtorm-7/sing-box-extended`)
  lists a "MASQUE" protocol in its README, separate from its WireGuard-based
  "WARP" entry. It is a **fork**, not official sing-box.
- **Not found:** MASQUE outbounds in Xray-core, mihomo, or official sing-box.
  A web search turned up nothing; absence of results is not proof of absence.
- **Open:** exact outbound type name and config fields in the fork (README
  points at its `docs/` and `examples/`); how a third-party client
  registers/authenticates against Cloudflare (key/cert enrollment) -- the
  Cloudflare article does not cover it.

**Update:** the fork's own example (`examples/masque/client.json`) confirms
the outbound type `masque` and its fields; the fork creates the Cloudflare
device profile itself when none is given, so Xray Forge does no enrollment.
Implemented as an opt-in binary slot (`core/masque.py`); still never run
against the real fork or Cloudflare from this project's tests.

Original decision (kept for context): do **not** add a MASQUE protocol handler until a core that supports
it is pinned. Plan: (1) read the fork's docs for the config schema, (2) add a
`CoreSpec` for it that is opt-in and clearly labelled as a fork, (3) gate the
UI behind core detection, exactly like `supports()` does for XHTTP today.

## Psiphon

- **Confirmed:** `psiphon-labs/psiphon-tunnel-core` is a Go library/client
  (versions v2.0.x on pkg.go.dev).
- **Open:** a usable standalone binary, its config keys (propagation channel,
  sponsor ID, remote server list URLs) and whether Psiphon Labs permits
  third-party apps to embed it with the public values. These come from
  Psiphon Labs and must not be invented here.

Blockers: the official build and config values come from Psiphon Labs, and
psiphon-tunnel-core is GPL-3.0, so shipping or embedding it is a licensing
decision for the project owner (the project itself is GPL-3.0-only).

**Update:** implemented as bring-your-own (`core/psiphon.py`): the user supplies
the `ConsoleClient` binary and their own config; we rewrite local ports and the
data directory on a private copy. Documented upstream usage is
`ConsoleClient -config <file>` with `LocalSocksProxyPort`/`LocalHttpProxyPort`;
`DataRootDirectory` and `-version` are assumed from newer releases and are unverified
(the version command is informational only). Needs a real-client check.

Decision: Psiphon is a *managed subprocess exposing a local SOCKS port*, which
matches the existing core-adapter model. Blocked on obtaining the official
build and config values; track as a spike, not a feature.

## Why this matters for the health check

Both would be tested through the same path as other external cores (start
subprocess -> wait for SOCKS port -> run staged probes via `fetch_via_socks`),
so no new probe code is needed once an adapter exists.
