# Engine API (protocol v1)

`python -m xray_forge serve` speaks newline-delimited JSON-RPC 2.0 on
stdin/stdout. No network port is opened. stdout carries protocol messages only
(library output is redirected to stderr; logs go to `~/.xray_forge/logs`).
Batches are not supported. Requests run concurrently; responses may arrive out
of order, match them by `id`.

## Jobs

Long operations (`sub.fetch`, `health.run`) return `{"job": "<id>"}` at once and
then stream notifications:

```json
{"jsonrpc":"2.0","method":"job.event","params":{"job":"ab12","type":"progress","done":3,"total":10}}
```

`type` is `started`, `progress`, `item` (one result), `done` (`result`,
`cancelled`) or `error` (`message`). Cancel with `job.cancel`. Closing stdin
cancels everything and shuts the engine down.

## Methods

| Method | Params | Result |
|---|---|---|
| `engine.info` | – | version, protocol, schemes, cores, methods, defaults, template_keys, editor (`transports`, `flows`, `securities`, `xhttp_modes`) |
| `config.parse` | `line` | `{ok, outbound, supports:{core:bool}}` |
| `config.parse_many` | `text` | list of the above |
| `config.render` | `outbound` | `{uri, roundtrip_ok, supports}` (editor save). The payload is validated: unknown fields, wrongly-typed values and ports outside 1..65535 are `-32602`; `port` / `alter_id` may be integers; `raw` is ignored |
| `config.from_json` | `text` | `{outbound, supports}`: the raw-JSON editor's JSON -> form step, same validation as `config.render` plus `bad JSON: ...` |
| `config.convert` | `text`, rules (below) | `{lines, counts, removed, names:[{name,line}]}` |
| `config.check_override` | `ip`, `port` | `{ip: "ipv4"/"ipv6"/"domain"/""/null, port: true/false/null}`; live feedback for FORCE IP / PORT (`null` = invalid / empty) |
| `config.tag_cc` | `items:[{line, cc}]` | `{items:[{line, name, changed}], tagged}`; appends `[CC]` to a name, idempotent, VMess-aware |
| `config.export` | `lines`, `format` (`clash`/`singbox`/`sub`) | `{content, count}` |
| `config.dedup` | `lines` | `{lines, removed}` |
| `sub.list/add/remove/set_enabled/configs` | see code | source state |
| `sub.presets` | none | `[{id, name, url, note, added}]`: built-in one-click sources (currently `patterniha-f`, the Patterniha-F free daily configs). Nothing is downloaded by listing or adding one |
| `sub.add_preset` | `id` | the new (or existing) source; unknown ids give -32602. Adding never fetches: the list is downloaded only by `sub.fetch` |
Note: `sub.add` treats a `#fragment` on the URL as the display name and stores the URL without it (a fragment is never sent to a server).
| `sub.fetch` | `force`, `timeout` | job; result `{counts, total, removed}` |
| `health.run` | `lines`, `workers` (1..64), `timeout` (0.5..120), `timeouts`, `throughput`, `core`, plus the optional anti-DPI options below | job; items are reports. The reports of the last 4 runs are kept by the engine |
| `sub.check` | `workers`, `timeout`, `timeouts`, `throughput`, `core`, anti-DPI options | `{job, total, removed}`; `health.run` over the cached configs of every enabled source (errors with "no cached configs: fetch the sources first") |
| *(anti-DPI options of `health.run` / `sub.check`)* | `fake_sni` (host name sent in the ClientHello), `front_host` (Host header of the WebSocket upgrade), `record_frag`, `pad_hello` (booleans), `frag_variants` (1..8 specs, default `["off","5,94,1@2","rand:1-16@2"]`) | Only the built-in TLS/WebSocket probes use them; checks run through a proxy core ignore them. Invalid values are `-32602` |
| *(`timeouts` of `health.run` / `sub.check`)* | optional object `{dns, tcp, tls, request, transfer}`, each 0.5..120 seconds | Overrides `timeout` for that stage only; unlisted stages keep `timeout`, and `dns` keeps its own 4 s default. `tls` applies to each fragmentation variant tried; `transfer` bounds the download and upload stages, including the fresh session the upload opens. Unknown stage names or bad values are `-32602` |
| `health.export_best` | `job`, `top_n` (1..1000, default 10) | `{content, count}`; base64 subscription of the best *working* configs of a run (also while it is still running) |
| `health.tagged` | `job`, `min_score` (0..100) | `{lines}`; working configs, best first, names tagged with the techniques that worked, e.g. `name [fragment:5,94,1@2]` |
| `scan.run` | `cidrs`, `count`, `port`, `sni`, `workers`, `frag`, `geo`, `timeout` (0.2..120), `tcp_timeout`, `tls_timeout` (0.2..120 or null = `timeout`), `tcp_retries` (0..5, default 1), `session`, `resume` | `{job, session, targets}`; items are scan results. Only `workers * 4` probes are in flight at once; cancelling stops everything that has not started, and IPs interrupted by it stay pending. `tcp_retries` is how many extra connects a host that never answered gets (0 = a filtered IP costs one `tcp_timeout`). The session file is saved atomically at most every 5 s |
| `scan.sessions` / `scan.get` / `scan.export` | `session`, `format` (`csv`/`json`) | saved scan data |
| `sni.run` | `ips`, `snis`, `presets`, `from_scan`, `port`, `workers`, `frag`, `timeout`, `http_check`, `session`, `resume` | `{job, session, pairs}`; items are hits |
| `sni.presets` / `sni.sessions` / `sni.get` / `sni.export` | – / `session` | saved SNI data |
| `net.resolve` | `host` (domain; an IP literal is echoed back) | `{host, answers:[{ip, sources:[...]}]}`; DoH, Iranian UDP resolvers and system DNS, so disagreeing answers reveal tampering. Blocking (several seconds): requests run concurrently, so other calls are not held up |
| `net.geo` | `ip` (IPv4/IPv6/domain; empty = this machine's public IP) | `{query, text, ok}`; `ok` is false when every provider failed. The value is validated because it is placed in provider URLs |
| `ui.settings_get` | – | `{settings}`: the Electron UI's saved form values (flat `{id: string/bool/number}`); unreadable or malformed entries are dropped |
| `ui.settings_set` | `settings` | `{saved}`; replaces the saved settings (<= 200 keys `[a-z][a-z0-9_-]*`, string values <= 4096, finite numbers). Stored in `~/.xray_forge/ui_settings.json`, owner-only; separate from `settings.json` (core paths) |
| `warp.status` | – | `{registered, device_id (12 chars), endpoint, ipv4, ipv6}`; never returns keys or tokens |
| `warp.register` | – | status; talks to Cloudflare, saved 0600 |
| `warp.config` | `endpoint`, `format` (`xray`/`singbox`/`mihomo`) | outbound JSON snippet (contains the WireGuard key: it is the user's own config) |
| `warp.scan` | `count`, `workers` | job; items `{endpoint, ms}` |
| `masque.status` | – | `{path, source, configured, found, version, ok, supported, detail}` for the opt-in `sing-box-extended` binary (a fork; not a registered core). `supported` comes from the binary's own `check` on a credential-free config; `detail` says what is missing |
| `masque.set_path` | `path` | status; absolute, executable, must answer `version`; `""` clears. Stored under `core_paths.singbox_extended` |
| `masque.config` | `options`, `socks_port` (1080), `include_secrets` (false) | `{content, redacted}`: the fork's client config as JSON. `options` keys: `use_http2`, `use_l4_proxy`, `use_ipv6`, `address`, `port`, `server_name`, `insecure`, `fragment`, `record_fragment`, `congestion_controller`, `doh_servers` (1-4 IP literals, default `["8.8.8.8","1.1.1.1"]`), `dns` (`auto`|`system`|`doh`; auto uses IP-literal DoH only when the system resolver returns fake-IP 198.18.0.0/15 answers), `bind_interface` (default false), `profile_id`, `auth_token`, `license_key`; unknown keys are rejected. `auth_token`/`license_key` are `***` unless `include_secrets` |
| `masque.probe` | `options`, `timeout` (8, 0.2..120), `start_timeout` (60, 1..300) | job; item and result `{real, cc, exit_ip, status}`. Refused (-32602) when no binary is set; cancelling kills the core and takes effect at once, also while the page fetch is in flight. The first run can be slow because the fork may have to create the Cloudflare device profile |
| `core.release` | `name` (`xray`/`singbox`/`singbox_extended`/`mihomo`) | `{core, repo, tag, asset, size, sha256, url}`: what `core.install` would fetch (latest official GitHub release for this platform). Application error -32000 when the release has no matching asset or no sha256 digest. Nothing is downloaded |
| `core.install` | `name` | job; progress events `{done, total}` bytes; result `{core, path, tag, asset, sha256, size, ok, version}` (or `{status: "cancelled"}`). Only `https` GitHub hosts and redirects, the asset must sit under the core's official repo, GitHub's sha256 digest must match, sizes are capped, only the known file names are written to `<data>/cores/<core>/<tag>/`. The path is remembered (`core_paths`) only if the binary answers its version command. The digest comes from the publisher, so it detects a corrupted or swapped download, not a compromised release |
| `psiphon.status` | – | `{path, source, configured, found, version, ok, config_path, config_ok, detail}` for the user's own Psiphon `ConsoleClient` and config file; config values are never returned |
| `psiphon.set_path` | `path` | status; absolute executable (its version command is informational only); `""` clears. Stored under `core_paths.psiphon` |
| `psiphon.set_config` | `path` | status; absolute JSON file with `PropagationChannelId` and `SponsorId` (from Psiphon Labs); `""` clears. Stored as `psiphon_config` in `settings.json` |
| `psiphon.probe` | `timeout` (8, 0.2..120), `start_timeout` (120, 1..600) | job; item and result `{real, cc, exit_ip, status}`. Runs the client on a private rewritten copy of the config (own SOCKS/HTTP ports, temp data directory, removed afterwards); cancelling kills it |
| `mitm.groups` / `mitm.build` | `groups`, `use_generated_ca` | route families / Xray config JSON |
| `mitm.generate_ca` / `mitm.ca_paths` | `cn`, `permitted_domains` | paths only; key material is never returned |
| `mitm.guide` | `platform` | setup text |
| `job.cancel` / `job.list` | `job` | bool / ids |

### `config.convert` rules

| Param | Default | Meaning |
|---|---|---|
| `fp`, `cs`, `fm` | engine defaults (`engine.info.defaults`) | values injected into each link; `fm` must be JSON when `want_fm` is on |
| `want_fp`, `want_cs`, `want_fm` | `true` | what to inject; all `false` = "IP only" mode |
| `tls_only` | `true` | when injecting, skip links whose `security` is not `tls` |
| `rename`, `template`, `start` | `true`, default template, `1` | naming; keys are listed in `engine.info.template_keys`; `start` is 0..99999 |
| `ip`, `port` | `""` | force one endpoint on every link (IPv4, IPv6 or domain; port 1..65535). Only the connect address changes: sni/host/path are untouched |
| `dedup` | `false` | drop duplicates after conversion |

Invalid values return `-32602`. `names` follows the output order after
de-duplication; with `rename` off it reports each link's own `#name`.

Errors use standard JSON-RPC codes; `-32602` for invalid params, `-32000` for
a failure inside the engine (message is `Type: text`).
When `scan.run` / `sni.run` get no `session`, the engine names it
`scan_<timestamp>` / `sni_<timestamp>` and appends `_2`, `_3`, ... if that name
is already taken, so two runs started in the same second never share a session.
An explicit `session` is used as given (that is how `resume` finds it).
Session names (`session`) are restricted to `[A-Za-z0-9_.-]`, max 64
characters, so a client cannot address files outside the data directory.
