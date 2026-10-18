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
| `engine.info` | – | version, protocol, schemes, cores, methods, defaults |
| `config.parse` | `line` | `{ok, outbound, supports:{core:bool}}` |
| `config.parse_many` | `text` | list of the above |
| `config.render` | `outbound` | `{uri, roundtrip_ok, supports}` (editor save) |
| `config.convert` | `text`, options | `{lines, counts, removed}` |
| `config.export` | `lines`, `format` (`clash`/`singbox`/`sub`) | `{content, count}` |
| `config.dedup` | `lines` | `{lines, removed}` |
| `sub.list/add/remove/set_enabled/configs` | see code | source state |
| `sub.fetch` | `force`, `timeout` | job |
| `health.run` | `lines`, `workers`, `timeout`, `throughput`, `core` | job; items are reports |
| `scan.run` | `cidrs`, `count`, `port`, `sni`, `workers`, `frag`, `geo`, `timeout`, `session`, `resume` | `{job, session, targets}`; items are scan results |
| `scan.sessions` / `scan.get` / `scan.export` | `session`, `format` (`csv`/`json`) | saved scan data |
| `sni.run` | `ips`, `snis`, `presets`, `from_scan`, `port`, `workers`, `frag`, `timeout`, `http_check`, `session`, `resume` | `{job, session, pairs}`; items are hits |
| `sni.presets` / `sni.sessions` / `sni.get` / `sni.export` | – / `session` | saved SNI data |
| `warp.status` | – | `{registered, device_id (12 chars), endpoint, ipv4, ipv6}`; never returns keys or tokens |
| `warp.register` | – | status; talks to Cloudflare, saved 0600 |
| `warp.config` | `endpoint`, `format` (`xray`/`singbox`/`mihomo`) | outbound JSON snippet (contains the WireGuard key: it is the user's own config) |
| `warp.scan` | `count`, `workers` | job; items `{endpoint, ms}` |
| `mitm.groups` / `mitm.build` | `groups`, `use_generated_ca` | route families / Xray config JSON |
| `mitm.generate_ca` / `mitm.ca_paths` | `cn`, `permitted_domains` | paths only; key material is never returned |
| `mitm.guide` | `platform` | setup text |
| `job.cancel` / `job.list` | `job` | bool / ids |

Errors use standard JSON-RPC codes; `-32602` for invalid params, `-32000` for
a failure inside the engine (message is `Type: text`).
Session names (`session`) are restricted to `[A-Za-z0-9_.-]`, max 64
characters, so a client cannot address files outside the data directory.
