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
| `sub.fetch` | `force`, `timeout` | job |
| `health.run` | `lines`, `workers`, `timeout`, `throughput`, `core` | job; items are reports |
| `scan.run` | `cidrs`, `count`, `port`, `sni`, `workers`, `frag`, `geo`, `timeout`, `session`, `resume` | `{job, session, targets}`; items are scan results |
| `scan.sessions` / `scan.get` / `scan.export` | `session`, `format` (`csv`/`json`) | saved scan data |
| `sni.run` | `ips`, `snis`, `presets`, `from_scan`, `port`, `workers`, `frag`, `timeout`, `http_check`, `session`, `resume` | `{job, session, pairs}`; items are hits |
| `sni.presets` / `sni.sessions` / `sni.get` / `sni.export` | – / `session` | saved SNI data |
| `net.resolve` | `host` (domain; an IP literal is echoed back) | `{host, answers:[{ip, sources:[...]}]}`; DoH, Iranian UDP resolvers and system DNS, so disagreeing answers reveal tampering. Blocking (several seconds): requests run concurrently, so other calls are not held up |
| `net.geo` | `ip` (IPv4/IPv6/domain; empty = this machine's public IP) | `{query, text, ok}`; `ok` is false when every provider failed. The value is validated because it is placed in provider URLs |
| `warp.status` | – | `{registered, device_id (12 chars), endpoint, ipv4, ipv6}`; never returns keys or tokens |
| `warp.register` | – | status; talks to Cloudflare, saved 0600 |
| `warp.config` | `endpoint`, `format` (`xray`/`singbox`/`mihomo`) | outbound JSON snippet (contains the WireGuard key: it is the user's own config) |
| `warp.scan` | `count`, `workers` | job; items `{endpoint, ms}` |
| `mitm.groups` / `mitm.build` | `groups`, `use_generated_ca` | route families / Xray config JSON |
| `mitm.generate_ca` / `mitm.ca_paths` | `cn`, `permitted_domains` | paths only; key material is never returned |
| `mitm.guide` | `platform` | setup text |
| `job.cancel` / `job.list` | `job` | bool / ids |

### `config.convert` rules

| Param | Default | Meaning |
|---|---|---|
| `fp`, `cs`, `fm` | engine defaults (`engine.info.defaults`) | values injected into each link; `fm` must be JSON when `want_fm` is on |
| `want_fp`, `want_cs`, `want_fm` | `true` | what to inject; all `false` = the Tk GUI's "IP only" mode |
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
