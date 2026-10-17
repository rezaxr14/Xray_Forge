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
| `job.cancel` / `job.list` | `job` | bool / ids |

Errors use standard JSON-RPC codes; `-32602` for invalid params, `-32000` for
a failure inside the engine (message is `Type: text`). Scan, SNI search, WARP
and MITM methods follow in a later step.
