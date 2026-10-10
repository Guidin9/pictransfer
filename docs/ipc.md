# Agent ⇄ UI IPC (named pipe)

`warpshot-ui.exe` talks to `warpshot-agent.exe` over `\\.\pipe\warpshot-<user SID>`
(DACL: the current user SID only; `PIPE_REJECT_REMOTE_CLIENTS`; threat model T9).
The agent owns all state, keys and network access; the UI holds none of them.

## Framing

- One JSON object per line (UTF-8, `\n`-terminated), at most 1 MiB per line.
- Request: `{"id": <uint>, "method": "<name>", "params": {...}}` (`params` optional).
- Response: `{"id": <same>, "result": <value>}` or
  `{"id": <same>, "error": {"code": "<code>", "message": "<short, no content>"}}`.
- Event (agent → UI, unsolicited): `{"event": "<name>", "data": {...}}`.
- Unknown methods → error `unknown-method`; bad params → `bad-params`; malformed
  JSON → `parse-error`; a malformed request → `bad-request`; other failures carry
  short codes (`not-paired`, `no-server`, `network`, `storage`, …).
- A `jsonrpc: "2.0"` member is accepted and ignored; responses don't carry it.
  Unknown fields are ignored (forward compatibility).
- Device ids are lowercase hex of the 32-byte `EndpointId`; times are Unix ms.

## Methods

| Method | Params | Result |
|---|---|---|
| `status` | – | `{device: {id, name, platform}, paired: bool, server: "connected" \| "connecting" \| "offline", version}` |
| `devices.list` | – | `[{id, name, platform, me, online, last_seen, push, default_target}]` (`push`: the server holds a push token, so the device can be woken) |
| `devices.rename` | `{name}` (own device; appends `update`) | `{}` |
| `devices.remove` | `{id, reason: "user" \| "lost-or-stolen" \| "not-me"}` | `{}` |
| `devices.set_default` | `{id}` | `{}` |
| `pair.start` | – | `{qr_text, expires_at}` (opens a 120 s pairing window) |
| `pair.confirm` | `{accept: bool}` | `{}` (answers the `pair.sas` event) |
| `pair.cancel` | – | `{}` |
| `settings.get` | – | `Settings` (below) |
| `settings.set` | partial `Settings` | `Settings` |
| `hotkey.check` | `{hotkey: "Ctrl+Alt+Shift+S"}` | `{valid: bool, conflict: bool, produces?: string}` (AltGr check on the active layout) |
| `history.list` | `{before?: ts, limit?: uint ≤ 200}` | `[{id, ts, direction: "in" \| "out", peer, kind: "text" \| "image" \| "file", name?, size, path?, ok}]` |
| `history.reveal` | `{id}` | `{}` — shows the file selected in Explorer. Received files are **never** opened or executed by the agent. |
| `history.delete` | `{id}` | `{}` |
| `send.files` | `{paths: [string], target?: id}` | `{transfer: id}` |
| `send.text` | `{text, target?: id}` | `{transfer: id}` |
| `transfer.list` | – | `{transfers: [Transfer]}` — the running transfers (below) |
| `transfer.cancel` | `{transfer}` | `{}`, or error `not-found` if it already ended. The transfer then ends with `transfer.done {ok: false, code: "cancelled"}`; the receiving side deletes partial files (protocol §8.4 "Cancellation") |
| `group.not_me` | `{id}` | `{}` — "This wasn't me": removes the device (reason `not-me`) |
| `debug.counters` | – | `{ws_bytes_in, ws_bytes_out, transfers, route_direct, route_relay_only, route_slow, ...}` (ids and counts only; `route_*` count finished transfers by how they travelled, see `transfer.slow`) |

`Settings` = `{hotkey, default_target, save_dir, ask_above_mb, relay_data, autostart,
on_receive: {save, clipboard, notify, history}, history_days, history_items}`
(defaults in architecture.md §8).

`Transfer` = `{transfer, direction: "in" | "out", peer, label, items,
state: "waiting" | "running", done_bytes, total_bytes, bytes_per_sec,
started_ms}`. `peer` is the other device's name; `label` is the first item's
name (`"name +2"` for more, `""` for text and for incoming transfers before the
offer). `waiting`: queued, or waiting for the woken device to answer;
`running`: items accepted, data flowing. Byte counts cover item data only
(inline text counts as 0).

## Events

| Event | Data |
|---|---|
| `status` | same shape as the `status` result, sent on change |
| `pair.sas` | `{sas, peer_name, peer_platform}` — show it and ask the user (`pair.confirm`) |
| `pair.done` | `{peer_id}` |
| `pair.failed` | `{code: "expired" \| "proof" \| "rejected" \| "other-group" \| "network"}` |
| `transfer.started` | `Transfer` — a send or receive began (state `waiting`) |
| `transfer.progress` | `{transfer, done_bytes, total_bytes, bytes_per_sec}` — the first one (`done_bytes: 0`) means `running`; then at most 4 per second, and one at the end |
| `transfer.done` | `{transfer, ok, code?}` — `code`: `cancelled` (here or on the other device; no toast), `offline`, `no-answer`, `rejected`, `timeout`, `network`, ... |
| `transfer.path` | `{transfer, direction, ms, note}` — diagnostics: a path of the transfer opened, was selected or closed (`note` names the address class — `lan4`, `wan4`, `relay`, ... — and, on close, RTT, bytes and lost packets; never an address) |
| `transfer.slow` | `{direction: "in" \| "out"}` — a transfer has had no direct path for 8 s and crawls through the rate-limited relay; sent once per transfer (the agent also shows a toast) |
| `group.alert` | `{kind: "device-added", id, name, platform, by_name}` (§4.6; the UI offers "This wasn't me") |
| `group.fork` | `{}` — security alert: transfers are stopped until re-pairing (§4.5) |
| `history.changed` | `{}` — reload the history list |

## Lifetime

The UI connects on start and closes the pipe on exit; the agent keeps no UI
state. Several UI instances are refused (single-instance mutex in the UI).
