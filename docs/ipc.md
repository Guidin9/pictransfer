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
| `group.not_me` | `{id}` | `{}` — "This wasn't me": removes the device (reason `not-me`) |
| `debug.counters` | – | `{ws_bytes_in, ws_bytes_out, transfers, ...}` (ids and counts only) |

`Settings` = `{hotkey, default_target, save_dir, ask_above_mb, relay_data, autostart,
on_receive: {save, clipboard, notify, history}, history_days, history_items}`
(defaults in architecture.md §8).

## Events

| Event | Data |
|---|---|
| `status` | same shape as the `status` result, sent on change |
| `pair.sas` | `{sas, peer_name, peer_platform}` — show it and ask the user (`pair.confirm`) |
| `pair.done` | `{peer_id}` |
| `pair.failed` | `{code: "expired" \| "proof" \| "rejected" \| "other-group" \| "network"}` |
| `transfer.progress` | `{transfer, done_bytes, total_bytes}` (at most 4 per second) |
| `transfer.done` | `{transfer, ok, code?}` |
| `group.alert` | `{kind: "device-added", id, name, platform, by_name}` (§4.6; the UI offers "This wasn't me") |
| `group.fork` | `{}` — security alert: transfers are stopped until re-pairing (§4.5) |
| `history.changed` | `{}` — reload the history list |

## Lifetime

The UI connects on start and closes the pipe on exit; the agent keeps no UI
state. Several UI instances are refused (single-instance mutex in the UI).
