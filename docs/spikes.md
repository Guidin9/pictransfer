# Faz 0 spikes

Spikes are throwaway experiments under `spikes/<name>/`. They answer the riskiest
questions before the production code is written. Each one records its numbers
here; if a pass criterion fails, the plan or the protocol is revised first.

| Spike | Question | Needs (downloads/accounts) |
|---|---|---|
| A | Is iroh 1.x fast and lean enough to start on demand? | Rust + MSVC; for the Android part also the NDK |
| B | Can the agent skeleton meet the idle budget? | Rust + MSVC |
| C | How long may a hibernating DO WebSocket stay silent, and what does it cost? | Node deps (`wrangler`, ~100 MB), a Cloudflare account |
| D | How fast is FCM wake → foreground service → iroh dial on the user's phone? | Android NDK + Gradle deps, a Firebase project, the phone with USB debugging |

## Spike A — iroh 1.x on demand

Setup: `spikes/iroh-probe` (Rust bin) with `listen` and `dial <ticket>` modes,
printing timings as JSON. It runs on the PC and, via a minimal JNI or UniFFI
wrapper, on the phone.

| # | Measure / check | Pass |
|---|---|---|
| A1 | `bind` → home relay connected, Windows / Android | < 500 ms |
| A2 | Dial → connected: same LAN with direct addresses, cross-network (relay → direct), relay only | LAN < 300 ms |
| A3 | Connect → first direct path (`path_events`); a reliable "is direct" check via `paths()` | documented API usage |
| A4 | 200 MB throughput: direct LAN; relayed (note the n0 rate limit) | LAN ≥ 50 MB/s |
| A5 | Private working set before bind / during transfer / 30 s after `Endpoint::close` | back to baseline + ≤ 2 MB |
| A6 | `export_keying_material` gives equal output on both sides; single-region relay map; address lookup disabled; runs on a `current_thread` runtime | all OK |
| A7 | X-Wing crate choice: `libcrux-kem` vs `x-wing`, checked against the draft-06 vectors | one chosen |

Results:

| Date | Device | A1 | A2 (LAN / x-net / relay) | A4 | A5 | A6 | Notes |
|---|---|---|---|---|---|---|---|
| – | – | – | – | – | – | – | – |

## Spike B — agent skeleton vs the idle budget

Setup: `spikes/agent-skeleton`: tray icon and menu, `RegisterHotKey`, clipboard
read (PNG format; DIB → PNG fallback), the WebSocket client from Spike C, no
logging. Measured with `scripts/measure-idle.ps1`.

| # | Measure | Pass |
|---|---|---|
| B1 | Idle private working set / threads / CPU after 10 min | < 5 MB / ≤ 6 / ≈ 0 |
| B2 | Idle network (internal counters, projected per day) | < 0.5 MB |
| B3 | Hotkey → PNG bytes ready, 4K screenshot (PNG present / DIB encode) | < 20 ms / < 150 ms |
| B4 | AltGr conflict check via `ToUnicodeEx` on TR-Q for Ctrl+Alt+Q, Ctrl+Alt+Shift+S | Q flagged, S+Shift clear |

Results:

| Date | Commit | B1 | B2 | B3 | B4 | Notes |
|---|---|---|---|---|---|---|
| – | – | – | – | – | – | – |

## Spike C — hibernating Durable Object WebSocket

Setup: `spikes/do-keepalive`, a minimal Worker + DO using the Hibernation API and
`setWebSocketAutoResponse("p" → "o")`, deployed to the user's free account.
A Node client (built-in `WebSocket`) holds 6 connections with ping intervals of
30 / 60 / 90 / 120 / 300 / 600 s for 6 hours and logs every close (time, code).

| # | Measure | Pass |
|---|---|---|
| C1 | Longest interval with zero unexpected closes | ≥ 60 s |
| C2 | DO duration while idle (dashboard / GraphQL analytics) | ≈ 0 (auto-response doesn't wake) |
| C3 | Request count per connection-day (are auto-responses billed?) | fits 1000 devices in the free tier |
| C4 | Reconnect after laptop sleep/resume and network change | < 5 s after resume |

Results:

| Date | C1 | C2 | C3 | C4 | Notes |
|---|---|---|---|---|---|
| – | – | – | – | – | – |

## Spike D — Android wake path (user's phone)

Setup: `spikes/android-wake`, a minimal app. It registers an FCM token, receives a
HIGH-priority data message, starts a `dataSync` foreground service, dials the PC
listener through the Rust core (UniFFI) and receives 3 MB. Doze is forced with
`adb shell dumpsys deviceidle force-idle`.

| # | Measure | Pass |
|---|---|---|
| D1 | FCM send → `onMessageReceived` (screen on / off / Doze) | median < 1 s |
| D2 | FGS start allowed from the high-priority message (no `ForegroundServiceStartNotAllowedException`) on the current Android version | yes |
| D3 | End to end: push sent → file saved, Wi-Fi, Doze | median < 3 s |
| D4 | Battery setting "Optimized" vs "Unrestricted" (OEM behavior) | documented |

Results:

| Date | Phone / Android | D1 | D2 | D3 | D4 | Notes |
|---|---|---|---|---|---|---|
| – | – | – | – | – | – | – |
