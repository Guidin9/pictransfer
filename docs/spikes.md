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
| 2026-10-09 | PC ↔ PC (same Win11 host, 12 threads), EU relay, slow home uplink | bind 27–82 ms ✓; home relay online 0.77–1.15 s ✗ | 33–51 ms bind→connected ✓ / pending (phone) / 400–561 ms | 128–166 MB/s ✓; relay 0.5 MB/s (10 MB) | 0.9 → peak 5.0–6.7 → 3.6 MB; 0.07 MB after trim ✓ | all ✓ | see below |
| 2026-10-10 | S21 FE (Android 16, Wi-Fi 11n) → PC (Ethernet), same router, `warpctl` | – | see "Phone ↔ PC routes" below | main AP: 100 MB in 13.1 s (7.6 MB/s), 20 MB in 3.5 s; via a repeater AP: no lasting direct path, relay only, 20 MB not done in 90 s | – | – | below |
| – | Android | – | – | – | – | – | pending, run with Spike D on the phone |

Probe: `spikes/iroh-probe` (iroh 1.3.0, `default-features = false`, `tls-ring`;
release build). Raw JSON in `spikes/iroh-probe/out/` (not committed).

Findings and the API usage they fix:
- **Never wait for `Endpoint::online()` before dialing.** It took ~0.8 s (it
  waits for the home relay); a dial with known direct addresses connects 33–51 ms
  after `bind` starts, relay-only 400–561 ms. The sender's relay connection
  overlaps the wake round-trip (WS/FCM, seconds), so A1's miss does not delay a
  transfer. Pass criterion A1 is therefore replaced by "bind < 100 ms, dial
  without waiting for online".
- **"Is direct"** = `conn.paths().iter().any(|p| p.is_selected() && p.is_ip())`.
  Take one `paths()` snapshot right after `connect`, then follow
  `conn.path_events()` (`Selected { remote_addr }` with `remote_addr.is_ip()`);
  a selection made during the handshake does not appear as an event.
- **EKM:** `Connection::export_keying_material(&mut out, label, context)` gives
  equal 32 bytes on both sides (checked on every run).
- **A6 configuration:** `Endpoint::builder(presets::Minimal)` +
  `.relay_mode(RelayMode::custom([defaults::prod::default_eu_relay().url]))` +
  `.clear_address_lookup()`; relay-only test via `.clear_ip_transports()`.
  Runs on `#[tokio::main(flavor = "current_thread")]`.
- **Threads:** 4 before bind (main + OS loader pool), 9 while the endpoint
  lives (one `tokio-rt-worker` blocking-pool thread + OS thread-pool workers used
  by sockets and network-change notifications), back to 8 at close+30 s, 5 at
  +60 s, 3 at +140 s. Nothing persistent: the ≤ 6 idle-thread budget holds about
  a minute after a transfer.
- **Memory:** private working set returns to baseline + ≤ 2 MB only after
  trimming the working set (`SetProcessWorkingSetSize(-1, -1)`); untrimmed it
  stays ~2.7 MB above baseline. Private bytes stay +3 MB after close (committed,
  not resident) — check against the 12 MB private-bytes budget in Spike B.
- **A7:** `x-wing` chosen (ADR 0008).
- Path events show several IP paths opening and closing within the first ~30 ms
  (multiple local interfaces); harmless.

### Phone ↔ PC routes (roadmap 4c, 2026-10-10)

Why the 258 MB video took 27 min (~167 KB/s). Measured with `warpctl` on both
sides (the Android build needs `CARGO_PROFILE_RELEASE_PANIC=unwind`: without a
JVM, iroh's DNS setup panics and falls back only when unwinding) and the
`path` events from `net::watch_paths` (address class only).

- **Same AP:** the direct `lan4` path is selected within ~120 ms and carries
  everything; 7.6 MB/s is about the phone's 11n Wi-Fi limit. The Windows
  "Public" firewall does not block it (outbound UDP opens the return path),
  so no firewall rule is needed.
- **Phone on a second AP of the same network (a repeater):** direct `lan4`
  paths open, carry a few KB and die after `PATH_IDLE` (4 s), again and again;
  PC → phone packets arrive, phone → PC mostly do not. Cause: the repeater
  proxies ARP (every host appears with the repeater's MAC) and the phone's ARP
  requests for the PC go unanswered (`ip neigh`: PC `INCOMPLETE`/`FAILED`,
  router `REACHABLE`, 5 of 5 tries). The phone learns the PC only briefly from
  the PC's own ARP traffic. Not fixable in the app; an AP in access-point
  (wired) mode or a mesh avoids it.
- **Relay:** the free n0 relay is rate-limited (ADR 0001): 0.5 MB/s PC ↔ PC,
  ~0.17 MB/s from the phone, RTT up to 4 s under load. Only a relay of our own
  makes non-direct transfers fast (open decision, roadmap).
- **Ruled out:** packet size (no MTU discovery: same loss); port mapping
  (iroh `portmapper`): one run looked better, but the phone had silently
  roamed back to the main AP; the repeat failed. Neither is enabled.
- **Untried idea:** keeping the phone's neighbour entry fresh by having the PC
  send ARP requests during a transfer (`SendARP`); blocking API, needs a
  thread, uncertain. Not pursued.
- **Pitfalls:** ping is not a reachability test here (Windows drops ICMP echo
  on "Public"); Android may switch APs on its own, so record the AP before and
  after each run.

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
| 2026-10-09 | Spike B | 0.69 MB / 5 threads / 0 % ✓ | ≈ 0.25 MB/day ✓ | 0.6 ms ✓ / 84 ms ✓ | `@` flagged, S+Shift clear ✓ | see below |

Setup: release build (opt-level "s", fat LTO, strip; 1.2 MB exe), hidden window +
tray icon + `RegisterHotKey`, one `current_thread` tokio thread holding the
WebSocket to the Spike C Worker (rustls + ring + webpki-roots, a ~150-line
RFC 6455 client, no WebSocket crate), EcoQoS on, working set trimmed after
startup and after each connect. `measure-idle.ps1`: 60 s warm-up, 10 min of
samples.

- **B1:** private working set 0.69 MB max, private bytes 1.89 MB, 5 threads
  (main, tokio, three OS pool threads), CPU 0 %, 184 → 183 handles, one TCP connection.
- **B2:** internal counters over 780 s: 12 pings, 12 pongs, 0 missed; 5259 B in /
  954 B out at the TLS layer, almost all of it the TLS handshake. Steady state is
  ≈ 54 B of TLS records per keepalive round trip → ≈ 78 KB/day at K = 60 s, about
  250 KB/day with TCP/IP headers (estimate; confirm with `pktmon` once). K = 120 s
  would halve it — decide with Spike C.
- **B3:** synthetic 3840×2160 UI-like screenshot. PNG already on the clipboard:
  0.6 ms (one copy). DIB → PNG with the `png` crate: 190 ms with the default
  adaptive filter, **84 ms with `Filter::Sub` + `Compression::Fast`** (+7 % size,
  3.98 MB). The agent uses Sub/Fast.
- **B4:** on Turkish Q, `ToUnicodeEx` (flag 4, no keyboard-state change) yields
  `@` for Ctrl+Alt+Q → flagged; Ctrl+Alt+Shift+S yields nothing → clear. The
  layout was already installed; otherwise the probe loads it with
  `KLF_NOTELLSHELL` and unloads it again.
- The WebSocket root store is built per connection and dropped with it, so it
  is not resident while connected-and-idle beyond what rustls keeps.

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
| 2026-10-09 | 600 s: 0 missed pongs at every interval | not measured | not measured | not measured | 6 h, 6 connections; see below |

Every connection, at every interval (30–600 s), was closed by the edge with
code 1006 every 25–135 min (5–7 closes per connection in 6 h, longest
uninterrupted 1.5–2.2 h), independent of the ping interval. No pong was ever
missed and reconnects never failed. So the keepalive does not keep the socket
alive; it only detects silent deaths, and the closes are not silent.

**Decision: K = 120 s** (protocol §6.3). Network per day ≈ 125 KB of
keepalives (Spike B estimate halved) + ≈ 30 reconnects × ≈ 6 KB TLS handshake
≈ 0.3 MB/day, inside the 0.5 MB/day budget; K = 60 would sit at ≈ 0.45 MB.
Worst-case detection of a silently dead socket is 2 × K = 4 min, and the
client also reconnects on network-change and resume events. C2–C4 are checked
on the deployed server (E2).

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
