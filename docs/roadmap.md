# Roadmap and task list

Each task is sized for one agent session, so it can be verified independently.
**Acceptance** says how to verify it. `[DL]` marks tasks that need large
downloads (toolchains, SDKs, first dependency fetch); schedule those for a fast
connection (`docs/dev-setup.md`).

## Faz 0 — Foundations and spikes

- [x] **F0-1** Repo skeleton, license, `CLAUDE.md`, the docs (architecture,
  protocol, threat model, resource budget, spikes, ADRs, dev setup).
- [x] **F0-2** `scripts/setup-dev.ps1` (dry run tested) and `scripts/measure-idle.ps1`
  (tested on Windows PowerShell 5.1: over-budget and within-budget cases).
- [x] **F0-3** `[DL]` Run `setup-dev.ps1` on a fast connection.
  Acceptance: the verification block shows MSVC installed and rustc with host
  `x86_64-pc-windows-msvc`; `cargo new` + `cargo run` works.
- [ ] **F0-4** Accounts (user): Cloudflare (`npx wrangler login`); a Firebase
  project with the Android app and a service-account key.
- [ ] **F0-5** Decide names: app name, Android `applicationId`, Worker name. Rename
  the working name `pictransfer` if needed **before** any code ships.
- [ ] **F0-6** `[DL]` Spike A — iroh on demand (`docs/spikes.md`).
- [ ] **F0-7** `[DL]` Spike B — agent skeleton vs the idle budget; first row in
  `resource-budget.md` §4.
- [ ] **F0-8** `[DL]` Spike C — DO keepalive. Set K in protocol §6.3.
- [ ] **F0-9** `[DL]` Spike D — Android wake path on the user's phone.
- [ ] **F0-10** ADR 0007, crate choices: X-Wing implementation, CBOR crate
  (`minicbor` vs `ciborium`, judged by strict-decoding support), SQLite binding.

## Faz 1 — MVP (personal use)

### Core (`crates/core`)

| Id | Task | Acceptance |
|---|---|---|
| C1 | Strict CBOR helpers (limits, rejection rules) + fuzz target | `cbor-reject.json` passes; 10 min of fuzzing clean |
| C2 | Keys and keystore trait (DPAPI impl in the agent; Android via an FFI callback) | round-trip tests; keys never appear in `Debug` output |
| C3 | Membership log: records, §4.3 validation, state, append/CAS logic, fork detection | `record.json` vectors; property tests (random ops, forks, re-adds) |
| C4 | Wake envelopes §7: seal/open, replay cache | `wake.json` vectors; every tamper case rejected |
| C5 | Server client: §6.1 auth, REST, WebSocket (keepalive, backoff, resume) | `server-auth.json`; integration test against `wrangler dev` |
| C6 | Endpoint manager: on-demand bind, 30 s idle teardown, single relay, no address lookup, direct-only policy | unit tests + spike A numbers reproduced |
| C7 | Transfer §8: handshake and key schedule, control messages, item streams, BLAKE3, temp file + atomic rename, name sanitization | `xfer-keys.json`; ptctl E2E with text, image and a 1 GB file; relay-only and direct-only modes |
| C8 | Pairing §5: QR encode/decode, SAS, group resolution table | `pair.json`; ptctl pairing E2E covering all 5 table rows |
| C9 | Settings store and history store (encrypted fields) | tests; no plaintext names in the DB file |
| C10 | Test-vector generator (`gen_vectors`) used by core and server | vectors reproducible from fixed seeds |

### CLI (`crates/cli`, `ptctl`)

| Id | Task | Acceptance |
|---|---|---|
| L1 | `init`, `pair-display`, `pair-scan <qr>`, `send <device> <path>` / `send <device> --text`, `listen`, `devices`, `log`, `remove` | `scripts/e2e-local.ps1` green |

### Server (`server/`)

| Id | Task | Acceptance |
|---|---|---|
| S1 | Worker router + DO skeleton (SQLite schema, Hibernation API, auto-response) | vitest (workers pool) |
| S2 | §6.1 auth + replay cache (WebCrypto Ed25519) + operator admission token | `server-auth.json` vectors; group creation without/with a wrong token → 403 `not-allowed` |
| S3 | Log store: §4.3 validation + CAS + `log` push | `record.json` vectors shared with core |
| S4 | Wake routing (WS, else FCM HTTP v1 with cached OAuth token), rate limits | tests with a fake FCM endpoint |
| S5 | Presence, push-token endpoints, removal handling (`bye`, token deletion) | tests |
| S6 | Deploy (wrangler), secrets, `/v1/health` | health check on the free account |

### Windows agent (`apps/windows-agent`)

| Id | Task | Acceptance |
|---|---|---|
| W1 | Message loop, tray (devices + status, default-target radio, settings, quit), single instance | manual check; idle budget |
| W2 | Global hotkey + AltGr conflict check; toast if the hotkey is taken | TR-Q: `Ctrl+Alt+Q` flagged |
| W3 | Clipboard read (PNG, DIBV5, text, CF_HDROP) and write (PNG + DIBV5, text, CF_HDROP) | paste works in Paint, Word, Explorer |
| W4 | WinRT toasts with preview + COM activator; Start Menu shortcut with AUMID | the action opens the right history item; no URL handler is registered |
| W5 | Receive pipeline: save with MOTW, clipboard, toast, history | `Zone.Identifier` present; sanitization tests |
| W6 | Named-pipe JSON-RPC server (user-SID ACL, remote clients rejected) | another local user is refused |
| W7 | Resource discipline: on-demand endpoint, working-set trim, EcoQoS | `measure-idle.ps1` within budget |
| W8 | Autostart (HKCU Run) + per-user installer | clean install/uninstall, no admin rights |

### Windows UI (`apps/windows-ui`)

| Id | Task | Acceptance |
|---|---|---|
| U1 | Tauri v2 skeleton: no network capability, strict CSP, pipe client | `pt-ui` exits fully on close (no leftover WebView2 processes) |
| U2 | Screens: pairing (QR, SAS, confirm), devices (rename/remove), settings (hotkey recorder with AltGr warning, target, folder, relay, autostart), history | manual walkthrough |

### Android (`apps/android`)

| Id | Task | Acceptance |
|---|---|---|
| A1 | Gradle project; Rust core via `cargo-ndk` + UniFFI; Keystore bridge | debug build on the phone |
| A2 | Onboarding: QR scan, pairing confirmation, notification permission, battery guidance | pairs with ptctl and with the agent |
| A3 | FCM → `TransferService` (dataSync FGS) → receive → outputs (MediaStore, clipboard, notification, history) | delivery in Doze, < 3 s on Wi-Fi |
| A4 | `ShareActivity` + sharing shortcuts (the PC appears directly in the share sheet) | share an image from Gallery → PC clipboard |
| A5 | Devices (presence), settings, history; group alerts with "This wasn't me" | the alert appears when ptctl adds a device |

### End-to-end and personal release

| Id | Task | Acceptance |
|---|---|---|
| E1 | `scripts/e2e-local.ps1`: `wrangler dev` + two `ptctl` peers | green locally and in CI |
| E2 | Real-device checklists: `resource-budget.md`, `threat-model.md` §6, Spike D numbers | all checked |
| E3 | CI (GitHub Actions): fmt, clippy, test, deny; server tests; Windows agent build + idle gate; Android assemble | green on `main` |

## Faz 2 and 3

See [`architecture.md`](architecture.md) §11 for the planned extensions.
Faz 3 (public release) adds code signing (SignPath Foundation), the Play Store,
a self-host option, TPM keys, UnifiedPush/F-Droid, reproducible builds and an
external audit.
