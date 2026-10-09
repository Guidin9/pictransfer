# CLAUDE.md — warpshot

Android ⇄ Windows instant transfer of screenshots, text and files. End-to-end
encrypted P2P (iroh) with a post-quantum inner layer, a passwordless QR device
group, and a $0 Cloudflare wake-up server.

- Conversation with the user: **Turkish**.
- Code, comments, commit messages and docs: **English**.

## Read before changing anything

| File | Why |
|---|---|
| `docs/architecture.md` | components, Windows process model, flows, storage, settings |
| `docs/protocol.md` | **normative** wire and crypto spec. Change the spec and test vectors first, then the code |
| `docs/threat-model.md` | what we defend against. Security-relevant changes must keep it true |
| `docs/resource-budget.md` | Windows agent idle budget — an acceptance gate |
| `docs/ipc.md` | agent ⇄ UI named-pipe protocol |
| `docs/adr/` | decisions and their reasons. Don't re-litigate without new facts; write a new ADR instead |
| `docs/spikes.md` | Faz 0 measurements that the plan depends on |
| `docs/roadmap.md` | task list with acceptance criteria — pick the next unchecked task; tick it when its acceptance passes |

## Hard constraints

1. **Windows agent at idle:** < 5 MB private working set, ≈ 0 CPU, < 0.5 MB/day
   network, ≤ 6 threads. Verify with `scripts/measure-idle.ps1`. Every change that
   touches `apps/windows-agent` or code it links must report these numbers.
2. **$0 server:** Workers Free + SQLite-backed Durable Objects with WebSocket
   Hibernation. No paid services without the user's approval.
3. **Security invariants** (below) are never traded for convenience.

## Security invariants — NEVER

- Accept a transfer connection from an `EndpointId` that is not in the locally
  **verified** membership log (bounded in-band sync is the only exception, protocol §8.1).
- Trust the server's view of membership, presence or ordering for security decisions.
- Send content, item names or peer addresses to the server or FCM except inside
  an encrypted wake envelope.
- Log secrets, keys, content, item names, clipboard data or addresses. Logs carry
  ids, timings and error codes only.
- Auto-open or execute received files. Skip Mark-of-the-Web on Windows. Skip file
  name sanitization.
- Compare secrets with `==` (use `subtle`), or keep key material without `zeroize`.
- Use `unwrap()` / `expect()` / unchecked indexing on network or disk data in library code.
- Add a dependency without checking its license (GPL-3.0-compatible), its
  maintenance, and whether it starts background threads.
- Commit secrets: FCM service account, `google-services.json`, signing keys, `.dev.vars`.
- Add a URL protocol handler or a local HTTP server to the agent (use the named
  pipe and the COM toast activator).

## Agent (`warpshot-agent.exe`) rules

- Two threads at idle: the Win32 message loop and one tokio `current_thread`
  runtime (server WebSocket + named-pipe IPC). No other threads, timers or polling.
- The iroh endpoint lives only during transfers and closes after 30 s idle. Trim
  the working set afterwards.
- No WebView or Tauri in the agent. WinRT/COM objects are created lazily and released.
- Full rules: `docs/resource-budget.md` §2.

## Repository layout (target)

```
crates/core             warpshot-core   protocol, crypto, log, pairing, iroh endpoint manager, transfers, storage
crates/ffi              warpshot-ffi    UniFFI bindings for Android
crates/cli              warpctl         headless peer for E2E tests and spikes
apps/windows-agent      warpshot-agent.exe (Rust, Win32)
apps/windows-ui         warpshot-ui.exe (Tauri v2 + React/TS)
apps/android            Kotlin + Jetpack Compose, minSdk 29
server/                 Cloudflare Worker + Durable Object (TypeScript, vitest)
spikes/                 throwaway Faz 0 experiments
scripts/                setup-dev.ps1, measure-idle.ps1, e2e-local.ps1
docs/                   specs, ADRs, test vectors
```

## Toolchain and versions

Pinned at setup (`docs/dev-setup.md`). **Model knowledge of these APIs may be
outdated — read docs.rs or the official docs for the pinned version before using
an API.**

- Rust stable, edition 2024, target `x86_64-pc-windows-msvc`; Android targets via `cargo-ndk`.
- iroh **1.3.x**: `Endpoint`, `EndpointId`, `EndpointAddr`, `address_lookup`,
  `Connection::{export_keying_material, paths, path_events, remote_id}`. Pre-1.0
  names like `NodeId` / `discovery` are gone.
- Tauri **2.x**: v2 APIs only (capabilities and permissions, plugins). React + TypeScript + Vite.
- UniFFI for Kotlin; Kotlin + Jetpack Compose; FCM HTTP v1.
- Cloudflare Workers / Durable Objects (SQLite backend, Hibernation API,
  `setWebSocketAutoResponse`); tests with `vitest` + `@cloudflare/vitest-pool-workers`.

## Commands

Filled in as components land. Planned:

```powershell
cargo fmt --all; cargo clippy --workspace --all-targets -- -D warnings; cargo test --workspace
cargo deny check
cd server; npm ci --ignore-scripts; npm test
powershell -ExecutionPolicy Bypass -File scripts\measure-idle.ps1 -ProcessName warpshot-agent
powershell -ExecutionPolicy Bypass -File scripts\e2e-local.ps1
```

## Workflow

- **Spec first.** Wire or crypto changes start with `docs/protocol.md` plus the
  test vectors in `docs/test-vectors/`.
- **Small, verifiable steps.** Run the relevant tests before saying something
  works. Report failures verbatim, including measurement numbers.
- **Every validation rule gets a negative test.** Decoders get fuzz targets.
- **Ask the user before large downloads** (toolchains, SDKs, first dependency
  fetches) and before anything that costs money or publishes something
  (pushing, releases, store uploads).
