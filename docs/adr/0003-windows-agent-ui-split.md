# ADR 0003 — Tiny always-on Windows agent + on-demand UI process

- Status: Accepted · 2026-10-07

## Context

The hotkey and clipboard features need a resident process. The user's top
Windows requirement: almost no RAM and almost no network while idle. Tauri and
WebView2 are productive for the UI, but WebView2 costs tens of MB or more while loaded.

## Decision

- `warpshot-agent.exe`: pure Rust + Win32/WinRT, using `windows`, `tray-icon`, `muda`
  and `global-hotkey`. Two threads: the message loop and a `current_thread` tokio
  runtime with the server WebSocket and the named-pipe IPC. The iroh endpoint
  exists only during transfers. No WebView, no Tauri. Budget: < 5 MB private
  working set, < 0.5 MB/day network (`docs/resource-budget.md`).
- `warpshot-ui.exe`: Tauri v2 + React/TypeScript. It is started from the tray and exits
  when closed. It is stateless and talks to the agent via JSON-RPC over a named
  pipe whose ACL allows only the current user.

## Consequences

- The idle cost stays minimal, while UI development keeps the most agent-friendly
  stack (React/TS).
- Process isolation: a WebView bug cannot touch keys, because the UI never holds them.
- ✗ Two binaries and an IPC protocol to maintain.
- ✗ Opening settings costs a WebView2 cold start (~0.5–1 s).

## Alternatives

- **A single Tauri app with a tray and a hidden window:** the always-resident
  Tauri runtime is heavier, and the memory a window used is not reliably returned.
- **A native settings UI (Slint or egui) in the agent process:** lighter while
  open, but slower to build with agents, and its memory stays in the resident process.
- **A local HTTP server with the browser as the UI:** adds a local attack surface
  (CSRF, DNS rebinding).
