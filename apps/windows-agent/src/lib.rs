//! Win32 building blocks of the Warpshot Windows agent (`warpshot-agent.exe`):
//! tray, hotkey, clipboard, toasts, named-pipe IPC, autostart, power and
//! single-instance helpers, and the network service on top of `warpshot-core`.
//! The binary (`main.rs`) wires them into the message loop.
//!
//! Thread model (resource-budget.md §2.1): the Win32 UI thread owns windows,
//! hotkeys, the clipboard and toasts; one tokio `current_thread` runtime thread
//! owns the pipe server, the server WebSocket and transfers ([`service`]).

// Win32 FFI requires `unsafe`. The workspace forbids it; this crate denies it in
// Cargo.toml and allows it only at its crate roots (here and main.rs). Every
// unsafe block is small and carries a SAFETY comment.
#![allow(unsafe_code)]
// HWND / HKL / HMENU are opaque OS handles typed as raw pointers. We never
// dereference them; Win32 validates handles and fails cleanly on bad ones.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

pub mod autostart;
pub mod clipboard;
pub mod dpapi;
pub mod hotkey;
pub mod image;
pub mod osd;
pub mod pipe;
pub mod power;
pub mod selftest;
pub mod service;
pub mod single_instance;
pub mod toast;
pub mod tray;
pub mod win;
