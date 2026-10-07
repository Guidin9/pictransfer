# Development setup (Windows)

Everything that needs a large download is done in **one session on a fast
connection** with `scripts/setup-dev.ps1`. Until then we work on the specs and on
the parts that need no toolchain.

## 1. What gets downloaded

Sizes are estimates. Check the totals after the first run and correct this table.

| Item | Needed for | Download | Disk |
|---|---|---|---|
| VS 2022 Build Tools — **only** MSVC x64/x86 + Windows 11 SDK (no "recommended" extras) | Windows builds: linker, C compiler, SDK import libraries | ~2 GB | ~5 GB |
| Rust via rustup — stable, `minimal` profile + clippy + rustfmt | all Rust code | ~150–250 MB | ~1 GB |
| Cargo dependencies, first build (iroh, tokio, windows, rusqlite, tauri …) | building | ~300–500 MB | 3–6 GB (`target/`) |
| Server dev deps (`wrangler`, `vitest`) | `server/` | ~100–150 MB | ~300 MB |
| UI deps (Tauri CLI, React, Vite) | `apps/windows-ui` | ~100–150 MB | ~400 MB |
| Android NDK + command-line tools | Rust for Android | ~1 GB | ~3 GB |
| Gradle, AGP, Kotlin, Compose, Firebase | `apps/android` | ~0.7–1 GB | ~2 GB |
| **Total** | | **≈ 4.5–5.5 GB** | |

Already present on this machine: Git, Node 26, Python 3.11, Android Studio with
SDK platform 37, build-tools 36, an emulator image with Play Store, and WebView2.

## 2. Why MSVC Build Tools are required

On Windows, the Rust compiler links `.exe` files with Microsoft's linker
(`link.exe`) against the Windows SDK import libraries. Several dependencies also
compile C or assembly code — the TLS/crypto backends and SQLite — so they need a
C compiler. Tauri officially requires the MSVC toolchain. The minimal component
set above is a fraction of the ~6 GB "Desktop development with C++" default.

Alternatives considered:
- **llvm-mingw + the `gnullvm` target** (~150 MB). Rejected: Tauri/WebView2 and
  some crates are poorly supported, which risks lost time and different behavior
  from release builds.
- **Build only in GitHub Actions** (nothing installed locally). Rejected: every
  iteration takes minutes, which kills the fast agentic edit–build–test loop.
  CI is still used for release builds and gates.

## 3. One-shot setup

```powershell
# Preview — downloads nothing:
powershell -ExecutionPolicy Bypass -File scripts\setup-dev.ps1 -DryRun
# Windows toolchain only (MSVC + Rust):
powershell -ExecutionPolicy Bypass -File scripts\setup-dev.ps1
# Also the Android NDK (needs Android Studio's SDK; installs cmdline-tools first if missing):
powershell -ExecutionPolicy Bypass -File scripts\setup-dev.ps1 -Android
```

The script is idempotent: it skips anything already installed. The VS Build Tools
installer shows one UAC prompt.

## 4. Accounts (free, created by the user)

- **Cloudflare:** run `npx wrangler login` in `server/` (opens the browser). The
  Workers Free plan is enough.
- **Firebase:** create a project, add the Android app (package id to be decided),
  enable Cloud Messaging and create a service-account key for the FCM HTTP v1 API.
  Then:
  - `google-services.json` stays local (git-ignored). CI injects it from a secret.
  - The service-account JSON goes only into the Worker: `npx wrangler secret put FCM_SERVICE_ACCOUNT`.

## 5. Verify

```powershell
rustc -vV          # host: x86_64-pc-windows-msvc
cargo --version
cargo new $env:TEMP\pt-hello; cargo run --manifest-path $env:TEMP\pt-hello\Cargo.toml   # builds & links without extra downloads
node --version     # ≥ 22 (built-in WebSocket used by spike C)
```
