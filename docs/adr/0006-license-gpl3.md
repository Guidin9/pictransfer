# ADR 0006 — GPL-3.0-or-later with a Google Play Services linking permission

- Status: Accepted · 2026-10-07

## Context

The user wants open source and chose GPL-3.0. The Android app uses FCM, whose
client libraries depend on proprietary Google Play Services.

## Decision

- License: **GPL-3.0-or-later** (`LICENSE`).
- A GPL §7 additional permission allows combining the program with the Google
  Play Services and Firebase client libraries (`LICENSE-ADDITIONAL-PERMISSION.md`).
- Dependencies must be GPL-3.0-compatible: MIT, Apache-2.0, BSD, ISC, Zlib,
  MPL-2.0, LGPL and similar. This is enforced by `cargo-deny` and an npm license check.
- External contributions are accepted under the same terms (inbound = outbound).
  Contributions to the linking permission need sign-off from the copyright holders.

## Consequences

- Modified redistributions must stay open, which makes closed adware clones harder.
- ✗ F-Droid does not accept FCM builds. A UnifiedPush flavor is planned.
- "or-later" follows the FSF recommendation. If the user prefers GPL-3.0-only,
  change the SPDX identifiers and README before the first release.
