# ADR 0002 — Passwordless device group with a signed linear membership log

- Status: Accepted · 2026-10-07

## Context

The user must see their devices and send to them. Priorities are the fewest steps,
$0 server cost and security above market standard. The app stores no cloud data,
so there is nothing to "recover" if all devices are lost.

## Decision

- No accounts, emails or passwords. A **group** is formed by QR pairing. The
  first pairing creates it, and a new device joins by scanning a QR code with
  confirmation on both devices.
- Membership is defined only by a **linear, hash-chained log of member-signed
  records** (`genesis`, `add`, `remove`, `update`; protocol §4). Any member may
  append. The server serializes appends with compare-and-swap but is not trusted:
  clients validate the full log and detect forks through head comparison during P2P handshakes.
- Every `add` alerts all members, with a "This wasn't me" action.

## Consequences

- There is no password database to leak and nothing to phish. The server cannot
  add devices. Onboarding is a single scan.
- The linear log rules out backdated operations from a removed device (it is
  not a member at later `seq`). Forks are detectable instead of silently merged.
- ✗ Membership changes need the server online (v1).
- ✗ A malicious server can equivocate. This is detected (alert plus transfer
  block), not prevented.
- ✗ If all devices are lost, the user creates a new group. That is acceptable:
  nothing is stored.

## Alternatives

- **E-mail + passkey account plus device approval:** more steps, a user database,
  higher cost and attack surface.
- **OAuth (Google/Apple/GitHub):** a third-party dependency and metadata sharing.
- **DAG/CRDT membership with concurrent ops:** removal semantics under
  concurrency are subtle. A compromised device can backdate operations, which
  needs seniority rules. Rejected for complexity.
- **Single primary device:** simple, but a lost primary strands the group, and
  the PC could not remove a lost phone.
