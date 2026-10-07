# ADR 0004 — Cloudflare Worker + Durable Object for auth, log, presence and wake

- Status: Accepted · 2026-10-07

## Context

- A sleeping phone can only be reached through a push service (FCM), and sending
  FCM needs server-held credentials.
- An idle PC must be reachable from anywhere with almost no traffic, so the iroh
  endpoint is not kept open (ADR 0003).
- The membership log needs a serialization point.
- The budget is $0.

## Decision

- One **Cloudflare Worker**, with one **SQLite-backed Durable Object per group**.
  It handles request auth (Ed25519 signatures), the log store with
  compare-and-swap, `last_seen` and presence, and wake routing (WebSocket if
  connected, otherwise FCM HTTP v1).
- The PC keeps one **hibernating** WebSocket. Keepalive uses
  `setWebSocketAutoResponse`, so idle sockets do not wake the object and incur no
  duration charges.
- The server never sees content, names of items, or addresses: wakes are
  end-to-end-encrypted envelopes. It stores records, push tokens and `last_seen` only.

## Consequences

- $0 on Workers Free (100k requests/day; DO free tier with hibernation).
  Expected idle traffic for the PC is ≈ 0.2–0.3 MB/day.
- Presence is cheap: the online state of WebSocket-connected devices plus
  `last_seen`, fetched only on request.
- Self-hosting is possible later with `workerd`.
- ✗ Metadata is visible to Cloudflare (threat model §4).
- ✗ The idle-timeout behavior of hibernated sockets and the billing of
  auto-responses must be measured (Spike C).

## Alternatives

- **Keep the iroh endpoint up on the PC with n0 relays and DNS discovery:**
  continuous relay keepalives and net-report probing — idle traffic and RAM above budget.
- **Windows Push (WNS):** zero marginal idle traffic, but complex for unpackaged
  Win32 apps (Entra app registration, Windows App SDK). A Faz 3+ option.
- **Supabase or Firebase backends:** free tiers pause or are less suitable for
  hibernating sockets; less control.
