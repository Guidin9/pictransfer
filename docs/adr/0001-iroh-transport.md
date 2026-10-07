# ADR 0001 — iroh 1.x for the P2P transport (not WebRTC)

- Status: Accepted · 2026-10-07

## Context

Phone and PC must connect directly when possible: on the same Wi-Fi, across NATs,
and through an encrypted relay only as a last resort. The relay must be optional
for data. Both main clients are native (Windows agent, Android app). A browser
client is deferred.

## Decision

Use **iroh 1.x** (1.3.0 at the time of writing; stable wire protocol since 1.0,
June 2026). Peers dial by public key (`EndpointId` = the device's Ed25519 key).
The transport is QUIC + TLS 1.3 with raw public keys, QUIC NAT traversal and
multipath, and end-to-end encrypted relays.

## Consequences

- The device identity *is* the transport identity, so we get mutual
  authentication by key without writing our own signaling, ICE or TURN logic.
  Less custom code means a smaller attack surface.
- One Rust implementation serves Windows and Android. QUIC streams give
  multiplexing and flow control, and throughput is high.
- `Connection::export_keying_material` lets the PQ inner layer bind to the TLS session.
- `Connection::paths` and `path_events` let the "direct only" policy work.
- ✗ In browsers iroh is relay-only. A future web client would always relay.
- ✗ The free n0 public relays are rate-limited. A self-hosted `iroh-relay` is the
  escape hatch (Faz 3).
- ✗ The API changed a lot before 1.0, so agents must read docs.rs for the pinned
  version instead of relying on memory.

## Alternatives

- **WebRTC data channels:** native P2P in browsers. Rejected for v1:
  - it needs a signaling server, STUN/TURN credential minting, and DTLS
    fingerprint binding to device keys;
  - native Rust WebRTC is mid-rewrite (webrtc-rs 0.17 is in maintenance, the
    sans-IO 0.20 is still a release candidate);
  - SCTP throughput is lower.

  Revisit if a P2P browser client becomes a must.
- **Custom QUIC + our own hole punching:** reinventing iroh's NAT traversal. Rejected.
