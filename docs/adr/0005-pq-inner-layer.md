# ADR 0005 — Post-quantum hybrid inner encryption layer

- Status: Accepted · 2026-10-07

## Context

"Security above market standard" is a hard requirement. Transport TLS 1.3 key
exchange (X25519) is vulnerable to harvest-now-decrypt-later by a future quantum
computer. Comparable apps (AirDrop, Quick Share, LocalSend, KDE Connect) rely on
classical TLS or DTLS only.

## Decision

Inside iroh's TLS, run a second handshake:

- an ephemeral **X-Wing** key exchange (X25519 + ML-KEM-768, draft-06);
- binding to the TLS session through `export_keying_material`;
- HKDF-SHA-256 key derivation;
- **ChaCha20-Poly1305 STREAM** for item data (64 KiB chunks);
- BLAKE3 for end-to-end integrity.

Wake envelopes use the same KEM-DEM construction, addressed to the recipient's
static X-Wing key and signed by the sender (protocol §7–8).

## Consequences

- Recorded traffic stays confidential unless both X25519 **and** ML-KEM-768 are
  broken. There is forward secrecy for every connection.
- Defense in depth: a TLS-layer bug alone does not expose content.
- ✗ Authentication stays classical (Ed25519). Post-quantum signatures (hybrid
  ML-DSA) are future work.
- ✗ The X-Wing implementations are young. Use test vectors and choose between
  `libcrux-kem` (formally verified ML-KEM) and RustCrypto `x-wing` in Spike A.
- Cost: ~2.3 KB per handshake and a second AEAD pass, which is negligible
  (ChaCha20-Poly1305 runs at GB/s on these CPUs).

## Alternatives

- **TLS only, relying on rustls' X25519MLKEM768:** whether the iroh build
  negotiates it is not guaranteed, and it is not under our control.
- **Noise with a PQ extension:** less standard tooling in Rust.
