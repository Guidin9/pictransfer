# ADR 0008 — Crate choices: X-Wing, CBOR, SQLite

- Status: Accepted · 2026-10-09
- Evidence: Spike A (A7) and the F0-10 review, run against the crate sources in
  the cargo registry and the official X-Wing test vectors.

## X-Wing: RustCrypto `x-wing`

| | `x-wing` 0.1.1 | `libcrux-kem` 0.0.10 |
|---|---|---|
| Spec | draft-06 | draft-06 (`XWingKemDraft06`) |
| Official vectors (3) | pass | pass |
| All-zero X25519 output | rejected by `DecapsulationKeyRejectNonContrib`; the default `DecapsulationKey` accepts it | rejected |
| Zeroize | seed wiped on drop; ML-KEM and X25519 secrets zeroize on drop; the returned shared key is not wiped (the caller does it) | none: the private seed is a public field without `Drop`, the combiner builds an unwiped `Vec` |
| License | Apache-2.0 OR MIT | Apache-2.0 |
| Threads / globals | none | CPU-feature flags in `AtomicBool`s |
| Audit | not audited | ML-KEM formally verified; the KEM wrapper is labelled pre-verification |

Decision: `x-wing` with the `zeroize` feature, `DecapsulationKeyRejectNonContrib`
for decapsulation, `hazmat` (deterministic encapsulation) only in tests. Our
zeroize invariant rules out `libcrux-kem` as it is today.

Spec status: draft-connolly-cfrg-xwing-kem-11 (2026-09-23) keeps the draft-06
combiner, encodings and vectors. Standardisation continues in
draft-irtf-cfrg-concrete-hybrid-kems (MLKEM768-X25519, stated identical to
X-Wing). The CFRG asked for a normative rule on an all-zero X25519 output;
protocol §2.1 now requires rejecting it, as RFC 9180 does.

## CBOR: hand-written strict codec

Neither candidate enforces protocol §1: `minicbor` 2.x accepts non-shortest
integers and has no depth limit, duplicate-key or key-order checks; `ciborium`
0.2.2 has been unreleased since 2024 and accepts non-shortest headers. Our subset
is small (unsigned integers, byte strings, text, arrays, maps with integer keys),
so `warpshot-core` gets its own encoder and decoder (~300 lines) with one negative
test per rule and a fuzz target. No dependency, no license question
(`minicbor`'s BlueOak-1.0.0 is not on the FSF list).

## SQLite: `rusqlite` with `bundled`

`rusqlite` 0.40 + `libsqlite3-sys` 0.38 (MIT), bundled SQLite 3.53 (public
domain). Builds on MSVC and for Android (`cargo ndk -t arm64-v8a -P 29`, NDK r30).
SQLite starts no threads (`SQLITE_DEFAULT_WORKER_THREADS=0`). Extension loading
stays disabled at runtime.

## Related finding: TLS key exchange in iroh

With `tls-ring` (our choice, and iroh's default) the rustls provider offers only
X25519, P-256 and P-384, so iroh's TLS is classical. X25519MLKEM768 needs the
`tls-aws-lc-rs` backend (not cached, C/asm build, idle-budget impact unknown);
iroh 1.3 then lets an endpoint require it and a connection can check the
negotiated group. This does not change ADR 0005: wake envelopes never travel
over TLS and need X-Wing anyway, and the inner layer keeps transfers safe
independent of the TLS backend. Revisit "prefer PQ in TLS as well" in Faz 3.
