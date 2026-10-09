//! Warpshot core: protocol encodings, crypto, membership log, pairing and
//! transfers. The normative specification is `docs/protocol.md`.

pub mod b64u;
pub mod cbor;
pub mod client;
pub mod keys;
pub mod log;
pub mod net;
pub mod pair;
pub mod sanitize;
pub mod server_auth;
#[cfg(test)]
mod vectors;
pub mod wake;
pub mod xfer;
