//! Server request authentication (protocol §6.1): the canonical string, the
//! `Authorization: WARP1 …` header, and its strict parser.

use sha2::{Digest, Sha256};

use crate::{
    b64u,
    keys::{EndpointId, IdentityKey, verify_strict},
};

pub const SERVER_AUTH_LABEL: &[u8] = b"warpshot/server-auth/v1\0";
pub const MAX_SKEW_MS: u64 = 120 * 1000;

/// `signed` bytes for a request.
pub fn canonical(method: &str, path_and_query: &str, ts: u64, body: &[u8]) -> Vec<u8> {
    let digest: String = Sha256::digest(body)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let mut s = SERVER_AUTH_LABEL.to_vec();
    s.extend_from_slice(format!("{method}\n{path_and_query}\n{ts}\n{digest}").as_bytes());
    s
}

/// The `Authorization` header value for a request.
pub fn authorization(
    ik: &IdentityKey,
    method: &str,
    path_and_query: &str,
    ts: u64,
    body: &[u8],
) -> String {
    let sig = ik.sign(&canonical(method, path_and_query, ts, body));
    format!(
        "WARP1 id={}, ts={ts}, sig={}",
        b64u::encode(&ik.endpoint_id().0),
        b64u::encode(&sig)
    )
}

/// Parsed header fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthHeader {
    pub id: EndpointId,
    pub ts: u64,
    pub sig: [u8; 64],
}

/// Strict parse of the header value; `None` on any deviation.
pub fn parse(header: &str) -> Option<AuthHeader> {
    let rest = header.strip_prefix("WARP1 id=")?;
    let (id, rest) = rest.split_once(", ts=")?;
    let (ts, sig) = rest.split_once(", sig=")?;
    if ts.is_empty()
        || !ts.bytes().all(|c| c.is_ascii_digit())
        || (ts.len() > 1 && ts.starts_with('0'))
    {
        return None;
    }
    let ts: u64 = ts.parse().ok()?;
    let id: [u8; 32] = b64u::decode(id)?.try_into().ok()?;
    let sig: [u8; 64] = b64u::decode(sig)?.try_into().ok()?;
    Some(AuthHeader {
        id: EndpointId(id),
        ts,
        sig,
    })
}

/// Signature and clock checks (membership and replay are the server's job).
pub fn verify(
    h: &AuthHeader,
    method: &str,
    path_and_query: &str,
    body: &[u8],
    now_ms: u64,
) -> bool {
    now_ms.abs_diff(h.ts) <= MAX_SKEW_MS
        && verify_strict(
            &h.id,
            &canonical(method, path_and_query, h.ts, body),
            &h.sig,
        )
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_tamper() {
        let ik = IdentityKey::from_secret(&[1; 32]);
        let h = authorization(&ik, "POST", "/v1/groups/abc/log", 1_000, b"{}");
        let p = parse(&h).unwrap();
        assert_eq!(p.id, ik.endpoint_id());
        assert!(verify(&p, "POST", "/v1/groups/abc/log", b"{}", 1_000));
        assert!(!verify(&p, "GET", "/v1/groups/abc/log", b"{}", 1_000));
        assert!(!verify(&p, "POST", "/v1/groups/abc/log?x", b"{}", 1_000));
        assert!(!verify(&p, "POST", "/v1/groups/abc/log", b"{ }", 1_000));
        assert!(verify(
            &p,
            "POST",
            "/v1/groups/abc/log",
            b"{}",
            1_000 + MAX_SKEW_MS
        ));
        assert!(!verify(
            &p,
            "POST",
            "/v1/groups/abc/log",
            b"{}",
            1_000 + MAX_SKEW_MS + 1
        ));
    }

    #[test]
    fn strict_header_parsing() {
        let ik = IdentityKey::from_secret(&[1; 32]);
        let h = authorization(&ik, "GET", "/", 42, b"");
        assert!(parse(&h).is_some());
        for bad in [
            h.replace("WARP1 ", "WARP2 "),
            h.replace("WARP1 ", "warp1 "),
            h.replace(", ts=", ",ts="),
            h.replace("ts=42", "ts=042"),
            h.replace("ts=42", "ts=+42"),
            h.replace("ts=42", "ts="),
            format!("{h} "),
            format!(" {h}"),
            h.replace(", sig=", ", sig==").to_string(),
        ] {
            assert!(parse(&bad).is_none(), "{bad}");
        }
    }
}
