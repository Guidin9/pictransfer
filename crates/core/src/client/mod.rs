//! Server client (protocol §6): HTTP/1.1 REST and the WebSocket.
//!
//! - [`Client`] signs every request with §6.1 and exposes the §6.2 endpoints.
//! - [`Client::websocket`] starts the §6.3 session task (keepalive, reconnect
//!   with backoff); events arrive on a channel and requests go through a
//!   [`ws::WsHandle`].
//!
//! Everything runs on the caller's tokio runtime (a `current_thread` runtime
//! in the agent) and starts no threads or timers of its own besides the
//! keepalive. Nothing here logs. Errors carry kinds and §6.8 codes only:
//! never URLs, headers, tokens, envelopes or bodies.

pub mod api;
pub mod http;
pub mod json;
mod sha1;
mod transport;
pub mod ws;

use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use zeroize::Zeroizing;

use crate::{
    b64u,
    keys::{EndpointId, IdentityKey},
    log::{GroupId, Head, RecordId},
};

pub use api::{DevicePresence, LogPage, Via};
pub use ws::{DisconnectReason, Event, WsConfig, WsHandle};

/// Per-request timeout (connect, TLS, request and response).
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Default cap on an HTTP response (head + body).
pub const MAX_RESPONSE: usize = 64 * 1024;
/// §10: maximum WebSocket message.
pub const MAX_WS_MESSAGE: usize = 64 * 1024;

/// §6.8 error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    BadRequest,
    Unauthenticated,
    NotMember,
    NotAllowed,
    NoGroup,
    HeadMoved,
    Exists,
    TooLarge,
    InvalidRecord,
    RateLimited,
    Internal,
    /// A code this client does not know (or none at all).
    Unknown,
}

impl ErrorCode {
    pub fn parse(s: &str) -> Self {
        match s {
            "bad-request" => Self::BadRequest,
            "unauthenticated" => Self::Unauthenticated,
            "not-member" => Self::NotMember,
            "not-allowed" => Self::NotAllowed,
            "no-group" => Self::NoGroup,
            "head-moved" => Self::HeadMoved,
            "exists" => Self::Exists,
            "too-large" => Self::TooLarge,
            "invalid-record" => Self::InvalidRecord,
            "rate-limited" => Self::RateLimited,
            "internal" => Self::Internal,
            _ => Self::Unknown,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::BadRequest => "bad-request",
            Self::Unauthenticated => "unauthenticated",
            Self::NotMember => "not-member",
            Self::NotAllowed => "not-allowed",
            Self::NoGroup => "no-group",
            Self::HeadMoved => "head-moved",
            Self::Exists => "exists",
            Self::TooLarge => "too-large",
            Self::InvalidRecord => "invalid-record",
            Self::RateLimited => "rate-limited",
            Self::Internal => "internal",
            Self::Unknown => "unknown",
        }
    }

    /// The device is not (or no longer) allowed in the group: retrying does not help.
    pub fn is_permanent(self) -> bool {
        matches!(self, Self::NotMember | Self::NoGroup | Self::NotAllowed)
    }
}

/// Client errors. Kinds and codes only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientError {
    /// The base URL is not `https://host[:port]` (or `http://` on loopback).
    Url,
    /// A local argument is out of range (envelope size, ttl, token charset).
    Argument,
    /// DNS or TCP connect failed.
    Connect,
    /// TLS setup or handshake failed.
    Tls,
    /// Read or write failed, or the connection closed early.
    Io,
    Timeout,
    /// The response exceeded its size cap.
    ResponseTooLarge,
    /// The response is not valid HTTP/1.1 or WebSocket.
    Protocol,
    /// The response body does not have the expected shape.
    Malformed,
    /// The server answered with a §6.8 error.
    Server {
        status: u16,
        code: ErrorCode,
    },
    /// The WebSocket session task has ended.
    Closed,
    /// The WebSocket is not connected; retry after [`Event::Connected`].
    NotConnected,
    /// Random number generator failure.
    Rng,
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Server { status, code } => write!(f, "server {status} {}", code.as_str()),
            other => fmt::Debug::fmt(other, f),
        }
    }
}

impl std::error::Error for ClientError {}

/// Network counters for idle measurement (bytes as seen by the TCP socket,
/// i.e. including TLS and HTTP/WebSocket framing, excluding TCP/IP headers).
#[derive(Debug, Default)]
pub struct Counters {
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    pub http_requests: AtomicU64,
    pub ws_connects: AtomicU64,
    pub ws_disconnects: AtomicU64,
    pub pings: AtomicU64,
    pub pongs: AtomicU64,
    pub missed_pongs: AtomicU64,
    /// Server messages that were ignored as malformed.
    pub malformed: AtomicU64,
}

/// A copy of [`Counters`] at one point in time.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CounterSnapshot {
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub http_requests: u64,
    pub ws_connects: u64,
    pub ws_disconnects: u64,
    pub pings: u64,
    pub pongs: u64,
    pub missed_pongs: u64,
    pub malformed: u64,
}

impl Counters {
    pub fn snapshot(&self) -> CounterSnapshot {
        let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
        CounterSnapshot {
            bytes_in: g(&self.bytes_in),
            bytes_out: g(&self.bytes_out),
            http_requests: g(&self.http_requests),
            ws_connects: g(&self.ws_connects),
            ws_disconnects: g(&self.ws_disconnects),
            pings: g(&self.pings),
            pongs: g(&self.pongs),
            missed_pongs: g(&self.missed_pongs),
            malformed: g(&self.malformed),
        }
    }

    pub(crate) fn inc(a: &AtomicU64) {
        a.fetch_add(1, Ordering::Relaxed);
    }
}

/// Parsed base URL: `https://host[:port]`, or `http://` for loopback hosts
/// (local `wrangler dev`). No path (other than `/`), query, fragment or userinfo.
#[derive(Clone, PartialEq, Eq)]
pub struct ServerUrl {
    pub(crate) tls: bool,
    /// Host as used for DNS and SNI (IPv6 without brackets).
    pub(crate) host: String,
    pub(crate) port: u16,
}

impl fmt::Debug for ServerUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Deployment config is not a secret, but keep it out of debug output
        // anyway (ADR 0007: the server address is private deployment data).
        write!(f, "ServerUrl(tls={})", self.tls)
    }
}

impl ServerUrl {
    pub fn parse(s: &str) -> Result<Self, ClientError> {
        let (tls, rest) = if let Some(r) = s.strip_prefix("https://") {
            (true, r)
        } else if let Some(r) = s.strip_prefix("http://") {
            (false, r)
        } else {
            return Err(ClientError::Url);
        };
        let authority = match rest.strip_suffix('/') {
            Some(a) => a,
            None => rest,
        };
        if authority.is_empty()
            || !authority
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-' | b':' | b'[' | b']'))
        {
            return Err(ClientError::Url);
        }
        let default_port = if tls { 443 } else { 80 };
        let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
            let (h, after) = v6.split_once(']').ok_or(ClientError::Url)?;
            let port = match after {
                "" => default_port,
                p => parse_port(p.strip_prefix(':').ok_or(ClientError::Url)?)?,
            };
            if h.parse::<std::net::Ipv6Addr>().is_err() {
                return Err(ClientError::Url);
            }
            (h.to_string(), port)
        } else {
            match authority.split_once(':') {
                Some((h, p)) => (h.to_string(), parse_port(p)?),
                None => (authority.to_string(), default_port),
            }
        };
        if host.is_empty() || host.contains('[') || host.contains(']') {
            return Err(ClientError::Url);
        }
        let url = Self { tls, host, port };
        // §6: HTTPS only. Plain HTTP is allowed for loopback development servers.
        if !tls && !url.is_loopback() {
            return Err(ClientError::Url);
        }
        Ok(url)
    }

    fn is_loopback(&self) -> bool {
        self.host.eq_ignore_ascii_case("localhost")
            || self
                .host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    }

    /// The `Host` header value.
    pub(crate) fn host_header(&self) -> String {
        let h = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        let default = if self.tls { 443 } else { 80 };
        if self.port == default {
            h
        } else {
            format!("{h}:{}", self.port)
        }
    }
}

fn parse_port(p: &str) -> Result<u16, ClientError> {
    if p.is_empty() || !p.bytes().all(|c| c.is_ascii_digit()) || p.starts_with('0') {
        return Err(ClientError::Url);
    }
    p.parse::<u16>().map_err(|_| ClientError::Url)
}

/// The operator admission token (§6.1). Never printed.
#[derive(Clone)]
pub struct CreateToken(Zeroizing<String>);

impl CreateToken {
    /// Header-safe tokens only (visible ASCII, no spaces), at most 256 bytes.
    pub fn new(token: &str) -> Result<Self, ClientError> {
        if token.is_empty() || token.len() > 256 || !token.bytes().all(|c| c.is_ascii_graphic()) {
            return Err(ClientError::Argument);
        }
        Ok(Self(Zeroizing::new(token.to_string())))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for CreateToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CreateToken(<redacted>)")
    }
}

pub(crate) struct Inner {
    pub(crate) url: ServerUrl,
    pub(crate) ik: Arc<IdentityKey>,
    pub(crate) create_token: Option<CreateToken>,
    pub(crate) counters: Arc<Counters>,
    /// Last `ts` used in a signature; `ts` is strictly increasing so two
    /// requests in the same millisecond never repeat `(id, ts, sig)` (§6.1 replay).
    last_ts: AtomicU64,
    clock: fn() -> u64,
}

impl Inner {
    pub(crate) fn next_ts(&self) -> u64 {
        let now = (self.clock)();
        let prev = self
            .last_ts
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |last| {
                Some(now.max(last.saturating_add(1)))
            })
            .unwrap_or(now);
        now.max(prev.saturating_add(1))
    }

    pub(crate) fn sign(&self, method: &str, target: &str, body: &[u8]) -> String {
        let ts = self.next_ts();
        crate::server_auth::authorization(&self.ik, method, target, ts, body)
    }
}

/// The server client. Cheap to clone; clones share counters and the clock.
#[derive(Clone)]
pub struct Client {
    pub(crate) inner: Arc<Inner>,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Client({:?})", self.inner.ik.endpoint_id())
    }
}

impl Client {
    pub fn new(base_url: &str, ik: Arc<IdentityKey>) -> Result<Self, ClientError> {
        Ok(Self {
            inner: Arc::new(Inner {
                url: ServerUrl::parse(base_url)?,
                ik,
                create_token: None,
                counters: Arc::new(Counters::default()),
                last_ts: AtomicU64::new(0),
                clock: crate::net::store::now_ms,
            }),
        })
    }

    /// Adds the operator admission token sent with `POST /v1/groups`.
    pub fn with_create_token(self, token: CreateToken) -> Self {
        self.rebuild(|i| i.create_token = Some(token))
    }

    /// Replaces the wall clock (ms since the epoch); for tests.
    pub fn with_clock(self, clock: fn() -> u64) -> Self {
        self.rebuild(|i| i.clock = clock)
    }

    fn rebuild(self, f: impl FnOnce(&mut Inner)) -> Self {
        let i = &self.inner;
        let mut n = Inner {
            url: i.url.clone(),
            ik: i.ik.clone(),
            create_token: i.create_token.clone(),
            counters: i.counters.clone(),
            last_ts: AtomicU64::new(i.last_ts.load(Ordering::Relaxed)),
            clock: i.clock,
        };
        f(&mut n);
        Self { inner: Arc::new(n) }
    }

    pub fn endpoint_id(&self) -> EndpointId {
        self.inner.ik.endpoint_id()
    }

    pub fn counters(&self) -> CounterSnapshot {
        self.inner.counters.snapshot()
    }
}

/// `gid` path segment (§6): `b64u(group_id)`, 22 characters.
pub(crate) fn gid_segment(gid: &GroupId) -> String {
    b64u::encode(&gid.0)
}

/// Strict `Head` = `{"seq": n, "id": b64u}` with a 32-byte id.
pub(crate) fn parse_head(v: &json::Value) -> Result<Head, ClientError> {
    let seq = v
        .get("seq")
        .and_then(json::Value::as_u64)
        .ok_or(ClientError::Malformed)?;
    let id = v
        .get("id")
        .and_then(json::Value::as_str)
        .and_then(b64u::decode)
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .ok_or(ClientError::Malformed)?;
    Ok(Head {
        seq,
        id: RecordId(id),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn url_parsing() {
        let u = ServerUrl::parse("https://warpshot.example.workers.dev").unwrap();
        assert!(u.tls);
        assert_eq!(u.port, 443);
        assert_eq!(u.host_header(), "warpshot.example.workers.dev");
        let u = ServerUrl::parse("https://h.example:8443/").unwrap();
        assert_eq!((u.port, u.host_header().as_str()), (8443, "h.example:8443"));
        let u = ServerUrl::parse("http://127.0.0.1:8787").unwrap();
        assert!(!u.tls);
        assert_eq!(u.host_header(), "127.0.0.1:8787");
        let u = ServerUrl::parse("http://[::1]:8787").unwrap();
        assert_eq!(
            (u.host.as_str(), u.host_header().as_str()),
            ("::1", "[::1]:8787")
        );
        assert!(ServerUrl::parse("http://localhost:8787").is_ok());
        for bad in [
            "",
            "ftp://x",
            "https://",
            "https:///",
            "http://example.com",
            "http://10.0.0.1:8787",
            "https://h/v1",
            "https://h?x",
            "https://h#x",
            "https://u@h",
            "https://h:",
            "https://h:0",
            "https://h:080",
            "https://h:65536",
            "https://[::1",
            "https://[zz]",
            "https://h:1:2",
            "https://h\r\nX: y",
            "https://h x",
        ] {
            assert!(ServerUrl::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn ts_strictly_increasing_and_debug_redacted() {
        let ik = Arc::new(IdentityKey::from_secret(&[3; 32]));
        let c = Client::new("https://h.example", ik)
            .unwrap()
            .with_clock(|| 1000);
        let a = c.inner.next_ts();
        let b = c.inner.next_ts();
        assert_eq!((a, b), (1000, 1001));
        let t = CreateToken::new("s3cret-token").unwrap();
        assert!(!format!("{t:?}").contains("s3cret"));
        let c = c.with_create_token(t);
        assert!(!format!("{c:?}").contains("h.example"));
        assert!(!format!("{:?}", c.inner.url).contains("h.example"));
        assert_eq!(c.inner.next_ts(), 1002);
        assert!(CreateToken::new("a b").is_err());
        assert!(CreateToken::new("a\r\nb").is_err());
        assert!(CreateToken::new("").is_err());
    }

    #[test]
    fn error_codes_roundtrip() {
        for c in [
            ErrorCode::BadRequest,
            ErrorCode::Unauthenticated,
            ErrorCode::NotMember,
            ErrorCode::NotAllowed,
            ErrorCode::NoGroup,
            ErrorCode::HeadMoved,
            ErrorCode::Exists,
            ErrorCode::TooLarge,
            ErrorCode::InvalidRecord,
            ErrorCode::RateLimited,
            ErrorCode::Internal,
        ] {
            assert_eq!(ErrorCode::parse(c.as_str()), c);
        }
        assert_eq!(ErrorCode::parse("whatever"), ErrorCode::Unknown);
    }
}
