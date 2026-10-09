//! iroh networking: endpoint configuration (§9), framing (§8.2), transfer
//! sessions (§8) and pairing (§5).

pub mod pair;
pub mod store;
pub mod xfer;

use std::{fmt, time::Duration};

use iroh::{
    Endpoint, EndpointAddr, RelayMode, SecretKey, TransportAddr,
    endpoint::{Connection, RecvStream, SendStream, VarInt, presets},
};

use crate::{
    keys::{EndpointId, IdentityKey},
    log::LogError,
    pair::PairError,
    wake::DialInfo,
    xfer::{MAX_FRAME, XferError, code},
};

/// Errors carry codes and kinds only — never content, names or addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetError {
    Bind,
    Connect,
    /// The peer is not the expected identity or not a member.
    Identity,
    /// A stream operation failed; the tag names the operation.
    Stream(&'static str),
    /// The connection was closed with this application code.
    Closed(u32),
    Timeout,
    TooLarge,
    Xfer(XferError),
    Log(LogError),
    Pair(PairError),
    Io(std::io::ErrorKind),
    /// Fork detected during sync (§4.5): stop and alert.
    Fork,
    Declined(u64),
    Rejected,
    State(&'static str),
}

impl NetError {
    pub fn close_code(&self) -> u32 {
        match self {
            NetError::Identity => code::NOT_MEMBER,
            NetError::Timeout => code::TIMEOUT,
            NetError::TooLarge => code::TOO_LARGE,
            NetError::Xfer(e) => e.close_code(),
            NetError::Fork => code::GROUP_FORK,
            NetError::Pair(PairError::Expired) => code::PAIR_EXPIRED,
            NetError::Pair(_) => code::PAIR_PROOF,
            NetError::Rejected => code::PAIR_REJECTED,
            NetError::Closed(c) => *c,
            _ => code::PROTOCOL,
        }
    }
}

impl fmt::Display for NetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl std::error::Error for NetError {}

impl From<XferError> for NetError {
    fn from(e: XferError) -> Self {
        Self::Xfer(e)
    }
}

impl From<LogError> for NetError {
    fn from(e: LogError) -> Self {
        Self::Log(e)
    }
}

impl From<PairError> for NetError {
    fn from(e: PairError) -> Self {
        Self::Pair(e)
    }
}

impl From<std::io::Error> for NetError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.kind())
    }
}

/// Relay choice (§9: one region; Spike A picked the n0 EU relay).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Relay {
    Eu,
    /// No relay: direct addresses only (LAN tests, `relay_data = off` experiments).
    Disabled,
}

pub fn relay_url(relay: Relay) -> Option<iroh::RelayUrl> {
    match relay {
        Relay::Eu => Some(iroh::defaults::prod::default_eu_relay().url),
        Relay::Disabled => None,
    }
}

/// Binds an endpoint per §9: device key, our ALPNs, a single relay region and
/// no address lookup. Addresses travel only in QR codes and wake envelopes.
pub async fn bind(ik: &IdentityKey, relay: Relay) -> Result<Endpoint, NetError> {
    let sk = SecretKey::from_bytes(&ik.secret());
    let relay_mode = match relay_url(relay) {
        Some(u) => RelayMode::custom([u]),
        None => RelayMode::Disabled,
    };
    Endpoint::builder(presets::Minimal)
        .secret_key(sk)
        .relay_mode(relay_mode)
        .clear_address_lookup()
        .alpns(vec![crate::xfer::ALPN.to_vec(), crate::pair::ALPN.to_vec()])
        .bind()
        .await
        .map_err(|_| NetError::Bind)
}

/// Our dial info: the configured relay plus current direct addresses.
pub fn dial_info(ep: &Endpoint) -> DialInfo {
    let addr = ep.addr();
    DialInfo {
        relay: addr.relay_urls().next().map(|u| u.to_string()),
        addrs: addr.ip_addrs().copied().take(8).collect(),
    }
}

pub fn endpoint_id(ep: &Endpoint) -> EndpointId {
    EndpointId(*ep.id().as_bytes())
}

/// Builds the iroh address for a peer from its id and dial info.
pub fn endpoint_addr(id: &EndpointId, dial: &DialInfo) -> Result<EndpointAddr, NetError> {
    let pk = iroh::PublicKey::from_bytes(&id.0).map_err(|_| NetError::Identity)?;
    let mut addrs: Vec<TransportAddr> = dial.addrs.iter().map(|a| TransportAddr::Ip(*a)).collect();
    if let Some(r) = &dial.relay {
        addrs.push(TransportAddr::Relay(
            r.parse().map_err(|_| NetError::Connect)?,
        ));
    }
    Ok(EndpointAddr::from_parts(pk, addrs))
}

/// Dials `id` and checks that TLS authenticated exactly that identity.
pub async fn connect(
    ep: &Endpoint,
    id: &EndpointId,
    dial: &DialInfo,
    alpn: &[u8],
) -> Result<Connection, NetError> {
    let addr = endpoint_addr(id, dial)?;
    let conn = tokio::time::timeout(HANDSHAKE_TIMEOUT, ep.connect(addr, alpn))
        .await
        .map_err(|_| NetError::Timeout)?
        .map_err(|_| NetError::Connect)?;
    if conn.remote_id().as_bytes() != &id.0 {
        conn.close(VarInt::from_u32(code::NOT_MEMBER), b"");
        return Err(NetError::Identity);
    }
    Ok(conn)
}

pub fn remote_id(conn: &Connection) -> EndpointId {
    EndpointId(*conn.remote_id().as_bytes())
}

pub fn close(conn: &Connection, code: u32) {
    conn.close(VarInt::from_u32(code), b"");
}

pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// TLS exporter value (§5.3, §8.3).
pub fn ekm(conn: &Connection, label: &[u8], context: &[u8]) -> Result<[u8; 32], NetError> {
    let mut out = [0u8; 32];
    conn.export_keying_material(&mut out, label, context)
        .map_err(|_| NetError::Stream("ekm"))?;
    Ok(out)
}

/// `frame = u32be(len) ‖ payload` (§8.2).
pub async fn write_frame(s: &mut SendStream, payload: &[u8]) -> Result<(), NetError> {
    if payload.len() > MAX_FRAME {
        return Err(NetError::TooLarge);
    }
    s.write_all(&(payload.len() as u32).to_be_bytes())
        .await
        .map_err(|_| NetError::Stream("write"))?;
    s.write_all(payload)
        .await
        .map_err(|_| NetError::Stream("write"))
}

/// Reads one frame within `timeout`; the length is checked before allocating.
pub async fn read_frame(
    r: &mut RecvStream,
    max: usize,
    timeout: Duration,
) -> Result<Vec<u8>, NetError> {
    tokio::time::timeout(timeout, async {
        let mut len = [0u8; 4];
        r.read_exact(&mut len)
            .await
            .map_err(|_| NetError::Stream("read len"))?;
        let len = u32::from_be_bytes(len) as usize;
        if len > max {
            return Err(NetError::TooLarge);
        }
        let mut buf = vec![0u8; len];
        r.read_exact(&mut buf)
            .await
            .map_err(|_| NetError::Stream("read body"))?;
        Ok(buf)
    })
    .await
    .map_err(|_| NetError::Timeout)?
}
