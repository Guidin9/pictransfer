//! iroh networking: endpoint configuration (§9), framing (§8.2), transfer
//! sessions (§8) and pairing (§5).

pub mod flow;
pub mod manager;
pub mod pair;
pub mod server;
pub mod store;
pub mod xfer;

use std::{fmt, time::Duration};

pub use iroh::endpoint::Connection;
use iroh::{
    Endpoint, EndpointAddr, RelayMode, SecretKey, TransportAddr,
    endpoint::{RecvStream, SendStream, VarInt, presets},
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
    /// Server API failure (kind/code only).
    Server(crate::client::ClientError),
    /// The server's head moved; fetch, re-check and retry (§4.4).
    HeadMoved,
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
    let transport = iroh::endpoint::QuicTransportConfig::builder()
        .default_path_max_idle_timeout(PATH_IDLE)
        .default_path_keep_alive_interval(PATH_KEEPALIVE)
        .build();
    let ep = Endpoint::builder(presets::Minimal)
        .secret_key(sk)
        .relay_mode(relay_mode)
        .transport_config(transport)
        .clear_address_lookup()
        .alpns(vec![crate::xfer::ALPN.to_vec(), crate::pair::ALPN.to_vec()])
        .bind()
        .await
        .map_err(|_| NetError::Bind)?;
    // The dial info we hand out (QR, wake envelope) must carry the relay: right
    // after bind the home relay is not connected yet and `addr()` omits it, and
    // without it a peer behind a firewall (e.g. a "Public" Windows network) can't
    // reach us at all. Wait briefly; offline we continue with direct addresses.
    if relay != Relay::Disabled {
        let _ = tokio::time::timeout(RELAY_WAIT, ep.online()).await;
    }
    Ok(ep)
}

/// How long [`bind`] waits for the home relay connection.
pub const RELAY_WAIT: Duration = Duration::from_secs(5);

/// A path without packets for this long is abandoned and the connection moves
/// to another path (normally the relay). iroh's default is 15 s: on a phone →
/// PC transfer whose direct LAN path died right after the handshake (Windows
/// "Public" network), the stream stalled ~20 s before falling back (measured
/// 2026-10-09). If the last path goes idle the connection closes, so keep this
/// well above the keep-alive interval.
pub const PATH_IDLE: Duration = Duration::from_secs(4);
/// Per-path keep-alive while a connection is open (endpoints exist only during
/// transfers, so this costs nothing at idle).
pub const PATH_KEEPALIVE: Duration = Duration::from_secs(1);

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

/// True if the connection currently sends over a direct (IP) path.
pub fn is_direct(conn: &Connection) -> bool {
    conn.paths().iter().any(|p| p.is_selected() && p.is_ip())
}

/// `relay_data = off` (§9): wait up to `timeout` for a direct path; otherwise
/// close with `DIRECT_UNAVAILABLE`.
pub async fn require_direct(conn: &Connection, timeout: Duration) -> Result<(), NetError> {
    use n0_future::StreamExt;
    if is_direct(conn) {
        return Ok(());
    }
    let mut events = conn.path_events();
    let wait = async {
        while let Some(ev) = events.next().await {
            if let iroh::endpoint::PathEvent::Selected { remote_addr, .. } = ev
                && remote_addr.is_ip()
            {
                return true;
            }
            if is_direct(conn) {
                return true;
            }
        }
        false
    };
    match tokio::time::timeout(timeout, wait).await {
        Ok(true) => Ok(()),
        _ => {
            close(conn, code::DIRECT_UNAVAILABLE);
            Err(NetError::Closed(code::DIRECT_UNAVAILABLE))
        }
    }
}

/// A transfer that has had no direct path for this long is "slow": it crawls
/// through the rate-limited public relay and the user should know why
/// (roadmap 4c). Direct paths normally win within 1–2 s, so short transfers
/// never trigger it.
pub const SLOW_ROUTE_AFTER: Duration = Duration::from_secs(8);

/// How a transfer travelled (diagnostics; no addresses).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Route {
    /// A direct path was selected at some point.
    pub ever_direct: bool,
    /// The transfer ran on the relay alone for [`SLOW_ROUTE_AFTER`].
    pub slow: bool,
}

/// Runs `work` while watching the paths of `conn`; calls `on_slow` once when
/// the transfer has had no direct path for `slow_after` in a row. Runs in the
/// caller's task: no spawn, no polling (path events and one timer that exists
/// only while relayed).
pub async fn watch_route<T>(
    conn: &Connection,
    slow_after: Duration,
    work: impl Future<Output = T>,
    on_slow: impl FnOnce(),
) -> (T, Route) {
    route_loop(
        || is_direct(conn),
        conn.path_events(),
        slow_after,
        work,
        on_slow,
    )
    .await
}

/// [`watch_route`] with the path source abstracted (unit-testable): `direct`
/// is re-read after every item of `events`.
async fn route_loop<T, E>(
    direct: impl Fn() -> bool,
    events: impl n0_future::Stream<Item = E>,
    slow_after: Duration,
    work: impl Future<Output = T>,
    on_slow: impl FnOnce(),
) -> (T, Route) {
    use n0_future::StreamExt;
    tokio::pin!(work);
    tokio::pin!(events);
    let mut events_open = true;
    let mut on_slow = Some(on_slow);
    let mut route = Route::default();
    let mut relayed_since: Option<tokio::time::Instant> = None;
    loop {
        let now_direct = direct();
        route.ever_direct |= now_direct;
        relayed_since = if now_direct {
            None
        } else {
            relayed_since.or_else(|| Some(tokio::time::Instant::now()))
        };
        let deadline = relayed_since
            .filter(|_| !route.slow)
            .and_then(|t| t.checked_add(slow_after));
        let timer = async {
            match deadline {
                Some(d) => tokio::time::sleep_until(d).await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            out = &mut work => return (out, route),
            ev = events.next(), if events_open => events_open = ev.is_some(),
            () = timer => {
                route.slow = true;
                if let Some(f) = on_slow.take() {
                    f();
                }
            }
        }
    }
}

/// A path change, without addresses (logs carry kinds and timings only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathNote {
    Opened {
        id: String,
        kind: &'static str,
    },
    Selected {
        id: String,
        kind: &'static str,
    },
    Closed {
        id: String,
        kind: &'static str,
        rtt_ms: u128,
        tx_bytes: u64,
        rx_bytes: u64,
        lost_packets: u64,
    },
    Lagged,
}

/// The class of a path's remote address — never the address itself.
fn addr_kind(a: &TransportAddr) -> &'static str {
    match a {
        TransportAddr::Ip(sa) => match sa.ip() {
            std::net::IpAddr::V4(v4) if v4.is_private() || v4.is_link_local() => "lan4",
            std::net::IpAddr::V4(v4) if v4.is_loopback() => "loop",
            std::net::IpAddr::V4(_) => "wan4",
            std::net::IpAddr::V6(v6) if v6.is_unique_local() || v6.is_unicast_link_local() => {
                "lan6"
            }
            std::net::IpAddr::V6(_) => "wan6",
        },
        TransportAddr::Relay(_) => "relay",
        _ => "other",
    }
}

/// Reports path changes of `conn` until it closes (diagnostics for the
/// direct-vs-relay question; see roadmap 4c).
pub async fn watch_paths(conn: &Connection, mut note: impl FnMut(PathNote)) {
    use iroh::endpoint::PathEvent;
    use n0_future::StreamExt;
    let mut events = conn.path_events();
    while let Some(ev) = events.next().await {
        note(match ev {
            PathEvent::Opened {
                id, remote_addr, ..
            } => PathNote::Opened {
                id: id.to_string(),
                kind: addr_kind(&remote_addr),
            },
            PathEvent::Selected {
                id, remote_addr, ..
            } => PathNote::Selected {
                id: id.to_string(),
                kind: addr_kind(&remote_addr),
            },
            PathEvent::Closed {
                id,
                remote_addr,
                last_stats,
                ..
            } => PathNote::Closed {
                id: id.to_string(),
                kind: addr_kind(&remote_addr),
                rtt_ms: last_stats.rtt.as_millis(),
                tx_bytes: last_stats.udp_tx.bytes,
                rx_bytes: last_stats.udp_rx.bytes,
                lost_packets: last_stats.lost_packets,
            },
            _ => PathNote::Lagged,
        });
    }
}

/// The application close code the peer used, if the connection was closed by it.
pub fn peer_close_code(conn: &Connection) -> Option<u32> {
    match conn.close_reason()? {
        iroh::endpoint::ConnectionError::ApplicationClosed(c) => {
            u32::try_from(c.error_code.into_inner()).ok()
        }
        _ => None,
    }
}

/// Maps a stream failure to the peer's close code when there is one.
pub fn explain(conn: &Connection, e: NetError) -> NetError {
    match (&e, peer_close_code(conn)) {
        (NetError::Stream(_) | NetError::Timeout, Some(c)) => NetError::Closed(c),
        _ => e,
    }
}

impl From<crate::client::ClientError> for NetError {
    fn from(e: crate::client::ClientError) -> Self {
        Self::Server(e)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    use n0_future::stream;

    use super::*;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    /// Path events at the given offsets; each one first sets `direct`.
    fn script(
        direct: Arc<AtomicBool>,
        steps: Vec<(u64, bool)>,
    ) -> impl n0_future::Stream<Item = ()> {
        stream::unfold((steps.into_iter(), 0u64), move |(mut it, at)| {
            let direct = Arc::clone(&direct);
            async move {
                let (t, d) = it.next()?;
                tokio::time::sleep(ms(t.saturating_sub(at))).await;
                direct.store(d, Ordering::SeqCst);
                Some(((), (it, t)))
            }
        })
    }

    async fn run(start_direct: bool, steps: Vec<(u64, bool)>, work_ms: u64) -> (usize, Route) {
        let direct = Arc::new(AtomicBool::new(start_direct));
        let events = script(Arc::clone(&direct), steps);
        let mut fired = 0;
        let ((), route) = route_loop(
            || direct.load(Ordering::SeqCst),
            events,
            ms(50),
            tokio::time::sleep(ms(work_ms)),
            || fired += 1,
        )
        .await;
        (fired, route)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn relay_only_alerts_once() {
        let (fired, route) = run(false, vec![], 200).await;
        assert_eq!(fired, 1);
        assert_eq!(
            route,
            Route {
                ever_direct: false,
                slow: true
            }
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn direct_never_alerts() {
        let (fired, route) = run(true, vec![], 150).await;
        assert_eq!(fired, 0);
        assert_eq!(
            route,
            Route {
                ever_direct: true,
                slow: false
            }
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn short_transfer_on_relay_does_not_alert() {
        let (fired, route) = run(false, vec![], 20).await;
        assert_eq!(fired, 0);
        assert!(!route.slow);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_direct_spell_restarts_the_clock() {
        // Relay 0–30, direct 30–70, relay from 70: the 50 ms deadline moves to
        // 120, after the work ends at 110.
        let (fired, route) = run(false, vec![(30, true), (70, false)], 110).await;
        assert_eq!(fired, 0);
        assert!(route.ever_direct && !route.slow);
        // The same path changes with longer work do alert, once.
        let (fired, route) = run(false, vec![(30, true), (70, false)], 220).await;
        assert_eq!(fired, 1);
        assert!(route.ever_direct && route.slow);
    }
}
