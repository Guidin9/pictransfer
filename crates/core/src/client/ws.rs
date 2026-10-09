//! WebSocket session (protocol §6.3): authenticated upgrade, hand-written
//! RFC 6455 framing, keepalive `p`/`o` every K seconds (reconnect after two
//! missed `o`), reconnect with exponential backoff and ±20 % jitter.
//!
//! One task on the caller's runtime holds the socket. Server messages arrive
//! as [`Event`]s on a bounded channel; requests go through [`WsHandle`].
//! The only timer is the keepalive (plus the backoff sleep while offline).

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::mpsc,
    task::JoinHandle,
    time::{Instant, sleep_until},
};

use super::{
    Client, ClientError, Counters, ErrorCode, Inner, MAX_RESPONSE, MAX_WS_MESSAGE,
    api::{self, DevicePresence, Via},
    gid_segment, http,
    json::{self, Value},
    parse_head, sha1,
    transport::{self, Stream},
};
use crate::{
    b64u,
    keys::{self, EndpointId},
    log::{GroupId, Head},
    wake::MAX_ENVELOPE,
};

const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const OP_CONT: u8 = 0x0;
const OP_TEXT: u8 = 0x1;
const OP_BINARY: u8 = 0x2;
const OP_CLOSE: u8 = 0x8;
const OP_PING: u8 = 0x9;
const OP_PONG: u8 = 0xA;
const MAX_CONTROL: usize = 125;
const CLOSE_NORMAL: u16 = 1000;
const CLOSE_PROTOCOL: u16 = 1002;
const CLOSE_TOO_BIG: u16 = 1009;

/// Session parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WsConfig {
    /// `K` (§6.3): the keepalive interval.
    pub keepalive: Duration,
    pub backoff_initial: Duration,
    pub backoff_max: Duration,
    /// Capacity of the event channel.
    pub event_capacity: usize,
}

impl Default for WsConfig {
    fn default() -> Self {
        Self {
            keepalive: Duration::from_secs(60),
            backoff_initial: Duration::from_secs(1),
            backoff_max: Duration::from_secs(300),
            event_capacity: 32,
        }
    }
}

/// Why a connected socket went away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisconnectReason {
    /// Two keepalive replies were missed.
    KeepaliveTimeout,
    /// The server sent a close frame or closed the connection.
    ServerClosed,
    /// A read or write failed or timed out.
    Io,
    /// The server violated RFC 6455.
    Protocol,
    /// A server message exceeded 64 KiB.
    TooLarge,
    /// [`WsHandle::reconnect_now`] (network change, resume).
    Requested,
}

/// Session events, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// The socket is up. Re-sync the log (`log_get`) after every connect.
    Connected,
    Disconnected(DisconnectReason),
    /// A connect attempt failed; the next one follows after a backoff.
    ConnectFailed(ClientError),
    /// `{"t":"wake","env"}`: a sealed envelope (§7) to open locally.
    Wake {
        env: Vec<u8>,
    },
    /// `{"t":"ack","id","via"}`.
    Ack {
        id: u64,
        via: Via,
    },
    /// `{"t":"presence","id","devices"}`.
    Presence {
        id: u64,
        devices: Vec<DevicePresence>,
    },
    /// `{"t":"log","records","head"}`: pushed after every accepted append
    /// (`id: None`) or the reply to `log-get` (`id: Some`). Records are raw
    /// and must be validated locally.
    Log {
        id: Option<u64>,
        records: Vec<Vec<u8>>,
        head: Head,
    },
    /// `{"t":"err","id","code"}`.
    Err {
        id: Option<u64>,
        code: ErrorCode,
    },
    /// `{"t":"bye","code"}` (for example after removal).
    Bye {
        code: ErrorCode,
    },
    /// Request `id` was not sent because the socket went down.
    NotSent {
        id: u64,
    },
    /// The server refused this device permanently (`not-member`, `no-group`,
    /// `not-allowed`). The session task has stopped.
    Ended(ClientError),
}

#[derive(Debug)]
enum Cmd {
    Send { id: u64, text: String },
    Reconnect,
}

/// Handle to a running session. Dropping it (or [`WsHandle::close`]) ends the session.
#[derive(Debug)]
pub struct WsHandle {
    tx: mpsc::Sender<Cmd>,
    next_id: AtomicU64,
    connected: Arc<AtomicBool>,
    task: JoinHandle<()>,
}

impl WsHandle {
    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }

    async fn request(&self, build: impl FnOnce(u64) -> String) -> Result<u64, ClientError> {
        if !self.is_connected() {
            return Err(if self.tx.is_closed() {
                ClientError::Closed
            } else {
                ClientError::NotConnected
            });
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let text = build(id);
        self.tx
            .send(Cmd::Send { id, text })
            .await
            .map_err(|_| ClientError::Closed)?;
        Ok(id)
    }

    /// `{"t":"wake",…}`. Returns the request id; the reply is [`Event::Ack`]
    /// or [`Event::Err`] with that id.
    pub async fn wake(&self, to: &EndpointId, env: &[u8], ttl: u32) -> Result<u64, ClientError> {
        let (to, env) = api::wake_args(to, env, ttl)?;
        self.request(|id| {
            json::object(&[
                ("t", json::str_lit("wake")),
                ("id", json::uint(id)),
                ("to", json::str_lit(&to)),
                ("env", json::str_lit(&env)),
                ("ttl", json::uint(u64::from(ttl))),
            ])
        })
        .await
    }

    /// `{"t":"presence","id"}`; the reply is [`Event::Presence`].
    pub async fn presence(&self) -> Result<u64, ClientError> {
        self.request(|id| json::object(&[("t", json::str_lit("presence")), ("id", json::uint(id))]))
            .await
    }

    /// `{"t":"log-get","id","after"}`; the reply is [`Event::Log`] with this id.
    /// The server truncates it below 64 KiB: repeat with the last seq until the head is reached.
    pub async fn log_get(&self, after: u64) -> Result<u64, ClientError> {
        self.request(|id| {
            json::object(&[
                ("t", json::str_lit("log-get")),
                ("id", json::uint(id)),
                ("after", json::uint(after)),
            ])
        })
        .await
    }

    /// Drops the socket (if any) and reconnects now with a reset backoff.
    /// Call on OS network-change and resume events (§6.3).
    pub fn reconnect_now(&self) {
        let _ = self.tx.try_send(Cmd::Reconnect);
    }

    /// Sends a close frame and waits for the task to end.
    pub async fn close(self) {
        let WsHandle { tx, task, .. } = self;
        drop(tx);
        let _ = task.await;
    }
}

impl Client {
    /// Starts the WebSocket session for `gid` on the current tokio runtime.
    pub fn websocket(&self, gid: GroupId, cfg: WsConfig) -> (WsHandle, mpsc::Receiver<Event>) {
        let (cmd_tx, cmd_rx) = mpsc::channel(16);
        let (ev_tx, ev_rx) = mpsc::channel(cfg.event_capacity.max(1));
        let connected = Arc::new(AtomicBool::new(false));
        let task = tokio::spawn(run(
            self.inner.clone(),
            gid,
            cfg,
            cmd_rx,
            ev_tx,
            connected.clone(),
        ));
        (
            WsHandle {
                tx: cmd_tx,
                next_id: AtomicU64::new(1),
                connected,
                task,
            },
            ev_rx,
        )
    }
}

// ------------------------------------------------------------------ framing

/// A client frame: FIN, `op`, masked with `mask`.
pub fn encode_frame(op: u8, payload: &[u8], mask: [u8; 4]) -> Vec<u8> {
    let len = payload.len();
    let mut f = Vec::with_capacity(len.saturating_add(14));
    f.push(0x80 | (op & 0x0f));
    if len < 126 {
        f.push(0x80 | len as u8);
    } else if let Ok(l) = u16::try_from(len) {
        f.push(0x80 | 126);
        f.extend_from_slice(&l.to_be_bytes());
    } else {
        f.push(0x80 | 127);
        f.extend_from_slice(&(len as u64).to_be_bytes());
    }
    f.extend_from_slice(&mask);
    f.extend(payload.iter().zip(mask.iter().cycle()).map(|(b, m)| b ^ m));
    f
}

/// A parsed server frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub fin: bool,
    pub op: u8,
    pub payload: Vec<u8>,
}

/// Why a server frame or message was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    Protocol,
    TooLarge,
}

/// Parses one server frame from the front of `b`. `Ok(None)` until the
/// frame is complete; the size is checked before the payload is buffered.
pub fn parse_frame(b: &[u8], max: usize) -> Result<Option<(Frame, usize)>, FrameError> {
    let (Some(&b0), Some(&b1)) = (b.first(), b.get(1)) else {
        return Ok(None);
    };
    let fin = b0 & 0x80 != 0;
    let op = b0 & 0x0f;
    if b0 & 0x70 != 0 || b1 & 0x80 != 0 {
        // RSV bits without an extension, or a masked server frame.
        return Err(FrameError::Protocol);
    }
    if !matches!(
        op,
        OP_CONT | OP_TEXT | OP_BINARY | OP_CLOSE | OP_PING | OP_PONG
    ) {
        return Err(FrameError::Protocol);
    }
    let (len, hdr): (u64, usize) = match b1 & 0x7f {
        126 => {
            let Some(x) = b.get(2..4) else {
                return Ok(None);
            };
            let l = u16::from_be_bytes([
                x.first().copied().unwrap_or(0),
                x.get(1).copied().unwrap_or(0),
            ]);
            if l < 126 {
                return Err(FrameError::Protocol);
            }
            (u64::from(l), 4)
        }
        127 => {
            let Some(x) = b.get(2..10) else {
                return Ok(None);
            };
            let mut a = [0u8; 8];
            a.copy_from_slice(x);
            let l = u64::from_be_bytes(a);
            if l <= 0xffff || l >> 63 != 0 {
                return Err(FrameError::Protocol);
            }
            (l, 10)
        }
        n => (u64::from(n), 2),
    };
    if op >= OP_CLOSE && (!fin || len > MAX_CONTROL as u64) {
        return Err(FrameError::Protocol);
    }
    if len > max as u64 {
        return Err(FrameError::TooLarge);
    }
    let len = len as usize;
    let end = hdr.checked_add(len).ok_or(FrameError::TooLarge)?;
    let Some(payload) = b.get(hdr..end) else {
        return Ok(None);
    };
    Ok(Some((
        Frame {
            fin,
            op,
            payload: payload.to_vec(),
        },
        end,
    )))
}

/// A complete server message (after reassembly).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Text(String),
    Binary,
    Close(Option<u16>),
    Ping(Vec<u8>),
    Pong,
}

/// Reassembles fragmented data messages, bounded by `max`.
#[derive(Debug, Default)]
pub struct Assembler {
    partial: Option<(u8, Vec<u8>)>,
}

impl Assembler {
    pub fn push(&mut self, f: Frame, max: usize) -> Result<Option<Message>, FrameError> {
        match f.op {
            OP_CLOSE => {
                let code = match f.payload.as_slice() {
                    [] => None,
                    [a, b, rest @ ..] => {
                        std::str::from_utf8(rest).map_err(|_| FrameError::Protocol)?;
                        Some(u16::from_be_bytes([*a, *b]))
                    }
                    [_] => return Err(FrameError::Protocol),
                };
                Ok(Some(Message::Close(code)))
            }
            OP_PING => Ok(Some(Message::Ping(f.payload))),
            OP_PONG => Ok(Some(Message::Pong)),
            OP_TEXT | OP_BINARY => {
                if self.partial.is_some() {
                    return Err(FrameError::Protocol);
                }
                if f.fin {
                    return Self::finish(f.op, f.payload);
                }
                self.partial = Some((f.op, f.payload));
                Ok(None)
            }
            OP_CONT => {
                let Some((op, mut data)) = self.partial.take() else {
                    return Err(FrameError::Protocol);
                };
                if data.len().saturating_add(f.payload.len()) > max {
                    return Err(FrameError::TooLarge);
                }
                data.extend_from_slice(&f.payload);
                if f.fin {
                    Self::finish(op, data)
                } else {
                    self.partial = Some((op, data));
                    Ok(None)
                }
            }
            _ => Err(FrameError::Protocol),
        }
    }

    fn finish(op: u8, data: Vec<u8>) -> Result<Option<Message>, FrameError> {
        if op == OP_TEXT {
            String::from_utf8(data)
                .map(|s| Some(Message::Text(s)))
                .map_err(|_| FrameError::Protocol)
        } else {
            Ok(Some(Message::Binary))
        }
    }
}

/// Standard base64 with padding (RFC 4648 §4), for the handshake headers.
fn b64_std(data: &[u8]) -> String {
    b64u::encode(data).replace('-', "+").replace('_', "/")
        + match data.len() % 3 {
            1 => "==",
            2 => "=",
            _ => "",
        }
}

/// `Sec-WebSocket-Accept` for a key (RFC 6455 §4.2.2).
pub fn accept_key(key: &str) -> String {
    b64_std(&sha1::digest(format!("{key}{WS_GUID}").as_bytes()))
}

// ------------------------------------------------------------ server messages

/// Parses a server text message. `Ok(None)`: unknown `t`, ignored (§6.3).
pub fn parse_server_message(text: &str) -> Result<Option<Event>, ClientError> {
    let v = json::parse(text.as_bytes()).map_err(|_| ClientError::Malformed)?;
    let t = v
        .get("t")
        .and_then(Value::as_str)
        .ok_or(ClientError::Malformed)?;
    let id = || {
        v.get("id")
            .and_then(Value::as_u64)
            .ok_or(ClientError::Malformed)
    };
    let opt_id = || match v.get("id") {
        None | Some(Value::Null) => Ok(None),
        Some(x) => x.as_u64().map(Some).ok_or(ClientError::Malformed),
    };
    let code = || {
        v.get("code")
            .and_then(Value::as_str)
            .map(ErrorCode::parse)
            .ok_or(ClientError::Malformed)
    };
    Ok(Some(match t {
        "wake" => {
            let env = v
                .get("env")
                .and_then(Value::as_str)
                .and_then(b64u::decode)
                .filter(|e| !e.is_empty() && e.len() <= MAX_ENVELOPE)
                .ok_or(ClientError::Malformed)?;
            Event::Wake { env }
        }
        "ack" => Event::Ack {
            id: id()?,
            via: v
                .get("via")
                .and_then(Value::as_str)
                .and_then(Via::parse)
                .ok_or(ClientError::Malformed)?,
        },
        "presence" => Event::Presence {
            id: id()?,
            devices: api::parse_devices(v.get("devices"))?,
        },
        "log" => Event::Log {
            id: opt_id()?,
            records: api::parse_records(v.get("records"))?,
            head: parse_head(v.get("head").ok_or(ClientError::Malformed)?)?,
        },
        "err" => Event::Err {
            id: opt_id()?,
            code: code()?,
        },
        "bye" => Event::Bye { code: code()? },
        _ => return Ok(None),
    }))
}

// ------------------------------------------------------------------ session

fn random_mask() -> [u8; 4] {
    let mut m = [0u8; 4];
    // A failed RNG leaves a zero mask: masking protects intermediaries, not secrecy.
    let _ = keys::random(&mut m);
    m
}

/// `base` scaled by a random factor in [0.8, 1.2].
fn jittered(base: Duration) -> Duration {
    let mut r = [0u8; 2];
    let permille = if keys::random(&mut r).is_ok() {
        800u32.saturating_add(u32::from(u16::from_le_bytes(r)) % 401)
    } else {
        1000
    };
    base.saturating_mul(permille)
        .checked_div(1000)
        .unwrap_or(base)
}

/// Performs the authenticated upgrade. Returns the stream and bytes read past the head.
async fn handshake(inner: &Inner, gid: &GroupId) -> Result<(Stream, Vec<u8>), ClientError> {
    let target = format!("/v1/groups/{}/ws", gid_segment(gid));
    let mut key = [0u8; 16];
    keys::random(&mut key).map_err(|_| ClientError::Rng)?;
    let key = b64_std(&key);
    let auth = inner.sign("GET", &target, &[]);
    let req = http::build_request(
        "GET",
        &target,
        &inner.url.host_header(),
        &[
            ("Authorization", auth.as_str()),
            ("Upgrade", "websocket"),
            ("Connection", "Upgrade"),
            ("Sec-WebSocket-Key", key.as_str()),
            ("Sec-WebSocket-Version", "13"),
        ],
        None,
    );
    let mut s = transport::connect(&inner.url, &inner.counters).await?;
    s.write_all(&req).await.map_err(|_| ClientError::Io)?;
    s.flush().await.map_err(|_| ClientError::Io)?;
    let (head, head_len, rest) = http::read_head(&mut s).await?;
    if head.status != 101 {
        let body = http::read_body(&mut s, &head, head_len, rest, MAX_RESPONSE).await?;
        return Err(api::server_error(&http::Response {
            status: head.status,
            body,
        }));
    }
    let upgrade = head.header("upgrade")?.unwrap_or("");
    let connection = head.header("connection")?.unwrap_or("");
    let accept = head.header("sec-websocket-accept")?.unwrap_or("");
    if !upgrade.eq_ignore_ascii_case("websocket")
        || !connection
            .split(',')
            .any(|t| t.trim().eq_ignore_ascii_case("upgrade"))
        || accept != accept_key(&key)
        || head.header("sec-websocket-extensions")?.is_some()
    {
        return Err(ClientError::Protocol);
    }
    Ok((s, rest))
}

enum End {
    /// All handles dropped or the event receiver closed.
    Shutdown,
    Dropped(DisconnectReason),
}

struct Session<'a> {
    s: Stream,
    buf: Vec<u8>,
    asm: Assembler,
    counters: &'a Counters,
    events: &'a mpsc::Sender<Event>,
}

impl Session<'_> {
    async fn write(&mut self, op: u8, payload: &[u8]) -> Result<(), DisconnectReason> {
        let f = encode_frame(op, payload, random_mask());
        match tokio::time::timeout(super::REQUEST_TIMEOUT, async {
            self.s.write_all(&f).await?;
            self.s.flush().await
        })
        .await
        {
            Ok(Ok(())) => Ok(()),
            _ => Err(DisconnectReason::Io),
        }
    }

    async fn close(&mut self, code: u16) {
        let _ = self.write(OP_CLOSE, &code.to_be_bytes()).await;
        let _ = tokio::time::timeout(Duration::from_secs(1), self.s.shutdown()).await;
    }

    async fn emit(&self, ev: Event) -> Result<(), End> {
        self.events.send(ev).await.map_err(|_| End::Shutdown)
    }

    /// Handles all complete frames in the buffer.
    /// Returns `Ok(true)` when an `o` keepalive reply was seen.
    async fn drain(&mut self) -> Result<bool, End> {
        let mut pong = false;
        loop {
            let parsed = parse_frame(&self.buf, MAX_WS_MESSAGE);
            let (frame, used) = match parsed {
                Ok(Some(x)) => x,
                Ok(None) => break,
                Err(e) => return Err(self.fail(e).await),
            };
            self.buf.drain(..used);
            let msg = match self.asm.push(frame, MAX_WS_MESSAGE) {
                Ok(Some(m)) => m,
                Ok(None) => continue,
                Err(e) => return Err(self.fail(e).await),
            };
            match msg {
                Message::Text(t) if t == "o" => {
                    pong = true;
                    Counters::inc(&self.counters.pongs);
                }
                Message::Text(t) => match parse_server_message(&t) {
                    Ok(Some(ev)) => self.emit(ev).await?,
                    Ok(None) => {}
                    Err(_) => Counters::inc(&self.counters.malformed),
                },
                Message::Binary | Message::Pong => {}
                Message::Ping(p) => {
                    if let Err(r) = self.write(OP_PONG, &p).await {
                        return Err(End::Dropped(r));
                    }
                }
                Message::Close(code) => {
                    self.close(code.unwrap_or(CLOSE_NORMAL)).await;
                    return Err(End::Dropped(DisconnectReason::ServerClosed));
                }
            }
        }
        // Release a buffer that grew for a large message.
        if self.buf.capacity() > 16 * 1024 && self.buf.len() < 4096 {
            self.buf.shrink_to(4096);
        }
        Ok(pong)
    }

    async fn fail(&mut self, e: FrameError) -> End {
        let (code, reason) = match e {
            FrameError::Protocol => (CLOSE_PROTOCOL, DisconnectReason::Protocol),
            FrameError::TooLarge => (CLOSE_TOO_BIG, DisconnectReason::TooLarge),
        };
        self.close(code).await;
        End::Dropped(reason)
    }

    async fn run(&mut self, cmds: &mut mpsc::Receiver<Cmd>, k: Duration) -> End {
        let mut tmp = [0u8; 4096];
        let mut next_ping = Instant::now().checked_add(k).unwrap_or_else(Instant::now);
        let mut awaiting = false;
        let mut missed = 0u32;
        // Frames that arrived together with the handshake response.
        match self.drain().await {
            Ok(true) => awaiting = false,
            Ok(false) => {}
            Err(e) => return e,
        }
        loop {
            tokio::select! {
                _ = sleep_until(next_ping) => {
                    if awaiting {
                        missed = missed.saturating_add(1);
                        Counters::inc(&self.counters.missed_pongs);
                        if missed >= 2 {
                            self.close(CLOSE_NORMAL).await;
                            return End::Dropped(DisconnectReason::KeepaliveTimeout);
                        }
                    }
                    if let Err(r) = self.write(OP_TEXT, b"p").await {
                        return End::Dropped(r);
                    }
                    Counters::inc(&self.counters.pings);
                    awaiting = true;
                    next_ping = Instant::now().checked_add(k).unwrap_or(next_ping);
                }
                n = self.s.read(&mut tmp) => {
                    let n = match n {
                        Ok(0) => return End::Dropped(DisconnectReason::ServerClosed),
                        Ok(n) => n,
                        Err(_) => return End::Dropped(DisconnectReason::Io),
                    };
                    self.buf.extend_from_slice(tmp.get(..n).unwrap_or(&[]));
                    match self.drain().await {
                        Ok(true) => {
                            awaiting = false;
                            missed = 0;
                        }
                        Ok(false) => {}
                        Err(e) => return e,
                    }
                }
                cmd = cmds.recv() => match cmd {
                    None => {
                        self.close(CLOSE_NORMAL).await;
                        return End::Shutdown;
                    }
                    Some(Cmd::Reconnect) => {
                        self.close(CLOSE_NORMAL).await;
                        return End::Dropped(DisconnectReason::Requested);
                    }
                    Some(Cmd::Send { id, text }) => {
                        if text.len() > MAX_WS_MESSAGE {
                            if self.emit(Event::NotSent { id }).await.is_err() {
                                return End::Shutdown;
                            }
                            continue;
                        }
                        if let Err(r) = self.write(OP_TEXT, text.as_bytes()).await {
                            let _ = self.emit(Event::NotSent { id }).await;
                            return End::Dropped(r);
                        }
                    }
                }
            }
        }
    }
}

/// Waits `delay` while answering commands. Returns `false` on shutdown.
async fn backoff_wait(
    delay: Duration,
    cmds: &mut mpsc::Receiver<Cmd>,
    events: &mpsc::Sender<Event>,
) -> Result<bool, ()> {
    let until = Instant::now()
        .checked_add(delay)
        .unwrap_or_else(Instant::now);
    loop {
        tokio::select! {
            _ = sleep_until(until) => return Ok(false),
            cmd = cmds.recv() => match cmd {
                None => return Err(()),
                Some(Cmd::Reconnect) => return Ok(true),
                Some(Cmd::Send { id, .. }) => {
                    events.send(Event::NotSent { id }).await.map_err(|_| ())?;
                }
            }
        }
    }
}

async fn run(
    inner: Arc<Inner>,
    gid: GroupId,
    cfg: WsConfig,
    mut cmds: mpsc::Receiver<Cmd>,
    events: mpsc::Sender<Event>,
    connected: Arc<AtomicBool>,
) {
    let mut backoff = cfg.backoff_initial;
    loop {
        Counters::inc(&inner.counters.ws_connects);
        let attempt = tokio::time::timeout(super::REQUEST_TIMEOUT, handshake(&inner, &gid)).await;
        match attempt.unwrap_or(Err(ClientError::Timeout)) {
            Ok((s, rest)) => {
                connected.store(true, Ordering::Relaxed);
                let started = Instant::now();
                let mut session = Session {
                    s,
                    buf: rest,
                    asm: Assembler::default(),
                    counters: &inner.counters,
                    events: &events,
                };
                let end = if events.send(Event::Connected).await.is_err() {
                    End::Shutdown
                } else {
                    session.run(&mut cmds, cfg.keepalive).await
                };
                drop(session);
                connected.store(false, Ordering::Relaxed);
                Counters::inc(&inner.counters.ws_disconnects);
                let reason = match end {
                    End::Shutdown => return,
                    End::Dropped(r) => r,
                };
                if events.send(Event::Disconnected(reason)).await.is_err() {
                    return;
                }
                if reason == DisconnectReason::Requested {
                    backoff = cfg.backoff_initial;
                    continue;
                }
                // A session that stayed up for a keepalive interval resets the backoff.
                if started.elapsed() >= cfg.keepalive {
                    backoff = cfg.backoff_initial;
                }
            }
            Err(e) => {
                if let ClientError::Server { code, .. } = e
                    && code.is_permanent()
                {
                    let _ = events.send(Event::Ended(e)).await;
                    return;
                }
                if events.send(Event::ConnectFailed(e)).await.is_err() {
                    return;
                }
            }
        }
        let delay = jittered(backoff);
        backoff = backoff.saturating_mul(2).min(cfg.backoff_max);
        match backoff_wait(delay, &mut cmds, &events).await {
            Err(()) => return,
            Ok(true) => backoff = cfg.backoff_initial,
            Ok(false) => {}
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use crate::keys::IdentityKey;
    use tokio::net::TcpListener;

    fn unmask(f: &[u8]) -> (u8, Vec<u8>) {
        let len = (f[1] & 0x7f) as usize;
        let (len, off) = match len {
            126 => (u16::from_be_bytes([f[2], f[3]]) as usize, 4),
            127 => (
                u64::from_be_bytes(f[2..10].try_into().unwrap()) as usize,
                10,
            ),
            n => (n, 2),
        };
        let mask = &f[off..off + 4];
        let p = f[off + 4..off + 4 + len]
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ mask[i % 4])
            .collect();
        (f[0] & 0x0f, p)
    }

    #[test]
    fn rfc6455_accept_example() {
        assert_eq!(
            accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
        assert_eq!(b64_std(b"f"), "Zg==");
        assert_eq!(b64_std(b"fo"), "Zm8=");
        assert_eq!(b64_std(&[0xfb, 0xff, 0xff]), "+///");
    }

    #[test]
    fn client_frames_all_lengths() {
        for len in [0usize, 1, 125, 126, 65535, 65536] {
            let p = vec![0x5a; len];
            let f = encode_frame(OP_TEXT, &p, [1, 2, 3, 4]);
            assert_eq!(f[0], 0x81);
            assert!(f[1] & 0x80 != 0);
            assert_eq!(unmask(&f), (OP_TEXT, p));
        }
    }

    #[test]
    fn server_frames() {
        let (f, n) = parse_frame(&[0x81, 1, b'o', 0xff], 10).unwrap().unwrap();
        assert_eq!(
            (f.fin, f.op, f.payload.as_slice(), n),
            (true, 1, &b"o"[..], 3)
        );
        let mut b = vec![0x82, 126, 0, 200];
        b.extend(vec![0; 200]);
        assert_eq!(parse_frame(&b, 1000).unwrap().unwrap().1, 204);
        assert_eq!(parse_frame(&b[..100], 1000).unwrap(), None);
        let mut b = vec![0x82, 127, 0, 0, 0, 0, 0, 1, 0, 0];
        b.extend(vec![0; 65536]);
        assert_eq!(parse_frame(&b, 65536).unwrap().unwrap().1, 65546);
        assert_eq!(parse_frame(&[0x81], 10).unwrap(), None);
        assert_eq!(parse_frame(&[0x81, 126, 0], 10).unwrap(), None);
    }

    #[test]
    fn server_frames_rejected() {
        let p = Err(FrameError::Protocol);
        let big = Err(FrameError::TooLarge);
        assert_eq!(parse_frame(&[0x81, 0x81, 0, 0, 0, 0, b'o'], 10), p); // masked
        assert_eq!(parse_frame(&[0xC1, 1, b'o'], 10), p); // RSV1
        assert_eq!(parse_frame(&[0x83, 0], 10), p); // reserved opcode
        assert_eq!(parse_frame(&[0x8B, 0], 10), p); // reserved control opcode
        assert_eq!(parse_frame(&[0x09, 0], 10), p); // fragmented ping
        assert_eq!(parse_frame(&[0x89, 126, 0, 126], 1000), p); // control > 125
        assert_eq!(parse_frame(&[0x81, 126, 0, 5], 1000), p); // non-minimal 16-bit
        assert_eq!(parse_frame(&[0x81, 127, 0, 0, 0, 0, 0, 0, 0, 5], 1000), p); // non-minimal 64-bit
        assert_eq!(
            parse_frame(&[0x81, 127, 0x80, 0, 0, 0, 0, 0, 0, 0], u32::MAX as usize),
            p
        );
        assert_eq!(parse_frame(&[0x81, 11], 10), big);
        assert_eq!(
            parse_frame(&[0x81, 127, 0, 0, 0, 0, 0, 1, 0, 1], 65536),
            big
        );
        assert_eq!(
            parse_frame(
                &[0x81, 127, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
                65536
            ),
            big
        );
    }

    fn fr(fin: bool, op: u8, p: &[u8]) -> Frame {
        Frame {
            fin,
            op,
            payload: p.to_vec(),
        }
    }

    #[test]
    fn assembler() {
        let mut a = Assembler::default();
        assert_eq!(a.push(fr(false, OP_TEXT, b"ab"), 10).unwrap(), None);
        assert_eq!(
            a.push(fr(true, OP_PING, b"x"), 10).unwrap(),
            Some(Message::Ping(b"x".to_vec()))
        );
        assert_eq!(a.push(fr(false, OP_CONT, b"cd"), 10).unwrap(), None);
        assert_eq!(
            a.push(fr(true, OP_CONT, b"e"), 10).unwrap(),
            Some(Message::Text("abcde".into()))
        );
        assert_eq!(
            a.push(fr(true, OP_CLOSE, &[3, 232]), 10).unwrap(),
            Some(Message::Close(Some(1000)))
        );
        assert_eq!(
            a.push(fr(true, OP_CLOSE, &[]), 10).unwrap(),
            Some(Message::Close(None))
        );
        // Negative cases.
        let mut a = Assembler::default();
        assert_eq!(
            a.push(fr(true, OP_CONT, b"x"), 10),
            Err(FrameError::Protocol)
        );
        assert_eq!(a.push(fr(false, OP_TEXT, b"x"), 10).unwrap(), None);
        assert_eq!(
            a.push(fr(true, OP_TEXT, b"y"), 10),
            Err(FrameError::Protocol)
        );
        let mut a = Assembler::default();
        a.push(fr(false, OP_TEXT, &[0; 8]), 10).unwrap();
        assert_eq!(
            a.push(fr(true, OP_CONT, &[0; 3]), 10),
            Err(FrameError::TooLarge)
        );
        let mut a = Assembler::default();
        assert_eq!(
            a.push(fr(true, OP_TEXT, b"\xff"), 10),
            Err(FrameError::Protocol)
        );
        assert_eq!(
            a.push(fr(true, OP_CLOSE, &[3]), 10),
            Err(FrameError::Protocol)
        );
        assert_eq!(
            a.push(fr(true, OP_CLOSE, &[3, 232, 0xff]), 10),
            Err(FrameError::Protocol)
        );
        let mut a = Assembler::default();
        a.push(fr(false, OP_TEXT, b"\xe2\x82"), 10).unwrap();
        assert_eq!(
            a.push(fr(true, OP_CONT, b"\xac"), 10).unwrap(),
            Some(Message::Text("\u{20ac}".into()))
        );
    }

    #[test]
    fn server_messages() {
        let id = b64u::encode(&[7; 32]);
        let head = format!(r#"{{"seq":2,"id":"{id}"}}"#);
        assert_eq!(
            parse_server_message(r#"{"t":"wake","env":"AAEC"}"#).unwrap(),
            Some(Event::Wake { env: vec![0, 1, 2] })
        );
        assert_eq!(
            parse_server_message(r#"{"t":"ack","id":4,"via":"push"}"#).unwrap(),
            Some(Event::Ack {
                id: 4,
                via: Via::Push
            })
        );
        assert_eq!(
            parse_server_message(r#"{"t":"err","id":null,"code":"bad-request"}"#).unwrap(),
            Some(Event::Err {
                id: None,
                code: ErrorCode::BadRequest
            })
        );
        assert_eq!(
            parse_server_message(r#"{"t":"bye","code":"not-member"}"#).unwrap(),
            Some(Event::Bye {
                code: ErrorCode::NotMember
            })
        );
        let log = format!(r#"{{"t":"log","records":["AA"],"head":{head}}}"#);
        assert!(matches!(
            parse_server_message(&log).unwrap(),
            Some(Event::Log { id: None, .. })
        ));
        let log = format!(r#"{{"t":"log","id":3,"records":[],"head":{head}}}"#);
        assert!(matches!(
            parse_server_message(&log).unwrap(),
            Some(Event::Log { id: Some(3), .. })
        ));
        assert_eq!(
            parse_server_message(r#"{"t":"future","x":1}"#).unwrap(),
            None
        );
        let too_big = format!(
            r#"{{"t":"wake","env":"{}"}}"#,
            b64u::encode(&vec![0; MAX_ENVELOPE + 1])
        );
        for bad in [
            "o",
            "[]",
            r#"{"x":1}"#,
            r#"{"t":1}"#,
            r#"{"t":"wake"}"#,
            r#"{"t":"wake","env":""}"#,
            r#"{"t":"wake","env":"A"}"#,
            too_big.as_str(),
            r#"{"t":"ack","via":"ws"}"#,
            r#"{"t":"ack","id":1,"via":"pigeon"}"#,
            r#"{"t":"ack","id":-1,"via":"ws"}"#,
            r#"{"t":"presence","id":1}"#,
            r#"{"t":"log","records":[]}"#,
            r#"{"t":"err","id":"1","code":"x"}"#,
            r#"{"t":"bye"}"#,
        ] {
            assert!(parse_server_message(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn jitter_bounds() {
        for _ in 0..200 {
            let d = jittered(Duration::from_secs(10));
            assert!(
                d >= Duration::from_secs(8) && d <= Duration::from_secs(12),
                "{d:?}"
            );
        }
    }

    // ---- fake server over loopback TCP ----

    async fn read_request(s: &mut tokio::net::TcpStream) -> String {
        let mut buf = Vec::new();
        let mut tmp = [0u8; 1024];
        while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = s.read(&mut tmp).await.unwrap();
            assert!(n > 0);
            buf.extend_from_slice(&tmp[..n]);
        }
        String::from_utf8(buf).unwrap()
    }

    async fn upgrade(l: &TcpListener) -> tokio::net::TcpStream {
        let (mut s, _) = l.accept().await.unwrap();
        let req = read_request(&mut s).await;
        assert!(req.starts_with("GET /v1/groups/"));
        assert!(req.contains("\r\nAuthorization: WARP1 id="));
        let key = req
            .lines()
            .find_map(|l| l.strip_prefix("Sec-WebSocket-Key: "))
            .unwrap()
            .trim()
            .to_string();
        let resp = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Accept: {}\r\n\r\n",
            accept_key(&key)
        );
        s.write_all(resp.as_bytes()).await.unwrap();
        s
    }

    fn server_text(t: &str) -> Vec<u8> {
        let mut f = vec![0x81];
        if t.len() < 126 {
            f.push(t.len() as u8);
        } else {
            f.push(126);
            f.extend_from_slice(&(t.len() as u16).to_be_bytes());
        }
        f.extend_from_slice(t.as_bytes());
        f
    }

    async fn read_client_frame(s: &mut tokio::net::TcpStream) -> (u8, Vec<u8>) {
        let mut h = [0u8; 2];
        s.read_exact(&mut h).await.unwrap();
        let mut len = (h[1] & 0x7f) as usize;
        if len == 126 {
            let mut x = [0u8; 2];
            s.read_exact(&mut x).await.unwrap();
            len = u16::from_be_bytes(x) as usize;
        }
        let mut rest = vec![0u8; 4 + len];
        s.read_exact(&mut rest).await.unwrap();
        let mut f = vec![
            h[0],
            (h[1] & 0x80) | if len < 126 { len as u8 } else { 126 },
        ];
        if len >= 126 {
            f.extend_from_slice(&(len as u16).to_be_bytes());
        }
        f.extend_from_slice(&rest);
        unmask(&f)
    }

    fn client(port: u16) -> Client {
        Client::new(
            &format!("http://127.0.0.1:{port}"),
            Arc::new(IdentityKey::from_secret(&[5; 32])),
        )
        .unwrap()
    }

    fn fast() -> WsConfig {
        WsConfig {
            keepalive: Duration::from_millis(150),
            backoff_initial: Duration::from_millis(50),
            backoff_max: Duration::from_millis(200),
            event_capacity: 8,
        }
    }

    async fn next(rx: &mut mpsc::Receiver<Event>) -> Event {
        tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("event timeout")
            .expect("channel closed")
    }

    #[tokio::test]
    async fn keepalive_timeout_then_reconnect() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let c = client(port);
        let (h, mut rx) = c.websocket(GroupId([1; 16]), fast());
        let mut s1 = upgrade(&l).await;
        assert_eq!(next(&mut rx).await, Event::Connected);
        assert!(h.is_connected());
        // Answer the first ping, then go silent.
        assert_eq!(read_client_frame(&mut s1).await, (OP_TEXT, b"p".to_vec()));
        s1.write_all(&server_text("o")).await.unwrap();
        assert_eq!(
            next(&mut rx).await,
            Event::Disconnected(DisconnectReason::KeepaliveTimeout)
        );
        let snap = c.counters();
        assert!(
            snap.pings >= 3 && snap.pongs == 1 && snap.missed_pongs == 2,
            "{snap:?}"
        );
        // Reconnects after the backoff and receives server messages.
        let mut s2 = upgrade(&l).await;
        assert_eq!(next(&mut rx).await, Event::Connected);
        s2.write_all(&server_text(r#"{"t":"wake","env":"AAEC"}"#))
            .await
            .unwrap();
        s2.write_all(&server_text(r#"{"t":"unknown"}"#))
            .await
            .unwrap();
        s2.write_all(&server_text("not json")).await.unwrap();
        s2.write_all(&server_text(r#"{"t":"ack","id":1,"via":"ws"}"#))
            .await
            .unwrap();
        assert_eq!(next(&mut rx).await, Event::Wake { env: vec![0, 1, 2] });
        assert_eq!(
            next(&mut rx).await,
            Event::Ack {
                id: 1,
                via: Via::Ws
            }
        );
        assert_eq!(c.counters().malformed, 1);
        // A request goes out as a masked JSON text frame.
        let id = h.presence().await.unwrap();
        loop {
            let (op, p) = read_client_frame(&mut s2).await;
            if p == b"p" {
                continue;
            }
            assert_eq!(op, OP_TEXT);
            assert_eq!(
                String::from_utf8(p).unwrap(),
                format!(r#"{{"t":"presence","id":{id}}}"#)
            );
            break;
        }
        assert!(c.counters().bytes_out > 0 && c.counters().bytes_in > 0);
        h.close().await;
    }

    #[tokio::test]
    async fn protocol_violation_and_permanent_refusal() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let c = client(port);
        let (h, mut rx) = c.websocket(GroupId([1; 16]), fast());
        let mut s1 = upgrade(&l).await;
        assert_eq!(next(&mut rx).await, Event::Connected);
        // A masked server frame is a protocol error.
        s1.write_all(&[0x81, 0x81, 0, 0, 0, 0, b'o']).await.unwrap();
        assert_eq!(
            next(&mut rx).await,
            Event::Disconnected(DisconnectReason::Protocol)
        );
        // Not 101: transient error first, then a permanent refusal.
        let (mut s, _) = l.accept().await.unwrap();
        read_request(&mut s).await;
        let body = r#"{"error":"rate-limited"}"#;
        s.write_all(
            format!(
                "HTTP/1.1 429 Too Many\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        assert_eq!(
            next(&mut rx).await,
            Event::ConnectFailed(ClientError::Server {
                status: 429,
                code: ErrorCode::RateLimited
            })
        );
        // Requests while disconnected fail fast.
        assert_eq!(h.presence().await, Err(ClientError::NotConnected));
        let (mut s, _) = l.accept().await.unwrap();
        read_request(&mut s).await;
        let body = r#"{"error":"not-member"}"#;
        s.write_all(
            format!(
                "HTTP/1.1 403 Forbidden\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        assert_eq!(
            next(&mut rx).await,
            Event::Ended(ClientError::Server {
                status: 403,
                code: ErrorCode::NotMember
            })
        );
        assert!(rx.recv().await.is_none());
        assert_eq!(h.presence().await, Err(ClientError::Closed));
    }

    #[tokio::test]
    async fn bad_accept_key_is_refused() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let c = client(port);
        // A long backoff, so only reconnect_now can trigger the second attempt.
        let cfg = WsConfig {
            backoff_initial: Duration::from_secs(30),
            ..fast()
        };
        let (h, mut rx) = c.websocket(GroupId([1; 16]), cfg);
        let (mut s, _) = l.accept().await.unwrap();
        read_request(&mut s).await;
        s.write_all(
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
              Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
        )
        .await
        .unwrap();
        assert_eq!(
            next(&mut rx).await,
            Event::ConnectFailed(ClientError::Protocol)
        );
        // reconnect_now skips the backoff.
        h.reconnect_now();
        let _s2 = upgrade(&l).await;
        assert_eq!(next(&mut rx).await, Event::Connected);
        h.close().await;
    }
}
