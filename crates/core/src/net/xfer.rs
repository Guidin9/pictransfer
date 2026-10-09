//! Transfer sessions over iroh (protocol §8): admission, handshake, in-band log
//! sync, offer/accept, item streams, receiver durability and naming.

use std::path::{Path, PathBuf};

use iroh::{
    Endpoint,
    endpoint::{Connection, RecvStream, SendStream},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{IDLE_TIMEOUT, NetError, close, connect, ekm, read_frame, remote_id, write_frame};
use crate::{
    keys::{self, EndpointId},
    log::{Head, Incoming, Log},
    sanitize,
    wake::DialInfo,
    xfer::{
        self, CHUNK, Ctrl, CtrlCipher, Dir, EphemeralKem, Hello, HelloAck, Item, ItemOpener,
        ItemSealer, KeySchedule, MAX_FRAME, MAX_LOG_CHUNK, code, decline,
    },
};

/// What to send for one item.
#[derive(Debug, Clone)]
pub enum Source {
    Inline,
    File(PathBuf),
    Bytes(Vec<u8>),
}

#[derive(Debug, Clone)]
pub struct OutItem {
    pub item: Item,
    pub source: Source,
}

/// Builds an item for a file on disk (kind = image for common image types).
pub fn file_item(id: u32, path: &Path, created_at: u64) -> Result<OutItem, NetError> {
    let size = std::fs::metadata(path)?.len();
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("file")
        .to_string();
    let ext = sanitize::split_ext(&name).1.to_ascii_lowercase();
    let (kind, mime) = match ext.as_str() {
        ".png" => (xfer::kind::IMAGE, "image/png"),
        ".jpg" | ".jpeg" => (xfer::kind::IMAGE, "image/jpeg"),
        ".webp" => (xfer::kind::IMAGE, "image/webp"),
        ".gif" => (xfer::kind::IMAGE, "image/gif"),
        ".txt" => (xfer::kind::FILE, "text/plain"),
        _ => (xfer::kind::FILE, "application/octet-stream"),
    };
    let name: String = name.chars().take(xfer::MAX_NAME / 4).collect();
    Ok(OutItem {
        item: Item {
            id,
            kind,
            name,
            mime: mime.into(),
            size,
            created_at,
            text: None,
        },
        source: Source::File(path.to_path_buf()),
    })
}

/// Inline text item (≤ 64 KiB).
pub fn text_item(id: u32, text: &str, created_at: u64) -> Result<OutItem, NetError> {
    if text.len() as u64 > xfer::MAX_INLINE_TEXT {
        return Err(NetError::TooLarge);
    }
    Ok(OutItem {
        item: Item {
            id,
            kind: xfer::kind::TEXT,
            name: String::new(),
            mime: "text/plain;charset=utf-8".into(),
            size: text.len() as u64,
            created_at,
            text: Some(text.into()),
        },
        source: Source::Inline,
    })
}

/// A received item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Received {
    pub item: Item,
    /// Final path for streamed items.
    pub path: Option<PathBuf>,
}

/// Receiver policy.
#[derive(Debug, Clone)]
pub struct Policy {
    pub dir: PathBuf,
    /// Items above this size are declined unless `accept_large` is set (default 500 MB).
    pub max_size: u64,
    pub accept_large: bool,
}

/// An established, keyed control channel.
#[derive(Debug)]
pub struct Session {
    pub conn: Connection,
    send: SendStream,
    recv: RecvStream,
    tx: CtrlCipher,
    rx: CtrlCipher,
    ks: KeySchedule,
    my_dir: Dir,
    pub hello_session: [u8; 16],
    pub peer: EndpointId,
    pub peer_head: Head,
}

fn require_member(log: &Log, conn: &Connection) -> Result<EndpointId, NetError> {
    let id = remote_id(conn);
    if !log.is_member(&id) {
        close(conn, code::NOT_MEMBER);
        return Err(NetError::Identity);
    }
    Ok(id)
}

/// Dialer side: connect, check admission, run the handshake.
pub async fn dial(
    ep: &Endpoint,
    log: &Log,
    peer: &EndpointId,
    dial: &DialInfo,
    session: [u8; 16],
) -> Result<Session, NetError> {
    if !log.is_member(peer) {
        return Err(NetError::Identity);
    }
    let conn = connect(ep, peer, dial, xfer::ALPN).await?;
    let me = super::endpoint_id(ep);
    require_member(log, &conn)?;
    let head = log.head().ok_or(NetError::State("no log"))?;
    let res = async {
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|_| NetError::Stream("open_bi"))?;
        let kem = EphemeralKem::generate()?;
        let hello = Hello {
            session,
            ek: kem.public_key(),
            head,
            caps: vec![],
        }
        .encode();
        write_frame(&mut send, &hello).await?;
        let ack_raw = read_frame(&mut recv, MAX_FRAME, super::HANDSHAKE_TIMEOUT).await?;
        let ack = HelloAck::parse(&ack_raw)?;
        let ss = kem.decapsulate(&ack.ct)?;
        let ekm = ekm(&conn, xfer::EKM_LABEL, &session)?;
        let th = xfer::transcript(&hello, &ack_raw, &me, peer);
        let ks = KeySchedule::new(&ss, &ekm, th);
        Ok::<_, NetError>(Session {
            tx: ks.ctrl(Dir::Dl),
            rx: ks.ctrl(Dir::Ld),
            ks,
            my_dir: Dir::Dl,
            send,
            recv,
            conn: conn.clone(),
            hello_session: session,
            peer: *peer,
            peer_head: ack.head,
        })
    }
    .await;
    if let Err(e) = &res {
        close(&conn, e.close_code());
    }
    res
}

/// Listener side for an accepted `warpshot/xfer/1` connection.
pub async fn accept(ep: &Endpoint, conn: Connection, log: &Log) -> Result<Session, NetError> {
    // §8.1: admission right after the TLS handshake. (Bounded in-band sync for an
    // unknown dialer with a newer head is not implemented yet: such a dialer is
    // refused and retries after the agent syncs from the server.)
    let peer = require_member(log, &conn)?;
    let me = super::endpoint_id(ep);
    let head = log.head().ok_or(NetError::State("no log"))?;
    let res = async {
        let (mut send, mut recv) = tokio::time::timeout(super::HANDSHAKE_TIMEOUT, conn.accept_bi())
            .await
            .map_err(|_| NetError::Timeout)?
            .map_err(|_| NetError::Stream("accept"))?;
        let hello_raw = read_frame(&mut recv, MAX_FRAME, super::HANDSHAKE_TIMEOUT).await?;
        let hello = Hello::parse(&hello_raw)?;
        let (ss, ct) = xfer::encapsulate(&hello.ek)?;
        let ack = HelloAck {
            ct,
            head,
            caps: vec![],
        }
        .encode();
        write_frame(&mut send, &ack).await?;
        let ekm = ekm(&conn, xfer::EKM_LABEL, &hello.session)?;
        let th = xfer::transcript(&hello_raw, &ack, &peer, &me);
        let ks = KeySchedule::new(&ss, &ekm, th);
        Ok::<_, NetError>(Session {
            tx: ks.ctrl(Dir::Ld),
            rx: ks.ctrl(Dir::Dl),
            ks,
            my_dir: Dir::Ld,
            send,
            recv,
            conn: conn.clone(),
            hello_session: hello.session,
            peer,
            peer_head: hello.head,
        })
    }
    .await;
    if let Err(e) = &res {
        close(&conn, e.close_code());
    }
    res
}

impl Session {
    pub async fn send_ctrl(&mut self, msg: &Ctrl) -> Result<(), NetError> {
        let ct = self.tx.seal(&msg.encode())?;
        write_frame(&mut self.send, &ct).await
    }

    pub async fn recv_ctrl(&mut self) -> Result<Ctrl, NetError> {
        let ct = read_frame(&mut self.recv, MAX_FRAME, IDLE_TIMEOUT).await?;
        let pt = self.rx.open(&ct)?;
        Ok(Ctrl::parse(&pt)?)
    }

    fn fail(&self, e: NetError) -> NetError {
        close(&self.conn, e.close_code());
        e
    }

    /// §8.5: bring both logs to the same head before any `Offer`. Records the
    /// local side receives are validated as a continuation; a fork aborts.
    /// Returns true if `log` changed (the caller persists it).
    pub async fn sync_logs(&mut self, log: &mut Log, now_ms: u64) -> Result<bool, NetError> {
        let mine = log.head().ok_or(NetError::State("no log"))?;
        let theirs = self.peer_head;
        if mine == theirs {
            return Ok(false);
        }
        if mine.seq == theirs.seq || log.classify(theirs.seq, &theirs.id) == Incoming::Fork {
            return Err(self.fail(NetError::Fork));
        }
        if mine.seq < theirs.seq {
            self.send_ctrl(&Ctrl::LogReq { after: mine.seq }).await?;
            let mut received = 0usize;
            loop {
                let Ctrl::LogRecs { records, more } = self.recv_ctrl().await? else {
                    return Err(self.fail(NetError::Xfer(xfer::XferError::Shape)));
                };
                received = received.saturating_add(records.len());
                if received > crate::log::MAX_RECORDS {
                    return Err(self.fail(NetError::TooLarge));
                }
                for raw in &records {
                    let rec = log
                        .check(raw, now_ms)
                        .map_err(|e| self.fail(NetError::Log(e)))?;
                    match log.classify(rec.body.seq, &rec.id) {
                        Incoming::Next => {
                            log.append(raw, now_ms)?;
                        }
                        Incoming::Known => {}
                        Incoming::Fork | Incoming::Gap => return Err(self.fail(NetError::Fork)),
                    }
                }
                if !more {
                    break;
                }
            }
            if log.head() != Some(theirs) {
                return Err(self.fail(NetError::Fork));
            }
            Ok(true)
        } else {
            let Ctrl::LogReq { after } = self.recv_ctrl().await? else {
                return Err(self.fail(NetError::Xfer(xfer::XferError::Shape)));
            };
            let start = usize::try_from(after)
                .ok()
                .and_then(|a| a.checked_add(1))
                .ok_or(NetError::TooLarge)?;
            let rest: Vec<Vec<u8>> = log
                .records()
                .iter()
                .skip(start)
                .map(|r| r.raw.clone())
                .collect();
            let chunks: Vec<&[Vec<u8>]> = rest.chunks(MAX_LOG_CHUNK).collect();
            if chunks.is_empty() {
                self.send_ctrl(&Ctrl::LogRecs {
                    records: vec![],
                    more: false,
                })
                .await?;
            }
            let n = chunks.len();
            for (i, c) in chunks.into_iter().enumerate() {
                self.send_ctrl(&Ctrl::LogRecs {
                    records: c.to_vec(),
                    more: i.saturating_add(1) < n,
                })
                .await?;
            }
            Ok(false)
        }
    }

    /// Sender role: offer, stream accepted items, collect acks, say bye.
    /// Returns `(id, ok)` per offered item (declined items are `false`).
    pub async fn send_items(mut self, items: Vec<OutItem>) -> Result<Vec<(u32, bool)>, NetError> {
        let offer = Ctrl::Offer {
            session: self.hello_session,
            items: items.iter().map(|o| o.item.clone()).collect(),
        };
        self.send_ctrl(&offer).await?;
        let accepted = match self.recv_ctrl().await? {
            Ctrl::Accept { ids } => ids,
            Ctrl::Decline { reason } => {
                close(&self.conn, code::DECLINED);
                return Err(NetError::Declined(reason));
            }
            _ => return Err(self.fail(NetError::Xfer(xfer::XferError::Shape))),
        };
        let mut results = Vec::with_capacity(items.len());
        for o in &items {
            if !accepted.contains(&o.item.id) {
                results.push((o.item.id, false));
                continue;
            }
            if o.item.is_inline() {
                results.push((o.item.id, true));
                continue;
            }
            let (hash, size) = self.stream_item(o).await.map_err(|e| self.fail(e))?;
            self.send_ctrl(&Ctrl::ItemDone {
                id: o.item.id,
                blake3: hash,
                size,
            })
            .await?;
            match self.recv_ctrl().await? {
                Ctrl::ItemAck { id, ok, .. } if id == o.item.id => results.push((id, ok)),
                _ => return Err(self.fail(NetError::Xfer(xfer::XferError::Shape))),
            }
        }
        self.send_ctrl(&Ctrl::Bye).await?;
        let _ = self.send.finish();
        // The receiver closes with code 0 after Bye.
        let _ = tokio::time::timeout(IDLE_TIMEOUT, self.conn.closed()).await;
        Ok(results)
    }

    async fn stream_item(&mut self, o: &OutItem) -> Result<([u8; 32], u64), NetError> {
        let mut s = self
            .conn
            .open_uni()
            .await
            .map_err(|_| NetError::Stream("io"))?;
        s.write_all(&o.item.id.to_be_bytes())
            .await
            .map_err(|_| NetError::Stream("io"))?;
        let mut sealer = ItemSealer::new(&self.ks, self.my_dir, o.item.id);
        let mut hasher = blake3::Hasher::new();
        let mut total = 0u64;
        match &o.source {
            Source::Inline => return Err(NetError::State("inline item has no stream")),
            Source::Bytes(b) => {
                let mut chunks = b.chunks(CHUNK).peekable();
                if chunks.peek().is_none() {
                    send_chunk(&mut s, &mut sealer, &[], true).await?;
                }
                while let Some(c) = chunks.next() {
                    let last = chunks.peek().is_none();
                    hasher.update(c);
                    total = total.saturating_add(c.len() as u64);
                    let pad_last = last && c.len() == CHUNK;
                    send_chunk(&mut s, &mut sealer, c, last && !pad_last).await?;
                    if pad_last {
                        send_chunk(&mut s, &mut sealer, &[], true).await?;
                    }
                }
            }
            Source::File(path) => {
                let mut f = tokio::fs::File::open(path).await?;
                let mut cur = vec![0u8; CHUNK];
                let mut n = read_full(&mut f, &mut cur).await?;
                loop {
                    let mut next = vec![0u8; CHUNK];
                    let m = if n == CHUNK {
                        read_full(&mut f, &mut next).await?
                    } else {
                        0
                    };
                    let chunk = cur.get(..n).unwrap_or_default();
                    hasher.update(chunk);
                    total = total.saturating_add(n as u64);
                    if n < CHUNK {
                        send_chunk(&mut s, &mut sealer, chunk, true).await?;
                        break;
                    }
                    send_chunk(&mut s, &mut sealer, chunk, false).await?;
                    if m == 0 {
                        send_chunk(&mut s, &mut sealer, &[], true).await?;
                        break;
                    }
                    cur = next;
                    n = m;
                }
            }
        }
        s.finish().map_err(|_| NetError::Stream("io"))?;
        if total != o.item.size {
            // The file changed while sending; the receiver's size check will fail too.
            return Err(NetError::State("size changed"));
        }
        Ok((*hasher.finalize().as_bytes(), total))
    }

    /// Receiver role. `decide` may veto items (user prompt); size policy applies first.
    pub async fn receive(
        mut self,
        policy: &Policy,
        mut decide: impl FnMut(&Item) -> bool,
    ) -> Result<Vec<Received>, NetError> {
        let Ctrl::Offer { items, .. } = self.recv_ctrl().await? else {
            return Err(self.fail(NetError::Xfer(xfer::XferError::Shape)));
        };
        let ids: Vec<u32> = items
            .iter()
            .filter(|i| (i.size <= policy.max_size || policy.accept_large) && decide(i))
            .map(|i| i.id)
            .collect();
        if ids.is_empty() {
            let reason = if items.iter().any(|i| i.size > policy.max_size) {
                decline::TOO_LARGE
            } else {
                decline::USER
            };
            self.send_ctrl(&Ctrl::Decline { reason }).await?;
            let _ = tokio::time::timeout(IDLE_TIMEOUT, self.conn.closed()).await;
            return Ok(vec![]);
        }
        self.send_ctrl(&Ctrl::Accept { ids: ids.clone() }).await?;
        let mut out = Vec::new();
        for item in items.into_iter().filter(|i| ids.contains(&i.id)) {
            if item.is_inline() {
                out.push(Received { item, path: None });
                continue;
            }
            let tmp = policy.dir.join(format!(".warpshot-{}.part", random_hex()));
            let r = self.receive_stream(&item, &tmp).await;
            let (hash, bytes) = match r {
                Ok(v) => v,
                Err(e) => {
                    let _ = tokio::fs::remove_file(&tmp).await;
                    return Err(self.fail(e));
                }
            };
            let done = self.recv_ctrl().await?;
            let ok = matches!(done, Ctrl::ItemDone { id, blake3, size } if id == item.id && size == item.size && bytes == item.size && blake3 == hash);
            if !ok {
                let _ = tokio::fs::remove_file(&tmp).await;
                self.send_ctrl(&Ctrl::ItemAck {
                    id: item.id,
                    ok: false,
                    err: Some(u64::from(code::PROTOCOL)),
                })
                .await?;
                continue;
            }
            let path = finalize(&policy.dir, &tmp, &item)?;
            self.send_ctrl(&Ctrl::ItemAck {
                id: item.id,
                ok: true,
                err: None,
            })
            .await?;
            out.push(Received {
                item,
                path: Some(path),
            });
        }
        match self.recv_ctrl().await? {
            Ctrl::Bye => close(&self.conn, code::OK),
            _ => return Err(self.fail(NetError::Xfer(xfer::XferError::Shape))),
        }
        Ok(out)
    }

    async fn receive_stream(
        &mut self,
        item: &Item,
        tmp: &Path,
    ) -> Result<([u8; 32], u64), NetError> {
        let mut r = tokio::time::timeout(IDLE_TIMEOUT, self.conn.accept_uni())
            .await
            .map_err(|_| NetError::Timeout)?
            .map_err(|_| NetError::Stream("accept"))?;
        let mut idb = [0u8; 4];
        tokio::time::timeout(IDLE_TIMEOUT, r.read_exact(&mut idb))
            .await
            .map_err(|_| NetError::Timeout)?
            .map_err(|_| NetError::Stream("accept"))?;
        if u32::from_be_bytes(idb) != item.id {
            return Err(NetError::Xfer(xfer::XferError::Sequence));
        }
        let peer_dir = match self.my_dir {
            Dir::Dl => Dir::Ld,
            Dir::Ld => Dir::Dl,
        };
        let mut opener = ItemOpener::new(&self.ks, peer_dir, item.id);
        let mut f = tokio::fs::File::create(tmp).await?;
        let mut hasher = blake3::Hasher::new();
        let mut total = 0u64;
        while !opener.finished() {
            let ct = read_frame(&mut r, CHUNK.saturating_add(16), IDLE_TIMEOUT).await?;
            let (pt, _) = opener.open(&ct)?;
            total = total.saturating_add(pt.len() as u64);
            if total > item.size {
                return Err(NetError::TooLarge);
            }
            hasher.update(&pt);
            f.write_all(&pt).await?;
        }
        f.sync_all().await?;
        Ok((*hasher.finalize().as_bytes(), total))
    }
}

async fn send_chunk(
    s: &mut SendStream,
    sealer: &mut ItemSealer,
    pt: &[u8],
    last: bool,
) -> Result<(), NetError> {
    let ct = sealer.seal(pt, last)?;
    s.write_all(&(ct.len() as u32).to_be_bytes())
        .await
        .map_err(|_| NetError::Stream("io"))?;
    s.write_all(&ct).await.map_err(|_| NetError::Stream("io"))
}

async fn read_full(f: &mut tokio::fs::File, buf: &mut [u8]) -> Result<usize, NetError> {
    let mut n = 0;
    while n < buf.len() {
        let Some(rest) = buf.get_mut(n..) else { break };
        let m = f.read(rest).await?;
        if m == 0 {
            break;
        }
        n = n.saturating_add(m);
    }
    Ok(n)
}

fn random_hex() -> String {
    let mut b = [0u8; 8];
    let _ = keys::random(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Renames the verified temp file to its sanitized, de-duplicated final name
/// and marks it as downloaded from the internet (Windows MOTW).
fn finalize(dir: &Path, tmp: &Path, item: &Item) -> Result<PathBuf, NetError> {
    let fallback = if item.kind == xfer::kind::IMAGE {
        "image.png"
    } else {
        "file"
    };
    let name = sanitize::sanitize(&item.name, fallback);
    let name =
        sanitize::dedupe(&name, |n| dir.join(n).exists()).ok_or(NetError::State("no free name"))?;
    let path = dir.join(name);
    std::fs::rename(tmp, &path)?;
    mark_of_the_web(&path);
    Ok(path)
}

/// Writes the `Zone.Identifier` stream (ZoneId 3 = Internet) on Windows.
pub fn mark_of_the_web(path: &Path) {
    #[cfg(windows)]
    {
        let mut ads = path.as_os_str().to_owned();
        ads.push(":Zone.Identifier");
        let _ = std::fs::write(PathBuf::from(ads), b"[ZoneTransfer]\r\nZoneId=3\r\n");
    }
    #[cfg(not(windows))]
    let _ = path;
}
