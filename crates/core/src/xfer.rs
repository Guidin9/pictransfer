//! Transfer protocol, network-independent part (protocol §8): handshake
//! messages, key schedule, encrypted control messages and item chunks.

use std::fmt;

use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    cbor::{self, Encoder, FieldError, Limits, MapRef, Value},
    keys::{self, EndpointId, KEM_CT_LEN, KEM_PK_LEN, KeyError},
    log::{Head, RecordId},
};

pub const ALPN: &[u8] = b"warpshot/xfer/1";
pub const EKM_LABEL: &[u8] = b"EXPORTER-warpshot-xfer-v1";
pub const TRANSCRIPT_LABEL: &[u8] = b"warpshot/xfer-transcript/v1\0";
pub const KDF_LABEL: &[u8] = b"warpshot/xfer-kdf/v1 ";
pub const MAX_FRAME: usize = 1 << 20;
pub const CHUNK: usize = 64 * 1024;
pub const MAX_ITEMS: usize = 1000;
pub const MAX_INLINE_TEXT: u64 = 64 * 1024;
pub const MAX_NAME: usize = 255;
pub const MAX_MIME: usize = 127;
pub const MAX_LOG_CHUNK: usize = 64;

/// QUIC application close codes (§8.8).
pub mod code {
    pub const OK: u32 = 0x00;
    pub const NOT_MEMBER: u32 = 0x10;
    pub const GROUP_FORK: u32 = 0x11;
    pub const GROUP_MISMATCH: u32 = 0x12;
    pub const HANDSHAKE: u32 = 0x20;
    pub const VERSION: u32 = 0x21;
    pub const CRYPTO: u32 = 0x22;
    pub const PROTOCOL: u32 = 0x23;
    pub const PAIR_PROOF: u32 = 0x24;
    pub const PAIR_EXPIRED: u32 = 0x25;
    pub const PAIR_REJECTED: u32 = 0x26;
    pub const PAIR_OTHER_GROUP: u32 = 0x27;
    pub const DECLINED: u32 = 0x30;
    pub const TOO_LARGE: u32 = 0x31;
    pub const BUSY: u32 = 0x32;
    pub const DIRECT_UNAVAILABLE: u32 = 0x40;
    pub const TIMEOUT: u32 = 0x50;
    pub const INTERNAL: u32 = 0x7f;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XferError {
    Cbor(cbor::Error),
    Field(FieldError),
    Shape,
    Version,
    TooLarge,
    Crypto,
    Kem(KeyError),
    /// Chunk after the last one, or a counter overflow.
    Sequence,
}

impl XferError {
    /// The close code this error maps to.
    pub fn close_code(&self) -> u32 {
        match self {
            Self::Version => code::VERSION,
            Self::Crypto | Self::Kem(_) => code::CRYPTO,
            Self::TooLarge => code::TOO_LARGE,
            _ => code::PROTOCOL,
        }
    }
}

impl fmt::Display for XferError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl std::error::Error for XferError {}

impl From<cbor::Error> for XferError {
    fn from(e: cbor::Error) -> Self {
        Self::Cbor(e)
    }
}

impl From<FieldError> for XferError {
    fn from(e: FieldError) -> Self {
        Self::Field(e)
    }
}

fn decode(raw: &[u8]) -> Result<Value<'_>, XferError> {
    if raw.len() > MAX_FRAME {
        return Err(XferError::TooLarge);
    }
    Ok(cbor::decode(
        raw,
        &Limits {
            max_depth: 8,
            max_input: MAX_FRAME,
            max_items: MAX_ITEMS,
        },
    )?)
}

fn encode_head(e: &mut Encoder, h: &Head) {
    e.map(2).uint(0).uint(h.seq).uint(1).bytes(&h.id.0);
}

fn parse_head(m: Option<MapRef<'_, '_>>, key: u64) -> Result<Head, XferError> {
    let h = m.ok_or(XferError::Field(FieldError::Missing(key)))?;
    Ok(Head {
        seq: h.uint(0)?,
        id: RecordId(h.fixed(1)?),
    })
}

fn uint_list(a: Option<&[Value<'_>]>, key: u64) -> Result<Vec<u64>, XferError> {
    a.ok_or(XferError::Field(FieldError::Missing(key)))?
        .iter()
        .map(|v| match v {
            Value::Uint(n) => Ok(*n),
            _ => Err(XferError::Shape),
        })
        .collect()
}

/// `Hello` (D → L).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    pub session: [u8; 16],
    pub ek: Vec<u8>,
    pub head: Head,
    pub caps: Vec<u64>,
}

impl Hello {
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.map(5)
            .uint(0)
            .uint(1)
            .uint(1)
            .bytes(&self.session)
            .uint(2)
            .bytes(&self.ek)
            .uint(3);
        encode_head(&mut e, &self.head);
        e.uint(4).array(self.caps.len());
        for c in &self.caps {
            e.uint(*c);
        }
        e.into_bytes()
    }

    pub fn parse(raw: &[u8]) -> Result<Self, XferError> {
        let v = decode(raw)?;
        let m = MapRef::new(&v).ok_or(XferError::Shape)?;
        if m.uint(0)? != 1 {
            return Err(XferError::Version);
        }
        let ek = m.bytes(2)?;
        if ek.len() != KEM_PK_LEN {
            return Err(XferError::Shape);
        }
        Ok(Self {
            session: m.fixed(1)?,
            ek: ek.to_vec(),
            head: parse_head(m.opt_map(3)?, 3)?,
            caps: uint_list(m.opt_array(4)?, 4)?,
        })
    }
}

/// `HelloAck` (L → D).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloAck {
    pub ct: Vec<u8>,
    pub head: Head,
    pub caps: Vec<u64>,
}

impl HelloAck {
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.map(4).uint(0).uint(1).uint(1).bytes(&self.ct).uint(2);
        encode_head(&mut e, &self.head);
        e.uint(3).array(self.caps.len());
        for c in &self.caps {
            e.uint(*c);
        }
        e.into_bytes()
    }

    pub fn parse(raw: &[u8]) -> Result<Self, XferError> {
        let v = decode(raw)?;
        let m = MapRef::new(&v).ok_or(XferError::Shape)?;
        if m.uint(0)? != 1 {
            return Err(XferError::Version);
        }
        let ct = m.bytes(1)?;
        if ct.len() != KEM_CT_LEN {
            return Err(XferError::Shape);
        }
        Ok(Self {
            ct: ct.to_vec(),
            head: parse_head(m.opt_map(2)?, 2)?,
            caps: uint_list(m.opt_array(3)?, 3)?,
        })
    }
}

/// The dialer's ephemeral X-Wing key for one connection.
pub struct EphemeralKem {
    seed: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for EphemeralKem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EphemeralKem(<redacted>)")
    }
}

impl EphemeralKem {
    pub fn generate() -> Result<Self, XferError> {
        let mut seed = Zeroizing::new([0u8; 32]);
        keys::random(seed.as_mut()).map_err(XferError::Kem)?;
        Ok(Self { seed })
    }

    #[cfg(test)]
    pub(crate) fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            seed: Zeroizing::new(seed),
        }
    }

    pub fn public_key(&self) -> Vec<u8> {
        keys::KemKey::from_seed(&self.seed).public_key()
    }

    /// Consumes the key: it is zeroized after decapsulation (§8.3).
    pub fn decapsulate(self, ct: &[u8]) -> Result<Zeroizing<[u8; 32]>, XferError> {
        keys::KemKey::from_seed(&self.seed)
            .decapsulate(ct)
            .map_err(XferError::Kem)
    }
}

/// Listener side of the KEM: `(ss, ct) = Encaps(ek)`.
pub fn encapsulate(ek: &[u8]) -> Result<(Zeroizing<[u8; 32]>, Vec<u8>), XferError> {
    let mut eseed = Zeroizing::new([0u8; 64]);
    keys::random(eseed.as_mut()).map_err(XferError::Kem)?;
    encapsulate_with(ek, &eseed)
}

pub(crate) fn encapsulate_with(
    ek: &[u8],
    eseed: &[u8; 64],
) -> Result<(Zeroizing<[u8; 32]>, Vec<u8>), XferError> {
    let ek = x_wing::EncapsulationKey::try_from(ek).map_err(|_| XferError::Shape)?;
    let (ct, ss) = ek.encapsulate_deterministic(&(*eseed).into());
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(ss.as_slice());
    Ok((out, ct.as_slice().to_vec()))
}

/// Direction byte (§8.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    /// Dialer → listener.
    Dl = 0,
    /// Listener → dialer.
    Ld = 1,
}

/// Keys derived after the handshake (§8.3).
pub struct KeySchedule {
    prk: Zeroizing<[u8; 32]>,
    th: [u8; 32],
}

impl fmt::Debug for KeySchedule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KeySchedule(<redacted>)")
    }
}

/// `th` over the exact frame payloads and both endpoint ids.
pub fn transcript(
    hello: &[u8],
    hello_ack: &[u8],
    eid_d: &EndpointId,
    eid_l: &EndpointId,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(TRANSCRIPT_LABEL);
    h.update((hello.len() as u32).to_be_bytes());
    h.update(hello);
    h.update((hello_ack.len() as u32).to_be_bytes());
    h.update(hello_ack);
    h.update(eid_d.0);
    h.update(eid_l.0);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

impl KeySchedule {
    pub fn new(ss: &[u8; 32], ekm: &[u8; 32], th: [u8; 32]) -> Self {
        let (prk, _) = Hkdf::<Sha256>::extract(Some(ekm), ss);
        let mut p = Zeroizing::new([0u8; 32]);
        p.copy_from_slice(&prk);
        Self { prk: p, th }
    }

    fn expand(&self, info_tail: &[&[u8]]) -> Zeroizing<[u8; 32]> {
        let mut info = KDF_LABEL.to_vec();
        for part in info_tail {
            info.extend_from_slice(part);
        }
        info.extend_from_slice(&self.th);
        let mut out = Zeroizing::new([0u8; 32]);
        // PRK is 32 bytes and L = 32 is valid for SHA-256, so neither call can fail.
        if let Ok(h) = Hkdf::<Sha256>::from_prk(self.prk.as_ref()) {
            let _ = h.expand(&info, out.as_mut());
        }
        out
    }

    pub fn ctrl_key(&self, dir: Dir) -> Zeroizing<[u8; 32]> {
        self.expand(&[match dir {
            Dir::Dl => b"ctrl d>l",
            Dir::Ld => b"ctrl l>d",
        }])
    }

    pub fn item_key(&self, dir: Dir, id: u32) -> Zeroizing<[u8; 32]> {
        self.expand(&[b"item", &[dir as u8], &id.to_be_bytes()])
    }

    pub fn ctrl(&self, dir: Dir) -> CtrlCipher {
        CtrlCipher {
            key: self.ctrl_key(dir),
            counter: 0,
        }
    }
}

/// One direction of the encrypted control stream (§8.4).
pub struct CtrlCipher {
    key: Zeroizing<[u8; 32]>,
    counter: u64,
}

impl fmt::Debug for CtrlCipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CtrlCipher(<redacted>, counter={})", self.counter)
    }
}

fn ctrl_nonce(counter: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    for (dst, src) in n.iter_mut().skip(4).zip(counter.to_be_bytes()) {
        *dst = src;
    }
    n
}

impl CtrlCipher {
    pub fn seal(&mut self, pt: &[u8]) -> Result<Vec<u8>, XferError> {
        let n = ctrl_nonce(self.counter);
        self.counter = self.counter.checked_add(1).ok_or(XferError::Sequence)?;
        ChaCha20Poly1305::new(&(*self.key).into())
            .encrypt(
                &n.into(),
                Payload {
                    msg: pt,
                    aad: b"ctrl",
                },
            )
            .map_err(|_| XferError::Crypto)
    }

    pub fn open(&mut self, ct: &[u8]) -> Result<Zeroizing<Vec<u8>>, XferError> {
        let n = ctrl_nonce(self.counter);
        let pt = ChaCha20Poly1305::new(&(*self.key).into())
            .decrypt(
                &n.into(),
                Payload {
                    msg: ct,
                    aad: b"ctrl",
                },
            )
            .map_err(|_| XferError::Crypto)?;
        self.counter = self.counter.checked_add(1).ok_or(XferError::Sequence)?;
        Ok(Zeroizing::new(pt))
    }
}

fn chunk_nonce(index: u32, last: bool) -> [u8; 12] {
    let mut n = [0u8; 12];
    for (dst, src) in n.iter_mut().skip(7).zip(index.to_be_bytes()) {
        *dst = src;
    }
    if let Some(l) = n.get_mut(11) {
        *l = u8::from(last);
    }
    n
}

/// STREAM sealer for one item (§8.6).
pub struct ItemSealer {
    key: Zeroizing<[u8; 32]>,
    id: u32,
    index: u32,
    done: bool,
}

impl fmt::Debug for ItemSealer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ItemSealer(id={}, index={})", self.id, self.index)
    }
}

impl ItemSealer {
    pub fn new(ks: &KeySchedule, dir: Dir, id: u32) -> Self {
        Self {
            key: ks.item_key(dir, id),
            id,
            index: 0,
            done: false,
        }
    }

    pub fn seal(&mut self, pt: &[u8], last: bool) -> Result<Vec<u8>, XferError> {
        if self.done || pt.len() > CHUNK || (!last && pt.len() != CHUNK) {
            return Err(XferError::Sequence);
        }
        let ct = ChaCha20Poly1305::new(&(*self.key).into())
            .encrypt(
                &chunk_nonce(self.index, last).into(),
                Payload {
                    msg: pt,
                    aad: &self.id.to_be_bytes(),
                },
            )
            .map_err(|_| XferError::Crypto)?;
        self.done = last;
        self.index = self.index.checked_add(1).ok_or(XferError::Sequence)?;
        Ok(ct)
    }
}

/// STREAM opener for one item. Truncation (no `last`) and reordering fail.
pub struct ItemOpener {
    key: Zeroizing<[u8; 32]>,
    id: u32,
    index: u32,
    done: bool,
}

impl fmt::Debug for ItemOpener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ItemOpener(id={}, index={})", self.id, self.index)
    }
}

impl ItemOpener {
    pub fn new(ks: &KeySchedule, dir: Dir, id: u32) -> Self {
        Self {
            key: ks.item_key(dir, id),
            id,
            index: 0,
            done: false,
        }
    }

    /// Opens the next chunk. The sender's `last` flag is not transmitted; the
    /// opener tries "not last" for a full-size chunk and "last" otherwise, and a
    /// full-size last chunk falls back to `last = true`.
    pub fn open(&mut self, ct: &[u8]) -> Result<(Zeroizing<Vec<u8>>, bool), XferError> {
        if self.done || ct.len() > CHUNK.saturating_add(16) {
            return Err(XferError::Sequence);
        }
        let cipher = ChaCha20Poly1305::new(&(*self.key).into());
        let aad = self.id.to_be_bytes();
        let try_open = |last: bool| {
            cipher.decrypt(
                &chunk_nonce(self.index, last).into(),
                Payload { msg: ct, aad: &aad },
            )
        };
        let full = ct.len() == CHUNK.saturating_add(16);
        let (pt, last) = if full {
            match try_open(false) {
                Ok(pt) => (pt, false),
                Err(_) => (try_open(true).map_err(|_| XferError::Crypto)?, true),
            }
        } else {
            (try_open(true).map_err(|_| XferError::Crypto)?, true)
        };
        self.index = self.index.checked_add(1).ok_or(XferError::Sequence)?;
        self.done = last;
        Ok((Zeroizing::new(pt), last))
    }

    pub fn finished(&self) -> bool {
        self.done
    }
}

/// Item kinds.
pub mod kind {
    pub const TEXT: u64 = 1;
    pub const IMAGE: u64 = 2;
    pub const FILE: u64 = 3;
}

/// `Item` (§8.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    pub id: u32,
    pub kind: u64,
    pub name: String,
    pub mime: String,
    pub size: u64,
    pub created_at: u64,
    /// Inline text (kind = text, size ≤ 64 KiB).
    pub text: Option<String>,
}

impl Item {
    fn encode(&self, e: &mut Encoder) {
        e.map(if self.text.is_some() { 7 } else { 6 });
        e.uint(0)
            .uint(u64::from(self.id))
            .uint(1)
            .uint(self.kind)
            .uint(2)
            .text(&self.name)
            .uint(3)
            .text(&self.mime);
        e.uint(4).uint(self.size).uint(5).uint(self.created_at);
        if let Some(t) = &self.text {
            e.uint(6).text(t);
        }
    }

    fn parse(v: &Value<'_>) -> Result<Self, XferError> {
        let m = MapRef::new(v).ok_or(XferError::Shape)?;
        let id = u32::try_from(m.uint(0)?).map_err(|_| XferError::Shape)?;
        let kind = m.uint(1)?;
        if !(1..=3).contains(&kind) {
            return Err(XferError::Shape);
        }
        let name = m.text(2)?;
        let mime = m.text(3)?;
        if name.len() > MAX_NAME || mime.len() > MAX_MIME {
            return Err(XferError::Shape);
        }
        let size = m.uint(4)?;
        let text = m.opt_text(6)?;
        if let Some(t) = text
            && (kind != kind::TEXT || size > MAX_INLINE_TEXT || t.len() as u64 != size)
        {
            return Err(XferError::Shape);
        }
        Ok(Self {
            id,
            kind,
            name: name.to_owned(),
            mime: mime.to_owned(),
            size,
            created_at: m.uint(5)?,
            text: text.map(str::to_owned),
        })
    }

    pub fn is_inline(&self) -> bool {
        self.text.is_some()
    }
}

/// Encrypted control messages (§8.4); key 0 is the type `t`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ctrl {
    Offer {
        session: [u8; 16],
        items: Vec<Item>,
    },
    Accept {
        ids: Vec<u32>,
    },
    Decline {
        reason: u64,
    },
    ItemDone {
        id: u32,
        blake3: [u8; 32],
        size: u64,
    },
    ItemAck {
        id: u32,
        ok: bool,
        err: Option<u64>,
    },
    Cancel {
        id: Option<u32>,
    },
    Error {
        code: u64,
        detail: Option<String>,
    },
    Bye,
    LogReq {
        after: u64,
    },
    LogRecs {
        records: Vec<Vec<u8>>,
        more: bool,
    },
}

pub mod decline {
    pub const USER: u64 = 1;
    pub const TOO_LARGE: u64 = 2;
    pub const BUSY: u64 = 3;
    pub const POLICY: u64 = 4;
}

impl Ctrl {
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        match self {
            Ctrl::Offer { session, items } => {
                e.map(3)
                    .uint(0)
                    .uint(1)
                    .uint(1)
                    .bytes(session)
                    .uint(2)
                    .array(items.len());
                for i in items {
                    i.encode(&mut e);
                }
            }
            Ctrl::Accept { ids } => {
                e.map(2).uint(0).uint(2).uint(1).array(ids.len());
                for id in ids {
                    e.uint(u64::from(*id));
                }
            }
            Ctrl::Decline { reason } => {
                e.map(2).uint(0).uint(3).uint(1).uint(*reason);
            }
            Ctrl::ItemDone { id, blake3, size } => {
                e.map(4)
                    .uint(0)
                    .uint(4)
                    .uint(1)
                    .uint(u64::from(*id))
                    .uint(2)
                    .bytes(blake3)
                    .uint(3)
                    .uint(*size);
            }
            Ctrl::ItemAck { id, ok, err } => {
                e.map(if err.is_some() { 4 } else { 3 })
                    .uint(0)
                    .uint(5)
                    .uint(1)
                    .uint(u64::from(*id))
                    .uint(2)
                    .bool(*ok);
                if let Some(c) = err {
                    e.uint(3).uint(*c);
                }
            }
            Ctrl::Cancel { id } => {
                e.map(if id.is_some() { 2 } else { 1 }).uint(0).uint(6);
                if let Some(i) = id {
                    e.uint(1).uint(u64::from(*i));
                }
            }
            Ctrl::Error { code, detail } => {
                e.map(if detail.is_some() { 3 } else { 2 })
                    .uint(0)
                    .uint(7)
                    .uint(1)
                    .uint(*code);
                if let Some(d) = detail {
                    e.uint(2).text(d);
                }
            }
            Ctrl::Bye => {
                e.map(1).uint(0).uint(8);
            }
            Ctrl::LogReq { after } => {
                e.map(2).uint(0).uint(9).uint(1).uint(*after);
            }
            Ctrl::LogRecs { records, more } => {
                e.map(3).uint(0).uint(10).uint(1).array(records.len());
                for r in records {
                    e.bytes(r);
                }
                e.uint(2).bool(*more);
            }
        }
        e.into_bytes()
    }

    pub fn parse(raw: &[u8]) -> Result<Self, XferError> {
        let v = decode(raw)?;
        let m = MapRef::new(&v).ok_or(XferError::Shape)?;
        let id32 = |k: u64| -> Result<u32, XferError> {
            u32::try_from(m.uint(k)?).map_err(|_| XferError::Shape)
        };
        Ok(match m.uint(0)? {
            1 => {
                let list = m
                    .opt_array(2)?
                    .ok_or(XferError::Field(FieldError::Missing(2)))?;
                if list.len() > MAX_ITEMS {
                    return Err(XferError::TooLarge);
                }
                let items = list
                    .iter()
                    .map(Item::parse)
                    .collect::<Result<Vec<_>, _>>()?;
                let mut ids: Vec<u32> = items.iter().map(|i| i.id).collect();
                ids.sort_unstable();
                if ids.windows(2).any(|w| matches!(w, [a, b] if a == b)) {
                    return Err(XferError::Shape);
                }
                Ctrl::Offer {
                    session: m.fixed(1)?,
                    items,
                }
            }
            2 => Ctrl::Accept {
                ids: uint_list(m.opt_array(1)?, 1)?
                    .into_iter()
                    .map(|n| u32::try_from(n).map_err(|_| XferError::Shape))
                    .collect::<Result<_, _>>()?,
            },
            3 => Ctrl::Decline { reason: m.uint(1)? },
            4 => Ctrl::ItemDone {
                id: id32(1)?,
                blake3: m.fixed(2)?,
                size: m.uint(3)?,
            },
            5 => Ctrl::ItemAck {
                id: id32(1)?,
                ok: m
                    .opt_bool(2)?
                    .ok_or(XferError::Field(FieldError::Missing(2)))?,
                err: m.opt_uint(3)?,
            },
            6 => Ctrl::Cancel {
                id: m
                    .opt_uint(1)?
                    .map(|n| u32::try_from(n).map_err(|_| XferError::Shape))
                    .transpose()?,
            },
            7 => Ctrl::Error {
                code: m.uint(1)?,
                detail: m.opt_text(2)?.map(str::to_owned),
            },
            8 => Ctrl::Bye,
            9 => Ctrl::LogReq { after: m.uint(1)? },
            10 => {
                let list = m
                    .opt_array(1)?
                    .ok_or(XferError::Field(FieldError::Missing(1)))?;
                if list.len() > MAX_LOG_CHUNK {
                    return Err(XferError::TooLarge);
                }
                let records = list
                    .iter()
                    .map(|r| match r {
                        Value::Bytes(b) => Ok(b.to_vec()),
                        _ => Err(XferError::Shape),
                    })
                    .collect::<Result<_, _>>()?;
                Ctrl::LogRecs {
                    records,
                    more: m
                        .opt_bool(2)?
                        .ok_or(XferError::Field(FieldError::Missing(2)))?,
                }
            }
            _ => return Err(XferError::Shape),
        })
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;

    fn schedule() -> KeySchedule {
        KeySchedule::new(&[1; 32], &[2; 32], [3; 32])
    }

    #[test]
    fn handshake_messages_roundtrip_and_reject() {
        let head = Head {
            seq: 3,
            id: RecordId([4; 32]),
        };
        let ek = EphemeralKem::from_seed([5; 32]);
        let h = Hello {
            session: [0; 16],
            ek: ek.public_key(),
            head,
            caps: vec![],
        };
        assert_eq!(Hello::parse(&h.encode()).unwrap(), h);
        let (ss_l, ct) = encapsulate_with(&h.ek, &[6; 64]).unwrap();
        let a = HelloAck {
            ct: ct.clone(),
            head,
            caps: vec![1],
        };
        assert_eq!(HelloAck::parse(&a.encode()).unwrap(), a);
        let ss_d = ek.decapsulate(&ct).unwrap();
        assert_eq!(*ss_d, *ss_l);
        // Short ek / ct are rejected.
        let mut bad = h.clone();
        bad.ek.pop();
        assert_eq!(Hello::parse(&bad.encode()), Err(XferError::Shape));
        let mut bad = a.clone();
        bad.ct.pop();
        assert_eq!(HelloAck::parse(&bad.encode()), Err(XferError::Shape));
    }

    #[test]
    fn ctrl_cipher_counters_and_tamper() {
        let ks = schedule();
        let (mut tx, mut rx) = (ks.ctrl(Dir::Dl), ks.ctrl(Dir::Dl));
        let c0 = tx.seal(b"a").unwrap();
        let c1 = tx.seal(b"b").unwrap();
        // Reordering fails (counter mismatch).
        assert_eq!(
            rx.clone_for_test().open(&c1).unwrap_err(),
            XferError::Crypto
        );
        assert_eq!(&**rx.open(&c0).unwrap(), b"a");
        assert_eq!(&**rx.open(&c1).unwrap(), b"b");
        // Other direction's key does not open.
        let mut other = ks.ctrl(Dir::Ld);
        assert!(other.open(&c0).is_err());
        let mut t = c0.clone();
        t[0] ^= 1;
        assert!(ks.ctrl(Dir::Dl).open(&t).is_err());
    }

    impl CtrlCipher {
        fn clone_for_test(&self) -> Self {
            Self {
                key: self.key.clone(),
                counter: self.counter,
            }
        }
    }

    #[test]
    fn item_stream_seal_open_truncation_reorder() {
        let ks = schedule();
        let data: Vec<u8> = (0..(CHUNK * 2 + 100)).map(|i| i as u8).collect();
        let mut s = ItemSealer::new(&ks, Dir::Ld, 7);
        let c = [
            s.seal(&data[..CHUNK], false).unwrap(),
            s.seal(&data[CHUNK..2 * CHUNK], false).unwrap(),
            s.seal(&data[2 * CHUNK..], true).unwrap(),
        ];
        assert!(s.seal(b"", true).is_err());
        let mut o = ItemOpener::new(&ks, Dir::Ld, 7);
        let mut out = Vec::new();
        for ch in &c {
            let (pt, _) = o.open(ch).unwrap();
            out.extend_from_slice(&pt);
        }
        assert!(o.finished());
        assert_eq!(out, data);
        // Reordered chunk fails.
        let mut o = ItemOpener::new(&ks, Dir::Ld, 7);
        assert!(o.open(&c[1]).is_err());
        // Wrong item id fails.
        assert!(ItemOpener::new(&ks, Dir::Ld, 8).open(&c[0]).is_err());
        // Truncation: without the last chunk the opener never finishes.
        let mut o = ItemOpener::new(&ks, Dir::Ld, 7);
        o.open(&c[0]).unwrap();
        o.open(&c[1]).unwrap();
        assert!(!o.finished());
        // A full-size chunk sealed as last is detected as last.
        let mut s = ItemSealer::new(&ks, Dir::Ld, 9);
        let full = s.seal(&data[..CHUNK], true).unwrap();
        let mut o = ItemOpener::new(&ks, Dir::Ld, 9);
        assert!(o.open(&full).unwrap().1);
        // Empty item = one empty last chunk.
        let mut s = ItemSealer::new(&ks, Dir::Ld, 10);
        let e = s.seal(b"", true).unwrap();
        let mut o = ItemOpener::new(&ks, Dir::Ld, 10);
        assert_eq!(o.open(&e).unwrap().0.len(), 0);
        // A non-last short chunk is refused by the sealer.
        assert!(ItemSealer::new(&ks, Dir::Ld, 11).seal(b"x", false).is_err());
    }

    #[test]
    fn ctrl_messages_roundtrip() {
        let item = Item {
            id: 1,
            kind: kind::TEXT,
            name: "note.txt".into(),
            mime: "text/plain".into(),
            size: 5,
            created_at: 9,
            text: Some("hello".into()),
        };
        let file = Item {
            id: 2,
            kind: kind::FILE,
            name: "a.bin".into(),
            mime: "application/octet-stream".into(),
            size: 1 << 30,
            created_at: 9,
            text: None,
        };
        for m in [
            Ctrl::Offer {
                session: [1; 16],
                items: vec![item.clone(), file.clone()],
            },
            Ctrl::Accept { ids: vec![1, 2] },
            Ctrl::Decline {
                reason: decline::TOO_LARGE,
            },
            Ctrl::ItemDone {
                id: 2,
                blake3: [7; 32],
                size: 1 << 30,
            },
            Ctrl::ItemAck {
                id: 2,
                ok: false,
                err: Some(3),
            },
            Ctrl::ItemAck {
                id: 2,
                ok: true,
                err: None,
            },
            Ctrl::Cancel { id: None },
            Ctrl::Cancel { id: Some(2) },
            Ctrl::Error {
                code: 0x23,
                detail: Some("bad".into()),
            },
            Ctrl::Bye,
            Ctrl::LogReq { after: 4 },
            Ctrl::LogRecs {
                records: vec![vec![1, 2], vec![3]],
                more: true,
            },
        ] {
            assert_eq!(Ctrl::parse(&m.encode()).unwrap(), m);
        }
        // Inline text must match size and kind.
        let mut bad = item.clone();
        bad.size = 6;
        assert!(
            Ctrl::parse(
                &Ctrl::Offer {
                    session: [0; 16],
                    items: vec![bad]
                }
                .encode()
            )
            .is_err()
        );
        let mut bad = file.clone();
        bad.text = Some("x".into());
        assert!(
            Ctrl::parse(
                &Ctrl::Offer {
                    session: [0; 16],
                    items: vec![bad]
                }
                .encode()
            )
            .is_err()
        );
        // Duplicate item ids.
        assert!(
            Ctrl::parse(
                &Ctrl::Offer {
                    session: [0; 16],
                    items: vec![file.clone(), file.clone()]
                }
                .encode()
            )
            .is_err()
        );
        // Name too long.
        let mut bad = file;
        bad.name = "n".repeat(256);
        assert!(
            Ctrl::parse(
                &Ctrl::Offer {
                    session: [0; 16],
                    items: vec![bad]
                }
                .encode()
            )
            .is_err()
        );
    }

    #[test]
    fn keys_are_direction_and_item_separated() {
        let ks = schedule();
        assert_ne!(*ks.ctrl_key(Dir::Dl), *ks.ctrl_key(Dir::Ld));
        assert_ne!(*ks.item_key(Dir::Dl, 1), *ks.item_key(Dir::Ld, 1));
        assert_ne!(*ks.item_key(Dir::Dl, 1), *ks.item_key(Dir::Dl, 2));
        let th2 = KeySchedule::new(&[1; 32], &[2; 32], [4; 32]);
        assert_ne!(*ks.ctrl_key(Dir::Dl), *th2.ctrl_key(Dir::Dl));
    }
}
