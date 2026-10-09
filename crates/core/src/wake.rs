//! Wake envelopes (protocol §7): X-Wing KEM + HKDF + ChaCha20-Poly1305,
//! addressed to the recipient's static KEM key and signed by the sender.

use std::{collections::HashMap, fmt, net::SocketAddr};

use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{
    cbor::{self, Encoder, FieldError, Limits, MapRef, Value},
    keys::{self, EndpointId, IdentityKey, KEM_CT_LEN, KEM_PK_LEN, KemKey, kid, verify_strict},
    log::{GroupId, Head, Log, RecordId},
};

pub const WAKE_SIG_LABEL: &[u8] = b"warpshot/wake-sig/v1\0";
pub const WAKE_KDF_LABEL: &[u8] = b"warpshot/wake-kdf/v1";
/// §10: 3800 base64url characters.
pub const MAX_ENVELOPE_B64U: usize = 3800;
pub const MAX_ENVELOPE: usize = MAX_ENVELOPE_B64U * 3 / 4;
pub const CONNECT_MAX_AGE_MS: u64 = 120 * 1000;
pub const GROUP_CHANGED_MAX_AGE_MS: u64 = 24 * 3600 * 1000;
pub const REPLAY_WINDOW_MS: u64 = 10 * 60 * 1000;

/// `DialInfo` (§3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DialInfo {
    pub relay: Option<String>,
    pub addrs: Vec<SocketAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Preview {
    pub count: u64,
    pub total_size: u64,
    pub kinds: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    Connect {
        session: [u8; 16],
        dial: DialInfo,
        preview: Option<Preview>,
    },
    GroupChanged,
}

/// The signed `Inner` map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inner {
    pub kind: Kind,
    pub ts: u64,
    pub nonce: [u8; 16],
    pub group_id: GroupId,
    pub head: Head,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WakeError {
    TooLarge,
    Cbor(cbor::Error),
    Field(FieldError),
    Shape,
    Version,
    UnknownKid,
    Decapsulation,
    Aead,
    /// `sender ∉ S` but its head is ahead of ours: sync the log, then retry (§7.3 step 3).
    NeedSync,
    NotMember,
    BadSignature,
    GroupMismatch,
    Stale,
    Replay,
    Rng,
}

impl fmt::Display for WakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl std::error::Error for WakeError {}

impl From<cbor::Error> for WakeError {
    fn from(e: cbor::Error) -> Self {
        Self::Cbor(e)
    }
}

impl From<FieldError> for WakeError {
    fn from(e: FieldError) -> Self {
        Self::Field(e)
    }
}

impl Inner {
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        let n = match &self.kind {
            Kind::Connect { preview, .. } => {
                if preview.is_some() {
                    8
                } else {
                    7
                }
            }
            Kind::GroupChanged => 5,
        };
        e.map(n);
        let kind = match self.kind {
            Kind::Connect { .. } => 1,
            Kind::GroupChanged => 2,
        };
        e.uint(0)
            .uint(kind)
            .uint(1)
            .uint(self.ts)
            .uint(2)
            .bytes(&self.nonce)
            .uint(3)
            .bytes(&self.group_id.0);
        if let Kind::Connect {
            session,
            dial,
            preview,
        } = &self.kind
        {
            e.uint(4).bytes(session);
            e.uint(5).map(if dial.relay.is_some() { 2 } else { 1 });
            if let Some(r) = &dial.relay {
                e.uint(0).text(r);
            }
            e.uint(1).array(dial.addrs.len());
            for a in &dial.addrs {
                e.text(&a.to_string());
            }
            if let Some(p) = preview {
                e.uint(6)
                    .map(3)
                    .uint(0)
                    .uint(p.count)
                    .uint(1)
                    .uint(p.total_size)
                    .uint(2)
                    .array(p.kinds.len());
                for k in &p.kinds {
                    e.uint(*k);
                }
            }
        }
        e.uint(7)
            .map(2)
            .uint(0)
            .uint(self.head.seq)
            .uint(1)
            .bytes(&self.head.id.0);
        e.into_bytes()
    }

    pub fn parse(raw: &[u8]) -> Result<Self, WakeError> {
        let v = cbor::decode(raw, &Limits::new(MAX_ENVELOPE))?;
        let m = MapRef::new(&v).ok_or(WakeError::Shape)?;
        let head = m
            .opt_map(7)?
            .ok_or(WakeError::Field(FieldError::Missing(7)))?;
        let head = Head {
            seq: head.uint(0)?,
            id: RecordId(head.fixed(1)?),
        };
        let kind = match m.uint(0)? {
            1 => {
                let d = m
                    .opt_map(5)?
                    .ok_or(WakeError::Field(FieldError::Missing(5)))?;
                let relay = d.opt_text(0)?;
                if relay.is_some_and(|r| r.len() > 255) {
                    return Err(WakeError::Shape);
                }
                let list = d
                    .opt_array(1)?
                    .ok_or(WakeError::Field(FieldError::Missing(1)))?;
                if list.len() > 8 {
                    return Err(WakeError::Shape);
                }
                let mut addrs = Vec::with_capacity(list.len());
                for a in list {
                    let Value::Text(s) = a else {
                        return Err(WakeError::Shape);
                    };
                    addrs.push(s.parse::<SocketAddr>().map_err(|_| WakeError::Shape)?);
                }
                let preview = match m.opt_map(6)? {
                    None => None,
                    Some(p) => {
                        let kinds = p
                            .opt_array(2)?
                            .ok_or(WakeError::Field(FieldError::Missing(2)))?;
                        let kinds = kinds
                            .iter()
                            .map(|k| match k {
                                Value::Uint(n) => Ok(*n),
                                _ => Err(WakeError::Shape),
                            })
                            .collect::<Result<Vec<_>, _>>()?;
                        Some(Preview {
                            count: p.uint(0)?,
                            total_size: p.uint(1)?,
                            kinds,
                        })
                    }
                };
                Kind::Connect {
                    session: m.fixed(4)?,
                    dial: DialInfo {
                        relay: relay.map(str::to_owned),
                        addrs,
                    },
                    preview,
                }
            }
            2 => Kind::GroupChanged,
            _ => return Err(WakeError::Shape),
        };
        Ok(Self {
            kind,
            ts: m.uint(1)?,
            nonce: m.fixed(2)?,
            group_id: GroupId(m.fixed(3)?),
            head,
        })
    }
}

fn wake_key(
    ss: &[u8; 32],
    recipient: &EndpointId,
    kid: &[u8; 8],
) -> Result<Zeroizing<[u8; 32]>, WakeError> {
    let mut info = WAKE_KDF_LABEL.to_vec();
    info.extend_from_slice(&recipient.0);
    info.extend_from_slice(kid);
    let mut k = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(&[]), ss)
        .expand(&info, k.as_mut())
        .map_err(|_| WakeError::Shape)?;
    Ok(k)
}

/// Seals `inner` for `recipient` (whose `DeviceInfo.kem_pk` is given).
pub fn seal(
    sender: &IdentityKey,
    recipient: &EndpointId,
    recipient_kem_pk: &[u8],
    inner: &Inner,
) -> Result<Vec<u8>, WakeError> {
    let mut eseed = Zeroizing::new([0u8; 64]);
    keys::random(eseed.as_mut()).map_err(|_| WakeError::Rng)?;
    seal_with(sender, recipient, recipient_kem_pk, inner, &eseed)
}

/// `seal` with explicit encapsulation randomness (test vectors).
pub(crate) fn seal_with(
    sender: &IdentityKey,
    recipient: &EndpointId,
    recipient_kem_pk: &[u8],
    inner: &Inner,
    eseed: &[u8; 64],
) -> Result<Vec<u8>, WakeError> {
    if recipient_kem_pk.len() != KEM_PK_LEN {
        return Err(WakeError::Shape);
    }
    let ek = x_wing::EncapsulationKey::try_from(recipient_kem_pk).map_err(|_| WakeError::Shape)?;
    let (ct_kem, ss) = ek.encapsulate_deterministic(&(*eseed).into());
    let mut ss_arr = Zeroizing::new([0u8; 32]);
    ss_arr.copy_from_slice(ss.as_slice());
    let kid = kid(recipient_kem_pk);
    let k = wake_key(&ss_arr, recipient, &kid)?;

    let inner_raw = inner.encode();
    let mut msg = WAKE_SIG_LABEL.to_vec();
    msg.extend_from_slice(&recipient.0);
    msg.extend_from_slice(&inner_raw);
    let sig = sender.sign(&msg);
    let mut pt = Encoder::new();
    pt.array(3)
        .bytes(&inner_raw)
        .bytes(&sender.endpoint_id().0)
        .bytes(&sig);
    let pt = Zeroizing::new(pt.into_bytes());

    let mut aad = vec![1u8];
    aad.extend_from_slice(&kid);
    aad.extend_from_slice(ct_kem.as_slice());
    let ct = ChaCha20Poly1305::new(&(*k).into())
        .encrypt(
            &[0u8; 12].into(),
            Payload {
                msg: &pt,
                aad: &aad,
            },
        )
        .map_err(|_| WakeError::Aead)?;

    let mut e = Encoder::new();
    e.array(4)
        .uint(1)
        .bytes(&kid)
        .bytes(ct_kem.as_slice())
        .bytes(&ct);
    let out = e.into_bytes();
    if out.len() > MAX_ENVELOPE {
        return Err(WakeError::TooLarge);
    }
    Ok(out)
}

/// A decrypted but not yet authorized envelope (§7.3 steps 1–2).
#[derive(Debug, Clone)]
pub struct Opened {
    pub sender: EndpointId,
    inner_raw: Vec<u8>,
    sig: [u8; 64],
    pub inner: Inner,
}

/// Steps 1–2: select the KEM key by `kid`, decapsulate, open the AEAD, decode.
pub fn open<'k>(
    raw: &[u8],
    me: &EndpointId,
    key_for_kid: impl Fn(&[u8; 8]) -> Option<&'k KemKey>,
) -> Result<Opened, WakeError> {
    if raw.len() > MAX_ENVELOPE {
        return Err(WakeError::TooLarge);
    }
    let v = cbor::decode(raw, &Limits::new(MAX_ENVELOPE))?;
    let Value::Array(a) = &v else {
        return Err(WakeError::Shape);
    };
    let [
        Value::Uint(ver),
        Value::Bytes(kid),
        Value::Bytes(ct_kem),
        Value::Bytes(ct),
    ] = a.as_slice()
    else {
        return Err(WakeError::Shape);
    };
    if *ver != 1 {
        return Err(WakeError::Version);
    }
    let kid: [u8; 8] = (*kid).try_into().map_err(|_| WakeError::Shape)?;
    if ct_kem.len() != KEM_CT_LEN {
        return Err(WakeError::Shape);
    }
    let kk = key_for_kid(&kid).ok_or(WakeError::UnknownKid)?;
    let ss = kk
        .decapsulate(ct_kem)
        .map_err(|_| WakeError::Decapsulation)?;
    let k = wake_key(&ss, me, &kid)?;
    let mut aad = vec![1u8];
    aad.extend_from_slice(&kid);
    aad.extend_from_slice(ct_kem);
    let pt = Zeroizing::new(
        ChaCha20Poly1305::new(&(*k).into())
            .decrypt(&[0u8; 12].into(), Payload { msg: ct, aad: &aad })
            .map_err(|_| WakeError::Aead)?,
    );
    let sv = cbor::decode(&pt, &Limits::new(MAX_ENVELOPE))?;
    let Value::Array(s) = &sv else {
        return Err(WakeError::Shape);
    };
    let [
        Value::Bytes(inner_raw),
        Value::Bytes(sender),
        Value::Bytes(sig),
    ] = s.as_slice()
    else {
        return Err(WakeError::Shape);
    };
    let sender = EndpointId((*sender).try_into().map_err(|_| WakeError::Shape)?);
    let sig: [u8; 64] = (*sig).try_into().map_err(|_| WakeError::Shape)?;
    let inner = Inner::parse(inner_raw)?;
    Ok(Opened {
        sender,
        inner_raw: inner_raw.to_vec(),
        sig,
        inner,
    })
}

/// Replay cache for envelope nonces (§7.3 step 7), bounded in size.
#[derive(Debug, Default)]
pub struct ReplayCache {
    seen: HashMap<[u8; 16], u64>,
}

impl ReplayCache {
    const MAX: usize = 4096;

    /// Returns false if `nonce` was seen within the window; records it otherwise.
    pub fn check_and_insert(&mut self, nonce: [u8; 16], now_ms: u64) -> bool {
        self.seen
            .retain(|_, t| now_ms.saturating_sub(*t) < REPLAY_WINDOW_MS);
        if self.seen.contains_key(&nonce) {
            return false;
        }
        if self.seen.len() >= Self::MAX {
            // Under flood, refuse rather than forget (forgetting would allow replays).
            return false;
        }
        self.seen.insert(nonce, now_ms);
        true
    }
}

/// Steps 3–7. On `NeedSync`, sync the log and call again.
pub fn authorize(
    opened: &Opened,
    me: &EndpointId,
    log: &Log,
    now_ms: u64,
    replay: &mut ReplayCache,
) -> Result<Inner, WakeError> {
    if !log.is_member(&opened.sender) {
        let local = log.head().map(|h| h.seq);
        if local.is_none_or(|l| opened.inner.head.seq > l) {
            return Err(WakeError::NeedSync);
        }
        return Err(WakeError::NotMember);
    }
    let mut msg = WAKE_SIG_LABEL.to_vec();
    msg.extend_from_slice(&me.0);
    msg.extend_from_slice(&opened.inner_raw);
    if !verify_strict(&opened.sender, &msg, &opened.sig) {
        return Err(WakeError::BadSignature);
    }
    if opened.inner.group_id != log.group_id() {
        return Err(WakeError::GroupMismatch);
    }
    let max_age = match opened.inner.kind {
        Kind::Connect { .. } => CONNECT_MAX_AGE_MS,
        Kind::GroupChanged => GROUP_CHANGED_MAX_AGE_MS,
    };
    if now_ms.abs_diff(opened.inner.ts) > max_age {
        return Err(WakeError::Stale);
    }
    if !replay.check_and_insert(opened.inner.nonce, now_ms) {
        return Err(WakeError::Replay);
    }
    Ok(opened.inner.clone())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
pub(crate) mod tests {
    use super::*;
    use crate::log::{
        Op, sign_record,
        tests::{G, T0, body, dev, key},
    };

    pub fn connect_inner(log: &Log, ts: u64, nonce: u8) -> Inner {
        Inner {
            kind: Kind::Connect {
                session: [0x5e; 16],
                dial: DialInfo {
                    relay: Some("https://euc1-1.relay.n0.iroh.link./".into()),
                    addrs: vec![
                        "192.168.1.20:41234".parse().unwrap(),
                        "[fe80::1]:41234".parse().unwrap(),
                    ],
                },
                preview: Some(Preview {
                    count: 1,
                    total_size: 123_456,
                    kinds: vec![2],
                }),
            },
            ts,
            nonce: [nonce; 16],
            group_id: G,
            head: log.head().unwrap(),
        }
    }

    /// Group with PC (key 1, kem seed 1) and phone (key 2, kem seed 2).
    pub fn two_member_log() -> Log {
        let a = key(1);
        let b = key(2);
        let mut log = Log::new(G);
        log.append(
            &sign_record(&a, &body(&log, &a, Op::Genesis(dev("pc", 1, 1)), 0)),
            T0,
        )
        .unwrap();
        log.append(
            &sign_record(&a, &body(&log, &b, Op::Add(dev("phone", 2, 2)), 1)),
            T0,
        )
        .unwrap();
        log
    }

    fn setup() -> (Log, IdentityKey, IdentityKey, KemKey) {
        (
            two_member_log(),
            key(1),
            key(2),
            KemKey::from_seed(&[2; 32]),
        )
    }

    #[test]
    fn seal_open_authorize_roundtrip() {
        let (log, pc, phone, phone_kk) = setup();
        let inner = connect_inner(&log, T0, 1);
        let env = seal(&pc, &phone.endpoint_id(), &phone_kk.public_key(), &inner).unwrap();
        assert!(crate::b64u::encode(&env).len() <= MAX_ENVELOPE_B64U);
        let kid_pk = kid(&phone_kk.public_key());
        let opened = open(&env, &phone.endpoint_id(), |k| {
            (*k == kid_pk).then_some(&phone_kk)
        })
        .unwrap();
        assert_eq!(opened.sender, pc.endpoint_id());
        let mut rc = ReplayCache::default();
        assert_eq!(
            authorize(&opened, &phone.endpoint_id(), &log, T0 + 1000, &mut rc).unwrap(),
            inner
        );
        // Replay of the same envelope is rejected.
        assert_eq!(
            authorize(&opened, &phone.endpoint_id(), &log, T0 + 2000, &mut rc),
            Err(WakeError::Replay)
        );
    }

    #[test]
    fn group_changed_roundtrip_and_ages() {
        let (log, pc, phone, phone_kk) = setup();
        let mut inner = connect_inner(&log, T0, 2);
        inner.kind = Kind::GroupChanged;
        let env = seal(&pc, &phone.endpoint_id(), &phone_kk.public_key(), &inner).unwrap();
        let opened = open(&env, &phone.endpoint_id(), |_| Some(&phone_kk)).unwrap();
        let mut rc = ReplayCache::default();
        assert!(
            authorize(
                &opened,
                &phone.endpoint_id(),
                &log,
                T0 + 23 * 3600 * 1000,
                &mut rc
            )
            .is_ok()
        );
        let mut rc = ReplayCache::default();
        assert_eq!(
            authorize(
                &opened,
                &phone.endpoint_id(),
                &log,
                T0 + 25 * 3600 * 1000,
                &mut rc
            ),
            Err(WakeError::Stale)
        );
    }

    #[test]
    fn tamper_cases_rejected() {
        let (log, pc, phone, phone_kk) = setup();
        let inner = connect_inner(&log, T0, 3);
        let env = seal(&pc, &phone.endpoint_id(), &phone_kk.public_key(), &inner).unwrap();
        let me = phone.endpoint_id();
        // Every single-bit flip anywhere in the envelope is rejected at open.
        for i in 0..env.len() {
            let mut bad = env.clone();
            bad[i] ^= 0x01;
            assert!(
                open(&bad, &me, |_| Some(&phone_kk)).is_err(),
                "bit flip at {i} accepted"
            );
        }
        // Wrong recipient id (key binding in the KDF).
        assert_eq!(
            open(&env, &pc.endpoint_id(), |_| Some(&phone_kk)).unwrap_err(),
            WakeError::Aead
        );
        // Wrong KEM key.
        let other = KemKey::from_seed(&[9; 32]);
        assert!(open(&env, &me, |_| Some(&other)).is_err());
        // Unknown kid.
        assert_eq!(
            open(&env, &me, |_| None).unwrap_err(),
            WakeError::UnknownKid
        );
        // Stale connect.
        let opened = open(&env, &me, |_| Some(&phone_kk)).unwrap();
        let mut rc = ReplayCache::default();
        assert_eq!(
            authorize(&opened, &me, &log, T0 + 121_000, &mut rc),
            Err(WakeError::Stale)
        );
        assert_eq!(
            authorize(&opened, &me, &log, T0 - 121_000, &mut rc),
            Err(WakeError::Stale)
        );
    }

    #[test]
    fn signature_binds_recipient_and_membership() {
        let (log, pc, phone, phone_kk) = setup();
        let me = phone.endpoint_id();
        // A non-member sender whose head is not ahead: NotMember.
        let mallory = key(66);
        let inner = connect_inner(&log, T0, 4);
        let env = seal(&mallory, &me, &phone_kk.public_key(), &inner).unwrap();
        let opened = open(&env, &me, |_| Some(&phone_kk)).unwrap();
        assert_eq!(
            authorize(&opened, &me, &log, T0, &mut ReplayCache::default()),
            Err(WakeError::NotMember)
        );
        // Non-member with a head ahead of ours: sync first.
        let mut ahead = inner.clone();
        ahead.head.seq = 7;
        let env = seal(&mallory, &me, &phone_kk.public_key(), &ahead).unwrap();
        let opened = open(&env, &me, |_| Some(&phone_kk)).unwrap();
        assert_eq!(
            authorize(&opened, &me, &log, T0, &mut ReplayCache::default()),
            Err(WakeError::NeedSync)
        );
        // Signature made for another recipient does not verify for me.
        let mut forged = open(
            &seal(&pc, &me, &phone_kk.public_key(), &inner).unwrap(),
            &me,
            |_| Some(&phone_kk),
        )
        .unwrap();
        let mut msg = WAKE_SIG_LABEL.to_vec();
        msg.extend_from_slice(&pc.endpoint_id().0);
        msg.extend_from_slice(&forged.inner_raw);
        forged.sig = pc.sign(&msg);
        assert_eq!(
            authorize(&forged, &me, &log, T0, &mut ReplayCache::default()),
            Err(WakeError::BadSignature)
        );
    }

    #[test]
    fn replay_cache_window_and_bound() {
        let mut rc = ReplayCache::default();
        assert!(rc.check_and_insert([1; 16], 0));
        assert!(!rc.check_and_insert([1; 16], REPLAY_WINDOW_MS - 1));
        assert!(rc.check_and_insert([1; 16], REPLAY_WINDOW_MS + 1));
        for i in 0..ReplayCache::MAX as u32 {
            let mut n = [0u8; 16];
            n[..4].copy_from_slice(&i.to_be_bytes());
            n[15] = 0xee;
            let _ = rc.check_and_insert(n, REPLAY_WINDOW_MS + 2);
        }
        assert!(!rc.check_and_insert([2; 16], REPLAY_WINDOW_MS + 3));
    }
}
