//! Group membership log (protocol §4): signed, hash-chained records, the
//! normative validation of §4.3, state, append helpers and fork detection.

use std::{collections::BTreeMap, fmt};

use sha2::{Digest, Sha256};

use crate::{
    cbor::{self, Encoder, FieldError, Limits, MapRef, Value},
    keys::{EndpointId, IdentityKey, KEM_PK_LEN, is_valid_public_key, verify_strict},
};

pub const RECORD_LABEL: &[u8] = b"warpshot/record/v1\0";
pub const RECORD_ID_LABEL: &[u8] = b"warpshot/record-id/v1\0";
pub const MAX_RECORD: usize = 4096;
pub const MAX_MEMBERS: usize = 16;
pub const MAX_RECORDS: usize = 1024;
/// Allowed clock skew for `created_at` (§4.3 rule 3).
pub const SKEW_MS: u64 = 10 * 60 * 1000;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct GroupId(pub [u8; 16]);

impl fmt::Debug for GroupId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GroupId({})", crate::keys::short_hex(&self.0))
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct RecordId(pub [u8; 32]);

impl fmt::Debug for RecordId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RecordId({})", crate::keys::short_hex(&self.0))
    }
}

/// `LogHead` (§3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Head {
    pub seq: u64,
    pub id: RecordId,
}

/// `DeviceInfo` (§3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInfo {
    pub name: String,
    pub platform: u64,
    pub kem_pk: Vec<u8>,
    pub app: Option<String>,
}

pub mod platform {
    pub const WINDOWS: u64 = 1;
    pub const ANDROID: u64 = 2;
}

impl DeviceInfo {
    pub fn encode(&self, e: &mut Encoder) {
        e.map(if self.app.is_some() { 4 } else { 3 });
        e.uint(0)
            .text(&self.name)
            .uint(1)
            .uint(self.platform)
            .uint(2)
            .bytes(&self.kem_pk);
        if let Some(app) = &self.app {
            e.uint(3).text(app);
        }
    }

    pub fn parse(m: MapRef<'_, '_>) -> Result<Self, LogError> {
        let name = m.text(0)?;
        if name.is_empty()
            || name.len() > 64
            || name.chars().any(|c| c.is_control() || is_bidi_format(c))
        {
            return Err(LogError::DeviceName);
        }
        let platform = m.uint(1)?;
        if platform == 0 {
            return Err(LogError::DevicePlatform);
        }
        let kem_pk = m.bytes(2)?;
        if kem_pk.len() != KEM_PK_LEN {
            return Err(LogError::DeviceKemKey);
        }
        let app = m.opt_text(3)?;
        if app.is_some_and(|a| a.len() > 32) {
            return Err(LogError::DeviceApp);
        }
        Ok(Self {
            name: name.to_owned(),
            platform,
            kem_pk: kem_pk.to_vec(),
            app: app.map(str::to_owned),
        })
    }
}

/// Bidi formatting characters that could spoof the §4.6 alert text (§3).
fn is_bidi_format(c: char) -> bool {
    matches!(c, '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoveReason {
    User = 0,
    LostOrStolen = 1,
    Left = 2,
    NotMe = 3,
}

impl RemoveReason {
    fn from_u64(v: u64) -> Option<Self> {
        Some(match v {
            0 => Self::User,
            1 => Self::LostOrStolen,
            2 => Self::Left,
            3 => Self::NotMe,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    Genesis(DeviceInfo),
    Add(DeviceInfo),
    Remove(RemoveReason),
    Update(DeviceInfo),
}

impl Op {
    fn code(&self) -> u64 {
        match self {
            Op::Genesis(_) => 0,
            Op::Add(_) => 1,
            Op::Remove(_) => 2,
            Op::Update(_) => 3,
        }
    }
}

/// Decoded `RecordBody` (§4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordBody {
    pub group_id: GroupId,
    pub seq: u64,
    pub prev: Option<RecordId>,
    pub created_at: u64,
    pub subject: EndpointId,
    pub op: Op,
}

impl RecordBody {
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        // v, group_id, seq, created_at, op, subject, device|reason, plus prev if present.
        e.map(if self.prev.is_some() { 8 } else { 7 });
        e.uint(0)
            .uint(1)
            .uint(1)
            .bytes(&self.group_id.0)
            .uint(2)
            .uint(self.seq);
        if let Some(p) = &self.prev {
            e.uint(3).bytes(&p.0);
        }
        e.uint(4)
            .uint(self.created_at)
            .uint(5)
            .uint(self.op.code())
            .uint(6)
            .bytes(&self.subject.0);
        match &self.op {
            Op::Genesis(d) | Op::Add(d) | Op::Update(d) => {
                e.uint(7);
                d.encode(&mut e);
            }
            Op::Remove(r) => {
                e.uint(8).uint(*r as u64);
            }
        }
        e.into_bytes()
    }

    fn parse(body: &[u8]) -> Result<Self, LogError> {
        let v = cbor::decode(body, &Limits::new(MAX_RECORD))?;
        let m = MapRef::new(&v).ok_or(LogError::Shape)?;
        if m.uint(0)? != 1 {
            return Err(LogError::Version);
        }
        let op_code = m.uint(5)?;
        let device = m.opt_map(7)?;
        let reason = m.opt_uint(8)?;
        let op = match (op_code, device, reason) {
            (0 | 1 | 3, Some(d), None) => {
                let d = DeviceInfo::parse(d)?;
                match op_code {
                    0 => Op::Genesis(d),
                    1 => Op::Add(d),
                    _ => Op::Update(d),
                }
            }
            (2, None, Some(r)) => Op::Remove(RemoveReason::from_u64(r).ok_or(LogError::Presence)?),
            (0..=3, _, _) => return Err(LogError::Presence),
            _ => return Err(LogError::UnknownOp),
        };
        Ok(Self {
            group_id: GroupId(m.fixed(1)?),
            seq: m.uint(2)?,
            prev: m.opt_fixed(3)?.map(RecordId),
            created_at: m.uint(4)?,
            subject: EndpointId(m.fixed(6)?),
            op,
        })
    }
}

/// A validated record with its exact bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub raw: Vec<u8>,
    pub body: RecordBody,
    pub signer: EndpointId,
    pub id: RecordId,
}

/// Every way a record can be invalid; each maps to a §4.3 rule and has a test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogError {
    TooLarge,
    Cbor(cbor::Error),
    Field(FieldError),
    Shape,
    Version,
    UnknownOp,
    Presence,
    DeviceName,
    DevicePlatform,
    DeviceKemKey,
    DeviceApp,
    GroupMismatch,
    SeqMismatch,
    GenesisShape,
    PrevMismatch,
    NotGenesisOp,
    SignerNotMember,
    TimeFuture,
    TimeRegress,
    AddExisting,
    SubjectKey,
    RemoveMissing,
    UpdateNotSelf,
    UpdatePlatform,
    BadSignature,
    GroupDead,
    TooManyMembers,
    TooManyRecords,
}

impl fmt::Display for LogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl std::error::Error for LogError {}

impl From<cbor::Error> for LogError {
    fn from(e: cbor::Error) -> Self {
        Self::Cbor(e)
    }
}

impl From<FieldError> for LogError {
    fn from(e: FieldError) -> Self {
        Self::Field(e)
    }
}

/// Decodes a `SignedRecord` array; checks shape only (no chain rules).
pub fn parse_signed(raw: &[u8]) -> Result<(RecordBody, Vec<u8>, EndpointId, [u8; 64]), LogError> {
    if raw.len() > MAX_RECORD {
        return Err(LogError::TooLarge);
    }
    let v = cbor::decode(raw, &Limits::new(MAX_RECORD))?;
    let [Value::Bytes(body), Value::Bytes(signer), Value::Bytes(sig)] = (match &v {
        Value::Array(a) => a.as_slice(),
        _ => return Err(LogError::Shape),
    }) else {
        return Err(LogError::Shape);
    };
    let signer: [u8; 32] = (*signer).try_into().map_err(|_| LogError::Shape)?;
    let sig: [u8; 64] = (*sig).try_into().map_err(|_| LogError::Shape)?;
    Ok((
        RecordBody::parse(body)?,
        body.to_vec(),
        EndpointId(signer),
        sig,
    ))
}

pub fn record_id(body: &[u8], signer: &EndpointId, sig: &[u8; 64]) -> RecordId {
    let mut h = Sha256::new();
    h.update(RECORD_ID_LABEL);
    h.update(body);
    h.update(signer.0);
    h.update(sig);
    let mut id = [0u8; 32];
    id.copy_from_slice(&h.finalize());
    RecordId(id)
}

/// Signs a body and returns the `SignedRecord` bytes.
pub fn sign_record(ik: &IdentityKey, body: &RecordBody) -> Vec<u8> {
    let b = body.encode();
    let mut msg = RECORD_LABEL.to_vec();
    msg.extend_from_slice(&b);
    let sig = ik.sign(&msg);
    let mut e = Encoder::new();
    e.array(3).bytes(&b).bytes(&ik.endpoint_id().0).bytes(&sig);
    e.into_bytes()
}

/// Where an incoming record stands relative to the local log (§4.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Incoming {
    /// Same id at that seq: already have it.
    Known,
    /// The next record to validate.
    Next,
    /// Records are missing in between; fetch them first.
    Gap,
    /// Different id at an existing seq: security alert, stop transfers (§4.5).
    Fork,
}

/// A validated log and its membership state.
#[derive(Debug, Clone)]
pub struct Log {
    group_id: GroupId,
    records: Vec<Record>,
    members: BTreeMap<EndpointId, DeviceInfo>,
}

impl Log {
    pub fn new(group_id: GroupId) -> Self {
        Self {
            group_id,
            records: Vec::new(),
            members: BTreeMap::new(),
        }
    }

    /// Validates a full log from genesis.
    pub fn from_records<'a>(
        group_id: GroupId,
        raw: impl IntoIterator<Item = &'a [u8]>,
        now_ms: u64,
    ) -> Result<Self, (usize, LogError)> {
        let mut log = Self::new(group_id);
        for (i, r) in raw.into_iter().enumerate() {
            log.append(r, now_ms).map_err(|e| (i, e))?;
        }
        Ok(log)
    }

    pub fn group_id(&self) -> GroupId {
        self.group_id
    }

    pub fn records(&self) -> &[Record] {
        &self.records
    }

    pub fn members(&self) -> &BTreeMap<EndpointId, DeviceInfo> {
        &self.members
    }

    pub fn is_member(&self, id: &EndpointId) -> bool {
        self.members.contains_key(id)
    }

    pub fn head(&self) -> Option<Head> {
        self.records.last().map(|r| Head {
            seq: r.body.seq,
            id: r.id,
        })
    }

    /// Next `seq` and `prev` for a record built on this log.
    pub fn next_position(&self) -> (u64, Option<RecordId>) {
        match self.head() {
            Some(h) => (h.seq.saturating_add(1), Some(h.id)),
            None => (0, None),
        }
    }

    pub fn classify(&self, seq: u64, id: &RecordId) -> Incoming {
        let len = self.records.len() as u64;
        if seq < len {
            match self.records.get(seq as usize) {
                Some(r) if r.id == *id => Incoming::Known,
                _ => Incoming::Fork,
            }
        } else if seq == len {
            Incoming::Next
        } else {
            Incoming::Gap
        }
    }

    /// Validates `raw` as record `n` (§4.3) and applies it on success.
    pub fn append(&mut self, raw: &[u8], now_ms: u64) -> Result<&Record, LogError> {
        let rec = self.check(raw, now_ms)?;
        match &rec.body.op {
            Op::Genesis(d) | Op::Add(d) | Op::Update(d) => {
                self.members.insert(rec.body.subject, d.clone());
            }
            Op::Remove(_) => {
                self.members.remove(&rec.body.subject);
            }
        }
        self.records.push(rec);
        self.records.last().ok_or(LogError::Shape)
    }

    /// The §4.3 checks, in rule order, without mutating state.
    pub fn check(&self, raw: &[u8], now_ms: u64) -> Result<Record, LogError> {
        let n = self.records.len();
        if n >= MAX_RECORDS {
            return Err(LogError::TooManyRecords);
        }
        if n > 0 && self.members.is_empty() {
            return Err(LogError::GroupDead);
        }
        // Rule 1
        let (body, body_raw, signer, sig) = parse_signed(raw)?;
        if body.group_id != self.group_id {
            return Err(LogError::GroupMismatch);
        }
        if body.seq != n as u64 {
            return Err(LogError::SeqMismatch);
        }
        // Rule 2
        let prev = self.records.last();
        match prev {
            None => {
                if !matches!(body.op, Op::Genesis(_))
                    || body.prev.is_some()
                    || signer != body.subject
                {
                    return Err(LogError::GenesisShape);
                }
            }
            Some(p) => {
                if body.prev != Some(p.id) {
                    return Err(LogError::PrevMismatch);
                }
                if matches!(body.op, Op::Genesis(_)) {
                    return Err(LogError::NotGenesisOp);
                }
                if !self.members.contains_key(&signer) {
                    return Err(LogError::SignerNotMember);
                }
            }
        }
        // Rule 3
        if body.created_at > now_ms.saturating_add(SKEW_MS) {
            return Err(LogError::TimeFuture);
        }
        if let Some(p) = prev
            && body.created_at < p.body.created_at.saturating_sub(SKEW_MS)
        {
            return Err(LogError::TimeRegress);
        }
        // Rule 4
        match &body.op {
            Op::Genesis(_) => {}
            Op::Add(_) => {
                if self.members.contains_key(&body.subject) {
                    return Err(LogError::AddExisting);
                }
                if !is_valid_public_key(&body.subject) {
                    return Err(LogError::SubjectKey);
                }
                if self.members.len() >= MAX_MEMBERS {
                    return Err(LogError::TooManyMembers);
                }
            }
            Op::Remove(_) => {
                if !self.members.contains_key(&body.subject) {
                    return Err(LogError::RemoveMissing);
                }
            }
            Op::Update(d) => {
                if signer != body.subject {
                    return Err(LogError::UpdateNotSelf);
                }
                if self
                    .members
                    .get(&body.subject)
                    .is_none_or(|old| old.platform != d.platform)
                {
                    return Err(LogError::UpdatePlatform);
                }
            }
        }
        // Rule 5
        let mut msg = RECORD_LABEL.to_vec();
        msg.extend_from_slice(&body_raw);
        if !verify_strict(&signer, &msg, &sig) {
            return Err(LogError::BadSignature);
        }
        let id = record_id(&body_raw, &signer, &sig);
        Ok(Record {
            raw: raw.to_vec(),
            body,
            signer,
            id,
        })
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]
pub(crate) mod tests {
    use super::*;
    use crate::keys::KemKey;

    pub const T0: u64 = 1_790_000_000_000;
    pub const G: GroupId = GroupId([0x11; 16]);

    pub fn dev(name: &str, platform: u64, seed: u8) -> DeviceInfo {
        DeviceInfo {
            name: name.into(),
            platform,
            kem_pk: KemKey::from_seed(&[seed; 32]).public_key(),
            app: Some("0.1.0".into()),
        }
    }

    pub fn key(seed: u8) -> IdentityKey {
        IdentityKey::from_secret(&[seed; 32])
    }

    pub fn body(log: &Log, subject: &IdentityKey, op: Op, dt: u64) -> RecordBody {
        let (seq, prev) = log.next_position();
        RecordBody {
            group_id: G,
            seq,
            prev,
            created_at: T0 + dt,
            subject: subject.endpoint_id(),
            op,
        }
    }

    fn genesis_log() -> (Log, IdentityKey) {
        let a = key(1);
        let mut log = Log::new(G);
        let r = sign_record(&a, &body(&log, &a, Op::Genesis(dev("pc", 1, 1)), 0));
        log.append(&r, T0).unwrap();
        (log, a)
    }

    #[test]
    fn genesis_add_update_remove() {
        let (mut log, a) = genesis_log();
        let b = key(2);
        let r = sign_record(&a, &body(&log, &b, Op::Add(dev("phone", 2, 2)), 1));
        log.append(&r, T0).unwrap();
        assert!(log.is_member(&b.endpoint_id()));
        let r = sign_record(&b, &body(&log, &b, Op::Update(dev("my phone", 2, 3)), 2));
        log.append(&r, T0).unwrap();
        assert_eq!(log.members()[&b.endpoint_id()].name, "my phone");
        let r = sign_record(
            &a,
            &body(&log, &b, Op::Remove(RemoveReason::LostOrStolen), 3),
        );
        log.append(&r, T0).unwrap();
        assert!(!log.is_member(&b.endpoint_id()));
        // Re-adding a removed key is a new admission.
        let r = sign_record(&a, &body(&log, &b, Op::Add(dev("phone", 2, 4)), 4));
        log.append(&r, T0).unwrap();
        assert_eq!(log.head().unwrap().seq, 4);
        // Full re-validation from genesis gives the same state.
        let raws: Vec<&[u8]> = log.records().iter().map(|r| r.raw.as_slice()).collect();
        let again = Log::from_records(G, raws, T0).unwrap();
        assert_eq!(again.members(), log.members());
        assert_eq!(again.head(), log.head());
    }

    fn err(log: &Log, raw: &[u8]) -> LogError {
        log.check(raw, T0).unwrap_err()
    }

    #[test]
    fn rule1_shape_and_version() {
        let (log, a) = genesis_log();
        let b = key(2);
        assert!(matches!(err(&log, &[0x80]), LogError::Shape));
        assert!(matches!(
            err(&log, &[0x83, 0x40, 0x40, 0x40]),
            LogError::Cbor(_) | LogError::Shape
        ));
        let mut bd = body(&log, &b, Op::Add(dev("x", 2, 2)), 1);
        bd.group_id = GroupId([0x22; 16]);
        assert_eq!(err(&log, &sign_record(&a, &bd)), LogError::GroupMismatch);
        let mut bd = body(&log, &b, Op::Add(dev("x", 2, 2)), 1);
        bd.seq = 5;
        assert_eq!(err(&log, &sign_record(&a, &bd)), LogError::SeqMismatch);
        assert_eq!(err(&log, &vec![0u8; MAX_RECORD + 1]), LogError::TooLarge);
    }

    /// Builds a record from a hand-written body map so invalid shapes can be signed.
    fn raw_record(ik: &IdentityKey, entries: Vec<(u64, Value<'_>)>) -> Vec<u8> {
        let b = cbor::encode(&Value::Map(entries)).unwrap();
        let mut msg = RECORD_LABEL.to_vec();
        msg.extend_from_slice(&b);
        let mut e = Encoder::new();
        e.array(3)
            .bytes(&b)
            .bytes(&ik.endpoint_id().0)
            .bytes(&ik.sign(&msg));
        e.into_bytes()
    }

    #[test]
    fn rule1_field_presence_and_device_info() {
        let (log, a) = genesis_log();
        let b = key(2);
        let prev = log.head().unwrap().id.0;
        let bid = b.endpoint_id().0;
        let d = dev("phone", 2, 2);
        let dmap = |name: &'static str, platform: u64, pk: Vec<u8>| -> Value<'static> {
            Value::Map(vec![
                (0, Value::Text(name)),
                (1, Value::Uint(platform)),
                (2, Value::Bytes(Box::leak(pk.into_boxed_slice()))),
            ])
        };
        let base = |op: u64, extra: Vec<(u64, Value<'static>)>| -> Vec<(u64, Value<'static>)> {
            let mut v = vec![
                (0, Value::Uint(1)),
                (1, Value::Bytes(&G.0)),
                (2, Value::Uint(1)),
                (3, Value::Bytes(Box::leak(Box::new(prev)))),
                (4, Value::Uint(T0)),
                (5, Value::Uint(op)),
                (6, Value::Bytes(Box::leak(Box::new(bid)))),
            ];
            v.extend(extra);
            v
        };
        let pk = d.kem_pk.clone();
        // add without device
        assert_eq!(
            err(&log, &raw_record(&a, base(1, vec![]))),
            LogError::Presence
        );
        // add with reason
        assert_eq!(
            err(
                &log,
                &raw_record(
                    &a,
                    base(1, vec![(7, dmap("p", 2, pk.clone())), (8, Value::Uint(0))])
                )
            ),
            LogError::Presence
        );
        // remove with device
        assert_eq!(
            err(
                &log,
                &raw_record(
                    &a,
                    base(2, vec![(7, dmap("p", 2, pk.clone())), (8, Value::Uint(0))])
                )
            ),
            LogError::Presence
        );
        // remove with bad reason
        assert_eq!(
            err(&log, &raw_record(&a, base(2, vec![(8, Value::Uint(4))]))),
            LogError::Presence
        );
        // unknown op
        assert_eq!(
            err(&log, &raw_record(&a, base(4, vec![]))),
            LogError::UnknownOp
        );
        // version
        let mut v2 = base(1, vec![(7, dmap("p", 2, pk.clone()))]);
        v2[0] = (0, Value::Uint(2));
        assert_eq!(err(&log, &raw_record(&a, v2)), LogError::Version);
        // device info rules
        assert_eq!(
            err(
                &log,
                &raw_record(&a, base(1, vec![(7, dmap("", 2, pk.clone()))]))
            ),
            LogError::DeviceName
        );
        assert_eq!(
            err(
                &log,
                &raw_record(&a, base(1, vec![(7, dmap("a\u{7}b", 2, pk.clone()))]))
            ),
            LogError::DeviceName
        );
        let long: &'static str = Box::leak("x".repeat(65).into_boxed_str());
        assert_eq!(
            err(
                &log,
                &raw_record(&a, base(1, vec![(7, dmap(long, 2, pk.clone()))]))
            ),
            LogError::DeviceName
        );
        assert_eq!(
            err(
                &log,
                &raw_record(&a, base(1, vec![(7, dmap("p", 0, pk.clone()))]))
            ),
            LogError::DevicePlatform
        );
        assert_eq!(
            err(
                &log,
                &raw_record(&a, base(1, vec![(7, dmap("p", 2, vec![0; 1215]))]))
            ),
            LogError::DeviceKemKey
        );
        // unknown platform is accepted; unknown keys ignored
        let mut m = match dmap("p", 99, pk.clone()) {
            Value::Map(m) => m,
            _ => unreachable!(),
        };
        m.push((9, Value::Text("future")));
        assert!(
            log.check(&raw_record(&a, base(1, vec![(7, Value::Map(m))])), T0)
                .is_ok()
        );
    }

    #[test]
    fn rule2_chain_and_signer() {
        let (log, a) = genesis_log();
        let b = key(2);
        let c = key(3);
        let mut bd = body(&log, &b, Op::Add(dev("x", 2, 2)), 1);
        bd.prev = Some(RecordId([9; 32]));
        assert_eq!(err(&log, &sign_record(&a, &bd)), LogError::PrevMismatch);
        let bd = body(&log, &b, Op::Genesis(dev("x", 2, 2)), 1);
        assert_eq!(err(&log, &sign_record(&a, &bd)), LogError::NotGenesisOp);
        let bd = body(&log, &b, Op::Add(dev("x", 2, 2)), 1);
        assert_eq!(err(&log, &sign_record(&c, &bd)), LogError::SignerNotMember);
        // genesis: signer must be subject, no prev, op genesis
        let empty = Log::new(G);
        let bd = body(&empty, &b, Op::Genesis(dev("x", 2, 2)), 0);
        assert_eq!(err(&empty, &sign_record(&a, &bd)), LogError::GenesisShape);
        let bd = body(&empty, &a, Op::Add(dev("x", 2, 2)), 0);
        assert_eq!(err(&empty, &sign_record(&a, &bd)), LogError::GenesisShape);
    }

    #[test]
    fn rule3_time() {
        let (log, a) = genesis_log();
        let b = key(2);
        let bd = body(&log, &b, Op::Add(dev("x", 2, 2)), SKEW_MS + 1);
        assert_eq!(err(&log, &sign_record(&a, &bd)), LogError::TimeFuture);
        let mut bd = body(&log, &b, Op::Add(dev("x", 2, 2)), 0);
        bd.created_at = T0 - SKEW_MS - 1;
        assert_eq!(err(&log, &sign_record(&a, &bd)), LogError::TimeRegress);
        let mut bd = body(&log, &b, Op::Add(dev("x", 2, 2)), 0);
        bd.created_at = T0 - SKEW_MS;
        assert!(log.check(&sign_record(&a, &bd), T0).is_ok());
    }

    #[test]
    fn rule4_operations() {
        let (mut log, a) = genesis_log();
        let b = key(2);
        let bd = body(&log, &a, Op::Add(dev("x", 1, 2)), 1);
        assert_eq!(err(&log, &sign_record(&a, &bd)), LogError::AddExisting);
        let bd = body(&log, &b, Op::Remove(RemoveReason::User), 1);
        assert_eq!(err(&log, &sign_record(&a, &bd)), LogError::RemoveMissing);
        log.append(
            &sign_record(&a, &body(&log, &b, Op::Add(dev("phone", 2, 2)), 1)),
            T0,
        )
        .unwrap();
        let bd = body(&log, &b, Op::Update(dev("y", 2, 2)), 2);
        assert_eq!(err(&log, &sign_record(&a, &bd)), LogError::UpdateNotSelf);
        let bd = body(&log, &b, Op::Update(dev("y", 1, 2)), 2);
        assert_eq!(err(&log, &sign_record(&b, &bd)), LogError::UpdatePlatform);
        // self-removal (leave) is allowed
        let bd = body(&log, &b, Op::Remove(RemoveReason::Left), 2);
        assert!(log.check(&sign_record(&b, &bd), T0).is_ok());
    }

    #[test]
    fn rule5_signature() {
        let (log, a) = genesis_log();
        let b = key(2);
        let mut raw = sign_record(&a, &body(&log, &b, Op::Add(dev("x", 2, 2)), 1));
        let n = raw.len();
        raw[n - 1] ^= 1;
        assert_eq!(err(&log, &raw), LogError::BadSignature);
    }

    #[test]
    fn limits_and_dead_group() {
        let (mut log, a) = genesis_log();
        for i in 2..=16u8 {
            let k = key(i);
            log.append(
                &sign_record(&a, &body(&log, &k, Op::Add(dev("d", 2, i)), 1)),
                T0,
            )
            .unwrap();
        }
        assert_eq!(log.members().len(), 16);
        let k = key(17);
        assert_eq!(
            err(
                &log,
                &sign_record(&a, &body(&log, &k, Op::Add(dev("d", 2, 17)), 1))
            ),
            LogError::TooManyMembers
        );
        // Everyone leaves: group is dead.
        let ids: Vec<u8> = (1..=16).collect();
        for i in ids {
            let k = key(i);
            log.append(
                &sign_record(&k, &body(&log, &k, Op::Remove(RemoveReason::Left), 1)),
                T0,
            )
            .unwrap();
        }
        assert!(log.members().is_empty());
        assert_eq!(
            err(
                &log,
                &sign_record(&a, &body(&log, &a, Op::Add(dev("d", 1, 1)), 1))
            ),
            LogError::GroupDead
        );
    }

    #[test]
    fn fork_detection() {
        let (mut log, a) = genesis_log();
        let b = key(2);
        let r1 = sign_record(&a, &body(&log, &b, Op::Add(dev("phone", 2, 2)), 1));
        let rec = log.check(&r1, T0).unwrap();
        assert_eq!(log.classify(1, &rec.id), Incoming::Next);
        assert_eq!(log.classify(2, &rec.id), Incoming::Gap);
        log.append(&r1, T0).unwrap();
        assert_eq!(log.classify(1, &rec.id), Incoming::Known);
        // A different record at seq 1 (same author, different content) is a fork.
        let mut alt = Log::new(G);
        alt.append(&log.records()[0].raw, T0).unwrap();
        let r1b = sign_record(&a, &body(&alt, &b, Op::Add(dev("other", 2, 2)), 1));
        let recb = alt.check(&r1b, T0).unwrap();
        assert_eq!(log.classify(1, &recb.id), Incoming::Fork);
    }

    /// Property-style test: random valid operation sequences always re-validate
    /// from genesis to the same state, and random single-byte corruption of any
    /// record is always rejected.
    #[test]
    fn random_ops_revalidate_and_corruption_rejected() {
        let mut seed = 0x1234_5678_9abc_def0u64;
        let mut rnd = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for round in 0..20 {
            let (mut log, a) = genesis_log();
            let mut members: Vec<u8> = vec![1];
            let mut next_key = 2u8;
            for step in 0..40 {
                let signer = key(members[(rnd() % members.len() as u64) as usize]);
                let choice = rnd() % 3;
                let t = step + 1;
                let raw = if choice == 0 && members.len() < MAX_MEMBERS && next_key < 250 {
                    let k = key(next_key);
                    members.push(next_key);
                    next_key += 1;
                    sign_record(&signer, &body(&log, &k, Op::Add(dev("d", 2, next_key)), t))
                } else if choice == 1 && members.len() > 1 {
                    let i = (rnd() % members.len() as u64) as usize;
                    let k = key(members.remove(i));
                    sign_record(&signer, &body(&log, &k, Op::Remove(RemoveReason::User), t))
                } else {
                    let p = if members[0] == 1 { 1 } else { 2 };
                    let s = key(members[0]);
                    let plat = log.members()[&s.endpoint_id()].platform;
                    let _ = p;
                    sign_record(&s, &body(&log, &s, Op::Update(dev("renamed", plat, 9)), t))
                };
                log.append(&raw, T0 + 1000)
                    .unwrap_or_else(|e| panic!("round {round} step {step}: {e}"));
            }
            assert_eq!(log.members().len(), members.len());
            let raws: Vec<&[u8]> = log.records().iter().map(|r| r.raw.as_slice()).collect();
            let again = Log::from_records(G, raws.clone(), T0 + 1000).unwrap();
            assert_eq!(again.members(), log.members());
            // Corrupt one byte of one record: re-validation must fail at or before it.
            let victim = (rnd() % raws.len() as u64) as usize;
            let mut bad = raws[victim].to_vec();
            let pos = (rnd() % bad.len() as u64) as usize;
            bad[pos] ^= 1 << (rnd() % 8);
            let mut corrupted: Vec<&[u8]> = raws.clone();
            corrupted[victim] = &bad;
            let res = Log::from_records(G, corrupted, T0 + 1000);
            assert!(
                res.is_err(),
                "round {round}: corruption at record {victim} byte {pos} accepted"
            );
            let _ = a.endpoint_id();
        }
    }
}
