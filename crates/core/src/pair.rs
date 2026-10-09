//! Pairing, network-independent part (protocol §5): QR payload, proof, SAS,
//! messages, the one-time pairing window and group resolution.

// Arithmetic here is on bounded local values (bit counters < 13, field counts
// ≤ 8); lengths read from the wire go through the strict CBOR decoder.
#![allow(clippy::arithmetic_side_effects)]

use std::fmt;

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    cbor::{self, Encoder, FieldError, Limits, MapRef, Value},
    keys::{self, EndpointId},
    log::{DeviceInfo, GroupId, Head, RecordId},
    wake::DialInfo,
};

pub const ALPN: &[u8] = b"warpshot/pair/1";
pub const EKM_LABEL: &[u8] = b"EXPORTER-warpshot-pair-v1";
pub const PROOF_LABEL: &[u8] = b"warpshot/pair-proof/v1";
pub const SAS_LABEL: &[u8] = b"warpshot/sas/v1";
pub const QR_PREFIX: &str = "WARP1:";
/// QR lifetime and the confirmation timeout (§5.2, §5.3 step 6).
pub const WINDOW_SECS: u64 = 120;
const MAX_MSG: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairError {
    Prefix,
    Base32,
    Cbor(cbor::Error),
    Field(FieldError),
    Shape,
    Version,
    Expired,
    Used,
    Proof,
    Rng,
}

impl fmt::Display for PairError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl std::error::Error for PairError {}

impl From<cbor::Error> for PairError {
    fn from(e: cbor::Error) -> Self {
        Self::Cbor(e)
    }
}

impl From<FieldError> for PairError {
    fn from(e: FieldError) -> Self {
        Self::Field(e)
    }
}

const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// RFC 4648 base32, upper case, no padding.
pub fn base32(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().saturating_mul(8).div_ceil(5));
    let (mut acc, mut bits) = (0u32, 0u32);
    for b in data {
        acc = (acc << 8) | u32::from(*b);
        bits = bits.saturating_add(8);
        while bits >= 5 {
            bits = bits.saturating_sub(5);
            out.push(char::from(
                B32.get(((acc >> bits) & 31) as usize)
                    .copied()
                    .unwrap_or(b'A'),
            ));
        }
        acc &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(char::from(
            B32.get(((acc << (5 - bits)) & 31) as usize)
                .copied()
                .unwrap_or(b'A'),
        ));
    }
    out
}

/// Strict decode: upper case only, no padding, zero trailing bits.
pub fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len().saturating_mul(5) / 8);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.bytes() {
        let v = B32.iter().position(|x| *x == c)? as u32;
        acc = (acc << 5) | v;
        bits = bits.saturating_add(5);
        if bits >= 8 {
            bits = bits.saturating_sub(8);
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    // Leftover must be < 5 bits and all zero (canonical encoding).
    (bits < 5 && acc == 0).then_some(out)
}

/// `QrPayload` (§5.2).
#[derive(Clone, PartialEq, Eq)]
pub struct QrPayload {
    pub eid: EndpointId,
    pub dial: DialInfo,
    pub secret: Zeroizing<[u8; 32]>,
    /// Unix seconds.
    pub exp: u64,
    pub name: String,
    pub group: Option<GroupId>,
    pub server: Option<String>,
}

impl fmt::Debug for QrPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QrPayload")
            .field("eid", &self.eid)
            .field("exp", &self.exp)
            .field("group", &self.group)
            .finish_non_exhaustive()
    }
}

impl QrPayload {
    pub fn encode(&self) -> String {
        let mut e = Encoder::new();
        let n = 6 + usize::from(self.group.is_some()) + usize::from(self.server.is_some());
        e.map(n).uint(0).uint(1).uint(1).bytes(&self.eid.0).uint(2);
        e.map(if self.dial.relay.is_some() { 2 } else { 1 });
        if let Some(r) = &self.dial.relay {
            e.uint(0).text(r);
        }
        e.uint(1).array(self.dial.addrs.len());
        for a in &self.dial.addrs {
            e.text(&a.to_string());
        }
        e.uint(3)
            .bytes(self.secret.as_ref())
            .uint(4)
            .uint(self.exp)
            .uint(5)
            .text(&self.name);
        if let Some(g) = &self.group {
            e.uint(6).bytes(&g.0);
        }
        if let Some(s) = &self.server {
            e.uint(7).text(s);
        }
        format!("{QR_PREFIX}{}", base32(&e.into_bytes()))
    }

    pub fn parse(text: &str) -> Result<Self, PairError> {
        let b32 = text.strip_prefix(QR_PREFIX).ok_or(PairError::Prefix)?;
        let raw = base32_decode(b32).ok_or(PairError::Base32)?;
        let v = cbor::decode(&raw, &Limits::new(4096))?;
        let m = MapRef::new(&v).ok_or(PairError::Shape)?;
        if m.uint(0)? != 1 {
            return Err(PairError::Version);
        }
        let d = m
            .opt_map(2)?
            .ok_or(PairError::Field(FieldError::Missing(2)))?;
        let list = d
            .opt_array(1)?
            .ok_or(PairError::Field(FieldError::Missing(1)))?;
        if list.len() > 8 {
            return Err(PairError::Shape);
        }
        let mut addrs = Vec::with_capacity(list.len());
        for a in list {
            let Value::Text(s) = a else {
                return Err(PairError::Shape);
            };
            addrs.push(s.parse().map_err(|_| PairError::Shape)?);
        }
        let name = m.text(5)?;
        if name.is_empty() || name.len() > 64 {
            return Err(PairError::Shape);
        }
        Ok(Self {
            eid: EndpointId(m.fixed(1)?),
            dial: DialInfo {
                relay: d.opt_text(0)?.map(str::to_owned),
                addrs,
            },
            secret: Zeroizing::new(m.fixed(3)?),
            exp: m.uint(4)?,
            name: name.to_owned(),
            group: m.opt_fixed(6)?.map(GroupId),
            server: m.opt_text(7)?.map(str::to_owned),
        })
    }
}

/// `proof = HMAC-SHA-256(secret, label ‖ ekm ‖ eid_scanner)`.
pub fn proof(secret: &[u8; 32], ekm: &[u8; 32], eid_scanner: &EndpointId) -> [u8; 32] {
    let mut out = [0u8; 32];
    if let Ok(mut mac) = <Hmac<Sha256> as KeyInit>::new_from_slice(secret) {
        mac.update(PROOF_LABEL);
        mac.update(ekm);
        mac.update(&eid_scanner.0);
        out.copy_from_slice(&mac.finalize().into_bytes());
    }
    out
}

/// Constant-time proof check.
pub fn verify_proof(
    secret: &[u8; 32],
    ekm: &[u8; 32],
    eid_scanner: &EndpointId,
    got: &[u8],
) -> bool {
    let Ok(mut mac) = <Hmac<Sha256> as KeyInit>::new_from_slice(secret) else {
        return false;
    };
    mac.update(PROOF_LABEL);
    mac.update(ekm);
    mac.update(&eid_scanner.0);
    mac.verify_slice(got).is_ok()
}

/// Short authentication string `XXX-XXX` (§5.3 step 6).
pub fn sas(ekm: &[u8; 32]) -> String {
    let mut h = Sha256::new();
    h.update(SAS_LABEL);
    h.update(ekm);
    let b = base32(&h.finalize());
    format!("{}-{}", b.get(..3).unwrap_or(""), b.get(3..6).unwrap_or(""))
}

/// Display-side one-time pairing window (§5.3 step 4).
#[derive(Debug)]
pub struct Window {
    payload: QrPayload,
    used: bool,
}

impl Window {
    /// Opens a window with a fresh secret; `exp` = now + 120 s.
    pub fn open(
        eid: EndpointId,
        dial: DialInfo,
        name: String,
        group: Option<GroupId>,
        now_secs: u64,
    ) -> Result<Self, PairError> {
        let mut secret = Zeroizing::new([0u8; 32]);
        keys::random(secret.as_mut()).map_err(|_| PairError::Rng)?;
        let exp = now_secs.saturating_add(WINDOW_SECS);
        Ok(Self {
            payload: QrPayload {
                eid,
                dial,
                secret,
                exp,
                name,
                group,
                server: None,
            },
            used: false,
        })
    }

    /// Adds the server URL (QR key 7) so the scanner learns where the group lives.
    pub fn with_server(mut self, url: String) -> Self {
        self.payload.server = Some(url);
        self
    }

    pub fn expires_at_secs(&self) -> u64 {
        self.payload.exp
    }

    pub fn qr_text(&self) -> String {
        self.payload.encode()
    }

    /// Checks in spec order: expiry, unused (marks used on the first attempt), proof.
    pub fn check(
        &mut self,
        ekm: &[u8; 32],
        eid_scanner: &EndpointId,
        proof_bytes: &[u8],
        now_secs: u64,
    ) -> Result<(), PairError> {
        if now_secs > self.payload.exp {
            return Err(PairError::Expired);
        }
        if self.used {
            return Err(PairError::Used);
        }
        self.used = true;
        if !verify_proof(&self.payload.secret, ekm, eid_scanner, proof_bytes) {
            return Err(PairError::Proof);
        }
        Ok(())
    }
}

fn encode_head(e: &mut Encoder, h: &Head) {
    e.map(2).uint(0).uint(h.seq).uint(1).bytes(&h.id.0);
}

fn parse_head(m: MapRef<'_, '_>) -> Result<Head, PairError> {
    Ok(Head {
        seq: m.uint(0)?,
        id: RecordId(m.fixed(1)?),
    })
}

/// `PairHello` (S → D).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairHello {
    pub device: DeviceInfo,
    pub proof: [u8; 32],
    pub group: Option<GroupId>,
    pub head: Option<Head>,
}

impl PairHello {
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.map(3 + usize::from(self.group.is_some()) + usize::from(self.head.is_some()));
        e.uint(0).uint(1).uint(1);
        self.device.encode(&mut e);
        e.uint(2).bytes(&self.proof);
        if let Some(g) = &self.group {
            e.uint(3).bytes(&g.0);
        }
        if let Some(h) = &self.head {
            e.uint(4);
            encode_head(&mut e, h);
        }
        e.into_bytes()
    }

    pub fn parse(raw: &[u8]) -> Result<Self, PairError> {
        let v = cbor::decode(raw, &Limits::new(MAX_MSG))?;
        let m = MapRef::new(&v).ok_or(PairError::Shape)?;
        if m.uint(0)? != 1 {
            return Err(PairError::Version);
        }
        let d = m
            .opt_map(1)?
            .ok_or(PairError::Field(FieldError::Missing(1)))?;
        Ok(Self {
            device: DeviceInfo::parse(d).map_err(|_| PairError::Shape)?,
            proof: m.fixed(2)?,
            group: m.opt_fixed(3)?.map(GroupId),
            head: m.opt_map(4)?.map(parse_head).transpose()?,
        })
    }
}

/// `PairInfo` (D → S).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairInfo {
    pub device: DeviceInfo,
    pub group: Option<GroupId>,
    pub head: Option<Head>,
}

impl PairInfo {
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.map(1 + usize::from(self.group.is_some()) + usize::from(self.head.is_some()));
        e.uint(0);
        self.device.encode(&mut e);
        if let Some(g) = &self.group {
            e.uint(1).bytes(&g.0);
        }
        if let Some(h) = &self.head {
            e.uint(2);
            encode_head(&mut e, h);
        }
        e.into_bytes()
    }

    pub fn parse(raw: &[u8]) -> Result<Self, PairError> {
        let v = cbor::decode(raw, &Limits::new(MAX_MSG))?;
        let m = MapRef::new(&v).ok_or(PairError::Shape)?;
        let d = m
            .opt_map(0)?
            .ok_or(PairError::Field(FieldError::Missing(0)))?;
        Ok(Self {
            device: DeviceInfo::parse(d).map_err(|_| PairError::Shape)?,
            group: m.opt_fixed(1)?.map(GroupId),
            head: m.opt_map(2)?.map(parse_head).transpose()?,
        })
    }
}

/// `PairConfirm {}` / `PairOk {}`: an empty map.
pub fn empty_map() -> Vec<u8> {
    vec![0xa0]
}

pub fn is_empty_map(raw: &[u8]) -> bool {
    matches!(cbor::decode(raw, &Limits::new(16)), Ok(Value::Map(m)) if m.is_empty())
}

/// `PairDone { 0: records [bstr] }`.
pub fn pair_done(records: &[Vec<u8>]) -> Vec<u8> {
    let mut e = Encoder::new();
    e.map(1).uint(0).array(records.len());
    for r in records {
        e.bytes(r);
    }
    e.into_bytes()
}

pub fn parse_pair_done(raw: &[u8]) -> Result<Vec<Vec<u8>>, PairError> {
    let v = cbor::decode(
        raw,
        &Limits {
            max_depth: 8,
            max_input: 4 << 20,
            max_items: crate::log::MAX_RECORDS,
        },
    )?;
    let m = MapRef::new(&v).ok_or(PairError::Shape)?;
    let list = m
        .opt_array(0)?
        .ok_or(PairError::Field(FieldError::Missing(0)))?;
    list.iter()
        .map(|r| match r {
            Value::Bytes(b) => Ok(b.to_vec()),
            _ => Err(PairError::Shape),
        })
        .collect()
}

/// Group resolution table (§5.3 step 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolution {
    /// Display appends genesis (new group) and then `add(scanner)`.
    NewGroup,
    /// Display appends `add(scanner)` to its group.
    DisplayAdds(GroupId),
    /// Scanner appends `add(display)` to its group.
    ScannerAdds(GroupId),
    /// Both already in the same group: refresh `DeviceInfo` via `update` if changed.
    AlreadyPaired(GroupId),
    /// Different groups: close `PAIR_OTHER_GROUP`.
    OtherGroup,
}

pub fn resolve(display: Option<GroupId>, scanner: Option<GroupId>) -> Resolution {
    match (display, scanner) {
        (None, None) => Resolution::NewGroup,
        (Some(g), None) => Resolution::DisplayAdds(g),
        (None, Some(h)) => Resolution::ScannerAdds(h),
        (Some(g), Some(h)) if g == h => Resolution::AlreadyPaired(g),
        (Some(_), Some(_)) => Resolution::OtherGroup,
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
    use crate::log::tests::dev;

    fn payload() -> QrPayload {
        QrPayload {
            eid: EndpointId([1; 32]),
            dial: DialInfo {
                relay: Some("https://euc1-1.relay.n0.iroh.link./".into()),
                addrs: vec!["192.168.1.20:41234".parse().unwrap()],
            },
            secret: Zeroizing::new([2; 32]),
            exp: 1_790_000_120,
            name: "desk-pc".into(),
            group: Some(GroupId([3; 16])),
            server: None,
        }
    }

    #[test]
    fn base32_rfc4648() {
        for (p, e) in [
            ("", ""),
            ("f", "MY"),
            ("fo", "MZXQ"),
            ("foo", "MZXW6"),
            ("foob", "MZXW6YQ"),
            ("fooba", "MZXW6YTB"),
            ("foobar", "MZXW6YTBOI"),
        ] {
            assert_eq!(base32(p.as_bytes()), e);
            assert_eq!(base32_decode(e).unwrap(), p.as_bytes());
        }
        assert!(base32_decode("my").is_none());
        assert!(base32_decode("MZ").is_none()); // non-zero trailing bits
        assert!(base32_decode("MY======").is_none());
    }

    #[test]
    fn qr_roundtrip_and_alphanumeric() {
        let p = payload();
        let t = p.encode();
        assert!(
            t.bytes()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b':')
        );
        assert_eq!(QrPayload::parse(&t).unwrap(), p);
        assert_eq!(
            QrPayload::parse(&t.replace("WARP1:", "WARP2:")).unwrap_err(),
            PairError::Prefix
        );
        assert!(QrPayload::parse(&t.to_lowercase()).is_err());
    }

    #[test]
    fn window_checks_in_order_and_is_single_use() {
        let mut w =
            Window::open(EndpointId([1; 32]), payload().dial, "pc".into(), None, 1000).unwrap();
        let qr = QrPayload::parse(&w.qr_text()).unwrap();
        let scanner = EndpointId([9; 32]);
        let ekm = [7; 32];
        let good = proof(&qr.secret, &ekm, &scanner);
        // Wrong proof on the first attempt burns the window.
        assert_eq!(
            w.check(&ekm, &scanner, &[0; 32], 1001),
            Err(PairError::Proof)
        );
        assert_eq!(w.check(&ekm, &scanner, &good, 1002), Err(PairError::Used));
        // Fresh window: good proof works once; expiry is checked first.
        let mut w =
            Window::open(EndpointId([1; 32]), payload().dial, "pc".into(), None, 1000).unwrap();
        let qr = QrPayload::parse(&w.qr_text()).unwrap();
        let good = proof(&qr.secret, &ekm, &scanner);
        assert_eq!(
            w.check(&ekm, &scanner, &good, 1000 + WINDOW_SECS + 1),
            Err(PairError::Expired)
        );
        let mut w2 = Window {
            payload: qr.clone(),
            used: false,
        };
        assert!(w2.check(&ekm, &scanner, &good, 1100).is_ok());
        assert_eq!(w2.check(&ekm, &scanner, &good, 1100), Err(PairError::Used));
        // Proof binds ekm and scanner id.
        let mut w3 = Window {
            payload: qr.clone(),
            used: false,
        };
        assert_eq!(
            w3.check(&[8; 32], &scanner, &good, 1100),
            Err(PairError::Proof)
        );
        let mut w4 = Window {
            payload: qr,
            used: false,
        };
        assert_eq!(
            w4.check(&ekm, &EndpointId([8; 32]), &good, 1100),
            Err(PairError::Proof)
        );
    }

    #[test]
    fn sas_format() {
        let s = sas(&[0; 32]);
        assert_eq!(s.len(), 7);
        assert_eq!(&s[3..4], "-");
        assert_ne!(sas(&[0; 32]), sas(&[1; 32]));
    }

    #[test]
    fn messages_roundtrip() {
        let head = Some(Head {
            seq: 2,
            id: RecordId([5; 32]),
        });
        let h = PairHello {
            device: dev("phone", 2, 2),
            proof: [6; 32],
            group: None,
            head: None,
        };
        assert_eq!(PairHello::parse(&h.encode()).unwrap(), h);
        let h = PairHello {
            group: Some(GroupId([3; 16])),
            head,
            ..h
        };
        assert_eq!(PairHello::parse(&h.encode()).unwrap(), h);
        let i = PairInfo {
            device: dev("pc", 1, 1),
            group: Some(GroupId([3; 16])),
            head,
        };
        assert_eq!(PairInfo::parse(&i.encode()).unwrap(), i);
        assert!(is_empty_map(&empty_map()));
        assert!(!is_empty_map(&[0xa1, 0, 0]));
        let recs = vec![vec![1, 2, 3], vec![4]];
        assert_eq!(parse_pair_done(&pair_done(&recs)).unwrap(), recs);
    }

    #[test]
    fn resolution_table_all_rows() {
        let (g, h) = (GroupId([1; 16]), GroupId([2; 16]));
        assert_eq!(resolve(None, None), Resolution::NewGroup);
        assert_eq!(resolve(Some(g), None), Resolution::DisplayAdds(g));
        assert_eq!(resolve(None, Some(h)), Resolution::ScannerAdds(h));
        assert_eq!(resolve(Some(g), Some(g)), Resolution::AlreadyPaired(g));
        assert_eq!(resolve(Some(g), Some(h)), Resolution::OtherGroup);
    }
}
