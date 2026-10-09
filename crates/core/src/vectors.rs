//! Test-vector generator (protocol §12). Vectors are derived from fixed seeds,
//! written to `docs/test-vectors/`, and consumed by the core and server tests.
//!
//! Regenerate: `cargo test -p warpshot-core gen_vectors -- --ignored`.
//! `vectors_are_current` fails when the committed files drift from the code.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

use std::path::PathBuf;

use serde_json::{Value as J, json};

use crate::{
    cbor::{self, Encoder, Limits, Value},
    keys::{IdentityKey, KemKey},
    log::{
        self, DeviceInfo, GroupId, Log, LogError, Op, RECORD_LABEL, RecordBody, RemoveReason,
        sign_record,
    },
};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/test-vectors")
}

/// Inputs that every strict decoder MUST reject (§1), with the reason.
const CBOR_REJECT: &[(&str, &str, &str)] = &[
    ("non-shortest uint (1 byte for 23)", "1817", "NonShortest"),
    (
        "non-shortest uint (2 bytes for 255)",
        "1900ff",
        "NonShortest",
    ),
    ("non-shortest uint (4 bytes)", "1a0000ffff", "NonShortest"),
    (
        "non-shortest uint (8 bytes)",
        "1b00000000ffffffff",
        "NonShortest",
    ),
    ("non-shortest bstr length", "580100", "NonShortest"),
    ("non-shortest array length", "98020102", "NonShortest"),
    ("non-shortest map key", "a1180101", "NonShortest"),
    ("indefinite bstr", "5f4101ff", "Indefinite"),
    ("indefinite tstr", "7f6161ff", "Indefinite"),
    ("indefinite array", "9f01ff", "Indefinite"),
    ("indefinite map", "bf0101ff", "Indefinite"),
    ("stray break", "ff", "Indefinite"),
    ("reserved additional info 28", "1c", "Reserved"),
    ("negative integer", "20", "Unsupported"),
    ("tag", "c11a514b67b0", "Unsupported"),
    ("null", "f6", "Unsupported"),
    ("undefined", "f7", "Unsupported"),
    ("half float", "f90000", "Unsupported"),
    ("single float", "fa47c35000", "Unsupported"),
    ("double float", "fb3ff199999999999a", "Unsupported"),
    ("simple value 16", "f0", "Unsupported"),
    ("duplicate map key", "a201020103", "DuplicateKey"),
    ("unsorted map keys", "a203040102", "UnsortedKeys"),
    ("text map key", "a1616101", "NonUintKey"),
    ("negative map key", "a12001", "NonUintKey"),
    ("invalid utf-8", "62c328", "InvalidUtf8"),
    ("utf-8 surrogate", "63eda080", "InvalidUtf8"),
    ("empty input", "", "Truncated"),
    ("truncated uint", "1a0001", "Truncated"),
    ("truncated bstr", "4401", "Truncated"),
    ("truncated array", "830102", "Truncated"),
    (
        "huge declared array length",
        "9b0000000100000000",
        "Truncated",
    ),
    (
        "huge declared bstr length",
        "5bffffffffffffffff",
        "Truncated",
    ),
    ("trailing bytes", "0000", "TrailingBytes"),
    ("nesting depth 9", "818181818181818100", "TooDeep"),
];

fn cbor_reject() -> J {
    let lim = Limits::new(1 << 20);
    let cases: Vec<J> = CBOR_REJECT
        .iter()
        .map(|(name, h, err)| {
            let got = cbor::decode(&unhex(h), &lim).unwrap_err();
            assert_eq!(format!("{got:?}"), *err, "{name}");
            json!({ "name": name, "hex": h, "error": err })
        })
        .collect();
    json!({
        "description": "Inputs a strict decoder MUST reject (protocol §1). max_depth = 8. 'error' names the rule (informational).",
        "cases": cases,
    })
}

const NOW: u64 = 1_790_000_000_000;
const GROUP: [u8; 16] = [0x47; 16];

fn dev(name: &str, platform: u64, kem_seed: u8) -> DeviceInfo {
    DeviceInfo {
        name: name.into(),
        platform,
        kem_pk: KemKey::from_seed(&[kem_seed; 32]).public_key(),
        app: Some("0.1.0".into()),
    }
}

fn body(log: &Log, subject: &IdentityKey, op: Op, dt: u64) -> RecordBody {
    let (seq, prev) = log.next_position();
    RecordBody {
        group_id: GroupId(GROUP),
        seq,
        prev,
        created_at: NOW + dt,
        subject: subject.endpoint_id(),
        op,
    }
}

/// Signs an arbitrary body map (for invalid shapes the typed builder cannot express).
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

fn record_vectors() -> J {
    let k = |s: u8| IdentityKey::from_secret(&[s; 32]);
    let (a, b, c) = (k(0xa1), k(0xb2), k(0xc3));
    let mut log = Log::new(GroupId(GROUP));
    let mut valid = Vec::new();
    let mut push = |log: &mut Log, raw: Vec<u8>, what: &str| {
        let rec = log
            .append(&raw, NOW)
            .unwrap_or_else(|e| panic!("{what}: {e}"))
            .clone();
        valid.push(
            json!({ "what": what, "record": hex(&raw), "id": hex(&rec.id.0), "seq": rec.body.seq }),
        );
    };
    let raw = sign_record(&a, &body(&log, &a, Op::Genesis(dev("desk-pc", 1, 0x01)), 0));
    push(&mut log, raw, "genesis by A");
    let raw = sign_record(&a, &body(&log, &b, Op::Add(dev("phone", 2, 0x02)), 1000));
    push(&mut log, raw, "A adds B");
    let raw = sign_record(&b, &body(&log, &b, Op::Update(dev("Pixel", 2, 0x03)), 2000));
    push(&mut log, raw, "B renames and rotates its KEM key");
    let raw = sign_record(&b, &body(&log, &c, Op::Add(dev("laptop", 1, 0x04)), 3000));
    push(&mut log, raw, "B adds C");
    let raw = sign_record(
        &a,
        &body(&log, &c, Op::Remove(RemoveReason::LostOrStolen), 4000),
    );
    push(&mut log, raw, "A removes C (lost or stolen)");
    let members: Vec<String> = log.members().keys().map(|id| hex(&id.0)).collect();

    // Invalid continuations of the full valid log (prefix = all valid records).
    let n = log.records().len() as u64;
    let head = log.head().unwrap().id.0;
    let prefix = log.records().len();
    let mut invalid = Vec::new();
    let mut bad = |name: &str, raw: Vec<u8>, err: LogError| {
        let got = log.check(&raw, NOW).unwrap_err();
        assert_eq!(got, err, "{name}");
        invalid.push(json!({ "name": name, "prefix": prefix, "record": hex(&raw), "error": format!("{err:?}") }));
    };
    let d = dev("tablet", 2, 0x05);
    let base = |op: u64,
                extra: Vec<(u64, Value<'static>)>,
                seq: u64,
                subject: [u8; 32]|
     -> Vec<(u64, Value<'static>)> {
        let mut v = vec![
            (0, Value::Uint(1)),
            (1, Value::Bytes(&GROUP)),
            (2, Value::Uint(seq)),
            (3, Value::Bytes(Box::leak(Box::new(head)))),
            (4, Value::Uint(NOW + 5000)),
            (5, Value::Uint(op)),
            (6, Value::Bytes(Box::leak(Box::new(subject)))),
        ];
        v.extend(extra);
        v
    };
    let dmap = |dev: &DeviceInfo| -> Value<'static> {
        Value::Map(vec![
            (0, Value::Text(Box::leak(dev.name.clone().into_boxed_str()))),
            (1, Value::Uint(dev.platform)),
            (
                2,
                Value::Bytes(Box::leak(dev.kem_pk.clone().into_boxed_slice())),
            ),
        ])
    };
    let cid = c.endpoint_id().0;
    let bid = b.endpoint_id().0;

    let mut bd = body(&log, &c, Op::Add(d.clone()), 5000);
    bd.group_id = GroupId([0x48; 16]);
    bad(
        "wrong group_id",
        sign_record(&a, &bd),
        LogError::GroupMismatch,
    );
    let mut bd = body(&log, &c, Op::Add(d.clone()), 5000);
    bd.seq = n + 1;
    bad("seq skips one", sign_record(&a, &bd), LogError::SeqMismatch);
    let mut bd = body(&log, &c, Op::Add(d.clone()), 5000);
    bd.prev = Some(log::RecordId([0; 32]));
    bad(
        "prev is not the head",
        sign_record(&a, &bd),
        LogError::PrevMismatch,
    );
    bad(
        "second genesis",
        sign_record(&a, &body(&log, &c, Op::Genesis(d.clone()), 5000)),
        LogError::NotGenesisOp,
    );
    bad(
        "signer was removed",
        sign_record(&c, &body(&log, &c, Op::Add(d.clone()), 5000)),
        LogError::SignerNotMember,
    );
    bad(
        "created_at too far in the future",
        sign_record(&a, &body(&log, &c, Op::Add(d.clone()), 11 * 60 * 1000)),
        LogError::TimeFuture,
    );
    let mut bd = body(&log, &c, Op::Add(d.clone()), 0);
    bd.created_at = NOW + 4000 - 10 * 60 * 1000 - 1;
    bad(
        "created_at regresses more than 10 min",
        sign_record(&a, &bd),
        LogError::TimeRegress,
    );
    bad(
        "add an existing member",
        sign_record(&a, &body(&log, &b, Op::Add(d.clone()), 5000)),
        LogError::AddExisting,
    );
    bad(
        "remove a non-member",
        sign_record(&a, &body(&log, &c, Op::Remove(RemoveReason::User), 5000)),
        LogError::RemoveMissing,
    );
    bad(
        "update signed by someone else",
        sign_record(&a, &body(&log, &b, Op::Update(dev("x", 2, 6)), 5000)),
        LogError::UpdateNotSelf,
    );
    bad(
        "update changes platform",
        sign_record(&b, &body(&log, &b, Op::Update(dev("x", 1, 6)), 5000)),
        LogError::UpdatePlatform,
    );
    let mut raw = sign_record(&a, &body(&log, &c, Op::Add(d.clone()), 5000));
    let last = raw.len() - 1;
    raw[last] ^= 0x01;
    bad("signature bit flipped", raw, LogError::BadSignature);
    bad(
        "add without device",
        raw_record(&a, base(1, vec![], n, cid)),
        LogError::Presence,
    );
    bad(
        "remove with device",
        raw_record(
            &a,
            base(2, vec![(7, dmap(&d)), (8, Value::Uint(0))], n, bid),
        ),
        LogError::Presence,
    );
    bad(
        "remove reason 4",
        raw_record(&a, base(2, vec![(8, Value::Uint(4))], n, bid)),
        LogError::Presence,
    );
    bad(
        "add with reason",
        raw_record(
            &a,
            base(1, vec![(7, dmap(&d)), (8, Value::Uint(0))], n, cid),
        ),
        LogError::Presence,
    );
    bad(
        "op 4",
        raw_record(&a, base(4, vec![], n, cid)),
        LogError::UnknownOp,
    );
    bad(
        "device name empty",
        raw_record(&a, base(1, vec![(7, dmap(&dev("", 2, 5)))], n, cid)),
        LogError::DeviceName,
    );
    bad(
        "device name with control char",
        raw_record(&a, base(1, vec![(7, dmap(&dev("a\nb", 2, 5)))], n, cid)),
        LogError::DeviceName,
    );
    bad(
        "device name 65 bytes",
        raw_record(
            &a,
            base(1, vec![(7, dmap(&dev(&"n".repeat(65), 2, 5)))], n, cid),
        ),
        LogError::DeviceName,
    );
    bad(
        "device name with bidi override U+202E",
        raw_record(
            &a,
            base(1, vec![(7, dmap(&dev("pc\u{202E}evil", 2, 5)))], n, cid),
        ),
        LogError::DeviceName,
    );
    let mut small = [0u8; 32];
    small[0] = 1; // identity point: small order
    bad(
        "add subject is a small-order point",
        raw_record(&a, base(1, vec![(7, dmap(&d))], n, small)),
        LogError::SubjectKey,
    );
    bad(
        "platform 0",
        raw_record(&a, base(1, vec![(7, dmap(&dev("t", 0, 5)))], n, cid)),
        LogError::DevicePlatform,
    );
    let mut short = d.clone();
    short.kem_pk.pop();
    bad(
        "kem_pk 1215 bytes",
        raw_record(&a, base(1, vec![(7, dmap(&short))], n, cid)),
        LogError::DeviceKemKey,
    );
    let mut v = base(1, vec![(7, dmap(&d))], n, cid);
    v[0] = (0, Value::Uint(2));
    bad("record version 2", raw_record(&a, v), LogError::Version);

    // Valid edge cases (must be ACCEPTED as the next record).
    let mut accept = Vec::new();
    let mut fut = match dmap(&dev("future-os", 77, 0x07)) {
        Value::Map(m) => m,
        _ => unreachable!(),
    };
    fut.push((9, Value::Text("unknown key")));
    let r = raw_record(&a, base(1, vec![(7, Value::Map(fut))], n, cid));
    log.check(&r, NOW).unwrap();
    accept.push(json!({ "name": "unknown platform 77 and an unknown DeviceInfo key", "prefix": prefix, "record": hex(&r) }));
    let r = sign_record(&b, &body(&log, &b, Op::Remove(RemoveReason::Left), 5000));
    log.check(&r, NOW).unwrap();
    accept.push(
        json!({ "name": "member removes itself (leave)", "prefix": prefix, "record": hex(&r) }),
    );

    json!({
        "description": "Membership log vectors (protocol §4). Validate 'valid' in order from an empty log with now_ms; then each 'invalid' record MUST be rejected and each 'accept' record MUST be accepted as record number 'prefix'. Keys: Ed25519 secret = 32 × seed byte. 'error' names the rule (informational).",
        "group_id": hex(&GROUP),
        "now_ms": NOW,
        "keys": [
            { "name": "A", "secret": hex(&[0xa1; 32]), "endpoint_id": hex(&a.endpoint_id().0) },
            { "name": "B", "secret": hex(&[0xb2; 32]), "endpoint_id": hex(&b.endpoint_id().0) },
            { "name": "C", "secret": hex(&[0xc3; 32]), "endpoint_id": hex(&c.endpoint_id().0) },
        ],
        "valid": valid,
        "members_after_valid": members,
        "invalid": invalid,
        "accept": accept,
    })
}

fn wake_vectors() -> J {
    use crate::{
        keys::kid,
        log::Head,
        wake::{self, DialInfo, Inner, Kind, Preview, WakeError},
    };
    let sender = IdentityKey::from_secret(&[0xa1; 32]);
    let recipient = IdentityKey::from_secret(&[0xb2; 32]);
    let rkem = KemKey::from_seed(&[0x02; 32]);
    let rpk = rkem.public_key();
    let me = recipient.endpoint_id();
    let head = Head {
        seq: 4,
        id: log::RecordId([0x99; 32]),
    };
    let connect = Inner {
        kind: Kind::Connect {
            session: [0x5e; 16],
            dial: DialInfo {
                relay: Some("https://euc1-1.relay.n0.iroh.link./".into()),
                addrs: vec![
                    "192.168.1.20:41234".parse().unwrap(),
                    "[2001:db8::7]:41234".parse().unwrap(),
                ],
            },
            preview: Some(Preview {
                count: 1,
                total_size: 248_113,
                kinds: vec![2],
            }),
        },
        ts: NOW,
        nonce: [0x0c; 16],
        group_id: GroupId(GROUP),
        head,
    };
    let changed = Inner {
        kind: Kind::GroupChanged,
        nonce: [0x0d; 16],
        ..connect.clone()
    };
    let mut cases = Vec::new();
    for (name, inner, eseed) in [
        ("connect", &connect, [0x31u8; 64]),
        ("group-changed", &changed, [0x32u8; 64]),
    ] {
        let env = wake::seal_with(&sender, &me, &rpk, inner, &eseed).unwrap();
        let opened = wake::open(&env, &me, |_| Some(&rkem)).unwrap();
        assert_eq!(&opened.inner, inner);
        cases.push(json!({
            "name": name,
            "eseed": hex(&eseed),
            "inner": hex(&inner.encode()),
            "envelope": hex(&env),
            "envelope_b64u": crate::b64u::encode(&env),
        }));
    }
    let env = wake::seal_with(&sender, &me, &rpk, &connect, &[0x31; 64]).unwrap();
    let flip = |at: usize| {
        let mut b = env.clone();
        b[at] ^= 0x01;
        b
    };
    let kid_pk = kid(&rpk);
    let mut tamper = Vec::new();
    // Layout: 84 01 48 <kid 8> 59 0460 <ct_kem 1120> 59 xxxx <ct>.
    for (name, raw, err) in [
        ("kid flipped", flip(3), WakeError::UnknownKid),
        ("ct_kem flipped", flip(14), WakeError::Aead),
        ("ciphertext flipped", flip(1140), WakeError::Aead),
        ("tag flipped", flip(env.len() - 1), WakeError::Aead),
    ] {
        let got = wake::open(&raw, &me, |k| (*k == kid_pk).then_some(&rkem)).unwrap_err();
        assert_eq!(got, err, "{name}");
        tamper.push(json!({ "name": name, "envelope": hex(&raw), "error": format!("{err:?}") }));
    }
    assert_eq!(
        wake::open(&env, &sender.endpoint_id(), |_| Some(&rkem)).unwrap_err(),
        WakeError::Aead
    );
    json!({
        "description": "Wake envelopes (protocol §7). Sender secret = 32 × 0xa1, recipient secret = 32 × 0xb2, recipient X-Wing seed = 32 × 0x02. seal(eseed) MUST reproduce 'envelope' byte for byte; open MUST return 'inner'. Tamper cases MUST be rejected; opening as the sender's id MUST fail (recipient binding).",
        "sender_endpoint_id": hex(&sender.endpoint_id().0),
        "recipient_endpoint_id": hex(&me.0),
        "recipient_kem_pk": hex(&rpk),
        "kid": hex(&kid_pk),
        "cases": cases,
        "tamper": tamper,
    })
}

fn server_auth_vectors() -> J {
    use crate::server_auth::{self, MAX_SKEW_MS};
    let ik = IdentityKey::from_secret(&[0xa1; 32]);
    let reqs: [(&str, &str, &[u8]); 4] = [
        ("POST", "/v1/groups", br#"{"genesis":"AAAA"}"#),
        ("GET", "/v1/groups/R0dHR0dHR0dHR0dHR0dHRw/log?after=3", b""),
        (
            "PUT",
            "/v1/groups/R0dHR0dHR0dHR0dHR0dHRw/push-token",
            br#"{"provider":"fcm","token":"t"}"#,
        ),
        ("GET", "/v1/groups/R0dHR0dHR0dHR0dHR0dHRw/ws", b""),
    ];
    let valid: Vec<J> = reqs
        .iter()
        .map(|(m, p, body)| {
            let canon = server_auth::canonical(m, p, NOW, body);
            let header = server_auth::authorization(&ik, m, p, NOW, body);
            let parsed = server_auth::parse(&header).unwrap();
            assert!(server_auth::verify(&parsed, m, p, body, NOW));
            json!({ "method": m, "path": p, "ts": NOW, "body_hex": hex(body), "signed_hex": hex(&canon), "authorization": header })
        })
        .collect();
    let (m, p, body) = reqs[0];
    let h = server_auth::authorization(&ik, m, p, NOW, body);
    let parsed = server_auth::parse(&h).unwrap();
    let mut reject = Vec::new();
    for (name, now, method, path, b, ok) in [
        ("accepted at +120 s", NOW + MAX_SKEW_MS, m, p, body, true),
        ("accepted at -120 s", NOW - MAX_SKEW_MS, m, p, body, true),
        (
            "rejected at +120.001 s",
            NOW + MAX_SKEW_MS + 1,
            m,
            p,
            body,
            false,
        ),
        (
            "rejected at -120.001 s",
            NOW - MAX_SKEW_MS - 1,
            m,
            p,
            body,
            false,
        ),
        ("different method", NOW, "PUT", p, body, false),
        ("different path", NOW, m, "/v1/groups/", body, false),
        (
            "different body",
            NOW,
            m,
            p,
            &br#"{"genesis":"AAAB"}"#[..],
            false,
        ),
    ] {
        assert_eq!(
            server_auth::verify(&parsed, method, path, b, now),
            ok,
            "{name}"
        );
        reject.push(json!({ "name": name, "authorization": h, "now_ms": now, "method": method, "path": path, "body_hex": hex(b), "accept": ok }));
    }
    let mut bad_sig = parsed.sig;
    bad_sig[10] ^= 1;
    let bad_sig_header = format!(
        "WARP1 id={}, ts={NOW}, sig={}",
        crate::b64u::encode(&parsed.id.0),
        crate::b64u::encode(&bad_sig)
    );
    reject.push(json!({ "name": "signature bit flipped", "authorization": bad_sig_header, "now_ms": NOW, "method": m, "path": p, "body_hex": hex(body), "accept": false }));
    let malformed: Vec<J> = [
        ("wrong scheme", h.replace("WARP1 ", "WARP2 ")),
        ("lowercase scheme", h.replace("WARP1 ", "warp1 ")),
        ("missing space after comma", h.replace(", ts=", ",ts=")),
        (
            "ts with leading zero",
            h.replace(&format!("ts={NOW}"), &format!("ts=0{NOW}")),
        ),
        (
            "ts with plus sign",
            h.replace(&format!("ts={NOW}"), &format!("ts=+{NOW}")),
        ),
        (
            "fields out of order",
            format!(
                "WARP1 ts={NOW}, id={}, sig={}",
                crate::b64u::encode(&parsed.id.0),
                crate::b64u::encode(&parsed.sig)
            ),
        ),
        ("trailing space", format!("{h} ")),
        ("id with padding", h.replacen(", ts=", "=, ts=", 1)),
        (
            "sig 63 bytes",
            format!(
                "WARP1 id={}, ts={NOW}, sig={}",
                crate::b64u::encode(&parsed.id.0),
                crate::b64u::encode(&parsed.sig[..63])
            ),
        ),
    ]
    .into_iter()
    .map(|(name, hdr)| {
        assert!(server_auth::parse(&hdr).is_none(), "{name}");
        json!({ "name": name, "authorization": hdr })
    })
    .collect();
    json!({
        "description": "Server request auth (protocol §6.1). Signer secret = 32 × 0xa1. 'valid': signed_hex and authorization MUST match exactly. 'verify': parse the header and check signature and clock against now_ms; 'accept' is the expected result (membership and replay are out of scope here). 'malformed': the header MUST be rejected by the parser.",
        "endpoint_id": hex(&ik.endpoint_id().0),
        "valid": valid,
        "verify": reject,
        "malformed": malformed,
    })
}

fn all() -> Vec<(&'static str, J)> {
    vec![
        ("server-auth.json", server_auth_vectors()),
        ("cbor-reject.json", cbor_reject()),
        ("record.json", record_vectors()),
        ("wake.json", wake_vectors()),
    ]
}

fn render(v: &J) -> String {
    serde_json::to_string_pretty(v).unwrap() + "\n"
}

#[test]
#[ignore]
fn gen_vectors() {
    std::fs::create_dir_all(dir()).unwrap();
    for (name, v) in all() {
        std::fs::write(dir().join(name), render(&v)).unwrap();
    }
}

#[test]
fn vectors_are_current() {
    for (name, v) in all() {
        let path = dir().join(name);
        let Ok(on_disk) = std::fs::read_to_string(&path) else {
            panic!("{name} missing; run gen_vectors");
        };
        assert_eq!(
            on_disk.replace("\r\n", "\n"),
            render(&v),
            "{name} is stale; run gen_vectors"
        );
    }
}

#[test]
fn record_vectors_replay() {
    let v: J =
        serde_json::from_str(&std::fs::read_to_string(dir().join("record.json")).unwrap()).unwrap();
    let now = v["now_ms"].as_u64().unwrap();
    let g: [u8; 16] = unhex(v["group_id"].as_str().unwrap()).try_into().unwrap();
    let raws: Vec<Vec<u8>> = v["valid"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| unhex(r["record"].as_str().unwrap()))
        .collect();
    let log = Log::from_records(GroupId(g), raws.iter().map(Vec::as_slice), now).unwrap();
    for case in v["invalid"].as_array().unwrap() {
        let raw = unhex(case["record"].as_str().unwrap());
        assert_eq!(
            format!("{:?}", log.check(&raw, now).unwrap_err()),
            case["error"].as_str().unwrap()
        );
    }
    for case in v["accept"].as_array().unwrap() {
        log.check(&unhex(case["record"].as_str().unwrap()), now)
            .unwrap();
    }
}
