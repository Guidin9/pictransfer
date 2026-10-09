# Warpshot protocol — version 1

Status: **DRAFT** (Faz 0). Normative keywords MUST / SHOULD / MAY follow RFC 2119.
Code follows this document. To change a wire format or a crypto step, change this
document and the test vectors (§12) first, then the code.

Contents: 1 Conventions · 2 Cryptography · 3 Identities · 4 Membership log ·
5 Pairing · 6 Server API · 7 Wake envelopes · 8 Transfer protocol ·
9 Endpoint policy · 10 Limits · 11 Versioning · 12 Test vectors

---

## 1. Conventions

- `‖` is byte concatenation. `"..."` is ASCII without a terminator; `\0` is a 0x00 byte.
- `u32be(x)` / `u64be(x)`: big-endian unsigned integers.
- Times are `u64` milliseconds since the Unix epoch (UTC) unless stated otherwise.
- JSON byte strings are base64url **without padding** (RFC 4648 §5), written `b64u`.
- **CBOR** (RFC 8949) is used for all binary structures:
  - Maps use small unsigned-integer keys. Encoders MUST use preferred serialization
    (shortest-form integers and lengths, definite lengths only) and write map
    keys in ascending order.
  - Decoders MUST reject indefinite-length items, non-shortest integers or
    lengths, duplicate map keys, map keys out of ascending order, tags, floats,
    nesting deeper than 8, trailing bytes after the top-level item, and any size
    above the limits in §10 — **before** allocating. (Each rule has a negative
    test; the decoder is hand-written and fuzzed, ADR 0008.)
  - Decoders MUST ignore unknown map keys (forward compatibility) unless a
    section says otherwise.
- Signed structures carry the exact signed bytes as a CBOR byte string. Receivers
  verify those bytes and never re-encode before verifying.
- Every signature, MAC and KDF input starts with a unique label (§2.3).

## 2. Cryptography

### 2.1 Primitives

| Purpose | Algorithm |
|---|---|
| Device identity, signatures | Ed25519 (RFC 8032). Verification MUST be strict: reject non-canonical encodings and small-order points (`verify_strict`). |
| Hybrid post-quantum KEM | X-Wing (X25519 + ML-KEM-768), `draft-connolly-cfrg-xwing-kem-06` (wire format and combiner unchanged through draft -11). Encapsulation key 1216 B, ciphertext 1120 B, shared secret 32 B. Decapsulation MUST fail when the X25519 shared secret is all zero (non-contributory peer share); a negative test vector covers it. |
| KDF | HKDF-SHA-256 (RFC 5869) |
| MAC | HMAC-SHA-256 |
| AEAD | ChaCha20-Poly1305 (RFC 8439), 96-bit nonce, 128-bit tag |
| Protocol object hash | SHA-256 |
| Content integrity hash | BLAKE3-256 |
| Transport | iroh 1.x: QUIC + TLS 1.3 with Ed25519 raw public keys. Peer identity = `EndpointId`. |
| Randomness | OS CSPRNG |

Implementation notes (non-normative): X-Wing from RustCrypto `x-wing` with the
`zeroize` feature, decapsulating with `DecapsulationKeyRejectNonContrib`; the
returned shared key is zeroized by the caller (ADR 0008). Also use `hkdf`, `hmac`, `sha2`, `chacha20poly1305`, `blake3`,
`zeroize`, `subtle` (constant-time). The Cloudflare Worker uses WebCrypto (Ed25519, SHA-256).

### 2.2 Keys

| Key | Type | Lifetime | Storage |
|---|---|---|---|
| Identity key `IK` | Ed25519 | device lifetime | private part wrapped by the OS keystore (Windows DPAPI, later TPM; Android Keystore AES-GCM, StrongBox if present). Public part = `EndpointId`. |
| KEM key `KK` | X-Wing | until rotated (`update` record) | private part wrapped by the OS keystore. Public part in the membership log. |
| Ephemeral transfer KEM key | X-Wing | one connection | memory only, zeroized after the handshake |
| Pairing secret | 32 random bytes | single use, ≤ 120 s | memory only |
| History key | 32 random bytes | device lifetime | wrapped by the OS keystore |

All secrets MUST be zeroized after use and MUST NOT be logged.

### 2.3 Labels (domain separation)

| Label | Use |
|---|---|
| `warpshot/record/v1\0` | membership record signature input prefix |
| `warpshot/record-id/v1\0` | record id hash prefix |
| `warpshot/server-auth/v1\0` | server request signature prefix |
| `warpshot/wake-sig/v1\0` | wake envelope sender signature prefix |
| `warpshot/wake-kdf/v1` | wake envelope HKDF `info` prefix |
| `warpshot/pair-proof/v1` | pairing proof HMAC message prefix |
| `warpshot/sas/v1` | short authentication string hash prefix |
| `EXPORTER-warpshot-pair-v1` | TLS exporter label, pairing |
| `EXPORTER-warpshot-xfer-v1` | TLS exporter label, transfer |
| `warpshot/xfer-transcript/v1\0` | transfer transcript hash prefix |
| `warpshot/xfer-kdf/v1 ` | transfer HKDF `info` prefix (note trailing space) |

## 3. Identities

- `EndpointId`: the 32-byte Ed25519 public key of `IK`. It is both the iroh
  endpoint id and the device's identity in the group.
- `DeviceInfo` (CBOR map):

  | Key | Field | Type | Rules |
  |---|---|---|---|
  | 0 | `name` | tstr | 1–64 bytes UTF-8, no control characters (Cc) and no bidi formatting characters (U+061C, U+200E, U+200F, U+202A–U+202E, U+2066–U+2069), which could spoof the §4.6 alert |
  | 1 | `platform` | uint | 1 = windows, 2 = android; other values are reserved for new platforms. Receivers MUST accept them (shown as "other") so a newer member never breaks an older client's log. 0 is invalid. |
  | 2 | `kem_pk` | bstr | exactly 1216 bytes (X-Wing encapsulation key) |
  | 3 | `app` | tstr | ≤ 32 bytes, app version, informational |

- Unknown `DeviceInfo` keys are ignored; missing `name`, `platform` or `kem_pk` is invalid.
- `kid(kem_pk)` = first 8 bytes of `SHA-256(kem_pk)`.
- `LogHead` = `{ 0: seq uint, 1: id bstr .size 32 }`.
- `DialInfo` = `{ 0: relay tstr (optional), 1: [ tstr "ip:port" ] (≤ 8 entries) }`.

## 4. Group membership log

### 4.1 Model

A group is identified by `group_id`, 16 random bytes chosen by the founder. The
group's membership is defined **only** by a linear, hash-chained, signed log.
Any current member may append a record. The server stores the log and serializes
appends (compare-and-swap on the head), but it is not trusted: every client
validates the whole log itself and detects forks (§4.5).

### 4.2 Encoding

```
SignedRecord = [ body: bstr, signer: bstr .size 32, sig: bstr .size 64 ]   ; CBOR array

RecordBody (CBOR map, encoded inside `body`):
  0: v          uint = 1
  1: group_id   bstr .size 16
  2: seq        uint            ; 0 = genesis, then +1
  3: prev       bstr .size 32   ; record id of seq-1 (absent for genesis)
  4: created_at uint            ; ms
  5: op         uint            ; 0 genesis, 1 add, 2 remove, 3 update
  6: subject    bstr .size 32   ; EndpointId the record is about
  7: device     DeviceInfo      ; genesis, add, update
  8: reason     uint            ; remove only: 0 user, 1 lost-or-stolen, 2 left, 3 not-me

sig       = Ed25519.Sign(IK_signer, "warpshot/record/v1\0" ‖ body)
record_id = SHA-256("warpshot/record-id/v1\0" ‖ body ‖ signer ‖ sig)
```

### 4.3 Validation (normative)

Let records `0..n-1` be validated, with state `S` (a map `EndpointId → DeviceInfo`)
and head id `H`. Record `R` at position `n` is valid **iff all** hold:

1. `R` decodes per §4.2 within the limits (a `SignedRecord` ≤ 4 KiB); `v == 1`;
   `group_id` is the group's id; `seq == n`; `op ≤ 3`. Field presence by `op`:
   `device` present for genesis/add/update and absent for remove; `reason`
   present (0–3) for remove and absent otherwise.
2. If `n == 0`: `op == genesis`, `prev` absent, `signer == subject`, `device` present.
   If `n > 0`: `prev == H`, `op ∈ {add, remove, update}`, `signer ∈ S`.
3. `created_at ≤ now + 10 min`, and for `n > 0` also `created_at ≥ created_at(n-1) − 10 min`.
   Order comes from `seq`, not from time.
4. Operation rules:
   - `add`: `subject ∉ S`, `device` present, `subject` is a valid Ed25519 public key that is not of small order. Re-adding a previously removed key is a new admission and is allowed.
   - `remove`: `subject ∈ S`. A member may remove itself (leave).
   - `update`: `signer == subject`, `device` present, `device.platform` unchanged (rename or KEM key rotation).
5. `Ed25519.VerifyStrict(signer, "warpshot/record/v1\0" ‖ body, sig)` succeeds.

State transition: `genesis`/`add`/`update` set `S[subject] = device`; `remove`
deletes `S[subject]`. When `S` becomes empty the group is dead and no further
record is valid. Limits: at most 16 members and 1024 records (§10); an `add`
that would make a 17th member is invalid.

### 4.4 Appending

1. The client builds `R` on top of the head it knows (`seq + 1`, `prev = id`), signs
   it and submits it (§6.2 `POST …/log`). The server validates it (§6.6) and
   accepts only if `prev` equals the server's current head.
2. On `409 head-moved`: fetch the missing records, validate them, re-check the
   intent against the new state (for example, the subject may already have been
   removed), rebuild, re-sign and retry, up to 3 times.
3. On success, the appender sends a `group-changed` wake (§7) to every other member.
4. Membership changes require the server in v1. Offline (LAN-only) membership
   changes are out of scope.

### 4.5 Sync and fork detection

- Every device stores its group's full log (tens of records, a few KiB).
- Records arrive from the server (`GET …/log`, WebSocket `log` push) and from
  peers (head exchange in every transfer handshake, §8.3; in-band sync, §8.5).
- Received records MUST be validated as a continuation of the local log.
- **Fork:** a received record has `seq ≤ local head seq` but its id differs from
  the local record at that `seq`. Then the device MUST raise a security alert and
  stop all transfers and membership changes for the group until the user
  resolves it (re-pair). It MUST NOT merge automatically.

### 4.6 User alerts (required UX)

Every validated `add` that the local device did not create MUST notify the user
on every member:

> "New device added: {name} ({platform}) by {adder name}"

with the action **"This wasn't me"**. That action appends `remove(subject, reason = 3)`
and offers to remove the adder as well.

## 5. Pairing (ALPN `warpshot/pair/1`)

### 5.1 Roles

The **display** device (always the PC in v1) shows a QR code. The **scanner** (the
phone) scans it. Either device may already belong to a group.

### 5.2 QR payload

```
QR text = "WARP1:" ‖ BASE32_NOPAD_UPPER(CBOR(QrPayload))   ; QR alphanumeric mode

QrPayload:
  0: v       uint = 1
  1: eid     bstr .size 32   ; display EndpointId
  2: dial    DialInfo        ; display relay URL + direct addresses
  3: secret  bstr .size 32   ; one-time pairing secret
  4: exp     uint            ; expiry, Unix SECONDS, ≤ creation + 120
  5: name    tstr            ; display device name
  6: group   bstr .size 16   ; display's group_id, if any
  7: server  tstr            ; server base URL, only if not the build default
```

### 5.3 Exchange

Frames: length-prefixed CBOR as in §8.2, phase 1 only. Pairing carries no
content, so the inner AEAD layer is not used. TLS plus the exporter-bound proof
are sufficient.

1. The scanner dials `eid` using `dial`. It MUST abort unless `remote_id() == eid`.
2. Both sides compute:
   `ekm = export_keying_material(len 32, label "EXPORTER-warpshot-pair-v1", context eid_display ‖ eid_scanner)`.
3. S → D `PairHello { 0: v=1, 1: device DeviceInfo, 2: proof bstr32, 3: group bstr16?, 4: head LogHead? }`
   where `proof = HMAC-SHA-256(key = secret, msg = "warpshot/pair-proof/v1" ‖ ekm ‖ eid_scanner)`.
4. D checks, in this order:
   - The QR has not expired.
   - The secret is unused. D marks it used on the **first** attempt, whether that attempt succeeds or fails.
   - `proof` matches, compared in constant time.

   On any failure D closes with `PAIR_PROOF` or `PAIR_EXPIRED` and discards the QR.
5. D → S `PairInfo { 0: device DeviceInfo, 1: group bstr16?, 2: head LogHead? }`.
6. Both screens show the SAS: the first 6 characters of
   `BASE32(SHA-256("warpshot/sas/v1" ‖ ekm))`, formatted `XXX-XXX`, together
   with the other device's name and platform. **The user must confirm on both devices.**
   The confirmations are exchanged as `PairConfirm {}`. A refusal or a 120 s
   timeout closes with `PAIR_REJECTED`.
7. Group resolution. The **appender** builds the records:

   | Display | Scanner | Appender | Action |
   |---|---|---|---|
   | none | none | display | genesis (new group G), then `add(scanner)` |
   | in G | none | display | `add(scanner)` to G |
   | none | in H | scanner | `add(display)` to H |
   | in G | in G | — | already paired: refresh `DeviceInfo` via `update` if changed |
   | in G | in H ≠ G | — | close `PAIR_OTHER_GROUP` ("leave the other group first") |

8. The appender submits to the server (§4.4), then sends `PairDone { 0: records [bstr] }`
   with the full log. The other side validates the log from genesis, stores it,
   replies `PairOk {}`, and both sides close with code `0`.

## 6. Server API

Base URL `SRV` is the build-time default or the value from the QR payload. HTTPS only.
`gid` in paths is `b64u(group_id)` (22 characters).

### 6.1 Request authentication

```
Authorization: WARP1 id=<b64u EndpointId>, ts=<decimal ms>, sig=<b64u signature>

signed = "warpshot/server-auth/v1\0" ‖ METHOD ‖ "\n" ‖ PATH_AND_QUERY ‖ "\n"
         ‖ ts ‖ "\n" ‖ lowercase_hex(SHA-256(body))      ; empty body → SHA-256("")
sig    = Ed25519.Sign(IK, signed)
```

The header is parsed strictly: exactly `WARP1 id=<…>, ts=<…>, sig=<…>` in this
order with single spaces as shown; `id` is 32 bytes and `sig` 64 bytes in
canonical base64url without padding; `ts` is decimal digits without sign or
leading zeros. `ts` in `signed` is the same digit string. `PATH_AND_QUERY` is the
request target exactly as sent (no normalization).

The server MUST:
- require `|now − ts| ≤ 120 s`;
- reject a repeated `(id, ts, sig)` within that window;
- verify `sig` strictly;
- require `id ∈` its member set. The exception is `POST /v1/groups`, where `id` MUST be the genesis signer.

**Operator admission (private deployments).** If the Worker secret
`GROUP_CREATE_TOKEN` is set, `POST /v1/groups` MUST also carry
`Warpshot-Create-Token: <token>`. The server compares it with the secret in constant
time and answers 403 `not-allowed` when it is missing or wrong, before any other
processing. All other endpoints already require membership, so this restricts the
whole deployment to the operator's groups. The token is not a key: a leak only
allows creating new groups (quota abuse), never access to existing ones. Clients
take it from build-time deployment config that is not committed (ADR 0007).

### 6.2 Endpoints

| Method | Path | Request body | Responses |
|---|---|---|---|
| POST | `/v1/groups` | `{"genesis": b64u}` | 201 `{"group": gid, "head": Head}` · 409 `exists` · 422 `invalid-record` |
| GET | `/v1/groups/{gid}/log?after={seq}` | – | 200 `{"records": [b64u], "head": Head}` |
| POST | `/v1/groups/{gid}/log` | `{"record": b64u}` | 200 `{"head": Head}` · 409 `{"error":"head-moved","head":Head}` · 422 |
| POST | `/v1/groups/{gid}/wake` | `{"to": b64u, "env": b64u, "ttl": s}` | 200 `{"via": "ws" \| "push" \| "none"}` |
| PUT | `/v1/groups/{gid}/push-token` | `{"provider": "fcm", "token": str}` | 204 |
| DELETE | `/v1/groups/{gid}/push-token` | – | 204 |
| GET | `/v1/groups/{gid}/presence` | – | 200 `{"devices": [{"id", "online", "push", "last_seen"}]}` |
| GET | `/v1/groups/{gid}/ws` | – (WebSocket upgrade) | 101 |
| GET | `/v1/health` | – | 200 (unauthenticated) |

`Head` = `{"seq": n, "id": b64u}`. `last_seen` is in ms, with 60 s granularity
(this limits storage writes).

### 6.3 WebSocket

- The upgrade request is authenticated as in §6.1. The Durable Object accepts the
  socket with the Hibernation API and tags it with the device id.
- **Keepalive:** the client sends the text frame `p` every `K` seconds. The server
  answers `o` through `setWebSocketAutoResponse`, without waking the object.
  `K` is set by Spike C (default 60). After two missed `o` replies the client
  reconnects. It also reconnects on OS network-change and resume events.
  Backoff: 1, 2, 4 … up to 300 s, ±20 % jitter.
- Client → server: `{"t":"wake","id":n,"to","env","ttl"}`, `{"t":"presence","id":n}`,
  `{"t":"log-get","id":n,"after":seq}`.
- Server → client: `{"t":"wake","env"}` (the sender identity is only inside the
  envelope), `{"t":"ack","id","via"}`, `{"t":"presence","id","devices"}`,
  `{"t":"log","records","head"}` (pushed after every accepted append),
  `{"t":"err","id","code"}`, `{"t":"bye","code"}` (for example, after removal).
- Unknown `t` values MUST be ignored. Maximum message size is 64 KiB.

### 6.4 Wake routing

`to` MUST be a member. Routing order:
1. If `to` has an open socket, send `{"t":"wake","env"}` → `via: "ws"`.
2. Otherwise, if `to` has a push token, send through FCM (§6.5) → `via: "push"`.
3. Otherwise → `via: "none"`.

The server MUST NOT inspect `env` beyond its size (≤ 3800 b64u characters).
Rate limit: 60 wakes per minute per device, burst 20.

### 6.5 FCM message

```
POST https://fcm.googleapis.com/v1/projects/{project}/messages:send
{ "message": {
    "token": "<token>",
    "android": { "priority": "HIGH", "ttl": "<ttl>s" },
    "data": { "v": "1", "e": "<b64u envelope>" } } }
```

No `notification` block and no plaintext sender or kind. TTL is 60 s for
`connect` and 86400 s for `group-changed`. If FCM reports the token as
`UNREGISTERED` or invalid, the server deletes it.

### 6.6 Server-side log validation

The server applies §4.3 rules 1–5 (all inputs are public) plus compare-and-swap
on the head. The member set it derives is used only for authentication and wake
routing. Clients never rely on it.

When a `remove` is accepted, the server:
- sends `bye` to the removed device and closes its sockets;
- deletes its push token;
- rejects its later requests.

### 6.7 Server storage (Durable Object, SQLite)

`records(seq PK, id, bytes)`, `devices(eid PK, push_provider, push_token, last_seen)`,
`meta(head_seq, head_id, created_at)`, `replay(hash PK, expires)` for the §6.1
replay cache (it must survive hibernation, so it cannot live in memory), and the
cached FCM OAuth token (< 1 h) in the object's key-value storage. Nothing else.
Rate-limit counters are in memory and reset when the object hibernates. The application does not log
IP addresses (Cloudflare's own platform logs are outside our control; see the
threat model).

### 6.8 Errors

Responses use `{"error": code}`. Codes by HTTP status:
- 400 `bad-request`
- 401 `unauthenticated`
- 403 `not-member`, `not-allowed`
- 404 `no-group`
- 409 `head-moved`, `exists`
- 413 `too-large`
- 422 `invalid-record`
- 429 `rate-limited`
- 500 `internal`

## 7. Wake envelopes

### 7.1 Purpose

A wake envelope asks a member to connect to the sender (to receive items) or to
sync the log. It is opaque to the server and to the push provider, and it is
signed by the sender.

### 7.2 Format

```
Envelope = [ v: uint = 1, kid: bstr .size 8, ct_kem: bstr .size 1120, ct: bstr ]   ; CBOR array → b64u

(ss, ct_kem) = XWing.Encaps(kem_pk_recipient)            ; kid = kid(kem_pk_recipient)
k   = HKDF-SHA-256(salt = "", ikm = ss, info = "warpshot/wake-kdf/v1" ‖ eid_recipient ‖ kid, L = 32)
ct  = ChaCha20-Poly1305.Seal(k, nonce = 0^12, aad = u8(v) ‖ kid ‖ ct_kem, pt = CBOR(Sealed))

Sealed = [ inner: bstr, sender: bstr .size 32, sig: bstr .size 64 ]
sig    = Ed25519.Sign(IK_sender, "warpshot/wake-sig/v1\0" ‖ eid_recipient ‖ inner)

Inner (CBOR map inside `inner`):
  0: kind     uint            ; 1 connect, 2 group-changed
  1: ts       uint            ; ms
  2: nonce    bstr .size 16
  3: group_id bstr .size 16
  4: session  bstr .size 16   ; connect only
  5: dial     DialInfo        ; connect only: where to reach the sender
  6: preview  { 0: count uint, 1: total_size uint, 2: kinds [uint] }   ; connect, optional
  7: head     LogHead         ; sender's log head
```

The all-zero nonce is safe because `k` is single-use: every envelope uses a fresh
KEM encapsulation.

### 7.3 Opening (normative)

The recipient MUST, in order:
1. Select its KEM private key by `kid`. A previous key stays valid for 7 days after rotation.
2. Decapsulate, derive `k`, and open the AEAD. On failure, drop silently.
3. Decode `Sealed`. If `sender ∉ S` and `head.seq` is greater than the local
   head seq, sync the log from the server first, then re-check.
4. Verify `sig` strictly.
5. Require `group_id` to match.
6. Require `|now − ts| ≤ 120 s` for `connect`, or ≤ 24 h for `group-changed`.
7. Reject the envelope if its `nonce` was already seen in the last 10 minutes.

### 7.4 Actions

- `connect`: within 10 s, dial `sender` at `dial` with ALPN `warpshot/xfer/1`
  and present `session` (§8.3). On Android, start the foreground service first.
- `group-changed`: sync the log from the server, validate it, and raise alerts (§4.6).

## 8. Transfer protocol (ALPN `warpshot/xfer/1`)

### 8.1 Admission

After the QUIC/TLS handshake, both sides MUST check `remote_id() ∈ S`, where `S`
is the verified local state. Otherwise they close with `NOT_MEMBER`.

One exception exists. If the remote id is unknown but the dialer's `Hello.head.seq`
is greater than the listener's head, the listener MAY run a bounded in-band log
sync first (§8.5: at most 64 records, at most 256 KiB, once per connection), then
re-check membership.

### 8.2 Framing

The **control stream** is the first bidirectional stream; the dialer opens it.

```
frame = u32be(len) ‖ payload[len]          ; len ≤ 1 MiB
```

- Phase 1 (handshake): `payload` is plain CBOR inside TLS.
- Phase 2: `payload` is the AEAD ciphertext of a CBOR message (§8.4).

### 8.3 Handshake

```
D → L  Hello    { 0: v=1, 1: session bstr16 (all-zero = none), 2: ek bstr1216, 3: head LogHead, 4: caps [uint] }
L → D  HelloAck { 0: v=1, 1: ct bstr1120, 2: head LogHead, 3: caps [uint] }
```

- `ek` is a fresh X-Wing encapsulation key. L computes `(ss, ct) = XWing.Encaps(ek)`.
  D computes `ss = XWing.Decaps(dk, ct)` and zeroizes `dk`.
- `ekm = export_keying_material(len 32, label "EXPORTER-warpshot-xfer-v1", context session)`.
- `th = SHA-256("warpshot/xfer-transcript/v1\0" ‖ u32be(|Hello|) ‖ Hello ‖ u32be(|HelloAck|) ‖ HelloAck ‖ eid_D ‖ eid_L)`,
  where `Hello` and `HelloAck` are the exact frame payload bytes.
- `prk = HKDF-Extract(salt = ekm, ikm = ss)`.
- Control keys:
  - `k_ctrl_dl = HKDF-Expand(prk, "warpshot/xfer-kdf/v1 ctrl d>l" ‖ th, 32)`
  - `k_ctrl_ld = HKDF-Expand(prk, "warpshot/xfer-kdf/v1 ctrl l>d" ‖ th, 32)`
- An unsupported `v` closes with `VERSION`. If the heads differ, §8.5 runs before any `Offer`.

Security rationale (non-normative):
- **Identity:** TLS 1.3 authenticates both identities (Ed25519 raw public keys).
- **Session binding:** `ekm` binds the inner keys to that TLS session.
- **Post-quantum confidentiality:** the X-Wing secret keeps recorded traffic
  confidential even if X25519 is broken later (harvest-now-decrypt-later).
- **Limitation:** authentication is classical. Post-quantum authentication
  (hybrid ML-DSA) is future work.

### 8.4 Encrypted control messages

```
ct = ChaCha20-Poly1305.Seal(k_ctrl_<dir>, nonce = 0^4 ‖ u64be(counter_<dir>), aad = "ctrl", pt = CBOR(msg))
```

Counters start at 0 for each direction and increase by 1 per frame. Any
authentication failure closes the connection with `CRYPTO`.

| t | Message | Fields |
|---|---|---|
| 1 | `Offer` | 1: session bstr16, 2: items [Item] |
| 2 | `Accept` | 1: ids [uint] |
| 3 | `Decline` | 1: reason uint (1 user, 2 too-large, 3 busy, 4 policy) |
| 4 | `ItemDone` | 1: id uint, 2: blake3 bstr32, 3: size uint |
| 5 | `ItemAck` | 1: id uint, 2: ok bool, 3: err uint (optional) |
| 6 | `Cancel` | 1: id uint (absent = everything) |
| 7 | `Error` | 1: code uint, 2: detail tstr (optional, no content/paths) |
| 8 | `Bye` | – |
| 9 | `LogReq` | 1: after uint |
| 10 | `LogRecs` | 1: records [bstr], 2: more bool |

`Item` = `{ 0: id uint, 1: kind uint (1 text, 2 image, 3 file), 2: name tstr, 3: mime tstr, 4: size uint, 5: created_at uint, 6: text tstr }`.
Key 6 is present only for `kind = text` with `size ≤ 64 KiB`. Inline text has no data stream.

**Who sends `Offer`:** if `Hello.session` matches a pending session of the
listener, the listener sends `Offer` (it answered a wake). If the session is
all-zero, the dialer sends `Offer`.

**Flow:**
1. The sender sends `Offer`.
2. The receiver applies its policy (size limits; asks the user above 500 MB by
   default) and answers `Accept` or `Decline`.
3. The sender streams each accepted non-inline item (§8.6) and then sends
   `ItemDone` for it.
4. The receiver answers `ItemAck` after a durable write.
5. When finished, the sender sends `Bye` and the receiver closes the connection with code `0`.

### 8.5 In-band log sync

The side with the lower head seq sends `LogReq{after: own seq}`. The peer answers
with `LogRecs` in chunks of at most 64 records. The receiver validates them as a
continuation (§4.5). A fork closes with `GROUP_FORK` and raises the alert. Then
admission (§8.1) is checked again.

### 8.6 Item data streams

- The sender opens one unidirectional stream per item. The header is `u32be(id)`.
- The stream then carries `chunk = u32be(len) ‖ ciphertext` until the last chunk.
  Plaintext chunks are 64 KiB, except the last (0–64 KiB). An empty item is one
  empty last chunk.
- `dir` is the direction byte: `0x00` for d>l, `0x01` for l>d.
- `k_item = HKDF-Expand(prk, "warpshot/xfer-kdf/v1 item" ‖ u8(dir) ‖ u32be(id) ‖ th, 32)`.
- `nonce = 0^7 ‖ u32be(chunk_index) ‖ u8(last)`, where `last` is 0x00 or 0x01
  (STREAM construction). `aad = u32be(id)`. The `last` flag is not sent: a chunk
  shorter than 64 KiB (ciphertext < 65552 bytes) is opened as last; a full-size
  chunk is opened as non-last first and, if that fails, as last. A non-last chunk
  MUST carry exactly 64 KiB of plaintext.
- **Receiver procedure:**
  1. Write to a temporary file in the destination directory, updating BLAKE3 as data arrives.
  2. After the `last` chunk, require `bytes == Item.size` and `BLAKE3 == ItemDone.blake3`.
  3. Atomically rename to the sanitized, de-duplicated final name.
  4. On any mismatch, delete the file and reply `ItemAck{ok: false}`.

  A missing last chunk means truncation; a counter mismatch means reordering.
  Both are errors.

### 8.7 Timeouts

- Handshake: 10 s.
- Control stream idle: 30 s.
- A data stream that makes no progress for 30 s → `TIMEOUT`.

### 8.8 Close and error codes (QUIC application error codes)

| Code | Name | Code | Name |
|---|---|---|---|
| 0x00 | OK | 0x25 | PAIR_EXPIRED |
| 0x10 | NOT_MEMBER | 0x26 | PAIR_REJECTED |
| 0x11 | GROUP_FORK | 0x27 | PAIR_OTHER_GROUP |
| 0x12 | GROUP_MISMATCH | 0x30 | DECLINED |
| 0x20 | HANDSHAKE | 0x31 | TOO_LARGE |
| 0x21 | VERSION | 0x32 | BUSY |
| 0x22 | CRYPTO | 0x40 | DIRECT_UNAVAILABLE |
| 0x23 | PROTOCOL | 0x50 | TIMEOUT |
| 0x24 | PAIR_PROOF | 0x7F | INTERNAL |

## 9. Endpoint and connection policy

- **iroh `Endpoint` configuration:**
  - the device `SecretKey`;
  - ALPNs `warpshot/xfer/1` and `warpshot/pair/1` (pair is rejected unless a pairing window is open);
  - a relay map with **one** region, chosen in Spike A. The home relay URL is then
    known in advance and can go into wake envelopes immediately;
  - **no address lookup** (no DNS/pkarr publishing, no mDNS). Addresses travel
    only inside QR codes and wake envelopes, encrypted to group members.
- **Lifetime:** the endpoint is created on demand (send, wake, pairing, Android UI
  in the foreground). It is closed after 30 s with no connections and no pending sessions.
- **Relay data policy:** the `relay_data` setting is on by default. When it is off,
  the client waits up to 5 s after connecting for a direct path (`Connection::paths`
  / `path_events`). If none appears, it closes with `DIRECT_UNAVAILABLE` and tells
  the user why.
- **Pending sessions:** the sender keeps items ready for 120 s after sending a wake.
  If no connection arrives in that time, it tells the user the device did not respond.

## 10. Limits

| Item | Limit |
|---|---|
| CBOR nesting depth | 8 |
| Control frame | 1 MiB |
| Items per `Offer` | 1000 |
| Inline text | 64 KiB |
| Item name / MIME | 255 / 127 bytes |
| Device name | 64 bytes |
| Members per group | 16 |
| Records per log | 1024 |
| Envelope (b64u) | 3800 characters |
| WebSocket message | 64 KiB |
| Pairing window | 120 s |
| In-band sync before admission | 64 records / 256 KiB |

## 11. Versioning

Version markers are the ALPN suffix, record `v`, envelope `v`, `Hello.v`, the
server path prefix `/v1`, and the QR prefix `WARP1:`. Unknown CBOR map keys are
ignored. There is no algorithm negotiation and therefore no downgrade surface. A
breaking change gets a new version. Clients MAY support versions N and N−1 during
a migration.

## 12. Test vectors

`docs/test-vectors/*.json` are generated by the core test suite from fixed seeds
(`cargo test -p warpshot-core gen_vectors -- --ignored`). They are consumed by the core
tests and by the server tests (TypeScript), so both implementations agree byte for byte:

| File | Content |
|---|---|
| `xwing.json` | conformance vectors from the X-Wing draft |
| `record.json` | genesis/add/remove/update: bodies, ids, signatures, plus invalid cases with the rule each violates |
| `server-auth.json` | canonical strings, signatures, accept/reject cases |
| `wake.json` | seal/open with fixed randomness, tamper cases |
| `xfer-keys.json` | key schedule from fixed `ss`, `ekm` and handshake bytes |
| `pair.json` | proof and SAS |
| `cbor-reject.json` | malformed inputs that MUST be rejected |
