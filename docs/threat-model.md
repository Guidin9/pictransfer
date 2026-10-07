# Threat model — v1

Status: DRAFT (Faz 0). Every security-relevant change must keep this document
true. If a change weakens a mitigation, update this file in the same PR and say so.

## 1. Assets

| # | Asset |
|---|---|
| A1 | Content in transit: images, text, files, and their names and sizes |
| A2 | Device keys: identity `IK` (impersonation) and KEM `KK` (decrypting wakes) |
| A3 | Integrity of group membership: who may send to and receive from the user's devices |
| A4 | Metadata: which devices talk to each other, when, how much, from which IP; online times |
| A5 | Local data at rest: history, received files, settings |
| A6 | Availability of transfers |
| A7 | Integrity of the user's PC and phone: received data or local interfaces must not become an attack vector |

## 2. Trust assumptions

- **Trusted:** the user's member devices and their operating systems, until a device is removed.
- **Untrusted:** the network (LAN, Wi-Fi, ISP), the Cloudflare Worker and Durable
  Object (including Cloudflare itself and anyone who takes over the account), the
  iroh relays (n0 public or self-hosted), Google FCM, DNS, and the update channel
  (until signature verification).
- **Out of scope:** code running as the same OS user on a member device. It can
  already read the clipboard, files and keystore-wrapped keys while the user is
  logged in.

## 3. Adversaries and mitigations

| # | Adversary | Can | Cannot (mitigation) | Residual |
|---|---|---|---|---|
| T1 | Passive network observer (Wi-Fi, ISP, backbone) | See IPs, ports, timing and encrypted sizes | Read content: QUIC/TLS 1.3, plus the inner X-Wing layer against future quantum decryption of recorded traffic (§8.3 protocol) | Traffic analysis: sizes and timing are not padded in v1 |
| T2 | Active network attacker (MITM, ARP/DNS spoofing, rogue AP) | Block, delay or reset traffic | Impersonate a device: TLS raw-public-key auth against the expected `EndpointId` from the signed log, QR or envelope. No TOFU anywhere | DoS |
| T3 | Malicious or compromised server operator | Drop or delay wakes and appends; lie about presence; equivocate the log (show different heads to different devices); see the metadata in §4 | Read content (never receives it); forge membership (records are member-signed and validated by clients); forge or read wakes (signed by the sender, encrypted to the recipient); add devices | DoS. Equivocation is **detected**, not prevented: head comparison in every transfer handshake raises a fork alert (protocol §4.5). Metadata exposure (§4) |
| T4 | Relay operator (n0 or self-hosted) | See relayed encrypted QUIC packets, EndpointIds, IPs; drop traffic | Decrypt or modify (end-to-end QUIC) | DoS. The user can disable relaying of data (`relay_data = off`) |
| T5 | Push provider (Google FCM) | See push timing, target token, encrypted payload size, Firebase project | Read wakes or the sender identity (payload is an encrypted envelope, `data` has only `v` and `e`); forge wakes | Timing metadata |
| T6 | Thief of a member device | Use an unlocked device. With a locked device, only offline attacks on the OS keystore | Use keys without breaking the OS keystore (keys are wrapped by DPAPI/TPM or Android Keystore/StrongBox); stay in the group after removal (any member removes it; the server drops its sessions; peers refuse it) | Until the user removes it, an unlocked stolen device can receive new sends. Content already on the device is protected only by the OS |
| T7 | Attacker controlling a member device (malware with its keys) | Receive what is sent to it; send to members; append records (e.g., add a sybil device); together with a malicious server, show other devices a fork | Add devices silently (every `add` alerts all members with "This wasn't me", protocol §4.6); rewrite history (hash chain); act after removal (not a member at later `seq`) | Until noticed and removed. If several devices are compromised: re-pair everything (new group) |
| T8 | Pairing attacker (photographs the QR; shows a malicious QR) | Try to pair within the 120 s window | Pair without the user noticing: single-use secret, 120 s expiry, explicit confirmation on **both** devices with SAS and name, and a new-device alert on all members. A malicious QR cannot silently join or add devices, because the scanner also confirms | Social engineering of a careless user |
| T9 | Local attacker on the PC: other OS users, other sessions, websites | Use the local interfaces of the Windows agent | Reach the IPC: named pipe ACL limited to the user SID and `PIPE_REJECT_REMOTE_CLIENTS`; no local HTTP server. Trigger actions from the web: toast activation uses COM, there is no URL protocol handler. Inject code into the UI: the Tauri UI loads only bundled assets, strict CSP, no remote content | Same-user code (out of scope) |
| T10 | Malicious content from a member (e.g., a compromised member) | Send arbitrary bytes and names | Path traversal (names are sanitized: separators, `..`, reserved DOS names, trailing dots/spaces, control and bidi characters removed); auto-execution (received files are never opened automatically; Windows Mark-of-the-Web `ZoneId=3` enables SmartScreen and Office Protected View); size abuse (limits, prompt above 500 MB) | Image previews use OS decoders (toast, Android); their bugs are an OS issue |
| T11 | Supply chain (dependency, CI, release channel) | Get malicious code into a release | Without passing our controls: pinned dependency versions and a lockfile, `cargo-deny`/`cargo-audit`, a minimal dependency set, `npm ci --ignore-scripts` where possible, GitHub Actions pinned by SHA with least-privilege tokens, signed releases and updates (minisign) with artifact attestations; reproducible builds and an external audit in Faz 3 | Compromise of a pinned upstream release |
| T12 | Future quantum adversary | Record traffic today and break X25519 later | Decrypt recorded content (the X-Wing inner layer needs ML-KEM-768 broken as well) | Authentication is classical (Ed25519). A live quantum MITM is not defended against in v1 (hybrid ML-DSA is planned) |
| T13 | Downgrade attacker | Tamper with version fields | Downgrade: there is no algorithm negotiation; versions are fixed per ALPN and record, and unknown versions are refused | — |
| T14 | Replay attacker | Replay captured messages | Get them accepted: envelopes have `ts` ±120 s and a 10-minute nonce cache; server auth has a `ts` window and replay cache; records are bound by `seq`/`prev`; the pairing secret is single-use | — |
| T15 | Spammer / DoS from outside the group | Hit the server API | Wake devices or transfer: only members authenticate; per-device rate limits; FCM TTL | Server-level DoS (Cloudflare absorbs most) |

## 4. Metadata exposure

| Observer | Learns |
|---|---|
| LAN / ISP | IPs, ports, timing, encrypted sizes |
| Cloudflare (server) | Client IPs; `group_id`; member EndpointIds, device **names** and platforms (records are public to the server); online times of WebSocket-connected devices; time and target of each wake (not its content or kind); FCM tokens |
| n0 relays | IPs, EndpointIds, timing and sizes of relayed packets |
| Google FCM | Push time, target token, encrypted payload size, the Firebase project |
| Other group members | Everything about the group — they are the user's own devices |

Minimization in v1: no accounts, emails or phone numbers; no public discovery
(pkarr/DNS disabled); addresses only inside encrypted envelopes; presence only on
request; `last_seen` with 60 s granularity; default device names are generic
("Windows PC", "Android phone") and the user may rename them.

## 5. Accepted residual risks

1. Traffic analysis (sizes and timing). Padding small items to fixed buckets is a candidate for Faz 2.
2. DoS by the server, relay or push provider. The design detects equivocation; it does not prevent DoS.
3. Device names and the group structure are visible to the server.
4. Classical authentication: no post-quantum signatures yet.
5. Same-user malware on a member device.
6. Availability depends on free tiers (Cloudflare, n0 relays, FCM).

## 6. Security verification

- Every validation rule in the protocol has positive **and** negative tests. Test
  vectors are shared by the Rust and TypeScript implementations.
- All decoders are fuzzed with `cargo-fuzz`: CBOR, frames, envelopes, QR payload, records.
- Log validation has property tests: random append/remove sequences, forks, re-adds.
- A manual checklist runs before each release:
  - [ ] An unknown EndpointId is rejected on the transfer ALPN.
  - [ ] A record signed by a removed device is rejected.
  - [ ] A fork is detected and blocks transfers.
  - [ ] Received files carry `Zone.Identifier`; `..\`, `CON`, and RTL-override names are sanitized.
  - [ ] The named pipe refuses another local user.
  - [ ] The toast activator acts only on known history ids.
  - [ ] No content, names or keys appear in logs (grep the logs after an E2E run).
  - [ ] `relay_data = off` never sends data through a relay.
