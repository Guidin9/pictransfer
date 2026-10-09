// Membership log records: decoding (protocol §4.2) and validation (§4.3),
// as applied by the server (§6.6). Pure functions, no storage access.

import {
  asArray,
  asBytes,
  asMap,
  asText,
  asUint,
  Cbor,
  CborError,
  CborShapeError,
  decodeCbor,
} from "./cbor";
import { b64uEncode } from "./b64u";
import { isStrictPublicKey, verifyStrict } from "./ed25519";
import { bytesEqual, concat, LABEL_RECORD, LABEL_RECORD_ID, LIMITS, sha256, utf8 } from "./util";

export const OP_GENESIS = 0;
export const OP_ADD = 1;
export const OP_REMOVE = 2;
export const OP_UPDATE = 3;


const TEN_MIN_MS = 10 * 60 * 1000;

/** Which §4.3 rule (or decoding step) a record violated. Used in tests only, never logged with content. */
export type RecordRule =
  | "decode" // §4.2 / §1 decoding and field types
  | "version" // rule 1: v == 1
  | "group" // rule 1: group_id
  | "seq" // rule 1: seq == n
  | "genesis" // rule 2, n == 0
  | "prev" // rule 2, n > 0: prev == H
  | "op" // rule 1: op ≤ 3; rule 2, n > 0: op ∈ {add, remove, update}
  | "presence" // rule 1: device / reason presence by op
  | "signer" // rule 2, n > 0: signer ∈ S
  | "time" // rule 3
  | "add" // rule 4
  | "remove" // rule 4
  | "update" // rule 4
  | "dead" // state empty: no further record valid
  | "limit" // §10: members / records
  | "sig"; // rule 5

export class RecordError extends Error {
  constructor(readonly rule: RecordRule) {
    super(`record: ${rule}`);
  }
}

export interface DeviceInfo {
  name: string;
  platform: number;
  kemPk: Uint8Array;
  app?: string;
}

export interface RecordBody {
  v: number;
  groupId: Uint8Array;
  seq: number;
  prev?: Uint8Array;
  createdAt: number;
  op: number;
  subject: Uint8Array;
  device?: DeviceInfo;
  reason?: number;
}

export interface ParsedRecord {
  /** Exact SignedRecord encoding as received (stored and served verbatim). */
  bytes: Uint8Array;
  /** Exact signed body bytes. Never re-encoded (§1). */
  body: Uint8Array;
  signer: Uint8Array;
  sig: Uint8Array;
  fields: RecordBody;
}

export interface LogState {
  groupId: Uint8Array;
  /** Head seq, -1 for an empty log. */
  seq: number;
  headId: Uint8Array | null;
  lastCreatedAt: number;
  /** b64u(EndpointId) → DeviceInfo */
  members: Map<string, DeviceInfo>;
}

export function emptyState(groupId: Uint8Array): LogState {
  return { groupId, seq: -1, headId: null, lastCreatedAt: 0, members: new Map() };
}

// C0, DEL and C1 control characters (Unicode Cc).
const CONTROL_RE = /[\u0000-\u001f\u007f-\u009f]/;
// SPEC-GAP: §3 forbids "control characters" in device names. Bidi
// formatting characters (Cf) are not control characters, but they can spoof
// the "New device added: {name}" alert (§4.6). Stricter reading: rejected.
const BIDI_RE = /[؜‎‏‪-‮⁦-⁩]/;

function decodeDeviceInfo(c: Cbor | undefined): DeviceInfo {
  const m = asMap(c, "device");
  const name = asText(m.get(0), "device.name");
  const nameLen = utf8(name).length;
  if (nameLen < 1 || nameLen > LIMITS.deviceName) throw new CborShapeError("device.name");
  if (CONTROL_RE.test(name) || BIDI_RE.test(name)) throw new CborShapeError("device.name");
  // §3: 0 is invalid; values other than 1/2 are reserved for new platforms
  // and MUST be accepted.
  const platform = asUint(m.get(1), "device.platform");
  if (platform === 0) throw new CborShapeError("device.platform");
  const kemPk = asBytes(m.get(2), "device.kem_pk", LIMITS.kemPk);
  // `app` is optional and informational (§3), ≤ 32 bytes when present.
  let app: string | undefined;
  if (m.has(3)) {
    app = asText(m.get(3), "device.app");
    if (utf8(app).length > LIMITS.appVersion) throw new CborShapeError("device.app");
  }
  // Unknown DeviceInfo keys are ignored (§3).
  return { name, platform, kemPk, app };
}

/** Decodes a SignedRecord and its body (§4.2). Throws RecordError("decode"). */
export function parseSignedRecord(bytes: Uint8Array): ParsedRecord {
  try {
    const outer = asArray(
      decodeCbor(bytes, { maxBytes: LIMITS.recordBytes }),
      "record",
      3, // SPEC-GAP: arrays have no forward-compatibility rule; exactly 3 elements.
    );
    const body = asBytes(outer[0], "body");
    const signer = asBytes(outer[1], "signer", 32);
    const sig = asBytes(outer[2], "sig", 64);
    const m = asMap(decodeCbor(body, { maxBytes: LIMITS.recordBytes }), "body");
    const fields: RecordBody = {
      v: asUint(m.get(0), "v"),
      groupId: asBytes(m.get(1), "group_id", 16),
      seq: asUint(m.get(2), "seq"),
      createdAt: asUint(m.get(4), "created_at"),
      op: asUint(m.get(5), "op"),
      subject: asBytes(m.get(6), "subject", 32),
    };
    if (m.has(3)) fields.prev = asBytes(m.get(3), "prev", 32);
    if (m.has(7)) fields.device = decodeDeviceInfo(m.get(7));
    if (m.has(8)) fields.reason = asUint(m.get(8), "reason");
    // Keys > 8 are unknown and ignored (§1).
    return { bytes, body, signer, sig, fields };
  } catch (e) {
    if (e instanceof CborError || e instanceof CborShapeError) throw new RecordError("decode");
    throw e;
  }
}

export async function recordId(r: ParsedRecord): Promise<Uint8Array> {
  return sha256(concat(utf8(LABEL_RECORD_ID), r.body, r.signer, r.sig));
}

/** Compare-and-swap precondition (§4.4, §6.6): the record must build on the current head. */
export function buildsOnHead(state: LogState, r: ParsedRecord): boolean {
  const n = state.seq + 1;
  if (r.fields.seq !== n) return false;
  if (n === 0) return r.fields.prev === undefined;
  return r.fields.prev !== undefined && state.headId !== null && bytesEqual(r.fields.prev, state.headId);
}

/**
 * Validates `r` as the record at position `state.seq + 1` (§4.3 rules 1–5)
 * and returns the new state. Does not mutate `state`. Throws RecordError.
 */
export async function validateRecord(
  state: LogState,
  r: ParsedRecord,
  now: number,
): Promise<{ state: LogState; id: Uint8Array }> {
  const f = r.fields;
  const n = state.seq + 1;
  const signerKey = b64uEncode(r.signer);
  const subjectKey = b64uEncode(f.subject);

  // Rule 1.
  if (f.v !== 1) throw new RecordError("version");
  if (!bytesEqual(f.groupId, state.groupId)) throw new RecordError("group");
  if (f.seq !== n) throw new RecordError("seq");
  if (n >= LIMITS.records) throw new RecordError("limit");
  if (f.op > OP_UPDATE) throw new RecordError("op");
  // Field presence by op (§4.3 rule 1): device present for genesis/add/update
  // and absent for remove; reason present (0–3) for remove, absent otherwise.
  if (f.op === OP_REMOVE) {
    if (f.device !== undefined || f.reason === undefined || f.reason > 3) throw new RecordError("presence");
  } else if (f.device === undefined || f.reason !== undefined) {
    throw new RecordError("presence");
  }

  // Rule 2.
  if (n === 0) {
    if (f.op !== OP_GENESIS || f.prev !== undefined || !bytesEqual(r.signer, f.subject) || f.device === undefined) {
      throw new RecordError("genesis");
    }
  } else {
    if (state.members.size === 0) throw new RecordError("dead");
    if (f.prev === undefined || state.headId === null || !bytesEqual(f.prev, state.headId)) {
      throw new RecordError("prev");
    }
    if (f.op !== OP_ADD && f.op !== OP_REMOVE && f.op !== OP_UPDATE) throw new RecordError("op");
    if (!state.members.has(signerKey)) throw new RecordError("signer");
  }

  // Rule 3.
  if (f.createdAt > now + TEN_MIN_MS) throw new RecordError("time");
  if (n > 0 && f.createdAt < state.lastCreatedAt - TEN_MIN_MS) throw new RecordError("time");

  // Rule 4.
  const members = new Map(state.members);
  switch (f.op) {
    case OP_GENESIS:
      members.set(subjectKey, f.device!);
      break;
    case OP_ADD:
      if (members.has(subjectKey) || f.device === undefined) throw new RecordError("add");
      // SPEC-GAP: §4.3 does not require `subject` to be a valid key. A
      // member key that can never verify is useless; stricter reading:
      // the subject of add must be a strict Ed25519 public key.
      if (!isStrictPublicKey(f.subject)) throw new RecordError("add");
      if (members.size + 1 > LIMITS.members) throw new RecordError("limit");
      members.set(subjectKey, f.device);
      break;
    case OP_REMOVE:
      if (!members.has(subjectKey)) throw new RecordError("remove");
      members.delete(subjectKey);
      break;
    case OP_UPDATE: {
      if (!bytesEqual(r.signer, f.subject) || f.device === undefined) throw new RecordError("update");
      const old = members.get(subjectKey);
      if (old === undefined || old.platform !== f.device.platform) throw new RecordError("update");
      members.set(subjectKey, f.device);
      break;
    }
  }

  // Rule 5.
  const signed = concat(utf8(LABEL_RECORD), r.body);
  if (!(await verifyStrict(r.signer, signed, r.sig))) throw new RecordError("sig");

  const id = await recordId(r);
  return {
    id,
    state: { groupId: state.groupId, seq: n, headId: id, lastCreatedAt: f.createdAt, members },
  };
}

/**
 * Applies an already-validated, stored record to the state without
 * re-verifying (used to rebuild the in-memory state from storage).
 */
export function applyTrusted(state: LogState, r: ParsedRecord, id: Uint8Array): LogState {
  const f = r.fields;
  const members = new Map(state.members);
  const key = b64uEncode(f.subject);
  if (f.op === OP_REMOVE) members.delete(key);
  else if (f.device !== undefined) members.set(key, f.device);
  return { groupId: state.groupId, seq: f.seq, headId: id, lastCreatedAt: f.createdAt, members };
}
