// Shared test vectors produced by the Rust core (protocol §12):
//   docs/test-vectors/cbor-reject.json and docs/test-vectors/record.json.
// They are imported read-only; never edit them here.
import { describe, expect, it } from "vitest";
import cborReject from "../../docs/test-vectors/cbor-reject.json";
import recordVectors from "../../docs/test-vectors/record.json";
import { b64uEncode } from "../src/b64u";
import { CborError, decodeCbor } from "../src/cbor";
import { emptyState, LogState, parseSignedRecord, RecordError, RecordRule, validateRecord } from "../src/record";
import { hex } from "../src/util";
import { device, fromHex } from "./helpers/fixtures";

describe("cbor-reject.json", () => {
  it.each(cborReject.cases.map((c) => [c.name, c.hex] as const))("rejects: %s", (_name, h) => {
    expect(() => decodeCbor(fromHex(h), { maxBytes: 1 << 20, maxDepth: 8 })).toThrow(CborError);
  });
});

/** Our rule names for the vectors' informational `error` names. */
const RULE_MAP: Record<string, RecordRule[]> = {
  GroupMismatch: ["group"],
  SeqMismatch: ["seq"],
  PrevMismatch: ["prev"],
  NotGenesisOp: ["op"],
  SignerNotMember: ["signer"],
  TimeFuture: ["time"],
  TimeRegress: ["time"],
  AddExisting: ["add"],
  SubjectKey: ["add"],
  RemoveMissing: ["remove"],
  UpdateNotSelf: ["update"],
  UpdatePlatform: ["update"],
  BadSignature: ["sig"],
  Presence: ["presence"],
  UnknownOp: ["op"],
  DeviceName: ["decode"],
  DevicePlatform: ["decode"],
  DeviceKemKey: ["decode"],
  Version: ["version"],
};

/** States after each valid record: states[k] is the state with records 0..k-1 applied. */
async function validStates(): Promise<LogState[]> {
  const states: LogState[] = [emptyState(fromHex(recordVectors.group_id))];
  for (const v of recordVectors.valid) {
    const r = parseSignedRecord(fromHex(v.record));
    const res = await validateRecord(states[states.length - 1]!, r, recordVectors.now_ms);
    expect(res.state.seq).toBe(v.seq);
    expect(hex(res.id)).toBe(v.id);
    states.push(res.state);
  }
  return states;
}

async function rejectionRule(state: LogState, recHex: string): Promise<RecordRule | null> {
  try {
    const r = parseSignedRecord(fromHex(recHex));
    await validateRecord(state, r, recordVectors.now_ms);
    return null;
  } catch (e) {
    if (e instanceof RecordError) return e.rule;
    throw e;
  }
}

describe("record.json", () => {
  it("keys derive from 32 × seed byte", async () => {
    for (const k of recordVectors.keys) {
      const d = await device(fromHex(k.secret)[0]!);
      expect(hex(d.pk)).toBe(k.endpoint_id);
    }
  });

  it("valid log validates in order; ids and final member set match", async () => {
    const states = await validStates();
    const last = states[states.length - 1]!;
    expect(last.members.size).toBe(recordVectors.members_after_valid.length);
    for (const id of recordVectors.members_after_valid) {
      expect(last.members.has(b64uEncode(fromHex(id)))).toBe(true);
    }
  });

  it.each(recordVectors.invalid.map((c) => [c.name, c] as const))("invalid: %s", async (_name, c) => {
    const states = await validStates();
    const rule = await rejectionRule(states[c.prefix]!, c.record);
    expect(rule).not.toBeNull();
    expect(RULE_MAP[c.error], `unmapped vector error ${c.error}`).toBeDefined();
    expect(RULE_MAP[c.error]).toContain(rule);
  });

  it.each(recordVectors.accept.map((c) => [c.name, c] as const))("accept: %s", async (_name, c) => {
    const states = await validStates();
    expect(await rejectionRule(states[c.prefix]!, c.record)).toBeNull();
  });
});
