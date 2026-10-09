// §4.2/§4.3 record validation with local fixtures: every rule has a negative
// test (the shared record.json vectors are in vectors.test.ts).
import { describe, expect, it } from "vitest";
import { b64uEncode } from "../src/b64u";
import {
  DeviceInfo,
  emptyState,
  LogState,
  parseSignedRecord,
  RecordError,
  RecordRule,
  validateRecord,
} from "../src/record";
import { concat } from "../src/util";
import {
  addBody,
  BodyIn,
  cbor,
  device,
  deviceInfo,
  Device,
  fromHex,
  genesisBody,
  kemPk,
  newGroupId,
  removeBody,
  signRecord,
  updateBody,
} from "./helpers/fixtures";

const NOW = 1_790_000_000_000;
const MIN10 = 10 * 60 * 1000;

async function apply(state: LogState, body: BodyIn | Uint8Array, signer: Device, now = NOW) {
  const rec = await signRecord(body, signer);
  return validateRecord(state, parseSignedRecord(rec.bytes), now);
}

async function ruleOf(p: Promise<unknown>): Promise<RecordRule | null> {
  try {
    await p;
    return null;
  } catch (e) {
    if (e instanceof RecordError) return e.rule;
    throw e;
  }
}

async function ruleOfBytes(state: LogState, bytes: Uint8Array): Promise<RecordRule | null> {
  return ruleOf((async () => validateRecord(state, parseSignedRecord(bytes), NOW))());
}

/** Genesis by A, then A adds B. */
async function base() {
  const [A, B, C] = await Promise.all([device(1), device(2), device(3)]);
  const gid = newGroupId();
  const g = await apply(emptyState(gid), { ...genesisBody(gid, A, NOW) }, A);
  const s1 = await apply(g.state, { ...addBody(gid, 1, g.id, B), 4: NOW }, A);
  return { A, B, C, gid, s0: emptyState(gid), g, s1 };
}

function body(gid: Uint8Array, seq: number, prev: Uint8Array | undefined, op: number, subject: Device, extra: BodyIn = {}): BodyIn {
  return { 0: 1, 1: gid, 2: seq, 3: prev, 4: NOW, 5: op, 6: subject.pk, ...extra };
}

describe("record decoding (§4.2, rule 1)", () => {
  it("rejects garbage and malformed SignedRecord arrays", async () => {
    const { A } = await base();
    expect(() => parseSignedRecord(fromHex("00"))).toThrow(RecordError);
    expect(() => parseSignedRecord(cbor([new Uint8Array(1), A.pk]))).toThrow(RecordError);
    expect(() => parseSignedRecord(cbor([new Uint8Array(1), A.pk, new Uint8Array(64), 0]))).toThrow(RecordError);
    expect(() => parseSignedRecord(cbor([new Uint8Array(1), A.pk.subarray(1), new Uint8Array(64)]))).toThrow(RecordError);
    expect(() => parseSignedRecord(cbor([new Uint8Array(1), A.pk, new Uint8Array(63)]))).toThrow(RecordError);
    expect(() => parseSignedRecord(cbor(["text", A.pk, new Uint8Array(64)]))).toThrow(RecordError);
  });

  it("rejects a body that is not a map or misses required fields", async () => {
    const { A, gid } = await base();
    const good = genesisBody(gid, A, NOW);
    const bad: BodyIn[] = [
      { ...good, 0: undefined },
      { ...good, 1: undefined },
      { ...good, 1: gid.subarray(1) },
      { ...good, 2: "0" },
      { ...good, 4: undefined },
      { ...good, 5: undefined },
      { ...good, 6: A.pk.subarray(1) },
      { ...good, 3: new Uint8Array(31) },
      { ...good, 7: [1, 2] },
    ];
    for (const b of bad) {
      const rec = await signRecord(b, A);
      expect(() => parseSignedRecord(rec.bytes)).toThrow(RecordError);
    }
    const notMap = await signRecord(cbor([1, 2, 3]), A);
    expect(() => parseSignedRecord(notMap.bytes)).toThrow(RecordError);
  });

  it("rejects a non-canonical body even with a valid signature (no re-encoding)", async () => {
    const { A, gid } = await base();
    const canonical = cbor(genesisBody(gid, A, NOW));
    // Replace `2: 0` (seq) with a non-shortest encoding `2: 0x1800`.
    // a6 00 01 01 50 <16-byte group_id> | 02 00 ...
    const idx = 21;
    expect([canonical[idx], canonical[idx + 1]]).toEqual([0x02, 0x00]);
    const nonCanonical = concat(canonical.subarray(0, idx + 1), new Uint8Array([0x18, 0x00]), canonical.subarray(idx + 2));
    const rec = await signRecord(nonCanonical, A);
    expect(() => parseSignedRecord(rec.bytes)).toThrow(RecordError);
  });

  it("rejects a SignedRecord above 4 KiB", async () => {
    const { A, gid } = await base();
    const big = await signRecord({ ...genesisBody(gid, A, NOW), 100: new Uint8Array(4096) }, A);
    expect(() => parseSignedRecord(big.bytes)).toThrow(RecordError);
  });

  it("ignores unknown body keys and unknown DeviceInfo keys", async () => {
    const { A, gid, s0 } = await base();
    const dev = { ...deviceInfo("A"), 9: "future" };
    expect(await ruleOf(apply(s0, { ...genesisBody(gid, A, NOW), 7: dev, 42: [1, 2] }, A))).toBeNull();
  });

  describe("DeviceInfo (§3)", () => {
    const cases: Array<[string, (d: Record<number, unknown>) => void, boolean]> = [
      ["name empty", (d) => (d[0] = ""), false],
      ["name 64 bytes", (d) => (d[0] = "x".repeat(64)), true],
      ["name 65 bytes", (d) => (d[0] = "x".repeat(65)), false],
      ["name 64 bytes of multibyte UTF-8 + 1", (d) => (d[0] = "é".repeat(32) + "x"), false],
      ["name with NUL", (d) => (d[0] = "a\u0000b"), false],
      ["name with newline", (d) => (d[0] = "a\nb"), false],
      ["name with DEL", (d) => (d[0] = "a\u007fb"), false],
      ["name with C1 control", (d) => (d[0] = "a\u0085b"), false],
      ["name with RLO bidi override (SPEC-GAP)", (d) => (d[0] = "a‮b"), false],
      ["name missing", (d) => delete d[0], false],
      ["name not text", (d) => (d[0] = new Uint8Array(3)), false],
      ["platform 0", (d) => (d[1] = 0), false],
      ["platform 2", (d) => (d[1] = 2), true],
      ["platform 77 (reserved, accepted)", (d) => (d[1] = 77), true],
      ["platform missing", (d) => delete d[1], false],
      ["kem_pk 1215 bytes", (d) => (d[2] = kemPk(1, 1215)), false],
      ["kem_pk 1217 bytes", (d) => (d[2] = kemPk(1, 1217)), false],
      ["kem_pk missing", (d) => delete d[2], false],
      ["app 32 bytes", (d) => (d[3] = "v".repeat(32)), true],
      ["app 33 bytes", (d) => (d[3] = "v".repeat(33)), false],
      ["app missing (optional)", (d) => delete d[3], true],
      ["app not text", (d) => (d[3] = 1), false],
    ];
    it.each(cases)("%s", async (_n, mutate, ok) => {
      const { A, gid, s0 } = await base();
      const d = deviceInfo("A") as Record<number, unknown>;
      mutate(d);
      const rule = await ruleOf(apply(s0, { ...genesisBody(gid, A, NOW), 7: d as BodyIn }, A));
      expect(rule).toBe(ok ? null : "decode");
    });
  });
});

describe("§4.3 rules", () => {
  it("valid genesis, add, update, remove; re-add of a removed key is allowed", async () => {
    const { A, B, gid, s1 } = await base();
    const s2 = await apply(s1.state, { ...updateBody(gid, 2, s1.id, B, "B2", 2), 4: NOW }, B);
    expect((s2.state.members.get(B.id) as DeviceInfo).name).toBe("B2");
    const s3 = await apply(s2.state, { ...removeBody(gid, 3, s2.id, B, 1), 4: NOW }, A);
    expect(s3.state.members.has(B.id)).toBe(false);
    const s4 = await apply(s3.state, { ...addBody(gid, 4, s3.id, B), 4: NOW }, A);
    expect(s4.state.members.has(B.id)).toBe(true);
    expect(s4.state.seq).toBe(4);
  });

  it("rule 1: v != 1", async () => {
    const { A, gid, s0 } = await base();
    expect(await ruleOf(apply(s0, { ...genesisBody(gid, A, NOW), 0: 2 }, A))).toBe("version");
  });
  it("rule 1: wrong group_id", async () => {
    const { A, s0 } = await base();
    expect(await ruleOf(apply(s0, genesisBody(newGroupId(), A, NOW), A))).toBe("group");
  });
  it("rule 1: seq != n", async () => {
    const { A, B, C, gid, s1 } = await base();
    expect(await ruleOf(apply(s1.state, body(gid, 3, s1.id, 1, C, { 7: deviceInfo("C") }), A))).toBe("seq");
    expect(await ruleOf(apply(s1.state, body(gid, 1, s1.id, 1, C, { 7: deviceInfo("C") }), A))).toBe("seq");
    void B;
  });
  it("rule 1: op > 3", async () => {
    const { A, C, gid, s1 } = await base();
    expect(await ruleOf(apply(s1.state, body(gid, 2, s1.id, 4, C, { 7: deviceInfo("C") }), A))).toBe("op");
  });
  it("rule 1: presence — add without device, remove with device, remove without reason, reason 4, add with reason", async () => {
    const { A, B, C, gid, s1 } = await base();
    const s = s1.state;
    expect(await ruleOf(apply(s, body(gid, 2, s1.id, 1, C), A))).toBe("presence");
    expect(await ruleOf(apply(s, body(gid, 2, s1.id, 2, B, { 7: deviceInfo("B"), 8: 0 }), A))).toBe("presence");
    expect(await ruleOf(apply(s, body(gid, 2, s1.id, 2, B), A))).toBe("presence");
    expect(await ruleOf(apply(s, body(gid, 2, s1.id, 2, B, { 8: 4 }), A))).toBe("presence");
    expect(await ruleOf(apply(s, body(gid, 2, s1.id, 1, C, { 7: deviceInfo("C"), 8: 0 }), A))).toBe("presence");
    expect(await ruleOf(apply(s, body(gid, 2, s1.id, 3, B, { 8: 0 }), B))).toBe("presence");
  });
  it("rule 1: genesis without device", async () => {
    const { A, gid, s0 } = await base();
    expect(await ruleOf(apply(s0, { ...genesisBody(gid, A, NOW), 7: undefined }, A))).toBe("presence");
  });

  it("rule 2 (n = 0): op must be genesis, prev absent, signer == subject", async () => {
    const { A, B, gid, s0 } = await base();
    expect(await ruleOf(apply(s0, { ...genesisBody(gid, A, NOW), 5: 1 }, A))).toBe("genesis");
    expect(await ruleOf(apply(s0, { ...genesisBody(gid, A, NOW), 3: new Uint8Array(32) }, A))).toBe("genesis");
    expect(await ruleOf(apply(s0, genesisBody(gid, B, NOW), A))).toBe("genesis");
  });
  it("rule 2 (n > 0): prev must equal the head", async () => {
    const { A, C, gid, s1 } = await base();
    expect(await ruleOf(apply(s1.state, body(gid, 2, new Uint8Array(32), 1, C, { 7: deviceInfo("C") }), A))).toBe("prev");
    expect(await ruleOf(apply(s1.state, body(gid, 2, undefined, 1, C, { 7: deviceInfo("C") }), A))).toBe("prev");
  });
  it("rule 2 (n > 0): genesis op is not allowed", async () => {
    const { A, C, gid, s1 } = await base();
    expect(await ruleOf(apply(s1.state, body(gid, 2, s1.id, 0, C, { 7: deviceInfo("C") }), A))).toBe("op");
  });
  it("rule 2 (n > 0): signer must be a member", async () => {
    const { C, gid, s1 } = await base();
    const D = await device(4);
    expect(await ruleOf(apply(s1.state, body(gid, 2, s1.id, 1, D, { 7: deviceInfo("D") }), C))).toBe("signer");
  });

  it("rule 3: created_at ≤ now + 10 min (boundary accepted)", async () => {
    const { A, gid, s0 } = await base();
    expect(await ruleOf(apply(s0, genesisBody(gid, A, NOW + MIN10 + 1), A))).toBe("time");
    expect(await ruleOf(apply(s0, genesisBody(gid, A, NOW + MIN10), A))).toBeNull();
  });
  it("rule 3: created_at ≥ previous − 10 min (boundary accepted)", async () => {
    const { A, C, gid, s1 } = await base();
    expect(await ruleOf(apply(s1.state, body(gid, 2, s1.id, 1, C, { 4: NOW - MIN10 - 1, 7: deviceInfo("C") }), A))).toBe("time");
    expect(await ruleOf(apply(s1.state, body(gid, 2, s1.id, 1, C, { 4: NOW - MIN10, 7: deviceInfo("C") }), A))).toBeNull();
  });

  it("rule 4 add: subject already a member", async () => {
    const { A, B, gid, s1 } = await base();
    expect(await ruleOf(apply(s1.state, body(gid, 2, s1.id, 1, B, { 7: deviceInfo("B") }), A))).toBe("add");
  });
  it("rule 4 add: small-order subject key (SPEC-GAP)", async () => {
    const { A, gid, s1 } = await base();
    const weak = { pk: fromHex("0100000000000000000000000000000000000000000000000000000000000000") } as Device;
    expect(await ruleOf(apply(s1.state, body(gid, 2, s1.id, 1, weak, { 7: deviceInfo("W") }), A))).toBe("add");
  });
  it("rule 4 remove: subject not a member", async () => {
    const { A, C, gid, s1 } = await base();
    expect(await ruleOf(apply(s1.state, body(gid, 2, s1.id, 2, C, { 8: 0 }), A))).toBe("remove");
  });
  it("rule 4 remove: a member may remove itself", async () => {
    const { B, gid, s1 } = await base();
    expect(await ruleOf(apply(s1.state, body(gid, 2, s1.id, 2, B, { 8: 2 }), B))).toBeNull();
  });
  it("rule 4 update: signer must be the subject; platform unchanged", async () => {
    const { A, B, gid, s1 } = await base();
    expect(await ruleOf(apply(s1.state, body(gid, 2, s1.id, 3, B, { 7: deviceInfo("B", 2) }), A))).toBe("update");
    expect(await ruleOf(apply(s1.state, body(gid, 2, s1.id, 3, B, { 7: deviceInfo("B", 1) }), B))).toBe("update");
  });

  it("rule 5: bad signature, signature by another key, signer field swapped", async () => {
    const { A, B, gid, s0 } = await base();
    const g = await signRecord(genesisBody(gid, A, NOW), A);
    const flipped = g.bytes.slice();
    flipped[flipped.length - 1]! ^= 1;
    expect(await ruleOfBytes(s0, flipped)).toBe("sig");
    const byB = await signRecord(genesisBody(gid, A, NOW), B, { signerOverride: A.pk });
    expect(await ruleOfBytes(s0, byB.bytes)).toBe("sig");
    const zeroSig = await signRecord(genesisBody(gid, A, NOW), A, { sigOverride: new Uint8Array(64) });
    expect(await ruleOfBytes(s0, zeroSig.bytes)).toBe("sig");
  });

  it("a removed member cannot sign", async () => {
    const { A, B, C, gid, s1 } = await base();
    const s2 = await apply(s1.state, body(gid, 2, s1.id, 2, B, { 8: 0 }), A);
    expect(await ruleOf(apply(s2.state, body(gid, 3, s2.id, 1, C, { 7: deviceInfo("C") }), B))).toBe("signer");
  });

  it("dead group: no record is valid after the last member leaves", async () => {
    const { A, C, gid, s0 } = await base();
    const g = await apply(s0, genesisBody(gid, A, NOW), A);
    const s1 = await apply(g.state, body(gid, 1, g.id, 2, A, { 8: 2 }), A);
    expect(s1.state.members.size).toBe(0);
    expect(await ruleOf(apply(s1.state, body(gid, 2, s1.id, 1, C, { 7: deviceInfo("C") }), A))).toBe("dead");
  });

  it("limit: an add that would make a 17th member is invalid", async () => {
    const { A, gid, s0 } = await base();
    let st = (await apply(s0, genesisBody(gid, A, NOW), A)).state;
    for (let i = 0; i < 15; i++) {
      const d = await device(10 + i);
      st = (await apply(st, body(gid, st.seq + 1, st.headId!, 1, d, { 7: deviceInfo(d.label) }), A)).state;
    }
    expect(st.members.size).toBe(16);
    const extra = await device(40);
    expect(await ruleOf(apply(st, body(gid, st.seq + 1, st.headId!, 1, extra, { 7: deviceInfo("x") }), A))).toBe("limit");
  });

  it("limit: at most 1024 records (seq 1023 ok, seq 1024 rejected)", async () => {
    const { A, B, C, gid } = await base();
    const members = new Map<string, DeviceInfo>([[A.id, { name: "A", platform: 1, kemPk: kemPk(1) }]]);
    const at = (seq: number): LogState => ({ groupId: gid, seq, headId: new Uint8Array(32).fill(9), lastCreatedAt: NOW, members });
    const prev = new Uint8Array(32).fill(9);
    expect(await ruleOf(apply(at(1022), body(gid, 1023, prev, 1, B, { 7: deviceInfo("B") }), A))).toBeNull();
    expect(await ruleOf(apply(at(1023), body(gid, 1024, prev, 1, C, { 7: deviceInfo("C") }), A))).toBe("limit");
  });

  it("member keys are b64u EndpointIds", async () => {
    const { A, B, s1 } = await base();
    expect([...s1.state.members.keys()].sort()).toEqual([b64uEncode(A.pk), b64uEncode(B.pk)].sort());
  });
});
