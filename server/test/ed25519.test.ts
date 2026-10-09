// Strict Ed25519 (protocol §2.1, verify_strict semantics) and strict b64u.
import { describe, expect, it } from "vitest";
import { b64uDecode, b64uDecodeExact, b64uEncode } from "../src/b64u";
import { decodePointStrict, isStrictPublicKey, strictPrecheck, verifyStrict } from "../src/ed25519";
import { concat, utf8 } from "../src/util";
import { device, fromHex } from "./helpers/fixtures";

const L = (1n << 252n) + 27742317777372353535851937790883648493n;
const P = (1n << 255n) - 19n;

function le(n: bigint, len = 32): Uint8Array {
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}
function leToBig(b: Uint8Array): bigint {
  let n = 0n;
  for (let i = b.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(b[i]!);
  return n;
}

// The 8 small-order points (canonical encodings) and sign-flipped variants.
const SMALL_ORDER = [
  "0100000000000000000000000000000000000000000000000000000000000000", // identity (order 1)
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // y = -1 (order 2)
  "0000000000000000000000000000000000000000000000000000000000000000", // y = 0 (order 4)
  "0000000000000000000000000000000000000000000000000000000000000080", // y = 0, other x (order 4)
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", // order 8
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa", // order 8
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", // order 8
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85", // order 8
];

describe("ed25519 strict verification", () => {
  it("accepts a valid signature and rejects a wrong message", async () => {
    const d = await device(1);
    const msg = utf8("hello");
    const sig = await d.sign(msg);
    expect(await verifyStrict(d.pk, msg, sig)).toBe(true);
    expect(await verifyStrict(d.pk, utf8("hellO"), sig)).toBe(false);
  });

  it("deterministic keys from fixed seeds", async () => {
    // RFC 8032 test 1 uses another seed; here we only pin that the seed→key mapping is stable.
    const a = await device(1);
    const b = await device(1);
    expect(a.id).toBe(b.id);
    expect(a.id).not.toBe((await device(2)).id);
  });

  it.each(SMALL_ORDER)("rejects small-order public key %s", (h) => {
    expect(isStrictPublicKey(fromHex(h))).toBe(false);
  });

  it("small-order key with a signature that verifies under lax rules is rejected", async () => {
    // A = identity, R = identity, S = 0 satisfies [S]B = R + [k]A cofactorless.
    const identity = fromHex(SMALL_ORDER[0]!);
    const sig = concat(identity, new Uint8Array(32));
    expect(await verifyStrict(identity, utf8("any"), sig)).toBe(false);
  });

  it("rejects small-order R", async () => {
    const d = await device(1);
    const sig = await d.sign(utf8("m"));
    for (const h of SMALL_ORDER) {
      const forged = concat(fromHex(h), sig.subarray(32));
      expect(strictPrecheck(d.pk, forged)).toBe(false);
    }
  });

  it("rejects non-canonical S (S + L)", async () => {
    const d = await device(1);
    const msg = utf8("m");
    const sig = await d.sign(msg);
    const s = leToBig(sig.subarray(32));
    const malleated = concat(sig.subarray(0, 32), le(s + L));
    expect(strictPrecheck(d.pk, malleated)).toBe(false);
    expect(await verifyStrict(d.pk, msg, malleated)).toBe(false);
  });

  it("rejects S = L exactly", async () => {
    const d = await device(1);
    const sig = await d.sign(utf8("m"));
    expect(strictPrecheck(d.pk, concat(sig.subarray(0, 32), le(L)))).toBe(false);
  });

  it("rejects non-canonical y encodings (y >= p)", () => {
    for (let k = 0n; k < 19n; k++) {
      expect(decodePointStrict(le(P + k))).toBeNull();
      const neg = le(P + k);
      neg[31]! |= 0x80;
      expect(decodePointStrict(neg)).toBeNull();
    }
  });

  it("rejects x = 0 with the sign bit set", () => {
    const enc = fromHex(SMALL_ORDER[0]!);
    enc[31]! |= 0x80;
    expect(decodePointStrict(enc)).toBeNull();
  });

  it("rejects a point not on the curve", () => {
    // y = 2 is not the y-coordinate of a curve point.
    expect(decodePointStrict(le(2n))).toBeNull();
  });

  it("rejects wrong lengths", async () => {
    const d = await device(1);
    expect(await verifyStrict(d.pk.subarray(1), utf8("m"), new Uint8Array(64))).toBe(false);
    expect(await verifyStrict(d.pk, utf8("m"), new Uint8Array(63))).toBe(false);
  });

  it("accepts real device keys as strict", async () => {
    for (let i = 1; i < 10; i++) expect(isStrictPublicKey((await device(i)).pk)).toBe(true);
  });
});

describe("b64u strict", () => {
  it("round-trips", () => {
    for (let n = 0; n < 40; n++) {
      const b = new Uint8Array(n).map((_, i) => (i * 37 + n) & 0xff);
      expect(b64uDecode(b64uEncode(b))).toEqual(b);
    }
  });
  it("rejects padding, standard alphabet, bad length, non-zero trailing bits", () => {
    expect(b64uDecode("AA==")).toBeNull();
    expect(b64uDecode("+/8")).toBeNull();
    expect(b64uDecode("A")).toBeNull();
    expect(b64uDecode("AB")).toBeNull(); // trailing bits of 'B' are non-zero
    expect(b64uDecode("AQ")).toEqual(new Uint8Array([1]));
    expect(b64uDecode("AAAA AA")).toBeNull();
  });
  it("exact length", () => {
    expect(b64uDecodeExact("AQ", 1)).toEqual(new Uint8Array([1]));
    expect(b64uDecodeExact("AQ", 2)).toBeNull();
    expect(b64uDecodeExact(5, 1)).toBeNull();
  });
});
