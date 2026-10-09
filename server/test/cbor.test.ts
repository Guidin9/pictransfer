// Strict CBOR decoder: one negative test per §1 rejection rule, plus positives.
import { describe, expect, it } from "vitest";
import { CborError, decodeCbor } from "../src/cbor";
import { cbor, fromHex } from "./helpers/fixtures";

const LIM = { maxBytes: 4096 };

function rejects(hexStr: string, code: string, lim: { maxBytes: number; maxString?: number; maxItems?: number } = LIM) {
  try {
    decodeCbor(fromHex(hexStr), lim);
  } catch (e) {
    expect(e).toBeInstanceOf(CborError);
    expect((e as CborError).code).toBe(code);
    return;
  }
  throw new Error(`accepted ${hexStr}`);
}

describe("cbor: accepts canonical input", () => {
  it.each([
    ["00", 0n],
    ["17", 23n],
    ["1818", 24n],
    ["18ff", 255n],
    ["190100", 256n],
    ["19ffff", 65535n],
    ["1a00010000", 65536n],
    ["1b0000000100000000", 4294967296n],
    ["1bffffffffffffffff", 18446744073709551615n],
  ])("uint %s", (h, v) => {
    expect(decodeCbor(fromHex(h), LIM)).toEqual({ t: "uint", v });
  });

  it("bool, bytes, text", () => {
    expect(decodeCbor(fromHex("f4"), LIM)).toEqual({ t: "bool", v: false });
    expect(decodeCbor(fromHex("f5"), LIM)).toEqual({ t: "bool", v: true });
    expect(decodeCbor(fromHex("43010203"), LIM)).toEqual({ t: "bytes", v: new Uint8Array([1, 2, 3]) });
    expect(decodeCbor(fromHex("62c3a9"), LIM)).toEqual({ t: "text", v: "é" });
  });

  it("sorted map, nested array", () => {
    const v = decodeCbor(cbor({ 0: 1, 1: [2, 3], 24: "x" }), LIM);
    expect(v.t).toBe("map");
    if (v.t === "map") expect([...v.v.keys()]).toEqual([0, 1, 24]);
  });

  it("nesting depth 8 is accepted (7 arrays + scalar; 8 arrays, innermost empty)", () => {
    expect(() => decodeCbor(fromHex("81818181818181" + "00"), LIM)).not.toThrow();
    expect(() => decodeCbor(fromHex("8181818181818180"), LIM)).not.toThrow();
  });
});

describe("cbor: §1 rejection rules", () => {
  it("indefinite-length byte string", () => rejects("5f4101ff", "indefinite"));
  it("indefinite-length text string", () => rejects("7f6161ff", "indefinite"));
  it("indefinite-length array", () => rejects("9f00ff", "indefinite"));
  it("indefinite-length map", () => rejects("bf0000ff", "indefinite"));
  it("stray break", () => rejects("ff", "indefinite"));
  it("indefinite uint (ai 31 on major 0)", () => rejects("1f", "indefinite"));

  it("non-shortest uint (1-byte)", () => rejects("1817", "non-shortest"));
  it("non-shortest uint (2-byte)", () => rejects("1900ff", "non-shortest"));
  it("non-shortest uint (4-byte)", () => rejects("1a0000ffff", "non-shortest"));
  it("non-shortest uint (8-byte)", () => rejects("1b00000000ffffffff", "non-shortest"));
  it("non-shortest byte-string length", () => rejects("580101", "non-shortest"));
  it("non-shortest text length", () => rejects("78016161".slice(0, 6), "non-shortest"));
  it("non-shortest array length", () => rejects("980100", "non-shortest"));
  it("non-shortest map length", () => rejects("b8010000", "non-shortest"));
  it("non-shortest map key", () => rejects("a1180000", "non-shortest"));

  it("duplicate map keys", () => rejects("a2010001 00".replace(" ", ""), "dup-key"));
  it("map keys out of ascending order", () => rejects("a202000100", "unsorted-key"));

  it("tag (small)", () => rejects("c000", "tag"));
  it("tag (1-byte)", () => rejects("d82000", "tag"));
  it("tag inside an array", () => rejects("81c100", "tag"));

  it("half float", () => rejects("f90000", "float"));
  it("single float", () => rejects("fa00000000", "float"));
  it("double float", () => rejects("fb0000000000000000", "float"));

  it("nesting deeper than 8 (arrays)", () => rejects("8181818181818181" + "00", "depth"));
  it("nesting deeper than 8 (maps)", () => rejects("a100a100a100a100a100a100a100a10000", "depth"));
  it("nesting deeper than 8 (empty container at level 9)", () => rejects("818181818181818180", "depth"));

  it("trailing bytes after the top-level item", () => rejects("0000", "trailing"));
  it("trailing bytes after a map", () => rejects("a0ff", "trailing"));

  it("input above the size limit", () => rejects("00".repeat(10), "too-large", { maxBytes: 9 }));
  it("string above the string limit", () => rejects("43010203", "too-large", { maxBytes: 100, maxString: 2 }));
  it("array above the item limit", () => rejects("83000000", "too-large", { maxBytes: 100, maxItems: 2 }));
  it("huge declared byte-string length is rejected before allocation", () =>
    rejects("5bffffffffffffffff", "too-large"));
  it("huge declared array count is rejected before allocation", () => rejects("9b0000000100000000", "too-large"));
  it("declared length longer than the input", () => rejects("4501", "truncated"));
  it("declared array count longer than the input", () => rejects("8300", "truncated"));
  it("map count needs 2 bytes per entry", () => rejects("a300000000", "truncated"));
  it("truncated argument", () => rejects("19ff", "truncated"));
  it("empty input", () => rejects("", "truncated"));
});

describe("cbor: stricter rules (SPEC-GAP)", () => {
  it("text map key", () => rejects("a1616100", "key-type"));
  it("negative map key", () => rejects("a12000", "key-type"));
  it("negative integer", () => rejects("20", "negative"));
  it("negative integer inside an array", () => rejects("8120", "negative"));
  it("null", () => rejects("f6", "simple"));
  it("undefined", () => rejects("f7", "simple"));
  it("unassigned simple value", () => rejects("f0", "simple"));
  it("one-byte simple value", () => rejects("f820", "simple"));
  it("reserved additional info 28", () => rejects("1c", "reserved"));
  it("reserved additional info 30 on byte string", () => rejects("5e", "reserved"));
  it("reserved additional info 29 on major 7", () => rejects("fd", "reserved"));
  it("invalid UTF-8 in text", () => rejects("62c328", "utf8"));
  it("UTF-8 surrogate encoding in text", () => rejects("63eda080", "utf8"));
});
