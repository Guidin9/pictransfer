// Strict CBOR (RFC 8949) decoder implementing every rejection rule of
// protocol §1:
//   indefinite lengths, non-shortest integers/lengths, duplicate map keys,
//   map keys out of ascending order, tags, floats, nesting deeper than 8,
//   trailing bytes, and size limits — checked BEFORE allocating.
// Additionally rejected (stricter reading, see SPEC-GAP notes below):
//   negative integers, non-uint map keys, simple values other than
//   false/true (incl. null and undefined), reserved additional-info values
//   28–30, invalid UTF-8. These match docs/test-vectors/cbor-reject.json.
//
// The decoder never throws anything but CborError.

export type Cbor =
  | { t: "uint"; v: bigint }
  | { t: "bytes"; v: Uint8Array }
  | { t: "text"; v: string }
  | { t: "array"; v: Cbor[] }
  | { t: "map"; v: Map<number, Cbor> }
  | { t: "bool"; v: boolean };

export type CborErrorCode =
  | "too-large"
  | "truncated"
  | "trailing"
  | "indefinite"
  | "non-shortest"
  | "tag"
  | "float"
  | "simple"
  | "reserved"
  | "depth"
  | "dup-key"
  | "unsorted-key"
  | "key-type"
  | "utf8"
  | "negative";

export class CborError extends Error {
  constructor(readonly code: CborErrorCode) {
    super(`cbor: ${code}`);
  }
}

export interface CborLimits {
  /** Maximum size of the whole encoded input. */
  maxBytes: number;
  /** Maximum nesting depth of arrays/maps (protocol §10: 8). */
  maxDepth?: number;
  /** Maximum length of one byte/text string. */
  maxString?: number;
  /** Maximum number of entries in one array or map. */
  maxItems?: number;
}

export const MAX_DEPTH = 8;

const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

class Reader {
  pos = 0;
  constructor(
    readonly buf: Uint8Array,
    readonly view: DataView,
    readonly lim: Required<CborLimits>,
  ) {}

  remaining(): number {
    return this.buf.length - this.pos;
  }

  byte(): number {
    if (this.pos >= this.buf.length) throw new CborError("truncated");
    return this.buf[this.pos++]!;
  }

  /** Reads the argument of a head with additional info `ai`, enforcing shortest form. */
  arg(ai: number): bigint {
    if (ai < 24) return BigInt(ai);
    switch (ai) {
      case 24: {
        const v = this.byte();
        if (v < 24) throw new CborError("non-shortest");
        return BigInt(v);
      }
      case 25: {
        if (this.remaining() < 2) throw new CborError("truncated");
        const v = this.view.getUint16(this.pos);
        this.pos += 2;
        if (v < 0x100) throw new CborError("non-shortest");
        return BigInt(v);
      }
      case 26: {
        if (this.remaining() < 4) throw new CborError("truncated");
        const v = this.view.getUint32(this.pos);
        this.pos += 4;
        if (v < 0x10000) throw new CborError("non-shortest");
        return BigInt(v);
      }
      case 27: {
        if (this.remaining() < 8) throw new CborError("truncated");
        const v = this.view.getBigUint64(this.pos);
        this.pos += 8;
        if (v < 0x100000000n) throw new CborError("non-shortest");
        return v;
      }
      case 31:
        throw new CborError("indefinite");
      default: // 28, 29, 30
        throw new CborError("reserved");
    }
  }

  /** A length/count argument, bounded before anything is allocated. */
  len(ai: number, max: number, minBytesPerUnit: number): number {
    const n = this.arg(ai);
    // Every unit needs at least `minBytesPerUnit` input bytes, so a count that
    // exceeds the remaining input can never be valid.
    if (n > BigInt(max) || n * BigInt(minBytesPerUnit) > BigInt(this.remaining())) {
      throw new CborError(n > BigInt(max) ? "too-large" : "truncated");
    }
    return Number(n);
  }

  /** `depth` is the level of this item: 1 for the top-level item. */
  item(depth: number): Cbor {
    if (depth > this.lim.maxDepth) throw new CborError("depth");
    const ib = this.byte();
    const major = ib >> 5;
    const ai = ib & 0x1f;
    switch (major) {
      case 0:
        return { t: "uint", v: this.arg(ai) };
      case 1:
        // SPEC-GAP: §1 does not list negative integers, but no structure uses
        // them and the core decoder rejects them (cbor-reject.json). Rejected.
        throw new CborError("negative");
      case 2: {
        const n = this.len(ai, this.lim.maxString, 1);
        const v = this.buf.slice(this.pos, this.pos + n);
        this.pos += n;
        return { t: "bytes", v };
      }
      case 3: {
        const n = this.len(ai, this.lim.maxString, 1);
        const raw = this.buf.subarray(this.pos, this.pos + n);
        this.pos += n;
        let v: string;
        try {
          v = utf8.decode(raw);
        } catch {
          throw new CborError("utf8");
        }
        return { t: "text", v };
      }
      case 4: {
        const n = this.len(ai, this.lim.maxItems, 1);
        const v: Cbor[] = [];
        for (let i = 0; i < n; i++) v.push(this.item(depth + 1));
        return { t: "array", v };
      }
      case 5: {
        const n = this.len(ai, this.lim.maxItems, 2);
        const v = new Map<number, Cbor>();
        let prev = -1;
        for (let i = 0; i < n; i++) {
          const kb = this.byte();
          // SPEC-GAP: §1 says maps use small unsigned-integer keys but does not
          // say what a decoder does with other key types. Stricter reading:
          // any non-uint key is rejected.
          if (kb >> 5 !== 0) throw new CborError("key-type");
          const kbig = this.arg(kb & 0x1f);
          if (kbig > BigInt(Number.MAX_SAFE_INTEGER)) throw new CborError("key-type");
          const k = Number(kbig);
          if (k === prev) throw new CborError("dup-key");
          if (k < prev) throw new CborError("unsorted-key");
          prev = k;
          v.set(k, this.item(depth + 1));
        }
        return { t: "map", v };
      }
      case 6:
        throw new CborError("tag");
      default: {
        // major 7
        if (ai === 20) return { t: "bool", v: false };
        if (ai === 21) return { t: "bool", v: true };
        if (ai === 25 || ai === 26 || ai === 27) throw new CborError("float");
        if (ai === 31) throw new CborError("indefinite"); // stray "break"
        if (ai >= 28) throw new CborError("reserved");
        // SPEC-GAP: §1 does not mention simple values. null (22),
        // undefined (23) and all other simple values are not used by any
        // structure, so they are rejected.
        throw new CborError("simple");
      }
    }
  }
}

/**
 * Decodes exactly one CBOR item spanning all of `bytes`.
 *
 * Depth convention (SPEC-GAP: §1 says "nesting deeper than 8" without
 * defining the count; this follows cbor-reject.json): every item has a level,
 * the top-level item is level 1 and the contents of a container at level k
 * are at level k+1. An item at level 9 is rejected, so 8 nested arrays around
 * a scalar are too deep, while 7 arrays around a scalar (or 8 with the
 * innermost empty) are accepted.
 */
export function decodeCbor(bytes: Uint8Array, limits: CborLimits): Cbor {
  const lim: Required<CborLimits> = {
    maxBytes: limits.maxBytes,
    maxDepth: Math.min(limits.maxDepth ?? MAX_DEPTH, MAX_DEPTH),
    maxString: limits.maxString ?? limits.maxBytes,
    maxItems: limits.maxItems ?? limits.maxBytes,
  };
  if (bytes.length > lim.maxBytes) throw new CborError("too-large");
  const r = new Reader(bytes, new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength), lim);
  const v = r.item(1);
  if (r.pos !== bytes.length) throw new CborError("trailing");
  return v;
}

// ---- typed accessors (throw CborShapeError on mismatch) ----

export class CborShapeError extends Error {
  constructor(readonly field: string) {
    super(`shape: ${field}`);
  }
}

export function asUint(c: Cbor | undefined, field: string): number {
  if (c === undefined || c.t !== "uint" || c.v > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new CborShapeError(field);
  }
  return Number(c.v);
}

export function asBytes(c: Cbor | undefined, field: string, exactLen?: number): Uint8Array {
  if (c === undefined || c.t !== "bytes") throw new CborShapeError(field);
  if (exactLen !== undefined && c.v.length !== exactLen) throw new CborShapeError(field);
  return c.v;
}

export function asText(c: Cbor | undefined, field: string): string {
  if (c === undefined || c.t !== "text") throw new CborShapeError(field);
  return c.v;
}

export function asMap(c: Cbor | undefined, field: string): Map<number, Cbor> {
  if (c === undefined || c.t !== "map") throw new CborShapeError(field);
  return c.v;
}

export function asArray(c: Cbor | undefined, field: string, exactLen?: number): Cbor[] {
  if (c === undefined || c.t !== "array") throw new CborShapeError(field);
  if (exactLen !== undefined && c.v.length !== exactLen) throw new CborShapeError(field);
  return c.v;
}
