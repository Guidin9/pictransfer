// Strict base64url without padding (RFC 4648 §5), protocol §1.
//
// Decoding rejects padding, characters outside the URL-safe alphabet, an
// impossible length (len % 4 == 1) and non-zero trailing bits, so every byte
// string has exactly one accepted encoding.

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const LOOKUP: Int16Array = (() => {
  const t = new Int16Array(128).fill(-1);
  for (let i = 0; i < ALPHABET.length; i++) t[ALPHABET.charCodeAt(i)] = i;
  return t;
})();

export const B64U_RE = /^[A-Za-z0-9_-]*$/;

export function b64uEncode(bytes: Uint8Array): string {
  let out = "";
  let i = 0;
  for (; i + 3 <= bytes.length; i += 3) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8) | bytes[i + 2]!;
    out += ALPHABET[(n >> 18) & 63]! + ALPHABET[(n >> 12) & 63]! + ALPHABET[(n >> 6) & 63]! + ALPHABET[n & 63]!;
  }
  const rem = bytes.length - i;
  if (rem === 1) {
    const n = bytes[i]! << 16;
    out += ALPHABET[(n >> 18) & 63]! + ALPHABET[(n >> 12) & 63]!;
  } else if (rem === 2) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8);
    out += ALPHABET[(n >> 18) & 63]! + ALPHABET[(n >> 12) & 63]! + ALPHABET[(n >> 6) & 63]!;
  }
  return out;
}

/** Returns null for any non-canonical or malformed input. `maxBytes` is checked before allocating. */
export function b64uDecode(s: string, maxBytes: number = Number.MAX_SAFE_INTEGER): Uint8Array | null {
  const len = s.length;
  if (len % 4 === 1) return null;
  const outLen = Math.floor((len * 3) / 4);
  if (outLen > maxBytes) return null;
  const out = new Uint8Array(outLen);
  let o = 0;
  let acc = 0;
  let bits = 0;
  for (let i = 0; i < len; i++) {
    const c = s.charCodeAt(i);
    const v = c < 128 ? LOOKUP[c]! : -1;
    if (v < 0) return null;
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >> bits) & 0xff;
      acc &= (1 << bits) - 1;
    }
  }
  // Leftover bits (2 or 4) must be zero: canonical encoding only.
  if (acc !== 0) return null;
  return out;
}

/** Decode and require an exact byte length. */
export function b64uDecodeExact(s: unknown, n: number): Uint8Array | null {
  if (typeof s !== "string") return null;
  if (s.length !== Math.ceil((n * 4) / 3)) return null;
  const b = b64uDecode(s, n);
  return b !== null && b.length === n ? b : null;
}
