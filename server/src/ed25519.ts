// Strict Ed25519 verification (protocol §2.1: "reject non-canonical encodings
// and small-order points", the semantics of ed25519-dalek `verify_strict`).
//
// WebCrypto (BoringSSL in workerd) checks S < L and compares R by encoding,
// but it accepts small-order public keys and small-order R. We therefore run
// these checks first, in BigInt arithmetic on the curve:
//   - A and R: y < p (canonical), on the curve, not (x == 0 with sign bit 1),
//     and not of small order ([8]P != identity);
//   - S < L.
// Then the signature equation is checked by WebCrypto (cofactorless).

const P = (1n << 255n) - 19n;
const L = (1n << 252n) + 27742317777372353535851937790883648493n;

function mod(a: bigint): bigint {
  const r = a % P;
  return r >= 0n ? r : r + P;
}

function pow(base: bigint, exp: bigint): bigint {
  let result = 1n;
  let b = mod(base);
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % P;
    b = (b * b) % P;
    e >>= 1n;
  }
  return result;
}

function inv(a: bigint): bigint {
  return pow(a, P - 2n);
}

const D = mod(-121665n * inv(121666n));
const SQRT_M1 = pow(2n, (P - 1n) / 4n);

function leToBigInt(bytes: Uint8Array): bigint {
  let n = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(bytes[i]!);
  return n;
}

interface Point {
  x: bigint;
  y: bigint;
}

/** Decodes a point strictly. Returns null for non-canonical or off-curve encodings. */
export function decodePointStrict(enc: Uint8Array): Point | null {
  if (enc.length !== 32) return null;
  const sign = (enc[31]! >> 7) & 1;
  const yBytes = enc.slice();
  yBytes[31]! &= 0x7f;
  const y = leToBigInt(yBytes);
  if (y >= P) return null; // non-canonical y
  const y2 = (y * y) % P;
  const u = mod(y2 - 1n);
  const v = mod(D * y2 + 1n);
  // x = u v^3 (u v^7)^((p-5)/8)
  const v3 = (v * v * v) % P;
  const v7 = (v3 * v3 * v) % P;
  let x = (((u * v3) % P) * pow((u * v7) % P, (P - 5n) / 8n)) % P;
  const vx2 = (v * x * x) % P;
  if (vx2 !== u) {
    if (vx2 === mod(-u)) x = (x * SQRT_M1) % P;
    else return null; // not on the curve
  }
  if (x === 0n && sign === 1) return null; // non-canonical sign for x == 0
  if (Number(x & 1n) !== sign) x = mod(-x);
  return { x, y };
}

function add(a: Point, b: Point): Point {
  // Complete twisted Edwards addition, a = -1.
  const x1x2 = (a.x * b.x) % P;
  const y1y2 = (a.y * b.y) % P;
  const dxy = (((D * x1x2) % P) * y1y2) % P;
  const x3 = mod((a.x * b.y + a.y * b.x) * inv(mod(1n + dxy)));
  const y3 = mod((y1y2 + x1x2) * inv(mod(1n - dxy)));
  return { x: x3, y: y3 };
}

export function isSmallOrder(p: Point): boolean {
  let q = p;
  for (let i = 0; i < 3; i++) q = add(q, q);
  return q.x === 0n && q.y === 1n;
}

/** True when `pk` is a canonical, on-curve, non-small-order Ed25519 public key. */
export function isStrictPublicKey(pk: Uint8Array): boolean {
  const a = decodePointStrict(pk);
  return a !== null && !isSmallOrder(a);
}

/** Pre-checks of `verify_strict` on the signature encoding and key. */
export function strictPrecheck(pk: Uint8Array, sig: Uint8Array): boolean {
  if (pk.length !== 32 || sig.length !== 64) return false;
  if (leToBigInt(sig.subarray(32, 64)) >= L) return false; // S must be canonical
  const r = decodePointStrict(sig.subarray(0, 32));
  if (r === null || isSmallOrder(r)) return false;
  return isStrictPublicKey(pk);
}

export async function verifyStrict(pk: Uint8Array, msg: Uint8Array, sig: Uint8Array): Promise<boolean> {
  if (!strictPrecheck(pk, sig)) return false;
  try {
    const key = await crypto.subtle.importKey("raw", pk, { name: "Ed25519" }, false, ["verify"]);
    return await crypto.subtle.verify({ name: "Ed25519" }, key, sig, msg);
  } catch {
    return false;
  }
}
