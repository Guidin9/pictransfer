// Shared helpers: protocol constants, error responses (§6.8), byte utilities.

export const LABEL_RECORD = "warpshot/record/v1\0";
export const LABEL_RECORD_ID = "warpshot/record-id/v1\0";
export const LABEL_SERVER_AUTH = "warpshot/server-auth/v1\0";

/** Protocol §10 and §6 limits used by the server. */
export const LIMITS = {
  members: 16,
  records: 1024,
  envelopeB64u: 3800,
  wsMessage: 64 * 1024,
  deviceName: 64,
  appVersion: 32,
  kemPk: 1216,
  /** §4.3 rule 1: a SignedRecord is at most 4 KiB. */
  recordBytes: 4096,
  /** Maximum HTTP request body. The largest valid body (a wake) is < 4 KiB. */
  httpBody: 16 * 1024,
  /** SPEC-GAP: FCM tokens have no documented maximum; ~160–200 chars in practice. */
  pushToken: 1024,
  authWindowMs: 120_000,
} as const;

export type ErrorCode =
  | "bad-request"
  | "unauthenticated"
  | "not-member"
  | "not-allowed"
  | "no-group"
  | "head-moved"
  | "exists"
  | "too-large"
  | "invalid-record"
  | "rate-limited"
  | "internal";

export const STATUS: Record<ErrorCode, number> = {
  "bad-request": 400,
  unauthenticated: 401,
  "not-member": 403,
  "not-allowed": 403,
  "no-group": 404,
  "head-moved": 409,
  exists: 409,
  "too-large": 413,
  "invalid-record": 422,
  "rate-limited": 429,
  internal: 500,
};

/** Thrown inside handlers; converted to `{"error": code}` with the §6.8 status. */
export class ApiError extends Error {
  constructor(
    readonly code: ErrorCode,
    readonly extra?: Record<string, unknown>,
  ) {
    super(code);
  }
}

export function json(body: unknown, status = 200, headers?: Record<string, string>): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store", ...headers },
  });
}

export function errorResponse(code: ErrorCode, extra?: Record<string, unknown>): Response {
  return json({ error: code, ...extra }, STATUS[code]);
}

export function noContent(): Response {
  return new Response(null, { status: 204, headers: { "cache-control": "no-store" } });
}

const enc = new TextEncoder();

export function utf8(s: string): Uint8Array {
  return enc.encode(s);
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data));
}

export function hex(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i]! ^ b[i]!;
  return d === 0;
}

/** Constant-time comparison of two secrets of possibly different length. */
export async function secretEquals(a: string, b: string): Promise<boolean> {
  // Hashing first gives equal-length inputs, so timingSafeEqual never throws
  // and the length of the secret does not leak through an early return.
  const [ha, hb] = await Promise.all([sha256(utf8(a)), sha256(utf8(b))]);
  return crypto.subtle.timingSafeEqual(ha, hb);
}

/**
 * Reads a request body with a hard cap, without trusting Content-Length.
 * Throws ApiError("too-large") as soon as the cap is exceeded.
 */
export async function readBodyCapped(req: Request, max: number): Promise<Uint8Array> {
  const cl = req.headers.get("content-length");
  if (cl !== null && /^[0-9]+$/.test(cl) && Number(cl) > max) throw new ApiError("too-large");
  if (req.body === null) return new Uint8Array(0);
  const reader = req.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > max) {
      await reader.cancel().catch(() => {});
      throw new ApiError("too-large");
    }
    chunks.push(value);
  }
  return concat(...chunks);
}

/** Parses a JSON object body. Unknown fields are ignored (forward compatibility, as §1 for CBOR maps). */
export function parseJsonObject(body: Uint8Array): Record<string, unknown> {
  let v: unknown;
  try {
    v = JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(body));
  } catch {
    throw new ApiError("bad-request");
  }
  if (typeof v !== "object" || v === null || Array.isArray(v)) throw new ApiError("bad-request");
  return v as Record<string, unknown>;
}

/** Structured log line: ids, timings and error codes only (CLAUDE.md security invariants). */
export function logEvent(ev: string, fields: Record<string, string | number | boolean> = {}): void {
  console.log(JSON.stringify({ ev, ...fields }));
}
