// Request authentication, protocol §6.1.
//
//   Authorization: WARP1 id=<b64u EndpointId>, ts=<decimal ms>, sig=<b64u signature>
//   signed = "warpshot/server-auth/v1\0" ‖ METHOD ‖ "\n" ‖ PATH_AND_QUERY ‖ "\n"
//            ‖ ts ‖ "\n" ‖ lowercase_hex(SHA-256(body))
//
// This module does the stateless part (syntax, time window, strict signature).
// The replay cache and the membership check live in the Durable Object,
// which owns the storage (group.ts).

import { b64uDecodeExact } from "./b64u";
import { verifyStrict } from "./ed25519";
import { ApiError, concat, hex, LABEL_SERVER_AUTH, LIMITS, secretEquals, sha256, utf8 } from "./util";

// Strict syntax: exactly one space after the scheme, ", " separators, fixed
// field order, canonical decimal ts (no leading zeros, no sign).
const AUTH_RE = /^WARP1 id=([A-Za-z0-9_-]{43}), ts=(0|[1-9][0-9]{0,15}), sig=([A-Za-z0-9_-]{86})$/;

export interface AuthInfo {
  id: Uint8Array;
  /** b64u(id), the device tag used everywhere in the DO. */
  idB64: string;
  ts: number;
  sig: Uint8Array;
}

export function parseAuthorization(h: string | null): AuthInfo {
  if (h === null) throw new ApiError("unauthenticated");
  const m = AUTH_RE.exec(h);
  if (m === null) throw new ApiError("unauthenticated");
  const id = b64uDecodeExact(m[1], 32);
  const sig = b64uDecodeExact(m[3], 64);
  const ts = Number(m[2]);
  if (id === null || sig === null || !Number.isSafeInteger(ts)) throw new ApiError("unauthenticated");
  return { id, idB64: m[1]!, ts, sig };
}

/**
 * PATH_AND_QUERY: the request target exactly as sent (§6.1), taken from the
 * raw request URL without re-serializing it through the URL parser.
 */
export function requestTarget(req: Request): string {
  const url = req.url;
  const scheme = url.indexOf("://");
  const slash = scheme < 0 ? -1 : url.indexOf("/", scheme + 3);
  if (slash < 0) return "/";
  const hash = url.indexOf("#", slash);
  return hash < 0 ? url.slice(slash) : url.slice(slash, hash);
}

/** Splits a request target into path and raw query (null when there is no "?"). */
export function splitTarget(target: string): { path: string; query: string | null } {
  const q = target.indexOf("?");
  return q < 0 ? { path: target, query: null } : { path: target.slice(0, q), query: target.slice(q + 1) };
}

export async function authSignedBytes(method: string, pq: string, ts: number, body: Uint8Array): Promise<Uint8Array> {
  const bodyHash = hex(await sha256(body));
  return concat(utf8(LABEL_SERVER_AUTH), utf8(`${method}\n${pq}\n${ts}\n${bodyHash}`));
}

/**
 * Verifies syntax, the ±120 s window and the strict signature.
 * Throws ApiError("unauthenticated").
 */
export async function verifyAuthorization(
  header: string | null,
  method: string,
  target: string,
  body: Uint8Array,
  now: number,
): Promise<AuthInfo> {
  const a = parseAuthorization(header);
  if (Math.abs(now - a.ts) > LIMITS.authWindowMs) throw new ApiError("unauthenticated");
  const msg = await authSignedBytes(method, target, a.ts, body);
  if (!(await verifyStrict(a.id, msg, a.sig))) throw new ApiError("unauthenticated");
  return a;
}

export function verifyRequestSignature(req: Request, body: Uint8Array, now: number): Promise<AuthInfo> {
  return verifyAuthorization(req.headers.get("authorization"), req.method, requestTarget(req), body, now);
}

/** Replay-cache key for `(id, ts, sig)`; 16 bytes of SHA-256, no content. */
export async function replayKey(a: AuthInfo): Promise<Uint8Array> {
  const ts = new Uint8Array(8);
  new DataView(ts.buffer).setBigUint64(0, BigInt(a.ts));
  return (await sha256(concat(a.id, ts, a.sig))).slice(0, 16);
}

/**
 * Operator admission (§6.1). When GROUP_CREATE_TOKEN is set, POST /v1/groups
 * must carry `Warpshot-Create-Token` equal to it (constant-time compare).
 * Called before any other processing of the request.
 */
export async function checkCreateToken(secret: string | undefined, req: Request): Promise<void> {
  if (secret === undefined) return;
  // An empty configured secret is a misconfiguration: refuse rather than admit everyone.
  if (secret === "") throw new ApiError("not-allowed");
  const given = req.headers.get("warpshot-create-token");
  if (given === null) throw new ApiError("not-allowed");
  if (!(await secretEquals(given, secret))) throw new ApiError("not-allowed");
}
