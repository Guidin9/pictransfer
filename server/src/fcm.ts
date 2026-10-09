// FCM HTTP v1 (protocol §6.5) with an OAuth 2.0 access token minted from the
// FCM_SERVICE_ACCOUNT secret (service-account JSON) via an RS256 JWT bearer
// assertion. The caller caches the token in Durable Object storage for < 1 h.
//
// Never logged: tokens, envelopes, the service-account key.

import { b64uEncode } from "./b64u";
import { utf8 } from "./util";

const PROD_FCM_BASE = "https://fcm.googleapis.com";
const PROD_TOKEN_URL = "https://oauth2.googleapis.com/token";
const SCOPE = "https://www.googleapis.com/auth/firebase.messaging";
/** Tokens are used for at most 55 minutes (< 1 h, §architecture 5). */
const MAX_TOKEN_AGE_MS = 55 * 60 * 1000;

export interface FcmConfig {
  projectId: string;
  clientEmail: string;
  privateKeyPem: string;
  messagesUrl: string;
  tokenUrl: string;
}

/**
 * Builds the config from env. `baseUrl` (env FCM_BASE_URL) exists for tests
 * only; it replaces both Google hosts. Production leaves it unset.
 * Returns null when FCM is not configured or the secret is malformed.
 */
export function fcmConfig(serviceAccount: string | undefined, baseUrl: string | undefined): FcmConfig | null {
  if (serviceAccount === undefined || serviceAccount === "") return null;
  let sa: unknown;
  try {
    // A BOM or surrounding whitespace can come with the secret depending on how it
    // was piped into `wrangler secret put` (a PowerShell pipe prepends a BOM);
    // JSON.parse rejects a leading BOM, which silently disabled push wake-ups.
    sa = JSON.parse(serviceAccount.replace(/^﻿/, "").trim());
  } catch {
    return null;
  }
  if (typeof sa !== "object" || sa === null) return null;
  const { project_id, client_email, private_key } = sa as Record<string, unknown>;
  if (typeof project_id !== "string" || !/^[a-z0-9-]{1,64}$/.test(project_id)) return null;
  if (typeof client_email !== "string" || typeof private_key !== "string") return null;
  const fcmBase = baseUrl ?? PROD_FCM_BASE;
  return {
    projectId: project_id,
    clientEmail: client_email,
    privateKeyPem: private_key,
    messagesUrl: `${fcmBase}/v1/projects/${project_id}/messages:send`,
    // The token endpoint is fixed (not taken from the secret's token_uri), so
    // the signed assertion can only ever be sent to Google (or the test fake).
    tokenUrl: baseUrl !== undefined ? `${baseUrl}/token` : PROD_TOKEN_URL,
  };
}

function pemToDer(pem: string): Uint8Array {
  const b64 = pem
    .replace(/-----BEGIN PRIVATE KEY-----/, "")
    .replace(/-----END PRIVATE KEY-----/, "")
    .replace(/\s+/g, "");
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export async function signJwt(cfg: FcmConfig, nowMs: number): Promise<string> {
  const iat = Math.floor(nowMs / 1000);
  const header = b64uEncode(utf8(JSON.stringify({ alg: "RS256", typ: "JWT" })));
  const claims = b64uEncode(
    utf8(JSON.stringify({ iss: cfg.clientEmail, scope: SCOPE, aud: cfg.tokenUrl, iat, exp: iat + 3600 })),
  );
  const key = await crypto.subtle.importKey(
    "pkcs8",
    pemToDer(cfg.privateKeyPem),
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const input = `${header}.${claims}`;
  const sig = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, utf8(input)));
  return `${input}.${b64uEncode(sig)}`;
}

export interface AccessToken {
  token: string;
  /** Epoch ms after which the cached token must not be used. */
  exp: number;
}

export async function mintAccessToken(cfg: FcmConfig, nowMs: number): Promise<AccessToken | null> {
  const assertion = await signJwt(cfg, nowMs);
  const res = await fetch(cfg.tokenUrl, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: `grant_type=${encodeURIComponent("urn:ietf:params:oauth:grant-type:jwt-bearer")}&assertion=${assertion}`,
  });
  if (!res.ok) return null;
  let j: unknown;
  try {
    j = await res.json();
  } catch {
    return null;
  }
  const { access_token, expires_in } = (j ?? {}) as Record<string, unknown>;
  if (typeof access_token !== "string" || access_token === "") return null;
  const lifetimeMs = typeof expires_in === "number" && expires_in > 0 ? expires_in * 1000 : 3600 * 1000;
  return { token: access_token, exp: nowMs + Math.min(lifetimeMs - 5 * 60 * 1000, MAX_TOKEN_AGE_MS) };
}

/** §6.5 message body. No `notification` block, no plaintext sender or kind. */
export function fcmMessage(pushToken: string, env: string, ttlS: number): string {
  return JSON.stringify({
    message: {
      token: pushToken,
      android: { priority: "HIGH", ttl: `${ttlS}s` },
      data: { v: "1", e: env },
    },
  });
}

export type FcmResult = "ok" | "token-invalid" | "auth" | "error";

export async function sendFcm(
  cfg: FcmConfig,
  accessToken: string,
  pushToken: string,
  env: string,
  ttlS: number,
): Promise<{ result: FcmResult; status: number }> {
  let res: Response;
  try {
    res = await fetch(cfg.messagesUrl, {
      method: "POST",
      headers: { authorization: `Bearer ${accessToken}`, "content-type": "application/json" },
      body: fcmMessage(pushToken, env, ttlS),
    });
  } catch {
    return { result: "error", status: 0 };
  }
  if (res.ok) {
    await res.body?.cancel();
    return { result: "ok", status: res.status };
  }
  let errorCode = "";
  let status = "";
  try {
    const j = (await res.json()) as { error?: { status?: unknown; details?: unknown } };
    if (typeof j.error?.status === "string") status = j.error.status;
    if (Array.isArray(j.error?.details)) {
      for (const d of j.error.details as Array<Record<string, unknown>>) {
        if (typeof d?.errorCode === "string") errorCode = d.errorCode;
      }
    }
  } catch {
    // Non-JSON error body: classify by HTTP status only.
  }
  if (res.status === 401 || status === "UNAUTHENTICATED") return { result: "auth", status: res.status };
  // "If FCM reports the token as UNREGISTERED or invalid, the server deletes it" (§6.5).
  // Only token-specific detail codes delete a token. A bare 404 or a generic
  // INVALID_ARGUMENT can come from a wrong project id or a bad message, and
  // must not wipe every device's token on the first wake.
  if (errorCode === "UNREGISTERED" || errorCode === "SENDER_ID_MISMATCH") {
    return { result: "token-invalid", status: res.status };
  }
  return { result: "error", status: res.status };
}
