// §6.4 wake routing and §6.5 FCM against a fake FCM/OAuth endpoint
// (FCM_BASE_URL = https://fcm.test, set in vitest.config.ts only).
import { env } from "cloudflare:workers";
import { runInDurableObject } from "cloudflare:test";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { b64uDecode } from "../src/b64u";
import { call, connect, createGroup, device, Device, TestGroup } from "./helpers/fixtures";

const ENV = "QUJD" + "y".repeat(200);
const FAKE = "https://fcm.test";

interface FakeFcm {
  tokenCalls: number;
  sends: Array<{ auth: string | null; body: unknown }>;
  /** Response for the next sends (FIFO); default 200. */
  sendResponses: Array<() => Response>;
  jwtClaims: Array<Record<string, unknown>>;
  issued: string[];
}

let fake: FakeFcm;

function pemToDer(pem: string): Uint8Array {
  const b64 = pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

async function verifyJwt(jwt: string): Promise<Record<string, unknown>> {
  const [h, c, s] = jwt.split(".");
  const key = await crypto.subtle.importKey(
    "spki",
    pemToDer(env.TEST_FCM_PUBLIC_KEY),
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"],
  );
  const ok = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, b64uDecode(s!)!, new TextEncoder().encode(`${h}.${c}`));
  if (!ok) throw new Error("bad jwt signature");
  expect(JSON.parse(new TextDecoder().decode(b64uDecode(h!)!))).toEqual({ alg: "RS256", typ: "JWT" });
  return JSON.parse(new TextDecoder().decode(b64uDecode(c!)!)) as Record<string, unknown>;
}

beforeEach(() => {
  fake = { tokenCalls: 0, sends: [], sendResponses: [], jwtClaims: [], issued: [] };
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
    const req = new Request(input, init);
    if (req.url === `${FAKE}/token`) {
      fake.tokenCalls++;
      const form = new URLSearchParams(await req.text());
      expect(form.get("grant_type")).toBe("urn:ietf:params:oauth:grant-type:jwt-bearer");
      fake.jwtClaims.push(await verifyJwt(form.get("assertion")!));
      const token = `access-${fake.tokenCalls}`;
      fake.issued.push(token);
      return Response.json({ access_token: token, expires_in: 3599, token_type: "Bearer" });
    }
    if (req.url === `${FAKE}/v1/projects/test-project/messages:send`) {
      fake.sends.push({ auth: req.headers.get("authorization"), body: await req.json() });
      const next = fake.sendResponses.shift();
      return next ? next() : Response.json({ name: "projects/test-project/messages/1" });
    }
    throw new Error(`unexpected outbound fetch`);
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});

async function setup(): Promise<{ A: Device; B: Device; tg: TestGroup }> {
  const [A, B] = await Promise.all([device(1), device(2)]);
  const tg = await createGroup(A, [B]);
  return { A, B, tg };
}

async function wake(tg: TestGroup, from: Device, to: Device, ttl = 60, envelope = ENV): Promise<Response> {
  return call(from, "POST", tg.path("wake"), { to: to.id, env: envelope, ttl });
}

describe("routing order", () => {
  it("no socket and no push token → via none (no FCM call)", async () => {
    const { A, B, tg } = await setup();
    expect(await (await wake(tg, A, B)).json()).toEqual({ via: "none" });
    expect(fake.tokenCalls + fake.sends.length).toBe(0);
  });

  it("open socket wins over a push token → via ws", async () => {
    const { A, B, tg } = await setup();
    await call(B, "PUT", tg.path("push-token"), { provider: "fcm", token: "tokB" });
    const sb = await connect(tg, B);
    expect(await (await wake(tg, A, B)).json()).toEqual({ via: "ws" });
    expect(fake.sends.length).toBe(0);
    sb.ws.close(1000);
  });

  it("push token, no socket → via push with the §6.5 message shape", async () => {
    const { A, B, tg } = await setup();
    await call(B, "PUT", tg.path("push-token"), { provider: "fcm", token: "tokB:abc-_1" });
    expect(await (await wake(tg, A, B, 86400)).json()).toEqual({ via: "push" });
    expect(fake.sends).toHaveLength(1);
    expect(fake.sends[0]!.auth).toBe("Bearer access-1");
    expect(fake.sends[0]!.body).toEqual({
      message: {
        token: "tokB:abc-_1",
        android: { priority: "HIGH", ttl: "86400s" },
        data: { v: "1", e: ENV },
      },
    });
    const claims = fake.jwtClaims[0]!;
    expect(claims.iss).toBe("sender@test-project.iam.gserviceaccount.com");
    expect(claims.scope).toBe("https://www.googleapis.com/auth/firebase.messaging");
    expect(claims.aud).toBe(`${FAKE}/token`);
    expect((claims.exp as number) - (claims.iat as number)).toBe(3600);
  });
});

describe("OAuth token cache", () => {
  it("is minted once and cached in DO storage for < 1 h", async () => {
    const { A, B, tg } = await setup();
    await call(B, "PUT", tg.path("push-token"), { provider: "fcm", token: "tokB" });
    await wake(tg, A, B);
    await wake(tg, A, B);
    expect(fake.tokenCalls).toBe(1);
    expect(fake.sends.map((s) => s.auth)).toEqual(["Bearer access-1", "Bearer access-1"]);
    const cached = await runInDurableObject(env.GROUPS.get(env.GROUPS.idFromName(tg.gid)), (_i, state) =>
      state.storage.get<{ token: string; exp: number }>("fcm_oauth"),
    );
    expect(cached?.token).toBe("access-1");
    expect(cached!.exp - Date.now()).toBeLessThan(3600 * 1000);
    expect(cached!.exp - Date.now()).toBeGreaterThan(50 * 60 * 1000);
  });

  it("an expired cached token is replaced", async () => {
    const { A, B, tg } = await setup();
    await call(B, "PUT", tg.path("push-token"), { provider: "fcm", token: "tokB" });
    await wake(tg, A, B);
    await runInDurableObject(env.GROUPS.get(env.GROUPS.idFromName(tg.gid)), async (instance, state) => {
      await state.storage.put("fcm_oauth", { token: "access-1", exp: Date.now() - 1 });
      (instance as unknown as { fcmToken: unknown }).fcmToken = null;
    });
    await wake(tg, A, B);
    expect(fake.tokenCalls).toBe(2);
    expect(fake.sends[1]!.auth).toBe("Bearer access-2");
  });

  it("FCM 401 → refresh once and retry", async () => {
    const { A, B, tg } = await setup();
    await call(B, "PUT", tg.path("push-token"), { provider: "fcm", token: "tokB" });
    fake.sendResponses.push(() => Response.json({ error: { code: 401, status: "UNAUTHENTICATED" } }, { status: 401 }));
    expect(await (await wake(tg, A, B)).json()).toEqual({ via: "push" });
    expect(fake.tokenCalls).toBe(2);
    expect(fake.sends.map((s) => s.auth)).toEqual(["Bearer access-1", "Bearer access-2"]);
  });

  it("token endpoint failure → 500 internal", async () => {
    const { A, B, tg } = await setup();
    await call(B, "PUT", tg.path("push-token"), { provider: "fcm", token: "tokB" });
    vi.mocked(globalThis.fetch).mockImplementation(async () => new Response("no", { status: 500 }));
    const res = await wake(tg, A, B);
    expect(res.status).toBe(500);
    expect(await res.json()).toEqual({ error: "internal" });
  });
});

describe("token invalidation", () => {
  const unregistered = () =>
    Response.json(
      {
        error: {
          code: 404,
          status: "NOT_FOUND",
          details: [{ "@type": "type.googleapis.com/google.firebase.fcm.v1.FcmError", errorCode: "UNREGISTERED" }],
        },
      },
      { status: 404 },
    );
  const invalid = () =>
    Response.json(
      {
        error: {
          code: 400,
          status: "INVALID_ARGUMENT",
          details: [{ "@type": "type.googleapis.com/google.firebase.fcm.v1.FcmError", errorCode: "INVALID_ARGUMENT" }],
        },
      },
      { status: 400 },
    );

  it.each([
    ["UNREGISTERED", unregistered],
    ["INVALID_ARGUMENT", invalid],
  ])("%s → token deleted, via none, later wakes skip FCM", async (_n, resp) => {
    const { A, B, tg } = await setup();
    await call(B, "PUT", tg.path("push-token"), { provider: "fcm", token: "tokB" });
    fake.sendResponses.push(resp);
    expect(await (await wake(tg, A, B)).json()).toEqual({ via: "none" });
    const presence = (await (await call(A, "GET", tg.path("presence"))).json()) as { devices: Array<{ id: string; push: boolean }> };
    expect(presence.devices.find((d) => d.id === B.id)!.push).toBe(false);
    expect(await (await wake(tg, A, B)).json()).toEqual({ via: "none" });
    expect(fake.sends).toHaveLength(1);
  });

  it("FCM 500 → 500 internal, token kept", async () => {
    const { A, B, tg } = await setup();
    await call(B, "PUT", tg.path("push-token"), { provider: "fcm", token: "tokB" });
    fake.sendResponses.push(() => new Response("boom", { status: 503 }));
    expect((await wake(tg, A, B)).status).toBe(500);
    expect(await (await wake(tg, A, B)).json()).toEqual({ via: "push" });
  });
});

describe("validation", () => {
  it("to must be a member → 403 not-member", async () => {
    const { A, tg } = await setup();
    const X = await device(9);
    expect(await (await wake(tg, A, X)).json()).toEqual({ error: "not-member" });
  });

  it("malformed fields → 400; envelope above 3800 chars → 413", async () => {
    const { A, B, tg } = await setup();
    const bad = [
      { to: "short", env: ENV, ttl: 60 },
      { to: B.id + "A", env: ENV, ttl: 60 },
      { env: ENV, ttl: 60 },
      { to: B.id, env: "", ttl: 60 },
      { to: B.id, env: "a+b/", ttl: 60 },
      { to: B.id, env: "AAAA=", ttl: 60 },
      { to: B.id, env: "AAAAA", ttl: 60 },
      { to: B.id, env: 5, ttl: 60 },
      { to: B.id, env: ENV, ttl: 0 },
      { to: B.id, env: ENV, ttl: 86401 },
      { to: B.id, env: ENV, ttl: 1.5 },
      { to: B.id, env: ENV, ttl: "60" },
      { to: B.id, env: ENV },
    ];
    for (const body of bad) {
      const res = await call(A, "POST", tg.path("wake"), body);
      expect(res.status, JSON.stringify(body).slice(0, 80)).toBe(400);
    }
    expect((await wake(tg, A, B, 60, "A".repeat(3800))).status).toBe(200);
    const res = await wake(tg, A, B, 60, "A".repeat(3801));
    expect(res.status).toBe(413);
    expect(await res.json()).toEqual({ error: "too-large" });
  });

  it("rate limit: burst of 20 per device, then 429 rate-limited", async () => {
    const { A, B, tg } = await setup();
    const statuses: number[] = [];
    for (let i = 0; i < 22; i++) statuses.push((await wake(tg, A, B)).status);
    expect(statuses.slice(0, 20).every((s) => s === 200)).toBe(true);
    expect(statuses[21]).toBe(429);
    // Another device has its own bucket.
    expect((await wake(tg, B, A)).status).toBe(200);
  });
});
