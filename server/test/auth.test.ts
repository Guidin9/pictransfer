// §6.1 request authentication and operator admission, end to end through the Worker.
import { abortAllDurableObjects } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { checkCreateToken } from "../src/auth";
import { ApiError, utf8 } from "../src/util";
import {
  authHeader,
  call,
  createGroup,
  device,
  genesisBody,
  newGroupId,
  signRecord,
} from "./helpers/fixtures";

async function errorOf(res: Response): Promise<[number, string]> {
  const j = (await res.json()) as { error: string };
  return [res.status, j.error];
}

describe("operator admission (GROUP_CREATE_TOKEN)", () => {
  it("creation without the token → 403 not-allowed", async () => {
    const A = await device(1);
    const g = await signRecord(genesisBody(newGroupId(), A), A);
    expect(await errorOf(await call(A, "POST", "/v1/groups", { genesis: g.b64 }, { createToken: null }))).toEqual([
      403,
      "not-allowed",
    ]);
  });

  it("creation with a wrong token → 403 not-allowed", async () => {
    const A = await device(1);
    const g = await signRecord(genesisBody(newGroupId(), A), A);
    for (const t of ["wrong", "test-create-toke", "test-create-token-", ""]) {
      expect(await errorOf(await call(A, "POST", "/v1/groups", { genesis: g.b64 }, { createToken: t }))).toEqual([
        403,
        "not-allowed",
      ]);
    }
  });

  it("the token is checked before any other processing", async () => {
    // Malformed body and no Authorization at all: still 403, not 400/401.
    const res = await call(null, "POST", "/v1/groups", undefined, {
      rawBody: utf8("not json"),
      createToken: "wrong",
    });
    expect(await errorOf(res)).toEqual([403, "not-allowed"]);
  });

  it("creation with the right token → 201", async () => {
    const A = await device(1);
    const groupId = newGroupId();
    const g = await signRecord(genesisBody(groupId, A), A);
    const res = await call(A, "POST", "/v1/groups", { genesis: g.b64 });
    expect(res.status).toBe(201);
  });

  it("checkCreateToken: unset admits; empty secret refuses; constant-time match", async () => {
    const req = (h?: string) =>
      new Request("https://x/v1/groups", { method: "POST", headers: h === undefined ? {} : { "warpshot-create-token": h } });
    await expect(checkCreateToken(undefined, req())).resolves.toBeUndefined();
    await expect(checkCreateToken("", req(""))).rejects.toBeInstanceOf(ApiError);
    await expect(checkCreateToken("s3cret", req("s3cret"))).resolves.toBeUndefined();
    await expect(checkCreateToken("s3cret", req())).rejects.toMatchObject({ code: "not-allowed" });
    await expect(checkCreateToken("s3cret", req("s3cre"))).rejects.toMatchObject({ code: "not-allowed" });
  });
});

describe("§6.1 signature checks", () => {
  it("valid request → 200", async () => {
    const A = await device(1);
    const tg = await createGroup(A);
    expect((await call(A, "GET", tg.path("log"))).status).toBe(200);
  });

  it("missing Authorization → 401", async () => {
    const A = await device(1);
    const tg = await createGroup(A);
    expect(await errorOf(await call(A, "GET", tg.path("log"), undefined, { auth: null }))).toEqual([401, "unauthenticated"]);
  });

  it("malformed Authorization headers → 401", async () => {
    const A = await device(1);
    const tg = await createGroup(A);
    const good = await authHeader(A, "GET", tg.path("log"), new Uint8Array(0));
    const ts = /ts=(\d+)/.exec(good)![1]!;
    const variants = [
      good.replace("WARP1 ", "warp1 "),
      good.replace("WARP1 ", "WARP1  "),
      good.replace(", ts=", ",ts="),
      good.replace(`ts=${ts}`, `ts=0${ts}`),
      good.replace(`ts=${ts}`, `ts=+${ts}`),
      good.replace("id=", "id=A"),
      good.replace(/id=[^,]+/, `id=${A.id.slice(0, 42)}A`), // non-canonical trailing bits or other key
      good + ", x=1",
      good.replace(/sig=.*/, "sig=" + "A".repeat(86)),
      `Bearer ${good}`,
      good.replace(/sig=(.*)/, (_m, s: string) => `sig=${s}==`),
    ];
    for (const auth of variants) {
      const [status] = await errorOf(await call(A, "GET", tg.path("log"), undefined, { auth }));
      expect(status, auth).toBe(401);
    }
  });

  it("ts outside ±120 s → 401; inside → ok", async () => {
    const A = await device(1);
    const tg = await createGroup(A);
    const now = Date.now();
    expect((await call(A, "GET", tg.path("log"), undefined, { ts: now - 121_000 })).status).toBe(401);
    expect((await call(A, "GET", tg.path("log"), undefined, { ts: now + 121_000 })).status).toBe(401);
    expect((await call(A, "GET", tg.path("log"), undefined, { ts: now - 110_000 })).status).toBe(200);
    expect((await call(A, "GET", tg.path("log"), undefined, { ts: now + 110_000 })).status).toBe(200);
  });

  it("replayed (id, ts, sig) → 401", async () => {
    const A = await device(1);
    const tg = await createGroup(A);
    const auth = await authHeader(A, "GET", tg.path("presence"), new Uint8Array(0));
    expect((await call(A, "GET", tg.path("presence"), undefined, { auth })).status).toBe(200);
    expect(await errorOf(await call(A, "GET", tg.path("presence"), undefined, { auth }))).toEqual([401, "unauthenticated"]);
  });

  it("the replay cache survives a restart of the object", async () => {
    const A = await device(1);
    const tg = await createGroup(A);
    const auth = await authHeader(A, "GET", tg.path("presence"), new Uint8Array(0));
    expect((await call(A, "GET", tg.path("presence"), undefined, { auth })).status).toBe(200);
    await abortAllDurableObjects();
    expect((await call(A, "GET", tg.path("presence"), undefined, { auth })).status).toBe(401);
  });

  it("signature bound to method, path, query and body", async () => {
    const A = await device(1);
    const B = await device(2);
    const tg = await createGroup(A, [B]);
    const body = { provider: "fcm", token: "tok" };
    const authPut = await authHeader(A, "PUT", tg.path("push-token"), utf8(JSON.stringify(body)));
    // different body
    expect((await call(A, "PUT", tg.path("push-token"), { provider: "fcm", token: "tok2" }, { auth: authPut })).status).toBe(401);
    // different method
    const authGet = await authHeader(A, "GET", tg.path("log"), new Uint8Array(0));
    expect((await call(A, "DELETE", tg.path("push-token"), undefined, { auth: authGet })).status).toBe(401);
    // different query
    expect((await call(A, "GET", tg.path("log") + "?after=0", undefined, { auth: authGet })).status).toBe(401);
    // signed by B but claiming A's id
    const authB = await authHeader(B, "GET", tg.path("log"), new Uint8Array(0));
    const forged = authB.replace(/id=[^,]+/, `id=${A.id}`);
    expect((await call(A, "GET", tg.path("log"), undefined, { auth: forged })).status).toBe(401);
  });

  it("small-order key with a lax-valid signature → 401", async () => {
    const A = await device(1);
    const tg = await createGroup(A);
    const ts = Date.now();
    const identity = "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const sig = "AQ" + "A".repeat(84); // R = identity, S = 0
    const auth = `WARP1 id=${identity}, ts=${ts}, sig=${sig}`;
    expect((await call(null, "GET", tg.path("log"), undefined, { auth })).status).toBe(401);
  });

  it("valid signature from a non-member → 403 not-member", async () => {
    const A = await device(1);
    const X = await device(9);
    const tg = await createGroup(A);
    expect(await errorOf(await call(X, "GET", tg.path("log")))).toEqual([403, "not-member"]);
    expect(await errorOf(await call(X, "POST", tg.path("wake"), { to: A.id, env: "AAAA", ttl: 60 }))).toEqual([
      403,
      "not-member",
    ]);
  });

  it("POST /v1/groups must be signed by the genesis signer", async () => {
    const A = await device(1);
    const X = await device(9);
    const g = await signRecord(genesisBody(newGroupId(), A), A);
    expect(await errorOf(await call(X, "POST", "/v1/groups", { genesis: g.b64 }))).toEqual([403, "not-member"]);
  });

  it("unknown group → 404 no-group (after a valid signature)", async () => {
    const A = await device(1);
    const gid = "AAAAAAAAAAAAAAAAAAAAAA";
    expect(await errorOf(await call(A, "GET", `/v1/groups/${gid}/log`))).toEqual([404, "no-group"]);
    expect((await call(A, "GET", `/v1/groups/${gid}/log`, undefined, { auth: null })).status).toBe(401);
  });
});
