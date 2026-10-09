// §6.2 routing, group creation, log store with compare-and-swap (§6.6), errors (§6.8).
import { env, exports } from "cloudflare:workers";
import { abortAllDurableObjects, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { b64uEncode } from "../src/b64u";
import { utf8 } from "../src/util";
import {
  addBody,
  append,
  appendOk,
  call,
  createGroup,
  device,
  genesisBody,
  newGroupId,
  ORIGIN,
  removeBody,
  signRecord,
  updateBody,
} from "./helpers/fixtures";

async function errorOf(res: Response): Promise<[number, string]> {
  const j = (await res.json()) as { error: string };
  return [res.status, j.error];
}

describe("routing", () => {
  it("GET /v1/health → 200 without auth", async () => {
    const res = await exports.default.fetch(`${ORIGIN}/v1/health`);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ status: "ok" });
  });

  it("unknown paths and wrong methods → 400 bad-request", async () => {
    const A = await device(1);
    const tg = await createGroup(A);
    expect(await errorOf(await exports.default.fetch(`${ORIGIN}/`))).toEqual([400, "bad-request"]);
    expect(await errorOf(await exports.default.fetch(`${ORIGIN}/v1/health`, { method: "POST" }))).toEqual([400, "bad-request"]);
    expect(await errorOf(await exports.default.fetch(`${ORIGIN}/v1/groups`))).toEqual([400, "bad-request"]);
    expect(await errorOf(await call(A, "GET", `/v1/groups/${tg.gid}/nope`))).toEqual([400, "bad-request"]);
    expect(await errorOf(await call(A, "DELETE", tg.path("log")))).toEqual([400, "bad-request"]);
    expect(await errorOf(await call(A, "GET", tg.path("wake")))).toEqual([400, "bad-request"]);
    expect(await errorOf(await call(A, "GET", tg.path("presence") + "?x=1"))).toEqual([400, "bad-request"]);
  });

  it("non-canonical or wrong-length gid → 400", async () => {
    const A = await device(1);
    expect(await errorOf(await call(A, "GET", `/v1/groups/AAAAAAAAAAAAAAAAAAAAAB/log`))).toEqual([400, "bad-request"]);
    expect(await errorOf(await call(A, "GET", `/v1/groups/AAAAAAAAAAAAAAAAAAAAA/log`))).toEqual([400, "bad-request"]);
  });

  it("body above the cap → 413 too-large", async () => {
    const A = await device(1);
    const tg = await createGroup(A);
    const res = await call(A, "POST", tg.path("log"), { record: "A".repeat(20_000) });
    expect(await errorOf(res)).toEqual([413, "too-large"]);
  });
});

describe("POST /v1/groups", () => {
  it("creates the group: 201 {group, head}", async () => {
    const A = await device(1);
    const groupId = newGroupId();
    const g = await signRecord(genesisBody(groupId, A), A);
    const res = await call(A, "POST", "/v1/groups", { genesis: g.b64 });
    expect(res.status).toBe(201);
    expect(await res.json()).toEqual({ group: b64uEncode(groupId), head: { seq: 0, id: g.idB64 } });
  });

  it("second creation → 409 exists", async () => {
    const A = await device(1);
    const groupId = newGroupId();
    const g = await signRecord(genesisBody(groupId, A), A);
    expect((await call(A, "POST", "/v1/groups", { genesis: g.b64 })).status).toBe(201);
    const g2 = await signRecord(genesisBody(groupId, A, Date.now() + 1), A);
    expect(await errorOf(await call(A, "POST", "/v1/groups", { genesis: g2.b64 }))).toEqual([409, "exists"]);
  });

  it("invalid genesis → 422 invalid-record (bad signature, add op, bad CBOR)", async () => {
    const A = await device(1);
    const groupId = newGroupId();
    const g = await signRecord(genesisBody(groupId, A), A, { sigOverride: new Uint8Array(64).fill(1) });
    expect(await errorOf(await call(A, "POST", "/v1/groups", { genesis: g.b64 }))).toEqual([422, "invalid-record"]);
    const op = await signRecord({ ...genesisBody(groupId, A), 5: 1 }, A);
    expect(await errorOf(await call(A, "POST", "/v1/groups", { genesis: op.b64 }))).toEqual([422, "invalid-record"]);
    expect(await errorOf(await call(A, "POST", "/v1/groups", { genesis: "AAAA" }))).toEqual([422, "invalid-record"]);
    // The failed attempts did not create the group.
    const ok = await signRecord(genesisBody(groupId, A), A);
    expect((await call(A, "POST", "/v1/groups", { genesis: ok.b64 })).status).toBe(201);
  });

  it("malformed body → 400", async () => {
    const A = await device(1);
    expect(await errorOf(await call(A, "POST", "/v1/groups", { genesis: 5 }))).toEqual([400, "bad-request"]);
    expect(await errorOf(await call(A, "POST", "/v1/groups", { genesis: "AA==" }))).toEqual([400, "bad-request"]);
    expect(await errorOf(await call(A, "POST", "/v1/groups", undefined, { rawBody: utf8("[1]") }))).toEqual([400, "bad-request"]);
  });

  it("an unknown group creates no storage (probe)", async () => {
    const A = await device(1);
    const gid = b64uEncode(newGroupId());
    expect((await call(A, "GET", `/v1/groups/${gid}/log`)).status).toBe(404);
    const tables = await runInDurableObject(env.GROUPS.get(env.GROUPS.idFromName(gid)), (_i, state) =>
      state.storage.sql.exec(`SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE '\\_%' ESCAPE '\\'`).toArray(),
    );
    expect(tables).toEqual([]);
  });
});

describe("log store", () => {
  it("GET log returns all records and the head; ?after filters", async () => {
    const [A, B, C] = await Promise.all([device(1), device(2), device(3)]);
    const tg = await createGroup(A, [B, C]);
    const all = (await (await call(A, "GET", tg.path("log"))).json()) as { records: string[]; head: unknown };
    expect(all.records).toEqual(tg.records.map((r) => r.b64));
    expect(all.head).toEqual({ seq: 2, id: b64uEncode(tg.head) });
    const after = (await (await call(B, "GET", tg.path("log") + "?after=1")).json()) as { records: string[] };
    expect(after.records).toEqual([tg.records[2]!.b64]);
    const none = (await (await call(B, "GET", tg.path("log") + "?after=99")).json()) as { records: string[] };
    expect(none.records).toEqual([]);
  });

  it("GET log rejects malformed ?after", async () => {
    const A = await device(1);
    const tg = await createGroup(A);
    for (const q of ["?after=01", "?after=-1", "?after=", "?after=1&after=2", "?before=1", "?after=1.0", "?", "?after=1&"]) {
      // The raw request target is used, so even a bare "?" is seen and rejected.
      expect(await errorOf(await call(A, "GET", tg.path("log") + q)), q).toEqual([400, "bad-request"]);
    }
  });

  it("append → 200 {head}; stale head → 409 head-moved with the current head", async () => {
    const [A, B, C] = await Promise.all([device(1), device(2), device(3)]);
    const tg = await createGroup(A, [B]);
    const staleSeq = tg.seq;
    const staleHead = tg.head;
    const rec = await appendOk(tg, B, updateBody(tg.groupId, tg.seq + 1, tg.head, B, "B2", 2));
    expect(tg.seq).toBe(2);
    const { res } = await append(tg, A, addBody(tg.groupId, staleSeq + 1, staleHead, C));
    expect(res.status).toBe(409);
    expect(await res.json()).toEqual({ error: "head-moved", head: { seq: 2, id: rec.idB64 } });
  });

  it("append with seq beyond the head → 409 head-moved", async () => {
    const [A, C] = await Promise.all([device(1), device(3)]);
    const tg = await createGroup(A);
    const { res } = await append(tg, A, addBody(tg.groupId, 5, tg.head, C));
    expect((await errorOf(res))[1]).toBe("head-moved");
  });

  it("invalid record → 422 (non-member signer, other group, bad sig, garbage)", async () => {
    const [A, B, C, X] = await Promise.all([device(1), device(2), device(3), device(9)]);
    const tg = await createGroup(A, [B]);
    // Signed by a non-member, but sent by member B.
    const byX = await signRecord(addBody(tg.groupId, tg.seq + 1, tg.head, C), X);
    expect(await errorOf(await call(B, "POST", tg.path("log"), { record: byX.b64 }))).toEqual([422, "invalid-record"]);
    const other = await signRecord(addBody(newGroupId(), tg.seq + 1, tg.head, C), A);
    expect(await errorOf(await call(A, "POST", tg.path("log"), { record: other.b64 }))).toEqual([422, "invalid-record"]);
    const badSig = await signRecord(addBody(tg.groupId, tg.seq + 1, tg.head, C), A, { sigOverride: new Uint8Array(64).fill(3) });
    expect(await errorOf(await call(A, "POST", tg.path("log"), { record: badSig.b64 }))).toEqual([422, "invalid-record"]);
    expect(await errorOf(await call(A, "POST", tg.path("log"), { record: "gw" }))).toEqual([422, "invalid-record"]);
    expect(await errorOf(await call(A, "POST", tg.path("log"), { record: 1 }))).toEqual([400, "bad-request"]);
    // Nothing was appended.
    const log = (await (await call(A, "GET", tg.path("log"))).json()) as { head: { seq: number } };
    expect(log.head.seq).toBe(1);
  });

  it("concurrent appends on the same head: exactly one wins", async () => {
    const [A, B, C, D] = await Promise.all([device(1), device(2), device(3), device(4)]);
    const tg = await createGroup(A, [B]);
    const r1 = await signRecord(addBody(tg.groupId, tg.seq + 1, tg.head, C), A);
    const r2 = await signRecord(addBody(tg.groupId, tg.seq + 1, tg.head, D), B);
    const [x, y] = await Promise.all([
      call(A, "POST", tg.path("log"), { record: r1.b64 }),
      call(B, "POST", tg.path("log"), { record: r2.b64 }),
    ]);
    expect([x.status, y.status].sort()).toEqual([200, 409]);
    const log = (await (await call(A, "GET", tg.path("log"))).json()) as { records: string[] };
    expect(log.records.length).toBe(3);
  });

  it("state is rebuilt from storage after the object restarts", async () => {
    const [A, B, C] = await Promise.all([device(1), device(2), device(3)]);
    const tg = await createGroup(A, [B]);
    await abortAllDurableObjects();
    // B is still a member and the head is still known.
    await appendOk(tg, B, addBody(tg.groupId, tg.seq + 1, tg.head, C));
    expect((await call(C, "GET", tg.path("log"))).status).toBe(200);
  });

  it("storage holds exactly the §6.7 tables plus the replay cache", async () => {
    const A = await device(1);
    const tg = await createGroup(A);
    const names = await runInDurableObject(env.GROUPS.get(env.GROUPS.idFromName(tg.gid)), (_i, state) =>
      state.storage.sql
        .exec<{ name: string }>(`SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE '\\_%' ESCAPE '\\'`)
        .toArray()
        .map((r) => r.name)
        .sort(),
    );
    expect(names).toEqual(["devices", "meta", "records", "replay"]);
  });

  it("append rate limit per device → 429 rate-limited", async () => {
    const [A, B] = await Promise.all([device(1), device(2)]);
    const tg = await createGroup(A, [B]);
    let limited = false;
    for (let i = 0; i < 12; i++) {
      const { res } = await append(tg, B, updateBody(tg.groupId, tg.seq + 1, tg.head, B, `B${i}`, 2));
      if (res.status === 429) {
        expect((await res.json()) as unknown).toEqual({ error: "rate-limited" });
        limited = true;
        break;
      }
      expect(res.status).toBe(200);
    }
    expect(limited).toBe(true);
  });

  it("removed device's later requests are rejected (403)", async () => {
    const [A, B] = await Promise.all([device(1), device(2)]);
    const tg = await createGroup(A, [B]);
    await appendOk(tg, A, removeBody(tg.groupId, tg.seq + 1, tg.head, B, 1));
    expect(await errorOf(await call(B, "GET", tg.path("log")))).toEqual([403, "not-member"]);
  });
});
