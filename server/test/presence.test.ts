// Presence (§6.2) and push-token endpoints.
import { env } from "cloudflare:workers";
import { runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { call, connect, createGroup, device } from "./helpers/fixtures";

interface Presence {
  devices: Array<{ id: string; online: boolean; push: boolean; last_seen: number | null }>;
}

describe("push-token", () => {
  it("PUT → 204, DELETE → 204, reflected in presence", async () => {
    const [A, B] = await Promise.all([device(1), device(2)]);
    const tg = await createGroup(A, [B]);
    const put = await call(B, "PUT", tg.path("push-token"), { provider: "fcm", token: "fcm:tok-1_2" });
    expect(put.status).toBe(204);
    let p = (await (await call(A, "GET", tg.path("presence"))).json()) as Presence;
    expect(p.devices.find((d) => d.id === B.id)!.push).toBe(true);
    // Replacing the token keeps one row.
    expect((await call(B, "PUT", tg.path("push-token"), { provider: "fcm", token: "tok-2" })).status).toBe(204);
    const rows = await runInDurableObject(env.GROUPS.get(env.GROUPS.idFromName(tg.gid)), (_i, state) =>
      state.storage.sql.exec<{ push_token: string }>(`SELECT push_token FROM devices WHERE eid = ?`, B.pk).toArray(),
    );
    expect(rows).toEqual([{ push_token: "tok-2" }]);
    expect((await call(B, "DELETE", tg.path("push-token"))).status).toBe(204);
    p = (await (await call(A, "GET", tg.path("presence"))).json()) as Presence;
    expect(p.devices.find((d) => d.id === B.id)!.push).toBe(false);
  });

  it("rejects bad provider, bad characters, oversize token, non-members", async () => {
    const [A, X] = await Promise.all([device(1), device(9)]);
    const tg = await createGroup(A);
    for (const body of [
      { provider: "apns", token: "t" },
      { token: "t" },
      { provider: "fcm", token: "" },
      { provider: "fcm", token: "has space" },
      { provider: "fcm", token: "new\nline" },
      { provider: "fcm", token: 5 },
    ]) {
      expect((await call(A, "PUT", tg.path("push-token"), body)).status, JSON.stringify(body)).toBe(400);
    }
    expect((await call(A, "PUT", tg.path("push-token"), { provider: "fcm", token: "a".repeat(1025) })).status).toBe(413);
    expect((await call(A, "PUT", tg.path("push-token"), { provider: "fcm", token: "a".repeat(1024) })).status).toBe(204);
    expect((await call(X, "PUT", tg.path("push-token"), { provider: "fcm", token: "t" })).status).toBe(403);
    expect((await call(X, "DELETE", tg.path("push-token"))).status).toBe(403);
  });
});

describe("presence", () => {
  it("lists every member with online, push and minute-granular last_seen", async () => {
    const [A, B, C] = await Promise.all([device(1), device(2), device(3)]);
    const tg = await createGroup(A, [B, C]);
    const sb = await connect(tg, B);
    const p = (await (await call(A, "GET", tg.path("presence"))).json()) as Presence;
    expect(p.devices.map((d) => d.id)).toEqual([A.id, B.id, C.id]);
    const byId = Object.fromEntries(p.devices.map((d) => [d.id, d]));
    expect(byId[B.id]!.online).toBe(true);
    expect(byId[A.id]!.online).toBe(false);
    expect(byId[C.id]!.online).toBe(false);
    // A made requests; C never did.
    expect(byId[A.id]!.last_seen! % 60_000).toBe(0);
    expect(Date.now() - byId[A.id]!.last_seen!).toBeLessThan(61_000);
    expect(byId[C.id]!.last_seen).toBeNull();
    sb.ws.close(1000);
  });

  it("last_seen writes at most once per minute per device", async () => {
    const A = await device(1);
    const tg = await createGroup(A);
    for (let i = 0; i < 5; i++) await call(A, "GET", tg.path("presence"));
    const rows = await runInDurableObject(env.GROUPS.get(env.GROUPS.idFromName(tg.gid)), (_i, state) =>
      state.storage.sql.exec<{ last_seen: number }>(`SELECT last_seen FROM devices`).toArray(),
    );
    expect(rows).toHaveLength(1);
    expect(rows[0]!.last_seen % 60_000).toBe(0);
  });

  it("removed devices disappear from presence", async () => {
    const [A, B] = await Promise.all([device(1), device(2)]);
    const tg = await createGroup(A, [B]);
    const { appendOk, removeBody } = await import("./helpers/fixtures");
    await appendOk(tg, A, removeBody(tg.groupId, tg.seq + 1, tg.head, B, 0));
    const p = (await (await call(A, "GET", tg.path("presence"))).json()) as Presence;
    expect(p.devices.map((d) => d.id)).toEqual([A.id]);
  });
});
