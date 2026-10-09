// §6.3 WebSocket: Hibernation API, auto-response keepalive, log push, wake
// delivery, client requests, removal (`bye`).
import { env } from "cloudflare:workers";
import { runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { b64uEncode } from "../src/b64u";
import {
  addBody,
  appendOk,
  call,
  connect,
  createGroup,
  device,
  removeBody,
} from "./helpers/fixtures";

const ENV = "QUJD" + "x".repeat(96); // opaque b64u envelope stand-in

describe("upgrade", () => {
  it("requires auth, membership and an Upgrade header", async () => {
    const [A, X] = await Promise.all([device(1), device(9)]);
    const tg = await createGroup(A);
    expect((await call(A, "GET", tg.path("ws"), undefined, { auth: null, headers: { upgrade: "websocket" } })).status).toBe(401);
    expect((await call(X, "GET", tg.path("ws"), undefined, { headers: { upgrade: "websocket" } })).status).toBe(403);
    expect((await call(A, "GET", tg.path("ws"))).status).toBe(400);
    const s = await connect(tg, A);
    s.ws.close(1000);
  });

  it("accepts with the Hibernation API, tagged with the device id", async () => {
    const A = await device(1);
    const tg = await createGroup(A);
    const s = await connect(tg, A);
    const tags = await runInDurableObject(env.GROUPS.get(env.GROUPS.idFromName(tg.gid)), (_i, state) =>
      state.getWebSockets().map((w) => state.getTags(w)),
    );
    expect(tags).toEqual([[A.id]]);
    s.ws.close(1000);
  });

  it("keepalive: 'p' is answered with 'o' by the auto-response", async () => {
    const A = await device(1);
    const tg = await createGroup(A);
    const s = await connect(tg, A);
    s.ws.send("p");
    expect(await s.next()).toBe("o");
    const ts = await runInDurableObject(env.GROUPS.get(env.GROUPS.idFromName(tg.gid)), (_i, state) =>
      state.getWebSocketAutoResponseTimestamp(state.getWebSockets()[0]!),
    );
    expect(ts).not.toBeNull();
    s.ws.close(1000);
  });
});

describe("messages", () => {
  it("log push after every accepted append", async () => {
    const [A, B, C] = await Promise.all([device(1), device(2), device(3)]);
    const tg = await createGroup(A, [B]);
    const sa = await connect(tg, A);
    const sb = await connect(tg, B);
    const rec = await appendOk(tg, A, addBody(tg.groupId, tg.seq + 1, tg.head, C));
    const expected = { t: "log", records: [rec.b64], head: { seq: tg.seq, id: rec.idB64 } };
    expect(JSON.parse(await sa.next())).toEqual(expected);
    expect(JSON.parse(await sb.next())).toEqual(expected);
    sa.ws.close(1000);
    sb.ws.close(1000);
  });

  it("wake over HTTP is delivered on the target's socket without sender identity", async () => {
    const [A, B] = await Promise.all([device(1), device(2)]);
    const tg = await createGroup(A, [B]);
    const sb = await connect(tg, B);
    const res = await call(A, "POST", tg.path("wake"), { to: B.id, env: ENV, ttl: 60 });
    expect(await res.json()).toEqual({ via: "ws" });
    expect(JSON.parse(await sb.next())).toEqual({ t: "wake", env: ENV });
    sb.ws.close(1000);
  });

  it("wake over WebSocket → ack with via", async () => {
    const [A, B] = await Promise.all([device(1), device(2)]);
    const tg = await createGroup(A, [B]);
    const sa = await connect(tg, A);
    const sb = await connect(tg, B);
    sb.ws.send(JSON.stringify({ t: "wake", id: 7, to: A.id, env: ENV, ttl: 60 }));
    expect(JSON.parse(await sa.next())).toEqual({ t: "wake", env: ENV });
    expect(JSON.parse(await sb.next())).toEqual({ t: "ack", id: 7, via: "ws" });
    sb.ws.send(JSON.stringify({ t: "wake", id: 8, to: A.id, env: "x".repeat(3801), ttl: 60 }));
    expect(JSON.parse(await sb.next())).toEqual({ t: "err", id: 8, code: "too-large" });
    sa.ws.close(1000);
    sb.ws.close(1000);
  });

  it("presence request", async () => {
    const [A, B] = await Promise.all([device(1), device(2)]);
    const tg = await createGroup(A, [B]);
    const sa = await connect(tg, A);
    sa.ws.send(JSON.stringify({ t: "presence", id: 1 }));
    const m = JSON.parse(await sa.next()) as { t: string; id: number; devices: Array<{ id: string; online: boolean }> };
    expect(m.t).toBe("presence");
    expect(m.id).toBe(1);
    expect(m.devices.map((d) => [d.id, d.online])).toEqual([
      [A.id, true],
      [B.id, false],
    ]);
    sa.ws.close(1000);
  });

  it("log-get request (reply carries the id)", async () => {
    const [A, B] = await Promise.all([device(1), device(2)]);
    const tg = await createGroup(A, [B]);
    const sa = await connect(tg, A);
    sa.ws.send(JSON.stringify({ t: "log-get", id: 3, after: 0 }));
    expect(JSON.parse(await sa.next())).toEqual({
      t: "log",
      id: 3,
      records: [tg.records[1]!.b64],
      head: { seq: 1, id: b64uEncode(tg.head) },
    });
    sa.ws.send(JSON.stringify({ t: "log-get", id: 4, after: -1 }));
    expect(JSON.parse(await sa.next())).toEqual({ t: "err", id: 4, code: "bad-request" });
    sa.ws.close(1000);
  });

  it("unknown t is ignored; malformed messages get err", async () => {
    const A = await device(1);
    const tg = await createGroup(A);
    const sa = await connect(tg, A);
    sa.ws.send(JSON.stringify({ t: "future-thing", id: 1 }));
    sa.ws.send("not json");
    expect(JSON.parse(await sa.next())).toEqual({ t: "err", id: null, code: "bad-request" });
    sa.ws.send(JSON.stringify({ t: "presence" })); // missing id
    expect(JSON.parse(await sa.next())).toEqual({ t: "err", id: null, code: "bad-request" });
    sa.ws.send(JSON.stringify({ t: "presence", id: -1 }));
    expect(JSON.parse(await sa.next())).toEqual({ t: "err", id: null, code: "bad-request" });
    sa.ws.send(JSON.stringify([1]));
    expect(JSON.parse(await sa.next())).toEqual({ t: "err", id: null, code: "bad-request" });
    sa.ws.send(new Uint8Array([1, 2]));
    expect(JSON.parse(await sa.next())).toEqual({ t: "err", id: null, code: "bad-request" });
    sa.ws.close(1000);
  });

  it("a message above 64 KiB closes the socket (1009)", async () => {
    const A = await device(1);
    const tg = await createGroup(A);
    const sa = await connect(tg, A);
    sa.ws.send(JSON.stringify({ t: "presence", id: 1, pad: "x".repeat(64 * 1024) }));
    expect((await sa.closed).code).toBe(1009);
  });

  it("removal: bye + close for the removed device, push token deleted, log push to the rest", async () => {
    const [A, B] = await Promise.all([device(1), device(2)]);
    const tg = await createGroup(A, [B]);
    expect((await call(B, "PUT", tg.path("push-token"), { provider: "fcm", token: "tokB" })).status).toBe(204);
    const sa = await connect(tg, A);
    const sb = await connect(tg, B);
    const rec = await appendOk(tg, A, removeBody(tg.groupId, tg.seq + 1, tg.head, B, 1));
    expect(JSON.parse(await sb.next())).toEqual({ t: "bye", code: "not-member" });
    expect((await sb.closed).code).toBe(1008);
    expect(sb.messages.some((m) => m.includes('"t":"log"'))).toBe(false);
    expect(JSON.parse(await sa.next())).toEqual({ t: "log", records: [rec.b64], head: { seq: tg.seq, id: rec.idB64 } });
    const rows = await runInDurableObject(env.GROUPS.get(env.GROUPS.idFromName(tg.gid)), (_i, state) =>
      state.storage.sql.exec(`SELECT push_token FROM devices WHERE eid = ?`, B.pk).toArray(),
    );
    expect(rows).toEqual([]);
    // Its later requests are rejected, including a new socket.
    expect((await call(B, "GET", tg.path("ws"), undefined, { headers: { upgrade: "websocket" } })).status).toBe(403);
    sa.ws.close(1000);
  });

  it("a member leaving (self-remove) gets bye too", async () => {
    const [A, B] = await Promise.all([device(1), device(2)]);
    const tg = await createGroup(A, [B]);
    const sb = await connect(tg, B);
    await appendOk(tg, B, removeBody(tg.groupId, tg.seq + 1, tg.head, B, 2));
    expect(JSON.parse(await sb.next())).toEqual({ t: "bye", code: "not-member" });
  });
});
