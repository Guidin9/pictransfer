// One SQLite-backed Durable Object per group (`idFromName(gid)`), ADR 0004.
//
// Responsibilities (protocol §6): request auth (replay cache + membership),
// log store with compare-and-swap (§6.6), WebSocket hub with Hibernation
// (§6.3), wake routing WS → FCM (§6.4/§6.5), presence, push tokens, removal.
//
// Logging: route names, status codes and timings only. Never envelopes,
// tokens, records, headers or addresses.

import { DurableObject } from "cloudflare:workers";
import { AuthInfo, replayKey, requestTarget, splitTarget, verifyRequestSignature } from "./auth";
import { B64U_RE, b64uDecode, b64uDecodeExact, b64uEncode } from "./b64u";
import { AccessToken, fcmConfig, FcmConfig, mintAccessToken, sendFcm } from "./fcm";
import {
  applyTrusted,
  buildsOnHead,
  emptyState,
  LogState,
  OP_REMOVE,
  parseSignedRecord,
  ParsedRecord,
  RecordError,
  validateRecord,
} from "./record";
import { APPEND_LIMIT, Limiter, MISC_LIMIT, WAKE_LIMIT } from "./ratelimit";
import {
  ApiError,
  bytesEqual,
  errorResponse,
  json,
  LIMITS,
  logEvent,
  noContent,
  parseJsonObject,
  readBodyCapped,
  utf8,
} from "./util";

export interface Env {
  GROUPS: DurableObjectNamespace<GroupDO>;
  /** Secret: operator admission token (§6.1). Optional. */
  GROUP_CREATE_TOKEN?: string;
  /** Secret: FCM service-account JSON (§6.5). Optional; without it wakes never use push. */
  FCM_SERVICE_ACCOUNT?: string;
  /** TESTS ONLY: replaces the Google FCM/OAuth hosts with a fake. Never set in production. */
  FCM_BASE_URL?: string;
}

const MINUTE_MS = 60_000;
const MAX_SOCKETS_PER_DEVICE = 4;
const MAX_TTL_S = 86_400;
const FCM_TOKEN_KEY = "fcm_oauth";
/** SPEC-GAP: §6.6 says "sends bye"; the close code is unspecified. 1008 = policy violation. */
const CLOSE_REMOVED = 1008;
const CLOSE_TOO_LARGE = 1009;

interface Head {
  seq: number;
  id: string;
}

interface SocketAttachment {
  id: string;
}

type Via = "ws" | "push" | "none";

function floorMinute(ms: number): number {
  return Math.floor(ms / MINUTE_MS) * MINUTE_MS;
}

function isWsId(v: unknown): v is number {
  return typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
}

/** Canonical decimal uint (no sign, no leading zeros). */
function parseCanonicalUint(s: string): number | null {
  if (!/^(0|[1-9][0-9]{0,15})$/.test(s)) return null;
  const n = Number(s);
  return Number.isSafeInteger(n) ? n : null;
}

export class GroupDO extends DurableObject<Env> {
  private readonly sql: SqlStorage;
  private state: LogState | null | undefined = undefined;
  private readonly wakeLimiter = new Limiter(WAKE_LIMIT);
  private readonly appendLimiter = new Limiter(APPEND_LIMIT);
  private readonly miscLimiter = new Limiter(MISC_LIMIT);
  /** Last persisted last_seen minute per device, to write at most once per minute. */
  private readonly seenMinute = new Map<string, number>();
  private fcmToken: AccessToken | null = null;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    // Runs on every (re)activation; the runtime answers "p" with "o" without
    // waking the object (§6.3).
    ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair("p", "o"));
  }

  // ---------------------------------------------------------------- storage

  private createSchema(): void {
    // §6.7 tables.
    this.sql.exec(`CREATE TABLE IF NOT EXISTS records (seq INTEGER PRIMARY KEY, id BLOB NOT NULL, bytes BLOB NOT NULL)`);
    this.sql.exec(
      `CREATE TABLE IF NOT EXISTS devices (eid BLOB PRIMARY KEY, push_provider TEXT, push_token TEXT, last_seen INTEGER)`,
    );
    this.sql.exec(
      `CREATE TABLE IF NOT EXISTS meta (head_seq INTEGER NOT NULL, head_id BLOB NOT NULL, created_at INTEGER NOT NULL)`,
    );
    // SPEC-GAP: §6.7 lists "records, devices, meta. Nothing else", but §6.1
    // requires rejecting a repeated (id, ts, sig) within the window, and
    // in-memory state is lost whenever the object hibernates (seconds). The
    // stricter reading keeps the replay cache durable: 16-byte hashes with an
    // expiry, purged after the 120 s window. No content, no addresses.
    this.sql.exec(`CREATE TABLE IF NOT EXISTS replay (k BLOB PRIMARY KEY, exp INTEGER NOT NULL)`);
  }

  /** Loads (once per activation) the log state, or null if the group does not exist. */
  private loadState(): LogState | null {
    if (this.state !== undefined) return this.state;
    let rows: Array<{ seq: number; id: ArrayBuffer; bytes: ArrayBuffer }>;
    try {
      rows = this.sql
        .exec<{ seq: number; id: ArrayBuffer; bytes: ArrayBuffer }>(`SELECT seq, id, bytes FROM records ORDER BY seq`)
        .toArray();
    } catch {
      // No table: this object was never initialized. Reading does not create storage.
      this.state = null;
      return null;
    }
    if (rows.length === 0) {
      this.state = null;
      return null;
    }
    let st: LogState | null = null;
    for (const row of rows) {
      // Stored records were validated at append time; a decode failure here
      // means storage corruption, which is an internal error.
      const r = parseSignedRecord(new Uint8Array(row.bytes));
      if (st === null) st = emptyState(r.fields.groupId);
      st = applyTrusted(st, r, new Uint8Array(row.id));
    }
    this.state = st;
    return st;
  }

  private head(st: LogState): Head {
    return { seq: st.seq, id: st.headId === null ? "" : b64uEncode(st.headId) };
  }

  private recordsAfter(after: number, maxBytes = Infinity): string[] {
    const out: string[] = [];
    let total = 0;
    for (const row of this.sql.exec<{ bytes: ArrayBuffer }>(
      `SELECT bytes FROM records WHERE seq > ? ORDER BY seq`,
      after,
    )) {
      const s = b64uEncode(new Uint8Array(row.bytes));
      total += s.length + 3;
      if (total > maxBytes && out.length > 0) break;
      out.push(s);
    }
    return out;
  }

  private touchLastSeen(idB64: string, now: number): void {
    const minute = floorMinute(now);
    if (this.seenMinute.get(idB64) === minute) return;
    const eid = b64uDecodeExact(idB64, 32);
    if (eid === null) return;
    this.sql.exec(
      `INSERT INTO devices (eid, last_seen) VALUES (?, ?)
       ON CONFLICT(eid) DO UPDATE SET last_seen = excluded.last_seen
       WHERE last_seen IS NULL OR last_seen < excluded.last_seen`,
      eid,
      minute,
    );
    this.seenMinute.set(idB64, minute);
  }

  // ------------------------------------------------------------------- auth

  /** Records (id, ts, sig) in the replay cache; throws when it was already seen. */
  private async checkReplay(a: AuthInfo, now: number): Promise<void> {
    const k = await replayKey(a);
    this.sql.exec(`DELETE FROM replay WHERE exp < ?`, now);
    const cur = this.sql.exec(`INSERT OR IGNORE INTO replay (k, exp) VALUES (?, ?)`, k, a.ts + LIMITS.authWindowMs + 1);
    if (cur.rowsWritten === 0) throw new ApiError("unauthenticated");
  }

  /**
   * §6.1 for an existing group: window + strict signature → group exists →
   * replay cache → membership. Returns the authenticated member and state.
   */
  private async authMember(req: Request, body: Uint8Array): Promise<{ a: AuthInfo; st: LogState; now: number }> {
    const now = Date.now();
    const a = await verifyRequestSignature(req, body, now);
    const st = this.loadState();
    if (st === null) throw new ApiError("no-group");
    // Membership before the replay cache, so non-members cause no storage writes.
    if (!st.members.has(a.idB64)) throw new ApiError("not-member");
    await this.checkReplay(a, now);
    // Re-read: the state may have changed during the awaits above.
    const cur = this.loadState();
    if (cur === null || !cur.members.has(a.idB64)) throw new ApiError("not-member");
    this.touchLastSeen(a.idB64, now);
    return { a, st: cur, now };
  }

  // ------------------------------------------------------------------ fetch

  async fetch(req: Request): Promise<Response> {
    const started = Date.now();
    let route = "unknown";
    try {
      const { path, query } = splitTarget(requestTarget(req));
      const parts = path.split("/"); // ["", "v1", "groups", gid?, endpoint?]
      if (parts.length === 3) {
        route = "create";
        return await this.createGroup(req);
      }
      const gid = b64uDecodeExact(parts[3], 16);
      const endpoint = parts[4] ?? "";
      if (gid === null) throw new ApiError("bad-request");
      route = `${req.method} ${endpoint}`;
      if (query !== null && !(endpoint === "log" && req.method === "GET")) throw new ApiError("bad-request");
      const st = this.loadState();
      if (st !== null && !bytesEqual(st.groupId, gid)) throw new ApiError("internal");
      switch (`${req.method} ${endpoint}`) {
        case "GET log":
          return await this.getLog(req, query);
        case "POST log":
          return await this.appendLog(req);
        case "POST wake":
          return await this.httpWake(req);
        case "PUT push-token":
          return await this.putPushToken(req);
        case "DELETE push-token":
          return await this.deletePushToken(req);
        case "GET presence":
          return await this.getPresence(req);
        case "GET ws":
          return await this.upgrade(req);
        default:
          throw new ApiError("bad-request");
      }
    } catch (e) {
      if (e instanceof ApiError) {
        if (e.code === "internal") logEvent("error", { route, code: e.code, ms: Date.now() - started });
        return errorResponse(e.code, e.extra);
      }
      logEvent("error", { route, code: "internal", kind: e instanceof Error ? e.name : "unknown" });
      return errorResponse("internal");
    }
  }

  // ------------------------------------------------------------- endpoints

  /** POST /v1/groups (§6.2). The Worker already checked the admission token. */
  private async createGroup(req: Request): Promise<Response> {
    const body = await readBodyCapped(req, LIMITS.httpBody);
    const now = Date.now();
    const a = await verifyRequestSignature(req, body, now);
    const j = parseJsonObject(body);
    if (typeof j.genesis !== "string") throw new ApiError("bad-request");
    const bytes = b64uDecode(j.genesis, LIMITS.recordBytes);
    if (bytes === null) throw new ApiError(j.genesis.length > (LIMITS.recordBytes * 4) / 3 + 4 ? "too-large" : "bad-request");
    let rec: ParsedRecord;
    try {
      rec = parseSignedRecord(bytes);
    } catch (e) {
      if (e instanceof RecordError) throw new ApiError("invalid-record");
      throw e;
    }
    // §6.1: for POST /v1/groups, id MUST be the genesis signer.
    if (!bytesEqual(a.id, rec.signer)) throw new ApiError("not-member");
    if (this.loadState() !== null) throw new ApiError("exists");
    let res: { state: LogState; id: Uint8Array };
    try {
      res = await validateRecord(emptyState(rec.fields.groupId), rec, now);
    } catch (e) {
      if (e instanceof RecordError) throw new ApiError("invalid-record");
      throw e;
    }
    // CAS: another creation may have won during the awaits.
    this.state = undefined;
    if (this.loadState() !== null) throw new ApiError("exists");
    this.ctx.storage.transactionSync(() => {
      this.createSchema();
      this.sql.exec(`INSERT INTO records (seq, id, bytes) VALUES (0, ?, ?)`, res.id, rec.bytes);
      this.sql.exec(`INSERT INTO meta (head_seq, head_id, created_at) VALUES (0, ?, ?)`, res.id, now);
    });
    await this.checkReplay(a, now);
    this.state = res.state;
    this.touchLastSeen(a.idB64, now);
    return json({ group: b64uEncode(rec.fields.groupId), head: this.head(res.state) }, 201);
  }

  private async getLog(req: Request, query: string | null): Promise<Response> {
    // The only accepted query is exactly `after=<canonical decimal>`.
    let after = -1;
    if (query !== null) {
      const n = query.startsWith("after=") ? parseCanonicalUint(query.slice(6)) : null;
      if (n === null) throw new ApiError("bad-request");
      after = n;
    }
    const body = await readBodyCapped(req, 0);
    const { st } = await this.authMember(req, body);
    return json({ records: this.recordsAfter(after), head: this.head(st) });
  }

  private async appendLog(req: Request): Promise<Response> {
    const body = await readBodyCapped(req, LIMITS.httpBody);
    const { a, now } = await this.authMember(req, body);
    if (!this.appendLimiter.take(a.idB64, now)) throw new ApiError("rate-limited");
    const j = parseJsonObject(body);
    if (typeof j.record !== "string") throw new ApiError("bad-request");
    const bytes = b64uDecode(j.record, LIMITS.recordBytes);
    if (bytes === null) throw new ApiError(j.record.length > (LIMITS.recordBytes * 4) / 3 + 4 ? "too-large" : "bad-request");
    let rec: ParsedRecord;
    try {
      rec = parseSignedRecord(bytes);
    } catch (e) {
      if (e instanceof RecordError) throw new ApiError("invalid-record");
      throw e;
    }
    const snapshot = this.loadState();
    if (snapshot === null) throw new ApiError("no-group");
    // §4.4 / §6.6 compare-and-swap. A record for another group is invalid,
    // not a head mismatch.
    if (!bytesEqual(rec.fields.groupId, snapshot.groupId)) throw new ApiError("invalid-record");
    if (!buildsOnHead(snapshot, rec)) throw new ApiError("head-moved", { head: this.head(snapshot) });
    let res: { state: LogState; id: Uint8Array };
    try {
      res = await validateRecord(snapshot, rec, now);
    } catch (e) {
      if (e instanceof RecordError) throw new ApiError("invalid-record");
      throw e;
    }
    // The validation awaited crypto; another append may have landed. The
    // check and the write below run without an await in between.
    if (this.state !== snapshot) {
      const cur = this.loadState();
      throw new ApiError("head-moved", cur === null ? undefined : { head: this.head(cur) });
    }
    this.ctx.storage.transactionSync(() => {
      this.sql.exec(`INSERT INTO records (seq, id, bytes) VALUES (?, ?, ?)`, rec.fields.seq, res.id, rec.bytes);
      this.sql.exec(`UPDATE meta SET head_seq = ?, head_id = ?`, rec.fields.seq, res.id);
      if (rec.fields.op === OP_REMOVE) {
        // §6.6: delete the removed device's push token (and its row).
        this.sql.exec(`DELETE FROM devices WHERE eid = ?`, rec.fields.subject);
      }
    });
    this.state = res.state;
    const head = this.head(res.state);
    if (rec.fields.op === OP_REMOVE) this.onRemoved(b64uEncode(rec.fields.subject));
    this.broadcast(JSON.stringify({ t: "log", records: [b64uEncode(rec.bytes)], head }));
    return json({ head });
  }

  /** §6.6: bye + close the removed device's sockets. Its later requests fail membership. */
  private onRemoved(idB64: string): void {
    this.seenMinute.delete(idB64);
    for (const ws of this.ctx.getWebSockets(idB64)) {
      try {
        ws.send(JSON.stringify({ t: "bye", code: "not-member" }));
        ws.close(CLOSE_REMOVED, "not-member");
      } catch {
        // Already closing.
      }
    }
  }

  private broadcast(msg: string): void {
    const st = this.state;
    for (const ws of this.ctx.getWebSockets()) {
      const att = ws.deserializeAttachment() as SocketAttachment | null;
      if (att === null || st === null || st === undefined || !st.members.has(att.id)) continue;
      try {
        ws.send(msg);
      } catch {
        // Closing socket.
      }
    }
  }

  private async httpWake(req: Request): Promise<Response> {
    const body = await readBodyCapped(req, LIMITS.httpBody);
    const { a, now } = await this.authMember(req, body);
    const via = await this.wake(a.idB64, parseJsonObject(body), now);
    return json({ via });
  }

  /** §6.4 wake routing. `msg` holds `to`, `env`, `ttl`. */
  private async wake(fromB64: string, msg: Record<string, unknown>, now: number): Promise<Via> {
    const to = b64uDecodeExact(msg.to, 32);
    if (to === null) throw new ApiError("bad-request");
    const env = msg.env;
    if (typeof env !== "string") throw new ApiError("bad-request");
    // §6.4: the server MUST NOT inspect env beyond its size. The alphabet and
    // length checks only enforce that it is a b64u string of allowed size.
    if (env.length > LIMITS.envelopeB64u) throw new ApiError("too-large");
    if (env.length === 0 || env.length % 4 === 1 || !B64U_RE.test(env)) throw new ApiError("bad-request");
    const ttl = msg.ttl;
    // SPEC-GAP: §6.2 gives `ttl` in seconds without a range. §6.5 uses 60 and
    // 86400; stricter reading: an integer in 1..86400.
    if (typeof ttl !== "number" || !Number.isSafeInteger(ttl) || ttl < 1 || ttl > MAX_TTL_S) {
      throw new ApiError("bad-request");
    }
    const toB64 = b64uEncode(to);
    const st = this.loadState();
    // SPEC-GAP: §6.4 says `to` MUST be a member but names no error code.
    // 403 not-member is used.
    if (st === null || !st.members.has(toB64)) throw new ApiError("not-member");
    if (!this.wakeLimiter.take(fromB64, now)) throw new ApiError("rate-limited");

    // 1. Open socket.
    const wsMsg = JSON.stringify({ t: "wake", env });
    let sent = false;
    for (const ws of this.ctx.getWebSockets(toB64)) {
      try {
        ws.send(wsMsg);
        sent = true;
      } catch {
        // Closing socket; try the next one or push.
      }
    }
    if (sent) return "ws";

    // 2. Push token.
    const row = this.sql
      .exec<{ push_provider: string | null; push_token: string | null }>(
        `SELECT push_provider, push_token FROM devices WHERE eid = ?`,
        to,
      )
      .toArray()[0];
    if (row === undefined || row.push_provider !== "fcm" || row.push_token === null) return "none";
    const cfg = fcmConfig(this.env.FCM_SERVICE_ACCOUNT, this.env.FCM_BASE_URL);
    if (cfg === null) return "none";
    const pushToken = row.push_token;
    const started = Date.now();
    let r = await sendFcm(cfg, await this.accessToken(cfg, false), pushToken, env, ttl);
    if (r.result === "auth") r = await sendFcm(cfg, await this.accessToken(cfg, true), pushToken, env, ttl);
    if (r.result === "ok") return "push";
    if (r.result === "token-invalid") {
      // §6.5: delete an UNREGISTERED or invalid token.
      this.sql.exec(
        `UPDATE devices SET push_provider = NULL, push_token = NULL WHERE eid = ? AND push_token = ?`,
        to,
        pushToken,
      );
      logEvent("fcm", { result: r.result, status: r.status, ms: Date.now() - started });
      return "none";
    }
    logEvent("fcm", { result: r.result, status: r.status, ms: Date.now() - started });
    throw new ApiError("internal");
  }

  /** OAuth token, cached in DO storage for < 1 h (architecture §5). */
  private async accessToken(cfg: FcmConfig, forceRefresh: boolean): Promise<string> {
    const now = Date.now();
    if (!forceRefresh) {
      if (this.fcmToken === null) this.fcmToken = (await this.ctx.storage.get<AccessToken>(FCM_TOKEN_KEY)) ?? null;
      if (this.fcmToken !== null && this.fcmToken.exp > now) return this.fcmToken.token;
    }
    const t = await mintAccessToken(cfg, now);
    if (t === null) {
      logEvent("fcm", { result: "oauth-failed" });
      throw new ApiError("internal");
    }
    this.fcmToken = t;
    // SPEC-GAP: §6.7 lists no place for the OAuth token, but architecture §5
    // caches it in DO storage. Stored with the key-value API, not a table.
    await this.ctx.storage.put(FCM_TOKEN_KEY, t);
    return t.token;
  }

  private async putPushToken(req: Request): Promise<Response> {
    const body = await readBodyCapped(req, LIMITS.httpBody);
    const { a } = await this.authMember(req, body);
    const j = parseJsonObject(body);
    if (j.provider !== "fcm") throw new ApiError("bad-request");
    const token = j.token;
    if (typeof token !== "string" || !/^[A-Za-z0-9_:\-.]+$/.test(token)) throw new ApiError("bad-request");
    if (token.length > LIMITS.pushToken) throw new ApiError("too-large");
    this.sql.exec(
      `INSERT INTO devices (eid, push_provider, push_token) VALUES (?, 'fcm', ?)
       ON CONFLICT(eid) DO UPDATE SET push_provider = 'fcm', push_token = excluded.push_token`,
      a.id,
      token,
    );
    return noContent();
  }

  private async deletePushToken(req: Request): Promise<Response> {
    const body = await readBodyCapped(req, 0);
    const { a } = await this.authMember(req, body);
    this.sql.exec(`UPDATE devices SET push_provider = NULL, push_token = NULL WHERE eid = ?`, a.id);
    return noContent();
  }

  private presence(st: LogState): Array<{ id: string; online: boolean; push: boolean; last_seen: number | null }> {
    const rows = new Map<string, { push: boolean; last_seen: number | null }>();
    for (const r of this.sql.exec<{ eid: ArrayBuffer; push_token: string | null; last_seen: number | null }>(
      `SELECT eid, push_token, last_seen FROM devices`,
    )) {
      rows.set(b64uEncode(new Uint8Array(r.eid)), { push: r.push_token !== null, last_seen: r.last_seen });
    }
    const out = [];
    for (const id of st.members.keys()) {
      const sockets = this.ctx.getWebSockets(id);
      let last = rows.get(id)?.last_seen ?? null;
      // Keepalive pings are answered without waking the object; the runtime
      // still records when it last auto-responded.
      for (const ws of sockets) {
        const t = this.ctx.getWebSocketAutoResponseTimestamp(ws);
        if (t !== null) last = Math.max(last ?? 0, floorMinute(t.getTime()));
      }
      out.push({ id, online: sockets.length > 0, push: rows.get(id)?.push ?? false, last_seen: last });
    }
    return out;
  }

  private async getPresence(req: Request): Promise<Response> {
    const body = await readBodyCapped(req, 0);
    const { st } = await this.authMember(req, body);
    return json({ devices: this.presence(st) });
  }

  // -------------------------------------------------------------- WebSocket

  private async upgrade(req: Request): Promise<Response> {
    if (req.headers.get("upgrade")?.toLowerCase() !== "websocket") throw new ApiError("bad-request");
    const body = await readBodyCapped(req, 0);
    const { a } = await this.authMember(req, body);
    // Bound sockets per device: close the oldest beyond the cap.
    const existing = this.ctx.getWebSockets(a.idB64);
    for (let i = 0; i <= existing.length - MAX_SOCKETS_PER_DEVICE; i++) {
      try {
        existing[i]!.close(1000, "replaced");
      } catch {
        // Already closing.
      }
    }
    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];
    this.ctx.acceptWebSocket(server, [a.idB64]);
    server.serializeAttachment({ id: a.idB64 } satisfies SocketAttachment);
    return new Response(null, { status: 101, webSocket: client });
  }

  private sendErr(ws: WebSocket, id: number | null, code: string): void {
    try {
      ws.send(JSON.stringify({ t: "err", id, code }));
    } catch {
      // Closing socket.
    }
  }

  async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    const now = Date.now();
    const att = ws.deserializeAttachment() as SocketAttachment | null;
    const st = this.loadState();
    if (att === null || st === null || !st.members.has(att.id)) {
      try {
        ws.send(JSON.stringify({ t: "bye", code: "not-member" }));
        ws.close(CLOSE_REMOVED, "not-member");
      } catch {
        // Closing.
      }
      return;
    }
    const size = typeof message === "string" ? message.length : message.byteLength;
    if (size > LIMITS.wsMessage || (typeof message === "string" && utf8(message).length > LIMITS.wsMessage)) {
      ws.close(CLOSE_TOO_LARGE, "too-large");
      return;
    }
    this.touchLastSeen(att.id, now);
    if (typeof message !== "string") return this.sendErr(ws, null, "bad-request");
    let m: unknown;
    try {
      m = JSON.parse(message);
    } catch {
      return this.sendErr(ws, null, "bad-request");
    }
    if (typeof m !== "object" || m === null || Array.isArray(m)) return this.sendErr(ws, null, "bad-request");
    const msg = m as Record<string, unknown>;
    const t = msg.t;
    if (t !== "wake" && t !== "presence" && t !== "log-get") return; // §6.3: unknown t is ignored.
    if (!isWsId(msg.id)) return this.sendErr(ws, null, "bad-request");
    const id = msg.id;
    try {
      if (t === "wake") {
        const via = await this.wake(att.id, msg, now);
        ws.send(JSON.stringify({ t: "ack", id, via }));
        return;
      }
      if (!this.miscLimiter.take(att.id, now)) throw new ApiError("rate-limited");
      if (t === "presence") {
        ws.send(JSON.stringify({ t: "presence", id, devices: this.presence(st) }));
        return;
      }
      // log-get
      if (!isWsId(msg.after)) throw new ApiError("bad-request");
      // SPEC-GAP: §6.3 defines no reply type for log-get; the reply is a
      // `log` message carrying the request id. It is truncated to stay under
      // the 64 KiB message limit; the client repeats with `after` = last seq.
      const records = this.recordsAfter(msg.after, LIMITS.wsMessage - 512);
      ws.send(JSON.stringify({ t: "log", id, records, head: this.head(st) }));
    } catch (e) {
      if (e instanceof ApiError) return this.sendErr(ws, id, e.code);
      logEvent("error", { route: "ws", code: "internal", kind: e instanceof Error ? e.name : "unknown" });
      this.sendErr(ws, id, "internal");
    }
  }

  async webSocketClose(ws: WebSocket, code: number, _reason: string, _wasClean: boolean): Promise<void> {
    const att = ws.deserializeAttachment() as SocketAttachment | null;
    const st = this.loadState();
    if (att !== null && st !== null && st.members.has(att.id)) this.touchLastSeen(att.id, Date.now());
    try {
      ws.close(code === 1005 || code === 1006 ? 1000 : code, "bye");
    } catch {
      // Already closed.
    }
  }

  async webSocketError(_ws: WebSocket, _error: unknown): Promise<void> {
    logEvent("ws-error");
  }
}
