// Test fixtures: deterministic Ed25519 keys from fixed seeds, a canonical CBOR
// encoder, membership-record builders and §6.1 auth headers.
//
// This is the single place that produces protocol bytes for the tests. When
// the Rust core publishes docs/test-vectors/{record,server-auth,cbor-reject}.json
// (protocol §12), swap the builders here for loaders of those files.

import { exports } from "cloudflare:workers";
import { b64uEncode } from "../../src/b64u";
import { concat, hex, LABEL_RECORD, LABEL_RECORD_ID, LABEL_SERVER_AUTH, sha256, utf8 } from "../../src/util";

export const ORIGIN = "https://warpshot.test";
export const CREATE_TOKEN = "test-create-token";

// ------------------------------------------------------------------ CBOR

export type CborIn = number | bigint | boolean | string | Uint8Array | CborIn[] | { [k: number]: CborIn | undefined };

function head(major: number, n: number | bigint): Uint8Array {
  const v = BigInt(n);
  const m = major << 5;
  if (v < 24n) return new Uint8Array([m | Number(v)]);
  if (v < 0x100n) return new Uint8Array([m | 24, Number(v)]);
  if (v < 0x10000n) return new Uint8Array([m | 25, Number(v >> 8n), Number(v & 0xffn)]);
  if (v < 0x100000000n) {
    const b = new Uint8Array(5);
    b[0] = m | 26;
    new DataView(b.buffer).setUint32(1, Number(v));
    return b;
  }
  const b = new Uint8Array(9);
  b[0] = m | 27;
  new DataView(b.buffer).setBigUint64(1, v);
  return b;
}

/** Preferred-serialization encoder (shortest forms, definite lengths, sorted int keys). */
export function cbor(v: CborIn): Uint8Array {
  if (typeof v === "number" || typeof v === "bigint") {
    return BigInt(v) >= 0n ? head(0, v) : head(1, -1n - BigInt(v));
  }
  if (typeof v === "boolean") return new Uint8Array([v ? 0xf5 : 0xf4]);
  if (typeof v === "string") {
    const b = utf8(v);
    return concat(head(3, b.length), b);
  }
  if (v instanceof Uint8Array) return concat(head(2, v.length), v);
  if (Array.isArray(v)) return concat(head(4, v.length), ...v.map(cbor));
  const keys = Object.keys(v)
    .map(Number)
    .filter((k) => v[k] !== undefined)
    .sort((a, b) => a - b);
  return concat(head(5, keys.length), ...keys.flatMap((k) => [head(0, k), cbor(v[k]!)]));
}

export function fromHex(h: string): Uint8Array {
  const clean = h.replace(/\s+/g, "");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

// ------------------------------------------------------------------ keys

export interface Device {
  label: string;
  pk: Uint8Array;
  id: string;
  key: CryptoKey;
  sign(msg: Uint8Array): Promise<Uint8Array>;
}

const PKCS8_ED25519_PREFIX = fromHex("302e020100300506032b657004220420");
const deviceCache = new Map<number, Promise<Device>>();

/** Deterministic device: the Ed25519 seed is 32 bytes of `n` (n = 1..255). */
export function device(n: number): Promise<Device> {
  let d = deviceCache.get(n);
  if (d === undefined) {
    d = (async () => {
      const seed = new Uint8Array(32).fill(n);
      const key = await crypto.subtle.importKey("pkcs8", concat(PKCS8_ED25519_PREFIX, seed), { name: "Ed25519" }, true, [
        "sign",
      ]);
      const jwk = (await crypto.subtle.exportKey("jwk", key)) as JsonWebKey;
      const pk = b64uToBytes(jwk.x!);
      return {
        label: `dev${n}`,
        pk,
        id: b64uEncode(pk),
        key,
        sign: async (msg: Uint8Array) =>
          new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, key, msg)),
      };
    })();
    deviceCache.set(n, d);
  }
  return d;
}

function b64uToBytes(s: string): Uint8Array {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4);
  const bin = atob(b64);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

/** Deterministic stand-in for an X-Wing encapsulation key (the server never parses it). */
export function kemPk(n: number, len = 1216): Uint8Array {
  const b = new Uint8Array(len);
  for (let i = 0; i < len; i++) b[i] = (i * 31 + n * 7) & 0xff;
  return b;
}

let groupCounter = 0;
/** Fresh 16-byte group id; unique per call so tests never share a Durable Object. */
export function newGroupId(): Uint8Array {
  const g = new Uint8Array(16);
  crypto.getRandomValues(g);
  g[0] = groupCounter++ & 0xff;
  return g;
}

// --------------------------------------------------------------- records

export interface DeviceInfoIn {
  0?: CborIn;
  1?: CborIn;
  2?: CborIn;
  3?: CborIn;
  [k: number]: CborIn | undefined;
}

export function deviceInfo(name: string, platform = 1, n = 1): DeviceInfoIn {
  return { 0: name, 1: platform, 2: kemPk(n), 3: "0.1.0" };
}

export interface BodyIn {
  [k: number]: CborIn | undefined;
}

export interface BuiltRecord {
  bytes: Uint8Array;
  b64: string;
  body: Uint8Array;
  id: Uint8Array;
  idB64: string;
}

/** Signs `body` (a map or raw bytes) by `signer` and wraps it as a SignedRecord. */
export async function signRecord(
  body: BodyIn | Uint8Array,
  signer: Device,
  opts: { sigOverride?: Uint8Array; signerOverride?: Uint8Array } = {},
): Promise<BuiltRecord> {
  const bodyBytes = body instanceof Uint8Array ? body : cbor(body);
  const sig = opts.sigOverride ?? (await signer.sign(concat(utf8(LABEL_RECORD), bodyBytes)));
  const signerPk = opts.signerOverride ?? signer.pk;
  const bytes = cbor([bodyBytes, signerPk, sig]);
  const id = await sha256(concat(utf8(LABEL_RECORD_ID), bodyBytes, signerPk, sig));
  return { bytes, b64: b64uEncode(bytes), body: bodyBytes, id, idB64: b64uEncode(id) };
}

export function genesisBody(groupId: Uint8Array, founder: Device, createdAt = Date.now(), n = 1): BodyIn {
  return { 0: 1, 1: groupId, 2: 0, 4: createdAt, 5: 0, 6: founder.pk, 7: deviceInfo(founder.label, 1, n) };
}

export function addBody(groupId: Uint8Array, seq: number, prev: Uint8Array, subject: Device, platform = 2): BodyIn {
  return { 0: 1, 1: groupId, 2: seq, 3: prev, 4: Date.now(), 5: 1, 6: subject.pk, 7: deviceInfo(subject.label, platform) };
}

export function removeBody(groupId: Uint8Array, seq: number, prev: Uint8Array, subject: Device, reason = 0): BodyIn {
  return { 0: 1, 1: groupId, 2: seq, 3: prev, 4: Date.now(), 5: 2, 6: subject.pk, 8: reason };
}

export function updateBody(groupId: Uint8Array, seq: number, prev: Uint8Array, subject: Device, name: string, platform = 1): BodyIn {
  return { 0: 1, 1: groupId, 2: seq, 3: prev, 4: Date.now(), 5: 3, 6: subject.pk, 7: deviceInfo(name, platform) };
}

// ------------------------------------------------------------ §6.1 auth

export async function authHeader(
  dev: Device,
  method: string,
  pathAndQuery: string,
  body: Uint8Array,
  ts = Date.now(),
): Promise<string> {
  const msg = concat(utf8(LABEL_SERVER_AUTH), utf8(`${method}\n${pathAndQuery}\n${ts}\n${hex(await sha256(body))}`));
  const sig = await dev.sign(msg);
  return `WARP1 id=${dev.id}, ts=${ts}, sig=${b64uEncode(sig)}`;
}

export interface CallOpts {
  ts?: number;
  headers?: Record<string, string>;
  /** Overrides the Authorization header entirely (null = omit). */
  auth?: string | null;
  rawBody?: Uint8Array;
  createToken?: string | null;
}

/** Signed request through the Worker's default export. */
export async function call(
  dev: Device | null,
  method: string,
  pathAndQuery: string,
  body?: unknown,
  opts: CallOpts = {},
): Promise<Response> {
  const bodyBytes = opts.rawBody ?? (body === undefined ? new Uint8Array(0) : utf8(JSON.stringify(body)));
  const headers: Record<string, string> = { ...opts.headers };
  if (opts.auth !== undefined) {
    if (opts.auth !== null) headers.authorization = opts.auth;
  } else if (dev !== null) {
    headers.authorization = await authHeader(dev, method, pathAndQuery, bodyBytes, opts.ts);
  }
  if (pathAndQuery === "/v1/groups" && opts.createToken !== null) {
    headers["warpshot-create-token"] = opts.createToken ?? CREATE_TOKEN;
  }
  return exports.default.fetch(
    new Request(ORIGIN + pathAndQuery, {
      method,
      headers,
      body: method === "GET" || method === "HEAD" ? undefined : bodyBytes,
    }),
  );
}

// -------------------------------------------------------------- groups

export interface TestGroup {
  groupId: Uint8Array;
  gid: string;
  seq: number;
  head: Uint8Array;
  records: BuiltRecord[];
  path(endpoint: string): string;
}

/** Creates a group founded by `founder` and adds `members` (each add signed by the founder). */
export async function createGroup(founder: Device, members: Device[] = []): Promise<TestGroup> {
  const groupId = newGroupId();
  const gid = b64uEncode(groupId);
  const g = await signRecord(genesisBody(groupId, founder), founder);
  const res = await call(founder, "POST", "/v1/groups", { genesis: g.b64 });
  if (res.status !== 201) throw new Error(`create failed: ${res.status} ${await res.text()}`);
  const tg: TestGroup = {
    groupId,
    gid,
    seq: 0,
    head: g.id,
    records: [g],
    path: (e: string) => `/v1/groups/${gid}/${e}`,
  };
  for (const m of members) await appendOk(tg, founder, addBody(groupId, tg.seq + 1, tg.head, m));
  return tg;
}

export async function append(tg: TestGroup, signer: Device, body: BodyIn): Promise<{ res: Response; rec: BuiltRecord }> {
  const rec = await signRecord(body, signer);
  const res = await call(signer, "POST", tg.path("log"), { record: rec.b64 });
  if (res.status === 200) {
    tg.seq += 1;
    tg.head = rec.id;
    tg.records.push(rec);
  }
  return { res, rec };
}

export async function appendOk(tg: TestGroup, signer: Device, body: BodyIn): Promise<BuiltRecord> {
  const { res, rec } = await append(tg, signer, body);
  if (res.status !== 200) throw new Error(`append failed: ${res.status} ${await res.text()}`);
  return rec;
}

// ------------------------------------------------------------ WebSocket

export interface TestSocket {
  ws: WebSocket;
  messages: string[];
  closed: Promise<{ code: number; reason: string }>;
  /** Resolves with the next message (or the first already buffered and unread). */
  next(timeoutMs?: number): Promise<string>;
}

export async function connect(tg: TestGroup, dev: Device): Promise<TestSocket> {
  const res = await call(dev, "GET", tg.path("ws"), undefined, { headers: { upgrade: "websocket" } });
  if (res.status !== 101 || res.webSocket === null) throw new Error(`upgrade failed: ${res.status}`);
  return wrapSocket(res.webSocket);
}

export function wrapSocket(ws: WebSocket): TestSocket {
  ws.accept();
  const messages: string[] = [];
  let read = 0;
  let waiter: (() => void) | null = null;
  ws.addEventListener("message", (e) => {
    messages.push(typeof e.data === "string" ? e.data : "<binary>");
    waiter?.();
  });
  const closed = new Promise<{ code: number; reason: string }>((resolve) => {
    ws.addEventListener("close", (e) => {
      resolve({ code: e.code, reason: e.reason });
      waiter?.();
    });
  });
  return {
    ws,
    messages,
    closed,
    async next(timeoutMs = 2000) {
      const deadline = Date.now() + timeoutMs;
      while (read >= messages.length) {
        const remaining = deadline - Date.now();
        if (remaining <= 0) throw new Error("timeout waiting for message");
        await new Promise<void>((resolve) => {
          waiter = resolve;
          setTimeout(resolve, Math.min(remaining, 50));
        });
        waiter = null;
      }
      return messages[read++]!;
    },
  };
}
