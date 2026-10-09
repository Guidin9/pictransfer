#!/usr/bin/env node
// Development-only mock of warpshot-agent's UI pipe (docs/ipc.md) with fake
// data, so warpshot-ui can be exercised without the real agent.
//
//   node dev/mock-agent.mjs [--alert] [--fork] [--sas-delay=4000] [--no-sas]
//                           [--offline] [--unpaired] [--suffix=dev]
//
// --suffix=dev listens on \\.\pipe\warpshot-<SID>-dev; start the UI with
// WARPSHOT_PIPE_SUFFIX=dev to use it beside a running real agent.
//
// stdin commands while running: alert | fork | sas | done | fail <code> |
//   server <connected|connecting|offline> | quit
//
// Not a security boundary: the real agent sets a user-only DACL and
// PIPE_REJECT_REMOTE_CLIENTS; this mock uses Node's default pipe security.
import { execFileSync } from "node:child_process";
import net from "node:net";
import readline from "node:readline";
import { randomBytes } from "node:crypto";

const args = new Set(process.argv.slice(2).filter((a) => !a.includes("=")));
const opt = Object.fromEntries(
  process.argv
    .slice(2)
    .filter((a) => a.includes("="))
    .map((a) => a.replace(/^--/, "").split("=")),
);
const SAS_DELAY = Number(opt["sas-delay"] ?? 4000);
const MAX_LINE = 1024 * 1024;

function currentSid() {
  const out = execFileSync("whoami", ["/user", "/fo", "csv", "/nh"], { encoding: "utf8" });
  const m = /"(S-1-[0-9-]+)"/.exec(out);
  if (!m) throw new Error("could not read the user SID");
  return m[1];
}

const hex = (n) => randomBytes(n).toString("hex");
const now = () => Date.now();
const MIN = 60_000;
const DAY = 86_400_000;

const me = { id: hex(32), name: "Windows PC", platform: "windows" };
const phone = { id: hex(32), name: "Pixel 8", platform: "android" };
const tablet = { id: hex(32), name: "Galaxy Tab S9", platform: "android" };

let paired = !args.has("--unpaired");
let server = args.has("--offline") ? "offline" : "connected";
const devices = new Map([
  [me.id, { ...me, me: true, online: true, last_seen: now(), default_target: false }],
]);
if (paired) {
  devices.set(phone.id, { ...phone, me: false, online: true, last_seen: now(), default_target: true });
  devices.set(tablet.id, { ...tablet, me: false, online: false, last_seen: now() - 3 * 3600_000, default_target: false });
}

let settings = {
  hotkey: "Ctrl+Alt+Shift+S",
  default_target: paired ? phone.id : null,
  save_dir: "C:\\Users\\Demo\\Downloads\\Warpshot",
  ask_above_mb: 500,
  relay_data: true,
  autostart: true,
  on_receive: { save: true, clipboard: true, notify: true, history: true },
  history_days: 30,
  history_items: 200,
};

const history = paired
  ? [
      { id: hex(8), ts: now() - 2 * MIN, direction: "in", peer: "Pixel 8", kind: "image", name: "Screenshot_20261009_141502.png", size: 1_482_311, path: "C:\\Users\\Demo\\Downloads\\Warpshot\\Screenshot_20261009_141502.png", ok: true },
      { id: hex(8), ts: now() - 25 * MIN, direction: "out", peer: "Pixel 8", kind: "text", size: 214, ok: true },
      { id: hex(8), ts: now() - 3 * 3600_000, direction: "in", peer: "Galaxy Tab S9", kind: "file", name: "Rapor_Q3.pdf", size: 3_904_120, path: "C:\\Users\\Demo\\Downloads\\Warpshot\\Rapor_Q3.pdf", ok: true },
      { id: hex(8), ts: now() - DAY, direction: "out", peer: "Pixel 8", kind: "image", name: "Ekran görüntüsü 2026-10-08 101210.png", size: 845_002, ok: true },
      { id: hex(8), ts: now() - DAY - 40 * MIN, direction: "in", peer: "Pixel 8", kind: "file", name: "video_20261008.mp4", size: 734_003_200, ok: false },
      { id: hex(8), ts: now() - 2 * DAY, direction: "in", peer: "Pixel 8", kind: "text", size: 58, ok: true },
      { id: hex(8), ts: now() - 4 * DAY, direction: "out", peer: "Galaxy Tab S9", kind: "file", name: "sunum.pptx", size: 12_582_912, ok: true },
    ]
  : [];

// Turkish-Q AltGr layer (Ctrl+Alt without Shift) for hotkey.check.
const ALTGR_TRQ = { Q: "@", E: "€", 1: ">", 2: "£", 3: "#", 4: "$", 5: "½", 7: "{", 8: "[", 9: "]", 0: "}", "-": "|", I: "i̇", "<": "|" };

const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function fakeQrText() {
  let s = "WARP1:";
  const bytes = randomBytes(240);
  for (const b of bytes) s += B32[b % 32];
  return s.slice(0, 6 + 384);
}

function status() {
  return { device: me, paired, server, version: "0.1.0-mock" };
}

class BadParams extends Error {}
const isObj = (v) => typeof v === "object" && v !== null && !Array.isArray(v);
const need = (cond) => {
  if (!cond) throw new BadParams();
};

const clients = new Set();
function broadcast(event, data) {
  const line = JSON.stringify({ event, data }) + "\n";
  for (const c of clients) c.write(line);
  console.log(`event ${event}`);
}

let pairTimers = [];
function clearPair() {
  pairTimers.forEach(clearTimeout);
  pairTimers = [];
}
let pairWindowOpen = false;

const methods = {
  status: () => status(),
  "devices.list": () => [...devices.values()],
  "devices.rename": (p) => {
    need(isObj(p) && typeof p.name === "string" && p.name.trim().length > 0 && p.name.length <= 64);
    me.name = p.name.trim();
    devices.get(me.id).name = me.name;
    setTimeout(() => broadcast("status", status()), 10);
    return {};
  },
  "devices.remove": (p) => {
    need(isObj(p) && typeof p.id === "string" && ["user", "lost-or-stolen", "not-me"].includes(p.reason));
    const d = devices.get(p.id);
    if (!d || d.me) throw Object.assign(new Error(), { code: "not-found" });
    devices.delete(p.id);
    if (settings.default_target === p.id) settings.default_target = [...devices.values()].find((x) => !x.me)?.id ?? null;
    syncDefault();
    return {};
  },
  "devices.set_default": (p) => {
    need(isObj(p) && typeof p.id === "string" && devices.has(p.id) && !devices.get(p.id).me);
    settings.default_target = p.id;
    syncDefault();
    return {};
  },
  "pair.start": () => {
    clearPair();
    pairWindowOpen = true;
    const expires_at = now() + 120_000;
    if (!args.has("--no-sas")) {
      pairTimers.push(setTimeout(() => broadcast("pair.sas", { sas: "482 913", peer_name: "Pixel 8a", peer_platform: "android" }), SAS_DELAY));
    }
    pairTimers.push(setTimeout(() => pairWindowOpen && broadcast("pair.failed", { code: "expired" }), 120_000));
    return { qr_text: fakeQrText(), expires_at };
  },
  "pair.confirm": (p) => {
    need(isObj(p) && typeof p.accept === "boolean");
    clearPair();
    pairWindowOpen = false;
    if (p.accept) {
      pairTimers.push(
        setTimeout(() => {
          const id = hex(32);
          devices.set(id, { id, name: "Pixel 8a", platform: "android", me: false, online: true, last_seen: now(), default_target: false });
          if (!settings.default_target) settings.default_target = id;
          syncDefault();
          paired = true;
          broadcast("pair.done", { peer_id: id });
          broadcast("status", status());
        }, 1500),
      );
    }
    return {};
  },
  "pair.cancel": () => {
    clearPair();
    pairWindowOpen = false;
    return {};
  },
  "settings.get": () => settings,
  "settings.set": (p) => {
    need(isObj(p));
    const next = structuredClone(settings);
    for (const [k, v] of Object.entries(p)) {
      if (!(k in next)) continue; // unknown fields are ignored
      if (k === "on_receive") {
        need(isObj(v));
        for (const [rk, rv] of Object.entries(v)) if (rk in next.on_receive) (need(typeof rv === "boolean"), (next.on_receive[rk] = rv));
      } else if (["relay_data", "autostart"].includes(k)) (need(typeof v === "boolean"), (next[k] = v));
      else if (["ask_above_mb", "history_days", "history_items"].includes(k)) (need(Number.isInteger(v) && v > 0), (next[k] = v));
      else if (k === "default_target") (need(v === null || (typeof v === "string" && devices.has(v))), (next[k] = v));
      else (need(typeof v === "string" && v.length > 0), (next[k] = v));
    }
    settings = next;
    syncDefault();
    return settings;
  },
  "hotkey.check": (p) => {
    need(isObj(p) && typeof p.hotkey === "string");
    const parts = p.hotkey.split("+");
    const key = parts.at(-1);
    const mods = new Set(parts.slice(0, -1));
    const valid = mods.size > 0 && !!key && !["Ctrl", "Alt", "Shift", "Win"].includes(key);
    const altgr = mods.has("Ctrl") && mods.has("Alt") && !mods.has("Shift") && !mods.has("Win");
    const produces = altgr ? ALTGR_TRQ[key] : undefined;
    return produces ? { valid, conflict: true, produces } : { valid, conflict: false };
  },
  "history.list": (p) => {
    const before = isObj(p) && typeof p.before === "number" ? p.before : Infinity;
    const limit = Math.min(isObj(p) && Number.isInteger(p.limit) ? p.limit : 50, 200);
    return history.filter((h) => h.ts < before).slice(0, limit);
  },
  "history.reveal": (p) => {
    need(isObj(p) && typeof p.id === "string");
    if (!history.some((h) => h.id === p.id && h.path)) throw Object.assign(new Error(), { code: "not-found" });
    console.log(`reveal ${p.id} (mock: Explorer is not opened)`);
    return {};
  },
  "history.delete": (p) => {
    need(isObj(p) && typeof p.id === "string");
    const i = history.findIndex((h) => h.id === p.id);
    if (i >= 0) history.splice(i, 1);
    return {};
  },
  "send.files": (p) => (need(isObj(p) && Array.isArray(p.paths)), { transfer: hex(8) }),
  "send.text": (p) => (need(isObj(p) && typeof p.text === "string"), { transfer: hex(8) }),
  "group.not_me": (p) => {
    need(isObj(p) && typeof p.id === "string");
    devices.delete(p.id);
    syncDefault();
    return {};
  },
  "debug.counters": () => ({ ws_bytes_in: 18_220, ws_bytes_out: 9_410, transfers: history.length }),
};

function syncDefault() {
  for (const d of devices.values()) d.default_target = d.id === settings.default_target;
}

function handle(sock, line) {
  let msg;
  try {
    msg = JSON.parse(line);
  } catch {
    return; // not JSON: ignore
  }
  if (!isObj(msg) || !Number.isInteger(msg.id) || typeof msg.method !== "string") return;
  const reply = (o) => sock.write(JSON.stringify({ id: msg.id, ...o }) + "\n");
  const f = methods[msg.method];
  console.log(`call ${msg.id} ${msg.method}`);
  if (!f) return reply({ error: { code: "unknown-method", message: "unknown method" } });
  try {
    reply({ result: f(msg.params) });
  } catch (e) {
    if (e instanceof BadParams) reply({ error: { code: "bad-params", message: "bad params" } });
    else reply({ error: { code: e.code ?? "internal", message: "error" } });
  }
}

const suffix = opt.suffix && /^[a-z0-9]{1,32}$/.test(opt.suffix) ? `-${opt.suffix}` : "";
const pipe = `\\\\.\\pipe\\warpshot-${currentSid()}${suffix}`;
const srv = net.createServer((sock) => {
  clients.add(sock);
  console.log(`ui connected (${clients.size})`);
  let buf = "";
  sock.setEncoding("utf8");
  sock.on("data", (chunk) => {
    buf += chunk;
    if (buf.length > MAX_LINE && !buf.includes("\n")) return sock.destroy();
    let i;
    while ((i = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, i);
      buf = buf.slice(i + 1);
      handle(sock, line);
    }
  });
  sock.on("close", () => {
    clients.delete(sock);
    console.log(`ui disconnected (${clients.size})`);
  });
  sock.on("error", () => {});
  if (args.has("--alert")) {
    setTimeout(() => sock.write(JSON.stringify({ event: "group.alert", data: { kind: "device-added", id: tablet.id, name: "Galaxy Tab S9", platform: "android", by_name: "Pixel 8" } }) + "\n"), 1500);
  }
  if (args.has("--fork")) setTimeout(() => sock.write(JSON.stringify({ event: "group.fork", data: {} }) + "\n"), 1500);
});
srv.listen(pipe, () => console.log(`mock agent listening on ${pipe}`));

const rl = readline.createInterface({ input: process.stdin });
rl.on("line", (l) => {
  const [cmd, a] = l.trim().split(/\s+/);
  if (cmd === "alert") broadcast("group.alert", { kind: "device-added", id: tablet.id, name: "Galaxy Tab S9", platform: "android", by_name: "Pixel 8" });
  else if (cmd === "fork") broadcast("group.fork", {});
  else if (cmd === "sas") broadcast("pair.sas", { sas: "482 913", peer_name: "Pixel 8a", peer_platform: "android" });
  else if (cmd === "done") broadcast("pair.done", { peer_id: phone.id });
  else if (cmd === "fail") broadcast("pair.failed", { code: a ?? "proof" });
  else if (cmd === "server" && a) ((server = a), broadcast("status", status()));
  else if (cmd === "quit") process.exit(0);
});
