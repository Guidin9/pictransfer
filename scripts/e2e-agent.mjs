// End-to-end test of warpshot-agent: a local `wrangler dev` server, the agent
// (driven over its named pipe like warpshot-ui) and a simulated phone
// (crates/ffi/examples/phone_sim, the same core object the Android app uses).
//
//   cd server; npx wrangler dev --local --port 8787     (in another shell)
//   cargo build -p warpshot-agent -p warpshot-ffi --example phone_sim
//   node scripts/e2e-agent.mjs
//
// The agent runs with a temporary data dir; clipboard writes and toasts are
// turned off so the test does not touch the desktop session.
import { execFileSync, spawn } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1")), "..");
const exe = (p) => path.join(root, "target", "debug", p);
const agentExe = path.join(root, "target", process.env.E2E_PROFILE ?? "debug", "warpshot-agent.exe");
// E2E_KEEP_AGENT=1 leaves the paired agent running (for scripts/measure-idle.ps1).
const keep = process.env.E2E_KEEP_AGENT === "1";
const server = process.env.WARPSHOT_SERVER_URL ?? "http://127.0.0.1:8787";
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "warpshot-e2e-"));
const agentDir = path.join(tmp, "agent");
const phoneDir = path.join(tmp, "phone");
const recvDir = path.join(tmp, "received");
fs.mkdirSync(agentDir, { recursive: true });
fs.mkdirSync(phoneDir, { recursive: true });
fs.writeFileSync(path.join(agentDir, "config.json"), JSON.stringify({ server_url: server }));
fs.writeFileSync(
  path.join(agentDir, "settings.json"),
  JSON.stringify({ save_dir: recvDir, on_receive: { clipboard: false, notify: false } }),
);

let failed = 0;
const check = (name, ok, extra = "") => {
  console.log(`${ok ? "PASS" : "FAIL"} ${name}${extra ? " — " + extra : ""}`);
  if (!ok) failed++;
};

const sid = execFileSync(path.join(process.env.SystemRoot ?? "C:\Windows", "System32", "whoami.exe"), ["/user", "/fo", "csv", "/nh"], { encoding: "utf8" }).trim().split(",")[1].replace(/"/g, "");
const pipeName = `\\\\.\\pipe\\warpshot-${sid}`;

const agent = spawn(agentExe, [], {
  detached: keep,
  env: { ...process.env, WARPSHOT_DATA_DIR: agentDir },
  stdio: "ignore",
});

function phone(...args) {
  try {
    return { ok: true, out: execFileSync(exe("examples/phone_sim.exe"), [phoneDir, server, ...args], { encoding: "utf8", timeout: 60000 }) };
  } catch (e) {
    return { ok: false, out: String(e.stdout ?? "") + String(e.stderr ?? "") };
  }
}

function phoneAsync(...args) {
  return new Promise((resolve) => {
    const p = spawn(exe("examples/phone_sim.exe"), [phoneDir, server, ...args]);
    let out = "";
    p.stdout.on("data", (d) => (out += d));
    p.stderr.on("data", (d) => (out += d));
    p.on("exit", (code) => resolve({ ok: code === 0, out }));
  });
}

async function connect() {
  for (let i = 0; i < 100; i++) {
    try {
      return await new Promise((res, rej) => {
        const s = net.connect(pipeName, () => res(s));
        s.once("error", rej);
      });
    } catch {
      await new Promise((r) => setTimeout(r, 100));
    }
  }
  throw new Error("agent pipe not available");
}

const sock = await connect();
let nextId = 1;
const pending = new Map();
const waiters = [];
let buf = "";
sock.on("data", (d) => {
  buf += d;
  let i;
  while ((i = buf.indexOf("\n")) >= 0) {
    const line = buf.slice(0, i);
    buf = buf.slice(i + 1);
    const m = JSON.parse(line);
    if (m.id !== undefined && pending.has(m.id)) {
      pending.get(m.id)(m);
      pending.delete(m.id);
    } else if (m.event) {
      for (const w of [...waiters]) if (w.name === m.event) { w.resolve(m.data); waiters.splice(waiters.indexOf(w), 1); }
    }
  }
});
const rpc = (method, params) =>
  new Promise((resolve, reject) => {
    const id = nextId++;
    pending.set(id, (m) => (m.error ? reject(m.error) : resolve(m.result)));
    sock.write(JSON.stringify({ id, method, params }) + "\n");
  });
const waitEvent = (name, ms = 60000) =>
  new Promise((resolve, reject) => {
    const w = { name, resolve };
    waiters.push(w);
    setTimeout(() => reject(new Error(`timeout waiting for ${name}`)), ms);
  });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

try {
  const st = await rpc("status");
  check("status", st.device.platform === "windows" && st.paired === false, JSON.stringify(st.server));
  const bad = await rpc("nope").catch((e) => e);
  check("unknown method", bad.code === "unknown-method");

  // Pairing: agent displays, phone scans, the agent confirms the SAS.
  const { qr_text } = await rpc("pair.start");
  check("pair.start returns a QR", qr_text.startsWith("WARP1"));
  const sas = waitEvent("pair.sas");
  const done = waitEvent("pair.done");
  const ph = phoneAsync("pair", qr_text);
  const s = await sas;
  await rpc("pair.confirm", { accept: true });
  const d = await done;
  const pr = await ph;
  check("pairing", pr.ok && pr.out.includes(s.sas), `sas ${s.sas}`);
  const phoneId = d.peer_id;

  const devs = await rpc("devices.list");
  check("devices.list has both", devs.length === 2 && devs.some((x) => x.id === phoneId && !x.me));
  const me = devs.find((x) => x.me).id;
  await sleep(1500); // the agent's WebSocket connects after pairing

  // Phone → PC: text, then an image file.
  let r = phone("send-text", me, "hello from the phone");
  check("phone → PC text", r.ok, r.out.trim());
  const png = path.join(tmp, "shot.png");
  fs.writeFileSync(png, Buffer.from("89504e470d0a1a0a0000000d4948445200000001000000010806000000" + "1f15c4890000000a49444154789c6300010000050001" + "0d0a2db40000000049454e44ae426082", "hex"));
  r = phone("send-file", me, png);
  check("phone → PC image", r.ok, r.out.trim());
  const saved = fs.existsSync(recvDir) ? fs.readdirSync(recvDir) : [];
  check("image saved", saved.includes("shot.png"), saved.join(","));
  let motw = false;
  try {
    motw = fs.readFileSync(path.join(recvDir, "shot.png:Zone.Identifier"), "utf8").includes("ZoneId=3");
  } catch {}
  check("Mark-of-the-Web", motw);
  const hist = await rpc("history.list", { limit: 10 });
  check("history has 2 incoming", hist.filter((h) => h.direction === "in").length === 2, hist.map((h) => h.kind).join(","));

  // PC → phone: the simulated phone has no WebSocket and no push token → offline.
  const tdone = waitEvent("transfer.done");
  await rpc("send.text", { text: "hi phone" });
  const t = await tdone;
  check("PC → offline phone reports offline", t.ok === false && t.code === "offline", JSON.stringify(t));

  // Settings round trip and validation.
  const s2 = await rpc("settings.set", { ask_above_mb: 100 });
  check("settings.set", s2.ask_above_mb === 100);
  const e2 = await rpc("settings.set", { ask_above_mb: "x" }).catch((e) => e);
  check("settings.set rejects bad types", e2.code === "bad-params");

  const c = await rpc("debug.counters");
  check("debug.counters", c.ws_connects >= 1, JSON.stringify(c));
} catch (e) {
  check("run", false, String(e?.message ?? JSON.stringify(e)));
} finally {
  sock.destroy();
  if (keep) {
    agent.unref();
    console.log(`agent pid ${agent.pid} left running; data dir ${tmp}`);
  } else {
    agent.kill();
    await sleep(500);
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  }
}
console.log(failed ? `${failed} FAILED` : "ALL PASSED");
process.exit(failed ? 1 : 0);
