// End-to-end test of warpshot-agent: a local `wrangler dev` server, the agent
// (driven over its named pipe like warpshot-ui) and a simulated phone
// (crates/ffi/examples/phone_sim, the same core object the Android app uses).
//
//   cd server; npx wrangler dev --local --port 8787     (in another shell)
//   cargo build -p warpshot-agent; cargo build -p warpshot-ffi --example phone_sim
//   node scripts/e2e-agent.mjs
//
// The agent runs with a temporary data dir as a separate test instance
// (WARPSHOT_INSTANCE, debug builds only: own pipe and mutex, no tray icon,
// hotkey, toasts or flyouts), so it runs next to the user's real agent;
// clipboard writes are turned off so the test does not touch the desktop.
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
const instance = `e2e${process.pid}`;
const pipeName = `\\\\.\\pipe\\warpshot-${sid}-${instance}`;

const agent = spawn(agentExe, [], {
  detached: keep,
  env: { ...process.env, WARPSHOT_DATA_DIR: agentDir, WARPSHOT_INSTANCE: instance },
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
const events = []; // every event, for the transfer checks
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
      events.push(m);
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

  // Diverge the logs: the PC appends an `update` record the phone hasn't seen.
  // Every transfer must then run the in-band log sync on both sides.
  await rpc("devices.rename", { name: "E2E PC" });
  const renamed = (await rpc("devices.list")).find((x) => x.me);
  check("devices.rename", renamed.name === "E2E PC");

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
  // A multi-chunk file (real screenshots are megabytes).
  const big = path.join(tmp, "big.bin");
  fs.writeFileSync(big, Buffer.from(Array.from({ length: 5 << 20 }, (_, i) => (i * 7919) & 255)));
  r = phone("send-file", me, big);
  const bigOut = path.join(recvDir, "big.bin");
  check("phone → PC 5 MB file", r.ok && fs.existsSync(bigOut) && fs.statSync(bigOut).size === 5 << 20, r.out.trim());
  // The agent announced that receive with progress up to the full size.
  await sleep(300); // `phone()` blocked the event loop: let the pipe events in
  const tin = events.filter((e) => e.event === "transfer.started" && e.data.direction === "in").at(-1)?.data;
  const prog = events.filter((e) => e.event === "transfer.progress" && e.data.transfer === tin?.transfer).map((e) => e.data);
  const tinDone = events.find((e) => e.event === "transfer.done" && e.data.transfer === tin?.transfer)?.data;
  check(
    "receive progress events",
    tin?.peer === "Sim Phone" && prog.length >= 2 && prog[0].done_bytes === 0 &&
      prog.at(-1).done_bytes === 5 << 20 && prog.at(-1).total_bytes === 5 << 20 && tinDone?.ok === true,
    `${prog.length} reports`,
  );
  const sims = r.out.split("\n").filter((l) => l.includes('"progress"')).map((l) => JSON.parse(l));
  check("phone send progress", sims.length >= 2 && sims.at(-1).done === 5 << 20, `${sims.length} reports`);
  const idle = await rpc("transfer.list");
  check("transfer.list empty after", idle.transfers.length === 0, JSON.stringify(idle));

  // Cancel on the PC while the phone sends 64 MB: both sides stop, no file stays.
  const huge = path.join(tmp, "huge.bin");
  fs.writeFileSync(huge, Buffer.alloc(64 << 20, 7));
  const before = fs.readdirSync(recvDir).length;
  const started = waitEvent("transfer.started");
  const firstProgress = waitEvent("transfer.progress");
  const sending = phoneAsync("send-file", me, huge);
  const st2 = await started;
  await firstProgress;
  const listed = await rpc("transfer.list");
  check(
    "transfer.list shows it",
    listed.transfers.some((x) => x.transfer === st2.transfer && x.direction === "in" && x.state === "running"),
    JSON.stringify(listed.transfers),
  );
  const cdone = waitEvent("transfer.done");
  await rpc("transfer.cancel", { transfer: st2.transfer });
  const cd = await cdone;
  const sres = await sending;
  check("PC cancel: agent reports cancelled", cd.ok === false && cd.code === "cancelled", JSON.stringify(cd));
  check("PC cancel: phone sees Cancelled", !sres.ok && sres.out.includes("Cancelled"), sres.out.trim().split("\n").at(-1));
  await sleep(300);
  const after = fs.readdirSync(recvDir);
  check("PC cancel: no partial or new file", after.length === before && !after.some((f) => f.endsWith(".part")), after.join(","));
  const unknown = await rpc("transfer.cancel", { transfer: st2.transfer }).catch((e) => e);
  check("transfer.cancel of a finished transfer", unknown.code === "not-found", JSON.stringify(unknown));

  // Cancel on the phone at its first progress report.
  const cdone2 = waitEvent("transfer.done");
  const pc2 = await phoneAsync("send-file-cancel", me, huge);
  const cd2 = await cdone2;
  check(
    "phone cancel: phone sees Cancelled",
    !pc2.ok && pc2.out.includes('"found":true') && pc2.out.includes("Cancelled"),
    pc2.out.trim().split("\n").at(-1),
  );
  check("phone cancel: agent reports cancelled", cd2.ok === false && cd2.code === "cancelled", JSON.stringify(cd2));
  await sleep(300);
  const after2 = fs.readdirSync(recvDir);
  check("phone cancel: no partial or new file", after2.length === before && !after2.some((f) => f.endsWith(".part")), after2.join(","));

  // Cancel while the wake is still on its way: a server that accepts and never
  // answers (the request timeout is 10 s); the send must end at once.
  const hole = net.createServer((c) => c.on("error", () => {}));
  await new Promise((r) => hole.listen(0, "127.0.0.1", r));
  const t0 = Date.now();
  const early = await new Promise((resolve) => {
    const p = spawn(exe("examples/phone_sim.exe"), [phoneDir, `http://127.0.0.1:${hole.address().port}`, "send-text-cancel", me, "never sent"]);
    let out = "";
    p.stdout.on("data", (d) => (out += d));
    p.stderr.on("data", (d) => (out += d));
    p.on("exit", (code) => resolve({ ok: code === 0, out, ms: Date.now() - t0 }));
  });
  hole.close();
  check(
    "phone cancel while waking: Cancelled at once",
    !early.ok && early.out.includes('"found":true') && early.out.includes("Cancelled") && early.ms < 4000,
    `${early.ms} ms, ${early.out.trim().split("\n").at(-1)}`,
  );

  const hist = await rpc("history.list", { limit: 10 });
  check("history has 3 incoming", hist.filter((h) => h.direction === "in").length === 3, hist.map((h) => h.kind).join(","));
  check("history shows the device name", hist.every((h) => h.peer === "Sim Phone" && h.peer_id === phoneId), hist.map((h) => h.peer).join(","));

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
