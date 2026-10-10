// Test PC for Android checks in the emulator (docs/dev-setup.md section 9): a
// separate debug agent instance ("emu", WARPSHOT_INSTANCE) on the local
// `wrangler dev` server, so the user's real agent and group are untouched.
// Starts pairing, writes qr.txt and sas.txt, confirms the SAS on the PC side,
// then logs every event (except progress) to events.log. More calls: write
// {"method": ..., "params": ...} to cmd.json; the result goes to cmd.out.
//   cargo build -p warpshot-agent
//   node scripts/test-pc.mjs <work dir>        (runs until stopped)
import { execFileSync, spawn } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1")), "..");
const work = path.resolve(process.argv[2] ?? "");
if (!process.argv[2]) {
  console.error("usage: node scripts/test-pc.mjs <work dir>");
  process.exit(2);
}
const agentDir = path.join(work, "agent");
fs.mkdirSync(agentDir, { recursive: true });
fs.writeFileSync(path.join(agentDir, "config.json"), JSON.stringify({ server_url: "http://127.0.0.1:8787" }));
fs.writeFileSync(
  path.join(agentDir, "settings.json"),
  JSON.stringify({ save_dir: path.join(work, "received"), on_receive: { clipboard: false, notify: false } }),
);
const log = (s) => fs.appendFileSync(path.join(work, "events.log"), `${new Date().toISOString()} ${s}\n`);

const sid = execFileSync(path.join(process.env.SystemRoot ?? "C:\\Windows", "System32", "whoami.exe"), ["/user", "/fo", "csv", "/nh"], { encoding: "utf8" }).trim().split(",")[1].replace(/"/g, "");
const instance = "emu";
const pipeName = `\\\\.\\pipe\\warpshot-${sid}-${instance}`;
const agent = spawn(path.join(root, "target", "debug", "warpshot-agent.exe"), [], {
  env: { ...process.env, WARPSHOT_DATA_DIR: agentDir, WARPSHOT_INSTANCE: instance },
  stdio: "ignore",
});
agent.on("exit", (c) => { log(`agent exit ${c}`); process.exit(1); });

let sock;
for (let i = 0; i < 100 && !sock; i++) {
  sock = await new Promise((res) => {
    const s = net.connect(pipeName, () => res(s));
    s.once("error", () => res(undefined));
  });
  if (!sock) await new Promise((r) => setTimeout(r, 100));
}
let nextId = 1;
const pending = new Map();
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
      if (m.event !== "transfer.progress") log(`event ${m.event} ${JSON.stringify(m.data)}`);
      if (m.event === "pair.sas") {
        fs.writeFileSync(path.join(work, "sas.txt"), m.data.sas ?? JSON.stringify(m.data));
        rpc("pair.confirm", { accept: true }).then((r) => log(`pair.confirm ${JSON.stringify(r)}`));
      }
    }
  }
});
const rpc = (method, params) =>
  new Promise((resolve) => {
    const id = nextId++;
    pending.set(id, (m) => resolve(m.error ? { error: m.error } : m.result));
    sock.write(JSON.stringify({ id, method, params }) + "\n");
  });

const p = await rpc("pair.start");
fs.writeFileSync(path.join(work, "qr.txt"), p.qr_text ?? JSON.stringify(p));
log(`pair.start ok`);

const cmdFile = path.join(work, "cmd.json");
setInterval(async () => {
  if (!fs.existsSync(cmdFile)) return;
  const c = JSON.parse(fs.readFileSync(cmdFile, "utf8"));
  fs.unlinkSync(cmdFile);
  const r = await rpc(c.method, c.params);
  fs.writeFileSync(path.join(work, "cmd.out"), JSON.stringify(r, null, 1));
}, 300);
