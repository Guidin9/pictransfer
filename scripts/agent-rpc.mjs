// One-shot call to the running agent over its named pipe (docs/ipc.md):
//   node scripts/agent-rpc.mjs <method> [json-params]
import { execFileSync } from "node:child_process";
import net from "node:net";
import path from "node:path";

const whoami = path.join(process.env.SystemRoot ?? "C:\\Windows", "System32", "whoami.exe");
const sid = execFileSync(whoami, ["/user", "/fo", "csv", "/nh"], { encoding: "utf8" }).trim().split(",")[1].replace(/"/g, "");
const [method, params] = process.argv.slice(2);
const s = net.connect(`\\\\.\\pipe\\warpshot-${sid}`, () => {
  s.write(JSON.stringify({ id: 1, method, params: params ? JSON.parse(params) : undefined }) + "\n");
});
let buf = "";
s.on("data", (d) => {
  buf += d;
  for (const line of buf.split("\n").slice(0, -1)) {
    const m = JSON.parse(line);
    if (m.id === 1) {
      console.log(JSON.stringify(m.result ?? m.error));
      s.destroy();
    }
  }
  buf = buf.slice(buf.lastIndexOf("\n") + 1);
});
s.on("error", (e) => {
  console.error(e.message);
  process.exit(1);
});
