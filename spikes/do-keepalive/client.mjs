// Spike C client: holds 6 WebSockets to the keepalive Worker with different
// application-level ping intervals and logs every open/pong/close/error/missed.
//
// Usage:  SPIKE_URL=https://<worker>.workers.dev node client.mjs
// Optional env: SPIKE_DURATION_S (default 21600 = 6 h), SPIKE_PONG_TIMEOUT_S (default 15).
//
// The Worker URL is read from the environment only and is never written to any
// file (the JSONL log carries labels, times and close codes only).

import { mkdirSync, appendFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const INTERVALS_S = [30, 60, 90, 120, 300, 600];
const DURATION_MS = Number(process.env.SPIKE_DURATION_S ?? 6 * 3600) * 1000;
const PONG_TIMEOUT_MS = Number(process.env.SPIKE_PONG_TIMEOUT_S ?? 15) * 1000;
const RECONNECT_DELAY_MS = 1000;
// Two missed "o" replies in a row → client closes and reconnects (protocol §6.3).
const MAX_CONSECUTIVE_MISSES = 2;
// A timer firing this much later than scheduled means the process/PC was suspended.
const STALL_THRESHOLD_MS = 5000;

const base = process.env.SPIKE_URL;
if (!base) {
  console.error("SPIKE_URL is not set");
  process.exit(2);
}
let wsBase;
try {
  const u = new URL(base);
  u.protocol = u.protocol === "http:" ? "ws:" : "wss:";
  u.pathname = "/ws";
  u.search = "";
  wsBase = u;
} catch {
  console.error("SPIKE_URL is not a valid URL");
  process.exit(2);
}

const here = dirname(fileURLToPath(import.meta.url));
const outDir = join(here, "out");
mkdirSync(outDir, { recursive: true });
const stamp = new Date().toISOString().replace(/[:.]/g, "-");
const logPath = join(outDir, `run-${stamp}.jsonl`);
const summaryPath = join(outDir, `summary-${stamp}.json`);
const startedAt = Date.now();
let stopping = false;

function log(rec) {
  const line = JSON.stringify({ t: new Date().toISOString(), ...rec });
  appendFileSync(logPath, line + "\n");
}

class Probe {
  constructor(intervalS) {
    this.intervalS = intervalS;
    this.label = `k${intervalS}`;
    this.ws = null;
    this.openedAt = 0;
    this.pingTimer = null;
    this.pongTimer = null;
    this.pingSentAt = 0;
    this.pingExpectedAt = 0;
    this.awaitingPong = false;
    this.consecutiveMisses = 0;
    this.clientInitiated = null; // reason string when we closed it ourselves
    this.stats = {
      interval_s: intervalS,
      opens: 0,
      connect_failures: 0,
      pongs: 0,
      closes: 0,
      unexpected_closes: 0,
      client_forced_closes: 0,
      missed_pongs: 0,
      errors: 0,
      stalls: 0,
      close_codes: {},
      longest_uninterrupted_s: 0,
      max_rtt_ms: 0,
    };
  }

  connect() {
    if (stopping) return;
    const u = new URL(wsBase);
    u.searchParams.set("label", this.label);
    this.clientInitiated = null;
    let ws;
    try {
      ws = new WebSocket(u);
    } catch (e) {
      this.stats.errors++;
      log({ label: this.label, event: "error", reason: String(e?.name ?? "ctor") });
      this.scheduleReconnect();
      return;
    }
    this.ws = ws;
    ws.addEventListener("open", () => {
      this.openedAt = Date.now();
      this.consecutiveMisses = 0;
      this.awaitingPong = false;
      this.stats.opens++;
      log({ label: this.label, event: "open" });
      this.schedulePing();
    });
    ws.addEventListener("message", (ev) => {
      if (ev.data === "o" && this.awaitingPong) {
        const rtt = Date.now() - this.pingSentAt;
        this.awaitingPong = false;
        this.consecutiveMisses = 0;
        clearTimeout(this.pongTimer);
        this.stats.pongs++;
        this.stats.max_rtt_ms = Math.max(this.stats.max_rtt_ms, rtt);
        log({ label: this.label, event: "pong", rtt_ms: rtt });
      } else {
        log({ label: this.label, event: "unexpected_message", reason: String(ev.data).slice(0, 8) });
      }
    });
    ws.addEventListener("error", (ev) => {
      this.stats.errors++;
      // Error kinds only (e.g. ECONNRESET, ENOTFOUND); never addresses.
      const err = ev?.error;
      const kind = err?.cause?.code ?? err?.code ?? err?.name ?? "unknown";
      log({ label: this.label, event: "error", reason: String(kind), opened: this.openedAt !== 0 });
    });
    ws.addEventListener("close", (ev) => {
      clearTimeout(this.pingTimer);
      clearTimeout(this.pongTimer);
      const lived = this.openedAt ? (Date.now() - this.openedAt) / 1000 : 0;
      if (this.openedAt) {
        this.stats.longest_uninterrupted_s = Math.max(this.stats.longest_uninterrupted_s, lived);
      }
      const expected = stopping;
      const neverOpened = this.openedAt === 0;
      const forced = !expected && this.clientInitiated !== null;
      if (!expected && neverOpened) {
        this.stats.connect_failures++;
      } else if (!expected) {
        this.stats.closes++;
        this.stats.close_codes[ev.code] = (this.stats.close_codes[ev.code] ?? 0) + 1;
        if (forced) this.stats.client_forced_closes++;
        else this.stats.unexpected_closes++;
      }
      log({
        label: this.label,
        event: "close",
        code: ev.code,
        reason: this.clientInitiated ?? ev.reason ?? "",
        lived_s: Math.round(lived),
        expected,
        never_opened: neverOpened,
        client_initiated: this.clientInitiated !== null,
      });
      this.openedAt = 0;
      this.ws = null;
      this.scheduleReconnect();
    });
  }

  scheduleReconnect() {
    if (stopping) return;
    setTimeout(() => this.connect(), RECONNECT_DELAY_MS);
  }

  schedulePing() {
    this.pingExpectedAt = Date.now() + this.intervalS * 1000;
    this.pingTimer = setTimeout(() => this.ping(), this.intervalS * 1000);
  }

  ping() {
    const ws = this.ws;
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    const late = Date.now() - this.pingExpectedAt;
    if (late > STALL_THRESHOLD_MS) {
      this.stats.stalls++;
      log({ label: this.label, event: "stall", reason: `timer late by ${late} ms` });
    }
    if (this.awaitingPong) this.miss("no pong before next ping");
    if (!this.ws || this.clientInitiated !== null) return;
    this.pingSentAt = Date.now();
    this.awaitingPong = true;
    try {
      ws.send("p");
    } catch (e) {
      log({ label: this.label, event: "error", reason: `send: ${e?.name ?? ""}` });
    }
    clearTimeout(this.pongTimer);
    this.pongTimer = setTimeout(() => {
      if (this.awaitingPong) this.miss(`no pong within ${PONG_TIMEOUT_MS} ms`);
    }, PONG_TIMEOUT_MS);
    this.schedulePing();
  }

  miss(reason) {
    this.awaitingPong = false;
    this.consecutiveMisses++;
    this.stats.missed_pongs++;
    log({ label: this.label, event: "missed", reason, consecutive: this.consecutiveMisses });
    if (this.consecutiveMisses >= MAX_CONSECUTIVE_MISSES && this.ws) {
      this.clientInitiated = `${this.consecutiveMisses} missed pongs`;
      clearTimeout(this.pingTimer);
      try {
        this.ws.close(4000, "missed pongs");
      } catch {
        /* close event follows */
      }
    }
  }

  finish() {
    clearTimeout(this.pingTimer);
    clearTimeout(this.pongTimer);
    if (this.openedAt) {
      const lived = (Date.now() - this.openedAt) / 1000;
      this.stats.longest_uninterrupted_s = Math.max(this.stats.longest_uninterrupted_s, lived);
    }
    this.stats.longest_uninterrupted_s = Math.round(this.stats.longest_uninterrupted_s);
    if (this.ws) {
      try {
        this.ws.close(1000, "done");
      } catch {
        /* ignore */
      }
    }
  }
}

const probes = INTERVALS_S.map((s) => new Probe(s));
log({ label: "*", event: "start", reason: `duration_s=${DURATION_MS / 1000} pid=${process.pid}` });
for (const p of probes) p.connect();

function stop(why) {
  if (stopping) return;
  stopping = true;
  for (const p of probes) p.finish();
  const summary = {
    started: new Date(startedAt).toISOString(),
    ended: new Date().toISOString(),
    stop_reason: why,
    duration_s: Math.round((Date.now() - startedAt) / 1000),
    pong_timeout_s: PONG_TIMEOUT_MS / 1000,
    log_file: logPath.split(/[\\/]/).pop(),
    per_label: Object.fromEntries(probes.map((p) => [p.label, p.stats])),
  };
  writeFileSync(summaryPath, JSON.stringify(summary, null, 2) + "\n");
  log({ label: "*", event: "stop", reason: why });
  setTimeout(() => process.exit(0), 2000);
}

setTimeout(() => stop("duration reached"), DURATION_MS);
process.on("SIGINT", () => stop("SIGINT"));
process.on("SIGTERM", () => stop("SIGTERM"));
