// Typed wrapper over the single Tauri command `rpc` (docs/ipc.md). The UI
// keeps no state of its own: everything is read from and written to the agent.
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

export type ServerState = "connected" | "connecting" | "offline";

export interface Status {
  device: { id: string; name: string; platform: string };
  paired: boolean;
  server: ServerState;
  version: string;
}

export interface Device {
  id: string;
  name: string;
  platform: string;
  me: boolean;
  online: boolean;
  last_seen: number | null;
  default_target: boolean;
}

export interface Settings {
  hotkey: string;
  default_target: string | null;
  save_dir: string;
  ask_above_mb: number;
  relay_data: boolean;
  autostart: boolean;
  on_receive: { save: boolean; clipboard: boolean; notify: boolean; history: boolean };
  history_days: number;
  history_items: number;
}

export interface HistoryItem {
  id: string;
  ts: number;
  direction: "in" | "out";
  /** The device's current name (a short id once it has left the group). */
  peer: string;
  peer_id: string;
  kind: "text" | "image" | "file";
  name?: string;
  size: number;
  path?: string;
  ok: boolean;
}

/** A running send or receive (docs/ipc.md `Transfer`). */
export interface Transfer {
  transfer: string;
  direction: "in" | "out";
  peer: string;
  label: string;
  items: number;
  state: "waiting" | "running";
  done_bytes: number;
  total_bytes: number;
  bytes_per_sec: number;
  started_ms: number;
}

export interface TransferProgress {
  transfer: string;
  done_bytes: number;
  total_bytes: number;
  bytes_per_sec: number;
}

export interface HotkeyCheck {
  valid: boolean;
  conflict: boolean;
  produces?: string;
}

export type RemoveReason = "user" | "lost-or-stolen" | "not-me";

export interface RpcError {
  code: string;
  message: string;
}

export function isRpcError(e: unknown): e is RpcError {
  return typeof e === "object" && e !== null && typeof (e as RpcError).code === "string";
}

export function errorCode(e: unknown): string {
  return isRpcError(e) ? e.code : "internal";
}

type Methods = {
  status: [undefined, Status];
  "devices.list": [undefined, Device[]];
  "devices.rename": [{ name: string }, Record<string, never>];
  "devices.remove": [{ id: string; reason: RemoveReason }, Record<string, never>];
  "devices.set_default": [{ id: string }, Record<string, never>];
  "pair.start": [undefined, { qr_text: string; expires_at: number }];
  "pair.confirm": [{ accept: boolean }, Record<string, never>];
  "pair.cancel": [undefined, Record<string, never>];
  "settings.get": [undefined, Settings];
  "settings.set": [Partial<Settings>, Settings];
  "hotkey.check": [{ hotkey: string }, HotkeyCheck];
  "history.list": [{ before?: number; limit?: number }, HistoryItem[]];
  "history.reveal": [{ id: string }, Record<string, never>];
  "history.delete": [{ id: string }, Record<string, never>];
  "group.not_me": [{ id: string }, Record<string, never>];
  "transfer.list": [undefined, { transfers: Transfer[] }];
  "transfer.cancel": [{ transfer: string }, Record<string, never>];
};

export function rpc<M extends keyof Methods>(
  method: M,
  ...params: Methods[M][0] extends undefined ? [] : [Methods[M][0]]
): Promise<Methods[M][1]> {
  return invoke<Methods[M][1]>("rpc", { method, params: params[0] ?? null });
}

export type AgentEvent =
  | { event: "status"; data: Status }
  | { event: "pair.sas"; data: { sas: string; peer_name: string; peer_platform: string } }
  | { event: "pair.done"; data: { peer_id: string } }
  | { event: "pair.failed"; data: { code: string } }
  | { event: "transfer.started"; data: Transfer }
  | { event: "transfer.progress"; data: TransferProgress }
  | { event: "transfer.done"; data: { transfer: string; ok: boolean; code?: string } }
  | { event: "group.alert"; data: { kind: string; id: string; name: string; platform: string; by_name: string } }
  | { event: "group.fork"; data: Record<string, never> };

type Handler = (e: AgentEvent) => void;
const handlers = new Set<Handler>();
const connHandlers = new Set<(up: boolean) => void>();
let started: Promise<UnlistenFn[]> | null = null;

function start(): void {
  if (started) return;
  started = Promise.all([
    listen<AgentEvent>("agent-event", (e) => handlers.forEach((h) => h(e.payload))),
    listen<boolean>("agent-connection", (e) => connHandlers.forEach((h) => h(e.payload))),
  ]);
}

/** Subscribes to agent events; returns an unsubscribe function. */
export function onAgentEvent(h: Handler): () => void {
  start();
  handlers.add(h);
  return () => handlers.delete(h);
}

export function onConnection(h: (up: boolean) => void): () => void {
  start();
  connHandlers.add(h);
  return () => connHandlers.delete(h);
}

/** Resolves once the Tauri event listeners are registered. */
export async function ready(): Promise<void> {
  start();
  await started;
}
