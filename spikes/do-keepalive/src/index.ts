// Spike C — minimal Worker + one SQLite-backed Durable Object using the
// WebSocket Hibernation API. Keepalive "p" is answered with "o" by the runtime
// (setWebSocketAutoResponse) without waking the object.
//
// Logging: counts only. Never addresses, headers or message contents.

import { DurableObject } from "cloudflare:workers";

interface Env {
  KEEPALIVE: DurableObjectNamespace<KeepaliveHub>;
}

const LABEL_RE = /^[A-Za-z0-9_-]{1,32}$/;

export class KeepaliveHub extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    // Runs on every (re)activation; cheap and idempotent.
    this.ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair("p", "o"));
  }

  async fetch(request: Request): Promise<Response> {
    const label = new URL(request.url).searchParams.get("label") ?? "";
    if (!LABEL_RE.test(label)) {
      return new Response("bad label", { status: 400 });
    }
    const pair = new WebSocketPair();
    const [client, server] = [pair[0], pair[1]];
    // acceptWebSocket (not ws.accept()) lets the object hibernate.
    this.ctx.acceptWebSocket(server, [label]);
    console.log(JSON.stringify({ ev: "accept", sockets: this.ctx.getWebSockets().length }));
    return new Response(null, { status: 101, webSocket: client });
  }

  // Only reached for messages other than the auto-response request ("p").
  async webSocketMessage(ws: WebSocket, _message: string | ArrayBuffer): Promise<void> {
    console.log(JSON.stringify({ ev: "message", sockets: this.ctx.getWebSockets().length }));
    ws.send("?");
  }

  async webSocketClose(ws: WebSocket, code: number, _reason: string, wasClean: boolean): Promise<void> {
    console.log(
      JSON.stringify({ ev: "close", code, wasClean, sockets: this.ctx.getWebSockets().length }),
    );
    try {
      ws.close(code, "bye");
    } catch {
      // Already closed (runtime auto-replies to Close frames on recent compat dates).
    }
  }

  async webSocketError(_ws: WebSocket, _error: unknown): Promise<void> {
    console.log(JSON.stringify({ ev: "error", sockets: this.ctx.getWebSockets().length }));
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (request.method !== "GET" || url.pathname !== "/ws") {
      return new Response("not found", { status: 404 });
    }
    if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
      return new Response("expected websocket", { status: 426 });
    }
    // One single instance for the whole spike.
    const stub = env.KEEPALIVE.getByName("spike");
    return stub.fetch(request);
  },
} satisfies ExportedHandler<Env>;
