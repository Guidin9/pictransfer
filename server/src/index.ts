// Warpshot Worker: routes /v1/groups/{gid}/… to the group's Durable Object
// (protocol §6, architecture §5). The Worker itself is stateless.

import { checkCreateToken, requestTarget, splitTarget } from "./auth";
import { b64uDecode, b64uDecodeExact, b64uEncode } from "./b64u";
import { Env } from "./group";
import { parseSignedRecord, RecordError } from "./record";
import { ApiError, errorResponse, json, LIMITS, logEvent, parseJsonObject, readBodyCapped } from "./util";

export { GroupDO } from "./group";
export type { Env } from "./group";

const GROUP_PATH_RE = /^\/v1\/groups\/([A-Za-z0-9_-]{22})\/(log|wake|push-token|presence|ws)$/;

const METHODS: Record<string, string[]> = {
  log: ["GET", "POST"],
  wake: ["POST"],
  "push-token": ["PUT", "DELETE"],
  presence: ["GET"],
  ws: ["GET"],
};

async function createGroup(req: Request, env: Env): Promise<Response> {
  // §6.1 operator admission: before any other processing.
  await checkCreateToken(env.GROUP_CREATE_TOKEN, req);
  if (splitTarget(requestTarget(req)).query !== null) throw new ApiError("bad-request");
  const body = await readBodyCapped(req, LIMITS.httpBody);
  const j = parseJsonObject(body);
  if (typeof j.genesis !== "string") throw new ApiError("bad-request");
  const bytes = b64uDecode(j.genesis, LIMITS.recordBytes);
  if (bytes === null) throw new ApiError("bad-request");
  // Only to find the group's object; the object authenticates and validates.
  let groupId: Uint8Array;
  try {
    groupId = parseSignedRecord(bytes).fields.groupId;
  } catch (e) {
    if (e instanceof RecordError) throw new ApiError("invalid-record");
    throw e;
  }
  const stub = env.GROUPS.get(env.GROUPS.idFromName(b64uEncode(groupId)));
  return stub.fetch(new Request(req.url, { method: req.method, headers: req.headers, body }));
}

export async function handle(req: Request, env: Env): Promise<Response> {
  // Routing uses the raw request target (the same bytes the client signed).
  const { path, query } = splitTarget(requestTarget(req));
  if (path === "/v1/health") {
    if (query !== null) throw new ApiError("bad-request");
    if (req.method !== "GET") throw new ApiError("bad-request");
    return json({ status: "ok" });
  }
  if (path === "/v1/groups") {
    if (req.method !== "POST") throw new ApiError("bad-request");
    return createGroup(req, env);
  }
  const m = GROUP_PATH_RE.exec(path);
  if (m === null) throw new ApiError("bad-request");
  const gid = m[1]!;
  const endpoint = m[2]!;
  if (b64uDecodeExact(gid, 16) === null) throw new ApiError("bad-request");
  if (!METHODS[endpoint]!.includes(req.method)) throw new ApiError("bad-request");
  return env.GROUPS.get(env.GROUPS.idFromName(gid)).fetch(req);
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    try {
      return await handle(req, env);
    } catch (e) {
      if (e instanceof ApiError) return errorResponse(e.code, e.extra);
      logEvent("error", { route: "worker", code: "internal", kind: e instanceof Error ? e.name : "unknown" });
      return errorResponse("internal");
    }
  },
} satisfies ExportedHandler<Env>;
