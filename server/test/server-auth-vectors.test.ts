// Shared §6.1 vectors from the Rust core: docs/test-vectors/server-auth.json (read-only).
import { describe, expect, it } from "vitest";
import vectors from "../../docs/test-vectors/server-auth.json";
import { authSignedBytes, parseAuthorization, requestTarget, verifyAuthorization } from "../src/auth";
import { b64uEncode } from "../src/b64u";
import { ApiError, hex } from "../src/util";
import { authHeader, device, fromHex } from "./helpers/fixtures";

const SIGNER_SEED = 0xa1;

describe("server-auth.json", () => {
  it("signer key is 32 × 0xa1", async () => {
    expect(hex((await device(SIGNER_SEED)).pk)).toBe(vectors.endpoint_id);
  });

  it.each(vectors.valid.map((c) => [`${c.method} ${c.path}`, c] as const))("valid: %s", async (_n, c) => {
    const body = fromHex(c.body_hex);
    const ts = parseAuthorization(c.authorization).ts;
    // Canonical string and header match byte for byte when we sign ourselves.
    expect(hex(await authSignedBytes(c.method, c.path, ts, body))).toBe(c.signed_hex);
    expect(await authHeader(await device(SIGNER_SEED), c.method, c.path, body, ts)).toBe(c.authorization);
    // And our verifier accepts the vector's header at ts.
    const a = await verifyAuthorization(c.authorization, c.method, c.path, body, ts);
    expect(b64uEncode(a.id)).toBe(b64uEncode(fromHex(vectors.endpoint_id)));
  });

  it.each(vectors.verify.map((c) => [c.name, c] as const))("verify: %s", async (_n, c) => {
    const ok = await verifyAuthorization(c.authorization, c.method, c.path, fromHex(c.body_hex), c.now_ms).then(
      () => true,
      (e) => {
        expect(e).toBeInstanceOf(ApiError);
        return false;
      },
    );
    expect(ok).toBe(c.accept);
  });

  it.each(vectors.malformed.map((c) => [c.name, c.authorization] as const))("malformed: %s", (_n, h) => {
    expect(() => parseAuthorization(h)).toThrow(ApiError);
  });

  it("request target is taken verbatim from the request URL", () => {
    expect(requestTarget(new Request("https://h.test/v1/groups/R0dHR0dHR0dHR0dHR0dHRw/log?after=3"))).toBe(
      "/v1/groups/R0dHR0dHR0dHR0dHR0dHRw/log?after=3",
    );
    expect(requestTarget(new Request("https://h.test:8443/v1/health"))).toBe("/v1/health");
  });
});
