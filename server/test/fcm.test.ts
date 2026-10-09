// FCM service-account parsing (§6.5).
import { describe, expect, it } from "vitest";
import { fcmConfig } from "../src/fcm";

const sa = {
  type: "service_account",
  project_id: "demo-project",
  private_key: "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
  client_email: "sa@demo-project.iam.gserviceaccount.com",
};

describe("fcmConfig", () => {
  it("parses a service account", () => {
    expect(fcmConfig(JSON.stringify(sa), undefined)?.projectId).toBe("demo-project");
  });

  it("tolerates a BOM and surrounding whitespace (piped secrets)", () => {
    const cfg = fcmConfig("﻿" + JSON.stringify(sa, null, 2) + "\r\n", undefined);
    expect(cfg?.projectId).toBe("demo-project");
    expect(cfg?.messagesUrl).toBe("https://fcm.googleapis.com/v1/projects/demo-project/messages:send");
  });

  it("rejects missing, malformed or incomplete secrets", () => {
    expect(fcmConfig(undefined, undefined)).toBeNull();
    expect(fcmConfig("", undefined)).toBeNull();
    expect(fcmConfig("{not json", undefined)).toBeNull();
    expect(fcmConfig(JSON.stringify({ ...sa, private_key: 1 }), undefined)).toBeNull();
    expect(fcmConfig(JSON.stringify({ ...sa, project_id: "Bad/Id" }), undefined)).toBeNull();
  });
});
