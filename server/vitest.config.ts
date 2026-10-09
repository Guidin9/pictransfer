// Tests run inside workerd via @cloudflare/vitest-pool-workers.
// FCM is never contacted: FCM_BASE_URL points at a fake host that the tests
// intercept, and the service account below is a throwaway key generated per run.
import { generateKeyPairSync } from "node:crypto";
import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

const { privateKey, publicKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
  publicKeyEncoding: { type: "spki", format: "pem" },
});

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.jsonc" },
      miniflare: {
        bindings: {
          GROUP_CREATE_TOKEN: "test-create-token",
          FCM_BASE_URL: "https://fcm.test",
          FCM_SERVICE_ACCOUNT: JSON.stringify({
            type: "service_account",
            project_id: "test-project",
            client_email: "sender@test-project.iam.gserviceaccount.com",
            private_key: privateKey,
          }),
          TEST_FCM_PUBLIC_KEY: publicKey,
        },
      },
    }),
  ],
  test: {
    testTimeout: 20000,
  },
});
