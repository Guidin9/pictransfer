import type { Env as WorkerEnv } from "../src/group";

declare global {
  namespace Cloudflare {
    interface Env extends WorkerEnv {
      /** Tests only: public half of the throwaway FCM service-account key. */
      TEST_FCM_PUBLIC_KEY: string;
    }
    interface GlobalProps {
      mainModule: typeof import("../src/index");
      durableNamespaces: "GroupDO";
    }
  }
}
