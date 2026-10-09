import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Everything is bundled locally; no CDN, no remote assets (threat model T9).
export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: { port: 1420, strictPort: true, host: "localhost" },
  build: {
    target: "es2022",
    outDir: "dist",
    emptyOutDir: true,
    assetsInlineLimit: 0,
    modulePreload: { polyfill: false },
  },
});
