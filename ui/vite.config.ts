import { defineConfig } from "vitest/config";
import solid from "vite-plugin-solid";
import tailwindcss from "@tailwindcss/vite";

// The app is served by the daemon under /ui; in development `vite` proxies the API to a
// running daemon (FTD_UI_PROXY, default http://127.0.0.1:4000).
const proxyTarget = process.env.FTD_UI_PROXY ?? "http://127.0.0.1:4000";

export default defineConfig({
  base: "/ui/",
  plugins: [solid(), tailwindcss()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
    sourcemap: false,
  },
  server: {
    port: 5173,
    strictPort: false,
    proxy: {
      "/ui/api": { target: proxyTarget, changeOrigin: false },
    },
  },
  test: {
    environment: "jsdom",
    include: ["src/**/*.test.{ts,tsx}"],
    globals: false,
  },
});
