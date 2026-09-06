import { defineConfig } from "@playwright/test";

// The E2E suite runs against a real daemon. `pnpm e2e` starts one itself through
// `fireemu exec` (see e2e/global-setup.ts); FIREEMU_UI_URL points at an already running
// UI instead.
const uiUrl =
  process.env.FIREEMU_UI_URL ?? `http://127.0.0.1:${process.env.FIREEMU_E2E_UI_PORT ?? "14000"}`;

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 60_000,
  reporter: [["list"]],
  ...(process.env.FIREEMU_UI_URL
    ? {}
    : { globalSetup: "./e2e/global-setup.ts", globalTeardown: "./e2e/global-teardown.ts" }),
  use: {
    baseURL: uiUrl,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [{ name: "chromium", use: { browserName: "chromium" } }],
});
