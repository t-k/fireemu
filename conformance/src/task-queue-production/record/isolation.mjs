// Test isolation for everything that can reach a Google service: import this module FIRST in a test file of the recorder.
// It gives the process an empty HOME (no gcloud or ADC files), removes the variables that name credentials or an emulator,
// puts refusing `gcloud` and `firebase` shims in front of PATH, and makes `fetch` throw, so that a test (or a mutant that
// makes a test reach the real client) cannot send a request or mint a token. The recorder's own `--send` flag is never passed
// by a test without an injected world (guarded in isolation.test.mjs).
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { after } from "node:test";

export const FORBIDDEN = [
  /^GOOGLE_APPLICATION_CREDENTIALS$/,
  /^GOOGLE_CLOUD_PROJECT$/,
  /^GCLOUD_PROJECT$/,
  /^GCP_PROJECT$/,
  /^CLOUDSDK_/,
  /^FIREBASE_TOKEN$/,
  /^FIREBASE_CONFIG$/,
  /_EMULATOR_HOST$/,
  /^TQ_PROJECT_NUMBER$/,
  /^GOOGLE_/,
];

const root = mkdtempSync(join(tmpdir(), "tq-isolated-"));
after(() => rmSync(root, { recursive: true, force: true }));
export const ISOLATED_HOME = join(root, "home");
export const SHIM_DIR = join(root, "bin");
export const TRAP_MARK = join(root, "trap-called");
mkdirSync(ISOLATED_HOME, { recursive: true });
mkdirSync(SHIM_DIR, { recursive: true });
for (const name of ["gcloud", "firebase", "gsutil"]) {
  const path = join(SHIM_DIR, name);
  writeFileSync(
    path,
    `#!/bin/sh\necho "${name} ran in a test" >> '${TRAP_MARK}'\necho "${name} is refused in a test" >&2\nexit 97\n`,
  );
  chmodSync(path, 0o755);
}
for (const key of Object.keys(process.env))
  if (FORBIDDEN.some((re) => re.test(key))) delete process.env[key];
process.env.HOME = ISOLATED_HOME;
process.env.XDG_CONFIG_HOME = join(ISOLATED_HOME, ".config");
process.env.PATH = SHIM_DIR + delimiter + (process.env.PATH ?? "");
process.env.TQ_TEST_ISOLATED = "1";
export const realFetch = globalThis.fetch;
globalThis.fetch = async (input) => {
  throw new Error("fetch is refused in a test: " + String(input?.url ?? input));
};
