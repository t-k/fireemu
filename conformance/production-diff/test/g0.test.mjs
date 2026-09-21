import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { test } from "node:test";
import { compareG0, g0SessionPythonSource, validateG0Origins } from "../g0.mjs";
import { G0_CASE } from "../registry.mjs";

test("G0 compare refuses a missing retained build binding", () => {
  assert.throws(
    () =>
      compareG0({
        repo: process.cwd(),
        entry: G0_CASE,
        actual: {},
        execution: { artifact: { sha256: "a".repeat(64) } },
        build: null,
      }),
    /g0-artifact-receipt-mismatch/,
  );
});

test("G0 compare refuses a snapshot whose bytes differ from the retained receipt", () => {
  assert.throws(
    () =>
      compareG0({
        repo: process.cwd(),
        entry: G0_CASE,
        actual: {},
        execution: { artifact: { sha256: "b".repeat(64) } },
        build: { artifactSha256: "a".repeat(64) },
      }),
    /g0-artifact-receipt-mismatch/,
  );
});

test("G0 origin binding requires both real loopback services", () => {
  assert.deepEqual(
    validateG0Origins({
      FIRESTORE_EMULATOR_HOST: "127.0.0.1:18080",
      FIREBASE_AUTH_EMULATOR_HOST: "127.0.0.1:19090",
    }),
    { firestore: "127.0.0.1:18080", auth: "127.0.0.1:19090" },
  );
  for (const env of [
    { FIRESTORE_EMULATOR_HOST: "127.0.0.1:18080" },
    { FIRESTORE_EMULATOR_HOST: "example.invalid:18080", FIREBASE_AUTH_EMULATOR_HOST: "127.0.0.1:19090" },
  ]) assert.throws(() => validateG0Origins(env), /g0-owned-origin-required/);
});

test("G0 session bridge compiles as the exact Python source it will execute", () => {
  const source = g0SessionPythonSource();
  execFileSync(
    "uv",
    ["run", "python", "-c", "compile(__import__('sys').stdin.read(), '<g0-session>', 'exec')"],
    { input: source, encoding: "utf8", stdio: ["pipe", "ignore", "pipe"] },
  );
});
