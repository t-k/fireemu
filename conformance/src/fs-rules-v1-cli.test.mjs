import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { test } from "node:test";

const RUN = join(import.meta.dirname, "fs-rules-v1/run.mjs");
const CLEAN_ENV = {
  PATH: process.env.PATH,
  HOME: process.env.HOME,
  NODE_OPTIONS: "",
};

/** Runs the real entry point with nothing production-related in the environment. */
const run = (args, env = {}) =>
  spawnSync(process.execPath, [RUN, ...args], {
    env: { ...CLEAN_ENV, ...env },
    encoding: "utf8",
    timeout: 20_000,
  });

test("an unknown command prints the usage and exits 2", () => {
  const result = run(["frobnicate"]);
  assert.equal(result.status, 2);
  assert.match(
    result.stderr,
    /usage: run\.mjs preflight\|record-production\|check\|local\|official/,
  );
});

test("record-production refuses to start without its ledger and private directory", () => {
  const result = run(["record-production"]);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /FIREEMU_SANDBOX_LEDGER and FIREEMU_FS3_PRIVATE_DIR are required/);
  const half = run(["record-production"], { FIREEMU_SANDBOX_LEDGER: "/nonexistent/ledger" });
  assert.notEqual(half.status, 0);
  assert.match(half.stderr, /FIREEMU_FS3_PRIVATE_DIR are required/);
});

test("preflight refuses to start without the sandbox web config, before any request", () => {
  const result = run(["preflight"]);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /FIREEMU_AUTH_SANDBOX_WEB_CONFIG is required/);
});

test("export-comparison needs an output path", () => {
  const result = run(["export-comparison"]);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /usage: export-comparison <output\.json>/);
});
