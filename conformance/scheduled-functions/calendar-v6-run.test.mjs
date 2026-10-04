import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";

const run = (args) =>
  spawnSync(
    process.execPath,
    [new URL("./calendar-v6-run.mjs", import.meta.url).pathname, ...args],
    {
      encoding: "utf8",
      env: { PATH: "/nonexistent" },
    },
  );

test("without --send the runner prints the plan and sends nothing", () => {
  const out = run([]);
  assert.equal(out.status, 0, out.stderr);
  const plan = JSON.parse(out.stdout.slice(0, out.stdout.indexOf("}\n") + 1));
  assert.equal(plan.project, "fireemu-oracle-sbx");
  assert.equal(plan.cases, 47);
  assert.match(plan.packetDigest, /^[0-9a-f]{64}$/);
  assert.match(out.stdout, /plan only: nothing was sent/);
});

test("--send with another digest, or without a run directory, refuses before any credential is read", () => {
  const wrong = run(["--send", "--expect-digest", "0".repeat(64)]);
  assert.equal(wrong.status, 2);
  assert.match(wrong.stderr, /digest differs/);
  const plan = JSON.parse(run([]).stdout.slice(0, run([]).stdout.indexOf("}\n") + 1));
  const missing = run(["--send", "--expect-digest", plan.packetDigest]);
  assert.equal(missing.status, 2);
  assert.match(missing.stderr, /--run-dir and --project-number are required/);
});
