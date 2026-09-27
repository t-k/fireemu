import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const runner = fileURLToPath(new URL("./storage-object/run.mjs", import.meta.url));

test("plan command prints a bounded non-sending two-recording draft", () => {
  const output = execFileSync(
    process.execPath,
    [runner, "plan", "example-project", "example.appspot.com", "recordone", "recordtwo"],
    { encoding: "utf8" },
  );
  const plan = JSON.parse(output);
  assert.equal(plan.status, "LOCAL_DRAFT_NO_SEND");
  assert.equal(plan.sendAuthorized, false);
  assert.equal(plan.maxRequests, 5600);
  assert.equal(plan.recordings.length, 2);
});

test("record-production refuses locally before loading any credential", () => {
  const result = spawnSync(process.execPath, [runner, "record-production"], { encoding: "utf8" });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /not implemented|disabled/i);
  assert.doesNotMatch(result.stderr, /token|key string|password/i);
});
