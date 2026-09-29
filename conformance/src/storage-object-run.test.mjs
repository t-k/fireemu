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
  assert.equal(plan.maxRequests, 6600);
  assert.equal(plan.recordings.length, 2);
});

test("record-production refuses locally before loading any credential", () => {
  const result = spawnSync(process.execPath, [runner, "record-production"], {
    encoding: "utf8",
    env: { PATH: process.env.PATH },
  });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /recording number/i);
  assert.doesNotMatch(result.stderr, /token|key string|password/i);
});

test("record-production names the missing environment and reads nothing", () => {
  const result = spawnSync(process.execPath, [runner, "record-production", "1"], {
    encoding: "utf8",
    env: { PATH: process.env.PATH },
  });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /missing environment: FIREEMU_STORAGE_OBJECT_PACKET/);
});

test("pins prints the packet pins and the commit as one line of JSON", () => {
  const output = execFileSync(process.execPath, [runner, "pins"], { encoding: "utf8" });
  const pins = JSON.parse(output);
  assert.match(pins.sourceCommit, /^[0-9a-f]{40}$/);
  for (const key of ["runnerSha256", "planSha256", "corpusSha256", "rulesSourceSha256"]) {
    assert.match(pins[key], /^[0-9a-f]{64}$/, key);
  }
  assert.equal(typeof pins.treeClean, "boolean");
  assert.ok(pins.sourceFiles > 50);
});
