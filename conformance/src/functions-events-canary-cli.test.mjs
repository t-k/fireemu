import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { buildCanaryCli } from "./functions-events/canary-cli.mjs";

const configPath = new URL("../functions-events/firebase.json", import.meta.url);
const fixtureLockPath = new URL("../functions-events/fixtures/pnpm-lock.yaml", import.meta.url);

test("the production Firebase config contains only the event fixture codebase", () => {
  const config = JSON.parse(readFileSync(configPath, "utf8"));
  assert.deepEqual(config, {
    functions: {
      source: "fixtures",
      codebase: "events",
      runtime: "nodejs22",
    },
  });
});

test("each canary CLI command pins its project, config, quota project, and one function", () => {
  for (const name of ["fsCreatedV1", "fsCreatedV2"]) {
    const deploy = buildCanaryCli("deploy", "demo-events-prod", name);
    assert.deepEqual(deploy.args, [
      "deploy",
      "--config",
      "conformance/functions-events/firebase.json",
      "--project",
      "demo-events-prod",
      "--only",
      `functions:events:${name}`,
      "--non-interactive",
    ]);
    assert.equal(deploy.env.GOOGLE_CLOUD_QUOTA_PROJECT, "demo-events-prod");
    const remove = buildCanaryCli("delete", "demo-events-prod", name);
    assert.deepEqual(remove.args, [
      "functions:delete",
      name,
      "--region",
      "us-central1",
      "--project",
      "demo-events-prod",
      "--force",
    ]);
    assert.equal(remove.env.GOOGLE_CLOUD_QUOTA_PROJECT, "demo-events-prod");
  }
});

test("canary CLI rejects an unreviewed function or malformed project", () => {
  for (const name of ["authCreatedV1", "fsCreatedV2,storageFinalizedV2", ""]) {
    assert.throws(() => buildCanaryCli("deploy", "demo-events-prod", name));
  }
  assert.throws(() => buildCanaryCli("deploy", "futaba-prod;other", "fsCreatedV1"));
  assert.throws(() => buildCanaryCli("other", "demo-events-prod", "fsCreatedV1"));
});

test("the deployable fixture has its own frozen SDK dependency lockfile", () => {
  const lock = readFileSync(fixtureLockPath, "utf8");
  assert.match(lock, /^lockfileVersion: '9\.0'/m);
  assert.match(lock, /firebase-admin:\n\s+specifier: 14\.3\.0/);
  assert.match(lock, /firebase-functions:\n\s+specifier: 7\.3\.2/);
});
