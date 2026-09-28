import assert from "node:assert/strict";
import { test } from "node:test";

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

import {
  checkHistoricalProduction,
  historicalArtifactIdentity,
  measureArtifact,
} from "./historical-production-check.mjs";

const definitions = [{ id: "writes", steps: [{ id: "same" }, { id: "changed" }] }];
const saved = {
  programs: [
    {
      id: "writes",
      steps: {
        same: {
          production: { status: 200, code: "OK", body: { x: 1 } },
          fireemu: { status: 200, code: "OK", body: { x: 1 } },
        },
        changed: {
          production: { status: 400, code: "INVALID_ARGUMENT" },
          fireemu: { status: 400, code: "INVALID_ARGUMENT" },
        },
      },
    },
  ],
};
const live = {
  writes: {
    steps: {
      same: { status: 200, code: "OK", body: { x: 1 } },
      changed: { status: 200, code: "OK", body: { x: 2 } },
    },
  },
};

test("changed recipes are excluded explicitly, not counted as production regressions", () => {
  const result = checkHistoricalProduction({
    saved,
    live,
    definitions,
    excludedKeys: ["writes#changed"],
  });
  assert.deepEqual(result, {
    comparable: 1,
    baselineMismatches: [],
    currentMismatches: [],
    newMismatches: [],
    indeterminate: [],
    newIndeterminate: [],
  });
});

test("a new mismatch in a comparable recipe fails the comparison", () => {
  const modified = structuredClone(live);
  modified.writes.steps.same.body.x = 2;
  const result = checkHistoricalProduction({
    saved,
    live: modified,
    definitions,
    excludedKeys: ["writes#changed"],
  });
  assert.deepEqual(result.newMismatches, ["writes#same"]);
});

test("missing observations remain indeterminate rather than becoming matches", () => {
  const modified = structuredClone(live);
  delete modified.writes.steps.same;
  const result = checkHistoricalProduction({
    saved,
    live: modified,
    definitions,
    excludedKeys: ["writes#changed"],
  });
  assert.deepEqual(result.indeterminate, ["writes#same"]);
  assert.deepEqual(result.newIndeterminate, ["writes#same"]);
});

test("unlisted recipe additions are rejected", () => {
  const modified = structuredClone(definitions);
  modified[0].steps.push({ id: "new" });
  assert.throws(
    () =>
      checkHistoricalProduction({
        saved,
        live,
        definitions: modified,
        excludedKeys: ["writes#changed"],
      }),
    /recipe identity/,
  );
});

test("the historical check records the artifact it ran and refuses one that changed", () => {
  const sha = "a".repeat(64);
  assert.deepEqual(
    historicalArtifactIdentity({
      root: "/repo",
      binary: "/repo/target/release/fireemu",
      before: sha,
      after: sha,
      version: "fireemu 0.7.1\n",
    }),
    {
      path: "target/release/fireemu",
      sha256Before: sha,
      sha256After: sha,
      version: "fireemu 0.7.1",
    },
  );
  assert.throws(
    () =>
      historicalArtifactIdentity({
        root: "/repo",
        binary: "/repo/target/debug/fireemu",
        before: sha,
        after: "b".repeat(64),
        version: "fireemu 0.7.1",
      }),
    /changed during the historical check/,
  );
  assert.throws(
    () =>
      historicalArtifactIdentity({
        root: "/repo",
        binary: "/repo/fireemu",
        before: "not-a-digest",
        after: "not-a-digest",
        version: "fireemu 0.7.1",
      }),
    /SHA-256/,
  );
});

test("an artifact is measured by its bytes and its --version answer", async () => {
  // The running Node binary stands in for fireemu: both answer --version on stdout.
  const measured = await measureArtifact(process.execPath);
  assert.equal(
    measured.sha256,
    createHash("sha256").update(readFileSync(process.execPath)).digest("hex"),
  );
  assert.equal(measured.version.trim(), process.version);
});
