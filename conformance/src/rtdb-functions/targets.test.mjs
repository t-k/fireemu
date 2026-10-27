import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { FIXTURE_HANDLERS } from "./frames.mjs";
import { CODEBASE, TARGETS } from "./targets.mjs";

test("the targets are the eight handlers in deploy order, the 1st gen ones first, all of one codebase", () => {
  assert.deepEqual(
    TARGETS.map((t) => t.functionName),
    FIXTURE_HANDLERS.map((h) => h.name),
  );
  assert.deepEqual(
    TARGETS.map((t) => t.generation),
    ["gcfv1", "gcfv1", "gcfv1", "gcfv1", "gcfv2", "gcfv2", "gcfv2", "gcfv2"],
  );
  assert.ok(TARGETS.every((t) => t.codebase === CODEBASE && t.region === "us-central1"));
  assert.ok(TARGETS.every((t) => Object.isFrozen(t) && t.named === false));
  assert.equal(new Set(TARGETS.map((t) => t.resourceId.toLowerCase())).size, 8);
});

test("firebase.json names the same codebase and the fixtures directory", () => {
  const config = JSON.parse(readFileSync(new URL("./firebase.json", import.meta.url), "utf8"));
  assert.deepEqual(config, { functions: { source: "fixtures", codebase: CODEBASE } });
});
