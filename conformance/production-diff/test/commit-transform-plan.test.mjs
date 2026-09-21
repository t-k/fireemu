// commit-transform-plan.mjs is a JS port of transform_compiler.compile_plan(). These tests
// establish, and keep proving, that the port is byte-structurally faithful to the real Python
// source read at test time (not imported into the pilot runtime -- see commit-transform.mjs).
import assert from "node:assert/strict";
import { test } from "node:test";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { compilePlan } from "../commit-transform-plan.mjs";
import { COMMIT_TRANSFORM_CASE } from "../registry.mjs";

const ROOT = fileURLToPath(new URL("../../..", import.meta.url));
const COMPILER = join(ROOT, "tools/compat-broad/fs-commit-transform-limits/transform_compiler.py");

function pythonPlan(project, database, nonce) {
  const script = `
import sys, json
sys.path.insert(0, ${JSON.stringify(dirname(COMPILER))})
from transform_compiler import compile_plan
print(json.dumps(compile_plan(sys.argv[1], sys.argv[2], sys.argv[3])))
`;
  const out = execFileSync("python3", ["-I", "-c", script, project, database, nonce], {
    encoding: "utf8",
  });
  return JSON.parse(out);
}

test("JS port is structurally identical to the real Python compiler for the same inputs", () => {
  const project = "demo-firestore-probe";
  const database = "(default)";
  const nonce = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4";
  const js = compilePlan(project, database, nonce);
  const py = pythonPlan(project, database, nonce);
  assert.deepEqual(js, py);
});

test("the registry-pinned local plan matches a fresh compile", () => {
  const entry = COMMIT_TRANSFORM_CASE;
  const plan = compilePlan(entry.project, entry.database, entry.nonce);
  assert.equal(plan.planDigest, entry.programDigest);
  assert.deepEqual(plan.ownedResources, entry.ownedDocuments);
});

test("plan shape: 11 observation + 6 recovery rows, matching the published row count", () => {
  const plan = compilePlan("demo-firestore-probe", "(default)", "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4");
  assert.equal(plan.observation.length, 11);
  assert.equal(plan.recovery.length, 6);
  assert.equal(plan.observation.length + plan.recovery.length, 17);
});

test("compiler rejects a malformed nonce", () => {
  assert.throws(
    () => compilePlan("demo-firestore-probe", "(default)", "not-hex"),
    /malformed-nonce/,
  );
});

test("compilation is deterministic for the same inputs", () => {
  const a = compilePlan("demo-firestore-probe", "(default)", "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4");
  const b = compilePlan("demo-firestore-probe", "(default)", "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4");
  assert.deepEqual(a, b);
});
