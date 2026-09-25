import assert from "node:assert/strict";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { compilePlan } from "../commit-transform-plan.mjs";
import { COMMIT_TRANSFORM_CASE } from "../registry.mjs";
import {
  documentedReference,
  compareCommitTransform,
  validateCommitPlan,
  prepareCommitTransform,
  planOperations,
  stepIdOf,
} from "../commit-transform.mjs";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const entry = COMMIT_TRANSFORM_CASE;
const plan = compilePlan(entry.project, entry.database, entry.nonce);

/** Build a fully-matching local rows fixture from the plan's own declared contract. */
function localRowsFixture(overrides = {}) {
  const rows = planOperations(plan).map((op, index) => {
    const stepId = stepIdOf(plan, op);
    const label = stepId.split(":")[1];
    const doc = plan.documents[label];
    let status, body;
    switch (op.kind) {
      case "preflight-typed-absence":
      case "cleanup-verify-absence":
        status = 404;
        body = {
          error: { code: 404, status: "NOT_FOUND", message: `document ${doc.resource} not found` },
        };
        break;
      case "create-only-patch":
      case "baseline-readback":
        status = 200;
        body = { name: doc.resource, fields: doc.fields, createTime: "t", updateTime: "t" };
        break;
      case "poststate-readback":
      case "poststate-control-readback": {
        const transformed = op.expect.postState === "transformed";
        status = 200;
        body = {
          name: doc.resource,
          fields: transformed ? doc.expectedFields : doc.fields,
          createTime: "t",
          updateTime: "t",
        };
        break;
      }
      case "cleanup-ownership-read": {
        const transformed = doc.transformCount === 500;
        status = 200;
        body = {
          name: doc.resource,
          fields: transformed ? doc.expectedFields : doc.fields,
          createTime: "t",
          updateTime: "t",
        };
        break;
      }
      case "cleanup-conditional-delete":
        status = 200;
        body = {};
        break;
      case "commit-transform":
        if (op.expect.outcome === "accepted") {
          status = 200;
          body = {
            commitTime: "t",
            writeResults: op.body.writes.map((w) => ({
              updateTime: "t",
              transformResults: w.transform.fieldTransforms.map(() => ({ integerValue: "1" })),
            })),
          };
        } else {
          status = 400;
          body = {
            error: { code: 400, status: "INVALID_ARGUMENT", message: entry.refusedCommitMessage },
          };
        }
        break;
      default:
        throw new Error("unreachable");
    }
    return { index, stepId, kind: op.kind, status, body };
  });
  return { schema: "fireemu-commit-transform-local-rows-v1", caseId: entry.id, rows, ...overrides };
}

test("documentedReference covers every plan operation exactly once", () => {
  const reference = documentedReference(plan, entry);
  assert.equal(reference.length, 17);
  assert.deepEqual(
    reference.map((r) => r.stepId),
    entry.stepIds,
  );
});

test("a fully-conforming local execution is a MATCH on every row", () => {
  const production = documentedReference(plan, entry);
  const comparison = compareCommitTransform({
    entry,
    program: plan,
    production,
    actual: localRowsFixture(),
  });
  assert.equal(comparison.verdict, "MATCH");
  assert.deepEqual(comparison.counts, { match: 17, mismatch: 0, indeterminate: 0 });
});

test("a wrong refusal status is a MISMATCH, not silently accepted", () => {
  const production = documentedReference(plan, entry);
  const actual = localRowsFixture();
  const row = actual.rows.find((r) => r.stepId === "commit-transform:over-501");
  row.status = 200;
  row.body = { commitTime: "t", writeResults: [] };
  const comparison = compareCommitTransform({ entry, program: plan, production, actual });
  assert.equal(comparison.verdict, "MISMATCH");
  assert.equal(
    comparison.rows.find((r) => r.stepId === "commit-transform:over-501").comparison,
    "MISMATCH",
  );
});

test("a different refusal message text is a MISMATCH (literal comparison, no normalization)", () => {
  const production = documentedReference(plan, entry);
  const actual = localRowsFixture();
  const row = actual.rows.find((r) => r.stepId === "commit-transform:over-501");
  row.body.error.message = "a different message";
  const comparison = compareCommitTransform({ entry, program: plan, production, actual });
  assert.equal(comparison.verdict, "MISMATCH");
});

test("writeResults must be one entry per write, each with its own transformResults count", () => {
  const production = documentedReference(plan, entry);
  const actual = localRowsFixture();
  const row = actual.rows.find((r) => r.stepId === "commit-transform:exact-500");
  // A flat array sized to the total transform count (500) is wrong; Firestore returns one
  // writeResult per write. Regression guard for the bug this case's own build caught.
  row.body.writeResults = Array.from({ length: 500 }, () => ({ updateTime: "t" }));
  const comparison = compareCommitTransform({ entry, program: plan, production, actual });
  assert.equal(comparison.verdict, "MISMATCH");
});

test("a missing row is INDETERMINATE, not silently dropped", () => {
  const production = documentedReference(plan, entry);
  const actual = localRowsFixture();
  actual.rows.pop();
  const comparison = compareCommitTransform({ entry, program: plan, production, actual });
  assert.equal(comparison.verdict, "INDETERMINATE");
});

test("validateCommitPlan rejects a plan that does not match the compiler", () => {
  const mutated = structuredClone(plan);
  mutated.documents["exact-500"].transformCount = 1;
  assert.throws(() => validateCommitPlan(mutated, entry), /commit-plan-compiler-drift/);
});

test("prepareCommitTransform pins the literal refusal message against the saved production record", async () => {
  const prepared = await prepareCommitTransform(REPO, entry);
  assert.equal(prepared.entry.id, entry.id);
  assert.equal(prepared.production.length, 17);
  assert.equal(prepared.provenance.oracle.historicalRawAvailable, false);
});
