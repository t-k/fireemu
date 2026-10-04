import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { EXTRA_CASES, MOVED_CASES, sdkCases } from "./fs-listen/sdk-cases.mjs";
import { conditionsOf } from "./fs-listen/sdk-record.mjs";

const closure = JSON.parse(
  readFileSync(
    new URL("../../spec/compatibility/closure/FS-LISTEN-SDK.json", import.meta.url),
    "utf8",
  ),
);
const catalog = JSON.parse(
  readFileSync(
    new URL("../../spec/compatibility/fs-listen-sdk-cases.json", import.meta.url),
    "utf8",
  ),
);

test("the SDK cases are the catalog's retained cases plus the three extras, none moved", () => {
  const ids = sdkCases().map((c) => c.caseId);
  assert.equal(new Set(ids).size, ids.length);
  assert.equal(ids.length, catalog.cases.length - MOVED_CASES.size + EXTRA_CASES.length);
  for (const moved of MOVED_CASES) assert.ok(!ids.includes(moved), moved);
  for (const extra of EXTRA_CASES) assert.ok(ids.includes(extra.caseId), extra.caseId);
  // The closure keeps 15 catalog cases here.
  assert.equal(ids.length - EXTRA_CASES.length, closure.productionPlan.retainedCatalogCases);
});

test("the cases that sign in, or need an account, run after the ones that do not", () => {
  const ids = sdkCases().map((c) => c.caseId);
  const lastPlain = Math.max(...ids.map((id, n) => (/10[0-7]|111/.test(id) ? n : -1)));
  assert.ok(ids.indexOf("FS-LISTEN-SDK-108") > lastPlain);
  assert.ok(ids.indexOf("FS-LISTEN-SDK-108C") > lastPlain);
  // 106N needs the primary client signed out, so it runs before anything signs it in.
  assert.ok(ids.indexOf("FS-LISTEN-SDK-106N") < ids.indexOf("FS-LISTEN-SDK-108"));
});

test("every case is well formed for the step machine and maps to a closure condition", () => {
  const conditionIds = new Set(closure.conditions.map((c) => c.conditionId));
  for (const spec of sdkCases()) {
    assert.ok(Array.isArray(spec.expectedLocal), spec.caseId);
    assert.ok(Array.isArray(spec.invariants), spec.caseId);
    const declared = new Set(spec.listeners.map((l) => l.name));
    for (const step of spec.steps)
      if (step.listener) assert.ok(declared.has(step.listener), `${spec.caseId}: ${step.listener}`);
    for (const condition of conditionsOf(spec.caseId))
      assert.ok(conditionIds.has(condition), `${spec.caseId}: ${condition}`);
  }
});

test("a case that waits for a server snapshot subscribes with metadata changes", () => {
  // Without metadata changes the SDK raises no callback for a server-confirmed unchanged result,
  // so `awaitServer` on such a listener never completes.
  for (const spec of sdkCases()) {
    const byName = new Map(spec.listeners.map((l) => [l.name, l]));
    for (const step of spec.steps)
      if (step.kind === "awaitServer")
        assert.equal(
          byName.get(step.listener).includeMetadataChanges,
          true,
          `${spec.caseId}: ${step.listener}`,
        );
  }
});

test("a grouped write names a group of at least two, and every member agrees on it", () => {
  for (const spec of sdkCases()) {
    const groups = new Map();
    for (const step of spec.steps) {
      const group = step.fields?.__txn;
      if (!group) continue;
      assert.ok(group.size >= 2, spec.caseId);
      groups.set(group.id, [...(groups.get(group.id) ?? []), group.size]);
    }
    for (const [id, sizes] of groups) {
      assert.equal(new Set(sizes).size, 1, `${spec.caseId}: ${id}`);
      assert.equal(sizes.length, sizes[0], `${spec.caseId}: ${id} members`);
    }
  }
});
