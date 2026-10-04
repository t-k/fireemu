import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import {
  EXTRA_CASES,
  MOVED_CASES,
  OWNER_COLLECTION,
  PUBLIC_COLLECTION,
  sdkCases,
} from "./fs-listen/sdk-cases.mjs";
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

test("sdkCases puts a case that signs in or needs rules after the plain ones, keeping 106N early", () => {
  const spec = (caseId, extra = {}) => ({
    caseId,
    requiresRules: false,
    steps: [{ kind: "seed" }],
    listeners: [],
    ...extra,
  });
  const fake = {
    cases: [
      spec("FS-LISTEN-SDK-901", { requiresRules: true }),
      spec("FS-LISTEN-SDK-902"),
      spec("FS-LISTEN-SDK-903", { steps: [{ kind: "signIn" }] }),
      spec("FS-LISTEN-SDK-106N", { requiresRules: true }),
      spec("FS-LISTEN-SDK-106"),
      spec("FS-LISTEN-SDK-904"),
    ],
  };
  const ids = sdkCases(fake).map((c) => c.caseId);
  const extras = EXTRA_CASES.map((c) => c.caseId);
  assert.deepEqual(ids, [
    "FS-LISTEN-SDK-902",
    "FS-LISTEN-SDK-106N",
    "FS-LISTEN-SDK-904",
    ...extras,
    "FS-LISTEN-SDK-901",
    "FS-LISTEN-SDK-903",
  ]);
});

test("the three extra cases carry what the step machine reads", () => {
  assert.deepEqual(
    EXTRA_CASES.map((c) => c.caseId),
    ["FS-LISTEN-SDK-103L", "FS-LISTEN-SDK-103T", "FS-LISTEN-SDK-111"],
  );
  const [limitToLast, grouped, offline] = EXTRA_CASES;
  assert.equal(limitToLast.listeners[0].limitToLast, true);
  assert.equal(limitToLast.listeners[0].limit, 2);
  assert.equal(grouped.listeners[0].includeMetadataChanges, false);
  assert.equal(grouped.collapseMetadataOnly, false);
  assert.equal(offline.comparison, "aggregate-changes");
  assert.deepEqual(offline.invariants, ["from-cache-true-then-false-across-break"]);
  for (const c of EXTRA_CASES) {
    assert.equal(c.listeners[0].name, "primary");
    assert.equal(c.listeners[0].kind, "query");
    assert.deepEqual(c.listeners[0].where, ["rank", "<", 10]);
  }
  // The transaction case writes two documents of one group, then ungrouped ones.
  const writes = grouped.steps.filter((s) => s.kind === "write");
  assert.deepEqual(
    writes.map((s) => Boolean(s.fields.__txn)),
    [true, true, false, false],
  );
  assert.ok(writes.every((s) => s.client === "witness"));
  // The offline case breaks and resumes the primary client around the witness's changes.
  const kinds = offline.steps.map((s) => s.kind);
  assert.ok(
    kinds.indexOf("break") < kinds.indexOf("delete") &&
      kinds.indexOf("delete") < kinds.indexOf("resume"),
  );
});

test("the collections are the ones the deployed Rules allow", () => {
  assert.equal(PUBLIC_COLLECTION, "conf_listen");
  assert.equal(OWNER_COLLECTION, "conf_rules_owner");
  assert.deepEqual([...MOVED_CASES].toSorted(), [
    "FS-LISTEN-SDK-106",
    "FS-LISTEN-SDK-109",
    "FS-LISTEN-SDK-109C",
  ]);
});
