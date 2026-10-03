import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const modulePath = resolve(root, "conformance/src/production-closure.mjs");
const api = async () => {
  assert.ok(existsSync(modulePath), "the production projection checker must be published");
  return import(modulePath);
};
const fixture = async () => (await api()).loadRepository(root);
const clone = (value) => structuredClone(value);
const pending = (value) => value.registry.parents.find((p) => p.parent === "STORAGE-RULES");
const problems = async (value) => (await api()).checkProjection(value).problems;

test("current projection reads the actual partial files instead of freezing every parent pending", async () => {
  const result = (await api()).checkProjection(await fixture());
  assert.ok(Array.isArray(result.currentEvidence), "current actual evidence must be evaluated");
  const transaction = result.currentEvidence.find((row) => row.parent === "FS-TRANSACTION");
  assert.equal(transaction.records.length, 2);
  assert.equal(transaction.eligible, false);
  assert.ok(transaction.missing.some((reason) => reason.includes("0/4")));
});

test("consumer migration requires executable actual and negative calls, not comment pins", async () => {
  const path = "conformance/src/fs-transaction-closure.test.mjs";
  const source = (await fixture()).documents.get(path).toString();
  const actual = 'assertCurrentParentEvidence(loadRepository(root), "FS-TRANSACTION")';
  const negative = 'assertCurrentParentEvidence(value, "FS-TRANSACTION")';
  assert.ok(source.includes(actual) && source.includes(negative));
  for (const change of [
    (s) => s.replace(actual, `({ eligible: false }) /* ${actual} */`),
    (s) => s.replace(negative, `({ eligible: false }) /* ${negative} */`),
    (s) => `${s}\n${actual};\n`,
  ]) {
    const value = await fixture();
    value.documents.set(path, Buffer.from(change(source)));
    assert.ok((await problems(value)).some((p) => p.includes("connection missing")));
  }
});

test("honest pending integrity preserves 21 parents, 95 public and 66 frozen conditions", async () => {
  const { checkProjection, renderStatus } = await api();
  const value = await fixture();
  const result = checkProjection(value);
  assert.deepEqual(result.problems, []);
  assert.equal(result.requiredParents, 21);
  assert.equal(result.historicalAccepted.length, 13);
  assert.equal(result.remaining.length, 8);
  assert.equal(result.publicOriginalConditions, 95);
  assert.equal(result.unpublishedOriginalConditions, 66);
  assert.equal(result.requireAll, false);
  assert.equal(result.currentProductionVerified.length, 0);
  assert.equal(
    renderStatus(result),
    readFileSync(resolve(root, "docs/compatibility/production-parent-status.md"), "utf8"),
  );
});

test("exact required IDs reject missing, duplicate and extra parents", async () => {
  for (const change of [
    (v) => v.registry.parents.pop(),
    (v) => v.registry.parents.push(clone(v.registry.parents[0])),
    (v) => {
      v.registry.parents[0].parent = "TASK-QUEUE";
    },
    (v) => v.registry.requiredParentIds.pop(),
  ]) {
    const value = await fixture();
    change(value);
    assert.ok((await problems(value)).some((p) => p.includes("required parent")));
  }
});

test("pending canonical pins include new current inventories and existing consumers", async () => {
  const { checkProjection } = await api();
  const value = await fixture();
  value.lock.records = {};
  const result = checkProjection(value);
  assert.ok(result.pendingPins.length >= 29);
  assert.ok(result.pendingPins.includes("conformance/src/production-evidence.mjs"));
  assert.ok(
    result.pendingPins.includes(
      "spec/compatibility/broad-runs/fs-transaction-p13b-recorded-observations-v1.json",
    ),
  );
  assert.ok(result.pendingPins.includes("conformance/src/storage-rules-closure.test.mjs"));
  assert.ok(result.pendingPins.includes("spec/compatibility/closure/FS-DATA-WRITE.json"));
});

test("unpublished inventories remain UNKNOWN and cannot become adopted closure evidence", async () => {
  const value = await fixture();
  const unpublished = value.registry.parents.find((p) => p.parent === "FUNCTIONS-EVENTS");
  assert.equal(unpublished.publicationState, "UNKNOWN");
  assert.equal(unpublished.conditionRegistry.length, 22);
  unpublished.publicationState = "PUBLISHED";
  assert.ok((await problems(value)).some((p) => p.includes("publication")));
});

test("every original obligation remains mapped, including mixed production and final gates", async () => {
  for (const change of [
    (p) => p.conditions.pop(),
    (p) => {
      p.conditions[0].facets = [];
    },
    (p) => {
      p.conditions[0].classification = "OFFICIAL_ONLY";
    },
    (p) => {
      p.conditions.find((c) => c.conditionId.endsWith("final-artifact-regression")).facets[0].kind =
        "OFFICIAL_COMPARISON";
    },
    (p) => {
      p.conditions.find((c) => c.conditionId.endsWith("closure-review")).facets[0].kind =
        "OFFICIAL_COMPARISON";
    },
    (p) => {
      p.profileContract = null;
    },
  ]) {
    const value = await fixture();
    change(pending(value));
    assert.ok(
      (await problems(value)).length > 0,
      "an original mandatory obligation must not disappear",
    );
  }
});

test("original IDs, cases, history bytes and frozen provenance are immutable", async () => {
  for (const change of [
    (v) => {
      pending(v).conditionRegistry[0].conditionId += "-changed";
    },
    (v) => {
      pending(v).conditionRegistry[0].casesSha256 = "0".repeat(64);
    },
    (v) => {
      pending(v).sourceIdentity.rawSha256 = "0".repeat(64);
    },
    (v) => {
      const path = pending(v).sourceIdentity.snapshotPath;
      v.documents.set(path, `${v.documents.get(path)} `);
    },
    (v) => {
      v.registry.parents[0].sourceIdentity.rawSha256 = "0".repeat(64);
    },
    (v) => {
      const path = v.registry.parents[0].inventoryPath;
      v.documents.set(path, `${v.documents.get(path)} `);
    },
    (v) => {
      const p = v.registry.parents.find((row) => row.parent === "PUBSUB");
      p.conditionRegistry.pop();
    },
  ]) {
    const value = await fixture();
    change(value);
    assert.ok((await problems(value)).length > 0);
  }
});

test("official OPEN preserves original status and does not issue production acceptance", async () => {
  const { checkProjection } = await api();
  const value = await fixture();
  assert.equal(value.official.tasks.length, 3);
  assert.ok(value.official.tasks.every((task) => task.state === "OPEN"));
  assert.equal(checkProjection(value).requireAll, false);
  value.official.tasks[0].state = "VERIFIED";
  assert.ok((await problems(value)).some((p) => p.includes("official")));
});

test("source-only, old or synthetic status cannot complete the new product or review gates", async () => {
  for (const change of [
    (v) => {
      pending(v).conditions[0].facets[0].state = "VERIFIED";
    },
    (v) => {
      v.registry.globalFinalProduct.state = "VERIFIED";
    },
    (v) => {
      v.registry.consumerMigration.state = "SOURCE_ONLY_VERIFIED";
    },
    (v) => {
      pending(v).conditions[0].facets[0].evidence = { sourceOnly: true };
    },
    (v) => {
      v.registry.extraApproval = true;
    },
  ]) {
    const value = await fixture();
    change(value);
    assert.ok((await problems(value)).length > 0);
  }
});

test("the finite production model excludes only official comparison", async () => {
  const { productionEligible } = await api();
  const requiredKinds = [
    "PRODUCTION_BEHAVIOR",
    "LOCAL_PRODUCT",
    "FINAL_PRODUCT",
    "CLEAN_REVIEW",
    "EMULATOR_PROFILE_CONTRACT",
  ];
  for (let bits = 0; bits < 32; bits++) {
    for (const officialState of ["OPEN", "VERIFIED"]) {
      const facets = requiredKinds.map((kind, i) => ({
        kind,
        state: bits & (1 << i) ? "VERIFIED" : "OPEN",
      }));
      facets.push({ kind: "OFFICIAL_COMPARISON", state: officialState });
      assert.equal(
        productionEligible(facets),
        bits === 31,
        `finite state ${bits}/${officialState}`,
      );
      assert.equal(productionEligible([...facets, { kind: "UNKNOWN", state: "VERIFIED" }]), false);
    }
  }
  assert.equal(productionEligible([]), false);
  assert.equal(productionEligible([{ kind: "OFFICIAL_COMPARISON", state: "OPEN" }]), false);
  assert.equal(productionEligible([{ kind: "MADE_UP", state: "VERIFIED" }]), false);
});

test("seeded properties preserve order independence and refuse lost or duplicate obligations", async () => {
  const { checkProjection, renderStatus } = await api();
  const expectedStatus = renderStatus(checkProjection(await fixture()));
  let seed = 0x21c09566;
  const next = () => (seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0);
  for (let i = 0; i < 96; i++) {
    const value = await fixture();
    for (let j = value.registry.parents.length - 1; j > 0; j--) {
      const k = next() % (j + 1);
      [value.registry.parents[j], value.registry.parents[k]] = [
        value.registry.parents[k],
        value.registry.parents[j],
      ];
    }
    assert.deepEqual(checkProjection(value).problems, []);
    assert.equal(
      renderStatus(checkProjection(value)),
      expectedStatus,
      "status depends only on current evidence, not registry ordering",
    );
    const p = pending(value);
    const index = next() % p.conditions.length;
    if (i % 2) p.conditions.splice(index, 1);
    else p.conditions.push(clone(p.conditions[index]));
    assert.ok(checkProjection(value).problems.length > 0);
  }
});

test("strict JSON refuses duplicate keys, malformed UTF-8 and accidental cyclic references", async () => {
  const { parseStrictJson } = await api();
  assert.throws(() => parseStrictJson('{"state":"OPEN","state":"VERIFIED"}'), /duplicate/);
  assert.throws(() => parseStrictJson('{"x":{"a":1,"a":2}}'), /duplicate/);
  assert.deepEqual(parseStrictJson('{"x":{"a":1},"y":{"a":2}}'), { x: { a: 1 }, y: { a: 2 } });
  assert.throws(() => parseStrictJson(Buffer.from([0xff])), /UTF-8/);
  const value = await fixture();
  value.official.parentRegistryPath = "spec/compatibility/production-parent-registry.json";
  assert.ok((await problems(value)).length > 0);
});
