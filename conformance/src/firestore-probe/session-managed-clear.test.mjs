import assert from "node:assert/strict";
import test from "node:test";

import {
  isManagedClearCommitRefusal,
  managedClearScope,
  managedShrinkScope,
  createShrinkRequestCounter,
  validateManagedClearOperation,
  validateManagedClearReadback,
  validateLegacyDebrisDocument,
  validateShrinkBoundaryDocument,
  validateShrinkBoundaryState,
  assertV3ProductionCleanupAllowed,
  isExactDeltaV3ProductionScope,
} from "./sandbox-session.mjs";

const prefix = "projects/fireemu-oracle-sbx/databases/(default)/documents/";
const names = [`${prefix}g500a/doc`, `${prefix}g1000b/doc`];
const frozenNames = (specs) =>
  specs.map(
    ([collectionPrefix, collectionLength, documentLength]) =>
      `${prefix}${collectionPrefix.padEnd(collectionLength, "c")}/${"d".repeat(documentLength)}`,
  );
const legacy = frozenNames([
  ["barrayname100012116n31", 998, 1],
  ["barrayname100012121n32", 998, 1],
  ["barrayname100012123n33", 998, 1],
  ["barrayname20007179n45", 1400, 599],
  ["barrayname20007183n47", 1400, 599],
  ["barrayname20007184n49", 1400, 599],
]);
const corpusV3 = frozenNames([
  ["g500a", 498, 1],
  ["g500b", 498, 1],
  ["g2000a", 1400, 599],
  ["g2000b", 1400, 599],
  ["g1000a", 998, 1],
  ["g1000b", 998, 1],
  ...["rest", "commit", "batch-write"].flatMap((route) =>
    [12_112, 12_113].map((length) => [
      `del${route.replaceAll("-", "")}${length}DELETE_RUN_ID`,
      979,
      1,
    ]),
  ),
]);

test("v3 production cleanup refuses the generic broad-clear path before network", () => {
  let networkCalls = 0;
  assert.throws(
    () => assertV3ProductionCleanupAllowed({ host: "firestore.googleapis.com" }),
    /v3 production cleanup is blocked.*generic broad clear is disabled/,
  );
  assert.equal(networkCalls, 0);
  assert.doesNotThrow(() => assertV3ProductionCleanupAllowed({ host: "127.0.0.1:8080" }));
  assert.doesNotThrow(() =>
    assertV3ProductionCleanupAllowed({ host: "firestore.googleapis.com", exactDeltaV3: true }),
  );
});

test("delta-v3 remote scope requires the dedicated journal binding and exact names", () => {
  const runId = "a".repeat(32);
  const deltaNames = corpusV3.slice(6).map((name) => name.replaceAll("DELETE_RUN_ID", runId));
  const scope = {
    mode: true,
    lockHeld: true,
    host: "firestore.googleapis.com",
    scheme: "https",
    project: "fireemu-oracle-sbx",
    maxRequests: 430,
    deltaJournal: "/private/delta.json",
    managedClearJournal: "/private/delta.json",
    names: deltaNames,
  };
  assert.equal(isExactDeltaV3ProductionScope(scope), true);
  assert.equal(isExactDeltaV3ProductionScope({ ...scope, host: "attacker.example" }), false);
  assert.equal(isExactDeltaV3ProductionScope({ ...scope, scheme: "http" }), false);
  assert.equal(isExactDeltaV3ProductionScope({ ...scope, host: "127.0.0.1:8080" }), false);
  assert.equal(isExactDeltaV3ProductionScope({ ...scope, managedClearJournal: undefined }), false);
  assert.equal(
    isExactDeltaV3ProductionScope({ ...scope, managedClearJournal: "/private/legacy.json" }),
    false,
  );
  assert.equal(isExactDeltaV3ProductionScope({ ...scope, lockHeld: false }), false);
  assert.equal(isExactDeltaV3ProductionScope({ ...scope, maxRequests: 431 }), false);
  assert.equal(
    isExactDeltaV3ProductionScope({ ...scope, names: [...deltaNames, deltaNames[0]] }),
    false,
  );
});

test("shrink request counter cannot reset between cleanup phases", () => {
  const counter = createShrinkRequestCounter(160);
  for (let request = 0; request < 140; request += 1) counter.claim();
  for (let request = 140; request < 160; request += 1) counter.claim();
  assert.equal(counter.current(), 160);
  assert.throws(() => counter.claim(), /cap reached before network send/);
  assert.equal(counter.current(), 160);
  assert.equal(counter.reset, undefined);
  assert.throws(() => counter.claim(), /cap reached before network send/);
});

test("array shrink accepts only the untouched frozen sequence or an empty document", () => {
  const document = {
    name: corpusV3[0],
    updateTime: "2026-09-24T00:00:00Z",
    fields: {
      a: {
        arrayValue: {
          values: Array.from({ length: 19_999 - 1_024 }, (_, index) => ({
            integerValue: String(index + 1_024),
          })),
        },
      },
    },
  };
  assert.throws(
    () => validateShrinkBoundaryState(document, corpusV3[0], 19_999),
    /operator recovery/,
  );
  const untouched = {
    ...document,
    fields: {
      a: {
        arrayValue: {
          values: Array.from({ length: 19_999 }, (_, index) => ({ integerValue: String(index) })),
        },
      },
    },
  };
  assert.equal(validateShrinkBoundaryState(untouched, corpusV3[0], 19_999).length, 19_999);
  assert.equal(
    validateShrinkBoundaryState(
      { ...untouched, fields: { a: { arrayValue: { values: [] } } } },
      corpusV3[0],
      19_999,
    ).length,
    0,
  );
  for (const invalid of [
    { ...document, fields: { a: { arrayValue: { values: [{ integerValue: "1025" }] } } } },
    {
      ...document,
      fields: {
        a: {
          arrayValue: {
            values: document.fields.a.arrayValue.values.slice(0, -1),
          },
        },
      },
    },
  ]) {
    assert.throws(() => validateShrinkBoundaryState(invalid, corpusV3[0], 19_999));
  }
});

test("empty ProtoJSON may omit repeated values only when emptiness is explicitly expected", () => {
  const empty = {
    name: corpusV3[0],
    updateTime: "2026-09-24T00:00:00Z",
    fields: { a: { arrayValue: {} } },
  };
  assert.throws(() => validateShrinkBoundaryState(empty, corpusV3[0], 19_999));
  assert.deepEqual(
    validateShrinkBoundaryState(empty, corpusV3[0], 19_999, { allowEmptyOmitted: true }),
    [],
  );
});

test("legacy debris accepts only a typed deterministic integer suffix", () => {
  const length = 12_116;
  const suffix = {
    name: legacy[0],
    updateTime: "2026-09-24T00:00:00Z",
    fields: {
      a: {
        arrayValue: {
          values: Array.from({ length: 3 }, (_, index) => ({
            integerValue: String(length - 3 + index),
          })),
        },
      },
    },
  };
  assert.equal(validateLegacyDebrisDocument(suffix, legacy[0], length).length, 3);
  assert.deepEqual(
    validateLegacyDebrisDocument(
      { ...suffix, fields: { a: { arrayValue: {} } } },
      legacy[0],
      length,
    ),
    [],
  );
  for (const invalid of [
    { ...suffix, name: legacy[1] },
    { ...suffix, fields: { a: { arrayValue: { values: [{ integerValue: "5" }] } } } },
    {
      ...suffix,
      fields: {
        a: {
          arrayValue: { values: [...suffix.fields.a.arrayValue.values, { integerValue: "1" }] },
        },
      },
    },
    {
      ...suffix,
      fields: {
        a: { arrayValue: { unexpected: true, values: suffix.fields.a.arrayValue.values } },
      },
    },
  ]) {
    assert.throws(() => validateLegacyDebrisDocument(invalid, legacy[0], length));
  }
});

test("managed clear is limited to distinct root collections in the fixed sandbox", () => {
  assert.deepEqual(managedClearScope(names, "fireemu-oracle-sbx", "(default)"), [
    "g500a",
    "g1000b",
  ]);
  for (const invalid of [
    [`${prefix}g500a/doc`, `${prefix}g500a/other`],
    [`${prefix}g500a/doc/child/nested`],
    ["projects/other/databases/(default)/documents/g500a/doc"],
    ["projects/fireemu-oracle-sbx/databases/other/documents/g500a/doc"],
    ["projects/fireemu-oracle-sbx/databases/(default)/documents/g500a"],
  ]) {
    assert.throws(() => managedClearScope(invalid, "fireemu-oracle-sbx", "(default)"));
  }
  assert.throws(() => managedClearScope(names, "another-project", "(default)"));
});

test("array shrink is restricted to frozen legacy or corpus-v3 root document names", () => {
  assert.equal(managedShrinkScope(legacy, "fireemu-oracle-sbx", "(default)"), "legacy");
  assert.equal(managedShrinkScope(corpusV3, "fireemu-oracle-sbx", "(default)"), "v3");
  for (const invalid of [
    legacy.slice(0, 5),
    [...legacy.slice(0, 5), corpusV3[0]],
    [...legacy.slice(0, 5), legacy[0]],
    legacy.map((name) => (name === legacy[0] ? name.replace("n31", "n30") : name)),
    corpusV3.slice(0, 11),
    [...corpusV3.slice(0, 11), legacy[0]],
    corpusV3.map((name) => (name === corpusV3[0] ? name.replace("g500a", "g500c") : name)),
    corpusV3.map((name) => (name === corpusV3[0] ? name.replace(/\/d$/, "/x") : name)),
    [`${prefix}${"g500a"}${"c".repeat(493)}/d/child/nested`],
  ]) {
    assert.throws(() => managedShrinkScope(invalid, "fireemu-oracle-sbx", "(default)"));
  }
  assert.throws(() => managedShrinkScope(corpusV3, "another-project", "(default)"));
});

test("delta-v3 cleanup has a distinct exact six-name shrink scope", () => {
  const deltaNames = corpusV3.slice(6);
  assert.equal(managedShrinkScope(deltaNames, "fireemu-oracle-sbx", "(default)"), "delta-v3");
  assert.throws(() =>
    managedShrinkScope([...deltaNames.slice(0, 5), corpusV3[0]], "fireemu-oracle-sbx", "(default)"),
  );
});

test("array shrink accepts only the exact generated integer sequence field", () => {
  const document = {
    name: names[0],
    updateTime: "2026-09-24T00:00:00Z",
    fields: {
      a: {
        arrayValue: {
          values: [0, 1, 2].map((value) => ({ integerValue: String(value) })),
        },
      },
    },
  };
  assert.deepEqual(validateShrinkBoundaryDocument(document, names[0]), [
    { integerValue: "0" },
    { integerValue: "1" },
    { integerValue: "2" },
  ]);
  for (const invalid of [
    { ...document, name: `${prefix}other/item` },
    { ...document, updateTime: undefined },
    { ...document, fields: { a: { arrayValue: { values: [{ integerValue: "1" }] } } } },
    { ...document, fields: { a: { arrayValue: { values: [{ stringValue: "0" }] } } } },
    {
      ...document,
      fields: {
        a: {
          arrayValue: { values: document.fields.a.arrayValue.values },
          b: { integerValue: "1" },
        },
      },
    },
  ]) {
    assert.throws(() => validateShrinkBoundaryDocument(invalid, names[0]));
  }
});

test("managed clear accepts only exact typed-missing readback", () => {
  assert.equal(
    validateManagedClearReadback(
      names,
      names.map((name) => ({ missing: name })),
    ),
    true,
  );
  for (const invalid of [
    [{ missing: names[0] }],
    [{ missing: names[0] }, { found: { name: names[1] } }],
    [{ missing: names[0] }, { missing: `${prefix}other/doc` }],
    [{ missing: names[0] }, { missing: names[0] }],
  ]) {
    assert.equal(validateManagedClearReadback(names, invalid), false);
  }
});

test("managed clear is entered only for an exact one-document transaction-size refusal", () => {
  const refusal = JSON.stringify({
    error: {
      status: "INVALID_ARGUMENT",
      message: "Transaction too big. Decrease transaction size.",
    },
  });
  assert.equal(isManagedClearCommitRefusal(400, refusal, names[0], "", names), true);
  assert.equal(isManagedClearCommitRefusal(403, refusal, names[0], "", names), false);
  assert.equal(isManagedClearCommitRefusal(400, refusal, names[0], "nested/doc", names), false);
  assert.equal(isManagedClearCommitRefusal(400, refusal, `${prefix}other/doc`, "", names), false);
  assert.equal(isManagedClearCommitRefusal(400, "not-json", names[0], "", names), false);
});

test("managed clear accepts only a terminal successful operation in the fixed database", () => {
  const name = "projects/fireemu-oracle-sbx/databases/(default)/operations/abc_123";
  assert.equal(validateManagedClearOperation({ name, done: true }, "fireemu-oracle-sbx"), name);
  for (const state of [
    { name },
    { name, done: false },
    { name, done: true, error: { message: "failed" } },
    { name: "projects/foreign/databases/(default)/operations/abc", done: true },
    { name: `${name}/../../other`, done: true },
  ]) {
    assert.throws(() => validateManagedClearOperation(state, "fireemu-oracle-sbx"));
  }
});
