import assert from "node:assert/strict";
import test from "node:test";

import {
  isManagedClearCommitRefusal,
  managedClearScope,
  managedShrinkScope,
  validateManagedClearOperation,
  validateManagedClearReadback,
  validateShrinkBoundaryDocument,
} from "./session.mjs";

const prefix = "projects/fireemu-oracle-sbx/databases/(default)/documents/";
const names = [`${prefix}g500a/doc`, `${prefix}g1000b/doc`];

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
  const legacy = [
    "barrayname100012116",
    "barrayname100012121",
    "barrayname100012123",
    "barrayname20007179",
    "barrayname20007183",
    "barrayname20007184",
  ].map((collection) => `${prefix}${collection}/item`);
  const corpusV3 = [
    ["g500a", 498, 1],
    ["g500b", 498, 1],
    ["g2000a", 1400, 599],
    ["g2000b", 1400, 599],
    ["g1000a", 998, 1],
    ["g1000b", 998, 1],
  ].map(
    ([tag, collectionLength, documentLength]) =>
      `${prefix}${tag}${"c".repeat(collectionLength - tag.length)}/${"d".repeat(documentLength)}`,
  );
  assert.equal(managedShrinkScope(legacy, "fireemu-oracle-sbx", "(default)"), "legacy");
  assert.equal(managedShrinkScope(corpusV3, "fireemu-oracle-sbx", "(default)"), "v3");
  for (const invalid of [
    legacy.slice(0, 5),
    [...legacy.slice(0, 5), `${prefix}g500a/item`],
    corpusV3.slice(0, 5),
    [...corpusV3.slice(0, 5), `${prefix}unexpected/item`],
    [`${prefix}${"g500a"}${"c".repeat(493)}/d/child/nested`],
  ]) {
    assert.throws(() => managedShrinkScope(invalid, "fireemu-oracle-sbx", "(default)"));
  }
  assert.throws(() => managedShrinkScope(corpusV3, "another-project", "(default)"));
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
