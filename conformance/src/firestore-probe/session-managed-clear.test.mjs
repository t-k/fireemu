import assert from "node:assert/strict";
import test from "node:test";

import {
  isManagedClearCommitRefusal,
  managedClearScope,
  validateManagedClearOperation,
  validateManagedClearReadback,
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
