import assert from "node:assert/strict";
import { test } from "node:test";

import { relabel, sameModuloIdNames } from "./relabel.mjs";

const index = (id, field) => ({
  name: `projects/p/databases/(default)/collectionGroups/g/indexes/${id}`,
  fields: [{ fieldPath: field, order: "ASCENDING" }],
  state: "READY",
});

test("a listing whose id symbols were numbered in a different order is the same listing", () => {
  const production = { status: 200, body: { indexes: [index("<index4>", "a"), index("<index1>", "b")] } };
  const fireemu = { status: 200, body: { indexes: [index("<index1>", "a"), index("<index2>", "b")] } };
  assert.ok(sameModuloIdNames(production, fireemu));
  assert.deepEqual(relabel(production), relabel(fireemu));
});

test("relabeling never merges two resources or changes what differs", () => {
  const two = { body: { indexes: [index("<index1>", "a"), index("<index2>", "b")] } };
  const one = { body: { indexes: [index("<index1>", "a"), index("<index1>", "b")] } };
  assert.ok(!sameModuloIdNames(two, one), "one id for two indexes is a difference");
  const other = { body: { indexes: [index("<index1>", "a"), index("<index2>", "c")] } };
  assert.ok(!sameModuloIdNames(two, other), "a different field is a difference");
  const state = { body: { indexes: [index("<index1>", "a"), { ...index("<index2>", "b"), state: "CREATING" }] } };
  assert.ok(!sameModuloIdNames(two, state));
});

test("only a listing is compared modulo id numbering", () => {
  const single = (id) => ({ status: 200, body: index(id, "a") });
  assert.ok(!sameModuloIdNames(single("<index1>"), single("<index2>")));
});
