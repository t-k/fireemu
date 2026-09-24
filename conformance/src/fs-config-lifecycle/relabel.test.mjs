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

test("instants in a listing are compared modulo their numbering, keeping which are equal", () => {
  const db = (name, created, earliest) => ({ name, createTime: created, earliestVersionTime: earliest });
  const production = {
    status: 200,
    body: { databases: [db("x/<db:a>", "<t1>", "<t1>"), db("x/(default)", "2026-01-01T00:00:00Z", "<t2>")] },
  };
  const fireemu = {
    status: 200,
    body: { databases: [db("x/<db:a>", "<t2>", "<t2>"), db("x/(default)", "2026-01-01T00:00:00Z", "<t1>")] },
  };
  assert.ok(sameModuloIdNames(production, fireemu));
  const merged = {
    status: 200,
    body: { databases: [db("x/<db:a>", "<t1>", "<t1>"), db("x/(default)", "2026-01-01T00:00:00Z", "<t1>")] },
  };
  assert.ok(!sameModuloIdNames(production, merged), "two instants are not one");
});
