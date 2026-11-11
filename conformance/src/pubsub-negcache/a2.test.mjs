import assert from "node:assert/strict";
import test from "node:test";

import { A2_MIN_AGE_MS, settleA2 } from "./a2.mjs";

const kindOf = (n) =>
  n.includes("/snapshots/") ? "snapshot" : n.includes("/topics/") ? "topic" : "subscription";
const S = (id) => `projects/p/subscriptions/${id}`;
const lists = (names, complete = true) => ({
  subscription: { complete, names },
  snapshot: { complete: true, names: [] },
  topic: { complete: true, names: [] },
});

test("A2 refuses before ten minutes", () => {
  assert.throws(
    () => settleA2({ open: [], lists: {}, kindOf, ageMs: A2_MIN_AGE_MS - 1 }),
    /ten minutes/,
  );
  assert.throws(() => settleA2({ open: [], lists: {}, kindOf, ageMs: NaN }), /ten minutes/);
  settleA2({ open: [], lists: {}, kindOf, ageMs: A2_MIN_AGE_MS });
});

test("absence from a complete LIST settles an unknown DELETE and a confirmed resource", () => {
  const open = [
    { name: S("a"), status: "delete-unknown" },
    { name: S("b"), status: "live-suspect" },
    { name: S("c"), status: "delete-404-present" },
  ];
  const out = settleA2({ open, lists: lists([]), kindOf, ageMs: A2_MIN_AGE_MS });
  assert.deepEqual(out.settled, [S("a"), S("b"), S("c")]);
});

test("a resource still listed is reported for a recovery packet", () => {
  const out = settleA2({
    open: [{ name: S("a"), status: "delete-unknown" }],
    lists: lists([S("a")]),
    kindOf,
    ageMs: A2_MIN_AGE_MS,
  });
  assert.deepEqual(out.stillPresent, [S("a")]);
  assert.deepEqual(out.settled, []);
});

test("an unknown CREATE is never settled by absence", () => {
  const out = settleA2({
    open: [{ name: S("a"), status: "unconfirmed-create" }],
    lists: lists([]),
    kindOf,
    ageMs: A2_MIN_AGE_MS,
  });
  assert.deepEqual(out.unconfirmed, [S("a")]);
  assert.deepEqual(out.settled, []);
});

test("a partial or missing LIST settles nothing", () => {
  const open = [{ name: S("a"), status: "delete-unknown" }];
  assert.deepEqual(
    settleA2({ open, lists: lists([], false), kindOf, ageMs: A2_MIN_AGE_MS }).unreadable,
    [S("a")],
  );
  assert.deepEqual(settleA2({ open, lists: {}, kindOf, ageMs: A2_MIN_AGE_MS }).unreadable, [
    S("a"),
  ]);
});

test("statuses that need no A2 are left alone", () => {
  const out = settleA2({
    open: [{ name: S("a"), status: "deleted" }],
    lists: lists([]),
    kindOf,
    ageMs: A2_MIN_AGE_MS,
  });
  assert.deepEqual(out, { settled: [], stillPresent: [], unconfirmed: [], unreadable: [] });
});
