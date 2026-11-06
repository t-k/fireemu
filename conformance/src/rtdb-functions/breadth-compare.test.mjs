import { test } from "node:test";
import assert from "node:assert/strict";
import { compareRecordings } from "./breadth-compare.mjs";
import { MASKED_NONCE } from "./mask-breadth.mjs";

const frame = (id, threw, extra = {}) => ({
  handler: "g9WrittenV2Retry",
  generation: 2,
  seq: 1,
  receivedAt: "later",
  event: {
    id,
    time: "2026-01-01T00:00:00.000Z",
    eventKeys: ["id", "time"],
    params: { group: "ga", id: "a1" },
    data: {
      before: { exists: false, value: null },
      after: { exists: true, value: { value: 1, run: MASKED_NONCE } },
    },
    ...extra,
  },
  attempt: { threw, ageMs: 10 },
});
const id = Buffer.alloc(20).toString("base64");
test("compares attempt patterns, counts and every event member without timing", () => {
  const a = [frame(id, true), frame(id, false)];
  const b = [
    frame(id, true),
    { ...frame(id, false), receivedAt: "other", attempt: { threw: false, ageMs: 20 } },
  ];
  assert.equal(compareRecordings({ production: a, local: b }).totals.difference, 0);
  assert.ok(compareRecordings({ production: a, local: [b[1], b[0]] }).totals.difference);
  assert.ok(compareRecordings({ production: a, local: [b[0]] }).totals.difference);
  assert.ok(
    compareRecordings({ production: a, local: [b[0], frame(id, false, { unexpected: 1 })] }).totals
      .difference,
  );
});

test("compares token keys as a set and masks user identities", () => {
  const make = (uid, keys) => ({
    handler: "g9WrittenV1Retry",
    generation: 1,
    attempt: { threw: false },
    event: {
      context: {
        eventId: id,
        timestamp: "2026-01-01T00:00:00.000Z",
        contextKeys: [],
        params: { group: "ga", id: "a1" },
        auth: { uid, tokenKeys: keys },
      },
      data: {
        before: { exists: false, value: null },
        after: { exists: true, value: { value: 1, run: MASKED_NONCE } },
      },
    },
  });
  assert.equal(
    compareRecordings({ production: [make("one", ["a", "b"])], local: [make("two", ["b", "a"])] })
      .totals.difference,
    0,
  );
  assert.ok(
    compareRecordings({ production: [make("one", ["a"])], local: [make("two", ["b"])] }).totals
      .difference,
  );
});
