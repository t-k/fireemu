import assert from "node:assert/strict";
import test from "node:test";

import { compareSubscriptionTraces, normalizeCallback, projectUniqueHeadings } from "./trace.mjs";

test("normalizes a query callback without transport identities", () => {
  assert.deepEqual(
    normalizeCallback({
      subscription: "query-b",
      kind: "query",
      ids: ["item"],
      revisions: [1],
      changes: [{ type: "modified", id: "item", oldIndex: 0, newIndex: 0 }],
      metadata: { fromCache: false, hasPendingWrites: false },
      transport: { targetId: 7, resumeToken: "opaque", connectionId: "channel-2" },
    }),
    {
      subscription: "query-b",
      ordinal: 1,
      kind: "query",
      ids: ["item"],
      revisions: [1],
      changes: [{ type: "modified", id: "item", oldIndex: 0, newIndex: 0 }],
      fromCache: false,
      hasPendingWrites: false,
    },
  );
});

test("compares callback order within each subscription but not between subscriptions", () => {
  const oracle = [
    { subscription: "doc", ordinal: 1, revisions: [0] },
    { subscription: "query", ordinal: 1, revisions: [0] },
    { subscription: "doc", ordinal: 2, revisions: [1] },
    { subscription: "query", ordinal: 2, revisions: [1] },
  ];
  const interleaved = [oracle[1], oracle[0], oracle[3], oracle[2]];
  assert.deepEqual(compareSubscriptionTraces(oracle, interleaved), { equal: true });

  const duplicated = [...interleaved, { ...oracle[3], ordinal: 3 }];
  assert.deepEqual(compareSubscriptionTraces(oracle, duplicated), {
    equal: false,
    subscription: "query",
    oracle: [oracle[1], oracle[3]],
    actual: [oracle[1], oracle[3], { ...oracle[3], ordinal: 3 }],
  });
});

test("projects headings by stable document key", () => {
  assert.deepEqual(
    projectUniqueHeadings([
      { id: "a", heading: "Auto reply" },
      { id: "a", heading: "Auto reply" },
      { id: "b", heading: "Daily report" },
    ]),
    [
      { id: "a", heading: "Auto reply" },
      { id: "b", heading: "Daily report" },
    ],
  );
});
