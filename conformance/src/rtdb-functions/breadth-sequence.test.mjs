import { test } from "node:test";
import assert from "node:assert/strict";
import { applyWrite, itemTransitions } from "./breadth-sequence.mjs";

test("ancestor and multi-path writes report only changed leaves", () => {
  const steps = [
    { id: "a", method: "PUT", path: "g9-rtdb/ga", body: { items: { a: { n: 1 }, b: { n: 2 } } } },
    {
      id: "b",
      method: "PATCH",
      path: "g9-rtdb",
      body: { "ga/items/a/n": 1, "ga/items/b/n": 3, "gb/items/c": { n: 4 } },
    },
    { id: "c", method: "DELETE", path: "g9-rtdb/ga" },
  ];
  const transitions = itemTransitions(steps);
  assert.deepEqual(
    transitions.map((t) => t.leaves.map(({ group, id }) => `${group}/${id}`)),
    [
      ["ga/a", "ga/b"],
      ["ga/b", "gb/c"],
      ["ga/a", "ga/b"],
    ],
  );
  assert.deepEqual(applyWrite({}, "PATCH", ["g9-rtdb"], { "ga/items/a": { n: 1 } }), {
    "g9-rtdb": { ga: { items: { a: { n: 1 } } } },
  });
});

import { buildSteps, observe } from "./breadth-sequence.mjs";
test("seeded writes match an independent leaf reference", () => {
  let state = 12345;
  const random = () => (state = (state * 1664525 + 1013904223) >>> 0);
  const ref = {};
  let tree = {};
  for (let n = 0; n < 300; n++) {
    const group = ["ga", "gb"][random() % 2],
      id = ["a", "b", "c"][random() % 3],
      value = random() % 5;
    const path = ["g9-rtdb", group, "items", id];
    if (random() % 3 === 0) {
      delete ref[`${group}/${id}`];
      tree = applyWrite(tree, "DELETE", path);
    } else {
      ref[`${group}/${id}`] = { value };
      tree = applyWrite(tree, "PATCH", ["g9-rtdb"], { [`${group}/items/${id}`]: { value } });
    }
    const actual = {};
    for (const [g, v] of Object.entries(tree["g9-rtdb"] ?? {}))
      for (const [i, item] of Object.entries(v.items ?? {})) actual[`${g}/${i}`] = item;
    assert.deepEqual(actual, ref);
  }
});
test("attempts group by event id and handlers expect every changed leaf", () => {
  const steps = buildSteps();
  const base = {
    handler: "g9WrittenV2Retry",
    generation: 2,
    event: {
      id: "event",
      params: { group: "ga", id: "a1" },
      data: {
        before: { exists: false, value: null },
        after: { exists: true, value: { value: 1 } },
      },
    },
    attempt: { threw: true },
  };
  const result = observe({
    steps,
    frames: [base, { ...base, attempt: { threw: false } }],
    writes: { w1: { outcome: "ok" } },
  });
  const seen = result.steps[0].leaves[0].handlers.g9WrittenV2Retry;
  assert.equal(seen.documented, 1);
  assert.equal(seen.distinctEventIds, 1);
  assert.equal(seen.attempts.event.length, 2);
  assert.equal(result.steps[2].leaves.length, 4);
});

test("PICT combinations exercise each writer, operation and handler", async () => {
  const { readFileSync } = await import("node:fs");
  // The committed table: CI has no pict binary. It is regenerated with
  // `pict breadth-pict.model /e:breadth-pict.seed.tsv > breadth-pict.tsv`.
  const read = (name) =>
    readFileSync(new URL(name, import.meta.url), "utf8")
      .trim()
      .split(/\r?\n/)
      .slice(1);
  const rows = read("./breadth-pict.tsv");
  for (const seed of read("./breadth-pict.seed.tsv")) assert.ok(rows.includes(seed), seed);
  const operations = {
    "leaf-set": ["PUT", "ga/items/a", { value: 1 }],
    "leaf-update": ["PATCH", "ga/items/a", { value: 2 }],
    "multi-path": ["PATCH", "ga", { "items/a/value": 2 }],
    "leaf-remove": ["DELETE", "ga/items/a", undefined],
    "ancestor-group-set": ["PUT", "ga", { items: { a: { value: 1 } } }],
    "ancestor-items-set": ["PUT", "ga/items", { a: { value: 1 } }],
    "ancestor-remove": ["DELETE", "ga", undefined],
    "root-multi-path": ["PATCH", "", { "ga/items/a": { value: 1 } }],
  };
  for (const row of rows) {
    const [writer, operation, generation, retry, failing] = row.split("\t");
    const [method, path, body] = operations[operation];
    const steps = [
      { id: "before", method: "PUT", path: "g9-rtdb/ga/items/a", body: { value: 0 } },
      {
        id: "case",
        method,
        path: ["g9-rtdb", path].filter(Boolean).join("/"),
        body,
        context: writer,
      },
    ];
    const result = observe({ steps, frames: [], writes: { case: { outcome: "ok" } } });
    assert.ok(result.steps[1].leaves.length, row);
    const name =
      generation === "v1"
        ? "g9WrittenV1Retry"
        : retry === "on"
          ? "g9WrittenV2Retry"
          : "g9WrittenV2";
    assert.equal(result.steps[1].leaves[0].handlers[name].documented, 1, row);
    assert.ok(["yes", "no"].includes(failing));
  }
});

test("duplicate count excludes the first frame of each event", () => {
  const frame = {
    handler: "g9WrittenV2Retry",
    generation: 2,
    event: {
      id: "event",
      params: { group: "ga", id: "a1" },
      data: {
        before: { exists: false, value: null },
        after: { exists: true, value: { value: 1 } },
      },
    },
  };
  const seen = observe({ frames: [frame, frame] }).steps[0].leaves[0].handlers.g9WrittenV2Retry;
  assert.equal(seen.duplicateFrames, 1);
});

test("identical transitions are left unattributed", () => {
  const steps = [
    { id: "one", method: "PUT", path: "g9-rtdb/ga/items/a", body: 1 },
    { id: "delete", method: "DELETE", path: "g9-rtdb/ga/items/a" },
    { id: "two", method: "PUT", path: "g9-rtdb/ga/items/a", body: 1 },
  ];
  const frame = {
    handler: "g9WrittenV2",
    generation: 2,
    event: {
      id: "x",
      params: { group: "ga", id: "a" },
      data: {
        before: { exists: false, value: null },
        after: { exists: true, value: 1 },
      },
    },
  };
  assert.deepEqual(observe({ steps, frames: [frame] }).unattributed[0].candidates, ["one", "two"]);
  assert.equal(observe({ steps, frames: [frame] }).unattributed[0].reason, "ambiguous");
});
