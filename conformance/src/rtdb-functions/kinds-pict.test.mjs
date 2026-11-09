import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { PREFIX } from "./kinds-frames.mjs";
import { observe } from "./kinds-sequence.mjs";

// The committed table: CI has no pict binary. It is regenerated with
// `pict kinds-pict.model /e:kinds-pict.seed.tsv > kinds-pict.tsv`.
const read = (name) =>
  readFileSync(new URL(name, import.meta.url), "utf8")
    .trim()
    .split(/\r?\n/u)
    .slice(1);
const rows = read("./kinds-pict.tsv");

test("the table contains every required seed row and only its factors", () => {
  for (const seed of read("./kinds-pict.seed.tsv")) assert.ok(rows.includes(seed), seed);
  assert.ok(rows.length >= 28);
  for (const row of rows) assert.equal(row.split("\t").length, 5);
});

// The starting node and the operation, written out by hand: the reference of the differential test.
const START = {
  absent: {},
  present: { "ga/a": { value: 0 } },
  same: { "ga/a": { value: 1 }, "ga/b": { value: 1 } },
};
const OPERATIONS = {
  "leaf-set": {
    method: "PUT",
    path: "ga/items/a",
    body: { value: 1 },
    apply: (state) => ({ ...state, "ga/a": { value: 1 } }),
  },
  "leaf-update": {
    method: "PATCH",
    path: "ga/items/a",
    body: { value: 2 },
    apply: (state) => ({ ...state, "ga/a": { ...state["ga/a"], value: 2 } }),
  },
  "leaf-remove": {
    method: "DELETE",
    path: "ga/items/a",
    apply: ({ "ga/a": _a, ...rest }) => rest,
  },
  "ancestor-group-set": {
    method: "PUT",
    path: "ga",
    body: { items: { a: { value: 1 }, b: { value: 1 } } },
    apply: (state) => {
      const { "ga/a": _a, "ga/b": _b, ...rest } = state;
      return { ...rest, "ga/a": { value: 1 }, "ga/b": { value: 1 } };
    },
  },
  "ancestor-items-set": {
    method: "PUT",
    path: "ga/items",
    body: { a: { value: 1 }, b: { value: 1 } },
    apply: (state) => {
      const { "ga/a": _a, "ga/b": _b, ...rest } = state;
      return { ...rest, "ga/a": { value: 1 }, "ga/b": { value: 1 } };
    },
  },
  "multi-path": {
    method: "PATCH",
    path: "ga",
    body: { "items/a/value": 2, "items/b/value": 2 },
    apply: (state) => ({
      ...state,
      "ga/a": { ...state["ga/a"], value: 2 },
      "ga/b": { ...state["ga/b"], value: 2 },
    }),
  },
  "ancestor-remove": {
    method: "DELETE",
    path: "ga",
    apply: ({ "ga/a": _a, "ga/b": _b, ...rest }) => rest,
  },
  "root-multi-path": {
    method: "PATCH",
    path: "",
    body: { "ga/items/a": { value: 1 }, "gb/items/c": { value: 1 } },
    apply: (state) => ({ ...state, "ga/a": { value: 1 }, "gb/c": { value: 1 } }),
  },
};
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const kind = (before, after) =>
  same(before, after)
    ? null
    : before === undefined
      ? "create"
      : after === undefined
        ? "delete"
        : "update";
const NAMES = {
  created: ["k9CreatedV1", "k9CreatedV2"],
  updated: ["k9UpdatedV1", "k9UpdatedV2"],
  deleted: ["k9DeletedV1", "k9DeletedV2"],
  any: [null, "k9AnyWrittenV2"],
  group: [null, "k9GroupWrittenV2"],
};
const KIND_OF = { created: "create", updated: "update", deleted: "delete" };

test("each row: the handler is expected for exactly the leaves and groups that changed", () => {
  for (const row of rows) {
    const [writer, operation, existing, handler, generation] = row.split("\t");
    const name = NAMES[handler][generation === "v1" ? 0 : 1];
    assert.ok(name, row);
    const start = START[existing];
    const op = OPERATIONS[operation];
    const after = op.apply(start);
    const steps = [
      ...Object.entries(start).map(([key, value], index) => {
        const [group, id] = key.split("/");
        return {
          id: `before${index}`,
          method: "PUT",
          path: `${PREFIX}/${group}/items/${id}`,
          body: value,
          context: "admin",
        };
      }),
      {
        id: "case",
        method: op.method,
        path: [PREFIX, op.path].filter(Boolean).join("/"),
        body: op.body,
        context: writer,
      },
    ];
    const report = observe({ steps, frames: [], writes: { case: { outcome: "ok" } } });
    const caseStep = report.steps.at(-1);
    // the reference: which leaves changed, which groups changed
    const keys = new Set([...Object.keys(start), ...Object.keys(after)]);
    const changed = [...keys].filter((key) => kind(start[key], after[key]) !== null);
    const expectedLeaves = changed
      .map((key) => `${key}:${kind(start[key], after[key])}`)
      .toSorted();
    assert.deepEqual(
      caseStep.leaves.map((l) => `${l.group}/${l.id}:${l.kind}`).toSorted(),
      expectedLeaves,
      row,
    );
    const groups = [...new Set(changed.map((key) => key.split("/")[0]))].toSorted();
    assert.deepEqual(caseStep.groups.map((g) => g.group).toSorted(), groups, row);
    // the handler's expectation per entry
    if (handler === "group") {
      for (const g of caseStep.groups) assert.equal(g.handlers[name].expected, 1, row);
      assert.equal(caseStep.groups.length, groups.length, row);
    } else {
      const wanted = changed.filter(
        (key) => handler === "any" || kind(start[key], after[key]) === KIND_OF[handler],
      );
      const got = caseStep.leaves.filter((l) => l.handlers[name].expected === 1);
      assert.deepEqual(
        got.map((l) => `${l.group}/${l.id}`).toSorted(),
        wanted.toSorted(),
        `${row} ${name}`,
      );
    }
  }
});
