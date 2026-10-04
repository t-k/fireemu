import assert from "node:assert/strict";
import { test } from "node:test";

import { decodeValue, frameRows, maskText } from "./fs-listen/frames.mjs";

const ROOT = "projects/p1/databases/(default)/documents";
const names = new Map([
  [`${ROOT}/lsn/r1-a`, "a"],
  [`${ROOT}/lsn/r1-b`, "b"],
]);
const target = (type, extra = {}) => ({
  kind: "targetChange",
  targetChange: { targetChangeType: type, targetIds: [1], ...extra },
});
const global = (extra = {}) => ({
  kind: "targetChange",
  targetChange: { targetChangeType: "NO_CHANGE", targetIds: [], ...extra },
});

test("decodeValue reads the Value shapes a Listen frame carries", () => {
  assert.equal(decodeValue({ integerValue: "7" }), 7);
  assert.equal(decodeValue({ stringValue: "x" }), "x");
  assert.equal(decodeValue({ booleanValue: true }), true);
  assert.equal(decodeValue({ nullValue: "NULL_VALUE" }), null);
  assert.deepEqual(decodeValue({ mapValue: { fields: { n: { integerValue: "1" } } } }), { n: 1 });
  assert.deepEqual(decodeValue({ arrayValue: { values: [{ integerValue: "1" }] } }), [1]);
  assert.deepEqual(decodeValue({ doubleValue: 1.5 }), 1.5);
});

test("decodeValue answers the placeholder shapes and empty containers", () => {
  assert.equal(decodeValue(null), null);
  assert.equal(decodeValue(undefined), null);
  assert.equal(decodeValue("text"), null);
  assert.equal(decodeValue(7), null);
  assert.equal(decodeValue({ timestampValue: "2026-01-01T00:00:00Z" }), "<timestamp>");
  assert.equal(
    decodeValue({ referenceValue: "projects/p/databases/d/documents/c/x" }),
    "<reference>",
  );
  assert.equal(decodeValue({ geoPointValue: { latitude: 1 } }), "<unsupported>");
  assert.deepEqual(decodeValue({ arrayValue: {} }), []);
  assert.deepEqual(decodeValue({ mapValue: {} }), {});
  assert.equal(decodeValue({ booleanValue: false }), false);
  assert.equal(decodeValue({ integerValue: "0" }), 0);
  assert.equal(decodeValue({ stringValue: "" }), "");
});

test("decodeValue orders map members by name, whatever the input order", () => {
  const names = ["m", "a", "z", "b", "k"];
  const orders = [names, names.toReversed(), ["z", "m", "k", "b", "a"], ["b", "k", "a", "z", "m"]];
  for (const order of orders) {
    const fields = Object.fromEntries(order.map((n) => [n, { integerValue: "1" }]));
    assert.deepEqual(Object.keys(decodeValue({ mapValue: { fields } })), ["a", "b", "k", "m", "z"]);
  }
  // Equal names cannot occur in an object, but a name that is a prefix of another sorts first.
  const prefixed = decodeValue({
    mapValue: { fields: { ab: { integerValue: "1" }, a: { integerValue: "1" } } },
  });
  assert.deepEqual(Object.keys(prefixed), ["a", "ab"]);
});

test("decodeValue sorts map members, so the server's order cannot differ a row", () => {
  const one = decodeValue({
    mapValue: { fields: { b: { integerValue: "1" }, a: { integerValue: "2" } } },
  });
  const two = decodeValue({
    mapValue: { fields: { a: { integerValue: "2" }, b: { integerValue: "1" } } },
  });
  assert.deepEqual(Object.keys(one), ["a", "b"]);
  assert.equal(JSON.stringify(one), JSON.stringify(two));
});

test("maskText hides the project and the run but keeps the wording", () => {
  assert.equal(
    maskText("no index in projects/p1/databases/(default) for run r1", {
      project: "p1",
      run: "r1",
    }),
    "no index in projects/{project}/databases/(default) for run {run}",
  );
  assert.equal(
    maskText(
      "create it here https://console.firebase.google.com/v1/r/project/p1/firestore/indexes?create_composite=Cgxxx",
      {
        project: "p1",
        run: "r1",
      },
    ),
    "create it here https://console.firebase.google.com/v1/r/project/{project}/firestore/indexes?create_composite=<index>",
  );
});

test("frameRows keeps what a Listen frame says and drops tokens, times and heartbeats", () => {
  const rows = frameRows(
    [
      target("ADD"),
      {
        kind: "documentChange",
        documentChange: {
          document: {
            name: `${ROOT}/lsn/r1-a`,
            fields: { n: { integerValue: "1" } },
            createTime: { seconds: "1" },
            updateTime: { seconds: "2" },
          },
          targetIds: [1],
          removedTargetIds: [],
        },
      },
      target("CURRENT", { resumeToken: Buffer.from("t"), readTime: { seconds: "3" } }),
      global({ resumeToken: Buffer.from("u") }),
      global(),
    ],
    { names, project: "p1", run: "r1" },
  );
  assert.deepEqual(rows, [
    { kind: "targetChange", type: "ADD", targetIds: [1], cause: null, resumeToken: false },
    {
      kind: "documentChange",
      doc: "a",
      fields: { n: 1 },
      targetIds: [1],
      removedTargetIds: [],
    },
    { kind: "targetChange", type: "CURRENT", targetIds: [1], cause: null, resumeToken: true },
    { kind: "boundary", resumeToken: true },
  ]);
});

test("a run of global NO_CHANGE frames counts once and says a token came if any frame had one", () => {
  const opts = { names, project: "p1", run: "r1" };
  assert.deepEqual(frameRows([global(), global({ resumeToken: Buffer.from("u") })], opts), [
    { kind: "boundary", resumeToken: true },
  ]);
  assert.deepEqual(frameRows([global({ resumeToken: Buffer.from("u") }), global()], opts), [
    { kind: "boundary", resumeToken: true },
  ]);
  assert.deepEqual(frameRows([global(), global()], opts), [
    { kind: "boundary", resumeToken: false },
  ]);
});

test("delete, remove, filter and an unnamed document are described", () => {
  const rows = frameRows(
    [
      {
        kind: "documentDelete",
        documentDelete: { document: `${ROOT}/lsn/r1-b`, removedTargetIds: [1] },
      },
      {
        kind: "documentRemove",
        documentRemove: { document: `${ROOT}/lsn/zzz`, removedTargetIds: [1] },
      },
      {
        kind: "filter",
        filter: {
          targetId: 1,
          count: 2,
          unchangedNames: { bits: { bitmap: Buffer.alloc(4), padding: 3 }, hashCount: 7 },
        },
      },
      { kind: "filter", filter: { targetId: 1, count: 3 } },
    ],
    { names, project: "p1", run: "r1" },
  );
  assert.deepEqual(rows, [
    { kind: "documentDelete", doc: "b", removedTargetIds: [1] },
    { kind: "documentRemove", doc: "<other>", removedTargetIds: [1] },
    {
      kind: "filter",
      targetId: 1,
      count: 2,
      unchangedNames: { hashCount: 7, bitmapBytes: 4, padding: 3 },
    },
    { kind: "filter", targetId: 1, count: 3, unchangedNames: null },
  ]);
});

test("a cause keeps its code and a masked message; target ids are sorted", () => {
  const [row] = frameRows(
    [
      {
        kind: "targetChange",
        targetChange: {
          targetChangeType: "REMOVE",
          targetIds: [3, 1],
          cause: { code: 9, message: "index in projects/p1/databases/x" },
        },
      },
    ],
    { names, project: "p1", run: "r1" },
  );
  assert.deepEqual(row, {
    kind: "targetChange",
    type: "REMOVE",
    targetIds: [1, 3],
    cause: { code: 9, message: "index in projects/{project}/databases/x" },
    resumeToken: false,
  });
});

import { commitGroups } from "./fs-listen/frames.mjs";

const change = (name, seconds, nanos = 0) => ({
  kind: "documentChange",
  documentChange: {
    document: { name: `${ROOT}/lsn/${name}`, updateTime: { seconds, nanos } },
    targetIds: [1],
  },
});

test("commitGroups splits at a boundary that carries a token and tells a shared update time", () => {
  const groups = commitGroups(
    [
      change("r1-a", "5", 10),
      change("r1-b", "5", 10),
      global({ resumeToken: Buffer.from("t") }),
      global(),
      change("r1-a", "6", 1),
      global(),
      change("r1-b", "7", 2),
      global({ resumeToken: Buffer.from("t") }),
    ],
    { names },
  );
  assert.deepEqual(groups, [
    { docs: ["a", "b"], sameUpdateTime: true },
    { docs: ["a", "b"], sameUpdateTime: false },
  ]);
});

test("commitGroups: no changes, no groups; a change with no update time is not shared with one that has", () => {
  assert.deepEqual(commitGroups([global({ resumeToken: Buffer.from("t") })], { names }), []);
  const mixed = commitGroups(
    [
      change("r1-a", "5"),
      { kind: "documentChange", documentChange: { document: { name: `${ROOT}/lsn/r1-b` } } },
    ],
    { names },
  );
  assert.deepEqual(mixed, [{ docs: ["a", "b"], sameUpdateTime: false }]);
});
