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
  const members = ["m", "a", "z", "b", "k"];
  const orders = [
    members,
    members.toReversed(),
    ["z", "m", "k", "b", "a"],
    ["b", "k", "a", "z", "m"],
  ];
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

const OPTS = { names, project: "p1", run: "r1" };

test("a target change is a boundary only when it is NO_CHANGE for no target at all", () => {
  // No type and no ids: NO_CHANGE for everything.
  assert.deepEqual(frameRows([{ kind: "targetChange", targetChange: {} }], OPTS), [
    { kind: "boundary", resumeToken: false },
  ]);
  assert.deepEqual(frameRows([{ kind: "targetChange" }], OPTS), [
    { kind: "boundary", resumeToken: false },
  ]);
  // NO_CHANGE for a named target is a row of its own.
  assert.deepEqual(frameRows([target("NO_CHANGE")], OPTS), [
    { kind: "targetChange", type: "NO_CHANGE", targetIds: [1], cause: null, resumeToken: false },
  ]);
  // A type that is not NO_CHANGE with no ids is a row too.
  assert.deepEqual(
    frameRows([{ kind: "targetChange", targetChange: { targetChangeType: "RESET" } }], OPTS),
    [{ kind: "targetChange", type: "RESET", targetIds: [], cause: null, resumeToken: false }],
  );
  // A named target without a type is NO_CHANGE.
  assert.equal(
    frameRows([{ kind: "targetChange", targetChange: { targetIds: [2] } }], OPTS)[0].type,
    "NO_CHANGE",
  );
});

test("target ids sort as numbers, and a cause without a message has an empty one", () => {
  const [row] = frameRows(
    [
      {
        kind: "targetChange",
        targetChange: { targetChangeType: "REMOVE", targetIds: [10, 2, 1], cause: { code: 5 } },
      },
    ],
    OPTS,
  );
  assert.deepEqual(row.targetIds, [1, 2, 10]);
  assert.deepEqual(row.cause, { code: 5, message: "" });
});

test("a document change with nothing in it, and an unknown frame kind, still make rows", () => {
  assert.deepEqual(frameRows([{ kind: "documentChange" }], OPTS), [
    { kind: "documentChange", doc: "<other>", fields: {}, targetIds: [], removedTargetIds: [] },
  ]);
  assert.deepEqual(frameRows([{ kind: "documentDelete" }, { kind: "documentRemove" }], OPTS), [
    { kind: "documentDelete", doc: "<other>", removedTargetIds: [] },
    { kind: "documentRemove", doc: "<other>", removedTargetIds: [] },
  ]);
  assert.deepEqual(frameRows([{ kind: "somethingNew" }, { kind: 7 }], OPTS), [
    { kind: "somethingNew" },
    { kind: "7" },
  ]);
  assert.deepEqual(frameRows([{ kind: "filter" }], OPTS), [
    { kind: "filter", targetId: undefined, count: undefined, unchangedNames: null },
  ]);
});

test("a bloom filter without bits reports zero bytes and zero padding", () => {
  const [row] = frameRows(
    [{ kind: "filter", filter: { targetId: 1, count: 1, unchangedNames: { hashCount: 2 } } }],
    OPTS,
  );
  assert.deepEqual(row.unchangedNames, { hashCount: 2, bitmapBytes: 0, padding: 0 });
  const [full] = frameRows(
    [
      {
        kind: "filter",
        filter: {
          targetId: 1,
          count: 1,
          unchangedNames: { hashCount: 2, bits: { bitmap: Buffer.alloc(9), padding: 5 } },
        },
      },
    ],
    OPTS,
  );
  assert.deepEqual(full.unchangedNames, { hashCount: 2, bitmapBytes: 9, padding: 5 });
});

test("maskText leaves text without the project or the run alone and masks every occurrence", () => {
  assert.equal(maskText("plain", { project: "p1", run: "r1" }), "plain");
  assert.equal(maskText(undefined, { project: "p1", run: "r1" }), "");
  assert.equal(
    maskText("p1 p1 r1 r1", { project: "p1", run: "r1" }),
    "{project} {project} {run} {run}",
  );
  assert.equal(
    maskText("a create_composite=Ab-_%3D.x and create_composite=Z", { project: "p1", run: "r1" }),
    "a create_composite=<index> and create_composite=<index>",
  );
});

test("commitGroups names an unnamed document, treats a missing time as none and nanos as zero", () => {
  const at = (name, time) => ({
    kind: "documentChange",
    documentChange: { document: { name, ...(time ? { updateTime: time } : {}) } },
  });
  const close = global({ resumeToken: Buffer.from("t") });
  assert.deepEqual(commitGroups([at(`${ROOT}/lsn/other`, { seconds: "1" }), close], { names }), [
    { docs: ["<other>"], sameUpdateTime: true },
  ]);
  // The same second with nanos left out and nanos 0 is one time.
  assert.deepEqual(
    commitGroups(
      [
        at(`${ROOT}/lsn/r1-a`, { seconds: "1" }),
        at(`${ROOT}/lsn/r1-b`, { seconds: "1", nanos: 0 }),
        close,
      ],
      { names },
    ),
    [{ docs: ["a", "b"], sameUpdateTime: true }],
  );
  // Two documents with no time share the "none" time; one with and one without differ.
  assert.deepEqual(
    commitGroups([at(`${ROOT}/lsn/r1-a`), at(`${ROOT}/lsn/r1-b`), close], { names }),
    [{ docs: ["a", "b"], sameUpdateTime: true }],
  );
  assert.deepEqual(commitGroups([{ kind: "documentChange" }, close], { names }), [
    { docs: ["<other>"], sameUpdateTime: true },
  ]);
  // A boundary without a token, or a target change for a named target, closes nothing.
  assert.deepEqual(
    commitGroups(
      [
        at(`${ROOT}/lsn/r1-a`, { seconds: "1" }),
        global(),
        target("NO_CHANGE", { resumeToken: Buffer.from("t") }),
        at(`${ROOT}/lsn/r1-b`, { seconds: "1" }),
        close,
      ],
      { names },
    ),
    [{ docs: ["a", "b"], sameUpdateTime: true }],
  );
  assert.deepEqual(commitGroups([{ kind: "targetChange" }, close], { names }), []);
});

test("a boundary merges only into the one directly before it, not into an earlier one", () => {
  const rows = frameRows(
    [global(), target("ADD"), global({ resumeToken: Buffer.from("t") })],
    OPTS,
  );
  assert.deepEqual(rows, [
    { kind: "boundary", resumeToken: false },
    { kind: "targetChange", type: "ADD", targetIds: [1], cause: null, resumeToken: false },
    { kind: "boundary", resumeToken: true },
  ]);
});
