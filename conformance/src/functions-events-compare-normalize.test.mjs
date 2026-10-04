import assert from "node:assert/strict";
import { test } from "node:test";
import {
  applyPlaceholders,
  flatten,
  formatOf,
  placeholderTable,
  splitProductionOnly,
} from "./functions-events/compare/normalize.mjs";
import { compareObservation, deriveVolatile } from "./functions-events/compare/diff.mjs";

test("placeholder table covers the matchKey roles, the project and their URI forms, longest first", () => {
  const firestore = placeholderTable({
    matchKey: { kind: "firestore", value: "fe_events_primary/eabc" },
    project: "fireemu-oracle-events",
  });
  assert.deepEqual(firestore, [
    ["fe_events_primary%2Feabc", "<key.value|uri>"],
    ["fe_events_primary/eabc", "<key.value>"],
    ["fireemu-oracle-events", "<project>"],
    ["eabc", "<key.id>"],
  ]);

  const storage = placeholderTable({
    matchKey: { kind: "storage", value: "fe-events/e1.txt", bucket: "demo-conformance-events-primary" },
    project: "demo-conformance",
  });
  assert.deepEqual(
    storage.map(([, token]) => token),
    ["<key.bucket>", "<key.value|uri>", "<project>", "<key.value>", "<key.id>"],
  );

  const bulk = placeholderTable({
    matchKey: { kind: "auth", values: ["uid-a", "uid-bb"] },
    project: "p",
  });
  assert.deepEqual(bulk, [
    ["uid-bb", "<key.values[1]>"],
    ["uid-a", "<key.values[0]>"],
    ["p", "<project>"],
  ]);
});

test("placeholder table refuses an empty or missing role value", () => {
  assert.throws(() => placeholderTable({ matchKey: { kind: "firestore", value: "" }, project: "p" }));
  assert.throws(() => placeholderTable({ matchKey: { kind: "firestore", value: "a/b" }, project: "" }));
  assert.throws(() => placeholderTable({ matchKey: null, project: "p" }));
});

test("placeholders replace in values and keys in one pass, never inside an inserted token", () => {
  const table = [
    ["fe_events_primary/eabc", "<key.value>"],
    ["eabc", "<key.id>"],
    ["key", "<danger>"],
  ];
  const out = applyPlaceholders(
    {
      path: "fe_events_primary/eabc",
      id: "eabc",
      nested: { eabc: ["x-eabc-y", 3, null, true] },
    },
    table,
  );
  assert.deepEqual(out, {
    path: "<key.value>",
    id: "<key.id>",
    nested: { "<key.id>": ["x-<key.id>-y", 3, null, true] },
  });
});

test("splitting the production-only listing removes only the four named members and keeps names", () => {
  const frame = {
    handler: "h",
    event: {
      context: { eventId: "1", contextKeys: ["eventId", "params"], contextExtras: { extra: 1 } },
      eventKeys: ["data", "id"],
      extensionAttributes: { traceparent: "00-secret", bucket: "b" },
      data: { eventKeys: "kept because not at the listing path" },
    },
  };
  const { frame: stripped, listing } = splitProductionOnly(frame);
  assert.deepEqual(stripped, {
    handler: "h",
    event: {
      context: { eventId: "1" },
      data: { eventKeys: "kept because not at the listing path" },
    },
  });
  assert.deepEqual(listing, {
    "$.event.context.contextExtras": ["extra"],
    "$.event.context.contextKeys": ["eventId", "params"],
    "$.event.eventKeys": ["data", "id"],
    "$.event.extensionAttributes": ["bucket", "traceparent"],
  });
  assert.equal(JSON.stringify(listing).includes("secret"), false);
  assert.equal(frame.event.eventKeys.length, 2, "input is not mutated");
});

test("flatten records every path with its type, object member order and array length", () => {
  const leaves = flatten({ b: 1, a: { "x.y": [true, null] }, e: {}, s: "t" });
  assert.deepEqual([...leaves.keys()], [
    "$",
    "$.b",
    "$.a",
    '$.a["x.y"]',
    '$.a["x.y"][0]',
    '$.a["x.y"][1]',
    "$.e",
    "$.s",
  ]);
  assert.deepEqual(leaves.get("$"), { type: "object", keys: ["b", "a", "e", "s"] });
  assert.deepEqual(leaves.get('$.a["x.y"]'), { type: "array", length: 2 });
  assert.deepEqual(leaves.get('$.a["x.y"][1]'), { type: "null", value: null });
  assert.deepEqual(leaves.get("$.e"), { type: "object", keys: [] });
  assert.deepEqual(leaves.get("$.b"), { type: "number", value: 1 });
});

test("format descriptors keep precision, length and kind but not the value", () => {
  assert.deepEqual(formatOf("2026-10-01T08:49:26.486927Z"), {
    kind: "timestamp",
    length: 27,
    fractionDigits: 6,
    zone: "Z",
  });
  assert.deepEqual(formatOf("2026-10-01T08:49:26Z"), {
    kind: "timestamp",
    length: 20,
    fractionDigits: 0,
    zone: "Z",
  });
  assert.deepEqual(formatOf("22201766561849599"), { kind: "decimal", length: 17 });
  assert.deepEqual(formatOf("4e141130-b7ae-47a0-9009-d11bc411baf5-0"), {
    kind: "uuid",
    length: 38,
  });
  assert.deepEqual(formatOf("dc880941-8bb2-410f-9b10-51c47560a33a"), { kind: "uuid", length: 36 });
  assert.deepEqual(formatOf("o9gONg=="), { kind: "text", length: 8 });
  assert.deepEqual(formatOf(3), { kind: "integer" });
  assert.deepEqual(formatOf(-0.5), { kind: "fraction" });
  assert.deepEqual(formatOf(true), { kind: "boolean" });
  assert.deepEqual(formatOf(null), { kind: "null" });
});

test("volatile paths come only from values that differ between the two production passes", () => {
  const pass1 = flatten({ id: "111", time: "2026-01-01T00:00:00.123Z", kind: "k", n: { a: 1, b: 2 } });
  const pass2 = flatten({ id: "222", time: "2026-01-01T00:00:01.456Z", kind: "k", n: { b: 2, a: 1 } });
  const { disagreements, volatile } = deriveVolatile(pass1, pass2);
  assert.deepEqual(disagreements, []);
  assert.deepEqual(
    [...volatile.entries()].map(([path, features]) => [path, [...features]]),
    [
      ["$.id", ["value"]],
      ["$.n", ["order"]],
      ["$.time", ["value"]],
    ],
  );
});

test("a format feature that also varies between passes is volatile; presence and type never are", () => {
  const { volatile } = deriveVolatile(flatten({ id: "1" }), flatten({ id: "22" }));
  assert.deepEqual([...volatile.get("$.id")], ["length", "value"]);

  const presence = deriveVolatile(flatten({ a: 1, b: 2 }), flatten({ a: 1 }));
  assert.deepEqual(presence.disagreements, ["production-presence $.b (pass 1 only)"]);
  const type = deriveVolatile(flatten({ a: "1" }), flatten({ a: 1 }));
  assert.deepEqual(type.disagreements, ["production-type $.a (string, number)"]);
});

test("local comparison reports deterministic value, presence, type, format and order differences", () => {
  const production = flatten({ id: "111", kind: "k", gen: "1790844566471739", n: { a: 1, b: 2 } });
  const pass2 = flatten({ id: "222", kind: "k", gen: "1790844566471800", n: { a: 1, b: 2 } });
  const { volatile } = deriveVolatile(production, pass2);

  assert.deepEqual(
    compareObservation(
      production,
      volatile,
      flatten({ id: "333", kind: "k", gen: "1790844566471999", n: { a: 1, b: 2 } }),
      "emulator",
    ),
    [],
  );
  const reasons = compareObservation(
    production,
    volatile,
    flatten({ id: "4444", kind: "other", gen: "1", n: { b: 2, a: 1 }, extra: true }),
    "strict",
  );
  assert.deepEqual(reasons.map((reason) => reason.split(" (")[0]), [
    "strict: extra-field $.extra",
    "strict: format $.gen length",
    "strict: format $.id length",
    "strict: value $.kind",
    "strict: order $.n",
  ]);
  for (const reason of reasons) {
    assert.equal(reason.includes("other"), false, "raw values never appear in a reason");
    assert.equal(reason.includes("1790844566471739"), false);
  }

  const missing = compareObservation(production, volatile, flatten({ kind: "k", gen: "1790844566471999", n: { a: 1, b: 2 } }), "emulator");
  assert.deepEqual(missing, ["emulator: missing-field $.id"]);
  const typed = compareObservation(production, volatile, flatten({ id: 333, kind: "k", gen: "1790844566471999", n: { a: 1, b: 2 } }), "emulator");
  assert.deepEqual(typed, ["emulator: type $.id (production string, local number)"]);
});
