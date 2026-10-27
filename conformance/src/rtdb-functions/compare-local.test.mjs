// The comparison of a local delivery with the production recording: the forms, the member-by-member
// difference, the row verdicts and the cross-delivery facts.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { MASKED_NONCE, maskRecording } from "./mask-recording.mjs";
import {
  compareRecordings,
  diffValues,
  idForm,
  normalizeFrame,
  timeForm,
  traceForm,
} from "./compare-local.mjs";

const production = JSON.parse(
  readFileSync(new URL("./recorded/production-rtdb-triggers.json", import.meta.url), "utf8"),
).frames.map(({ n: _n, step: _step, ...frame }) => frame);
const copy = () => structuredClone(production);

test("the production recording matches itself on all 72 rows, 28 of them deliveries", () => {
  const result = compareRecordings({ production, local: copy() });
  assert.deepEqual(result.totals, { rows: 72, match: 72, difference: 0 });
  assert.equal(result.rows.filter((row) => row.production === 1).length, 28);
  assert.deepEqual(result.unattributed, { production: [], local: [] });
  assert.deepEqual(
    result.facts.map((fact) => [fact.side, fact.oneTimePerWrite, fact.distinctIds]),
    [
      ["production", true, true],
      ["local", true, true],
    ],
  );
});

test("the forms: the production id is base64 of twenty bytes, the time has three fraction digits, the traceparent is W3C", () => {
  assert.equal(idForm("c3Z9sjVyryIB8xWn9p+AnnaNVKs="), "<id:base64-20-bytes>");
  assert.equal(idForm("376b42c8-d39c-4467-aa8a-5b31f92075f2"), "<id:uuid>");
  assert.equal(idForm("abc"), "<id:other>");
  assert.equal(
    idForm("c3Z9sjVyryIB8xWn9p+AnnaNVK="),
    "<id:other>",
    "26 characters are not 20 bytes",
  );
  assert.equal(
    idForm("c3Z9sjVyryIB8xWn9p+AnnaNVKsX="),
    "<id:other>",
    "28 characters are not 20 bytes",
  );
  assert.equal(idForm(7), "<id:number>");
  assert.equal(timeForm("2026-10-27T12:12:10.146Z"), "<time:rfc3339-utc-ms>");
  assert.equal(
    timeForm("2026-10-27T12:12:10.146789012Z"),
    "<time:rfc3339-other:9999-99-99T99:99:99.999999999Z>",
  );
  assert.equal(timeForm("2026-10-27T12:12:10Z"), "<time:rfc3339-other:9999-99-99T99:99:99Z>");
  assert.equal(timeForm("yesterday"), "<time:other>");
  assert.equal(
    traceForm("00-ba24ec84f95950aeca52ade83309684f-70b4120df31afb90-01"),
    "<traceparent:w3c>",
  );
  assert.equal(
    traceForm("00-ba24ec84f95950aeca52ade83309684f-70b4120df31afb90-09"),
    "<traceparent:other>",
  );
  assert.equal(traceForm(undefined), "<traceparent:other>");
});

test("the per-delivery values are compared by form: another id, time or traceparent of the same form still matches", () => {
  const local = copy();
  for (const frame of local) {
    if (frame.generation === 1) {
      frame.event.context.eventId = "AAAAAAAAAAAAAAAAAAAAAAAAAAA=";
      frame.event.context.timestamp = "2030-01-01T00:00:00.001Z";
    } else {
      frame.event.id = "BBBBBBBBBBBBBBBBBBBBBBBBBBB=";
      frame.event.time = "2030-01-01T00:00:00.001Z";
      frame.event.extras.traceparent = "00-00000000000000000000000000000001-0000000000000002-00";
    }
  }
  assert.equal(compareRecordings({ production, local }).totals.difference, 0);
});

test("a changed member, a missing delivery, a repeated one and a delivery on another write are differences", () => {
  const pathsOf = (local) =>
    compareRecordings({ production, local }).rows.filter((row) => row.verdict === "DIFFERENCE");
  // a member
  let local = copy();
  local[0].event.authType = "admin";
  let rows = pathsOf(local);
  assert.equal(rows.length, 1);
  assert.deepEqual(rows[0].differences, [
    { path: "$.authType", production: "unknown", local: "admin" },
  ]);
  // a form
  local = copy();
  local[0].event.id = "376b42c8-d39c-4467-aa8a-5b31f92075f2";
  assert.deepEqual(pathsOf(local)[0].differences, [
    { path: "$.id", production: "<id:base64-20-bytes>", local: "<id:uuid>" },
  ]);
  // a missing delivery
  local = copy().slice(1);
  rows = pathsOf(local);
  assert.equal(rows.length, 1);
  assert.deepEqual(rows[0].differences, [{ path: "deliveries", production: 1, local: 0 }]);
  // a repeated one
  local = [...copy(), structuredClone(production[0])];
  rows = pathsOf(local);
  assert.equal(rows.length, 1);
  assert.deepEqual(rows[0].differences, [{ path: "deliveries", production: 1, local: 2 }]);
  // an absent and an added member
  local = copy();
  delete local[0].event.firebaseDatabaseHost;
  local[0].event.extension = "x";
  assert.deepEqual(
    pathsOf(local)[0]
      .differences.map((d) => d.path)
      .toSorted(),
    ["$.extension", "$.firebaseDatabaseHost"],
  );
});

test("the cross-delivery facts notice a second time within one write and a reused id", () => {
  const local = copy();
  local[0].event.time = "2026-10-27T12:12:11.000Z";
  assert.equal(compareRecordings({ production, local }).facts[1].oneTimePerWrite, false);
  const reused = copy();
  reused[0].event.id = reused[1].event.id;
  assert.equal(compareRecordings({ production, local: reused }).facts[1].distinctIds, false);
});

test("diffValues lists every differing path, arrays by length first", () => {
  assert.deepEqual(diffValues({ a: [1, 2], b: { c: 1 } }, { a: [1, 2], b: { c: 1 } }), []);
  assert.deepEqual(diffValues({ a: [1, 2] }, { a: [1] }), [
    { path: "$.a", production: [1, 2], local: [1] },
  ]);
  assert.deepEqual(diffValues({ a: [1, 2] }, { a: [1, 3] }), [
    { path: "$.a[1]", production: 2, local: 3 },
  ]);
  assert.deepEqual(diffValues({ a: null }, { a: {} }), [
    { path: "$.a", production: null, local: {} },
  ]);
  assert.deepEqual(diffValues({ a: 1 }, { b: 1 }), [
    { path: "$.a", production: 1, local: "<absent>" },
    { path: "$.b", production: "<absent>", local: 1 },
  ]);
});

test("a frame that belongs to no write is listed apart and does not count as a delivery", () => {
  const local = copy();
  local.push({
    handler: "rtdbCreatedV2",
    generation: 2,
    event: { id: "x", data: null },
    seq: 99,
    receivedAt: "t",
  });
  const result = compareRecordings({ production, local });
  assert.deepEqual(result.unattributed.local, ["rtdbCreatedV2"]);
  assert.equal(result.totals.difference, 0);
});

test("normalizeFrame does not change its input", () => {
  const frame = structuredClone(production[1]);
  normalizeFrame(frame);
  assert.deepEqual(frame, production[1]);
});

test("when production and local both hold several deliveries for a row, each one is compared in order", () => {
  const twice = (frames, tweak) => {
    const copyOf = structuredClone(frames);
    const extra = structuredClone(copyOf[0]);
    tweak(extra);
    return [...copyOf, extra];
  };
  const base = twice(production, () => {});
  assert.equal(
    compareRecordings({ production: base, local: structuredClone(base) }).totals.difference,
    0,
  );
  const local = twice(production, (frame) => {
    frame.event.authType = "admin";
  });
  const rows = compareRecordings({ production: base, local }).rows.filter(
    (r) => r.verdict === "DIFFERENCE",
  );
  assert.equal(rows.length, 1);
  assert.deepEqual(rows[0].differences, [
    { path: "$[1].authType", production: "unknown", local: "admin" },
  ]);
});

test("an array is not equal to an object that looks like it", () => {
  assert.deepEqual(diffValues([1, 2], { 0: 1, 1: 2, length: 2 }), [
    { path: "$", production: [1, 2], local: { 0: 1, 1: 2, length: 2 } },
  ]);
  assert.deepEqual(diffValues({ a: null }, { a: null }), []);
  assert.deepEqual(diffValues(null, {}), [{ path: "$", production: null, local: {} }]);
});

// ---- the masking of a run directory into the committed fixture
const REAL_NONCE = "0123456789abcdef";
function runFiles() {
  const unmasked = production.map((frame) =>
    JSON.parse(JSON.stringify(frame).split(MASKED_NONCE).join(REAL_NONCE)),
  );
  return {
    "run/result.json": JSON.stringify({ nonce: REAL_NONCE }),
    "run/report.json": JSON.stringify({
      steps: [
        {
          id: "s1",
          context: "admin",
          write: { outcome: "ok", status: 200 },
          handlers: { rtdbCreatedV1: { frames: 1 }, rtdbUpdatedV1: { frames: 0 } },
        },
      ],
    }),
    "run/frames.jsonl": `${unmasked.map((frame) => JSON.stringify(frame)).join("\n")}\n`,
  };
}
const readFrom = (files) => (path) => {
  if (!(path in files)) throw new Error(`no ${path}`);
  return files[path];
};

test("maskRecording replaces the nonce, keeps each frame, adds its write and the delivered counts", () => {
  const fixture = maskRecording({
    runDirectory: "run",
    envelope: "E",
    recordedOn: "D",
    read: readFrom(runFiles()),
  });
  assert.equal(fixture.recording.nonce, MASKED_NONCE);
  assert.equal(fixture.recording.envelope, "E");
  assert.equal(fixture.recording.recordedOn, "D");
  assert.equal(fixture.recording.frames, 28);
  assert.equal(JSON.stringify(fixture).includes(REAL_NONCE), false);
  assert.equal(fixture.frames.length, 28);
  assert.deepEqual(
    fixture.frames.map(({ n, step, handler, seq }) => [n, step, handler, seq]),
    JSON.parse(
      readFileSync(new URL("./recorded/production-rtdb-triggers.json", import.meta.url), "utf8"),
    ).frames.map(({ n, step, handler, seq }) => [n, step, handler, seq]),
  );
  assert.deepEqual(fixture.steps, [
    { id: "s1", context: "admin", outcome: "ok", status: 200, delivered: { rtdbCreatedV1: 1 } },
  ]);
});

test("maskRecording refuses a run without a 16-hex nonce and a frame that belongs to no single write", () => {
  const files = runFiles();
  files["run/result.json"] = JSON.stringify({ nonce: "not-a-nonce" });
  assert.throws(
    () => maskRecording({ runDirectory: "run", read: readFrom(files) }),
    /16-hex nonce/u,
  );
  const stranger = runFiles();
  const frame = structuredClone(production[1]);
  frame.event.data = { exists: true, key: "zz", value: { n: 9 } };
  stranger["run/frames.jsonl"] += `${JSON.stringify(frame)}\n`;
  assert.throws(
    () => maskRecording({ runDirectory: "run", read: readFrom(stranger) }),
    /belongs to no single write/u,
  );
});
