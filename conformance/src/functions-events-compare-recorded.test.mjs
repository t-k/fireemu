// The comparator against the shapes production actually printed (attempts 011 and 012, sanitized in
// compare/fixtures/recorded-shapes.json) and a real local fireemu session (emulator profile).
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { parseTimeMs } from "./functions-events/compare/adapters.mjs";
import { compareRuns } from "./functions-events/compare/compare.mjs";
import {
  LOCAL_PROJECT,
  frameEntry,
  iso,
  localOp,
  localSession,
  op,
  productionRun,
  rekey,
} from "./functions-events/compare/fixtures/build.mjs";

const readJson = (path) => JSON.parse(readFileSync(new URL(path, import.meta.url)));
const corpus = readJson("../functions-events/corpus.json");
const programs = readJson("../functions-events/programs.json");
const shapes = readJson("./functions-events/compare/fixtures/recorded-shapes.json");
const localStorageSession = readJson("./functions-events/compare/fixtures/local-emulator-storage-finalize.json");

const rowsOf = (result, recipeId) => result.rows.filter(({ row }) => row.startsWith(`${recipeId}#`));
const rowById = (result, id) => result.rows.find(({ row }) => row === id);
const reasonHeads = (row) => row.reasons.map((reason) => reason.split(" (")[0]);

function firestoreWorld({ localTimes = (frame) => frame } = {}) {
  const { v1, v2, matchKey } = shapes.firestoreCreated;
  const docId = matchKey.value.split("/")[1];
  const recordedTime = v2.event.time;
  const start = parseTimeMs(recordedTime) - 300;
  const pass2Pairs = [
    [docId, "e0f1e2d3c4b5a69788796a5b4c3d2e1f0"],
    [v1.event.context.eventId, "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d-0"],
    [v2.event.id, "9f8e7d6c-5b4a-4398-a7b6-c5d4e3f2a1b0"],
    ["2026-09-30T12:03:18.846431Z", "2026-09-30T13:03:19.512845Z"],
    ["1790769798", "1790773399"],
    ["846431000", "512845000"],
  ];
  const pass2Path = rekey(matchKey.value, pass2Pairs);
  const frames = [
    frameEntry(v1, start + 2000),
    frameEntry(v2, start + 2000),
    frameEntry(rekey(v1, pass2Pairs), start + 3_600_000 + 2000),
    frameEntry(rekey(v2, pass2Pairs), start + 3_600_000 + 2000),
  ];
  const run = productionRun(
    [op({ scenarioId: "fs-create", start, matchKey, readback: { exists: true, path: matchKey.value } })],
    [op({ scenarioId: "fs-create", start: parseTimeMs("2026-09-30T13:03:19.512845Z") - 300, matchKey: { kind: "firestore", value: pass2Path }, readback: { exists: true, path: pass2Path } })],
    frames,
  );
  const local = (n) => {
    const pairs = [
      ["fireemu-oracle-events", LOCAL_PROJECT],
      [docId, `e${String(n).repeat(32)}`],
      [v1.event.context.eventId, `${String(n).repeat(8)}-0000-4000-8000-000000000000-0`],
      [v2.event.id, `${String(n).repeat(8)}-0000-4000-8000-000000000001`],
      ["2026-09-30T12:03:18.846431Z", `2026-10-04T00:00:0${n}.100200Z`],
      ["1790769798", "1791072000"],
      ["846431000", "100200000"],
    ];
    const path = rekey(matchKey.value, pairs);
    return localSession([
      {
        recipeId: "functions-events/firestore/create",
        operations: [
          localOp({
            scenarioId: "fs-create",
            matchKey: { kind: "firestore", value: path },
            readback: { exists: true, path },
            v1: [localTimes(rekey(v1, pairs))],
            v2: [localTimes(rekey(v2, pairs))],
          }),
        ],
      },
    ]);
  };
  return { run, emulator: local(1), strict: local(2) };
}

const compare = (w) =>
  compareRuns({ corpus, programs, productionRun: w.run, localSessions: { emulator: w.emulator, strict: w.strict }, localProject: LOCAL_PROJECT });

test("recorded Firestore created shapes (attempt 011): a local frame of the same shape MATCHes", () => {
  const result = compare(firestoreWorld());
  for (const row of rowsOf(result, "functions-events/firestore/create")) {
    assert.equal(row.status, "MATCH", `${row.row}: ${row.reasons.join("; ")}`);
  }
  assert.deepEqual(result.volatilePaths["fsCreatedV1/fs-create"], {
    "$.frame.event.context.eventId": ["value"],
    "$.frame.event.context.timestamp": ["value"],
    "$.frame.event.data.createTime._nanoseconds": ["value"],
    "$.frame.event.data.createTime._seconds": ["value"],
    "$.frame.event.data.updateTime._nanoseconds": ["value"],
    "$.frame.event.data.updateTime._seconds": ["value"],
  });
  assert.deepEqual(Object.keys(result.volatilePaths["fsCreatedV2/fs-create"]), [
    "$.frame.event.data.createTime._nanoseconds",
    "$.frame.event.data.createTime._seconds",
    "$.frame.event.data.updateTime._nanoseconds",
    "$.frame.event.data.updateTime._seconds",
    "$.frame.event.id",
    "$.frame.event.time",
  ]);
});

test("recorded Firestore created shapes: snapshot times printed as strings locally are a DIFF", () => {
  const asText = (frame) => {
    const copy = structuredClone(frame);
    const data = copy.event.data;
    data.createTime = "2026-10-04T00:00:01.100200Z";
    data.updateTime = "2026-10-04T00:00:01.100200Z";
    return copy;
  };
  const row = rowById(compare(firestoreWorld({ localTimes: asText })), "functions-events/firestore/create#new-document#v2");
  assert.equal(row.status, "DIFF");
  assert.deepEqual(reasonHeads(row), [
    "emulator: type $.frame.event.data.createTime",
    "emulator: type $.frame.event.data.updateTime",
    "strict: type $.frame.event.data.createTime",
    "strict: type $.frame.event.data.updateTime",
  ]);
});

test("recorded Firestore created shapes: a frame without its event time is INCOMPLETE, not guessed", () => {
  const w = firestoreWorld();
  delete w.run.frames[0].frame.event.context.timestamp;
  const row = rowById(compare(w), "functions-events/firestore/create#new-document#v1");
  assert.equal(row.status, "INCOMPLETE");
  assert.deepEqual(row.reasons, [
    "production pass 1: 1 fsCreatedV1 frame(s) of the subject cannot be attributed (no event time, or within 1000 ms of the source call)",
  ]);
});

function storageWorld() {
  const { v1, v2, matchKey } = shapes.storageFinalized;
  const name = matchKey.value;
  const hash = name.slice("fe-events/".length, -".txt".length);
  const generation = v1.event.data.generation;
  const etag = v1.event.data.etag;
  const start = parseTimeMs(v1.event.data.timeCreated) - 300;
  const variant = (prefix, n) => [
    [hash, `e${String(n).repeat(32)}`],
    [generation, `17908445661${String(n).repeat(5)}`],
    [etag, `CM${String(n).repeat(10)}EAE=`],
    [v1.event.context.eventId, `3141592653589${String(n).repeat(4)}`],
    [v2.event.id, `2718281828459${String(n).repeat(4)}`],
    ["2026-10-01T08:49:26", prefix],
  ];
  const readback = (frame) => ({
    exists: true,
    bucket: frame.event.data.bucket,
    name: frame.event.data.name,
    generation: frame.event.data.generation,
    metageneration: frame.event.data.metageneration,
    contentType: frame.event.data.contentType,
  });
  const passes = [[], []];
  const frames = [];
  const keyOf = (frame) => ({ kind: "storage", value: frame.event.data.name, bucket: matchKey.bucket });
  [
    { pass: 1, shift: 0, upload: [], control: variant("2026-10-01T08:51:46", 3) },
    { pass: 2, shift: 3_600_000, upload: variant("2026-10-01T09:49:26", 5), control: variant("2026-10-01T09:51:46", 7) },
  ].forEach(({ pass, shift, upload, control }) => {
    const s = start + shift;
    const subject = [rekey(v1, upload), rekey(v2, upload)];
    const after = [rekey(v1, control), rekey(v2, control)];
    const failedName = `fe-events/e${String(pass).repeat(32)}.txt`;
    passes[pass - 1].push(
      op({ scenarioId: "storage-upload", start: s, matchKey: keyOf(subject[0]), readback: readback(subject[0]) }),
      op({ scenarioId: "storage-failed-upload", sourceResult: "typed-refusal", start: s + 10_000, end: s + 10_500, matchKey: { kind: "storage", value: failedName, bucket: matchKey.bucket }, readback: { exists: false, bucket: matchKey.bucket, name: failedName } }),
      op({ scenarioId: "storage-upload", role: "positive-control-after", start: s + 140_000, matchKey: keyOf(after[0]), readback: readback(after[0]) }),
    );
    frames.push(...subject.map((frame) => frameEntry(frame, s + 1100)), ...after.map((frame) => frameEntry(frame, s + 141_100)));
  });
  return { run: productionRun(passes[0], passes[1], frames), emulator: localStorageSession, strict: localStorageSession };
}

test("recorded Storage finalized shapes (attempt 012) against a real fireemu session report the real DIFFs", () => {
  const result = compare(storageWorld());
  const rows = Object.fromEntries(rowsOf(result, "functions-events/storage/finalize").map((row) => [row.row, row]));
  const expectedV1 = [
    "format $.frame.event.data.etag length",
    "format $.frame.event.data.generation length",
    "format $.frame.event.data.id length",
    "format $.frame.event.data.mediaLink length",
    "format $.readback.generation length",
  ];
  const both = (heads) => ["emulator", "strict"].flatMap((profile) => heads.map((head) => `${profile}: ${head}`));
  const v1 = rows["functions-events/storage/finalize#new-object#v1"];
  assert.equal(v1.status, "DIFF");
  assert.deepEqual(reasonHeads(v1), both(expectedV1));
  assert.ok(v1.reasons.includes("emulator: format $.frame.event.data.generation length (production 16, local 1)"));
  const v2 = rows["functions-events/storage/finalize#new-object#v2"];
  assert.equal(v2.status, "DIFF");
  assert.deepEqual(reasonHeads(v2), both([...expectedV1.slice(0, 4), "type $.frame.event.datacontenttype", expectedV1[4]]));
  assert.ok(v2.reasons.includes("strict: type $.frame.event.datacontenttype (production null, local string)"));

  const overwrite = rows["functions-events/storage/finalize#overwritten-generation#v1"];
  assert.equal(overwrite.status, "INCOMPLETE");
  assert.ok(overwrite.reasons.includes("production pass 1: 0 subject operations for storage-overwrite"));
  for (const generation of [1, 2]) {
    const negative = rows[`functions-events/storage/finalize#failed-upload-no-event#v${generation}`];
    assert.equal(negative.status, "MATCH", negative.reasons.join("; "));
  }
  assert.equal(result.conditions["FUNCTIONS-EVENTS/storage-finalized"], "DIFF");
});

test("recorded production-only listing members are ignored for local comparison but reported by name", () => {
  const result = compare(storageWorld());
  assert.deepEqual(rowById(result, "functions-events/storage/finalize#new-object#v1").productionOnly, {
    "$.event.context.contextExtras": [],
    "$.event.context.contextKeys": ["eventId", "eventType", "params", "resource", "timestamp"],
  });
  assert.deepEqual(rowById(result, "functions-events/storage/finalize#new-object#v2").productionOnly, {
    "$.event.eventKeys": ["bucket", "context", "data", "id", "object", "source", "specversion", "subject", "time", "traceparent", "type"],
    "$.event.extensionAttributes": ["bucket", "context", "object", "traceparent"],
  });
  const text = JSON.stringify(result);
  for (const raw of ["0123456789abcdef0123456789abcdef", shapes.storageFinalized.matchKey.bucket, "demo-conformance-events-primary", shapes.storageFinalized.v1.event.data.generation]) {
    assert.equal(text.includes(raw), false, raw);
  }
  assert.equal(iso(0), "1970-01-01T00:00:00.000Z");
});
