// How the comparator attributes a production frame to a source operation (attribute in compare.mjs). The offsets are the
// ones measured in the FE v5 production run (functions-events-formal-20261004T182904Z-a9621bfae74fe9bc): of its 14 Storage
// subject frames, Gen1 context.timestamp fell +5, +10, +11 and +22 ms after the operation's endedAt (client and Google
// clocks), and the Gen1 finalize frame of one overwrite was stamped +1611 ms after endedAt while its own data.updated was
// inside the call. Delete and archive frames carry the data.updated of the previous object state, so they are not timed by it.
import assert from "node:assert/strict";
import { test } from "node:test";
import { attributionTimeMs, fromProductionRun } from "./functions-events/compare/adapters.mjs";
import { attribute } from "./functions-events/compare/compare.mjs";
import {
  T0,
  frameEntry,
  iso,
  op,
  productionRun,
} from "./functions-events/compare/fixtures/build.mjs";

const BUCKET = "b-test";
const NAME = "objects/o1.txt";
const matchKey = { kind: "storage", value: NAME, bucket: BUCKET };
const START = T0 + 10_000;
const END = START + 300;

const storageFrame = (handler, { time, updated, name = NAME }) => {
  const generation = handler.endsWith("V1") ? 1 : 2;
  const data = { kind: "storage#object", name, bucket: BUCKET, ...(updated ? { updated } : {}) };
  return {
    handler,
    generation,
    source: "storage",
    event:
      generation === 1
        ? { context: { eventId: "1", timestamp: time, eventType: "x" }, data }
        : { id: "1", time, type: "x", data },
  };
};

function attributionOf(frames, ops = [{ start: START, end: END }]) {
  const operations = ops.map(({ start, end }) =>
    op({ scenarioId: "storage-upload", start, end, matchKey, readback: {} }),
  );
  const run = productionRun(
    operations,
    [],
    frames.map((frame, index) => frameEntry(frame, START + 2000 + index)),
  );
  const production = fromProductionRun(run);
  const attribution = attribute(production, 1000);
  return production.frames.map((frame) => {
    const entry = attribution.get(frame);
    return {
      subject: entry.subjectOf.map((o) =>
        operations.indexOf(operations.find((x) => x.startedAt === iso(o.startMs))),
      ),
      near: entry.nearOf.length,
    };
  });
}

test("the time of a Storage finalize or metadata-update frame is its object's data.updated; other frames use their event time", () => {
  const at = iso(START);
  for (const handler of [
    "storageFinalizedV1",
    "storageFinalizedV2",
    "storageMetadataUpdatedV1",
    "storageMetadataUpdatedV2",
  ]) {
    const frame = storageFrame(handler, { time: iso(START + 1611), updated: at });
    assert.equal(attributionTimeMs(frame), START, handler);
  }
  for (const handler of [
    "storageDeletedV1",
    "storageDeletedV2",
    "storageArchivedV1",
    "storageArchivedV2",
  ]) {
    const frame = storageFrame(handler, { time: iso(START + 22), updated: iso(START - 20_000) });
    assert.equal(attributionTimeMs(frame), START + 22, handler);
  }
  // no usable data.updated: the event time again
  const bare = storageFrame("storageFinalizedV1", { time: iso(START + 5) });
  assert.equal(attributionTimeMs(bare), START + 5);
  const broken = storageFrame("storageFinalizedV1", {
    time: iso(START + 5),
    updated: "not a time",
  });
  assert.equal(attributionTimeMs(broken), START + 5);
  assert.equal(attributionTimeMs({ generation: 1, event: {} }), null);
  assert.equal(
    attributionTimeMs({
      handler: "storageFinalizedV1",
      generation: 1,
      event: { data: { updated: iso(START) } },
    }),
    START,
  );
  assert.equal(attributionTimeMs(null), null);
});

test("a frame inside the call window belongs to the operation", () => {
  const [one] = attributionOf([storageFrame("storageDeletedV1", { time: iso(START + 100) })]);
  assert.deepEqual(one, { subject: [0], near: 0 });
});

test("the recorded skews (+5, +10, +11, +22 ms after endedAt) attribute to the one operation that can own the frame", () => {
  for (const skew of [5, 10, 11, 22]) {
    const [one] = attributionOf([storageFrame("storageDeletedV1", { time: iso(END + skew) })]);
    assert.deepEqual(one, { subject: [0], near: 0 }, `+${skew} ms`);
  }
  // the same distance before the call is within the tolerance too
  const [early] = attributionOf([storageFrame("storageDeletedV1", { time: iso(START - 400) })]);
  assert.deepEqual(early, { subject: [0], near: 0 });
});

test("a frame near two operations of its resource is attributed to neither (fail closed)", () => {
  const later = { start: END + 500, end: END + 800 };
  const [one] = attributionOf(
    [storageFrame("storageDeletedV1", { time: iso(END + 250) })],
    [{ start: START, end: END }, later],
  );
  assert.deepEqual(one, { subject: [], near: 2 });
  // exactly at one tolerance away from each: still two candidates
  const [edge] = attributionOf(
    [storageFrame("storageDeletedV1", { time: iso(END + 1000) })],
    [
      { start: START, end: END },
      { start: END + 1000, end: END + 1200 },
    ],
  );
  assert.equal(edge.subject.length, 1, "inside the second window it is that operation's alone");
});

test("a frame inside one window and near another stays that window's", () => {
  const [one] = attributionOf(
    [storageFrame("storageDeletedV1", { time: iso(END + 100) })],
    [
      { start: START, end: END },
      { start: END + 100, end: END + 400 },
    ],
  );
  assert.deepEqual(one.subject, [1]);
});

test("a frame beyond the tolerance belongs to no operation, and one without an event time stays unattributable", () => {
  const [far] = attributionOf([storageFrame("storageDeletedV1", { time: iso(END + 1611) })]);
  assert.deepEqual(far, { subject: [], near: 0 });
  const [none] = attributionOf([
    {
      handler: "storageDeletedV1",
      generation: 1,
      source: "storage",
      event: { context: {}, data: { name: NAME, bucket: BUCKET } },
    },
  ]);
  assert.deepEqual(none, { subject: [], near: 1 });
});

test("the Gen1 finalize frame stamped +1611 ms after the call is the call's by its data.updated", () => {
  const frame = storageFrame("storageFinalizedV1", {
    time: iso(END + 1611),
    updated: iso(START + 120),
  });
  assert.deepEqual(attributionOf([frame])[0], { subject: [0], near: 0 });
  // a delete frame with the same stamp is not
  const del = storageFrame("storageDeletedV1", {
    time: iso(END + 1611),
    updated: iso(START + 120),
  });
  assert.deepEqual(attributionOf([del])[0], { subject: [], near: 0 });
  // the previous generation's finalize (updated 20 s earlier) is not the overwrite's
  const previous = storageFrame("storageFinalizedV1", {
    time: iso(START - 20_025),
    updated: iso(START - 20_086),
  });
  assert.deepEqual(attributionOf([previous])[0], { subject: [], near: 0 });
});

test("a frame exactly at the end of one window belongs to that operation even when another is near", () => {
  const [one] = attributionOf(
    [storageFrame("storageDeletedV1", { time: iso(END) })],
    [
      { start: START, end: END },
      { start: END + 200, end: END + 500 },
    ],
  );
  assert.deepEqual(one, { subject: [0], near: 1 });
});

test("an operation whose times are unknown could own the frame too, so a frame near another operation stays unattributed", () => {
  const known = op({
    scenarioId: "storage-upload",
    start: START,
    end: END,
    matchKey,
    readback: {},
  });
  const unknown = { ...known, startedAt: "unknown", endedAt: "unknown" };
  const run = productionRun(
    [known, unknown],
    [],
    [frameEntry(storageFrame("storageDeletedV1", { time: iso(END + 22) }), START + 2000)],
  );
  const production = fromProductionRun(run);
  const entry = attribute(production, 1000).get(production.frames[0]);
  assert.equal(entry.subjectOf.length, 0);
  assert.equal(entry.nearOf.length, 2);
});
