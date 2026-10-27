// The capture of the CV14 frames: the Cloud Logging query over the exact stdout origin of each of the
// eight handlers, and the parser of the printed frames. The parser never throws on a shape it does not
// know: it counts what it could not use and the run goes on. Nothing here decides whether an event was
// delivered; sequence.mjs does that.

import assert from "node:assert/strict";
import { test } from "node:test";

import { PROJECT } from "../../functions-http/harness.mjs";
import { FIXTURE_HANDLERS, FRAME_MARKER } from "./frames.mjs";
import { IGNORED, listRequest, logFilter, origin, parseEntries } from "./logs.mjs";

const HANDLER = Object.fromEntries(FIXTURE_HANDLERS.map((h) => [h.name, h]));

const entryFor = (name, over = {}, frame = {}) => {
  const handler = HANDLER[name];
  const o = origin(handler);
  return {
    logName: o.logName,
    resource: { type: o.resourceType, labels: o.labels },
    insertId: `ins-${name}`,
    timestamp: "2026-10-27T01:00:00.123456789Z",
    textPayload: `${FRAME_MARKER}${JSON.stringify({ handler: name, generation: handler.generation, seq: 1, event: {}, ...frame })}`,
    ...over,
  };
};

test("each handler has one stdout origin: a 1st gen function by its name, a 2nd gen service by its lower-cased name", () => {
  assert.deepEqual(origin(HANDLER.rtdbCreatedV1), {
    logName: `projects/${PROJECT}/logs/cloudfunctions.googleapis.com%2Fcloud-functions`,
    resourceType: "cloud_function",
    labels: { function_name: "rtdbCreatedV1", region: "us-central1" },
  });
  assert.deepEqual(origin(HANDLER.rtdbWrittenV2), {
    logName: `projects/${PROJECT}/logs/run.googleapis.com%2Fstdout`,
    resourceType: "cloud_run_revision",
    labels: { service_name: "rtdbwrittenv2", location: "us-central1" },
  });
});

test("the filter names every origin, the window and the marker; the request is one bounded POST", () => {
  const filter = logFilter({
    start: "2026-10-27T00:00:00.000000Z",
    end: "2026-10-27T01:00:00.000000Z",
  });
  for (const handler of FIXTURE_HANDLERS) {
    const o = origin(handler);
    assert.ok(filter.includes(`logName="${o.logName}"`));
    for (const [key, value] of Object.entries(o.labels)) {
      assert.ok(filter.includes(`resource.labels.${key}="${value}"`), `${handler.name} ${key}`);
    }
  }
  assert.ok(filter.includes('timestamp>="2026-10-27T00:00:00.000000Z"'));
  assert.ok(filter.includes('timestamp<="2026-10-27T01:00:00.000000Z"'));
  assert.ok(filter.includes(`textPayload:"${FRAME_MARKER.trim()}"`));
  const request = listRequest({ start: "a", end: "b", pageToken: "tok" });
  assert.equal(request.method, "POST");
  assert.equal(request.url, "https://logging.googleapis.com/v2/entries:list");
  assert.deepEqual(request.body.resourceNames, [`projects/${PROJECT}`]);
  assert.equal(request.body.orderBy, "timestamp asc");
  assert.equal(request.body.pageSize, 200);
  assert.equal(request.body.pageToken, "tok");
  assert.equal("pageToken" in listRequest({ start: "a", end: "b" }).body, false);
});

test("a frame of a known handler from its own origin is parsed, with its insert id and log time", () => {
  const result = parseEntries({ entries: [entryFor("rtdbCreatedV1")] }, { readAt: "r1" });
  assert.equal(result.entries, 1);
  assert.equal(result.frames.length, 1);
  assert.deepEqual(result.frames[0], {
    insertId: "ins-rtdbCreatedV1",
    logTimestamp: "2026-10-27T01:00:00.123456789Z",
    readAt: "r1",
    handler: "rtdbCreatedV1",
    generation: 1,
    frame: { handler: "rtdbCreatedV1", generation: 1, seq: 1, event: {} },
  });
  assert.equal(result.nextPageToken, null);
  assert.deepEqual(Object.keys(result.ignored), IGNORED);
});

test("a frame is read once per insert id, also across pages, and a jsonPayload message works too", () => {
  const seen = new Set();
  const first = parseEntries(
    { entries: [entryFor("rtdbCreatedV2")], nextPageToken: "n" },
    { readAt: "r1", seen },
  );
  const again = parseEntries({ entries: [entryFor("rtdbCreatedV2")] }, { readAt: "r2", seen });
  assert.equal(first.frames.length, 1);
  assert.equal(first.nextPageToken, "n");
  assert.equal(again.frames.length, 0);
  assert.equal(again.entries, 1);
  const json = entryFor("rtdbDeletedV2", { insertId: "ins-j" });
  json.jsonPayload = { message: json.textPayload };
  delete json.textPayload;
  assert.equal(parseEntries({ entries: [json] }, { readAt: "r3" }).frames.length, 1);
  // without an insert id the log time and handler stand in for it
  const bare = entryFor("rtdbDeletedV2");
  delete bare.insertId;
  const keyed = new Set();
  parseEntries({ entries: [bare] }, { readAt: "r", seen: keyed });
  assert.deepEqual([...keyed], ["2026-10-27T01:00:00.123456789Z:rtdbDeletedV2"]);
});

test("what cannot be used is counted by class, never thrown on", () => {
  const stranger = entryFor("rtdbCreatedV1", { insertId: "x1" });
  stranger.resource.labels.function_name = "someoneElse";
  const wrongGeneration = entryFor("rtdbCreatedV1", { insertId: "x2" }, { generation: 2 });
  const unknown = entryFor("rtdbCreatedV1", { insertId: "x3" }, { handler: "nope" });
  const broken = entryFor("rtdbCreatedV1", {
    insertId: "x4",
    textPayload: `${FRAME_MARKER}{not json`,
  });
  const plain = entryFor("rtdbCreatedV1", { insertId: "x5", textPayload: "hello" });
  const result = parseEntries(
    {
      entries: [
        stranger,
        wrongGeneration,
        unknown,
        broken,
        plain,
        null,
        "text",
        entryFor("rtdbWrittenV1"),
      ],
    },
    { readAt: "r" },
  );
  assert.equal(result.entries, 8);
  assert.equal(result.frames.length, 1);
  assert.deepEqual(result.ignored, {
    notTyped: 2,
    notFrame: 1,
    unparsed: 1,
    unknownHandler: 2,
    foreignOrigin: 1,
  });
  for (const body of [null, undefined, "x", 3, {}, { entries: "no" }]) {
    const empty = parseEntries(body, { readAt: "r" });
    assert.equal(empty.frames.length, 0);
    assert.equal(empty.entries, 0);
  }
});

// ---- generated: whatever the log holds, the parser returns what it can use and counts the rest ----

function prng(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4_294_967_296;
  };
}

test("generated entries: the parser never throws, every entry is counted once, and only own frames are kept", () => {
  const next = prng(0x10c5);
  const pick = (list) => list[Math.floor(next() * list.length)];
  const names = FIXTURE_HANDLERS.map((h) => h.name);
  for (let round = 0; round < 300; round += 1) {
    const entries = [];
    let expectedFrames = 0;
    const ids = new Set();
    for (let i = 0; i < Math.floor(next() * 12); i += 1) {
      const name = pick(names);
      const base = entryFor(name, { insertId: `i${Math.floor(next() * 6)}` });
      const kind = pick([
        "ok",
        "ok",
        "stranger",
        "plain",
        "broken",
        "wrongGen",
        "unknown",
        "null",
        "number",
      ]);
      let entry = base;
      if (kind === "stranger") entry = { ...base, resource: { type: "x", labels: {} } };
      if (kind === "plain") entry = { ...base, textPayload: "hello" };
      if (kind === "broken") entry = { ...base, textPayload: `${FRAME_MARKER}{x` };
      if (kind === "wrongGen")
        entry = entryFor(name, { insertId: base.insertId }, { generation: 3 });
      if (kind === "unknown")
        entry = entryFor(name, { insertId: base.insertId }, { handler: "zzz" });
      if (kind === "null") entry = null;
      if (kind === "number") entry = 7;
      entries.push(entry);
      if (kind === "ok" && !ids.has(base.insertId)) {
        ids.add(base.insertId);
        expectedFrames += 1;
      }
    }
    const result = parseEntries({ entries }, { readAt: "r" });
    assert.equal(result.entries, entries.length);
    assert.equal(result.frames.length, expectedFrames, JSON.stringify(entries));
    const counted = Object.values(result.ignored).reduce((a, b) => a + b, 0);
    assert.ok(counted + result.frames.length <= entries.length);
  }
});
