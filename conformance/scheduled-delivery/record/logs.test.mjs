import assert from "node:assert/strict";
import test from "node:test";
import { createGuard } from "./guard.mjs";
import {
  frameFilter,
  frameOrigin,
  listRequest,
  parseFrames,
  parseSchedulerEntries,
  schedulerFilter,
} from "./logs.mjs";
import { FRAME_MARK } from "./plan.mjs";

const RUN = "0123456789abcdef";
const start = "2026-10-06T00:00:00Z";
const end = "2026-10-06T01:00:00.123456Z";
const frameText = (frame) => FRAME_MARK + " " + JSON.stringify(frame);
const entryFor = (handler, body, extra = {}) => {
  const o = frameOrigin(handler);
  return {
    insertId: "i-" + Math.random().toString(16).slice(2),
    timestamp: "2026-10-06T00:01:00Z",
    logName: o.logName,
    resource: { type: o.resourceType, labels: o.labels },
    textPayload: body,
    ...extra,
  };
};

test("a v1 function's origin is the Cloud Functions log with its case-exact name, a v2's the Run stdout with the lower-case service", () => {
  assert.deepEqual(frameOrigin("schedOkV1"), {
    logName: "projects/fireemu-oracle-sbx/logs/cloudfunctions.googleapis.com%2Fcloud-functions",
    resourceType: "cloud_function",
    labels: { function_name: "schedOkV1", region: "us-central1" },
  });
  assert.deepEqual(frameOrigin("schedRetryV2"), {
    logName: "projects/fireemu-oracle-sbx/logs/run.googleapis.com%2Fstdout",
    resourceType: "cloud_run_revision",
    labels: { service_name: "schedretryv2", location: "us-central1" },
  });
});

test("the filters name every origin and the window, and the request passes the guard", () => {
  const filter = frameFilter({ start, end });
  for (const name of [
    "schedOkV1",
    "schedFailV1",
    "schedRetryV1",
    "schedokv2",
    "schedretryv2",
    "schedslowv2",
  ])
    assert.ok(filter.includes('"' + name + '"'), name);
  assert.ok(
    filter.includes('timestamp>="' + start + '"') && filter.includes('timestamp<="' + end + '"'),
  );
  assert.ok(
    filter.includes('textPayload:"SCHED_DELIVERY_FRAME"') &&
      filter.includes('jsonPayload.message:"SCHED_DELIVERY_FRAME"'),
  );
  const guard = createGuard(RUN, "123456789012");
  assert.equal(guard.allow(listRequest({ id: "x", filter })), true);
  assert.equal(guard.allow(listRequest({ id: "x", filter, pageToken: "abc" })), true);
  const sched = schedulerFilter({ runId: RUN, start, end });
  assert.ok(sched.startsWith('resource.type="cloud_scheduler_job" AND ('));
  assert.equal((sched.match(/job_id=/g) ?? []).length, 10);
  assert.equal(guard.allow(listRequest({ id: "y", filter: sched })), true);
  assert.throws(() => frameFilter({ start: "yesterday", end }), /RFC 3339/);
  assert.throws(() => schedulerFilter({ runId: RUN, start, end: "x" }), /RFC 3339/);
  assert.throws(() => schedulerFilter({ runId: "bad", start, end }), /invalid run ID/);
});

test("frames come from a text payload or a JSON message, once per insert id", () => {
  const seen = new Set();
  const a = entryFor("schedOkV2", frameText({ handler: "schedOkV2", n: 1 }));
  const b = entryFor("schedOkV2", undefined, {
    textPayload: undefined,
    jsonPayload: { message: "prefix " + frameText({ handler: "schedOkV2", n: 2 }) },
  });
  const out = parseFrames([a, b, a], seen);
  assert.deepEqual(
    out.frames.map((f) => f.frame.n),
    [1, 2],
  );
  assert.deepEqual(out.ignored, { notFrame: 0, unparsed: 0, foreignOrigin: 0 });
  assert.equal(parseFrames([a], seen).frames.length, 0, "seen on an earlier page");
});

test("what is not a usable frame is counted, never thrown", () => {
  const bad = [
    entryFor("schedOkV2", "an ordinary line"),
    entryFor("schedOkV2", FRAME_MARK + " {not json"),
    entryFor("schedOkV2", frameText({ handler: "someoneElse" })),
    entryFor("schedOkV2", frameText({ nothandler: 1 })),
    entryFor("schedOkV2", frameText({ handler: "schedFailV1" })), // a v1 frame from a Run origin
    {
      ...entryFor("schedOkV2", frameText({ handler: "schedOkV2" })),
      resource: {
        type: "cloud_run_revision",
        labels: { service_name: "other", location: "us-central1" },
      },
    },
    { insertId: "z" },
    null,
    "text",
    42,
  ];
  const out = parseFrames(bad);
  assert.equal(out.frames.length, 0);
  assert.equal(out.ignored.notFrame + out.ignored.unparsed + out.ignored.foreignOrigin, bad.length);
  assert.equal(out.ignored.foreignOrigin, 2);
  assert.deepEqual(parseFrames(undefined), {
    frames: [],
    ignored: { notFrame: 0, unparsed: 0, foreignOrigin: 0 },
  });
  assert.deepEqual(parseFrames({}).frames, []);
});

test("a v1 frame is accepted from the Cloud Functions origin only", () => {
  const good = entryFor("schedOkV1", frameText({ handler: "schedOkV1", generation: 1 }));
  assert.equal(parseFrames([good]).frames.length, 1);
  const wrong = {
    ...good,
    logName: "projects/fireemu-oracle-sbx/logs/run.googleapis.com%2Fstdout",
  };
  assert.equal(parseFrames([wrong]).ignored.foreignOrigin, 1);
});

test("Scheduler entries are kept as they came, once per insert id", () => {
  const seen = new Set();
  const a = { insertId: "1", jsonPayload: { "@type": "x" } };
  const b = { insertId: "2", protoPayload: {} };
  assert.deepEqual(parseSchedulerEntries([a, b, a, null, "x"], seen), [a, b]);
  assert.deepEqual(parseSchedulerEntries([a], seen), []);
  assert.deepEqual(parseSchedulerEntries(undefined), []);
});
