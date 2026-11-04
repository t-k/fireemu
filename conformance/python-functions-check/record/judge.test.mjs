// The judge: the production-shaped baseline is all as-expected, every rule has a mutation that makes exactly its case
// differ with the rule named, missing frames and unsent operations are reported as such, and it never throws.
import assert from "node:assert/strict";
import test from "node:test";
import { framesOf, judge } from "./judge.mjs";
import { PRODUCTION_FRAMES } from "./world.mjs";

const RUN = "0123456789abcdef";
const ALL_SENT = Object.fromEntries(
  [
    "fs-create",
    "fs-update",
    "ps-plain",
    "ps-ordered",
    "st-upload",
    "ea-fraction",
    "ea-whole",
    "sched-pcsch",
    "sched-pcschraw",
    "task-pctask",
    "task-pctaskraw",
  ].map((k) => [k, {}]),
);
const baseline = () =>
  JSON.parse(JSON.stringify(PRODUCTION_FRAMES).replaceAll("pcrun-RUNID", "pcrun-" + RUN)).map(
    (frame) => ({ frame }),
  );
const judged = (frames, extra = {}) => judge({ runId: RUN, frames, sent: ALL_SENT, ...extra });
/** A baseline with `edit` applied to the first frame of `fn` (and `kind`, when given). */
const edited = (fn, edit, kind) => {
  const frames = baseline();
  const entry = frames.find((e) => e.frame.function === fn && (!kind || e.frame.kind === kind));
  edit(entry.frame);
  return frames;
};

test("the production-shaped baseline judges every case as expected, with the whole-second time observed", () => {
  const r = judged(baseline());
  const statuses = Object.fromEntries(Object.entries(r.cases).map(([id, c]) => [id, c.status]));
  assert.deepEqual(statuses, {
    "firestore-protobuf": "as-expected",
    "firestore-attributes": "as-expected",
    "firestore-sdk": "as-expected",
    "pubsub-keys-plain": "as-expected",
    "pubsub-sdk-plain": "as-expected",
    "pubsub-keys-ordered": "as-expected",
    "pubsub-sdk-ordered": "as-expected",
    "storage-time": "as-expected",
    "storage-shape": "as-expected",
    "eventarc-time-fraction": "as-expected",
    "eventarc-time-whole": "observed",
    "eventarc-data": "as-expected",
    "scheduler-request": "as-expected",
    "tasks-request": "as-expected",
    "sdk-versions": "as-expected",
  });
  assert.equal(r.complete, true);
  assert.deepEqual(r.counts, {
    "as-expected": 14,
    differs: 0,
    observed: 1,
    "not-delivered": 0,
    "not-sent": 0,
  });
});

// [case, function, kind, edit, the rule that must be named]
const RULES = [
  ["firestore-protobuf", "pcfscraw", "raw-event", (f) => (f.data.kind = "json"), "data-is-bytes"],
  [
    "firestore-protobuf",
    "pcfscraw",
    "raw-event",
    (f) => (f.request.headers["content-type"] = "application/json"),
    "content-type-protobuf",
  ],
  [
    "firestore-protobuf",
    "pcfscraw",
    "raw-event",
    (f) => delete f.data.protobuf,
    "protobuf-decodes",
  ],
  [
    "firestore-protobuf",
    "pcfscraw",
    "raw-event",
    (f) => (f.data.protobuf.value.fields.run.stringValue = "pcrun-other"),
    "run-in-document",
  ],
  ["firestore-protobuf", "pcfscraw", "raw-event", (f) => (f.request = null), "request-context"],
  [
    "firestore-attributes",
    "pcfscraw",
    "raw-event",
    (f) => delete f.attributes.subject,
    "required-attributes",
  ],
  [
    "firestore-attributes",
    "pcfscraw",
    "raw-event",
    (f) => (f.attributes.location = 5),
    "all-strings",
  ],
  ["firestore-sdk", "pcfsc", "sdk-event", (f) => (f.snapshot.data.n = 9), "created-n"],
  ["firestore-sdk", "pcfsu", "sdk-event", (f) => (f.before.data.n = 9), "updated-before"],
  ["firestore-sdk", "pcfsu", "sdk-event", (f) => (f.after.data.n = 9), "updated-after"],
  ["firestore-sdk", "pcfsc", "sdk-event", (f) => (f.params = {}), "created-params"],
  [
    "pubsub-keys-plain",
    "pcpsraw",
    "raw-event",
    (f) => delete f.data.value.message.messageId,
    "message-id",
  ],
  [
    "pubsub-keys-plain",
    "pcpsraw",
    "raw-event",
    (f) => delete f.data.value.message.publishTime,
    "publish-time",
  ],
  [
    "pubsub-keys-plain",
    "pcpsraw",
    "raw-event",
    (f) => delete f.data.value.message.message_id,
    "snake-message-id",
  ],
  [
    "pubsub-keys-plain",
    "pcpsraw",
    "raw-event",
    (f) => delete f.data.value.message.publish_time,
    "snake-publish-time",
  ],
  [
    "pubsub-keys-plain",
    "pcpsraw",
    "raw-event",
    (f) => (f.data.value.message.ordering_key = "x"),
    "no-snake-ordering-key",
  ],
  [
    "pubsub-keys-plain",
    "pcpsraw",
    "raw-event",
    (f) => (f.data.value.message.orderingKey = "x"),
    "no-ordering-key",
  ],
  ["pubsub-sdk-plain", "pcps", "sdk-event", (f) => delete f.publish_time, "publish-time"],
  ["pubsub-sdk-plain", "pcps", "sdk-event", (f) => delete f.message_id, "message-id"],
  ["pubsub-sdk-plain", "pcps", "sdk-event", (f) => (f.ordering_key = "x"), "ordering-key"],
  [
    "storage-time",
    "pcstraw",
    "raw-event",
    (f) => (f.attributes.time = "2026-01-01T00:00:00Z"),
    "time-has-fraction",
  ],
  [
    "storage-shape",
    "pcstraw",
    "raw-event",
    (f) => delete f.data.value.storageClass,
    "sdk-required-keys",
  ],
  ["storage-shape", "pcstraw", "raw-event", (f) => (f.data.kind = "bytes"), "data-is-json"],
  [
    "eventarc-time-fraction",
    "pcearaw",
    "raw-event",
    (f) => (f.attributes.time = "2026-01-01T00:00:02Z"),
    "time-preserved",
  ],
  ["eventarc-data", "pcearaw", "raw-event", (f) => (f.data.kind = "bytes"), "data-is-json"],
  [
    "eventarc-data",
    "pcearaw",
    "raw-event",
    (f) => (f.data.value.run = "pcrun-other"),
    "run-in-data",
  ],
  ["eventarc-data", "pcearaw", "raw-event", (f) => (f.attributes.type = "other"), "type"],
  [
    "scheduler-request",
    "pcschraw",
    "raw-request",
    (f) => (f.request.headers["x-cloudscheduler"] = "false"),
    "x-cloudscheduler",
  ],
  [
    "scheduler-request",
    "pcschraw",
    "raw-request",
    (f) => (f.request.headers["x-cloudscheduler-jobname"] = "other"),
    "job-id",
  ],
  [
    "scheduler-request",
    "pcschraw",
    "raw-request",
    (f) => (f.request.headers["x-cloudscheduler-scheduletime"] = "2026-11-03T17:13:26Z"),
    "schedule-time-los-angeles",
  ],
  [
    "scheduler-request",
    "pcschraw",
    "raw-request",
    (f) => (f.request.headers["user-agent"] = "curl"),
    "user-agent",
  ],
  [
    "scheduler-request",
    "pcschraw",
    "raw-request",
    (f) => (f.request.headers["content-length"] = "2"),
    "content-length",
  ],
  [
    "scheduler-request",
    "pcschraw",
    "raw-request",
    (f) => (f.request.headers["x-forwarded-proto"] = "http"),
    "x-forwarded-proto",
  ],
  [
    "scheduler-request",
    "pcschraw",
    "raw-request",
    (f) => (f.request.headers["accept-encoding"] = "gzip"),
    "accept-encoding",
  ],
  [
    "scheduler-request",
    "pcschraw",
    "raw-request",
    (f) => (f.request.headers.host = "127.0.0.1"),
    "host",
  ],
  ["scheduler-request", "pcschraw", "raw-request", (f) => (f.request.method = "GET"), "method"],
  [
    "tasks-request",
    "pctaskraw",
    "raw-request",
    (f) => (f.request.headers["content-type"] = "text/plain"),
    "content-type-json",
  ],
  [
    "tasks-request",
    "pctaskraw",
    "raw-request",
    (f) => (f.request.headers["x-cloudtasks-queuename"] = "x"),
    "queue-name-header",
  ],
  [
    "tasks-request",
    "pctaskraw",
    "raw-request",
    (f) =>
      (f.request.header_names = f.request.header_names.filter(
        (n) => n !== "x-cloudtasks-taskname",
      )),
    "task-name-header",
  ],
  [
    "tasks-request",
    "pctaskraw",
    "raw-request",
    (f) =>
      (f.request.header_names = f.request.header_names.filter(
        (n) => n !== "x-cloudtasks-taskretrycount",
      )),
    "retry-count-header",
  ],
  [
    "tasks-request",
    "pctaskraw",
    "raw-request",
    (f) =>
      (f.request.header_names = f.request.header_names.filter(
        (n) => n !== "x-cloudtasks-taskexecutioncount",
      )),
    "execution-count-header",
  ],
  [
    "tasks-request",
    "pctaskraw",
    "raw-request",
    (f) =>
      (f.request.header_names = f.request.header_names.filter((n) => n !== "x-cloudtasks-tasketa")),
    "eta-header",
  ],
  [
    "tasks-request",
    "pctaskraw",
    "raw-request",
    (f) => (f.request.authorization = null),
    "bearer-token",
  ],
  [
    "tasks-request",
    "pctaskraw",
    "raw-request",
    (f) => (f.request.authorization = { scheme: "Bearer", segments: 2 }),
    "bearer-token",
  ],
  [
    "tasks-request",
    "pctaskraw",
    "raw-request",
    (f) => (f.request.body_text = JSON.stringify({ run: "x" })),
    "body-callable-format",
  ],
  ["tasks-request", "pctaskraw", "raw-request", (f) => (f.request.method = "PUT"), "method"],
  [
    "sdk-versions",
    "pcea",
    "sdk-event",
    (f) => (f.versions["firebase-functions"] = "0.5.0"),
    "pinned-sdk",
  ],
];
for (const [id, fn, kind, edit, rule] of RULES)
  test(`${id}: breaking ${rule} makes only that case differ and names the rule`, () => {
    const before = judged(baseline());
    const r = judged(edited(fn, edit, kind));
    assert.equal(r.cases[id].status, "differs", id + " " + JSON.stringify(r.cases[id].notes));
    assert.ok(r.cases[id].notes.includes(rule), `${rule} is named: ${r.cases[id].notes}`);
    for (const other of Object.keys(r.cases))
      if (other !== id)
        assert.equal(r.cases[other].status, before.cases[other].status, other + " unchanged");
  });

test("an operation that was not sent is not-sent, and its frames are not judged", () => {
  const { "fs-create": _drop, ...rest } = ALL_SENT;
  const r = judge({ runId: RUN, frames: baseline(), sent: rest });
  assert.equal(r.cases["firestore-protobuf"].status, "not-sent");
  assert.equal(r.cases["firestore-attributes"].status, "not-sent");
  assert.equal(r.cases["firestore-sdk"].status, "not-sent");
  assert.equal(r.complete, false);
  assert.equal(r.cases["pubsub-keys-plain"].status, "as-expected");
});

test("a sent operation with no frame is not-delivered for each family", () => {
  const without = (...fns) => baseline().filter((e) => !fns.includes(e.frame.function));
  const gone = (id, ...fns) =>
    assert.equal(judged(without(...fns)).cases[id].status, "not-delivered", id);
  gone("firestore-protobuf", "pcfscraw");
  gone("firestore-attributes", "pcfscraw");
  gone("firestore-sdk", "pcfsc");
  gone("firestore-sdk", "pcfsu");
  gone("pubsub-keys-plain", "pcpsraw");
  gone("pubsub-keys-ordered", "pcpsraw");
  gone("pubsub-sdk-plain", "pcps");
  gone("pubsub-sdk-ordered", "pcps");
  gone("storage-time", "pcstraw");
  gone("storage-shape", "pcstraw");
  gone("eventarc-time-fraction", "pcearaw");
  gone("eventarc-time-whole", "pcearaw");
  gone("eventarc-data", "pcearaw");
  gone("scheduler-request", "pcschraw");
  gone("tasks-request", "pctaskraw");
  gone("sdk-versions", ...baseline().map((e) => e.frame.function));
  assert.equal(
    judged(without("pcea")).cases["eventarc-time-fraction"].status,
    "differs",
    "the SDK function not running is a difference, not a missing delivery",
  );
  assert.equal(judged(without("pcst")).cases["storage-time"].status, "differs");
});

test("frames of another run, or without a run marker, are not this run's", () => {
  const other = JSON.parse(JSON.stringify(baseline()).replaceAll(RUN, "ffffffffffffffff"));
  const r = judged(other);
  for (const id of [
    "firestore-protobuf",
    "pubsub-keys-plain",
    "storage-shape",
    "eventarc-data",
    "tasks-request",
  ])
    assert.equal(r.cases[id].status, "not-delivered", id);
  assert.equal(framesOf(other, "pcfscraw", "pcrun-" + RUN).length, 0);
  assert.equal(framesOf(other, "pcfscraw", "pcrun-" + RUN, { anyRun: true }).length, 1);
});

test("the whole-second time is observed, preserved or changed, and never a difference", () => {
  // the first pcearaw frame is the fraction one; edit the whole one explicitly
  const frames = baseline();
  frames.filter((e) => e.frame.function === "pcearaw")[1].frame.attributes.time =
    "2026-01-01T00:00:02.000Z";
  const r = judged(frames);
  assert.equal(r.cases["eventarc-time-whole"].status, "observed");
  assert.deepEqual(r.cases["eventarc-time-whole"].notes, ["changed"]);
  assert.deepEqual(judged(baseline()).cases["eventarc-time-whole"].notes, ["preserved"]);
});

test("ERROR entries are carried through reduced to their function, time and text", () => {
  const r = judged(baseline(), {
    errors: [{ function: "pcea", timestamp: "t", text: "Traceback", extra: "dropped" }],
  });
  assert.deepEqual(r.errors, [{ function: "pcea", timestamp: "t", text: "Traceback" }]);
});

test("the production mode requires the request context and the local mode does not", () => {
  const frames = edited("pcfscraw", (f) => (f.request = null), "raw-event");
  assert.equal(judged(frames, { mode: "local" }).cases["firestore-protobuf"].status, "as-expected");
  assert.equal(
    judged(frames, { mode: "production" }).cases["firestore-protobuf"].status,
    "differs",
  );
});

test("it never throws on hostile or truncated frames", () => {
  let seed = 7;
  const next = () => (seed = (seed * 1103515245 + 12345) % 2147483648) / 2147483648;
  const junk = [
    null,
    1,
    "x",
    [],
    {},
    { frame: null },
    { frame: { function: "pcfscraw" } },
    { frame: { function: "pcpsraw", kind: "raw-event", data: { value: { message: 5 } } } },
    { function: "pcschraw", kind: "raw-request", request: { headers: null } },
  ];
  for (let round = 0; round < 200; round++) {
    const frames = baseline();
    for (let i = 0; i < 5; i++) {
      const target = frames[Math.floor(next() * frames.length)];
      if (!target?.frame || typeof target.frame !== "object") continue;
      const keys = Object.keys(target.frame);
      const key = keys[Math.floor(next() * keys.length)];
      target.frame[key] = junk[Math.floor(next() * junk.length)];
      if (next() < 0.3) frames.splice(Math.floor(next() * frames.length), 1);
      if (next() < 0.3) frames.push(junk[Math.floor(next() * junk.length)]);
    }
    const r = judged(frames);
    const total = Object.values(r.counts).reduce((a, b) => a + b, 0);
    assert.equal(total, Object.keys(r.cases).length);
    for (const c of Object.values(r.cases))
      assert.ok(
        ["as-expected", "differs", "observed", "not-delivered", "not-sent"].includes(c.status),
      );
  }
});
