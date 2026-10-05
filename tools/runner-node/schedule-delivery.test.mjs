// How the strict profile hands a scheduled function what production's Cloud Scheduler hands it (the second
// SCHEDULED-FUNCTIONS delivery recording, run 156715222b86ea44, 2026-10-05, 97 handler frames): the request a
// Gen2 function receives, the `x-cloudscheduler-*` header values, and the Gen1 Pub/Sub context.
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import test from "node:test";

import {
  deliverSchedule,
  pubsubMessageId,
  schedulerJobId,
  schedulerRequest,
  schedulerTimestamp,
  v1ScheduleContext,
} from "./schedule-delivery.mjs";

const JOB = "projects/demo-app/locations/us-central1/jobs/firebase-schedule-schedOkV2-us-central1";

test("the header time is the instant in America/Los_Angeles with its offset (recorded for UTC and Asia/Tokyo jobs alike)", () => {
  // Recorded: scheduleTime 08:45:00Z read 01:45:00-07:00, and the next 1 January 00:00Z read 16:00:00-08:00.
  assert.equal(schedulerTimestamp("2026-10-05T08:45:00Z"), "2026-10-05T01:45:00-07:00");
  assert.equal(schedulerTimestamp("2027-01-01T00:00:00Z"), "2026-12-31T16:00:00-08:00");
  // The fraction is kept, six digits as recorded, and trailing zeros are dropped.
  assert.equal(
    schedulerTimestamp("2026-10-05T08:42:01.416739Z"),
    "2026-10-05T01:42:01.416739-07:00",
  );
  assert.equal(schedulerTimestamp("2026-10-05T08:42:01.500000000Z"), "2026-10-05T01:42:01.5-07:00");
  assert.equal(schedulerTimestamp("2026-10-05T08:42:01.000Z"), "2026-10-05T01:42:01-07:00");
  assert.equal(
    schedulerTimestamp("2026-10-05T08:42:01.123456789Z"),
    "2026-10-05T01:42:01.123456789-07:00",
  );
});

test("the offset follows Pacific daylight time: both sides of each change, and the year's ends", () => {
  // 2026-03-08 10:00Z is 03:00 PDT (the clock skipped 02:00-03:00); 09:59:59Z is 01:59:59 PST.
  assert.equal(schedulerTimestamp("2026-03-08T09:59:59Z"), "2026-03-08T01:59:59-08:00");
  assert.equal(schedulerTimestamp("2026-03-08T10:00:00Z"), "2026-03-08T03:00:00-07:00");
  // 2026-11-01: 08:59:59Z is 01:59:59 PDT; 09:00:00Z is 01:00:00 PST (the hour repeats).
  assert.equal(schedulerTimestamp("2026-11-01T08:59:59Z"), "2026-11-01T01:59:59-07:00");
  assert.equal(schedulerTimestamp("2026-11-01T09:00:00Z"), "2026-11-01T01:00:00-08:00");
  assert.equal(schedulerTimestamp("2026-01-01T00:00:00Z"), "2025-12-31T16:00:00-08:00");
  assert.equal(schedulerTimestamp("2026-07-01T00:00:00Z"), "2026-06-30T17:00:00-07:00");
});

test("a value that is not an RFC 3339 UTC instant is refused, not guessed", () => {
  for (const bad of ["", "2026-10-05", "2026-10-05T08:45:00", "2026-10-05T08:45:00+09:00", "2026-13-05T08:45:00Z", "x", null, undefined, 5]) {
    assert.throws(() => schedulerTimestamp(bad), /scheduled time/, String(bad));
  }
});

test("the job id is the last segment of the resource name, and an id passes through", () => {
  assert.equal(schedulerJobId(JOB), "firebase-schedule-schedOkV2-us-central1");
  assert.equal(schedulerJobId("firebase-schedule-x-us-central1"), "firebase-schedule-x-us-central1");
  assert.throws(() => schedulerJobId(""), /job name/);
  assert.throws(() => schedulerJobId(undefined), /job name/);
});

test("the request is the recorded one: POST /, the scheduler headers, an empty body, case-insensitive lookup", () => {
  const req = schedulerRequest({ jobName: JOB, scheduleTime: "2026-10-05T08:45:00Z" });
  assert.equal(req.method, "POST");
  assert.equal(req.url, "/");
  assert.equal(req.originalUrl, "/");
  assert.deepEqual(req.headers, {
    "x-cloudscheduler": "true",
    "x-cloudscheduler-jobname": "firebase-schedule-schedOkV2-us-central1",
    "x-cloudscheduler-scheduletime": "2026-10-05T01:45:00-07:00",
    "user-agent": "Google-Cloud-Scheduler",
    "content-length": "0",
  });
  assert.equal(req.header("X-CloudScheduler-JobName"), "firebase-schedule-schedOkV2-us-central1");
  assert.equal(req.header("X-CloudScheduler-ScheduleTime"), "2026-10-05T01:45:00-07:00");
  assert.equal(req.header("x-missing"), undefined);
  assert.equal(req.get("User-Agent"), "Google-Cloud-Scheduler");
  assert.equal(req.body, undefined);
  assert.equal(req.rawBody, undefined);
});

test("delivery calls the function with that request and treats a 2xx answer as success", async () => {
  const seen = [];
  const fn = async (req, res) => {
    seen.push({ job: req.header("X-CloudScheduler-JobName"), time: req.header("X-CloudScheduler-ScheduleTime") });
    res.status(200).send();
  };
  await deliverSchedule(fn, { jobName: JOB, scheduleTime: "2026-10-05T08:45:00Z" });
  assert.deepEqual(seen, [{ job: "firebase-schedule-schedOkV2-us-central1", time: "2026-10-05T01:45:00-07:00" }]);
});

test("a 4xx or 5xx answer, or a throw, is a failed delivery; an answer is required", async () => {
  const data = { jobName: JOB, scheduleTime: "2026-10-05T08:45:00Z" };
  await assert.rejects(deliverSchedule(async (_req, res) => res.status(500).send(), data), /answered 500/);
  await assert.rejects(deliverSchedule(async (_req, res) => res.status(404).send(), data), /answered 404/);
  await assert.rejects(deliverSchedule(async () => { throw new Error("boom"); }, data), /boom/);
  // The SDK always answers; a function that never does is not a success we can claim.
  await assert.rejects(deliverSchedule(async () => {}, data), /did not answer/);
  // 399 and below are not failures.
  await deliverSchedule(async (_req, res) => res.status(204).send(), data);
});

test("the response double supports what Express handlers and the SDK use", async () => {
  await deliverSchedule(
    async (_req, res) => {
      res.setHeader("x-test", "1");
      res.status(200).json({});
    },
    { jobName: JOB, scheduleTime: "2026-10-05T08:45:00Z" },
  );
  await deliverSchedule(async (_req, res) => res.sendStatus(200), { jobName: JOB, scheduleTime: "2026-10-05T08:45:00Z" });
  await deliverSchedule(async (_req, res) => { res.status(200); res.end(); }, { jobName: JOB, scheduleTime: "2026-10-05T08:45:00Z" });
});

test("a Gen1 message id is 17 digits starting with 2, the same for the same event and different for another", () => {
  const ids = new Set();
  for (let i = 0; i < 500; i++) {
    const id = pubsubMessageId(`42-${i}`);
    assert.match(id, /^2\d{16}$/);
    assert.equal(pubsubMessageId(`42-${i}`), id);
    ids.add(id);
  }
  assert.equal(ids.size, 500);
  assert.notEqual(pubsubMessageId("1-3"), pubsubMessageId("2-3"));
  assert.throws(() => pubsubMessageId(""), /event id/);
  assert.throws(() => pubsubMessageId(undefined), /event id/);
});

test("the Gen1 context names the topic and the message, as recorded for pubsub.schedule", () => {
  const event = {
    id: "42-3",
    time: "2026-10-05T08:41:00Z",
    data: { jobName: "projects/demo-app/locations/us-central1/jobs/firebase-schedule-schedOkV1-us-central1", scheduleTime: "2026-10-05T08:41:00Z" },
  };
  const context = v1ScheduleContext(event);
  assert.deepEqual(context, {
    eventId: pubsubMessageId("42-3"),
    eventType: "google.pubsub.topic.publish",
    resource: {
      name: "projects/demo-app/topics/firebase-schedule-schedOkV1-us-central1",
      service: "pubsub.googleapis.com",
      type: "type.googleapis.com/google.pubsub.v1.PubsubMessage",
    },
    timestamp: "2026-10-05T08:41:00Z",
    params: {},
  });
  // The time is shown as a Pub/Sub publish time: milliseconds at most, trailing zeros dropped.
  assert.equal(v1ScheduleContext({ ...event, time: "2026-10-05T08:41:01.359000000Z" }).timestamp, "2026-10-05T08:41:01.359Z");
  assert.equal(v1ScheduleContext({ ...event, time: "2026-10-05T08:41:02.1Z" }).timestamp, "2026-10-05T08:41:02.1Z");
  assert.equal(v1ScheduleContext({ ...event, time: "2026-10-05T08:41:03.123456Z" }).timestamp, "2026-10-05T08:41:03.123Z");
  assert.throws(() => v1ScheduleContext({ ...event, data: { jobName: "" } }), /job name/);
});

test("the instant check: nine fractional digits at most, the calendar must agree, and the message names the value", () => {
  assert.equal(schedulerTimestamp("2026-10-05T08:42:01.123456789Z"), "2026-10-05T01:42:01.123456789-07:00");
  assert.throws(() => schedulerTimestamp("2026-10-05T08:42:01.1234567890Z"), /scheduled time/);
  // The calendar: a day that does not exist, a leap day that does, a year Date.UTC would move into the 1900s.
  for (const bad of ["2026-02-30T00:00:00Z", "2026-02-29T00:00:00Z", "2026-10-05T24:00:00Z", "2026-10-05T08:60:00Z", "2026-10-05T08:00:60Z", "0099-01-01T00:00:00Z"])
    assert.throws(() => schedulerTimestamp(bad), /scheduled time/, bad);
  assert.equal(schedulerTimestamp("2028-02-29T12:00:00Z"), "2028-02-29T04:00:00-08:00");
  assert.throws(() => schedulerTimestamp("2026-10-05"), new Error("the scheduled time is not an RFC 3339 UTC instant: 2026-10-05"));
  assert.throws(() => schedulerTimestamp("2026-02-30T00:00:00Z"), new Error("the scheduled time is not an RFC 3339 UTC instant: 2026-02-30T00:00:00Z"));
  assert.throws(() => v1ScheduleContext({ id: "x", time: "nope", data: { jobName: JOB } }), new Error("the publish time is not an RFC 3339 UTC instant: nope"));
});

test("an answer of exactly 400 fails, 399 does not, and sendStatus sets the status", async () => {
  const data = { jobName: JOB, scheduleTime: "2026-10-05T08:45:00Z" };
  await assert.rejects(deliverSchedule(async (_req, res) => res.status(400).send(), data), /answered 400/);
  await assert.rejects(deliverSchedule(async (_req, res) => res.sendStatus(500), data), /answered 500/);
  await assert.rejects(deliverSchedule(async (_req, res) => res.sendStatus(404), data), /answered 404/);
  await deliverSchedule(async (_req, res) => res.status(399).send(), data);
  await deliverSchedule(async (_req, res) => res.sendStatus(200), data);
  // an answer with no status at all is a 200
  await deliverSchedule(async (_req, res) => res.send(), data);
});

test("message ids are pinned, including one whose sixteen digits start with a zero", () => {
  assert.equal(pubsubMessageId("42-3"), "21060470636220959");
  assert.equal(pubsubMessageId("probe-8"), "20480968339137279");
  assert.equal(pubsubMessageId("1-1"), "25940261599779572");
});

// ---- against the real SDK -----------------------------------------------------------------------------------

const sdkRoot = process.env.FE_SOURCE_SDK_ROOT;
const withSdk = sdkRoot ? test : test.skip;

withSdk("the real onSchedule gets the recorded event: the job id, the Los Angeles time and the context getter", async () => {
  const { onSchedule } = createRequire(join(dirname(sdkRoot), "x.js"))("firebase-functions/v2/scheduler");
  let event;
  const fn = onSchedule("every 5 minutes", async (e) => {
    event = e;
  });
  await deliverSchedule(fn, { jobName: JOB, scheduleTime: "2026-10-05T08:45:00Z" });
  assert.equal(event.jobName, "firebase-schedule-schedOkV2-us-central1");
  assert.equal(event.scheduleTime, "2026-10-05T01:45:00-07:00");
  assert.deepEqual(Object.keys(event), ["jobName", "scheduleTime"]);
  const descriptor = Object.getOwnPropertyDescriptor(event, "context");
  assert.equal(descriptor.enumerable, false);
  assert.equal(typeof descriptor.get, "function");
  assert.equal(event.context.eventId, "firebase-schedule-schedOkV2-us-central1");
  assert.equal(event.context.timestamp, "2026-10-05T01:45:00-07:00");
  assert.equal(event.context.eventType, "google.pubsub.topic.publish");
});

withSdk("the real onSchedule failing is a failed delivery, and the SDK's own handling ran", async () => {
  const { onSchedule } = createRequire(join(dirname(sdkRoot), "x.js"))("firebase-functions/v2/scheduler");
  let ran = 0;
  const fn = onSchedule("every 5 minutes", async () => {
    ran++;
    throw new Error("deliberate");
  });
  await assert.rejects(deliverSchedule(fn, { jobName: JOB, scheduleTime: "2026-10-05T08:45:00Z" }), /answered 500/);
  assert.equal(ran, 1);
});
