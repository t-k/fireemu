// The extraction of the public digest from a (synthetic) private run directory.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { KEPT_HEADERS, extract } from "./extract-production.mjs";

const RUN = "0123456789abcdef";
const frameEntry = (id, handler, receivedAt, extra) => ({
  insertId: id,
  timestamp: receivedAt,
  logName: "projects/fireemu-oracle-sbx/logs/run.googleapis.com%2Fstdout",
  resource: {
    type: "cloud_run_revision",
    labels: { service_name: handler.toLowerCase(), location: "us-central1" },
  },
  textPayload:
    "SCHED_DELIVERY_FRAME " + JSON.stringify({ receivedAt, handler, generation: 2, ...extra }),
});
const request = (headers) => ({
  method: "POST",
  url: "/",
  headers,
  rawBodyLength: null,
  rawBody: null,
  body: null,
});
const row = (id, answer) => ({
  id,
  state: "response-persisted",
  bodyBase64: Buffer.from(JSON.stringify(answer)).toString("base64"),
});

function runDir(overrides = {}) {
  const dir = mkdtempSync(join(tmpdir(), "extract-production-"));
  const headers = {
    host: "us-central1-fireemu-oracle-sbx.cloudfunctions.net",
    authorization: "<credential, 840 chars>",
    "x-cloud-trace-context": "8128a5babf1345f69ce0aab47169e538/3884770098780217813;o=1",
    "x-forwarded-for": "34.98.143.13",
    "x-cloudscheduler": "true",
    "x-cloudscheduler-jobname": "firebase-schedule-schedOkV2-us-central1",
    "x-cloudscheduler-scheduletime": "2026-10-05T01:41:00-07:00",
    "user-agent": "Google-Cloud-Scheduler",
    "content-length": "0",
    "x-forwarded-proto": "https",
  };
  const frames = [
    frameEntry("a", "schedOkV2", "2026-10-05T08:41:04.109Z", {
      request: request(headers),
      event: {
        jobName: "firebase-schedule-schedOkV2-us-central1",
        scheduleTime: "2026-10-05T01:41:00-07:00",
      },
      eventKeys: ["jobName", "scheduleTime"],
      contextProperty: { enumerable: false },
      context: { eventId: "x" },
    }),
    frameEntry("b", "schedOkV2", "2026-10-05T08:42:02.145Z", {
      request: request(headers),
      event: { jobName: "j", scheduleTime: "t" },
      eventKeys: ["jobName"],
      contextProperty: null,
      context: null,
      failing: true,
      elapsedMs: 5,
    }),
  ];
  const entries = [
    {
      insertId: "s1",
      timestamp: "2026-10-05T08:41:05.000Z",
      resource: {
        type: "cloud_scheduler_job",
        labels: { job_id: "firebase-schedule-schedOkV2-us-central1" },
      },
      jsonPayload: {
        "@type": "type.googleapis.com/google.cloud.scheduler.logging.AttemptFinished",
        targetType: "HTTP",
        status: "INTERNAL",
        debugInfo: "URL_UNREACHABLE-UNREACHABLE_5xx. Original HTTP response code number = 500",
      },
    },
    {
      insertId: "s2",
      timestamp: "2026-10-05T08:41:04.000Z",
      resource: {
        type: "cloud_scheduler_job",
        labels: { job_id: "firebase-schedule-schedOkV2-us-central1" },
      },
      jsonPayload: {
        "@type": "type.googleapis.com/google.cloud.scheduler.logging.AttemptStarted",
        targetType: "HTTP",
      },
    },
  ];
  const journal = [
    row("logs-pass1-1-frames", { entries: frames }),
    row("logs-pass1-1-scheduler", { entries }),
    { id: "other", state: "before-send" },
    // the forced runs' requests (the journal rows `run-<pass>-<job id without its prefix>`): when each was sent
    {
      id: "run-1-fe-sd-run-zero",
      state: "before-send",
      dispatchAt: "2026-10-05T08:41:03.609Z",
    },
    { id: "run-1-fe-sd-run-zero", state: "response-headers", responseAt: "2026-10-05T08:41:04.0Z" },
    {
      id: "run-1-schedOkV2-us-central1",
      state: "before-send",
      dispatchAt: "2026-10-05T08:41:05.109Z",
    },
  ];
  writeFileSync(
    join(dir, `journal-${RUN}.jsonl`),
    journal.map((r) => JSON.stringify(r)).join("\n") + "\n",
  );
  writeFileSync(
    join(dir, `result-${RUN}.json`),
    JSON.stringify({
      runId: RUN,
      jobs: { schedOkV2: { schedule: "every 1 minutes", timeZone: "UTC" } },
      extraAnswers: { retry5: { status: 200, class: "2xx", message: null } },
      passes: [
        {
          number: 1,
          forced: [{ id: `fe-sd-${RUN}-zero` }, { id: "firebase-schedule-schedOkV2-us-central1" }],
        },
      ],
      frames: { schedOkV2: 2 },
      ...overrides,
    }),
  );
  return dir;
}

test("the digest keeps the deterministic headers by value and the others by name only", () => {
  const dir = runDir();
  try {
    const digest = extract(dir);
    assert.equal(digest.frames.length, 2);
    const [first, second] = digest.frames;
    assert.equal(first.at, 0);
    assert.equal(second.at, 58036);
    assert.deepEqual(Object.keys(first.headers).toSorted(), KEPT_HEADERS.toSorted());
    assert.equal(first.headers["x-cloudscheduler-scheduletime"], "2026-10-05T01:41:00-07:00");
    assert.equal(first.headerNames.includes("authorization"), true);
    assert.equal(JSON.stringify(digest).includes("<credential"), false);
    assert.equal(JSON.stringify(digest).includes("34.98.143.13"), false);
    assert.equal(JSON.stringify(digest).includes("8128a5babf"), false);
    assert.equal(second.failing, true);
    assert.equal(second.elapsedMs, 5);
    assert.deepEqual(digest.run, {
      id: RUN,
      project: "fireemu-oracle-sbx",
      region: "us-central1",
      recordedOn: "2026-10-05",
    });
    assert.deepEqual(digest.passes[0].forced, [
      "fe-sd-<runId>-zero",
      "firebase-schedule-schedOkV2-us-central1",
    ]);
    assert.deepEqual(digest.extraAnswers, { retry5: { status: 200, class: "2xx", message: null } });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("scheduler entries are counted by kind, target, status and debug info, and attempts are timed from the first frame", () => {
  const dir = runDir();
  try {
    const digest = extract(dir);
    assert.equal(
      digest.schedulerEntryTypes[
        "AttemptFinished|HTTP|INTERNAL|URL_UNREACHABLE-UNREACHABLE_5xx. Original HTTP response code number = 500"
      ],
      1,
    );
    assert.equal(digest.schedulerEntryTypes["AttemptStarted|HTTP||"], 1);
    const attempts = digest.attempts["firebase-schedule-schedOkV2-us-central1"];
    assert.deepEqual(
      attempts.map((a) => a.kind),
      ["AttemptStarted", "AttemptFinished"],
    );
    // timed from the first frame (08:41:04.109): the start 109 ms before it, the finish 891 ms after it
    assert.deepEqual(
      attempts.map((a) => a.at),
      [-109, 891],
    );
    assert.ok(attempts[0].at < attempts[1].at);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a twelve-digit number anywhere in the digest (a project number) refuses the write", () => {
  const dir = runDir({ jobs: { schedOkV2: { name: "projects/123456789012/jobs/x" } } });
  try {
    assert.throws(() => extract(dir), /twelve-digit number/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
  const ok = runDir({ jobs: { schedOkV2: { name: "projects/12345678901/jobs/x" } } });
  try {
    assert.doesNotThrow(() => extract(ok));
  } finally {
    rmSync(ok, { recursive: true, force: true });
  }
});

test("a directory without a journal or a result is an error, not an empty digest", () => {
  const dir = mkdtempSync(join(tmpdir(), "extract-production-empty-"));
  try {
    assert.throws(() => extract(dir));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("only persisted answers of the log reads count, frames come out in the order they were received, and only attempts are timed", () => {
  const dir = runDir();
  try {
    const journalPath = join(dir, `journal-${RUN}.jsonl`);
    const early = frameEntry("early", "schedOkV2", "2026-10-05T08:40:59.000Z", {
      request: request({ "x-cloudscheduler": "true" }),
      event: { jobName: "j", scheduleTime: "t" },
      eventKeys: [],
      contextProperty: null,
      context: null,
    });
    const stray = frameEntry("stray", "schedOkV2", "2026-10-05T08:30:00.000Z", {
      request: request({}),
      event: {},
      eventKeys: [],
      contextProperty: null,
      context: null,
    });
    const scheduler = [
      {
        insertId: "x1",
        timestamp: "2026-10-05T08:41:04.500Z",
        resource: { type: "cloud_scheduler_job", labels: {} },
        jsonPayload: {
          "@type": "type.googleapis.com/google.cloud.scheduler.logging.AttemptStarted",
        },
      },
      {
        insertId: "x2",
        timestamp: "2026-10-05T08:41:04.600Z",
        resource: { type: "cloud_scheduler_job", labels: { job_id: "j" } },
        jsonPayload: { "@type": "type.googleapis.com/google.cloud.scheduler.logging.JobUpdated" },
      },
    ];
    const extra = [
      row("logs-pass1-2-frames", { entries: [early] }),
      // not persisted answers (a request that got no body) and reads that are not log reads carry no frames
      {
        id: "logs-pass1-3-frames",
        state: "response-headers",
        bodyBase64: row("x", { entries: [stray] }).bodyBase64,
      },
      row("pull-pass1-1-schedOkV1", { entries: [stray] }),
      row("logs-pass1-2-scheduler", { entries: scheduler }),
    ];
    writeFileSync(
      journalPath,
      readFileSync(journalPath, "utf8") + extra.map((r) => JSON.stringify(r)).join("\n") + "\n",
    );
    const digest = extract(dir);
    assert.deepEqual(
      digest.frames.map((f) => f.at),
      [0, 5109, 63145],
    );
    assert.equal(
      digest.frames.some((f) => f.at < 0),
      false,
    );
    // the stray frames (an unpersisted answer, a pull row) are not in the digest: three frames only
    assert.equal(digest.frames.length, 3);
    assert.equal(digest.attempts["j"], undefined, "a job update is not an attempt");
    assert.equal(Object.keys(digest.attempts).length, 1);
    assert.equal(digest.schedulerEntryTypes["AttemptStarted|||"], 1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the command line writes the digest, one space indentation and a final newline", () => {
  const dir = runDir();
  const out = join(dir, "digest.json");
  try {
    const here = dirname(fileURLToPath(import.meta.url));
    execFileSync(process.execPath, [join(here, "extract-production.mjs"), dir, out]);
    const text = readFileSync(out, "utf8");
    assert.equal(text.endsWith("}\n"), true);
    assert.match(text, /\n "schemaVersion": 1,\n/);
    assert.equal(JSON.parse(text).schemaVersion, 1);
    assert.equal(JSON.parse(text).frames.length, 2);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("each forced run is kept with the instant it was requested, from the first frame, and the run id is masked", () => {
  const dir = runDir();
  try {
    const digest = extract(dir);
    assert.deepEqual(digest.forced, [
      { pass: 1, job: "fe-sd-<runId>-zero", atMs: -500 },
      { pass: 1, job: "firebase-schedule-schedOkV2-us-central1", atMs: 1000 },
    ]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a forced run whose request the journal does not hold is an error, not a guess", () => {
  const dir = runDir({
    passes: [{ number: 1, forced: [{ id: "firebase-schedule-schedGoneV2-us-central1" }] }],
  });
  try {
    assert.throws(() => extract(dir), /no journal row for the forced run/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
