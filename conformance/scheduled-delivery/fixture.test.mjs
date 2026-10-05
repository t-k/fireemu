// The delivery fixture, offline: the SDK's own discovery finds exactly the five functions, every one
// pinned to us-central1, with the schedules and retry options the packet declares; and the handlers
// print the frame the recorder reads.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
} from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";

const here = dirname(new URL(import.meta.url).pathname);
const sdkRoot = process.env.FE_SOURCE_SDK_ROOT ?? join(here, "../node_modules/firebase-functions");
const present = existsSync(join(sdkRoot, "package.json"));
const maybe = present ? test : test.skip;

const EXPECTED = [
  "schedOkV1",
  "schedFailV1",
  "schedOkV2",
  "schedRetryV2",
  "schedSlowV2",
].toSorted();

/** A copy of the fixture with the SDK reachable, as the recorder's source copy has it. */
function source() {
  const dir = mkdtempSync(join(tmpdir(), "sched-fixture-"));
  cpSync(join(here, "fixture"), join(dir, "fixture"), { recursive: true });
  mkdirSync(join(dir, "fixture/node_modules"), { recursive: true });
  symlinkSync(sdkRoot, join(dir, "fixture/node_modules/firebase-functions"));
  return dir;
}

function discover(dir) {
  const manifest = join(dir, "manifest.json");
  execFileSync(
    process.execPath,
    [join(sdkRoot, "lib/bin/firebase-functions.js"), join(dir, "fixture")],
    {
      env: {
        PATH: dirname(process.execPath),
        HOME: dir,
        FUNCTIONS_MANIFEST_OUTPUT_PATH: manifest,
        GCLOUD_PROJECT: "fireemu-oracle-sbx",
        FIREBASE_CONFIG: JSON.stringify({ projectId: "fireemu-oracle-sbx" }),
      },
      cwd: join(dir, "fixture"),
      timeout: 60_000,
      stdio: ["ignore", "ignore", "pipe"],
    },
  );
  return JSON.parse(readFileSync(manifest, "utf8"));
}

maybe("the SDK discovers exactly the five functions, all pinned to us-central1", () => {
  const dir = source();
  try {
    const manifest = discover(dir);
    const names = Object.keys(manifest.endpoints).toSorted();
    assert.deepEqual(names, EXPECTED);
    for (const [name, endpoint] of Object.entries(manifest.endpoints))
      assert.deepEqual(endpoint.region, ["us-central1"], name + " is pinned");
    assert.equal(manifest.endpoints.schedOkV2.platform, "gcfv2");
    assert.equal(manifest.endpoints.schedRetryV2.platform, "gcfv2");
    assert.equal(manifest.endpoints.schedSlowV2.platform, "gcfv2");
    assert.equal(manifest.endpoints.schedOkV1.platform, "gcfv1");
    assert.equal(manifest.endpoints.schedFailV1.platform, "gcfv1");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

maybe("the declared schedules, time zones and retry options are what the packet says", () => {
  const dir = source();
  try {
    const e = discover(dir).endpoints;
    assert.equal(e.schedOkV2.scheduleTrigger.schedule, "every 1 minutes");
    assert.ok(
      !("timeZone" in e.schedOkV2.scheduleTrigger) || e.schedOkV2.scheduleTrigger.timeZone == null,
    );
    assert.equal(e.schedRetryV2.scheduleTrigger.schedule, "every 5 minutes");
    assert.equal(e.schedRetryV2.scheduleTrigger.timeZone, "Asia/Tokyo");
    assert.deepEqual(e.schedRetryV2.scheduleTrigger.retryConfig, {
      retryCount: 6,
      minBackoffSeconds: 4,
      maxBackoffSeconds: 50,
      maxDoublings: 2,
    });
    assert.equal(e.schedSlowV2.timeoutSeconds, 90);
    assert.equal(e.schedSlowV2.scheduleTrigger.retryConfig.retryCount, 0);
    assert.equal(e.schedOkV1.scheduleTrigger.schedule, "every 1 minutes");
    assert.equal(e.schedOkV1.scheduleTrigger.timeZone, "Asia/Tokyo");
    assert.equal(e.schedFailV1.scheduleTrigger.schedule, "every 5 minutes");
    assert.ok(!e.schedFailV1.scheduleTrigger.timeZone);
    assert.ok(!e.schedFailV1.failurePolicy && !e.schedOkV1.failurePolicy, "no failure policy");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

function frames(run) {
  const lines = [];
  const log = console.log;
  console.log = (line) => lines.push(String(line));
  return Promise.resolve()
    .then(run)
    .finally(() => {
      console.log = log;
    })
    .then(() =>
      lines
        .filter((l) => l.startsWith("SCHED_DELIVERY_FRAME "))
        .map((l) => JSON.parse(l.slice(21))),
    );
}

maybe(
  "a v2 handler prints the request, the event and the context getter it was handed",
  async () => {
    const dir = source();
    try {
      const fixture = createRequire(join(dir, "fixture/index.js"))("./index.js");
      const req = {
        method: "POST",
        originalUrl: "/",
        url: "/",
        headers: {
          authorization: "Bearer secret-token-value",
          "user-agent": "Google-Cloud-Scheduler",
          "x-cloudscheduler": "true",
          "x-cloudscheduler-jobname": "firebase-schedule-schedOkV2-us-central1",
          "x-cloudscheduler-scheduletime": "2026-10-06T00:01:00Z",
        },
        rawBody: Buffer.from(""),
        body: {},
        header(name) {
          return this.headers[name.toLowerCase()];
        },
      };
      const res = {
        status() {
          return this;
        },
        send() {
          return this;
        },
      };
      const out = await frames(() => fixture.schedOkV2(req, res));
      assert.equal(out.length, 1);
      const [frame] = out;
      assert.equal(frame.handler, "schedOkV2");
      assert.equal(frame.generation, 2);
      assert.equal(frame.request.method, "POST");
      assert.equal(
        frame.request.headers["x-cloudscheduler-jobname"],
        "firebase-schedule-schedOkV2-us-central1",
      );
      assert.equal(
        frame.request.headers.authorization,
        "<credential, 25 chars>",
        "the credential is not printed",
      );
      assert.ok(!JSON.stringify(frame).includes("secret-token-value"));
      assert.equal(frame.event.jobName, "firebase-schedule-schedOkV2-us-central1");
      assert.equal(frame.event.scheduleTime, "2026-10-06T00:01:00Z");
      assert.deepEqual(frame.eventKeys, ["jobName", "scheduleTime"]);
      assert.deepEqual(frame.contextProperty, {
        enumerable: false,
        configurable: false,
        hasGetter: true,
      });
      assert.equal(frame.context.eventType, "google.pubsub.topic.publish");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  },
);

maybe(
  "the retry handler fails inside twenty seconds of the scheduled time and succeeds after",
  async () => {
    const dir = source();
    try {
      const fixture = createRequire(join(dir, "fixture/index.js"))("./index.js");
      const mk = (scheduleTime) => ({
        method: "POST",
        headers: { "x-cloudscheduler-jobname": "j", "x-cloudscheduler-scheduletime": scheduleTime },
        rawBody: Buffer.from(""),
        body: {},
        header(name) {
          return this.headers[name.toLowerCase()];
        },
      });
      const sent = [];
      const res = {
        status(code) {
          sent.push(code);
          return this;
        },
        send() {
          return this;
        },
      };
      const soon = new Date(Date.now() - 1000).toISOString();
      const late = new Date(Date.now() - 60_000).toISOString();
      const a = await frames(() => fixture.schedRetryV2(mk(soon), res));
      const b = await frames(() => fixture.schedRetryV2(mk(late), res));
      assert.equal(a[0].failing, true);
      assert.equal(b[0].failing, false);
      assert.deepEqual(sent, [500, 200], "a failing attempt is a 500, a good one a 200");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  },
);

maybe("the v1 handlers print the context; the failing one throws", async () => {
  const dir = source();
  try {
    const fixture = createRequire(join(dir, "fixture/index.js"))("./index.js");
    const context = {
      eventId: "e1",
      timestamp: "2026-10-06T00:01:00Z",
      eventType: "google.pubsub.topic.publish",
      resource: {
        service: "pubsub.googleapis.com",
        name: "projects/p/topics/firebase-schedule-schedOkV1-us-central1",
      },
    };
    const ok = await frames(() => fixture.schedOkV1.run(context));
    assert.equal(ok[0].handler, "schedOkV1");
    assert.equal(ok[0].generation, 1);
    assert.equal(ok[0].context.eventId, "e1");
    assert.equal(ok[0].argumentCount, 1, "a context-only handler");
    assert.deepEqual(ok[0].arguments, [context]);
    let thrown = null;
    const lines = await frames(async () => {
      try {
        await fixture.schedFailV1.run(context);
      } catch (error) {
        thrown = error;
      }
    });
    assert.match(thrown.message, /deliberate failure/);
    assert.equal(lines[0].failing, true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
