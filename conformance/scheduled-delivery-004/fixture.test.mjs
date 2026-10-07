// The delivery fixture, offline: the SDK's own discovery finds exactly the six functions, every one
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
  "schedFailV1",
  "schedRetryV1",
  "schedRetryV2",
  "declNullV2",
  "declOmitV2",
  "declTimeoutV2",
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

maybe("the SDK discovers exactly the six functions, all pinned to us-central1", () => {
  const dir = source();
  try {
    const manifest = discover(dir);
    const names = Object.keys(manifest.endpoints).toSorted();
    assert.deepEqual(names, EXPECTED);
    for (const [name, endpoint] of Object.entries(manifest.endpoints))
      assert.deepEqual(endpoint.region, ["us-central1"], name + " is pinned");
    for (const name of ["declNullV2", "declOmitV2", "declTimeoutV2", "schedRetryV2"])
      assert.equal(manifest.endpoints[name].platform, "gcfv2", name);
    for (const name of ["schedFailV1", "schedRetryV1"])
      assert.equal(manifest.endpoints[name].platform, "gcfv1", name);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

maybe("the declared schedules, time zones and retry options are what the packet says", () => {
  const dir = source();
  try {
    const e = discover(dir).endpoints;
    assert.equal(e.schedRetryV2.scheduleTrigger.schedule, "every 5 minutes");
    assert.equal(e.schedRetryV2.scheduleTrigger.timeZone, "Asia/Tokyo");
    assert.deepEqual(e.schedRetryV2.scheduleTrigger.retryConfig, {
      retryCount: 4,
      minBackoffSeconds: 4,
      maxBackoffSeconds: 50,
      maxDoublings: 2,
    });
    // the declaration functions: reset (null), omitted ({}), and a timeout of 540 s; none runs on its own schedule
    for (const name of ["declNullV2", "declOmitV2", "declTimeoutV2"])
      assert.equal(e[name].scheduleTrigger.schedule, "0 0 1 1 *", name);
    assert.deepEqual(e.declNullV2.scheduleTrigger.retryConfig, {
      retryCount: null,
      maxDoublings: null,
      maxRetrySeconds: null,
      minBackoffSeconds: null,
      maxBackoffSeconds: null,
    });
    assert.equal(
      e.declNullV2.scheduleTrigger.timeZone,
      null,
      "RESET_VALUE is null in the manifest",
    );
    assert.deepEqual(e.declOmitV2.scheduleTrigger.retryConfig, {});
    assert.ok(!("timeZone" in e.declOmitV2.scheduleTrigger));
    assert.deepEqual(e.declTimeoutV2.scheduleTrigger.retryConfig, {});
    assert.equal(e.declTimeoutV2.timeoutSeconds, 540);
    // Gen1: no failure policy on either, the probe's count of 1 on the Scheduler job
    assert.equal(e.schedFailV1.scheduleTrigger.schedule, "every 5 minutes");
    assert.ok(!e.schedFailV1.scheduleTrigger.timeZone);
    assert.ok(!e.schedRetryV1.failurePolicy && !e.schedFailV1.failurePolicy, "no failure policy");
    assert.equal(e.schedRetryV1.scheduleTrigger.schedule, "every 5 minutes");
    assert.deepEqual(e.schedRetryV1.scheduleTrigger.retryConfig, {
      retryCount: 1,
      maxBackoffDuration: null,
      maxDoublings: null,
      maxRetryDuration: null,
      minBackoffDuration: null,
    });
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
          "x-cloudscheduler-jobname": "firebase-schedule-declNullV2-us-central1",
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
      const out = await frames(() => fixture.declNullV2(req, res));
      assert.equal(out.length, 1);
      const [frame] = out;
      assert.equal(frame.handler, "declNullV2");
      assert.equal(frame.generation, 2);
      assert.equal(frame.request.method, "POST");
      assert.equal(
        frame.request.headers["x-cloudscheduler-jobname"],
        "firebase-schedule-declNullV2-us-central1",
      );
      assert.equal(
        frame.request.headers.authorization,
        "<credential, 25 chars>",
        "the credential is not printed",
      );
      assert.ok(!JSON.stringify(frame).includes("secret-token-value"));
      assert.equal(frame.event.jobName, "firebase-schedule-declNullV2-us-central1");
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

maybe(
  "the v1 handlers print the context and both throw; the declaration functions print the round",
  async () => {
    const dir = source();
    try {
      const fixture = createRequire(join(dir, "fixture/index.js"))("./index.js");
      const context = {
        eventId: "e1",
        timestamp: "2026-10-06T00:01:00Z",
        eventType: "google.pubsub.topic.publish",
        resource: {
          service: "pubsub.googleapis.com",
          name: "projects/p/topics/firebase-schedule-schedFailV1-us-central1",
        },
      };
      for (const name of ["schedFailV1", "schedRetryV1"]) {
        let thrown = null;
        const lines = await frames(async () => {
          try {
            await fixture[name].run(context);
          } catch (error) {
            thrown = error;
          }
        });
        assert.match(thrown.message, /deliberate failure/, name);
        assert.equal(lines[0].handler, name);
        assert.equal(lines[0].generation, 1);
        assert.equal(lines[0].failing, true);
        assert.equal(lines[0].argumentCount, 1, "a context-only handler");
        assert.deepEqual(lines[0].arguments, [context]);
        assert.equal(lines[0].context.eventId, "e1");
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  },
);

maybe("a declaration function prints one frame carrying the ROUND of its source", async () => {
  const dir = source();
  try {
    const fixture = createRequire(join(dir, "fixture/index.js"))("./index.js");
    const req = {
      method: "POST",
      headers: {
        "x-cloudscheduler-jobname": "j",
        "x-cloudscheduler-scheduletime": "2027-01-01T00:00:00Z",
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
    for (const name of ["declNullV2", "declOmitV2", "declTimeoutV2"]) {
      const out = await frames(() => fixture[name](req, res));
      assert.equal(out.length, 1, name);
      assert.equal(out[0].handler, name);
      assert.equal(out[0].round, 1);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
