// The real runner and its framed IPC: a scheduled invocation reaches the handler as the profile says. Strict: a Gen2
// function is called through its HTTP wrapper with the scheduler's headers and a Gen1 handler gets the Pub/Sub context
// recorded in production (run 156715222b86ea44, 2026-10-05). Emulator: the handler is called directly, unchanged.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { withTestWorld } from "../../npm/fireemu/testing.mjs";

const runner = fileURLToPath(new URL("./index.mjs", import.meta.url));
const frame = (value) => {
  const data = Buffer.from(JSON.stringify(value));
  return Buffer.concat([Buffer.from(`${data.length}\n`), data]);
};

// A Gen2 function shaped like the SDK's onSchedule: an HTTP wrapper that reads the scheduler headers, builds the event
// and answers 200 (500 when the handler throws), with the bare handler as `run`. A Gen1 handler takes (data, context).
const SOURCE = `
const { appendFileSync } = require("node:fs");
const { join } = require("node:path");
const log = (row) => appendFileSync(join(__dirname, "calls.jsonl"), JSON.stringify(row) + "\\n");
const v2 = (name, fail) => {
  const handler = async (event) => {
    log({ name, via: "handler", event, context: event.context ?? null });
    if (fail) throw new Error("deliberate");
  };
  const wrapper = async (req, res) => {
    const event = { jobName: req.header("X-CloudScheduler-JobName") || undefined, scheduleTime: req.header("X-CloudScheduler-ScheduleTime") };
    log({ name, via: "wrapper", method: req.method, headers: req.headers });
    try { await handler(event); res.status(200).send(); } catch { res.status(500).send(); }
  };
  wrapper.run = handler;
  wrapper.__endpoint = { platform: "gcfv2", scheduleTrigger: { schedule: "every 5 minutes" } };
  return wrapper;
};
exports.okV2 = v2("okV2", false);
exports.failV2 = v2("failV2", true);
const bare = async (event) => log({ name: "bareV2", via: "bare", event });
bare.run = bare;
bare.__endpoint = { platform: "gcfv2", scheduleTrigger: { schedule: "every 5 minutes" } };
exports.bareV2 = bare;
const v1 = async (data, context) => log({ name: "okV1", data, context });
v1.run = v1;
v1.__endpoint = { platform: "gcfv1", scheduleTrigger: { schedule: "every 1 minutes" } };
exports.okV1 = v1;
`;

async function start(t, profile) {
  const dir = await mkdtemp(join(tmpdir(), "fireemu-schedule-delivery-"));
  await writeFile(join(dir, "package.json"), JSON.stringify({ private: true, main: "index.cjs" }));
  await writeFile(join(dir, "index.cjs"), SOURCE);
  const child = spawn(process.execPath, [runner, "--source", dir], {
    env: { PATH: process.env.PATH, GCLOUD_PROJECT: "demo-app", FIREEMU_HTTP_PROFILE: profile },
    stdio: ["pipe", "pipe", "pipe"],
  });
  const frames = [];
  let buffer = Buffer.alloc(0);
  let stderr = "";
  let outcome;
  child.stdin.on("error", () => {});
  const exited = once(child, "exit").then(([code, signal]) => (outcome = { code, signal }));
  child.stderr.on("data", (chunk) => {
    if (stderr.length < 65536) stderr += chunk.toString();
  });
  child.stdout.on("data", (chunk) => {
    buffer = Buffer.concat([buffer, chunk]);
    for (;;) {
      const at = buffer.indexOf(10);
      if (at < 0) break;
      const n = Number(buffer.subarray(0, at).toString());
      if (buffer.length < at + 1 + n) break;
      frames.push(JSON.parse(buffer.subarray(at + 1, at + 1 + n).toString("utf8")));
      buffer = buffer.subarray(at + 1 + n);
    }
  });
  async function wait(predicate) {
    const until = Date.now() + 8000;
    while (Date.now() < until) {
      const found = predicate();
      if (found) return found;
      if (outcome) throw Error(`runner exited ${JSON.stringify(outcome)}: ${stderr.slice(-500)}`);
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
    throw Error("runner response timeout");
  }
  t.after(async () => {
    if (!outcome) {
      child.stdin.write(frame({ type: "shutdown" }));
      await Promise.race([exited, new Promise((resolve) => setTimeout(resolve, 3000).unref())]);
    }
    if (!outcome) child.kill("SIGKILL");
    await exited;
    child.stdin.destroy();
    child.stdout.destroy();
    child.stderr.destroy();
    await rm(dir, { recursive: true, force: true });
  });
  await wait(() => frames.find((x) => x.type === "hello"));
  let sequence = 0;
  return {
    async invoke(name, event, generation = 2) {
      const invocationId = `schedule-${++sequence}`;
      child.stdin.write(
        frame({ type: "invoke", invocationId, function: name, entryPoint: name, trigger: "schedule", event }),
      );
      return wait(() => frames.find((x) => x.type === "result" && x.invocationId === invocationId));
    },
    async calls() {
      try {
        return (await readFile(join(dir, "calls.jsonl"), "utf8")).trim().split("\n").filter(Boolean).map(JSON.parse);
      } catch (error) {
        if (error.code === "ENOENT") return [];
        throw error;
      }
    },
  };
}

const JOB = "projects/demo-app/locations/us-central1/jobs/firebase-schedule-okV2-us-central1";
const event = (jobName, id = "42-1") => ({
  specversion: "1.0",
  id,
  type: "google.cloud.scheduler.job.v1.executed",
  time: "2026-10-05T08:45:00Z",
  data: { jobName, scheduleTime: "2026-10-05T08:45:00Z" },
});

test("strict: a Gen2 function is called through its wrapper with the scheduler headers", async (t) => {
  const f = await start(t, "strict");
  const result = await f.invoke("okV2", event(JOB));
  assert.equal(result.ok, true);
  const calls = await f.calls();
  assert.deepEqual(calls.map((c) => c.via), ["wrapper", "handler"]);
  assert.equal(calls[0].method, "POST");
  assert.equal(calls[0].headers["x-cloudscheduler"], "true");
  assert.equal(calls[1].event.jobName, "firebase-schedule-okV2-us-central1");
  assert.equal(calls[1].event.scheduleTime, "2026-10-05T01:45:00-07:00");
});

test("strict: a function whose wrapper answers 500 is a failed invocation", async (t) => {
  const f = await start(t, "strict");
  const result = await f.invoke("failV2", event(JOB.replace("okV2", "failV2")));
  assert.equal(result.ok, false);
  assert.match(JSON.stringify(result), /answered 500/);
  assert.deepEqual((await f.calls()).map((c) => c.via), ["wrapper", "handler"]);
});

test("strict: a bare handler (its own wrapper) is called directly, as before", async (t) => {
  const f = await start(t, "strict");
  await f.invoke("bareV2", event(JOB.replace("okV2", "bareV2")));
  const calls = await f.calls();
  assert.deepEqual(calls.map((c) => c.via), ["bare"]);
  assert.equal(calls[0].event.jobName, JOB.replace("okV2", "bareV2"));
});

test("strict: a Gen1 handler gets the Pub/Sub context of the message the Scheduler published", async (t) => {
  const f = await start(t, "strict");
  await f.invoke("okV1", event(JOB.replace("okV2", "okV1"), "42-3"), 1);
  const [call] = await f.calls();
  assert.match(call.context.eventId, /^2\d{16}$/);
  assert.equal(call.context.resource.name, "projects/demo-app/topics/firebase-schedule-okV1-us-central1");
  assert.equal(call.context.resource.type, "type.googleapis.com/google.pubsub.v1.PubsubMessage");
  assert.equal(call.context.resource.service, "pubsub.googleapis.com");
  assert.equal(call.context.timestamp, "2026-10-05T08:45:00Z");
  assert.equal(call.context.eventType, "google.pubsub.topic.publish");
});

test("emulator: every scheduled invocation is unchanged (direct handler call, the job's resource name)", async (t) => {
  const f = await start(t, "emulator");
  await f.invoke("okV2", event(JOB));
  await f.invoke("okV1", event(JOB.replace("okV2", "okV1"), "42-3"), 1);
  const calls = await f.calls();
  assert.deepEqual(calls.map((c) => c.via ?? c.name), ["handler", "okV1"]);
  assert.equal(calls[0].event.jobName, JOB);
  assert.equal(calls[0].event.scheduleTime, "2026-10-05T08:45:00Z");
  assert.equal(calls[1].context.eventId, "42-3");
  assert.equal(calls[1].context.resource.name, JOB.replace("okV2", "okV1"));
  assert.equal(calls[1].context.resource.type, undefined);
});

test("strict world: scheduled wrappers and Gen1 contexts keep occurrence time under virtual Date", { skip: !process.env.FIREEMU_TEST_BINARY, timeout: 60_000 }, async (t) => {
  const source = await mkdtemp(join(tmpdir(), "fireemu-world-schedule-source-"));
  t.after(() => rm(source, { recursive: true, force: true }));
  await writeFile(join(source, "package.json"), JSON.stringify({ private: true, main: "index.cjs" }));
  await writeFile(join(source, "index.cjs"), `
    const handler = async event => {
      const now = new Date().toISOString();
      const response = await fetch('http://' + process.env.FIRESTORE_EMULATOR_HOST + '/v1/projects/' + process.env.GCLOUD_PROJECT + '/databases/(default)/documents/scheduled/gen2', {
        method: 'PATCH', headers: { authorization: 'Bearer owner', 'content-type': 'application/json' },
        body: JSON.stringify({ fields: { scheduleTime: { stringValue: event.scheduleTime }, via: { stringValue: event.via }, now: { stringValue: now } } }),
      });
      if (!response.ok) throw Error('local write failed: ' + response.status);
    };
    const schedule = async (req, res) => {
      await handler({ scheduleTime: req.header('x-cloudscheduler-scheduletime'), via: 'wrapper' });
      res.status(200).send();
    };
    schedule.run = handler;
    schedule.__endpoint = { platform: 'gcfv2', scheduleTrigger: { schedule: 'every 1 minutes' } };
    const gen1 = async (data, context) => {
      const now = new Date().toISOString();
      const response = await fetch('http://' + process.env.FIRESTORE_EMULATOR_HOST + '/v1/projects/' + process.env.GCLOUD_PROJECT + '/databases/(default)/documents/scheduled/gen1', {
        method: 'PATCH', headers: { authorization: 'Bearer owner', 'content-type': 'application/json' },
        body: JSON.stringify({ fields: { timestamp: { stringValue: context.timestamp }, now: { stringValue: now } } }),
      });
      if (!response.ok) throw Error('local write failed: ' + response.status);
    };
    gen1.run = gen1;
    gen1.__endpoint = { platform: 'gcfv1', scheduleTrigger: { schedule: 'every 1 minutes' } };
    module.exports = { schedule, gen1 };
  `);
  await withTestWorld({
    binaryPath: process.env.FIREEMU_TEST_BINARY,
    projectId: "demo-app", clockStart: "2026-10-05T08:44:00Z",
    functionsSource: source, services: ["functions", "pubsub", "firestore"],
    config: { schemaVersion: 1, profile: "strict", firestore: { edition: "standard", backend: "native" } },
    clock: { date: "virtual", timers: "real", tasks: "real" },
    env: { PATH: process.env.PATH, NODE_PATH: "", FIREEMU_RUNNER_NODE: runner },
  }, async world => {
    await world.clock.advance({ seconds: 90 });
    const deadline = Date.now() + 15_000;
    const documents = {};
    while (Date.now() < deadline) {
      for (const id of ["gen1", "gen2"]) {
        const reply = await fetch(`${world.endpoints.firestore.url}/v1/projects/${world.projectId}/databases/(default)/documents/scheduled/${id}`, { headers: { authorization: "Bearer owner" } });
        if (reply.status === 404) continue;
        assert.equal(reply.status, 200, await reply.clone().text());
        documents[id] = (await reply.json()).fields;
      }
      if (documents.gen1 && documents.gen2) break;
      await new Promise(resolve => setTimeout(resolve, 10));
    }
    assert.ok(documents.gen1 && documents.gen2, "both scheduled functions must finish");
    assert.equal(documents.gen2.via.stringValue, "wrapper");
    assert.equal(documents.gen2.scheduleTime.stringValue, "2026-10-05T01:45:00-07:00");
    assert.equal(documents.gen2.now.stringValue, "2026-10-05T08:45:30.000Z");
    assert.equal(documents.gen1.timestamp.stringValue, "2026-10-05T08:45:00Z");
    assert.equal(documents.gen1.now.stringValue, "2026-10-05T08:45:30.000Z");
  });
});

test("strict world: pinned Eventarc channel and operation times advance with the daemon clock even with native Date", { skip: !process.env.FIREEMU_TEST_BINARY, timeout: 60_000 }, async (t) => {
  const source = await mkdtemp(join(tmpdir(), "fireemu-world-eventarc-source-"));
  t.after(() => rm(source, { recursive: true, force: true }));
  await writeFile(join(source, "package.json"), JSON.stringify({ private: true, main: "index.cjs" }));
  await writeFile(join(source, "index.cjs"), SOURCE);
  await withTestWorld({
    binaryPath: process.env.FIREEMU_TEST_BINARY,
    projectId: "demo-app", clockStart: "2026-01-01T00:00:00Z",
    functionsSource: source, services: ["functions"],
    config: { schemaVersion: 1, profile: "strict" },
    clock: { date: "real", timers: "real", tasks: "real" },
    env: { PATH: process.env.PATH, NODE_PATH: "", FIREEMU_RUNNER_NODE: runner },
  }, async world => {
    const base = world.endpoints.eventarc.url;
    const parent = `projects/${world.projectId}/locations/us-central1`;
    const channel = `${parent}/channels/pinned`;
    const reply = await fetch(`${base}/v1/${parent}/channels?channelId=pinned`, {
      method: "POST", headers: { authorization: "Bearer ya29.test-only", "content-type": "application/json" },
      body: JSON.stringify({ name: channel }),
    });
    assert.equal(reply.status, 200);
    const operation = await reply.json();
    assert.equal(operation.metadata.createTime, "2026-01-01T00:00:00.000000000Z");
    assert.equal(operation.done, false);
    const headers = { authorization: "Bearer ya29.test-only" };
    assert.equal((await (await fetch(`${base}/v1/${operation.name}`, { headers })).json()).done, false);
    await new Promise(resolve => setTimeout(resolve, 5500));
    assert.equal((await (await fetch(`${base}/v1/${operation.name}`, { headers })).json()).done, false, "wall time cannot finish a pinned operation");
    await world.clock.advance({ seconds: 4 });
    assert.equal((await (await fetch(`${base}/v1/${operation.name}`, { headers })).json()).done, false);
    await world.clock.advance(1381);
    const done = await (await fetch(`${base}/v1/${operation.name}`, { headers })).json();
    assert.equal(done.done, true);
    assert.equal(done.metadata.endTime, "2026-01-01T00:00:05.381000000Z");
    assert.equal(done.response.createTime, "2025-12-31T23:59:59.994000000Z", "the recorded six-millisecond channel offset is preserved");
    const created = await (await fetch(`${base}/v1/${channel}`, { headers })).json();
    assert.equal(created.createTime, done.response.createTime);
    assert.equal(created.updateTime, "2026-01-01T00:00:05.401000000Z");
  });
});
