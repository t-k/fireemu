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
