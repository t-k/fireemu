// The third presend review's findings (r3 delta): a REST delete of a leftover function whose operation never reads
// done (or reads done with an error) is an unknown DELETE, sticky until the read-back, and a later 404 of the
// function settles nothing (M1-r3); a CLI deploy that fails cleanly can hide a create answered 5xx, which the CLI's
// debug output shows (S1-r3). Every case has a near miss that must still close.
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { runCli, unknownWrites } from "./deploy.mjs";
import { ALL_FUNCTIONS, FUNCTIONS, functionName, jobName, scheduleId, topicName } from "./plan.mjs";
import { readbackRun } from "./readback.mjs";
import { record } from "./run.mjs";
import { NUMBER, createWorld, reply } from "./world.mjs";

const RUN = "0123456789abcdef";
const SHORT = { passes: 1, naturalWindowMs: 60_000 };
const FN2 = functionName("declNullV2");
const DELETE_KEY = "DELETE cloudfunctions.googleapis.com/v2/" + FN2;
const OP = "projects/fireemu-oracle-sbx/locations/us-central1/operations/op-1";
const OP_KEY = "GET cloudfunctions.googleapis.com/v2/" + OP;

async function go(worldOptions = {}, options = {}, cli) {
  const world = createWorld(worldOptions);
  const journal = [];
  const result = await record({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "test-token",
    save: async (row) => journal.push(row),
    send: world.send,
    runCli: async (o) => (cli ? cli(o, world) : world.runCli(o)),
    clock: () => world.now,
    sleep: async (ms) => world.advance(ms),
    ...SHORT,
    ...options,
  });
  return { world, journal, result };
}
const labels = (list) => list.map((c) => c.label).toSorted();

// ---- M1-r3: a delete whose operation never reads done ---------------------------------------------------------

/** A world whose CLI delete leaves declNullV2 and whose REST DELETE of it answers `deleteAnswer`, removing it. */
const leftover = (deleteAnswer, operationAnswer) => ({
  leaveOnDelete: ["declNullV2"],
  hooks: {
    [DELETE_KEY]: async ({ w }) => {
      w.functionsV2.delete(FN2);
      w.runServices.delete("declnullv2");
      return deleteAnswer;
    },
    ...(operationAnswer ? { [OP_KEY]: operationAnswer } : {}),
  },
});
const pending = () => reply(200, { name: OP, done: false });
const stillRunning = (polls) => async () => (polls.push(1), reply(200, { name: OP, done: false }));

test("probe D: twelve polls of done:false and then the function reads absent is an unknown DELETE, not a close", async () => {
  const polls = [];
  const { result, world } = await go(leftover(pending(), stillRunning(polls)));
  assert.equal(polls.length, 12);
  assert.deepEqual(
    result.unknownMutationList.filter((u) => u.id === "leftover-delete-declNullV2"),
    [{ id: "leftover-delete-declNullV2", class: "operation-pending" }],
  );
  assert.equal(result.readBackRequired, true);
  assert.equal(result.closureReady, false);
  assert.equal(result.outcome, "calendar-delivery-needs-review");
  assert.equal(result.cleanup.verified, true, "the function did read absent");
  assert.deepEqual(result.unconfirmedCreates, [], "nothing else is open: the read-back closes it");
  const later = await readbackRun({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "test-token",
    save: async () => {},
    send: world.send,
    clock: () => world.now,
  });
  assert.equal(later.allAbsent, true, "the later read-back, all 404, settles it");
});

test("near miss: the third poll reads done:true, and the later 404 settles it", async () => {
  let n = 0;
  const { result } = await go(
    leftover(pending(), async () => reply(200, { name: OP, done: ++n >= 3 })),
  );
  assert.equal(n, 3, "polling stops at the first done");
  assert.equal(
    result.unknownMutationList.some((u) => u.id === "leftover-delete-declNullV2"),
    false,
  );
  assert.equal(result.closureReady, true);
  assert.equal(result.outcome, "calendar-delivery-recorded");
});

test("an operation done with an error is an unknown DELETE (operation-error)", async () => {
  const failed = async () =>
    reply(200, { name: OP, done: true, error: { code: 13, message: "internal" } });
  const { result } = await go(leftover(pending(), failed));
  assert.deepEqual(
    result.unknownMutationList.filter((u) => u.id === "leftover-delete-declNullV2"),
    [{ id: "leftover-delete-declNullV2", class: "operation-error" }],
  );
  assert.equal(result.closureReady, false);
  assert.equal(result.outcome, "calendar-delivery-needs-review");
});

test("operation reads that answer 503 never settle it, however many", async () => {
  const unavailable = async () =>
    reply(503, { error: { code: 503, message: "x", status: "UNAVAILABLE" } });
  const { result } = await go(leftover(pending(), unavailable));
  assert.deepEqual(
    result.unknownMutationList.filter((u) => u.id === "leftover-delete-declNullV2"),
    [{ id: "leftover-delete-declNullV2", class: "operation-pending" }],
  );
  assert.equal(result.closureReady, false);
});

test("a DELETE answer that is itself done settles it; one that is done with an error, or has no operation at all, does not", async () => {
  const settled = await go(leftover(reply(200, { name: OP, done: true })));
  assert.equal(settled.result.closureReady, true);
  const errored = await go(
    leftover(reply(200, { name: OP, done: true, error: { code: 9, message: "x" } })),
  );
  assert.deepEqual(
    errored.result.unknownMutationList.map((u) => u.class),
    ["operation-error"],
  );
  for (const bare of [reply(200, {}), reply(200, { done: false }), reply(200, { name: 5 })]) {
    const { result } = await go(leftover(bare));
    assert.deepEqual(
      result.unknownMutationList.map((u) => u.class),
      ["operation-pending"],
    );
    assert.equal(result.closureReady, false);
  }
});

test("a refused leftover DELETE (4xx) is neither unknown nor settled by the function reading absent", async () => {
  const { result } = await go(
    leftover(reply(400, { error: { code: 400, message: "x", status: "INVALID_ARGUMENT" } })),
  );
  assert.equal(
    result.unknownMutationList.some((u) => u.id === "leftover-delete-declNullV2"),
    false,
  );
});

test("a v1 leftover whose operation is a v1 operation is polled and judged the same way", async () => {
  const op = "operations/del-77";
  const polls = [];
  const world = {
    leaveOnDelete: ["schedFailV1"],
    v1Operations: true,
    hooks: {
      ["DELETE cloudfunctions.googleapis.com/v1/" + functionName("schedFailV1")]: async ({ w }) => {
        w.functionsV1.delete(functionName("schedFailV1"));
        return reply(200, { name: op, done: false });
      },
      ["GET cloudfunctions.googleapis.com/v1/" + op]: async () => (
        polls.push(1),
        reply(200, { name: op, done: false })
      ),
    },
  };
  const { result } = await go(world);
  assert.equal(polls.length, 12);
  assert.deepEqual(
    result.unknownMutationList.filter((u) => u.id === "leftover-delete-schedFailV1"),
    [{ id: "leftover-delete-schedFailV1", class: "operation-pending" }],
  );
});

// ---- S1-r3: a cleanly failed deploy can hide a create answered 5xx --------------------------------------------------

const line = (method, url, status) =>
  `[debug] [2026-10-06T00:00:00.000Z] <<< [apiv2][status] ${method} ${url} ${status}`;
const SCHED = "https://cloudscheduler.googleapis.com/v1/projects/p/locations/us-central1/jobs";
const GCF = "https://cloudfunctions.googleapis.com/v2/projects/p/locations/us-central1/functions";
const TOPIC = "https://pubsub.googleapis.com/v1/projects/p/topics/t";

test("unknownWrites reads writes to the three services answered 5xx, 3xx or below 200, and nothing else", () => {
  assert.deepEqual(unknownWrites(line("POST", SCHED, 500)), [
    { method: "POST", host: "cloudscheduler", status: 500 },
  ]);
  assert.deepEqual(
    unknownWrites(
      [line("PUT", TOPIC, 503), line("PATCH", GCF + "/f", 302), line("POST", GCF, 100)].join("\n"),
    ),
    [
      { method: "PUT", host: "pubsub", status: 503 },
      { method: "PATCH", host: "cloudfunctions", status: 302 },
      { method: "POST", host: "cloudfunctions", status: 100 },
    ],
  );
  assert.deepEqual(unknownWrites("<<< [apiv2][status] POST " + SCHED + " 502"), [
    { method: "POST", host: "cloudscheduler", status: 502 },
  ]);
  assert.deepEqual(unknownWrites(line("POST", SCHED, 500) + "   \n"), [
    { method: "POST", host: "cloudscheduler", status: 500 },
  ]);
});

test("near misses: answers that say what happened, reads, deletes, other services, and text that is not a status line", () => {
  const quiet = [
    line("POST", SCHED, 200),
    line("POST", SCHED, 409),
    line("POST", SCHED, 429),
    line("POST", SCHED, 404),
    line("POST", SCHED, 299),
    line("POST", SCHED, 400),
    line("GET", SCHED, 500),
    line("DELETE", SCHED + "/j", 500),
    line("POST", "https://cloudbuild.googleapis.com/v1/projects/p/builds", 500),
    line("POST", "https://storage.googleapis.com/upload", 503),
    line("POST", SCHED, 5000),
    "POST " + SCHED + " 500",
    ">>> [apiv2] POST " + SCHED + " 500",
    line("POST", SCHED, 500) + " retrying",
    line("POST", "http://cloudscheduler.googleapis.com/v1/jobs", 500),
  ].join("\n");
  assert.deepEqual(unknownWrites(quiet), []);
  assert.deepEqual(unknownWrites(""), []);
  assert.deepEqual(unknownWrites(undefined), []);
});

test("runCli reports the writes of its output that stay unknown, from the whole output and not only its tail", async () => {
  const dir = mkdtempSync(join(tmpdir(), "review4-"));
  try {
    const script = join(dir, "fake-firebase.mjs");
    writeFileSync(
      script,
      "console.log(" +
        JSON.stringify(line("POST", SCHED, 500)) +
        ");\nconsole.log('x'.repeat(100000));\nconsole.log('[t] 1 Functions Errored');\nprocess.exit(1);\n",
    );
    const result = await runCli({
      action: "deploy",
      plan: { args: [], cwd: dir, env: { PATH: dirname(process.execPath) } },
      firebaseJs: script,
      node: process.execPath,
      directory: join(dir, "out"),
      timeoutMs: 20_000,
    });
    assert.equal(result.errored, 1);
    assert.deepEqual(result.unknownWrites, [
      { method: "POST", host: "cloudscheduler", status: 500 },
    ]);
    const clean = await runCli({
      action: "delete",
      plan: { args: [], cwd: dir, env: { PATH: dirname(process.execPath) } },
      firebaseJs: script.replace("fake-firebase", "fake-firebase-clean"),
      node: process.execPath,
      directory: join(dir, "out2"),
      timeoutMs: 20_000,
    });
    assert.deepEqual(clean.unknownWrites, [], "an output with no such line has none");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

/** A CLI whose deploy fails cleanly (exit 1, one function errored), with the given unknown writes and names created. */
const failedDeploy =
  (writes, keep = () => {}) =>
  async (o, w) => {
    if (o.action !== "deploy") return w.runCli(o);
    await w.runCli(o);
    keep(w);
    return {
      action: "deploy",
      exitCode: 1,
      signal: null,
      timedOut: false,
      error: null,
      errored: 1,
      unknownWrites: writes,
      durationMs: 1,
    };
  };

test("a clean failure with a Scheduler create answered 500 leaves the jobs no own read showed unconfirmed", async () => {
  const { result } = await go(
    {},
    {},
    failedDeploy([{ method: "POST", host: "cloudscheduler", status: 500 }], (w) => w.jobs.clear()),
  );
  assert.deepEqual(
    labels(result.unconfirmedCreates),
    ALL_FUNCTIONS.map((fn) => "job-" + scheduleId(fn)).toSorted(),
  );
  assert.deepEqual(
    result.unconfirmedCreates.toSorted((a, b) => a.label.localeCompare(b.label)),
    ALL_FUNCTIONS.map((fn) => ({
      label: "job-" + scheduleId(fn),
      id: "cli-deploy",
      name: jobName(scheduleId(fn)),
      class: "cli-500",
    })).toSorted((a, b) => a.label.localeCompare(b.label)),
  );
  assert.equal(result.readBackRequired, true);
  assert.equal(result.closureReady, false);
  assert.equal(result.outcome, "calendar-delivery-needs-review");
});

test("the kind follows the service: Pub/Sub writes open the topics, Cloud Functions writes the functions", async () => {
  const topics = await go(
    {},
    {},
    failedDeploy([{ method: "PUT", host: "pubsub", status: 503 }], (w) => w.topics.clear()),
  );
  assert.deepEqual(
    topics.result.unconfirmedCreates.map((c) => [c.label, c.name, c.class]).toSorted(),
    FUNCTIONS.v1.map((fn) => ["topic-" + fn, topicName(scheduleId(fn)), "cli-503"]).toSorted(),
  );
  const functions = await go(
    {},
    {},
    failedDeploy([{ method: "POST", host: "cloudfunctions", status: 500 }], (w) => {
      w.functionsV1.clear();
      w.functionsV2.clear();
      w.runServices.clear();
    }),
  );
  assert.deepEqual(
    labels(functions.result.unconfirmedCreates),
    ALL_FUNCTIONS.map((fn) => "function-" + fn).toSorted(),
  );
});

test("near misses: names an own read showed, a failure without such a write, and a timeout (which has its own class)", async () => {
  const seen = await go(
    {},
    {},
    failedDeploy([{ method: "POST", host: "cloudscheduler", status: 500 }]),
  );
  assert.deepEqual(
    seen.result.unconfirmedCreates,
    [],
    "the retry succeeded: every job was read 200",
  );
  const none = await go(
    {},
    {},
    failedDeploy([], (w) => w.jobs.clear()),
  );
  assert.deepEqual(none.result.unconfirmedCreates, []);
  const timeout = await go({}, {}, async (o, w) => {
    const real = await failedDeploy(
      [{ method: "POST", host: "cloudscheduler", status: 500 }],
      (x) => x.jobs.clear(),
    )(o, w);
    return o.action === "deploy" ? { ...real, timedOut: true } : real;
  });
  assert.ok(timeout.result.unconfirmedCreates.every((c) => c.class === "cli-timeout"));
});

test("unknownWrites: the status boundaries are exact", () => {
  const flagged = (status) => unknownWrites(line("POST", SCHED, status)).length === 1;
  for (const status of [100, 199, 300, 301, 399, 500, 599])
    assert.equal(flagged(status), true, String(status));
  for (const status of [200, 201, 299, 400, 404, 499])
    assert.equal(flagged(status), false, String(status));
});
