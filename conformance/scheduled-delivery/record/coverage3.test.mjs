// The third group of survivors, all of the orchestrator: how every kind of failure of a read is classified, which
// requests are marked as observations and as cleanup, the bounds of every loop, and the cleanup's settling reads.
import assert from "node:assert/strict";
import test from "node:test";
import { ALL_FUNCTIONS, functionName } from "./plan.mjs";
import { record } from "./run.mjs";
import { NUMBER, createWorld, reply } from "./world.mjs";

const RUN = "0123456789abcdef";
const P = "/v1/projects/fireemu-oracle-sbx";
const error = (code, status) => reply(code, { error: { code, message: "x", status } });
const JOBS = "cloudscheduler.googleapis.com" + P + "/locations/us-central1/jobs";
const PUBSUB = "pubsub.googleapis.com" + P;
const SHORT = { passes: 1, naturalWindowMs: 60_000 };
const FN = (v, name) =>
  `cloudfunctions.googleapis.com/${v}/projects/fireemu-oracle-sbx/locations/us-central1/functions/${name}`;
const LIST1 = "cloudfunctions.googleapis.com/v1/projects/fireemu-oracle-sbx/locations/-/functions";
const LIST2 = "cloudfunctions.googleapis.com/v2/projects/fireemu-oracle-sbx/locations/-/functions";
const LISTR = "run.googleapis.com/v2/projects/fireemu-oracle-sbx/locations/-/services";
const SUB = "fe-sd-" + RUN + "-pull-schedokv1";
const empty = (w) =>
  w.jobs.size +
    w.topics.size +
    w.subs.size +
    w.functionsV1.size +
    w.functionsV2.size +
    w.runServices.size ===
  0;

/** `last` is the id of the request being sent, for hooks that act on one phase of the run. */
async function go(worldOptions = {}, options = {}, setup = () => {}) {
  const world = createWorld(worldOptions);
  setup(world);
  const journal = [];
  const sleeps = [];
  const state = { last: "" };
  const result = await record({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "test-token",
    save: async (row) => {
      journal.push(row);
      if (row.state === "before-send") state.last = row.id;
    },
    send: world.send,
    runCli: (o) => world.runCli(o),
    clock: () => world.now,
    sleep: async (ms) => {
      sleeps.push(ms);
      world.advance(ms);
    },
    ...options,
  });
  return { world, journal, sleeps, result, state };
}
const ids = (journal) => journal.filter((r) => r.state === "before-send").map((r) => r.id);
const row = (journal, id) => journal.find((r) => r.state === "before-send" && r.id === id);
const count = (journal, re) => ids(journal).filter((id) => re.test(id)).length;

test("a clean run reports no cleanup flag in its summary, an empty IAM change and exact observation counts", async () => {
  const { result, journal } = await go();
  assert.equal("cleanupVerified" in result, false);
  assert.deepEqual(result.inventory, {
    artifactPackages: 0,
    iam: { added: [], removed: [] },
    services: { added: [], removed: [] },
  });
  assert.deepEqual(result.framesIgnored, { notFrame: 0, unparsed: 0, foreignOrigin: 0 });
  assert.equal(result.jobs.schedOkV2.target, "http");
  assert.equal(result.jobs.schedOkV1.target, "pubsub");
  assert.equal(
    row(journal, "inventory-packages").url,
    "https://artifactregistry.googleapis.com/v1/projects/fireemu-oracle-sbx/locations/us-central1/repositories/gcf-artifacts/packages?pageSize=100",
  );
  const acked = {};
  for (const ackRow of journal.filter((x) => x.state === "before-send" && x.id.startsWith("ack-")))
    acked[ackRow.id.split("-").at(-1)] =
      (acked[ackRow.id.split("-").at(-1)] ?? 0) + ackRow.json.ackIds.length;
  assert.deepEqual(result.pulled, acked);
  for (const pullRow of journal.filter(
    (x) => x.state === "before-send" && x.id.startsWith("pull-"),
  ))
    assert.deepEqual(pullRow.json, { maxMessages: 10, returnImmediately: true });
});

test("a request's timeout is thirty seconds for a forced run and fifteen for anything else", async () => {
  const { journal } = await go({}, SHORT);
  const timeouts = (re) =>
    new Set(
      journal.filter((r) => r.state === "before-send" && re.test(r.id)).map((r) => r.timeoutMs),
    );
  assert.deepEqual([...timeouts(/^run-1-/)], [30_000]);
  assert.deepEqual([...timeouts(/^pull-/)], [15_000]);
  assert.deepEqual([...timeouts(/^pause-/)], [15_000]);
  assert.deepEqual([...timeouts(/^readback-job-/)], [15_000]);
});

test("an ordinary read that answers 403 stops the run, and one that answers 400 is an incomplete read", async () => {
  const stop = await go(
    {
      hooks: {
        ["GET " + JOBS]: async ({ w }) =>
          w.cliRuns.includes("deploy") ? error(403, "PERMISSION_DENIED") : undefined,
      },
    },
    SHORT,
  );
  assert.equal(stop.result.outcome, "calendar-delivery-auth-stop");
  const bad = await go(
    {
      hooks: {
        ["GET " + JOBS]: async ({ w }) =>
          w.cliRuns.includes("deploy") && !w.cliRuns.includes("delete")
            ? error(400, "INVALID_ARGUMENT")
            : undefined,
      },
    },
    SHORT,
  );
  assert.ok(bad.result.incompleteReads.some((r) => r.id === "readback-jobs" && r.class === "4xx"));
  assert.equal(bad.result.closureReady, false);
});

test("a log read that answers 403 is data, and is left incomplete", async () => {
  const { result } = await go(
    {
      hooks: {
        "POST logging.googleapis.com/v2/entries:list": async () => error(403, "PERMISSION_DENIED"),
      },
    },
    SHORT,
  );
  assert.notEqual(result.outcome, "calendar-delivery-auth-stop");
  assert.ok(result.incompleteReads.some((r) => r.id === "logs-preflight-frames"));
  assert.equal(result.cleanup.verified, true);
  assert.equal(result.closureReady, false);
});

test("ignored log entries are added up over the polls", async () => {
  const origin = {
    logName: "projects/fireemu-oracle-sbx/logs/run.googleapis.com%2Fstdout",
    resource: {
      type: "cloud_run_revision",
      labels: { service_name: "schedokv2", location: "us-central1" },
    },
  };
  const { result } = await go({}, { passes: 1, naturalWindowMs: 120_000 }, (w) => {
    let n = 0;
    for (const at of [20_000, 90_000, 150_000]) {
      w.entries.push({
        insertId: "bad" + ++n,
        timestamp: new Date(w.now + at).toISOString(),
        ...origin,
        textPayload: "SCHED_DELIVERY_FRAME nope",
      });
    }
  });
  assert.equal(result.framesIgnored.unparsed >= 2 && result.framesIgnored.unparsed <= 3, true);
  assert.equal(result.framesIgnored.notFrame, 0);
});

test("a pull that is not a 200 delivers nothing even if its body carries messages, and nothing is acknowledged", async () => {
  const { result, journal } = await go(
    {
      hooks: {
        ["POST " + PUBSUB + "/subscriptions/" + SUB + ":pull"]: async () =>
          reply(404, { receivedMessages: [{ ackId: "a", message: { data: "eA==" } }] }),
      },
    },
    SHORT,
  );
  assert.equal(result.pulled.schedOkV1, undefined);
  assert.equal(
    ids(journal).some((id) => id.startsWith("ack-") && id.endsWith("schedOkV1")),
    false,
  );
});

test("a services read that is not a 200 stops, even if its body lists every service", async () => {
  const all = [
    "artifactregistry",
    "cloudbuild",
    "cloudfunctions",
    "cloudscheduler",
    "compute",
    "pubsub",
    "run",
  ].map((s) => ({ config: { name: s + ".googleapis.com" } }));
  const { result } = await go({
    hooks: {
      "GET serviceusage.googleapis.com/v1/projects/123456789012/services": async () =>
        reply(500, { services: all }),
    },
  });
  assert.equal(result.stoppedBecause, "services");
  assert.deepEqual(result.servicesMissing, []);
});

test("the App Engine location a project names is read as the Scheduler will, and one that is not us-central1 stops", async () => {
  const named = (locationId) => ({
    hooks: {
      "GET firebase.googleapis.com/v1beta1/projects/fireemu-oracle-sbx/adminSdkConfig": async () =>
        reply(200, { projectId: "x", locationId }),
    },
  });
  const one = await go(named("u"));
  assert.equal(one.result.stoppedBecause, "app-engine-location");
  assert.equal(one.result.appEngineLocation, "u1");
  assert.deepEqual(one.world.cliRuns, []);
  const west = await go(named("europe-west"));
  assert.equal(west.result.appEngineLocation, "europe-west1");
  assert.equal(west.result.stoppedBecause, "app-engine-location");
  const ok = await go(named("us-central"), SHORT);
  assert.equal(ok.result.appEngineLocation, "us-central1");
  assert.equal(ok.result.stoppedBecause, undefined);
  const full = await go(named("us-central1"), SHORT);
  assert.equal(full.result.appEngineLocation, "us-central1");
  assert.equal(full.result.stoppedBecause, undefined);
  const none = await go(named(""), SHORT);
  assert.equal(none.result.appEngineLocation, undefined);
  assert.equal(none.result.stoppedBecause, undefined);
});

test("each of the three readiness lists must be readable before preflight goes on", async () => {
  for (const list of [LIST1, LIST2, LISTR]) {
    const { result, world } = await go({
      hooks: { ["GET " + list]: async () => error(500, "INTERNAL") },
    });
    assert.equal(result.stoppedBecause, "lists", list);
    assert.deepEqual(world.cliRuns, [], list);
  }
  for (const list of [
    "GET " + JOBS,
    "GET " + PUBSUB + "/topics",
    "GET " + PUBSUB + "/subscriptions",
  ]) {
    const { result, world } = await go({ hooks: { [list]: async () => error(500, "INTERNAL") } });
    assert.equal(result.stoppedBecause, "lists", list);
    assert.deepEqual(world.cliRuns, [], list);
  }
});

test("a failed deploy is read exactly twice, with the poll interval between", async () => {
  const { journal, sleeps } = await go({ failDeploy: true });
  assert.deepEqual(
    ids(journal).filter((id) => id.startsWith("ready-")),
    [
      "ready-1-functions-v1",
      "ready-1-functions-v2",
      "ready-1-run-services",
      "ready-2-functions-v1",
      "ready-2-functions-v2",
      "ready-2-run-services",
    ],
  );
  assert.deepEqual(sleeps.slice(0, 1), [30_000]);
});

test("readiness needs all three lists in one poll, and gives up after forty", async () => {
  let failures = 0;
  const flaky = await go({
    hooks: {
      ["GET " + LIST1]: async ({ w }) =>
        w.cliRuns.includes("deploy") && !w.cliRuns.includes("delete") && ++failures <= 2
          ? error(500, "INTERNAL")
          : undefined,
    },
  });
  assert.equal(count(flaky.journal, /^ready-\d+-functions-v1$/), 3);
  assert.equal(flaky.sleeps.filter((ms) => ms === 30_000).length, 2);
  // An unreadable list is an open question (`incompleteReads`): the run cannot close, so it is not "recorded".
  assert.equal(flaky.result.outcome, "calendar-delivery-needs-review");
  assert.equal(flaky.result.closureReady, false);
  const never = await go({
    hooks: {
      ["GET " + LISTR]: async ({ w }) =>
        w.cliRuns.includes("deploy") && !w.cliRuns.includes("delete")
          ? error(500, "INTERNAL")
          : undefined,
    },
  });
  assert.equal(count(never.journal, /^ready-\d+-functions-v1$/), 40);
  assert.equal(never.sleeps.filter((ms) => ms === 30_000).length, 39);
  assert.deepEqual(never.result.passes, []);
  assert.equal(never.result.cleanup.verified, true);
});

test("a job readback that is not a 200 is not summarized, whatever its body", async () => {
  let n = 0;
  const { result } = await go(
    {
      hooks: {
        ["GET " + JOBS + "/firebase-schedule-schedOkV1-us-central1"]: async ({ w }) =>
          w.cliRuns.includes("deploy") && ++n === 1 ? error(404, "NOT_FOUND") : undefined,
      },
    },
    SHORT,
  );
  assert.equal(result.jobs.schedOkV1, undefined);
  assert.equal(result.jobs.schedFailV1.target, "pubsub");
});

test("a failed subscription create is settled by a read that may answer 403, and only a 200 counts it as created", async () => {
  const key = "PUT " + PUBSUB + "/subscriptions/" + SUB;
  const lost = await go({ hooks: { [key]: async () => error(503, "UNAVAILABLE") } }, SHORT);
  const settle = row(lost.journal, "settle-subscription-schedOkV1");
  assert.equal(settle.url, "https://" + PUBSUB + "/subscriptions/" + SUB);
  assert.equal(settle.method, "GET");
  const denied = await go(
    {
      hooks: {
        [key]: async () => error(503, "UNAVAILABLE"),
        ["GET " + PUBSUB + "/subscriptions/" + SUB]: async ({ w }) =>
          w.calls.filter((c) => c === "GET " + PUBSUB + "/subscriptions/" + SUB).length === 1
            ? error(403, "PERMISSION_DENIED")
            : undefined,
      },
    },
    SHORT,
  );
  assert.notEqual(denied.result.outcome, "calendar-delivery-auth-stop");
  const created = await go(
    {
      hooks: {
        [key]: async ({ w }) => {
          w.subs.set("projects/fireemu-oracle-sbx/subscriptions/" + SUB, {
            topic: "projects/fireemu-oracle-sbx/topics/firebase-schedule-schedOkV1-us-central1",
            queue: [],
          });
          return reply(201, {});
        },
      },
    },
    SHORT,
  );
  assert.equal(created.world.calls.includes("DELETE " + PUBSUB + "/subscriptions/" + SUB), true);
});

test("a failed extra job create is settled by a read that may answer 403", async () => {
  const post = "POST " + JOBS;
  const hooks = {
    [post]: async ({ body }) =>
      body.name.endsWith("-duration") ? error(503, "UNAVAILABLE") : undefined,
    ["GET " + JOBS + "/fe-sd-" + RUN + "-duration"]: async () => error(403, "PERMISSION_DENIED"),
  };
  const { result, journal } = await go({ hooks }, SHORT);
  const settle = row(journal, "settle-extra-duration");
  assert.equal(settle.url, "https://" + JOBS + "/fe-sd-" + RUN + "-duration");
  assert.notEqual(result.outcome, "calendar-delivery-auth-stop");
  assert.equal(ids(journal).filter((id) => id.startsWith("run-1-fe-sd-run-")).length, 3);
});

test("a forced run that was refused is recorded with its class and status", async () => {
  const { result } = await go(
    {
      hooks: {
        ["POST " + JOBS + "/firebase-schedule-schedOkV2-us-central1:run"]: async () =>
          error(400, "FAILED_PRECONDITION"),
      },
    },
    SHORT,
  );
  assert.deepEqual(result.passes[0].forced[0], {
    id: "firebase-schedule-schedOkV2-us-central1",
    class: "4xx",
    status: 400,
  });
});

// ---- the cleanup ----------------------------------------------------------------------------------

test("the cleanup waits for the project to be empty: six polls, then the leftovers, then four more", async () => {
  const stuck = await go({
    leaveOnDelete: ["schedOkV2"],
    hooks: {
      ["DELETE " + FN("v2", "schedOkV2")]: async () =>
        reply(200, { name: "projects/x/operations/y", done: true }),
    },
  });
  assert.equal(count(stuck.journal, /^cleanup-\d-functions-v2$/), 6);
  assert.equal(count(stuck.journal, /^after-leftovers-\d-functions-v2$/), 4);
  assert.equal(stuck.result.cleanup.verified, false);
  assert.equal(stuck.result.outcome, "calendar-delivery-needs-recovery");
});

test("a project list that cannot be read in full during cleanup deletes no leftover and keeps polling", async () => {
  for (const list of [LIST1, LIST2, LISTR]) {
    const half = await go({
      leaveOnDelete: ["schedOkV2"],
      hooks: {
        ["GET " + list]: async ({ w }) =>
          w.cliRuns.includes("delete") ? error(500, "INTERNAL") : undefined,
      },
    });
    assert.equal(
      half.world.calls.filter((c) => c.startsWith("DELETE cloudfunctions")).length,
      0,
      list,
    );
    assert.equal(count(half.journal, /^cleanup-\d-functions-v1$/), 6, list);
    assert.equal(half.result.cleanup.functionsGone, false, list);
  }
});

// The leftover's delete answers with an operation of a fixed name, so a hook can script what its reads say.
const OP = "projects/fireemu-oracle-sbx/locations/us-central1/operations/op-1";
const OPKEY = "GET cloudfunctions.googleapis.com/v2/" + OP;
const leftoverWith = (opAnswer) => ({
  leaveOnDelete: ["schedOkV2"],
  hooks: {
    ["DELETE " + FN("v2", "schedOkV2")]: async ({ w }) => {
      w.functionsV2.delete(functionName("schedOkV2"));
      w.runServices.delete("schedokv2");
      return reply(200, { name: OP, done: false });
    },
    [OPKEY]: opAnswer,
  },
});

test("a leftover's delete operation is polled until done, at most twelve times, at the right address", async () => {
  let seen = 0;
  const polled = await go(leftoverWith(async () => reply(200, { name: OP, done: ++seen >= 3 })));
  assert.equal(seen, 3);
  assert.equal(polled.sleeps.filter((ms) => ms === 10_000).length, 3);
  assert.equal(polled.result.cleanup.verified, true);
  const never = await go(leftoverWith(async () => reply(200, { name: OP, done: false })));
  const operations = ids(never.journal).filter((id) => id.startsWith("leftover-operation-"));
  assert.equal(operations.length, 12);
  assert.equal(operations[0], "leftover-operation-schedOkV2-1");
  assert.equal(operations.at(-1), "leftover-operation-schedOkV2-12");
  assert.equal(
    row(never.journal, operations[0]).url,
    "https://cloudfunctions.googleapis.com/v2/" + OP,
  );
  const notDone = await go(leftoverWith(async () => reply(200, { name: OP, done: "true" })));
  assert.equal(
    count(notDone.journal, /^leftover-operation-/),
    12,
    "only the boolean true ends the polling",
  );
  const v1 = await go({ leaveOnDelete: ["schedOkV1"], v1Operations: true });
  assert.ok(
    v1.world.calls.some((c) =>
      c.startsWith("GET cloudfunctions.googleapis.com/v1/operations/del-"),
    ),
  );
  assert.ok(
    !v1.world.calls.some((c) =>
      c.includes("/v2/projects/fireemu-oracle-sbx/locations/us-central1/operations/"),
    ),
  );
  const v2 = await go({ leaveOnDelete: ["schedOkV2"] });
  assert.ok(
    v2.world.calls.some((c) =>
      c.includes("/v2/projects/fireemu-oracle-sbx/locations/us-central1/operations/del-"),
    ),
  );
  assert.ok(!v2.world.calls.some((c) => c.includes("/v1/operations/")));
});

test("a leftover delete that returns no operation, a finished one or a refusal is not polled", async () => {
  const key = "DELETE " + FN("v2", "schedOkV2");
  const gone = (w) => {
    w.functionsV2.delete(functionName("schedOkV2"));
    w.runServices.delete("schedokv2");
  };
  for (const answer of [
    (w) => (gone(w), reply(200, {})),
    (w) => (gone(w), reply(200, { name: "projects/x/operations/y", done: true })),
    () => error(400, "INVALID_ARGUMENT"),
    () => reply(200, { name: 5 }),
  ]) {
    const { world } = await go({
      leaveOnDelete: ["schedOkV2"],
      hooks: { [key]: async ({ w }) => answer(w) },
    });
    assert.equal(world.calls.filter((c) => c.includes("/operations/")).length, 0);
  }
});

test("a leftover operation read that answers 403 is data", async () => {
  const { result, journal } = await go(leftoverWith(async () => error(403, "PERMISSION_DENIED")));
  assert.notEqual(result.outcome, "calendar-delivery-auth-stop");
  assert.equal(count(journal, /^leftover-operation-/), 12);
  assert.equal(result.cleanup.verified, true);
});

test("a job delete that is busy is tried four times with a minute between; any other refusal stops at one", async () => {
  const id = "fe-sd-" + RUN + "-count";
  const busy = () =>
    reply(409, {
      error: { code: 409, status: "ABORTED", message: "sync mutate calls cannot be queued" },
    });
  const four = await go({ hooks: { ["DELETE " + JOBS + "/" + id]: async () => busy() } });
  assert.equal(four.world.calls.filter((c) => c === "DELETE " + JOBS + "/" + id).length, 4);
  assert.deepEqual(
    ids(four.journal).filter((i) => i.startsWith("delete-job-") && i.endsWith("count")),
    [
      "delete-job-0-fe-sd-run-count",
      "delete-job-1-fe-sd-run-count",
      "delete-job-2-fe-sd-run-count",
      "delete-job-3-fe-sd-run-count",
    ],
  );
  assert.equal(four.sleeps.filter((ms) => ms === 60_000).length >= 4 + 4, true);
  assert.equal(four.result.cleanup.verified, false);
  const one = await go({
    hooks: { ["DELETE " + JOBS + "/" + id]: async () => error(400, "INVALID_ARGUMENT") },
  });
  assert.equal(one.world.calls.filter((c) => c === "DELETE " + JOBS + "/" + id).length, 1);
  let busyOnce = true;
  const second = await go({
    hooks: {
      ["DELETE " + JOBS + "/" + id]: async () =>
        busyOnce ? ((busyOnce = false), busy()) : undefined,
    },
  });
  assert.equal(second.world.calls.filter((c) => c === "DELETE " + JOBS + "/" + id).length, 2);
  assert.equal(second.result.cleanup.verified, true);
});

test("a v1 topic that is still there once its function is gone is deleted, and one that is not is left alone", async () => {
  const topic = "firebase-schedule-schedOkV1-us-central1";
  const { world, journal, result } = await go({}, SHORT, () => {});
  assert.equal(
    ids(journal).some((id) => id.startsWith("delete-topic-")),
    false,
  );
  assert.equal(world.calls.includes("DELETE " + PUBSUB + "/topics/" + topic), false);
  const w2 = createWorld();
  const journal2 = [];
  const result2 = await record({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "test-token",
    save: async (r) => journal2.push(r),
    send: w2.send,
    runCli: async (o) => {
      const r = await w2.runCli(o);
      if (o.action === "delete") w2.topics.add(topic);
      return r;
    },
    clock: () => w2.now,
    sleep: async (ms) => w2.advance(ms),
    ...SHORT,
  });
  assert.ok(ids(journal2).includes("delete-topic-schedOkV1"));
  assert.ok(row(journal2, "delete-topic-schedOkV1").url.endsWith("/topics/" + topic));
  assert.equal(result2.cleanup.verified, true);
  assert.equal(result.cleanup.verified, true);
  assert.equal(empty(w2), true);
});

test("the final lists must all be read in full, each separately", async () => {
  for (const [label, key] of [
    ["final-jobs", "GET " + JOBS],
    ["final-topics", "GET " + PUBSUB + "/topics"],
    ["final-subscriptions", "GET " + PUBSUB + "/subscriptions"],
    ["final-functions-v1", "GET " + LIST1],
    ["final-functions-v2", "GET " + LIST2],
    ["final-run-services", "GET " + LISTR],
  ]) {
    const seen = { last: "" };
    const { result } = await go(
      {
        hooks: {
          [key]: async () => (seen.last.startsWith(label) ? error(500, "INTERNAL") : undefined),
        },
      },
      {
        save: async (r) => {
          if (r.state === "before-send") seen.last = r.id;
        },
      },
    );
    assert.equal(result.cleanup.listsEmpty, false, label);
    assert.equal(result.cleanup.verified, false, label);
  }
});

test("the inventory counts the packages it reads, and keeps a refused status as the number it was", async () => {
  const key =
    "GET artifactregistry.googleapis.com/v1/projects/fireemu-oracle-sbx/locations/us-central1/repositories/gcf-artifacts/packages";
  const two = await go({ hooks: { [key]: async () => reply(200, { packages: [{}, {}] }) } });
  assert.equal(two.result.inventory.artifactPackages, 2);
  const none = await go({ hooks: { [key]: async () => reply(200, {}) } });
  assert.equal(none.result.inventory.artifactPackages, 0);
  const odd = await go({ hooks: { [key]: async () => reply(201, { packages: [{}] }) } });
  assert.equal(odd.result.inventory.artifactPackages, 201);
});

// ---- what stops a run, and what it leaves ---------------------------------------------------------

test("a budget stop before anything was created is a clean stop, and a thrown error then is thrown", async () => {
  const early = await go({}, { normalCeiling: 5 });
  assert.equal(early.result.stoppedBecause, "the normal request ceiling is reached");
  assert.deepEqual(early.world.cliRuns, []);
  const world = createWorld();
  await assert.rejects(
    () =>
      record({
        runId: RUN,
        projectNumber: NUMBER,
        accessToken: "test-token",
        save: async () => {
          throw new Error("disk");
        },
        send: world.send,
        runCli: (o) => world.runCli(o),
        clock: () => world.now,
        sleep: async () => {},
      }),
    /private persistence failed/,
  );
});

test("an error after something was created is recorded, the cleanup still runs, and the run is not complete", async () => {
  const world = createWorld();
  let failed = false;
  const result = await record({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "test-token",
    save: async (r) => {
      if (!failed && r.state === "before-send" && r.id === "readback-jobs") {
        failed = true;
        throw new Error("disk");
      }
    },
    send: world.send,
    runCli: (o) => world.runCli(o),
    clock: () => world.now,
    sleep: async (ms) => world.advance(ms),
    ...SHORT,
  });
  assert.equal(result.stoppedBecause, "private persistence failed before dispatch");
  assert.equal(result.cleanup.verified, true);
  assert.equal(result.outcome, "calendar-delivery-incomplete-clean");
  assert.equal(result.closureReady, false);
  assert.ok(empty(world));
});

test("a credential stop in the cleanup is an auth stop that never closes", async () => {
  const { result } = await go({
    hooks: {
      ["GET " + PUBSUB + "/topics"]: async ({ w }) =>
        w.cliRuns.includes("delete") ? error(401, "UNAUTHENTICATED") : undefined,
    },
  });
  assert.equal(result.outcome, "calendar-delivery-auth-stop");
  assert.equal(result.stage, "auth-stop");
  assert.equal(result.closureReady, false);
  assert.equal(result.readBackRequired, true);
});

test("every deployed function is read back at its own version", async () => {
  const { journal } = await go({}, SHORT);
  for (const fn of ALL_FUNCTIONS) {
    const version = fn.endsWith("V1") ? "v1" : "v2";
    assert.equal(
      row(journal, "readback-function-" + fn).url,
      `https://cloudfunctions.googleapis.com/${version}/${functionName(fn)}`,
    );
  }
});

test("the last poll of an observation window is as short as the window's remainder", async () => {
  const { sleeps } = await go({}, { passes: 1, naturalWindowMs: 90_000 });
  const start = sleeps.indexOf(60_000, sleeps.indexOf(3000));
  assert.deepEqual(sleeps.slice(start - 0, start + 2), [60_000, 30_000]);
});

test("while one of the readiness lists cannot be read the run is not ready and records no readiness summary", async () => {
  const never = await go({
    hooks: {
      ["GET " + LIST1]: async ({ w }) =>
        w.cliRuns.includes("deploy") && !w.cliRuns.includes("delete")
          ? error(500, "INTERNAL")
          : undefined,
    },
  });
  assert.equal(never.result.ready, null);
  assert.deepEqual(never.result.passes, []);
});
