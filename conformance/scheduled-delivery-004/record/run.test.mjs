// The orchestrator against the in-memory world: the clean run, what stops it, every unknown answer, and the
// cleanup's rules (only issued names, leftovers once, nothing re-sent).
import assert from "node:assert/strict";
import test from "node:test";
import {
  ALL_FUNCTIONS,
  EXTRA_JOBS,
  FUNCTIONS,
  extraJobId,
  functionName,
  jobName,
  scheduleId,
} from "./plan.mjs";
import { createWorld, NUMBER, reply } from "./world.mjs";
import { isBusy, record } from "./run.mjs";

const RUN = "0123456789abcdef";
const SCHED = "cloudscheduler.googleapis.com";
const error = (code, status, message = "x") => reply(code, { error: { code, message, status } });
const busy = () =>
  reply(409, {
    error: {
      code: 409,
      message: "sync mutate calls cannot be queued",
      status: "ABORTED",
      details: [{ "@type": "type.googleapis.com/google.rpc.ResourceInfo", resourceName: "x" }],
    },
  });

async function go(worldOptions = {}, options = {}) {
  const world = createWorld(worldOptions);
  const journal = [];
  const sleeps = [];
  const result = await record({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "test-token",
    save: async (row) => journal.push(row),
    send: world.send,
    runCli: (o) => world.runCli(o),
    clock: () => world.now,
    sleep: async (ms) => {
      sleeps.push(ms);
      world.advance(ms);
    },
    ...options,
  });
  return { world, journal, sleeps, result };
}
const ids = (journal) => journal.filter((r) => r.state === "before-send").map((r) => r.id);
const sent = (world, prefix) => world.calls.filter((c) => c.startsWith(prefix));
const writes = (world) =>
  world.calls.filter(
    (c) => !c.startsWith("GET ") && !c.includes("entries:list") && !c.includes("getIamPolicy"),
  );

test("a clean run records, cleans up and may close", async () => {
  const { world, result, journal } = await go();
  assert.equal(result.outcome, "calendar-delivery-recorded");
  assert.equal(result.closureReady, true);
  assert.equal(result.readBackRequired, false);
  assert.equal(result.unknownMutations, 0);
  assert.deepEqual(result.incompleteReads, []);
  assert.deepEqual(
    world.cliRuns,
    ["dry-run", "deploy", "deploy", "deploy", "delete"],
    "the dry run, the first deploy, the two round deploys and the delete, each once",
  );
  assert.equal(result.cleanup.verified, true);
  assert.equal(result.passes.length, 2);
  assert.ok(result.passes.every((p) => p.complete && p.forced.length === 10));
  assert.equal(
    world.jobs.size +
      world.topics.size +
      world.subs.size +
      world.functionsV1.size +
      world.functionsV2.size +
      world.runServices.size,
    0,
  );
  assert.ok(result.frames.declNullV2 > 0 && result.frames.schedFailV1 > 0);
  assert.ok(result.pulledMessages > 0);
  assert.ok(result.schedulerEntries > 0);
  assert.equal(result.attempted <= 420, true);
  assert.equal(result.adminSdkConfig.status, 200);
  // The order: preflight reads, the dry run's result, the issued names, the deploy's result, then the writes.
  const states = journal.map((r) => r.id + ":" + r.state);
  const at = (needle) => states.findIndex((s) => s.startsWith(needle));
  assert.ok(
    at("identity") < at("cli-dry-run") &&
      at("cli-dry-run") < at("issue-function-declNullV2") &&
      at("issue-function-declNullV2") < at("cli-deploy"),
  );
  assert.ok(at("cli-deploy") < at("create-subscription-schedFailV1"));
  assert.ok(
    ids(journal).indexOf("create-subscription-schedFailV1") <
      ids(journal).indexOf("run-1-declNullV2-us-central1"),
  );
});

test("every name that is created is journaled as issued before the request that creates it", async () => {
  const { journal } = await go();
  const issued = journal.filter((r) => r.state === "issued");
  assert.equal(issued.filter((r) => r.kind === "function").length, 6);
  assert.equal(issued.filter((r) => r.kind === "job").length, 10);
  assert.equal(issued.filter((r) => r.kind === "topic").length, 2);
  assert.equal(issued.filter((r) => r.kind === "subscription").length, 2);
  for (const row of issued.filter((r) => r.transport === "rest")) {
    const issuedAt = journal.indexOf(row);
    const createdAt = journal.findIndex(
      (r, i) =>
        (i > issuedAt &&
          r.state === "before-send" &&
          (r.method === "PUT" || r.method === "POST") &&
          String(r.url).includes(row.name.split("/").at(-1))) ||
        r.json?.name === row.name,
    );
    assert.ok(createdAt > issuedAt, row.name);
  }
});

// ---- preflight stops before the CLI --------------------------------------------------------

for (const [label, worldSetup, because] of [
  [
    "a required service is not enabled",
    (w) => w.services.delete("compute.googleapis.com"),
    "services",
  ],
  [
    "a function of this name already exists",
    (w) =>
      w.functionsV2.set(functionName("declNullV2"), {
        name: functionName("declNullV2"),
        state: "ACTIVE",
      }),
    "namespace",
  ],
  ["a Scheduler job exists", (w) => w.jobs.set("other", { name: jobName("other") }), "namespace"],
  ["a Pub/Sub topic exists", (w) => w.topics.add("other"), "namespace"],
  [
    "a Cloud Run service of one of the names exists",
    (w) => w.runServices.add("declnullv2"),
    "namespace",
  ],
]) {
  test("preflight stops before any CLI action when " + label, async () => {
    const world = createWorld();
    worldSetup(world);
    const journal = [];
    const result = await record({
      runId: RUN,
      projectNumber: NUMBER,
      accessToken: "test-token",
      save: async (r) => journal.push(r),
      send: world.send,
      runCli: (o) => world.runCli(o),
      clock: () => world.now,
      sleep: async (ms) => world.advance(ms),
    });
    assert.equal(result.outcome, "calendar-delivery-stopped-clean");
    assert.equal(result.stoppedBecause, because);
    assert.deepEqual(world.cliRuns, []);
    assert.deepEqual(writes(world), []);
    assert.equal(result.closureReady, false);
  });
}

test("a project whose App Engine location is another region stops before any CLI action", async () => {
  for (const locationId of ["europe-west", "us-east1", "asia-northeast"]) {
    const { world, result } = await go({
      hooks: {
        "GET firebase.googleapis.com/v1beta1/projects/fireemu-oracle-sbx/adminSdkConfig":
          async () => reply(200, { projectId: "fireemu-oracle-sbx", locationId }),
      },
    });
    assert.equal(result.stoppedBecause, "app-engine-location", locationId);
    assert.deepEqual(world.cliRuns, []);
  }
  for (const locationId of ["us-central", "us-central1", undefined, ""]) {
    const { result } = await go({
      hooks: {
        "GET firebase.googleapis.com/v1beta1/projects/fireemu-oracle-sbx/adminSdkConfig":
          async () =>
            reply(200, {
              projectId: "fireemu-oracle-sbx",
              ...(locationId === undefined ? {} : { locationId }),
            }),
      },
    });
    assert.equal(result.outcome, "calendar-delivery-recorded", String(locationId));
  }
});

test("a function of one of the names in another region stops preflight, and one left there is not closed", async () => {
  const strayName = "projects/fireemu-oracle-sbx/locations/us-east1/functions/declNullV2";
  const before = createWorld();
  before.functionsV2.set(strayName, { name: strayName, state: "ACTIVE", environment: "GEN_2" });
  const journal = [];
  const stopped = await record({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "test-token",
    save: async (r) => journal.push(r),
    send: before.send,
    runCli: (o) => before.runCli(o),
    clock: () => before.now,
    sleep: async (ms) => before.advance(ms),
  });
  assert.equal(stopped.stoppedBecause, "namespace");
  assert.deepEqual(before.cliRuns, []);
  // Left behind by the deploy (not ours to delete): the run cleans what it owns and says it is not clean.
  const { result, world } = await go({
    hooks: {
      "DELETE cloudfunctions.googleapis.com/v2/projects/fireemu-oracle-sbx/locations/us-central1/functions/declNullV2":
        async () => undefined,
    },
  });
  assert.equal(result.cleanup.verified, true);
  const late = createWorld();
  const lateResult = await record({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "test-token",
    save: async () => {},
    send: late.send,
    runCli: async (o) => {
      const r = await late.runCli(o);
      if (o.action === "deploy")
        late.functionsV2.set(strayName, { name: strayName, state: "ACTIVE", environment: "GEN_2" });
      return r;
    },
    clock: () => late.now,
    sleep: async (ms) => late.advance(ms),
  });
  assert.equal(
    lateResult.cleanup.verified,
    false,
    "a function in another region is reported, not deleted",
  );
  assert.equal(lateResult.outcome, "calendar-delivery-needs-recovery");
  assert.equal(
    late.calls.some((c) => c.startsWith("DELETE cloudfunctions") && c.includes("us-east1")),
    false,
  );
  assert.ok(world);
});

test("a wrong identity or a list that cannot be read stops before any CLI action", async () => {
  const wrong = await go({
    hooks: {
      "GET firebaserules.googleapis.com/v1/projects/fireemu-oracle-sbx/releases/cloud.firestore":
        async () => reply(200, { name: "projects/other/releases/cloud.firestore" }),
    },
  });
  assert.equal(wrong.result.stoppedBecause, "identity");
  assert.deepEqual(wrong.world.cliRuns, []);
  const unreadable = await go({
    hooks: {
      "GET /v1/projects/fireemu-oracle-sbx/locations/us-central1/jobs": async () =>
        error(500, "INTERNAL"),
    },
  });
  assert.equal(unreadable.result.stoppedBecause, "lists");
  assert.deepEqual(unreadable.world.cliRuns, []);
});

test("a failed dry run stops clean: nothing was deployed, deleted or written", async () => {
  const { world, result } = await go(
    {},
    {
      runCli: async ({ action }) => ({
        action,
        exitCode: 1,
        timedOut: false,
        error: null,
        errored: null,
      }),
    },
  );
  assert.equal(result.outcome, "calendar-delivery-stopped-clean");
  assert.equal(result.stoppedBecause, "the CLI dry run failed");
  assert.deepEqual(world.cliRuns, [], "the injected CLI is the only one that ran");
  assert.deepEqual(writes(world), []);
});

test("a deploy that errored is read twice, then cleaned up with one CLI delete", async () => {
  const { world, result } = await go({ failDeploy: true });
  assert.deepEqual(world.cliRuns, ["dry-run", "deploy", "delete"]);
  assert.equal(result.passes.length, 0);
  assert.equal(result.outcome, "calendar-delivery-incomplete-clean");
  assert.equal(result.cleanup.verified, true);
  assert.equal(result.closureReady, false);
  assert.equal(
    sent(
      world,
      "GET cloudfunctions.googleapis.com/v1/projects/fireemu-oracle-sbx/locations/us-central1/functions",
    ).length >= 2,
    true,
  );
});

// ---- unknown answers and refused credentials ---------------------------------------------------

test("a forced run answered 503 is an unknown mutation: the run still cleans up and does not close", async () => {
  const { result, world } = await go({
    hooks: {
      ["POST " +
      "/v1/projects/fireemu-oracle-sbx/locations/us-central1/jobs/" +
      scheduleId("declNullV2") +
      ":run"]: async () => error(503, "UNAVAILABLE"),
    },
  });
  assert.ok(result.unknownMutations >= 1);
  assert.equal(result.readBackRequired, true);
  assert.equal(result.closureReady, false);
  assert.equal(result.cleanup.verified, true);
  assert.equal(world.jobs.size, 0);
});

test("a 401 anywhere stops the REST requests at once, and the one CLI delete still runs after a deploy", async () => {
  const { world, result } = await go({
    hooks: {
      ["POST /v1/projects/fireemu-oracle-sbx/locations/us-central1/jobs/" +
      scheduleId("schedRetryV2") +
      ":run"]: async () => error(401, "UNAUTHENTICATED"),
    },
  });
  assert.equal(result.outcome, "calendar-delivery-auth-stop");
  assert.equal(result.stage, "auth-stop");
  assert.equal(result.readBackRequired, true);
  assert.equal(result.closureReady, false);
  assert.deepEqual(
    world.cliRuns,
    ["dry-run", "deploy", "delete"],
    "the CLI has its own credential: the one delete runs, once, and is not retried",
  );
  assert.equal(
    world.calls.at(-1).includes(":run"),
    true,
    "nothing was sent after the refused request",
  );
});

test("a 403 on a write stops the run, and a 403 on the optional reads is data", async () => {
  const stopped = await go({
    hooks: {
      ["PUT /v1/projects/fireemu-oracle-sbx/subscriptions/fe-sd-" + RUN + "-pull-schedfailv1"]:
        async () => error(403, "PERMISSION_DENIED"),
    },
  });
  assert.equal(stopped.result.outcome, "calendar-delivery-auth-stop");
  const data = await go({
    hooks: {
      "GET appengine.googleapis.com/v1/apps/fireemu-oracle-sbx": async () =>
        error(403, "PERMISSION_DENIED"),
    },
  });
  assert.equal(data.result.appEngine.status, 403);
  assert.equal(data.result.outcome, "calendar-delivery-recorded");
  // The project's location is read by firebase-tools too: an unreadable adminSdkConfig is a stop, not "no location".
  const config = await go({
    hooks: {
      "GET firebase.googleapis.com/v1beta1/projects/fireemu-oracle-sbx/adminSdkConfig": async () =>
        error(403, "PERMISSION_DENIED"),
    },
  });
  assert.equal(config.result.stoppedBecause, "admin-sdk-config");
  assert.equal(config.result.adminSdkConfig.status, 403);
  assert.deepEqual(config.world.cliRuns, []);
});

// ---- cleanup -------------------------------------------------------------------------------------

test("a leftover function is deleted once through REST, case-exact, after a fresh complete list shows it", async () => {
  const { world, result } = await go({ leaveOnDelete: ["declNullV2", "schedFailV1"] });
  const deletes = world.calls.filter((c) => c.startsWith("DELETE cloudfunctions.googleapis.com"));
  assert.deepEqual(deletes, [
    "DELETE cloudfunctions.googleapis.com/v2/projects/fireemu-oracle-sbx/locations/us-central1/functions/declNullV2",
    "DELETE cloudfunctions.googleapis.com/v1/projects/fireemu-oracle-sbx/locations/us-central1/functions/schedFailV1",
  ]);
  assert.equal(result.cleanup.verified, true);
  assert.equal(result.outcome, "calendar-delivery-recorded");
});

test("a leftover that the REST delete cannot remove is not re-sent and leaves the run needing recovery", async () => {
  const { world, result } = await go({
    leaveOnDelete: ["schedFailV1"],
    hooks: {
      "DELETE cloudfunctions.googleapis.com/v1/projects/fireemu-oracle-sbx/locations/us-central1/functions/schedFailV1":
        async () => error(503, "UNAVAILABLE"),
    },
  });
  assert.equal(
    world.calls.filter((c) => c.startsWith("DELETE cloudfunctions.googleapis.com/v1")).length,
    1,
    "sent once",
  );
  assert.equal(result.cleanup.verified, false);
  assert.equal(result.outcome, "calendar-delivery-needs-recovery");
  assert.equal(result.closureReady, false);
  assert.ok(result.unknownMutations >= 1);
  assert.equal(
    world.calls.some((c) =>
      c.startsWith("DELETE pubsub.googleapis.com/v1/projects/fireemu-oracle-sbx/topics/"),
    ),
    false,
    "a v1 topic is not deleted while its function may still exist",
  );
});

test("a job DELETE answered with the recorded 409 is repeated after sixty seconds", async () => {
  let first = true;
  const { world, sleeps, result } = await go({
    leaveOnDelete: ALL_FUNCTIONS.slice(0, 0),
    hooks: {
      ["DELETE /v1/projects/fireemu-oracle-sbx/locations/us-central1/jobs/" +
      extraJobId(RUN, "count")]: async () => (first ? ((first = false), busy()) : undefined),
    },
  });
  assert.ok(sleeps.includes(60_000));
  assert.equal(
    world.calls.filter(
      (c) => c.endsWith("jobs/" + extraJobId(RUN, "count")) && c.startsWith("DELETE"),
    ).length,
    2,
  );
  assert.equal(result.cleanup.verified, true);
  const answer = (status, state, message) => ({
    status,
    json: { error: { code: status, status: state, message } },
  });
  assert.equal(isBusy(answer(409, "ABORTED", "sync mutate calls cannot be queued")), true);
  assert.equal(isBusy(answer(409, "ABORTED", "other")), false);
  assert.equal(isBusy(answer(409, "ALREADY_EXISTS", "sync mutate calls cannot be queued")), false);
  assert.equal(isBusy(answer(500, "ABORTED", "sync mutate calls cannot be queued")), false);
  assert.equal(isBusy(null), false);
});

test("a job DELETE with an unknown answer is not re-sent, and the direct read decides", async () => {
  const id = extraJobId(RUN, "double1");
  const { world, result } = await go({
    hooks: {
      ["DELETE /v1/projects/fireemu-oracle-sbx/locations/us-central1/jobs/" + id]: async () =>
        error(503, "UNAVAILABLE"),
    },
  });
  assert.equal(
    world.calls.filter((c) => c.startsWith("DELETE") && c.endsWith("jobs/" + id)).length,
    1,
  );
  assert.equal(result.cleanup.verified, false, "the job is still there");
  assert.equal(result.outcome, "calendar-delivery-needs-recovery");
  assert.equal(result.closureReady, false);
});

test("only issued names are ever deleted, and no DELETE precedes its function's CLI delete", async () => {
  const { world } = await go({ leaveOnDelete: ["schedRetryV1"] });
  const allowed = new Set([
    ...ALL_FUNCTIONS.map(scheduleId),
    ...EXTRA_JOBS.map((job) => extraJobId(RUN, job.key)),
    ...FUNCTIONS.v1.map((f) => "fe-sd-" + RUN + "-pull-" + f.toLowerCase()),
    ...ALL_FUNCTIONS,
  ]);
  for (const call of world.calls.filter((c) => c.startsWith("DELETE")))
    assert.ok(allowed.has(call.split("/").at(-1)), call);
  const cliDelete = world.calls.length; // the CLI is not a request; its position is checked through the topics
  assert.ok(cliDelete > 0);
  const topicDeleteAt = world.calls.findIndex(
    (c) => c.startsWith("DELETE pubsub.googleapis.com") && c.includes("/topics/"),
  );
  const functionDeleteAt = world.calls.findIndex((c) =>
    c.startsWith("DELETE cloudfunctions.googleapis.com"),
  );
  assert.ok(functionDeleteAt >= 0 && (topicDeleteAt < 0 || functionDeleteAt < topicDeleteAt));
});

test("the normal request ceiling ends the passes and the cleanup still runs beyond it", async () => {
  const { result, world } = await go({}, { normalCeiling: 90 });
  assert.equal(result.outcome, "calendar-delivery-incomplete-clean");
  assert.ok(result.stoppedBecause.includes("ceiling"));
  assert.equal(result.cleanup.verified, true);
  assert.ok(result.attempted > 90 && result.attempted <= 420);
  assert.equal(world.jobs.size, 0);
});

test("without an HTTP target on the deployed retry job no extra job is created", async () => {
  let reads = 0;
  const { world, result } = await go({
    hooks: {
      ["GET /v1/projects/fireemu-oracle-sbx/locations/us-central1/jobs/" +
      scheduleId("schedRetryV2")]: async () =>
        ++reads <= 2
          ? reply(200, {
              name: jobName(scheduleId("schedRetryV2")),
              state: "ENABLED",
              schedule: "every 5 minutes",
            })
          : undefined,
    },
  });
  assert.ok(result.extraJobs.skipped);
  assert.equal(
    world.calls.some(
      (c) =>
        c.startsWith(
          "POST cloudscheduler.googleapis.com/v1/projects/fireemu-oracle-sbx/locations/us-central1/jobs",
        ) && !c.includes(":"),
    ),
    false,
  );
  assert.equal(result.cleanup.verified, true);
});

test("the extra jobs copy the deployed retry job's target and differ only in the retry rule and the schedule", async () => {
  const { journal } = await go();
  const creates = journal.filter(
    (r) => r.state === "before-send" && r.id.startsWith("create-extra-"),
  );
  assert.equal(creates.length, 4);
  for (const row of creates) {
    assert.deepEqual(row.json.httpTarget, {
      uri: "https://schedretryv2-abc-uc.a.run.app",
      httpMethod: "POST",
      oidcToken: { serviceAccountEmail: NUMBER + "-compute@developer.gserviceaccount.com" },
    });
    assert.equal(row.json.schedule, "0 0 1 1 *");
  }
  assert.deepEqual(
    creates.map((r) => Object.keys(r.json.retryConfig)),
    [
      ["retryCount", "maxRetryDuration", "minBackoffDuration", "maxBackoffDuration"],
      ["retryCount", "minBackoffDuration", "maxBackoffDuration", "maxDoublings"],
      ["retryCount", "minBackoffDuration", "maxBackoffDuration", "maxDoublings"],
      ["retryCount", "minBackoffDuration", "maxBackoffDuration", "maxDoublings"],
    ],
  );
});

test("a forced-only or windowless configuration is still a clean run", async () => {
  const { result } = await go({}, { passes: 1, naturalWindowMs: 60_000 });
  assert.equal(result.passes.length, 1);
  assert.equal(result.outcome, "calendar-delivery-recorded");
  assert.ok(SCHED && FUNCTIONS);
});
