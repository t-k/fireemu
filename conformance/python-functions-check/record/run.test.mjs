// The orchestrator against the in-memory world: the clean run, what stops it before anything is created, every
// unknown answer, and the cleanup's rules (only issued names, leftovers once, nothing re-sent, every name read back).
import assert from "node:assert/strict";
import test from "node:test";
import {
  ALL_FUNCTIONS,
  JOB_IDS,
  QUEUE_IDS,
  TOPIC,
  functionName,
  jobName,
  packageIds,
  queueName,
} from "./plan.mjs";
import { MAX_REQUESTS, absent, iamChanges, isBusy, record } from "./run.mjs";
import { NUMBER, createWorld, reply } from "./world.mjs";

const RUN = "0123456789abcdef";
const error = (code, status, message = "x") => reply(code, { error: { code, message, status } });

async function go(worldOptions = {}, options = {}, wrapSend = (send) => send) {
  const world = createWorld({ runId: RUN, ...worldOptions });
  const journal = [];
  const sleeps = [];
  const result = await record({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "test-token-abcdefgh",
    save: async (row) => journal.push(row),
    send: wrapSend(world.send, world),
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
const mutations = (world) =>
  world.calls.filter(
    (c) => !c.startsWith("GET ") && !c.includes("entries:list") && !c.includes("getIamPolicy"),
  );
const count = (world, prefix) => world.calls.filter((c) => c.startsWith(prefix)).length;
const emptyWorld = (w) =>
  w.functions.size === 0 &&
  w.runServices.size === 0 &&
  w.jobs.size === 0 &&
  w.queues.size === 0 &&
  w.topics.size === 0 &&
  w.packages.size === 0 &&
  w.documents.size === 0 &&
  w.objects.size === 0 &&
  w.triggers.size === 0;

test("a clean run records, cleans up, reads every name back and may close", async () => {
  const { world, result, journal } = await go();
  assert.equal(result.outcome, "pycheck-recorded");
  assert.equal(result.closureReady, true);
  assert.equal(result.readBackRequired, false);
  assert.equal(result.unknown, 0);
  assert.deepEqual(world.cliRuns, ["dry-run", "deploy", "delete"]);
  assert.ok(emptyWorld(world), "nothing of the run is left");
  assert.equal(result.cleanup.verified, true);
  assert.equal(result.cleanup.listsEmpty, true);
  assert.equal(result.cleanup.functionsGone, true);
  assert.ok(Object.values(result.cleanup.readBack).every((v) => v === true));
  const labels = Object.keys(result.cleanup.readBack);
  for (const fn of ALL_FUNCTIONS) assert.ok(labels.includes("function-" + fn));
  for (const id of [...JOB_IDS, ...QUEUE_IDS]) assert.ok(labels.some((l) => l.endsWith(id)));
  for (const fn of ALL_FUNCTIONS)
    for (const id of packageIds(fn)) assert.ok(labels.includes("package-" + id));
  assert.deepEqual(result.judged.counts, {
    "as-expected": 14,
    differs: 0,
    observed: 1,
    "not-delivered": 0,
    "not-sent": 0,
  });
  assert.ok(result.attempted <= MAX_REQUESTS);
  assert.equal(
    journal.filter((r) => r.status >= 400 && r.status !== 404).length,
    0,
    "the world refused no request",
  );
  assert.equal(
    JSON.stringify(journal).includes("test-token-abcdefgh"),
    false,
    "the token is never journaled",
  );
});

test("a clean run writes only the run's own names, once each", async () => {
  const { world, journal } = await go();
  const own = [
    /^PUT pubsub\.googleapis\.com\/v1\/projects\/[^/]+\/topics\/pycheck-orders$/,
    /^DELETE pubsub\.googleapis\.com\/v1\/projects\/[^/]+\/topics\/pycheck-orders$/,
    /^POST firestore\.googleapis\.com\/v1\/projects\/[^/]+\/databases\/\(default\)\/documents\/pycheck-src$/,
    /^PATCH firestore\.googleapis\.com\/.*\/documents\/pycheck-src\/pcrun-0123456789abcdef-a$/,
    /^DELETE firestore\.googleapis\.com\/.*\/documents\/pycheck-src\/pcrun-0123456789abcdef-a$/,
    /^POST pubsub\.googleapis\.com\/v1\/projects\/[^/]+\/topics\/pycheck-orders:publish$/,
    /^POST storage\.googleapis\.com\/upload\/storage\/v1\/b\/[^/]+\/o$/,
    /^DELETE storage\.googleapis\.com\/storage\/v1\/b\/[^/]+\/o\/pycheck%2Fpcrun-0123456789abcdef-a\.json$/,
    /^DELETE storage\.googleapis\.com\/storage\/v1\/b\/gcf-v2-(uploads|sources)-[^/]+\/o\/[^/]+$/,
    /^POST eventarcpublishing\.googleapis\.com\/.*\/channels\/firebase:publishEvents$/,
    /^POST cloudscheduler\.googleapis\.com\/.*\/jobs\/firebase-schedule-(pcsch|pcschraw)-us-central1:run$/,
    /^POST cloudtasks\.googleapis\.com\/.*\/queues\/(pctask|pctaskraw)\/tasks$/,
    /^DELETE artifactregistry\.googleapis\.com\/.*\/packages\/fireemu--oracle--events__us--central1__pc[a-z]+(%2Fcache)?$/,
  ];
  for (const call of mutations(world))
    assert.ok(
      own.some((re) => re.test(call)),
      "unexpected write: " + call,
    );
  const ids = journal
    .filter(
      (r) =>
        r.state === "before-send" &&
        r.method !== "GET" &&
        !r.url.includes("entries:list") &&
        !r.url.includes("getIamPolicy"),
    )
    .map((r) => r.id);
  assert.equal(new Set(ids).size, ids.length, "no write is sent twice");
  // The Eventarc channel is the project's, not the run's: it is never deleted.
  assert.equal(count(world, "DELETE eventarc"), 0);
  assert.equal(world.channels.has("firebase"), true);
});

test("the CLI deletes the functions, jobs and queues; REST deletes only the images, the topic and the sources", async () => {
  const { world } = await go();
  assert.equal(count(world, "DELETE cloudfunctions"), 0);
  assert.equal(count(world, "DELETE cloudscheduler"), 0);
  assert.equal(count(world, "DELETE cloudtasks"), 0);
  assert.equal(count(world, "DELETE artifactregistry"), ALL_FUNCTIONS.length * 2);
});

test("paged lists change nothing", async () => {
  const { result } = await go({ listPageSize: 7, logPageSize: 4 });
  assert.equal(result.outcome, "pycheck-recorded");
  assert.equal(result.closureReady, true);
  const six = await go({ listPageSize: 1 });
  assert.equal(
    six.result.closureReady,
    false,
    "a list of more than five pages is not read to its end",
  );
  assert.ok(six.result.incompleteReads.some((r) => r.class === "more-than-five-pages"));
});

test("the task operations use the function's own URL and identity, read back first", async () => {
  const { world, journal } = await go();
  const tasks = journal.filter((r) => r.state === "before-send" && r.id === "op-task-pctask");
  assert.equal(tasks.length, 1);
  assert.equal(tasks[0].json.task.httpRequest.url, "https://pctask-abc-uc.a.run.app");
  assert.equal(
    tasks[0].json.task.httpRequest.oidcToken.serviceAccountEmail,
    "123456789012-compute@developer.gserviceaccount.com",
  );
  const readFirst = world.calls.findIndex(
    (c) => c.includes("/functions/pctask") && c.startsWith("GET"),
  );
  assert.ok(readFirst < world.calls.findIndex((c) => c.includes("/queues/pctask/tasks")));
});

test("a function whose address cannot be read gets no task, and the run says so", async () => {
  const { result, world } = await go({
    hooks: {
      "GET cloudfunctions.googleapis.com/v2/projects/fireemu-oracle-events/locations/us-central1/functions/pctask":
        () => reply(200, { name: functionName("pctask"), state: "ACTIVE", serviceConfig: {} }),
    },
  });
  assert.equal(result.operations["task-pctask"].sent, false);
  assert.match(result.operations["task-pctask"].why, /task-target:pctask/);
  assert.equal(count(world, "POST cloudtasks"), 1, "the other queue's task is still sent");
  assert.equal(result.judged.cases["tasks-request"].status, "as-expected");
});

// ---- before anything is created -----------------------------------------------------------------------

const noWrites = (world) => assert.deepEqual(mutations(world), []);
test("a missing required API stops before anything is created", async () => {
  const world = createWorld({ runId: RUN });
  world.services.delete("cloudtasks.googleapis.com");
  const result = await record({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "tok-abcdefgh",
    save: async () => {},
    send: world.send,
    runCli: world.runCli,
    clock: () => world.now,
    sleep: async (ms) => world.advance(ms),
  });
  assert.equal(result.stoppedBecause, "services");
  assert.deepEqual(result.servicesMissing, ["cloudtasks.googleapis.com"]);
  assert.deepEqual(world.cliRuns, []);
  noWrites(world);
});

for (const [what, seed] of [
  ["a job", (w) => w.jobs.set(JOB_IDS[0], { name: jobName(JOB_IDS[0]) })],
  ["a queue", (w) => w.queues.set(QUEUE_IDS[0], { name: queueName(QUEUE_IDS[0]) })],
  ["the topic", (w) => w.topics.add(TOPIC)],
  ["an image package", (w) => w.packages.add(packageIds("pcps")[0])],
  [
    "a function",
    (w) => w.functions.set(functionName("pcps"), { name: functionName("pcps"), state: "ACTIVE" }),
  ],
  ["an object", (w) => w.objects.set("pycheck/old.json", { name: "pycheck/old.json" })],
  ["a document", (w) => w.documents.set("old", { name: "x/old" })],
  ["a trigger", (w) => w.triggers.add("pcps-999")],
]) {
  test(`${what} that is already there stops the run before anything is created`, async () => {
    const world = createWorld({ runId: RUN });
    seed(world);
    const result = await record({
      runId: RUN,
      projectNumber: NUMBER,
      accessToken: "tok-abcdefgh",
      save: async () => {},
      send: world.send,
      runCli: world.runCli,
      clock: () => world.now,
      sleep: async (ms) => world.advance(ms),
    });
    assert.equal(result.stoppedBecause, "namespace");
    assert.equal(result.outcome, "pycheck-stopped-clean");
    assert.deepEqual(world.cliRuns, []);
    noWrites(world);
  });
}

test("other people's images, topics, jobs and the project's channel do not stop the run and are never touched", async () => {
  const world = createWorld({ runId: RUN, seedChannels: ["firebase", "other"] });
  world.packages.add("someone-else");
  world.topics.add("their-topic");
  world.jobs.set("their-job", { name: "x" });
  world.queues.set("their-queue", { name: "x" });
  const result = await record({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "tok-abcdefgh",
    save: async () => {},
    send: world.send,
    runCli: world.runCli,
    clock: () => world.now,
    sleep: async (ms) => world.advance(ms),
  });
  assert.equal(result.outcome, "pycheck-recorded");
  assert.ok(
    world.packages.has("someone-else") &&
      world.topics.has("their-topic") &&
      world.jobs.has("their-job") &&
      world.queues.has("their-queue"),
  );
  assert.deepEqual(result.inventory.before.channels, ["firebase", "other"]);
});

test("a wrong project identity stops the run before anything else is read", async () => {
  const { result, world } = await go({
    hooks: {
      "GET firebaserules.googleapis.com/v1/projects/fireemu-oracle-events/releases/cloud.firestore":
        () => reply(200, { name: "projects/other/releases/cloud.firestore" }),
    },
  });
  assert.equal(result.stoppedBecause, "identity");
  assert.equal(world.calls.length, 1);
});

test("a failed CLI dry run stops the run clean, with no topic and no deploy", async () => {
  const world = createWorld({ runId: RUN });
  const runCli = async ({ action }) => {
    world.cliRuns.push(action);
    return { action, exitCode: 1, timedOut: false, error: null, errored: 0 };
  };
  const result = await record({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "tok-abcdefgh",
    save: async () => {},
    send: world.send,
    runCli,
    clock: () => world.now,
    sleep: async (ms) => world.advance(ms),
  });
  assert.equal(result.outcome, "pycheck-stopped-clean");
  assert.deepEqual(world.cliRuns, ["dry-run"]);
  noWrites(world);
});

// ---- after the deploy ---------------------------------------------------------------------------------

test("a failed deploy is cleaned up: delete runs, the topic and the images go, and the run does not close", async () => {
  const { result, world } = await go({ failDeploy: true });
  assert.deepEqual(world.cliRuns, ["dry-run", "deploy", "delete"]);
  assert.equal(result.outcome, "pycheck-incomplete-clean");
  assert.equal(result.closureReady, false);
  assert.equal(result.cleanup.verified, true);
  assert.equal(world.topics.size, 0);
  assert.equal(count(world, "POST cloudtasks"), 0);
});

test("a leftover function is deleted once through REST after a fresh list shows it", async () => {
  const { result, world } = await go({ leaveOnDelete: ["pcps"] });
  assert.equal(result.outcome, "pycheck-recorded");
  assert.equal(count(world, "DELETE cloudfunctions"), 1);
  assert.ok(
    world.calls.includes("DELETE cloudfunctions.googleapis.com/v2/" + functionName("pcps")),
  );
  assert.equal(world.functions.size, 0);
});

test("a leftover function whose delete fails is not re-sent and the run needs recovery", async () => {
  const { result, world } = await go({
    leaveOnDelete: ["pcps"],
    hooks: {
      ["DELETE cloudfunctions.googleapis.com/v2/" + functionName("pcps")]: () =>
        error(500, "INTERNAL"),
    },
  });
  assert.equal(count(world, "DELETE cloudfunctions"), 1);
  assert.equal(result.outcome, "pycheck-needs-recovery");
  assert.equal(result.closureReady, false);
  assert.equal(result.cleanup.verified, false);
  assert.equal(result.readBackRequired, true);
  assert.equal(result.unknownMutations, 1);
});

test("a leftover job is deleted after the busy answer, and a leftover queue once", async () => {
  let busy = 0;
  const { result, world } = await go(
    { leaveOnDelete: ["job:" + JOB_IDS[0], "queue:pctask"] },
    {},
    (send) => async (request) => {
      if (request.method === "DELETE" && request.url.includes("/jobs/") && busy++ < 2)
        return reply(409, {
          error: { code: 409, status: "ABORTED", message: "sync mutate calls cannot be queued" },
        });
      return send(request);
    },
  );
  assert.equal(result.outcome, "pycheck-recorded");
  assert.equal(busy, 3, "the busy answer twice, then the delete");
  assert.equal(count(world, "DELETE cloudscheduler"), 1);
  assert.equal(count(world, "DELETE cloudtasks"), 1);
});

test("a package delete that fails leaves the run needing recovery with the package named", async () => {
  const id = packageIds("pcst")[0];
  const { result, world } = await go({
    hooks: {
      ["DELETE artifactregistry.googleapis.com/v1/projects/fireemu-oracle-events/locations/us-central1/repositories/gcf-artifacts/packages/" +
      id]: () => error(500, "INTERNAL"),
    },
  });
  assert.equal(result.outcome, "pycheck-needs-recovery");
  assert.equal(result.cleanup.readBack["package-" + id], false);
  assert.equal(world.packages.has(id), true);
  assert.equal(
    count(world, "DELETE artifactregistry"),
    ALL_FUNCTIONS.length * 2,
    "each image once",
  );
});

test("only the run's own images are deleted, and each once", async () => {
  const world = createWorld({ runId: RUN });
  world.packages.add("other-package");
  const result = await record({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "tok-abcdefgh",
    save: async () => {},
    send: world.send,
    runCli: world.runCli,
    clock: () => world.now,
    sleep: async (ms) => world.advance(ms),
  });
  assert.equal(result.cleanup.packagesDeleted.length, ALL_FUNCTIONS.length * 2);
  assert.equal(world.packages.has("other-package"), true);
  assert.ok(result.cleanup.listsEmpty);
});

// ---- unknown answers ----------------------------------------------------------------------------------

test("an unknown topic create is never re-sent and is not settled by a 404", async () => {
  const { result, world } = await go({
    hooks: {
      "PUT pubsub.googleapis.com/v1/projects/fireemu-oracle-events/topics/pycheck-orders": () =>
        "throw",
    },
  });
  assert.equal(count(world, "PUT pubsub"), 1);
  assert.equal(result.closureReady, false);
  assert.equal(result.readBackRequired, true);
  assert.equal(result.unconfirmedCreates.length, 1);
  assert.equal(result.unconfirmedCreates[0].label, "topic");
  assert.deepEqual(
    world.cliRuns,
    ["dry-run"],
    "no deploy without the topic, and nothing for the CLI to delete",
  );
  assert.notEqual(result.outcome, "pycheck-recorded");
});

test("an unknown topic create that a later own 2xx read shows is settled", async () => {
  const { result } = await go({}, {}, (send) => async (request) => {
    const answer = await send(request);
    if (request.method === "PUT" && request.url.includes("/topics/"))
      throw new Error("reset after the write");
    return answer;
  });
  assert.equal(result.cleanup.verified, true);
  assert.equal(result.unconfirmedCreates.length, 0, "the own 2xx read settles the create");
  assert.equal(result.unknownMutations, 1, "the unknown answer is still reported");
  assert.equal(
    result.closureReady,
    false,
    "an unknown answer is only closed by the later read-back",
  );
  assert.equal(result.readBackRequired, true);
  assert.equal(result.outcome, "pycheck-needs-review");
});

test("an unknown source create is never re-sent, stays unconfirmed, is still deleted, and blocks the close", async () => {
  const { result, world } = await go({}, {}, (send) => async (request) => {
    const answer = await send(request);
    if (request.method === "POST" && request.url.includes("/documents/pycheck-src?"))
      throw new Error("reset");
    return answer;
  });
  assert.equal(count(world, "POST firestore"), 1);
  assert.equal(result.closureReady, false);
  assert.equal(result.readBackRequired, true);
  assert.ok(result.unconfirmedCreates.some((c) => c.label === "document"));
  assert.equal(world.documents.size, 0, "the document is deleted in the cleanup");
  assert.equal(result.cleanup.verified, true);
});

test("an unknown answer to a source publish is never re-sent and blocks the close", async () => {
  const { result, world } = await go({}, {}, (send) => async (request) => {
    const answer = await send(request);
    if (request.url.endsWith(":publishEvents"))
      return reply(503, { error: { code: 503, status: "UNAVAILABLE", message: "x" } });
    return answer;
  });
  assert.equal(count(world, "POST eventarcpublishing"), 2, "the two events once each");
  assert.equal(result.unknownMutations, 2);
  assert.equal(result.closureReady, false);
  assert.equal(result.readBackRequired, true);
});

test("a create that was seen and then reads absent before any delete of ours is flagged, not settled", async () => {
  const { result } = await go({}, {}, (send) => async (request) => {
    // The topic's cleanup read says gone although the run never deleted it successfully.
    if (request.method === "DELETE" && request.url.endsWith("/topics/pycheck-orders"))
      return reply(500, { error: { code: 500, status: "INTERNAL", message: "x" } });
    return send(request);
  });
  assert.equal(result.closureReady, false);
  assert.equal(result.unknownMutations >= 1, true);
});

// ---- stops -------------------------------------------------------------------------------------------

test("a 401 stops the run where it is: the CLI delete runs and no further REST request is sent", async () => {
  let afterStop = 0;
  let stopped = false;
  const { result, world } = await go({}, {}, (send) => async (request) => {
    if (stopped) afterStop++;
    if (request.url.includes("/queues/pctask/tasks")) {
      stopped = true;
      return error(401, "UNAUTHENTICATED");
    }
    return send(request);
  });
  assert.equal(result.outcome, "pycheck-auth-stop");
  assert.equal(result.closureReady, false);
  assert.equal(result.readBackRequired, true);
  assert.equal(afterStop, 0);
  assert.deepEqual(world.cliRuns, ["dry-run", "deploy", "delete"]);
});

test("a 403 on a write stops the run, but a 403 on an observing read is data", async () => {
  const { result } = await go({}, {}, (send) => async (request) => {
    if (request.url.endsWith("/adminSdkConfig")) return error(403, "PERMISSION_DENIED");
    return send(request);
  });
  assert.equal(result.outcome, "pycheck-stopped-clean", "the bucket cannot be learned");
  assert.equal(result.stoppedBecause, "admin-sdk-config");
  const stop = await go(
    {},
    {},
    (send) => async (request) =>
      request.method === "POST" && request.url.includes(":run")
        ? error(403, "PERMISSION_DENIED")
        : send(request),
  );
  assert.equal(stop.result.outcome, "pycheck-auth-stop");
});

test("a stop signal ends the operations at the next request and the cleanup still runs", async () => {
  const signal = { aborted: false };
  const { result, world } = await go({}, { signal }, (send) => async (request) => {
    if (request.url.includes(":publish") && request.url.includes("pubsub")) signal.aborted = true;
    return send(request);
  });
  assert.equal(result.outcome, "pycheck-incomplete-clean");
  assert.equal(result.cleanup.verified, true);
  assert.equal(emptyWorld(world), true);
});

test("the normal request ceiling ends the operations and leaves room for the cleanup", async () => {
  const { result, world } = await go({}, { normalCeiling: 30 });
  assert.equal(result.outcome, "pycheck-incomplete-clean");
  assert.equal(result.cleanup.verified, true);
  assert.equal(emptyWorld(world), true);
  assert.ok(result.attempted <= MAX_REQUESTS);
});

test("deliveries that never arrive are reported, and do not block the close", async () => {
  const { result } = await go({ silent: ["pcsch", "pcschraw"] });
  assert.equal(result.outcome, "pycheck-recorded");
  assert.equal(result.judged.cases["scheduler-request"].status, "not-delivered");
  assert.equal(result.judged.complete, false);
});

test("the run waits for the deliveries up to the window and no longer once they are in", async () => {
  const quick = await go();
  const slow = await go({ silent: ["pcschraw"] });
  assert.ok(slow.sleeps.length > quick.sleeps.length);
  const total = (sleeps) => sleeps.reduce((a, b) => a + b, 0) / 1000;
  assert.ok(total(slow.sleeps) - total(quick.sleeps) >= 100, "the full window was waited");
});

test("the inventory records what the deploy left: the channel, the IAM changes and the services", async () => {
  const { result } = await go();
  assert.deepEqual(result.inventory.channelsAfter, ["firebase"]);
  assert.deepEqual(result.inventory.iam, { added: [], removed: [] });
  assert.deepEqual(result.inventory.services, { added: [], removed: [] });
});

// ---- small functions ----------------------------------------------------------------------------------

test("absent accepts only a readable 404 NOT_FOUND", () => {
  assert.equal(absent({ status: 404, json: { error: { status: "NOT_FOUND" } } }), true);
  assert.equal(
    absent({ status: 404, json: { error: { code: 404, errors: [{ reason: "notFound" }] } } }),
    true,
    "the Storage layout",
  );
  assert.equal(absent({ status: 404, json: { error: { code: 404 } } }), false);
  assert.equal(
    absent({
      status: 404,
      json: { error: { status: "PERMISSION_DENIED", errors: [{ reason: "notFound" }] } },
    }),
    false,
  );
  assert.equal(absent({ status: 404, json: null }), false);
  assert.equal(absent({ status: 404, json: { error: { status: "PERMISSION_DENIED" } } }), false);
  assert.equal(absent({ status: 403, json: { error: { status: "NOT_FOUND" } } }), false);
  assert.equal(absent({ status: 200, json: {} }), false);
  assert.equal(absent(null), false);
});

test("isBusy matches only the recorded 409", () => {
  const body = (status, message) => ({ status: 409, json: { error: { status, message } } });
  assert.equal(isBusy(body("ABORTED", "sync mutate calls cannot be queued")), true);
  assert.equal(isBusy(body("ABORTED", "other")), false);
  assert.equal(isBusy(body("ALREADY_EXISTS", "sync mutate calls cannot be queued")), false);
  assert.equal(
    isBusy({
      status: 500,
      json: { error: { status: "ABORTED", message: "sync mutate calls cannot be queued" } },
    }),
    false,
  );
});

test("iamChanges lists additions and removals, and nothing when a read failed", () => {
  const policy = (...pairs) => ({
    status: 200,
    json: { bindings: pairs.map(([role, member]) => ({ role, members: [member] })) },
  });
  assert.deepEqual(iamChanges(policy(["a", "x"], ["b", "y"]), policy(["b", "y"], ["c", "z"])), {
    added: ["c|z"],
    removed: ["a|x"],
  });
  assert.equal(iamChanges({ status: 403, json: {} }, policy()), null);
  assert.equal(iamChanges(policy(), null), null);
});

test("a default bucket that is not the project's own stops the run before anything is created", async () => {
  const { result, world } = await go(
    {},
    {},
    (send) => async (request) =>
      request.url.endsWith("/adminSdkConfig")
        ? reply(200, { projectId: "fireemu-oracle-events", storageBucket: "someone-elses-bucket" })
        : send(request),
  );
  assert.equal(result.stoppedBecause, "bucket-name");
  assert.deepEqual(world.cliRuns, []);
  noWrites(world);
});
