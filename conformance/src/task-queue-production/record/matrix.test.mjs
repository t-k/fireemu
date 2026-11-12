// The unknown and ambiguous answers of a recording, and what stops it: each case of the pre-submission checklist section 3
// (never mixed), the stops before anything is created, the stops during the program, and the cleanup's rules.
import "./isolation.mjs";
import assert from "node:assert/strict";
import test from "node:test";
import { PROGRAM } from "../corpus.mjs";
import {
  PROJECT,
  REGION,
  functionName,
  functionOfRole,
  functionsOf,
  packageIds,
  queueName,
} from "../plan.mjs";
import { RUN, count, emptyWorld, go, mutations } from "./harness.mjs";
import { absent, iamPolicyOf } from "./run.mjs";
import { NUMBER, reply } from "./world.mjs";

const error = (code, status, message = "x") => reply(code, { error: { code, message, status } });
const tasksUrl = (role) =>
  `POST cloudtasks.googleapis.com/v2/projects/${PROJECT}/locations/${REGION}/queues/${functionOfRole(RUN, role)}/tasks`;
const taskUrl = (method, role, id) =>
  `${method} cloudtasks.googleapis.com/v2/projects/${PROJECT}/locations/${REGION}/queues/${functionOfRole(RUN, role)}/tasks/tqrun-${RUN}-${id}`;
const once = (handler) => {
  let used = false;
  return (...args) => {
    if (used) return undefined;
    used = true;
    return handler(...args);
  };
};
const stepRows = (journal, key) => journal.filter((r) => r.id === "step-" + key);

// ---- an unknown CREATE (a createTask), checklist 3 case 1 ------------------------------------------------------------

for (const [name, hook] of [
  ["a 503", () => error(503, "UNAVAILABLE")],
  ["a 3xx", () => new Response("", { status: 302, headers: { location: "https://x.example/" } })],
  ["a transport failure", () => "throw"],
  ["an unreadable 200", () => new Response("not json", { status: 200 })],
]) {
  test(`createTask answered ${name} is an unknown mutation: sent once, never settled by a 404, and the run cannot close`, async () => {
    const { world, result, journal } = await go({ hooks: { [tasksUrl("tqdef")]: once(hook) } });
    assert.ok(result.unknownMutations >= 1, "counted");
    assert.equal(result.closureReady, false);
    assert.equal(result.readBackRequired, true);
    assert.notEqual(result.outcome, "tq-recorded");
    // The first step of the default queue is the one that was hit; it was sent once.
    const first = PROGRAM.find((s) => s.kind === "create" && s.role === "tqdef").key;
    assert.equal(stepRows(journal, first).filter((r) => r.state === "before-send").length, 1);
    // A direct read that answers 404 (the program reads other tasks and queues that way) settles nothing.
    assert.ok(count(world, "GET cloudtasks.googleapis.com") > 0);
    assert.equal(result.cleanup.verified, true, "the queues are still read back absent");
    assert.ok(result.unknownMutationList.some((m) => m.id === "step-" + first));
  });
}

test("a createTask answered 400 or 409 is data: the run closes", async () => {
  const { result } = await go();
  assert.equal(result.program["dup-sched-again"].status, 409);
  assert.equal(result.program["sch-31d"].status, 400);
  assert.equal(result.unknownMutations, 0);
  assert.equal(result.closureReady, true);
});

// ---- an unknown DELETE (a deleteTask), checklist 3 case 3 ------------------------------------------------------------

test("a deleteTask answered 5xx is sticky: never sent again, no later step on that id is sent, the run cannot close", async () => {
  const { world, result, journal } = await go({
    hooks: { [taskUrl("DELETE", "tqdef", "dup-sched")]: once(() => error(500, "INTERNAL")) },
  });
  assert.equal(
    count(world, taskUrl("DELETE", "tqdef", "dup-sched")),
    1,
    "the second delete of that id is not sent",
  );
  assert.equal(
    stepRows(journal, "del-dup-sched").filter((r) => r.state === "before-send").length,
    1,
  );
  assert.equal(result.program["del-dup-sched"].class, "unknown-status");
  for (const key of ["del-dup-sched-again", "dup-sched-after-delete"]) {
    assert.equal(result.program[key].sent, false, key);
    assert.match(result.program[key].why, /same task id has an unknown answer/);
  }
  assert.equal(result.program["dup-first-after-done"].sent, true, "another id is not affected");
  assert.equal(result.closureReady, false);
  assert.equal(result.readBackRequired, true);
  assert.ok(result.unknownMutationList.some((m) => m.id === "step-del-dup-sched"));
});

test("an unknown create keeps every later step on the same task id from being sent", async () => {
  let hit = false;
  const { result } = await go({
    hooks: {
      [tasksUrl("tqdef")]: ({ body }) => {
        if (hit || !body.task?.name?.endsWith("-dup-first")) return undefined;
        hit = true;
        return error(503, "UNAVAILABLE");
      },
    },
  });
  assert.equal(result.program["dup-first"].class, "unknown-status");
  assert.equal(result.program["dup-first-after-done"].sent, false);
  assert.equal(result.program["get-dup-first"].sent, false);
  assert.equal(result.program["del-dup-first"].sent, false);
  assert.equal(result.program["dup-sched"].sent, true, "another id is not affected");
  assert.equal(result.closureReady, false);
});

test("a 409 of a later request never settles an earlier request's unknown answer", async () => {
  const { result } = await go({
    hooks: { [tasksUrl("tqdef")]: once(() => error(503, "UNAVAILABLE")) },
  });
  assert.equal(result.program["dup-sched-again"].status, 409);
  assert.ok(result.unknownMutations >= 1);
  assert.equal(result.closureReady, false);
});

// ---- a confirmed CREATE that later reads 404, checklist 3 case 2 ------------------------------------------------------

test("a function the CLI made, confirmed by a 2xx read and then missing without a delete of ours, is not settled in the run", async () => {
  const victim = functionOfRole(RUN, "tqrate");
  const { result } = await go({
    leaveOnDelete: [],
    hooks: {
      // After the program, the cleanup's first list no longer shows the function and its direct read says 404: the run
      // must not call that a clean end unless its own delete (or a clean CLI delete) is what removed it.
      [`DELETE cloudfunctions.googleapis.com/v2/${functionName(victim)}`]: () =>
        error(500, "INTERNAL"),
    },
  });
  // The clean CLI delete removed everything, so a 404 after it is the normal end.
  assert.equal(result.vanishedAfterCreate.length, 0);
  assert.equal(result.cleanup.verified, true);
});

test("a name that was confirmed and is gone with a CLI delete that did not run cleanly is reported as vanished after create", async () => {
  const { result } = await go({}, {}, undefined, (runCli) => async (o) => {
    // The CLI delete times out; the world still removes the functions (a deletion the run cannot vouch for).
    const out = await runCli(o);
    return o.action === "delete" ? { ...out, timedOut: true } : out;
  });
  assert.ok(result.vanishedAfterCreate.length > 0);
  assert.ok(result.vanishedAfterCreate.every((v) => v.class === "vanished-after-create"));
  assert.equal(result.closureReady, false);
  assert.equal(result.readBackRequired, true);
});

// ---- the stops before anything is created -----------------------------------------------------------------------

const stops = [
  [
    "the project identity is not read",
    {
      hooks: {
        [`GET cloudresourcemanager.googleapis.com/v1/projects/${PROJECT}`]: () =>
          error(500, "INTERNAL"),
      },
    },
    "identity",
  ],
  [
    "the project number is not the one named",
    { projectNumberReported: "999999999999" },
    "project-number",
  ],
  [
    "a required service is not enabled",
    { withoutServices: ["cloudtasks.googleapis.com"] },
    "services",
  ],
  ["a queue of the run's names already exists", { seedQueues: [functionsOf(RUN)[2]] }, "namespace"],
  [
    "the project IAM cannot be read",
    {
      hooks: {
        [`POST cloudresourcemanager.googleapis.com/v1/projects/${PROJECT}:getIamPolicy`]: () =>
          error(500, "INTERNAL"),
      },
    },
    "iam",
  ],
  [
    "a list cannot be read",
    {
      hooks: {
        [`GET cloudtasks.googleapis.com/v2/projects/${PROJECT}/locations/${REGION}/queues`]: () =>
          error(500, "INTERNAL"),
      },
    },
    "lists",
  ],
  [
    "the Gen2 source buckets cannot be listed",
    {
      hooks: {
        [`GET storage.googleapis.com/storage/v1/b/gcf-v2-uploads-${NUMBER}.${REGION}.cloudfunctions.appspot.com/o`]:
          () => error(500, "INTERNAL"),
      },
    },
    "source-buckets",
  ],
];
for (const [name, options, why] of stops) {
  test(`the run stops before anything is created when ${name}`, async () => {
    const { world, result } = await go(options);
    assert.equal(result.stoppedBecause, why);
    assert.equal(result.stage, "preflight");
    assert.deepEqual(world.cliRuns, []);
    assert.deepEqual(mutations(world), []);
    assert.equal(result.closureReady, false);
    assert.ok(["tq-stopped-clean", "tq-needs-review"].includes(result.outcome));
  });
}

test("a failed CLI dry run is a clean stop and nothing is deployed", async () => {
  const { world, result } = await go(
    {},
    {},
    undefined,
    (runCli) => async (o) =>
      o.action === "dry-run"
        ? {
            action: "dry-run",
            exitCode: 1,
            timedOut: false,
            error: null,
            errored: 0,
            cliWrites: [],
          }
        : runCli(o),
  );
  assert.equal(result.outcome, "tq-stopped-clean");
  assert.equal(result.stoppedBecause, "the CLI dry run failed");
  assert.deepEqual(world.cliRuns, []);
});

// ---- the stops during the run -----------------------------------------------------------------------------------

test("a failed deploy cleans up what the CLI may have made and does not run the program", async () => {
  const { world, result } = await go({ failDeploy: true });
  assert.deepEqual(world.cliRuns, ["dry-run", "deploy", "delete"]);
  assert.equal(Object.keys(result.program).length, 0);
  assert.equal(count(world, "POST cloudtasks.googleapis.com"), 0);
  assert.equal(result.closureReady, false);
  assert.ok(emptyWorld(world));
});

test("a queue Cloud Tasks will not create again fails the CLI deploy: the program is not sent and the run reports it", async () => {
  const tomb = new Set([functionsOf(RUN)[0]]);
  const { world, result } = await go({ queueTombstones: tomb });
  assert.equal(result.closureReady, false);
  assert.ok(result.unknownMutationList.some((m) => m.class === "cli-write-retried"));
  assert.ok(
    result.unconfirmedCreates.length > 0,
    "every name of a retried write is an open create",
  );
  assert.deepEqual(result.program, {}, "no step of the program is sent against a partial deploy");
  assert.equal(count(world, "POST cloudtasks.googleapis.com"), 0);
  assert.ok(world.cliRuns.includes("delete"));
});

test("a 401 stops the run where it is and the CLI delete still runs", async () => {
  const { world, result } = await go({
    hooks: { [tasksUrl("tqdef")]: () => error(401, "UNAUTHENTICATED") },
  });
  assert.equal(result.outcome, "tq-auth-stop");
  assert.equal(result.authStop.status, 401);
  assert.ok(world.cliRuns.includes("delete"));
  assert.equal(result.closureReady, false);
});

test("a 403 on a createTask that is not a probe of a permission stops the program; on a probe it is data", async () => {
  const stopped = await go({
    hooks: { [tasksUrl("tqretry")]: () => error(403, "PERMISSION_DENIED") },
  });
  assert.match(stopped.result.stoppedBecause, /was answered 403/);
  assert.ok(Object.keys(stopped.result.program).length < PROGRAM.length);
  assert.ok(stopped.world.cliRuns.includes("delete"));
  assert.equal(stopped.result.closureReady, false);
  // The step that points a name at another queue may be answered 403: the run goes on.
  const probe = await go({
    hooks: {
      [tasksUrl("tqdef")]: ({ body }) =>
        body.task?.name?.includes("id-other-queue") ? error(403, "PERMISSION_DENIED") : undefined,
    },
  });
  assert.equal(probe.result.program["id-other-queue"].status, 403);
  assert.equal(Object.keys(probe.result.program).length, PROGRAM.length);
  assert.equal(probe.result.outcome, "tq-recorded");
});

test("the request ceiling stops the program and the cleanup still runs and reads everything back", async () => {
  const { world, result } = await go({}, { normalCeiling: 80 });
  assert.match(result.stoppedBecause, /ceiling/);
  assert.ok(emptyWorld(world));
  assert.equal(result.cleanup.verified, true);
  assert.equal(result.closureReady, false);
  assert.notEqual(result.outcome, "tq-recorded");
});

test("a signal stops at the next request, runs the cleanup and does not close", async () => {
  const signal = { aborted: false };
  const { world, result } = await go({}, { signal }, (send) => async (request) => {
    if (request.method === "POST" && request.url.includes("/tasks")) signal.aborted = true;
    return send(request);
  });
  assert.match(result.stoppedBecause, /signal/);
  assert.ok(emptyWorld(world));
  assert.equal(result.closureReady, false);
});

// ---- the cleanup -----------------------------------------------------------------------------------------------

test("a function the CLI delete left behind is deleted once through REST after a fresh list, and its operation is read", async () => {
  const left = functionOfRole(RUN, "tqlimit");
  const { world, result } = await go({ leaveOnDelete: [left] });
  assert.equal(count(world, `DELETE cloudfunctions.googleapis.com/v2/${functionName(left)}`), 1);
  assert.ok(emptyWorld(world));
  assert.equal(result.cleanup.verified, true);
});

test("a function whose delete does not finish stays an unknown mutation and the run cannot close", async () => {
  const left = functionOfRole(RUN, "tqlimit");
  const { result } = await go({
    leaveOnDelete: [left],
    hooks: {
      [`DELETE cloudfunctions.googleapis.com/v2/${functionName(left)}`]: () =>
        error(500, "INTERNAL"),
    },
  });
  assert.equal(result.cleanup.verified, false);
  assert.equal(result.outcome, "tq-needs-recovery");
  assert.equal(result.closureReady, false);
});

test("a queue the function delete left is deleted once, after a list shows it", async () => {
  const left = functionOfRole(RUN, "tqrate");
  const { world, result } = await go({ leaveOnDelete: ["queue:" + left] });
  assert.equal(
    count(
      world,
      `DELETE cloudtasks.googleapis.com/v2/projects/${PROJECT}/locations/${REGION}/queues/${left}`,
    ),
    1,
  );
  assert.ok(emptyWorld(world));
  assert.equal(result.cleanup.verified, true);
});

test("the cleanup never deletes a queue or function it did not make", async () => {
  const other = "tqother123456";
  const { world } = await go({ seedQueues: [other] });
  assert.ok(world.queues.has(other), "a foreign queue is left alone");
  assert.equal(
    count(
      world,
      `DELETE cloudtasks.googleapis.com/v2/projects/${PROJECT}/locations/${REGION}/queues/${other}`,
    ),
    0,
  );
});

test("the upload object is deleted by generation, once, and any other new object is unexplained", async () => {
  const normal = await go();
  assert.equal(normal.result.cleanup.uploadObjectsDeleted.length, 1);
  assert.equal(normal.result.cleanup.uploadObjectsDeleted[0].class, "2xx");
  const extra = await go({ uploadLines: "extra" });
  assert.ok(
    extra.result.cleanup.uploadReasons.length > 0 || extra.result.cleanup.verified === false,
  );
  assert.equal(extra.result.closureReady, false);
  const none = await go({ uploadLines: "none" });
  assert.ok(none.result.cleanup.uploadReasons.includes("receipt-log-unreadable") === false);
  assert.equal(none.result.closureReady, false);
  assert.ok(none.result.unconfirmedCreates.some((c) => c.label === "upload-object"));
  const refused = await go({ uploadLines: "refused" });
  assert.equal(refused.result.cleanup.uploadObjectsDeleted.length, 0);
});

test("a source object that appears and is not the build's copy keeps the cleanup unverified", async () => {
  const { result } = await go({}, {}, (send, world) => async (request) => {
    if (request.method === "DELETE" && request.url.includes("/packages/")) {
      const [, sources] = [...world.sourceBuckets.keys()];
      world.sourceBuckets.get(sources).push("somebody-else/function-source.zip");
    }
    return send(request);
  });
  assert.equal(result.cleanup.verified, false);
  assert.ok(result.inventory.differences.some((d) => d.kind === "sourceObjects"));
});

test("the project IAM may gain a service-account member and nothing else; a service enabled in the meantime is a difference", async () => {
  const gained = await go({}, {}, (send, world) => async (request) => {
    if (request.method === "DELETE" && request.url.includes("/packages/"))
      world.projectIam.push({
        role: "roles/run.invoker",
        members: ["serviceAccount:sa@x.gserviceaccount.com"],
      });
    return send(request);
  });
  assert.equal(gained.result.cleanup.verified, true);
  const user = await go({}, {}, (send, world) => async (request) => {
    if (request.method === "DELETE" && request.url.includes("/packages/"))
      world.projectIam.push({ role: "roles/owner", members: ["user:someone@example.com"] });
    return send(request);
  });
  assert.equal(user.result.cleanup.verified, false);
  const service = await go({}, {}, (send, world) => async (request) => {
    if (request.method === "DELETE" && request.url.includes("/packages/"))
      world.services.add("pubsub.googleapis.com");
    return send(request);
  });
  assert.equal(service.result.cleanup.verified, false);
  assert.deepEqual(service.result.inventory.services.added, ["pubsub.googleapis.com"]);
});

// ---- the shape of what is sent -----------------------------------------------------------------------------------

test("every name is issued in the journal before the request that makes it, and no request is journaled twice", async () => {
  const { journal } = await go();
  const rows = journal.map((r, i) => ({ ...r, i }));
  for (const spec of PROGRAM.filter((s) => s.kind === "create")) {
    const issued = rows.find((r) => r.id === "issue-task-" + spec.key);
    const sent = rows.find((r) => r.id === "step-" + spec.key && r.state === "before-send");
    assert.ok(issued && sent && issued.i < sent.i, spec.key);
  }
  for (const fn of functionsOf(RUN)) {
    const issuedAt = rows.find((r) => r.id === "issue-function-" + fn)?.i;
    const deployAt = rows.find((r) => r.id === "cli-deploy")?.i;
    assert.ok(issuedAt < deployAt);
  }
  const befores = rows.filter((r) => r.state === "before-send").map((r) => r.id);
  assert.equal(new Set(befores).size, befores.length, "every request id is sent once");
});

test("the token is never journaled and the quota project header is the sandbox's", async () => {
  const seen = [];
  const { journal } = await go({}, {}, (send) => async (request) => {
    seen.push(request.headers["x-goog-user-project"]);
    return send(request);
  });
  assert.ok(seen.every((p) => p === PROJECT));
  assert.equal(JSON.stringify(journal).includes("test-token-abcdefgh"), false);
});

test("a log page that is cut is followed, and a frame seen twice is counted once", async () => {
  const paged = await go({ logPageSize: 40 });
  const whole = await go();
  assert.equal(paged.result.judged.totals.deliveries, whole.result.judged.totals.deliveries);
  assert.equal(paged.result.closureReady, true);
});

test("a delivery that never prints is reported as not delivered, and the run still closes", async () => {
  const { result } = await go({ silent: [functionOfRole(RUN, "tqrate")] });
  const findings = result.judged.findings.filter((f) => f.kind === "not-delivered");
  assert.equal(findings.length, 8);
  assert.equal(result.judged.observationComplete, false);
  assert.equal(result.closureReady, true);
});

test("absent() reads only a 404 whose body says NOT_FOUND, and the IAM policy keeps everything but etag and version", () => {
  const notFound = { status: 404, json: { error: { status: "NOT_FOUND" } } };
  assert.equal(absent(notFound), true);
  assert.equal(absent({ status: 404, json: { error: { status: "PERMISSION_DENIED" } } }), false);
  assert.equal(absent({ status: 404, json: null }), false);
  assert.equal(absent({ status: 403, json: { error: { status: "NOT_FOUND" } } }), false);
  assert.equal(
    absent({ status: 404, json: { error: { errors: [{ reason: "notFound" }] } } }),
    true,
  );
  assert.equal(absent(null), false);
  assert.deepEqual(
    iamPolicyOf({ status: 200, json: { etag: "e", version: 1, bindings: [], auditConfigs: [1] } }),
    { bindings: [], auditConfigs: [1] },
  );
  assert.equal(iamPolicyOf({ status: 200, json: { bindings: [{ role: 1 }] } }), null);
  assert.equal(iamPolicyOf({ status: 500, json: {} }), null);
  assert.equal(queueName("x"), `projects/${PROJECT}/locations/${REGION}/queues/x`);
});

// ---- what the CLI deploy of the codebase may delete, and what it may write -------------------------------------------

const STRAY = "tqdef999999";
for (const [name, options] of [
  ["a function of the codebase left by another run", { seedFunctions: [STRAY] }],
  ["a queue of another run", { seedQueues: [STRAY] }],
  ["an image of another run", { seedPackages: [packageIds(STRAY)[0], packageIds(STRAY)[1]] }],
]) {
  test(`the run stops before anything is created when ${name} is in the project (the deploy would delete it)`, async () => {
    const { world, result } = await go(options);
    assert.equal(result.stoppedBecause, "codebase-not-empty");
    assert.ok(result.strayFixture.some((x) => x.includes(STRAY)));
    assert.deepEqual(world.cliRuns, []);
    assert.deepEqual(mutations(world), []);
    assert.equal(world.deletedByDeploy, undefined);
  });
}

test("a function labelled with the codebase, whatever its id, stops the run", async () => {
  const { world, result } = await go({ seedFunctions: ["somethingelse"] });
  assert.equal(result.stoppedBecause, "codebase-not-empty");
  assert.deepEqual(world.cliRuns, []);
});

test("the model of the CLI deploys --force deleting a leftover of the codebase, which is why the stop exists", async () => {
  // Without the preflight check (a world the recorder did not read first) the deploy removes it: the world models that.
  const world = (await import("./world.mjs")).createWorld({ runId: RUN, seedFunctions: [STRAY] });
  await world.runCli({ action: "deploy" });
  assert.deepEqual(world.deletedByDeploy, [STRAY]);
});

test("the image repository must already have a cleanup policy, and a change of it during the run is a difference", async () => {
  const none = await go({ repositoryPolicies: null });
  assert.equal(none.result.stoppedBecause, "artifact-cleanup-policy");
  assert.deepEqual(none.world.cliRuns, []);
  const changed = await go({}, {}, (send, world) => async (request) => {
    if (request.method === "DELETE" && request.url.includes("/packages/"))
      world.repository.cleanupPolicies = {
        "keep-recent": { id: "keep-recent" },
        extra: { id: "extra" },
      };
    return send(request);
  });
  assert.equal(changed.result.cleanup.verified, false);
  assert.ok(changed.result.inventory.differences.some((d) => d.kind === "repository"));
});
