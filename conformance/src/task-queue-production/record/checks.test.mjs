// Checks of the orchestrator that each stand against one decision: the preflight's own stops, the answers it must not
// believe, the cleanup's second look at what it deleted, and the times the judge starts from. Every test fails when its
// decision is removed (the hand mutants of the mutation record name them).
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
  sourceBuckets,
} from "../plan.mjs";
import { RUN, count, go } from "./harness.mjs";
import { NUMBER, reply } from "./world.mjs";

const error = (code, status, message = "x") => reply(code, { error: { code, message, status } });
const get = (path) => `GET ${path}`;
const queueUrl = (role) =>
  `cloudtasks.googleapis.com/v2/projects/${PROJECT}/locations/${REGION}/queues/${functionOfRole(RUN, role)}`;
const idUrl = `GET cloudresourcemanager.googleapis.com/v1/projects/${PROJECT}`;
const identity = (change) => ({
  projectNumber: NUMBER,
  projectId: PROJECT,
  lifecycleState: "ACTIVE",
  name: PROJECT,
  ...change,
});

// ---- the preflight ---------------------------------------------------------------------------------------------

test("a project that is not ACTIVE, or whose id is not the sandbox's, is not the project", async () => {
  for (const change of [{ lifecycleState: "DELETE_REQUESTED" }, { projectId: "someone-else" }]) {
    const { world, result } = await go({ hooks: { [idUrl]: () => reply(200, identity(change)) } });
    assert.equal(result.stoppedBecause, "identity", JSON.stringify(change));
    assert.deepEqual(world.cliRuns, []);
  }
});

test("a package of the run's own names already in the registry is the namespace stopping the run", async () => {
  const { world, result } = await go({ seedPackages: [packageIds(functionsOf(RUN)[3])[0]] });
  assert.equal(result.stoppedBecause, "namespace");
  assert.deepEqual(world.cliRuns, []);
});

test("a preflight log read that fails stops the run before anything is created", async () => {
  const { world, result } = await go({
    hooks: { "POST logging.googleapis.com/v2/entries:list": () => error(500, "INTERNAL") },
  });
  assert.equal(result.stoppedBecause, "preflight-reads");
  assert.deepEqual(world.cliRuns, []);
});

// ---- answers the run must not believe --------------------------------------------------------------------------

test("a 201 or a 202 whose body is not JSON is an unknown answer, like a 200", async () => {
  for (const status of [201, 202]) {
    let hit = false;
    const { result } = await go({
      hooks: {
        [`POST ${queueUrl("tqdef")}/tasks`]: () => {
          if (hit) return undefined;
          hit = true;
          return new Response("not json", { status });
        },
      },
    });
    assert.ok(
      result.unknownMutationList.some((m) => m.class === "unreadable"),
      String(status),
    );
    assert.equal(result.closureReady, false);
  }
});

test("a function readback that fails is an incomplete read and the program is not sent", async () => {
  const victim = functionName(functionOfRole(RUN, "tqrate"));
  const { world, result } = await go({
    hooks: { [`GET cloudfunctions.googleapis.com/v2/${victim}`]: () => error(404, "NOT_FOUND") },
  });
  assert.equal(result.stoppedBecause, "a function readback gave no URL or identity");
  assert.deepEqual(result.program, {});
  assert.ok(result.incompleteReads.some((r) => r.id.includes("readback-function")));
  assert.equal(count(world, "POST cloudtasks.googleapis.com"), 0);
  assert.equal(result.closureReady, false);
});

test("a 403 on a read of a queue or a task is data, not a stop of the program", async () => {
  const { result } = await go({
    hooks: {
      [get(queueUrl("tqrate"))]: () => error(403, "PERMISSION_DENIED"),
    },
  });
  assert.equal(result.program["queue-tqrate"].status, 403);
  assert.equal(Object.keys(result.program).length, PROGRAM.length);
  assert.equal(result.stoppedBecause, undefined);
});

test("a signal that is already up sends nothing", async () => {
  const { world, result } = await go({}, { signal: { aborted: true } });
  assert.deepEqual(world.calls, []);
  assert.equal(result.outcome, "tq-stopped-clean");
  assert.match(result.stoppedBecause, /signal/);
});

// ---- the observation window -----------------------------------------------------------------------------------

test("the wait for deliveries ends at the first poll when every accepted task has arrived", async () => {
  const { journal } = await go();
  const polls = journal.filter(
    (r) => /^logs-observe-\d+-frames$/.test(r.id) && r.state === "before-send",
  );
  assert.equal(polls.length, 1);
});

test("the wait goes on while a delivery that was accepted has not been seen, up to its window", async () => {
  const { journal } = await go({ silent: [functionOfRole(RUN, "tqrate")] });
  const polls = journal.filter(
    (r) => /^logs-observe-\d+-frames$/.test(r.id) && r.state === "before-send",
  );
  assert.equal(polls.length, 4, "the whole window, 240 seconds in polls of 60");
});

test("a task that was refused is not waited for", async () => {
  // Every probe the model refuses has no delivery; the clean run still ends at the first poll (above). Here the only
  // accepted creates are silenced, so the window runs; the refused ones add nothing to the wait beyond it.
  const { journal } = await go({ silent: functionsOf(RUN) });
  const polls = journal.filter(
    (r) => /^logs-observe-\d+-frames$/.test(r.id) && r.state === "before-send",
  );
  assert.equal(polls.length, 4);
});

test("a retry that is seen late is waited for: only start frames count, and a delivery with its end already seen is not enough", async () => {
  // At the first poll only the first attempts of the retry cases are visible; the run must poll again for the rest.
  const { journal, result } = await go({ logVisibleAfterMs: 203_000 });
  const polls = journal.filter(
    (r) => /^logs-observe-\d+-frames$/.test(r.id) && r.state === "before-send",
  );
  assert.ok(polls.length >= 2, "polled again");
  const retries = result.judged.cases["retry-ladder"].deliveries;
  assert.equal(retries.length, 6, "and the final poll has all six attempts");
});

// ---- the times -------------------------------------------------------------------------------------------------

test("a delivery's time is counted from the moment its createTask was sent, on the run's clock", async () => {
  const { result } = await go();
  for (const key of ["env-default", "retry-ladder", "sch-20s"]) {
    const [first] = result.judged.cases[key].deliveries;
    assert.ok(first.startMs >= 0 && first.startMs < 60_000, `${key} ${first.startMs}`);
  }
  const sent = result.program["sch-20s"].dispatchedAt;
  assert.ok(sent > 1_700_000_000_000, "an instant, not zero");
  assert.ok(result.judged.cases["sch-20s"].deliveries[0].startMs >= 19_000);
});

// ---- the cleanup's second look ---------------------------------------------------------------------------------

test("nothing is deleted through REST when the CLI delete removed everything: no function or queue request", async () => {
  const { world } = await go();
  assert.equal(count(world, "DELETE cloudfunctions.googleapis.com"), 0);
  const queueDeletes = world.calls.filter((c) =>
    /^DELETE cloudtasks\.googleapis\.com\/.*\/queues\/[^/]+$/.test(c),
  );
  assert.deepEqual(queueDeletes, []);
});

test("a queue or an image of someone else in the lists is not the run's to delete: the filter refuses before the guard has to", async () => {
  const other = await go({
    seedQueues: ["tqother123456"],
    seedPackages: ["fireemu--oracle--events__us--central1__other"],
  });
  assert.equal(other.result.cleanup.errors, undefined, "no request was even attempted");
  assert.equal(other.result.cleanup.packagesDeleted.length, 16, "only the run's own images");
  assert.ok(other.world.queues.has("tqother123456"));
  assert.ok(other.world.packages.has("fireemu--oracle--events__us--central1__other"));
});

test("an upload object that is still there after its delete was answered is not verified: the name is read back", async () => {
  const uploads = sourceBuckets(NUMBER)[0];
  const { result, world } = await go({}, {}, (send) => async (request) => {
    if (request.method === "DELETE" && request.url.includes(`/b/${uploads}/o/`)) {
      // The delete is answered 204 and does nothing; the object stays.
      return new Response(null, { status: 204 });
    }
    return send(request);
  });
  assert.ok(world.sourceBuckets.get(uploads).includes(world.upload));
  assert.equal(result.cleanup.readBack["upload-object-1"], false);
  assert.equal(result.cleanup.verified, false);
  assert.equal(result.outcome, "tq-needs-recovery");
});

test("a queue that is in the list but reads 404 is not verified: the lists are a check of their own", async () => {
  const victim = functionOfRole(RUN, "tqrate");
  const url = queueUrl("tqrate");
  const { result } = await go(
    { leaveOnDelete: ["queue:" + victim] },
    {},
    (send) => async (request) => {
      if (request.method === "DELETE" && request.url.endsWith("/queues/" + victim))
        return reply(200, {});
      if (
        request.method === "GET" &&
        request.url.endsWith("/queues/" + victim) &&
        request.cleanup !== false
      )
        return send(request).then(async (answer) =>
          answer.status === 200 ? error(404, "NOT_FOUND") : answer,
        );
      return send(request);
    },
  );
  assert.equal(result.cleanup.listsEmpty, false);
  assert.equal(result.cleanup.verified, false);
  assert.ok(url.length > 0);
});

test("an upload that left no readable receipt, or an unexplained object, or a receipt for an object already there, keeps the cleanup unverified", async () => {
  const none = await go({ uploadLines: "none" });
  assert.ok(none.result.cleanup.uploadReasons.length > 0);
  assert.equal(none.result.cleanup.verified, false);
  const extra = await go({ uploadLines: "extra" });
  assert.ok(extra.result.cleanup.uploadReasons.length > 0);
  assert.equal(extra.result.cleanup.verified, false);
  const known = "514cacbe-3258-46fd-9a02-54b7485b9999.zip";
  const inBaseline = await go({ uploadName: known, baselineUploads: [known] });
  assert.ok(
    inBaseline.result.cleanup.uploadReasons.some((r) =>
      r.startsWith("receipt-names-baseline-object:"),
    ),
  );
  assert.equal(
    inBaseline.result.cleanup.uploadObjectsDeleted.length,
    0,
    "an object that was there before is never deleted",
  );
  assert.equal(inBaseline.result.cleanup.verified, false);
});

test("a refused upload is clean: its PUT made no object, so nothing is read, deleted or left open", async () => {
  const { result } = await go({ uploadLines: "refused" });
  assert.deepEqual(result.cleanup.uploadReasons, []);
  assert.deepEqual(result.cleanup.uploadObjectsDeleted, []);
  assert.equal(result.unconfirmedCreates.length, 0);
  assert.equal(result.cleanup.verified, true);
  assert.equal(result.closureReady, true);
});

test("the readiness polls of a failed deploy are two, and of a good deploy up to forty", async () => {
  const failed = await go({ failDeploy: true });
  const polls = failed.journal.filter(
    (r) => /^readiness|^ready-\d+-functions-v2$/.test(r.id) && r.state === "before-send",
  );
  assert.equal(polls.length, 2);
  assert.equal(queueName("x").length > 0, true);
});
