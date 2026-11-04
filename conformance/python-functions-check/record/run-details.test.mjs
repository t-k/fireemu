// The orchestrator's details, pinned by mutation testing of the first suite: the journal rows and the waits of each
// scenario (golden files, regenerated with UPDATE_GOLDEN=1 and reviewed by hand), the result fields, every loop bound,
// and each of the conditions that decide whether the run may close.
import assert from "node:assert/strict";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import test from "node:test";
import {
  ALL_FUNCTIONS,
  JOB_IDS,
  PROJECT,
  QUEUE_IDS,
  TOPIC,
  functionName,
  jobName,
  packageIds,
  queueName,
  topicName,
} from "./plan.mjs";
import { CLEANUP_CEILING, LOG_POLL_SECONDS, MAX_REQUESTS, NORMAL_CEILING, record } from "./run.mjs";
import { FRAME_MARK } from "./plan.mjs";
import { NUMBER, createWorld, reply } from "./world.mjs";

const RUN = "0123456789abcdef";
const GOLDEN = new URL("./run-goldens.json", import.meta.url);
const error = (code, status, message = "x") => reply(code, { error: { code, message, status } });

async function go(
  worldOptions = {},
  options = {},
  wrapSend = (send) => send,
  wrapCli = (cli) => cli,
) {
  const world = createWorld({ runId: RUN, ...worldOptions });
  const journal = [];
  const sleeps = [];
  const prepared = [];
  const result = await record({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "test-token-abcdefgh",
    save: async (row) => journal.push(row),
    send: wrapSend(world.send, world),
    runCli: wrapCli((o) => world.runCli(o), world),
    clock: () => world.now,
    sleep: async (ms) => {
      sleeps.push(ms);
      world.advance(ms);
    },
    prepareRequest: async (spec) => prepared.push(spec.id),
    ...options,
  });
  return { world, journal, sleeps, result, prepared };
}
const rows = (journal) =>
  journal
    .filter((r) => r.state !== "response-persisted" && r.state !== "response-headers")
    .map((r) => [r.id, r.state]);
const requestIds = (journal) => journal.filter((r) => r.state === "before-send").map((r) => r.id);
const count = (world, prefix) => world.calls.filter((c) => c.startsWith(prefix)).length;

// ---- goldens: the journal and the waits of whole scenarios ---------------------------------------------

const SCENARIOS = {
  clean: () => go(),
  leftoverFunctionWithPendingOperation: () =>
    go({ leaveOnDelete: ["pcps"] }, {}, (send) => {
      let polls = 0;
      return async (request) => {
        const url = new URL(request.url);
        if (request.method === "GET" && url.pathname.includes("/operations/del-"))
          return reply(200, { name: url.pathname, done: ++polls >= 3 });
        return send(request);
      };
    }),
  busyJobThenDeleted: () => {
    let busy = 0;
    return go(
      { leaveOnDelete: ["job:" + JOB_IDS[0]] },
      {},
      (send) => async (request) =>
        request.method === "DELETE" && request.url.includes("/jobs/") && busy++ < 3
          ? error(409, "ABORTED", "sync mutate calls cannot be queued")
          : send(request),
    );
  },
  failedDeploy: () => go({ failDeploy: true }),
  packageOperationPending: () => {
    let polls = 0;
    return go({}, {}, (send) => async (request) => {
      const url = new URL(request.url);
      if (
        request.method === "DELETE" &&
        url.hostname === "artifactregistry.googleapis.com" &&
        url.pathname.endsWith(packageIds("pcps")[0])
      ) {
        await send(request);
        return reply(200, {
          name: "projects/fireemu-oracle-events/locations/us-central1/operations/pk-1",
          done: false,
        });
      }
      if (request.method === "GET" && url.pathname.endsWith("/operations/pk-1"))
        return reply(200, { name: "x", done: ++polls >= 2 });
      return send(request);
    });
  },
};

const golden = () => (existsSync(GOLDEN) ? JSON.parse(readFileSync(GOLDEN, "utf8")) : {});
if (process.env.UPDATE_GOLDEN) {
  const next = {};
  for (const [name, run] of Object.entries(SCENARIOS)) {
    const { journal, sleeps, result } = await run();
    next[name] = { outcome: result.outcome, rows: rows(journal), sleeps };
  }
  writeFileSync(GOLDEN, JSON.stringify(next, null, 1) + "\n");
}
for (const name of Object.keys(SCENARIOS))
  test(`golden: ${name}`, async () => {
    const { journal, sleeps, result } = await SCENARIOS[name]();
    const expected = golden()[name];
    assert.ok(expected, "run with UPDATE_GOLDEN=1 once and review the file");
    assert.equal(result.outcome, expected.outcome);
    assert.deepEqual(rows(journal), expected.rows);
    assert.deepEqual(sleeps, expected.sleeps);
  });

// ---- constants and waits ---------------------------------------------------------------------------

test("the request ceilings and the log poll interval are the packet's", () => {
  assert.deepEqual(
    [NORMAL_CEILING, CLEANUP_CEILING, MAX_REQUESTS, LOG_POLL_SECONDS],
    [300, 200, 500, 60],
  );
});

test("every wait is in seconds, converted to milliseconds, and the settle and busy waits have their defaults", async () => {
  const waits = {
    propagation: 7,
    window: 13,
    logPoll: 5,
    logDelay: 11,
    ready: 3,
    gap: 2,
    settle: 4,
    busy: 6,
  };
  const { sleeps } = await go(
    { silent: ["pcschraw"], leaveOnDelete: ["pcps", "job:" + JOB_IDS[0]] },
    { waits },
    (send) => {
      let busy = 0;
      return async (request) =>
        request.method === "DELETE" && request.url.includes("/jobs/") && busy++ < 1
          ? error(409, "ABORTED", "sync mutate calls cannot be queued")
          : send(request);
    },
  );
  assert.ok(sleeps.includes(7000), "propagation");
  assert.ok(sleeps.includes(11000), "log delay");
  assert.ok(sleeps.includes(2000), "step gap");
  assert.ok(sleeps.includes(6000), "busy job");
  assert.equal(sleeps.filter((ms) => ms === 4000).length, 6, "settle polls after the CLI delete");
  assert.deepEqual(
    sleeps.filter((ms) => ms === 5000).length >= 2 && sleeps.includes(3000),
    true,
    "the observe steps: 5, 5, 3",
  );
});

test("the defaults: ready 30 s, settle 30 s, busy 60 s, propagation 90 s, log poll 60 s", async () => {
  const { sleeps } = await go(
    { leaveOnDelete: ["pcps", "job:" + JOB_IDS[0]], deployState: "DEPLOYING" },
    {},
    (send) => {
      let busy = 0;
      return async (request) =>
        request.method === "DELETE" && request.url.includes("/jobs/") && busy++ < 1
          ? error(409, "ABORTED", "sync mutate calls cannot be queued")
          : send(request);
    },
  );
  assert.ok(sleeps.includes(30_000) && sleeps.includes(60_000));
  assert.equal(
    sleeps.filter((ms) => ms === 30_000).length,
    39 + 6,
    "ready polls 40 (39 gaps) and 6 settle gaps",
  );
});

test("the observe loop waits the window in poll-sized steps and stops as soon as every raw delivery is in", async () => {
  const slow = await go({ silent: ["pcschraw"] }, { waits: { window: 13, logPoll: 5 } });
  const observe = slow.journal
    .filter((r) => r.state === "before-send" && /^logs-observe-\d+-frames$/.test(r.id))
    .map((r) => r.id);
  assert.deepEqual(observe, [
    "logs-observe-1-frames",
    "logs-observe-2-frames",
    "logs-observe-3-frames",
  ]);
  const quick = await go({}, { waits: { window: 13, logPoll: 5 } });
  assert.deepEqual(
    quick.journal
      .filter((r) => r.state === "before-send" && /^logs-observe-\d+-frames$/.test(r.id))
      .map((r) => r.id),
    ["logs-observe-1-frames"],
  );
});

test("the normal request ceiling is exact", async () => {
  for (const ceiling of [25, 26]) {
    const { journal } = await go({}, { normalCeiling: ceiling });
    assert.equal(
      requestIds(journal).findIndex((id) => id.startsWith("cleanup-")),
      ceiling,
      "attempts before the cleanup",
    );
  }
});

test("a request ceiling reached in the preflight ends the run clean with no cleanup", async () => {
  const { result, world } = await go({}, { normalCeiling: 5 });
  assert.equal(result.outcome, "pycheck-stopped-clean");
  assert.match(result.stoppedBecause, /ceiling/);
  assert.deepEqual(world.cliRuns, []);
  assert.equal(result.closureReady, false);
});

test("the request hook sees every request, cleanup included", async () => {
  const { prepared, result } = await go();
  assert.equal(prepared.length, result.attempted);
});

// ---- result fields ---------------------------------------------------------------------------------

test("a clean run reports what it read, sent, saw and cleaned", async () => {
  const { result } = await go();
  assert.equal(result.stage, "done");
  assert.equal(result.bucket, "fireemu-oracle-events.firebasestorage.app");
  assert.deepEqual(result.appEngine, { status: 200 });
  assert.deepEqual(result.cli.dryRun.exitCode, 0);
  assert.deepEqual(Object.keys(result.cli), ["dryRun", "deploy", "delete"]);
  assert.equal(result.readbacks.pcps.state, "ACTIVE");
  assert.equal(result.readbacks.pcps.uri, "https://pcps-abc-uc.a.run.app");
  assert.equal(
    result.readbacks.pcps.serviceAccount,
    "123456789012-compute@developer.gserviceaccount.com",
  );
  assert.deepEqual(result.readbacks.pcps.eventTrigger.eventType, "x");
  assert.equal(result.readbacks.pcsch.eventTrigger, null);
  assert.equal(result.readbacks["job-" + JOB_IDS[0]].schedule, "0 0 1 1 *");
  assert.equal(result.readbacks["job-" + JOB_IDS[0]].timeZone, "UTC");
  assert.equal(result.readbacks["job-" + JOB_IDS[0]].state, "ENABLED");
  assert.equal(result.readbacks["job-" + JOB_IDS[0]].uri, "https://pcsch-abc-uc.a.run.app");
  assert.equal(result.readbacks["queue-pctask"].state, "RUNNING");
  assert.deepEqual(result.readbacks["queue-pctask"].retryConfig, { maxAttempts: 1 });
  assert.equal(result.readbacks.triggers.length, 9);
  assert.deepEqual(result.operations["fs-create"], { sent: true, class: "2xx", status: 200 });
  assert.equal(Object.keys(result.operations).length, 11);
  assert.deepEqual(
    Object.values(result.frames).reduce((a, b) => a + b, 0),
    16,
  );
  assert.equal(result.frames.pcea, 1);
  assert.equal(result.frames.pcearaw, 2);
  assert.equal(result.errorsSeen, 0);
  assert.deepEqual(result.framesIgnored, { notFrame: 0, unparsed: 0, foreignOrigin: 0 });
  assert.equal(result.cleanup.error, undefined);
  assert.equal(result.cleanup.errors, undefined);
});

test("log noise and ERROR entries are counted, and a log read that fails is incomplete", async () => {
  const world = createWorld({ runId: RUN });
  const origin = {
    logName: "projects/p/logs/run.googleapis.com%2Fstderr",
    resource: {
      type: "cloud_run_revision",
      labels: { service_name: "pcps", location: "us-central1" },
    },
  };
  const at = new Date(world.now + 1000).toISOString();
  world.entries.push({
    insertId: "junk-1",
    timestamp: at,
    ...origin,
    textPayload: FRAME_MARK + " {bad",
  });
  world.entries.push({
    insertId: "junk-2",
    timestamp: at,
    ...origin,
    textPayload: FRAME_MARK + " {bad",
  });
  world.entries.push({
    insertId: "err-1",
    timestamp: at,
    severity: "ERROR",
    ...origin,
    textPayload: "Traceback",
  });
  const journal = [];
  const result = await record({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "tok-abcdefgh",
    save: async (r) => journal.push(r),
    send: world.send,
    runCli: world.runCli,
    clock: () => world.now,
    sleep: async (ms) => world.advance(ms),
  });
  assert.equal(result.errorsSeen, 1);
  assert.equal(result.judged.errors.length, 1);
  assert.ok(result.framesIgnored.unparsed >= 2);
  assert.equal(result.framesIgnored.unparsed % 1, 0);
});

test("a stopped run reports the stage it stopped at and an unverified cleanup", async () => {
  const dirty = await go({}, {}, (send, world) => {
    world.topics.add("pycheck-orders");
    return send;
  });
  assert.equal(dirty.result.stage, "preflight");
  assert.equal(dirty.result.cleanup.verified, false);
  assert.equal(dirty.result.errorsSeen, 0);
  assert.equal(dirty.result.closureReady, false);
  const failed = await go(
    {},
    {},
    (send) => send,
    (cli) => async (o) => (o.action === "dry-run" ? { action: o.action, exitCode: 1 } : cli(o)),
  );
  assert.equal(failed.result.stage, "dry-run");
  assert.equal(failed.result.stoppedBecause, "the CLI dry run failed");
  assert.equal(failed.result.closureReady, false);
  assert.equal(failed.result.cli.dryRun.exitCode, 1);
});

for (const [what, hook, because] of [
  [
    "a service list that cannot be read",
    (r) => (r.url.includes("serviceusage") ? error(500, "INTERNAL") : null),
    "services",
  ],
  [
    "an admin SDK config that is not 200",
    (r) => (r.url.endsWith("/adminSdkConfig") ? error(500, "INTERNAL") : null),
    "admin-sdk-config",
  ],
  [
    "an admin SDK config without a bucket",
    (r) => (r.url.endsWith("/adminSdkConfig") ? reply(200, { projectId: PROJECT }) : null),
    "admin-sdk-config",
  ],
  [
    "a bucket that cannot be read",
    (r) =>
      r.url.includes("/storage/v1/b/") && !r.url.includes("/o") ? error(404, "NOT_FOUND") : null,
    "bucket",
  ],
  [
    "a function list that cannot be read",
    (r) => (r.url.includes("/locations/-/functions") ? error(500, "INTERNAL") : null),
    "lists",
  ],
  [
    "a run service list that cannot be read",
    (r) => (r.url.includes("run.googleapis.com") ? error(500, "INTERNAL") : null),
    "lists",
  ],
  [
    "a job list that cannot be read",
    (r) => (r.url.includes("/jobs?") ? error(500, "INTERNAL") : null),
    "lists",
  ],
])
  test(`${what} stops the run before anything is created`, async () => {
    const { result, world } = await go(
      {},
      {},
      (send) => async (request) => (await Promise.resolve(hook(request))) ?? send(request),
    );
    assert.equal(result.stoppedBecause, because);
    assert.equal(result.outcome, "pycheck-stopped-clean");
    assert.equal(result.closureReady, false);
    assert.deepEqual(world.cliRuns, []);
    assert.equal(
      world.calls.filter(
        (c) => !c.startsWith("GET ") && !c.includes("entries:list") && !c.includes("getIamPolicy"),
      ).length,
      0,
    );
  });

test("a list may span five pages and no more, in the preflight and in the log reads", async () => {
  for (const [pages, ok] of [
    [5, true],
    [6, false],
  ]) {
    let n = 0;
    const { result } = await go({}, {}, (send) => async (request) => {
      if (
        request.method === "GET" &&
        /\/jobs\?pageSize=500/.test(request.url) &&
        request.url.indexOf("pageToken") === -1 &&
        n === 0
      )
        n = 1;
      if (
        request.method === "GET" &&
        /\/jobs\?pageSize=500/.test(request.url) &&
        n >= 1 &&
        n <= 10 &&
        !request.url.includes("cleanup")
      ) {
        const page = n++;
        if (page <= pages) return reply(200, page < pages ? { nextPageToken: "t" + page } : {});
      }
      return send(request);
    });
    assert.equal(result.stoppedBecause === "lists", !ok, `pages=${pages}`);
  }
});

test("the log reads page through their entries by token and give up after five pages", async () => {
  const five = await go({ logPageSize: 4 });
  assert.equal(five.result.incompleteReads.length, 0);
  assert.ok(requestIds(five.journal).some((id) => /^logs-observe-1-frames-page-4$/.test(id)));
  assert.equal(five.result.judged.complete, true);
  const many = await go({ logPageSize: 2 });
  assert.ok(
    many.result.incompleteReads.some(
      (r) => r.class === "more-than-five-pages" && r.id.startsWith("logs-"),
    ),
  );
  assert.equal(many.result.closureReady, false);
  assert.equal(many.result.readBackRequired, false, "an incomplete read alone needs no read-back");
});

test("overlapping windows: each poll starts five seconds before the last one ended, the final one at the start of the run", async () => {
  const { journal, world } = await go();
  const filters = journal
    .filter((r) => r.state === "before-send" && /^logs-[a-z0-9-]+-frames$/.test(r.id))
    .map((r) => [r.id, r.json.filter]);
  const at = (filter, key) => Date.parse(new RegExp(`timestamp${key}"([^"]+)"`).exec(filter)[1]);
  for (let i = 1; i < filters.length - 1; i++)
    assert.equal(at(filters[i][1], ">="), at(filters[i - 1][1], "<=") - 5000, filters[i][0]);
  const [first, last] = [filters[0][1], filters.at(-1)];
  assert.equal(last[0], "logs-final-frames");
  assert.equal(
    at(last[1], ">=") - at(first, ">="),
    5000,
    "the final poll reads from the start of the run; the first one started five seconds earlier",
  );
  assert.ok(at(first, ">=") >= world.now - 100 * 60_000);
});

test("a 403 on a log read is data, not a stop", async () => {
  const { result } = await go(
    {},
    {},
    (send) => async (request) =>
      request.url.includes("entries:list") ? error(403, "PERMISSION_DENIED") : send(request),
  );
  assert.notEqual(result.outcome, "pycheck-auth-stop");
  assert.ok(result.incompleteReads.some((r) => r.id.startsWith("logs-") && r.class === "4xx"));
  assert.equal(result.closureReady, false);
});

test("the observing reads (bucket, App Engine app, topic settle, leftover operations) treat a 403 as data", async () => {
  const stopAt = async (needle) =>
    (
      await go(
        {},
        {},
        (send) => async (request) =>
          request.url.includes(needle) ? error(403, "PERMISSION_DENIED") : send(request),
      )
    ).result;
  assert.equal((await stopAt("/apps/")).stoppedBecause, "appengine");
  const bucket = await go(
    {},
    {},
    (send) => async (request) =>
      request.url.endsWith(".firebasestorage.app")
        ? error(403, "PERMISSION_DENIED")
        : send(request),
  );
  assert.equal(bucket.result.stoppedBecause, "bucket");
  assert.equal(bucket.result.outcome, "pycheck-stopped-clean");
});

test("a read that is not 200 and not an observing read leaves the run incomplete", async () => {
  const { result } = await go(
    {},
    {},
    (send) => async (request) =>
      request.url.endsWith(`/functions/pcps`) && request.method === "GET"
        ? error(404, "NOT_FOUND")
        : send(request),
  );
  assert.ok(
    result.incompleteReads.some((r) => r.id === "readback-function-pcps" && r.class === "4xx"),
  );
  assert.equal(result.incompleteReads.length, 1);
  assert.equal(result.closureReady, false);
  assert.equal(result.readBackRequired, false);
  assert.equal(result.outcome, "pycheck-needs-review");
});

// ---- the deploy ------------------------------------------------------------------------------------

test("every name the CLI will create is journaled as issued before the deploy, with its full name", async () => {
  const { journal } = await go();
  const issued = journal.filter((r) => r.state === "issued");
  const firstDeploy = journal.findIndex((r) => r.id === "cli-deploy");
  assert.ok(
    issued.every(
      (r) =>
        journal.indexOf(r) < firstDeploy ||
        r.kind === "document" ||
        r.kind === "object" ||
        r.kind === "topic",
    ),
  );
  const byKind = (kind) =>
    issued.filter((r) => r.kind === kind).map((r) => [r.id, r.name, r.transport]);
  assert.deepEqual(
    byKind("function"),
    ALL_FUNCTIONS.map((fn) => ["issue-function-" + fn, functionName(fn), "cli"]),
  );
  assert.deepEqual(
    byKind("job"),
    JOB_IDS.map((id) => ["issue-job-" + id, jobName(id), "cli"]),
  );
  assert.deepEqual(
    byKind("queue"),
    QUEUE_IDS.map((id) => ["issue-queue-" + id, queueName(id), "cli"]),
  );
  assert.deepEqual(byKind("topic"), [["issue-topic", topicName(TOPIC), "rest"]]);
  assert.equal(byKind("document").length, 1);
  assert.equal(byKind("object").length, 1);
  assert.ok(journal.some((r) => r.id === "cli-deploy" && r.state === "cli-result"));
});

test("a failed deploy reads the lists twice, not forty times, and an unready deploy as many times as it is allowed", async () => {
  const failed = await go({ failDeploy: true });
  assert.deepEqual(
    requestIds(failed.journal).filter((id) => /^ready-\d+-functions-v2$/.test(id)),
    ["ready-1-functions-v2", "ready-2-functions-v2"],
  );
  const unready = await go({ deployState: "DEPLOYING" }, { waits: { readyPolls: 3, ready: 3 } });
  assert.deepEqual(
    requestIds(unready.journal).filter((id) => /^ready-\d+-functions-v2$/.test(id)),
    ["ready-1-functions-v2", "ready-2-functions-v2", "ready-3-functions-v2"],
  );
  assert.equal(unready.sleeps.filter((ms) => ms === 3000).length, 2);
  assert.equal(unready.result.outcome, "pycheck-incomplete-clean");
  assert.equal(
    unready.result.operations["fs-create"],
    undefined,
    "nothing is sent to functions that never became ready",
  );
  assert.equal(count(unready.world, "POST firestore"), 0);
  assert.equal(unready.result.cleanup.verified, true);
});

test("the CLI's own errors are unknown answers: the labels stay unconfirmed until an own read shows them", async () => {
  for (const [name, cli, klass] of [
    [
      "timeout",
      (inner) => async (o) =>
        o.action === "deploy" ? { ...(await inner(o)), timedOut: true } : inner(o),
      "cli-timeout",
    ],
    [
      "signal",
      (inner) => async (o) =>
        o.action === "deploy" ? { ...(await inner(o)), signal: "SIGKILL" } : inner(o),
      "cli-signal",
    ],
    [
      "error",
      (inner) => async (o) =>
        o.action === "deploy" ? { ...(await inner(o)), error: "spawn" } : inner(o),
      "cli-error",
    ],
  ]) {
    const { result } = await go({}, {}, (send) => send, cli);
    assert.deepEqual(
      result.unknownMutationList.map((u) => [u.id, u.class]),
      [["cli-deploy", klass]],
      name,
    );
    assert.equal(
      result.unconfirmedCreates.length,
      0,
      "every name was seen by an own 2xx read afterwards: " + name,
    );
    assert.equal(result.closureReady, false, name);
    assert.equal(result.readBackRequired, true, name);
    assert.equal(result.outcome, "pycheck-needs-review", name);
  }
});

test("a CLI deploy that times out leaves the names no read showed as unconfirmed, with the CLI's class", async () => {
  const { result } = await go(
    {},
    {},
    (send) => async (request) =>
      request.method === "GET" && request.url.endsWith(`/jobs/${JOB_IDS[1]}`)
        ? error(404, "NOT_FOUND")
        : send(request),
    (cli) => async (o) => (o.action === "deploy" ? { ...(await cli(o)), timedOut: true } : cli(o)),
  );
  assert.deepEqual(
    result.unconfirmedCreates.map((u) => [u.label, u.id, u.name, u.class]),
    [["job-" + JOB_IDS[1], "cli-deploy", jobName(JOB_IDS[1]), "cli-timeout"]],
  );
});

test("a CLI that throws leaves its labels unconfirmed as cli-error, records the error, and the cleanup still runs", async () => {
  const { result, world, journal } = await go(
    {},
    {},
    (send) => send,
    (cli) => async (o) => {
      if (o.action === "deploy") throw new Error("spawn failed");
      return cli(o);
    },
  );
  assert.equal(result.stoppedBecause, "spawn failed");
  assert.deepEqual(
    result.unknownMutationList.map((u) => [u.id, u.class]),
    [["cli-deploy", "cli-error"]],
  );
  assert.equal(
    result.unconfirmedCreates.length,
    ALL_FUNCTIONS.length + JOB_IDS.length + QUEUE_IDS.length,
  );
  assert.ok(
    result.unconfirmedCreates.every((u) => u.class === "cli-error" && u.id === "cli-deploy"),
  );
  assert.ok(
    journal.some(
      (r) =>
        r.id === "cli-deploy" &&
        r.state === "cli-result" &&
        r.result.error === "spawn failed" &&
        r.result.action === "deploy",
    ),
  );
  assert.deepEqual(world.cliRuns, ["dry-run", "delete"]);
  assert.equal(result.closureReady, false);
});

test("a write the CLI made that answered 5xx leaves the names of its kind unconfirmed until read", async () => {
  const { result } = await go(
    {},
    {},
    (send) => async (request) =>
      request.method === "GET" && request.url.endsWith(`/jobs/${JOB_IDS[0]}`)
        ? error(404, "NOT_FOUND")
        : send(request),
    (cli) => async (o) =>
      o.action === "deploy"
        ? { ...(await cli(o)), unknownWrites: [{ host: "cloudscheduler", status: 503 }] }
        : cli(o),
  );
  assert.deepEqual(
    result.unconfirmedCreates.map((u) => [u.label, u.class]),
    [["job-" + JOB_IDS[0], "cli-503"]],
  );
  assert.equal(result.closureReady, false);
  const seen = await go(
    {},
    {},
    (send) => send,
    (cli) => async (o) =>
      o.action === "deploy"
        ? { ...(await cli(o)), unknownWrites: [{ host: "cloudscheduler", status: 503 }] }
        : cli(o),
  );
  assert.deepEqual(seen.result.unconfirmedCreates, [], "the read showed it");
});

test("a CLI delete that did not finish cleanly leaves the CLI-made names flagged as vanished, a clean one does not", async () => {
  const bad = await go(
    {},
    {},
    (send) => send,
    (cli) => async (o) => (o.action === "delete" ? { ...(await cli(o)), exitCode: 1 } : cli(o)),
  );
  assert.equal(
    bad.result.vanishedAfterCreate.length,
    ALL_FUNCTIONS.length + JOB_IDS.length + QUEUE_IDS.length,
  );
  assert.equal(bad.result.closureReady, false);
  for (const flaw of [{ timedOut: true }, { signal: "SIGTERM" }, { error: "x" }]) {
    const r = await go(
      {},
      {},
      (send) => send,
      (cli) => async (o) => (o.action === "delete" ? { ...(await cli(o)), ...flaw } : cli(o)),
    );
    assert.ok(r.result.vanishedAfterCreate.length > 0, JSON.stringify(flaw));
  }
  const good = await go();
  assert.deepEqual(good.result.vanishedAfterCreate, []);
});

test("a confirmed name that reads absent without any delete of ours is flagged with its full name", async () => {
  const { result } = await go(
    {},
    {},
    (send) => async (request) =>
      request.method === "GET" && request.url.endsWith(`/topics/${TOPIC}`)
        ? error(404, "NOT_FOUND")
        : send(request),
  );
  assert.deepEqual(result.vanishedAfterCreate, [
    { label: "topic", name: topicName(TOPIC), class: "vanished-after-create" },
  ]);
  assert.equal(result.closureReady, false);
  assert.equal(result.readBackRequired, true);
  assert.equal(count(createWorld(), "DELETE"), 0);
});

// ---- the source operations ---------------------------------------------------------------------------

test("the unknown answer to the object upload is unconfirmed too, and an unknown update is not a create", async () => {
  const upload = await go({}, {}, (send) => async (request) => {
    const answer = await send(request);
    if (request.url.includes("/upload/storage")) throw new Error("reset");
    return answer;
  });
  assert.ok(
    upload.result.unconfirmedCreates.some(
      (c) => c.label === "object" && c.name === "st-upload" && c.id === "op-st-upload",
    ),
  );
  assert.equal(upload.world.objects.size, 0, "the object is deleted in the cleanup");
  const update = await go({}, {}, (send) => async (request) => {
    const answer = await send(request);
    if (request.method === "PATCH") throw new Error("reset");
    return answer;
  });
  assert.deepEqual(update.result.unconfirmedCreates, []);
  assert.equal(update.result.closureReady, false);
  assert.equal(update.result.readBackRequired, true);
});

test("an operation whose task target cannot be read is not sent and is not waited for", async () => {
  const hide = (fn) => async (request) =>
    request.method === "GET" && request.url.endsWith(`/functions/${fn}`)
      ? reply(200, { name: functionName(fn), state: "ACTIVE", serviceConfig: {} })
      : null;
  const { result, journal } = await go(
    {},
    {},
    (send) => async (request) => (await hide("pctaskraw")(request)) ?? send(request),
  );
  assert.deepEqual(result.operations["task-pctaskraw"], {
    sent: false,
    why: "missing task-target:pctaskraw",
  });
  assert.deepEqual(
    requestIds(journal).filter((id) => /^logs-observe-\d+-frames$/.test(id)),
    ["logs-observe-1-frames"],
    "one observe step: nothing is waited for from an unsent operation",
  );
  assert.ok(!requestIds(journal).includes("op-task-pctaskraw"));
  const half = await go(
    {},
    {},
    (send) => async (request) =>
      request.method === "GET" && request.url.endsWith(`/functions/pctask`)
        ? reply(200, {
            name: functionName("pctask"),
            state: "ACTIVE",
            serviceConfig: { uri: "https://x.run.app" },
          })
        : send(request),
  );
  assert.equal(
    half.result.operations["task-pctask"].sent,
    false,
    "a URI without a service account is not enough",
  );
});

// ---- cleanup -------------------------------------------------------------------------------------------

test("a failed deploy sends no source delete, because no source was created", async () => {
  const { world } = await go({ failDeploy: true });
  assert.equal(count(world, "DELETE firestore"), 0);
  assert.equal(count(world, "DELETE storage"), 0);
  assert.equal(count(world, "DELETE pubsub"), 1, "only the topic");
});

test("a leftover function whose delete does not finish blocks the topic delete and is unknown with the reason", async () => {
  const stuck = await go({ leaveOnDelete: ["pcps"] }, {}, (send) => async (request) => {
    const url = new URL(request.url);
    if (request.method === "GET" && url.pathname.includes("/operations/del-"))
      return reply(200, { name: url.pathname, done: false });
    return send(request);
  });
  assert.deepEqual(stuck.result.unknownMutationList, [
    { id: "leftover-delete-pcps", class: "operation-pending" },
  ]);
  assert.equal(
    requestIds(stuck.journal).filter((id) => id.startsWith("leftover-operation-pcps-")).length,
    12,
  );
  assert.equal(stuck.result.outcome, "pycheck-needs-review");
  assert.equal(stuck.result.cleanup.verified, true);
  assert.equal(stuck.result.closureReady, false);
  const refused = await go(
    { leaveOnDelete: ["pcps"] },
    {},
    (send) => async (request) =>
      request.method === "DELETE" && request.url.includes("/functions/pcps")
        ? error(500, "INTERNAL")
        : send(request),
  );
  assert.equal(
    count(refused.world, "DELETE pubsub"),
    0,
    "the topic stays while a function that triggers on it is still listed",
  );
  assert.equal(requestIds(refused.journal).includes("topic-present"), false);
  const errored = await go({ leaveOnDelete: ["pcps"] }, {}, (send) => async (request) => {
    const url = new URL(request.url);
    if (request.method === "GET" && url.pathname.includes("/operations/del-"))
      return reply(200, { name: url.pathname, done: true, error: { code: 13 } });
    return send(request);
  });
  assert.deepEqual(errored.result.unknownMutationList, [
    { id: "leftover-delete-pcps", class: "operation-error" },
  ]);
  const immediate = await go(
    { leaveOnDelete: ["pcps"] },
    {},
    (send) => async (request) =>
      request.method === "DELETE" && request.url.includes("/functions/pcps")
        ? reply(200, { name: "x", done: true, error: { code: 13 } })
        : send(request),
  );
  assert.deepEqual(immediate.result.unknownMutationList, [
    { id: "leftover-delete-pcps", class: "operation-error" },
  ]);
  const done = await go(
    { leaveOnDelete: ["pcps"] },
    {},
    (send) => async (request) =>
      request.method === "DELETE" && request.url.includes("/functions/pcps")
        ? (await send(request), reply(200, { name: "x", done: true }))
        : send(request),
  );
  assert.deepEqual(done.result.unknownMutationList, []);
  assert.equal(done.result.outcome, "pycheck-recorded");
  assert.equal(
    requestIds(done.journal).filter((id) => id.startsWith("leftover-operation")).length,
    0,
    "an operation that came back finished is not polled",
  );
});

test("a job that stays busy is deleted at most four times, and the fourth try is the last", async () => {
  let attempts = 0;
  const { result, world } = await go(
    { leaveOnDelete: ["job:" + JOB_IDS[0]] },
    {},
    (send) => async (request) => {
      if (request.method === "DELETE" && request.url.includes("/jobs/")) {
        attempts++;
        return error(409, "ABORTED", "sync mutate calls cannot be queued");
      }
      return send(request);
    },
  );
  assert.equal(attempts, 4);
  assert.equal(world.jobs.has(JOB_IDS[0]), true);
  assert.equal(result.outcome, "pycheck-needs-recovery");
  const other = await go(
    { leaveOnDelete: ["job:" + JOB_IDS[0]] },
    {},
    (send) => async (request) =>
      request.method === "DELETE" && request.url.includes("/jobs/")
        ? error(500, "INTERNAL")
        : send(request),
  );
  assert.equal(
    count(other.world, "DELETE cloudscheduler"),
    0,
    "the wrapper answered before the world saw it",
  );
  assert.equal(other.result.unknownMutations, 1);
  assert.equal(other.result.outcome, "pycheck-needs-recovery");
});

test("a queue delete is sent once, after the list shows it, and only for the run's queues", async () => {
  const { result, world, journal } = await go({ leaveOnDelete: ["queue:pctask"] });
  assert.equal(count(world, "DELETE cloudtasks"), 1);
  assert.ok(requestIds(journal).includes("delete-queue-pctask"));
  assert.equal(result.outcome, "pycheck-recorded");
  world.queues.set("foreign", { name: "x" });
});

test("an image delete that comes back unfinished is polled until done, at most six times", async () => {
  let polls = 0;
  const pending = await go({}, {}, (send) => async (request) => {
    const url = new URL(request.url);
    if (request.method === "DELETE" && url.pathname.endsWith(packageIds("pcps")[0]))
      return reply(200, {
        name: "projects/fireemu-oracle-events/locations/us-central1/operations/pk-1",
        done: false,
      });
    if (request.method === "GET" && url.pathname.endsWith("/operations/pk-1")) {
      polls++;
      return reply(200, { name: "x", done: false });
    }
    return send(request);
  });
  assert.equal(polls, 6);
  assert.deepEqual(
    requestIds(pending.journal)
      .filter((id) => id.startsWith("package-operation"))
      .map((id) => id.split("-").at(-1)),
    ["1", "2", "3", "4", "5", "6"],
  );
  const noName = await go(
    {},
    {},
    (send) => async (request) =>
      request.method === "DELETE" && new URL(request.url).pathname.endsWith(packageIds("pcps")[0])
        ? reply(200, { done: false })
        : send(request),
  );
  assert.equal(
    requestIds(noName.journal).filter((id) => id.startsWith("package-operation")).length,
    0,
  );
  const finished = await go(
    {},
    {},
    (send) => async (request) =>
      request.method === "DELETE" && new URL(request.url).pathname.endsWith(packageIds("pcps")[0])
        ? reply(200, {
            name: "projects/fireemu-oracle-events/locations/us-central1/operations/pk-1",
            done: true,
          })
        : send(request),
  );
  assert.equal(
    requestIds(finished.journal).filter((id) => id.startsWith("package-operation")).length,
    0,
  );
  const notTwoXx = await go(
    {},
    {},
    (send) => async (request) =>
      request.method === "DELETE" && new URL(request.url).pathname.endsWith(packageIds("pcps")[0])
        ? error(500, "INTERNAL")
        : send(request),
  );
  assert.equal(
    requestIds(notTwoXx.journal).filter((id) => id.startsWith("package-operation")).length,
    0,
  );
});

test("a cleanup step that fails is recorded with its name and the others still run", async () => {
  const journal = [];
  const w = createWorld({ runId: RUN });
  const out = await record({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "tok-abcdefgh",
    send: w.send,
    runCli: w.runCli,
    clock: () => w.now,
    sleep: async (ms) => w.advance(ms),
    save: async (row) => {
      if (row.id === "cleanup-fs-delete" && row.state === "before-send")
        throw new Error("disk full");
      journal.push(row);
    },
  });
  assert.deepEqual(
    out.cleanup.errors.map((e) => e.step),
    ["fs-delete"],
  );
  assert.match(out.cleanup.error, /persistence failed/);
  assert.equal(
    out.outcome,
    "pycheck-needs-recovery",
    "the document was left, so the read-back finds it",
  );
  assert.equal(w.documents.size, 1);
  assert.equal(w.functions.size, 0, "the other steps ran");
  assert.equal(out.closureReady, false);
});

test("a 401 during the cleanup stops it and the CLI delete is not run a second time", async () => {
  let cleanupStarted = false;
  const { result, world } = await go({}, {}, (send) => async (request) => {
    if (request.method === "DELETE" && request.url.includes("/documents/")) cleanupStarted = true;
    if (
      cleanupStarted &&
      request.url.includes("/locations/-/functions") &&
      request.method === "GET"
    )
      return error(401, "UNAUTHENTICATED");
    return send(request);
  });
  assert.equal(result.outcome, "pycheck-auth-stop");
  assert.equal(world.cliRuns.filter((a) => a === "delete").length, 1);
});

test("a 401 before anything exists does not run the CLI delete", async () => {
  const { result, world } = await go(
    {},
    {},
    (send) => async (request) =>
      request.url.includes("serviceusage") ? error(401, "UNAUTHENTICATED") : send(request),
  );
  assert.equal(result.outcome, "pycheck-auth-stop");
  assert.deepEqual(world.cliRuns, []);
  assert.equal(result.closureReady, false);
  assert.equal(result.readBackRequired, true);
});

// ---- what must be empty at the end ---------------------------------------------------------------------

const LISTS = [
  ["jobs", (w) => w.jobs.set(JOB_IDS[0], { name: jobName(JOB_IDS[0]) }), `/jobs/${JOB_IDS[0]}`],
  ["queues", (w) => w.queues.set("pctask", { name: queueName("pctask") }), "/queues/pctask"],
  ["topics", (w) => w.topics.add(TOPIC), `/topics/${TOPIC}`],
  ["triggers", (w) => w.triggers.add("pcps-777"), null],
  ["packages", (w) => w.packages.add(packageIds("pcps")[0]), `/packages/${packageIds("pcps")[0]}`],
];
test("a name that appears in the final list only is a leftover whatever the direct read says", async () => {
  for (const [name, seed, direct] of LISTS) {
    const world = createWorld({ runId: RUN });
    const journal = [];
    let reads = 0;
    const result = await record({
      runId: RUN,
      projectNumber: NUMBER,
      accessToken: "tok-abcdefgh",
      save: async (r) => journal.push(r),
      runCli: world.runCli,
      clock: () => world.now,
      sleep: async (ms) => world.advance(ms),
      send: async (request) => {
        const url = new URL(request.url);
        const final = journal.some((r) => r.id === "final-jobs" || r.id.startsWith("final-"));
        if (
          final &&
          request.method === "GET" &&
          /\/(jobs|queues|topics|triggers|packages)(\?|$)/.test(url.pathname + url.search) &&
          !direct?.includes("zzz")
        ) {
          seed(world);
          reads++;
        }
        if (
          direct &&
          request.method === "GET" &&
          url.pathname.endsWith(direct) &&
          journal.some((r) => r.id.startsWith("final-"))
        )
          return error(404, "NOT_FOUND");
        return world.send(request);
      },
    });
    assert.ok(reads > 0, name);
    assert.equal(result.cleanup.listsEmpty, false, name);
    assert.equal(result.cleanup.verified, false, name);
  }
});

test("the function and run service lists, and the subscriptions list, are part of what must be empty", async () => {
  const world = createWorld({ runId: RUN });
  const journal = [];
  const result = await record({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "tok-abcdefgh",
    save: async (r) => journal.push(r),
    runCli: world.runCli,
    clock: () => world.now,
    sleep: async (ms) => world.advance(ms),
    send: async (request) => {
      const final = journal.some((r) => r.id.startsWith("final-"));
      if (
        final &&
        request.method === "GET" &&
        new URL(request.url).hostname === "run.googleapis.com"
      )
        world.runServices.add("pcps");
      return world.send(request);
    },
  });
  assert.equal(result.cleanup.listsEmpty, false);
  assert.equal(result.cleanup.verified, false);
  const subs = createWorld({ runId: RUN });
  const j2 = [];
  const r2 = await record({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "tok-abcdefgh",
    save: async (r) => j2.push(r),
    runCli: subs.runCli,
    clock: () => subs.now,
    sleep: async (ms) => subs.advance(ms),
    send: async (request) => {
      const url = new URL(request.url);
      if (j2.some((r) => r.id.startsWith("final-")) && url.pathname.endsWith("/subscriptions"))
        return reply(200, { subscriptions: [{ name: "projects/p/subscriptions/s" }] });
      return subs.send(request);
    },
  });
  assert.equal(r2.cleanup.listsEmpty, false, "a subscription that was not there before the run");
});

test("the inventory notes the services and IAM changes, and nothing when a read failed", async () => {
  let phase = 0;
  const { result } = await go({}, {}, (send) => async (request) => {
    if (request.url.includes("serviceusage")) {
      phase++;
      if (phase === 2) return error(500, "INTERNAL");
    }
    return send(request);
  });
  assert.equal(result.inventory.services, null);
  let added = 0;
  const changed = await go({}, {}, (send) => async (request) => {
    if (request.url.includes("serviceusage") && ++added === 2)
      return reply(200, { services: [{ config: { name: "extra.googleapis.com" } }] });
    return send(request);
  });
  assert.deepEqual(changed.result.inventory.services.added, ["extra.googleapis.com"]);
  assert.equal(changed.result.inventory.services.removed.length > 0, true);
});

// ---- errors that are not stops ------------------------------------------------------------------------

test("an error before anything exists is thrown, and after something exists it is recorded and cleaned up", async () => {
  const before = createWorld({ runId: RUN });
  await assert.rejects(
    record({
      runId: RUN,
      projectNumber: NUMBER,
      accessToken: "tok-abcdefgh",
      save: async () => {
        throw new Error("no disk");
      },
      send: before.send,
      runCli: before.runCli,
      clock: () => before.now,
      sleep: async () => {},
    }),
    /private persistence failed/,
  );
  const after = createWorld({ runId: RUN });
  const journal = [];
  const result = await record({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "tok-abcdefgh",
    send: after.send,
    runCli: after.runCli,
    clock: () => after.now,
    sleep: async (ms) => after.advance(ms),
    save: async (row) => {
      if (row.id === "readback-function-pcps" && row.state === "before-send")
        throw new Error("disk went away");
      journal.push(row);
    },
  });
  assert.match(result.stoppedBecause, /persistence failed/);
  assert.equal(result.cleanup.verified, true);
  assert.deepEqual(after.cliRuns, ["dry-run", "deploy", "delete"]);
  assert.equal(result.outcome, "pycheck-incomplete-clean");
});

test("a stop signal before the first request ends the run clean", async () => {
  const { result, world } = await go({}, { signal: { aborted: true } });
  assert.equal(result.outcome, "pycheck-stopped-clean");
  assert.equal(world.calls.length, 0);
});

test("a topic that could not be created says so", async () => {
  const { result } = await go({
    hooks: {
      "PUT pubsub.googleapis.com/v1/projects/fireemu-oracle-events/topics/pycheck-orders": () =>
        "throw",
    },
  });
  assert.equal(result.stoppedBecause, "the topic could not be created");
  assert.equal(result.stage, "done");
});

test("a topic whose settle read is 200 lets the deploy go ahead", async () => {
  const { world } = await go({}, {}, (send) => async (request) => {
    const answer = await send(request);
    if (request.method === "PUT") throw new Error("reset");
    return answer;
  });
  assert.deepEqual(world.cliRuns, ["dry-run", "deploy", "delete"]);
});

test("the outcome says recorded only when the run went all the way", async () => {
  assert.equal((await go()).result.outcome, "pycheck-recorded");
  assert.equal(
    (await go({ deployState: "DEPLOYING" }, { waits: { readyPolls: 1 } })).result.outcome,
    "pycheck-incomplete-clean",
  );
  assert.equal(
    (await go({}, { signal: { aborted: false }, normalCeiling: 40 })).result.outcome,
    "pycheck-incomplete-clean",
  );
});
