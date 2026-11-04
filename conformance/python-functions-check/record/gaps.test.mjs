// What the second mutation pass still found alive, each pinned by a scenario that tells the mutant from the original.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { tempDir } from "./testtmp.mjs";
import { localChecks, main, realDeps, resultOf } from "./main.mjs";
import { SETTLE_MS } from "./readback.mjs";
import { ALL_FUNCTIONS, JOB_IDS, QUEUE_IDS, TOPIC, functionName, packageIds } from "./plan.mjs";
import { record } from "./run.mjs";
import { NUMBER, createWorld, reply } from "./world.mjs";

const RUN = "0123456789abcdef";
const error = (code, status) => reply(code, { error: { code, status, message: "x" } });
async function go(
  worldOptions = {},
  wrapSend = (send) => send,
  options = {},
  wrapCli = (cli) => cli,
) {
  const world = createWorld({ runId: RUN, ...worldOptions });
  const journal = [];
  const sleeps = [];
  const result = await record({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "tok-abcdefgh",
    save: async (row) => journal.push(row),
    send: wrapSend(world.send, world),
    runCli: wrapCli((o) => world.runCli(o), world),
    clock: () => world.now,
    sleep: async (ms) => (sleeps.push(ms), world.advance(ms)),
    ...options,
  });
  return { world, journal, sleeps, result };
}
const ids = (journal) => journal.filter((r) => r.state === "before-send").map((r) => r.id);
const count = (world, prefix) => world.calls.filter((c) => c.startsWith(prefix)).length;
const path = (request) => new URL(request.url).pathname;

// ---- answers that are not JSON, and boundaries of what counts as incomplete ---------------------------

test("a 200 that is not JSON is read as nothing, never as a crash, on every readback", async () => {
  for (const [name, match] of [
    ["function", (r) => r.method === "GET" && path(r).endsWith("/functions/pcps")],
    ["job", (r) => r.method === "GET" && path(r).endsWith(`/jobs/${JOB_IDS[0]}`)],
    ["queue", (r) => r.method === "GET" && path(r).endsWith("/queues/pctask")],
  ]) {
    let served = false;
    const { result } = await go({}, (send) => async (request) => {
      if (!served && match(request)) {
        served = true;
        return new Response("<html>", { status: 200 });
      }
      return send(request);
    });
    assert.equal(served, true, name);
    assert.equal(result.stoppedBecause, undefined, name);
    // A 200 whose body is not JSON is an unknown answer: the read is incomplete and the run does not close.
    assert.equal(result.outcome, "pycheck-needs-review", name);
    assert.ok(
      result.incompleteReads.some((r) => r.class === "unreadable"),
      name,
    );
    assert.equal(result.closureReady, false, name);
  }
  const noConfig = await go(
    {},
    (send) => async (request) =>
      request.url.endsWith("/adminSdkConfig")
        ? new Response("<html>", { status: 200 })
        : send(request),
  );
  assert.equal(noConfig.result.stoppedBecause, "admin-sdk-config");
  const noServices = await go(
    {},
    (send) => async (request) =>
      request.url.includes("serviceusage")
        ? new Response("<html>", { status: 200 })
        : send(request),
  );
  assert.equal(noServices.result.stoppedBecause, "services");
});

test("a read answered exactly 400 is incomplete, and an observing read answered 400 is not", async () => {
  const { result } = await go(
    {},
    (send) => async (request) =>
      request.method === "GET" && path(request).endsWith("/functions/pcps")
        ? error(400, "INVALID_ARGUMENT")
        : send(request),
  );
  assert.deepEqual(result.incompleteReads, [{ id: "readback-function-pcps", class: "4xx" }]);
  const observed = await go(
    {},
    (send) => async (request) =>
      request.method === "GET" && path(request).endsWith("/appengine-never")
        ? error(400, "X")
        : send(request),
  );
  assert.deepEqual(observed.result.incompleteReads, []);
});

test("page ids carry the page number, and no more than five pages are asked for", async () => {
  const lists = await go({ listPageSize: 7 });
  assert.ok(ids(lists.journal).includes("ready-1-functions-v2-page-2"));
  assert.ok(!ids(lists.journal).includes("ready-1-functions-v2-page-3"));
  const logs = await go({ logPageSize: 4 });
  assert.deepEqual(
    ids(logs.journal).filter((id) => id.startsWith("logs-observe-1-frames")),
    [
      "logs-observe-1-frames",
      "logs-observe-1-frames-page-2",
      "logs-observe-1-frames-page-3",
      "logs-observe-1-frames-page-4",
    ],
  );
  const many = await go({ logPageSize: 2 });
  const pages = ids(many.journal)
    .filter((id) => id.startsWith("logs-observe-1-frames-page-"))
    .map((id) => Number(id.split("-").at(-1)));
  assert.deepEqual(pages, [2, 3, 4, 5], "the sixth page is never asked for");
  const exactly = createWorld({ runId: RUN, logPageSize: 4 });
  for (let n = 0; n < 4; n++)
    exactly.entries.push({
      insertId: "pad-" + n,
      timestamp: new Date(exactly.now + 500).toISOString(),
      logName: "projects/p/logs/run.googleapis.com%2Fstdout",
      resource: {
        type: "cloud_run_revision",
        labels: { service_name: "pcps", location: "us-central1" },
      },
      textPayload: "PYCHECK_FRAME {",
    });
  const j = [];
  const r = await record({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "tok-abcdefgh",
    save: async (row) => j.push(row),
    send: exactly.send,
    runCli: exactly.runCli,
    clock: () => exactly.now,
    sleep: async (ms) => exactly.advance(ms),
  });
  assert.ok(
    r.incompleteReads.every((x) => x.class !== "more-than-five-pages"),
    "five pages are read to their end",
  );
});

test("each log window starts five seconds before the last one ended, whatever the clock does between them", async () => {
  const world = createWorld({ runId: RUN });
  const journal = [];
  let tick = 0;
  await record({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "tok-abcdefgh",
    save: async (r) => journal.push(r),
    send: world.send,
    runCli: world.runCli,
    clock: () => world.now + 1000 * tick++,
    sleep: async (ms) => world.advance(ms),
  });
  const filters = journal
    .filter((r) => r.state === "before-send" && /^logs-[a-z0-9-]+-frames$/.test(r.id))
    .map((r) => r.json.filter);
  const at = (filter, key) => Date.parse(new RegExp(`timestamp${key}"([^"]+)"`).exec(filter)[1]);
  assert.ok(filters.length >= 3);
  for (let i = 1; i < filters.length - 1; i++)
    assert.equal(at(filters[i], ">="), at(filters[i - 1], "<=") - 5000);
  assert.ok(at(filters[0], "<=") > at(filters[0], ">="));
});

test("the observe loop waits for every raw delivery, counting each one, and takes one step when the window is shorter than a poll", async () => {
  let frameReads = 0;
  const { journal } = await go({}, (send) => async (request) => {
    const response = await send(request);
    if (
      request.method === "POST" &&
      request.url.includes("entries:list") &&
      JSON.parse(request.body).filter.includes("PYCHECK_FRAME") &&
      !JSON.parse(request.body).filter.includes("severity")
    ) {
      frameReads++;
      if (frameReads === 2) {
        const body = await response.json();
        const kept = (body.entries ?? []).filter(
          (e) => !(e.textPayload.includes('"pcpsraw"') && e.textPayload.includes('"ordered"')),
        );
        return reply(200, kept.length ? { entries: kept } : {});
      }
    }
    return response;
  });
  assert.ok(
    ids(journal).includes("logs-observe-2-frames"),
    "the second pub/sub delivery was waited for",
  );
  const short = await go({ silent: ["pcschraw"] }, (send) => send, {
    waits: { window: 3, logPoll: 60 },
  });
  assert.deepEqual(
    ids(short.journal).filter((id) => /^logs-observe-\d+-frames$/.test(id)),
    ["logs-observe-1-frames"],
  );
});

// ---- the observing flag on reads that may be refused ----------------------------------------------------------

test("a 403 on the reads that observe is data: the topic settle and the topic-present read", async () => {
  const topicSettle = await go({}, (send) => async (request) => {
    if (request.method === "PUT" && request.url.includes("/topics/")) throw new Error("reset");
    if (request.method === "GET" && path(request).endsWith(`/topics/${TOPIC}`))
      return error(403, "PERMISSION_DENIED");
    return send(request);
  });
  assert.equal(topicSettle.result.stoppedBecause, "the topic could not be created");
  assert.notEqual(topicSettle.result.outcome, "pycheck-auth-stop");
  const world = createWorld({ runId: RUN });
  const journal = [];
  const result = await record({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "tok-abcdefgh",
    save: async (row) => journal.push(row),
    runCli: world.runCli,
    clock: () => world.now,
    sleep: async (ms) => world.advance(ms),
    send: async (request) => {
      if (
        request.method === "GET" &&
        path(request).endsWith(`/topics/${TOPIC}`) &&
        journal.some((r) => r.id === "cleanup-1-functions-v2")
      )
        return error(403, "PERMISSION_DENIED");
      return world.send(request);
    },
  });
  assert.notEqual(result.outcome, "pycheck-auth-stop");
  assert.equal(count(world, "DELETE pubsub"), 0, "the topic is not deleted when it cannot be seen");
});

test("a 403 on a leftover function's operation read and on an image's operation read is data, not a stop", async () => {
  const op = await go(
    { leaveOnDelete: ["pcps"] },
    (send) => async (request) =>
      request.method === "GET" && path(request).includes("/operations/del-")
        ? error(403, "PERMISSION_DENIED")
        : send(request),
  );
  assert.notEqual(op.result.outcome, "pycheck-auth-stop");
  assert.equal(op.result.unknownMutationList.length, 1);
  const pkg = await go({}, (send) => async (request) => {
    if (request.method === "DELETE" && path(request).endsWith(packageIds("pcps")[0])) {
      await send(request);
      return reply(200, {
        name: "projects/fireemu-oracle-events/locations/us-central1/operations/pk-1",
        done: false,
      });
    }
    if (request.method === "GET" && path(request).endsWith("/operations/pk-1"))
      return error(403, "PERMISSION_DENIED");
    return send(request);
  });
  assert.notEqual(pkg.result.outcome, "pycheck-auth-stop");
});

// ---- unconfirmed names, labelled and listed ---------------------------------------------------------------

test("the names of an unconfirmed CLI deploy are the full set, each with its label", async () => {
  const { result } = await go(
    {},
    (send) => send,
    {},
    (cli) => async (o) => {
      if (o.action === "deploy") throw new Error("spawn failed");
      return cli(o);
    },
  );
  const expected = [
    ...ALL_FUNCTIONS.map((fn) => "function-" + fn),
    ...JOB_IDS.map((id) => "job-" + id),
    ...QUEUE_IDS.map((id) => "queue-" + id),
  ];
  assert.deepEqual(result.unconfirmedCreates.map((u) => u.label).toSorted(), expected.toSorted());
  assert.deepEqual(
    result.unconfirmedCreates.map((u) => u.name).toSorted(),
    [
      ...ALL_FUNCTIONS.map(functionName),
      ...JOB_IDS.map((id) => `projects/fireemu-oracle-events/locations/us-central1/jobs/${id}`),
      ...QUEUE_IDS.map((id) => `projects/fireemu-oracle-events/locations/us-central1/queues/${id}`),
    ].toSorted(),
  );
});

test("a list that shows a name settles it, even when the direct reads were refused", async () => {
  const { result } = await go(
    {},
    (send) => async (request) =>
      request.method === "GET" && /\/functions\/[a-z]+$/.test(path(request))
        ? error(404, "NOT_FOUND")
        : send(request),
    {},
    (cli) => async (o) => (o.action === "deploy" ? { ...(await cli(o)), timedOut: true } : cli(o)),
  );
  assert.deepEqual(result.unconfirmedCreates, []);
  assert.ok(result.incompleteReads.length > 0);
});

test("a write the CLI made that answered 5xx asks for the read-back even when nothing else is open", async () => {
  const { result } = await go(
    {},
    (send) => async (request) =>
      request.method === "GET" && path(request).endsWith(`/jobs/${JOB_IDS[0]}`)
        ? error(404, "NOT_FOUND")
        : send(request),
    {},
    (cli) => async (o) =>
      o.action === "deploy"
        ? { ...(await cli(o)), unknownWrites: [{ host: "cloudscheduler", status: 503 }] }
        : cli(o),
  );
  assert.equal(result.unconfirmedCreates.length, 1);
  assert.equal(result.readBackRequired, true);
});

test("an unknown answer to a later operation is not a create when the object upload was refused", async () => {
  const { result } = await go({}, (send) => async (request) => {
    if (request.url.includes("/upload/storage")) return error(400, "INVALID_ARGUMENT");
    if (request.url.endsWith(":publishEvents")) {
      await send(request);
      throw new Error("reset");
    }
    return send(request);
  });
  assert.deepEqual(result.unconfirmedCreates, []);
  assert.ok(result.unknownMutationList.length >= 1);
});

test("a name that vanishes alone, with nothing else open, asks for the read-back and blocks the close", async () => {
  const { result } = await go({}, (send, world) => async (request) => {
    if (
      request.method === "GET" &&
      path(request).endsWith(`/topics/${TOPIC}`) &&
      world.functions.size === 0
    ) {
      world.topics.delete(TOPIC);
      return error(404, "NOT_FOUND");
    }
    return send(request);
  });
  assert.deepEqual(
    result.vanishedAfterCreate.map((v) => v.label),
    ["topic"],
  );
  assert.equal(result.cleanup.verified, true);
  assert.equal(result.closureReady, false);
  assert.equal(result.readBackRequired, true);
  assert.equal(result.unknownMutations, 0);
  assert.deepEqual(result.unconfirmedCreates, []);
});

test("an own delete of the document that answered unknown, after the delete took effect, is flagged as vanished", async () => {
  const { result } = await go({}, (send) => async (request) => {
    if (request.method === "DELETE" && request.url.includes("/documents/")) {
      await send(request);
      return error(503, "UNAVAILABLE");
    }
    return send(request);
  });
  assert.deepEqual(
    result.vanishedAfterCreate.map((v) => v.label),
    ["document"],
  );
  const object = await go({}, (send) => async (request) => {
    if (request.method === "DELETE" && request.url.includes("/storage/v1/b/")) {
      await send(request);
      return error(503, "UNAVAILABLE");
    }
    return send(request);
  });
  assert.deepEqual(
    object.result.vanishedAfterCreate.map((v) => v.label),
    ["object"],
  );
});

test("names the REST cleanup deleted are not vanished when the CLI delete was not clean, the others are", async () => {
  const { result } = await go(
    { leaveOnDelete: ["pcps", "job:" + JOB_IDS[0], "queue:pctask"] },
    (send) => send,
    {},
    (cli) => async (o) => (o.action === "delete" ? { ...(await cli(o)), exitCode: 1 } : cli(o)),
  );
  const flagged = result.vanishedAfterCreate.map((v) => v.label);
  assert.ok(
    !flagged.includes("function-pcps") &&
      !flagged.includes("job-" + JOB_IDS[0]) &&
      !flagged.includes("queue-pctask"),
    flagged.join(),
  );
  assert.equal(flagged.length, ALL_FUNCTIONS.length + JOB_IDS.length + QUEUE_IDS.length - 3);
});

// ---- the cleanup, step by step -------------------------------------------------------------------------

test("each cleanup step that fails is named, the rest run, and the cleanup is not verified", async () => {
  const pkg = packageIds("pcps")[0];
  for (const [id, step, options] of [
    ["leftover-delete-pcps", "leftover-pcps", { leaveOnDelete: ["pcps"] }],
    [`delete-job-0-${JOB_IDS[0]}`, "job-" + JOB_IDS[0], { leaveOnDelete: ["job:" + JOB_IDS[0]] }],
    ["delete-queue-pctask", "queue-pctask", { leaveOnDelete: ["queue:pctask"] }],
    [`delete-package-${pkg}`, "package-" + pkg, {}],
    ["readback-gone-function-pcps", "readback-function-pcps", {}],
    ["final-jobs", "final-lists", {}],
  ]) {
    const world = createWorld({ runId: RUN, ...options });
    const result = await record({
      runId: RUN,
      projectNumber: NUMBER,
      accessToken: "tok-abcdefgh",
      runCli: world.runCli,
      clock: () => world.now,
      sleep: async (ms) => world.advance(ms),
      send: world.send,
      save: async (row) => {
        if (row.id === id && row.state === "before-send") throw new Error("disk full");
      },
    });
    assert.deepEqual(
      result.cleanup.errors.map((e) => e.step),
      [step],
      id,
    );
    assert.equal(result.cleanup.verified, false, id);
    assert.equal(result.closureReady, false, id);
  }
});

test("a stop signal does not stop the cleanup: every kind of cleanup request is sent after it", async () => {
  const signal = { aborted: false };
  const { result, world } = await go(
    { leaveOnDelete: ["pcps", "job:" + JOB_IDS[0], "queue:pctask"] },
    (send) => async (request) => {
      if (request.url.endsWith(":publishEvents")) signal.aborted = true;
      if (request.method === "DELETE" && path(request).endsWith(packageIds("pcps")[0])) {
        await send(request);
        return reply(200, {
          name: "projects/fireemu-oracle-events/locations/us-central1/operations/pk-1",
          done: false,
        });
      }
      return send(request);
    },
    { signal },
  );
  assert.equal(result.cleanup.errors, undefined);
  assert.equal(result.cleanup.verified, true);
  assert.equal(
    world.functions.size +
      world.jobs.size +
      world.queues.size +
      world.topics.size +
      world.packages.size,
    0,
  );
});

test("a function that is still listed after its delete is polled up to four times, thirty seconds apart", async () => {
  for (const stale of [2, 9]) {
    let deleted = null;
    let served = 0;
    const { journal, sleeps, result } = await go(
      { leaveOnDelete: ["pcps"] },
      (send, world) => async (request) => {
        if (request.method === "DELETE" && path(request).endsWith("/functions/pcps"))
          deleted = structuredClone(world.functions.get(functionName("pcps")));
        const response = await send(request);
        if (
          deleted &&
          request.method === "GET" &&
          path(request).endsWith("/locations/-/functions") &&
          served < stale
        ) {
          served++;
          const body = await response.json();
          return reply(200, { functions: [...(body.functions ?? []), deleted] });
        }
        return response;
      },
    );
    const polls = ids(journal).filter(
      (id) => id.startsWith("after-leftovers-") && id.endsWith("-functions-v2"),
    );
    assert.deepEqual(
      polls,
      Array.from(
        { length: Math.min(stale + 1, 4) },
        (_, n) => `after-leftovers-${n + 1}-functions-v2`,
      ),
      "stale " + stale,
    );
    assert.equal(
      sleeps.filter((ms) => ms === 30_000).length,
      6 + Math.min(stale, 4),
      "stale " + stale,
    );
    assert.equal(result.cleanup.functionsGone, stale < 4);
  }
});

test("a 401 in the middle of the cleanup is the last request", async () => {
  const world = createWorld({ runId: RUN });
  const journal = [];
  let requestsAfter = 0;
  let fired = false;
  const result = await record({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "tok-abcdefgh",
    save: async (row) => journal.push(row),
    runCli: world.runCli,
    clock: () => world.now,
    sleep: async (ms) => world.advance(ms),
    send: async (request) => {
      if (fired) requestsAfter++;
      if (
        !fired &&
        request.method === "GET" &&
        path(request).endsWith("/locations/-/functions") &&
        journal.some((r) => r.id === "cleanup-st-delete")
      ) {
        fired = true;
        return error(401, "UNAUTHENTICATED");
      }
      return world.send(request);
    },
  });
  assert.equal(result.outcome, "pycheck-auth-stop");
  assert.equal(requestsAfter, 0);
});

test("an error after the topic exists but before the deploy is recorded and the topic is cleaned up", async () => {
  const world = createWorld({ runId: RUN });
  const result = await record({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "tok-abcdefgh",
    runCli: world.runCli,
    clock: () => world.now,
    sleep: async (ms) => world.advance(ms),
    send: world.send,
    save: async (row) => {
      if (row.id === "issue-function-pcfsc") throw new Error("disk full");
    },
  });
  assert.equal(result.stoppedBecause, "disk full");
  assert.equal(world.topics.size, 0, "the topic was deleted");
  assert.equal(result.cleanup.verified, true);
  assert.equal(
    result.outcome,
    "pycheck-incomplete-clean",
    "something was created, so this is not a stop before anything exists",
  );
});

// ---- the command line ----------------------------------------------------------------------------------

test("a missing flag, or a bad value, is the only problem reported", () => {
  const full = {
    "run-dir": "x",
    "project-number": "123456789012",
    "source-commit": "a".repeat(40),
    "venv-dir": "/v",
    node: "n",
    "firebase-js": "f",
  };
  const deps = {
    nodeVersion: () => "22.22.1",
    firebaseToolsVersion: () => "15.28.2",
    gitHead: () => "a".repeat(40),
    gitDirty: () => false,
    adcExists: () => true,
    sdkProblems: () => [],
  };
  const forbidden = Object.fromEntries(
    Object.keys(deps).map((name) => [
      name,
      () => assert.fail(name + " must not be called before the arguments are valid"),
    ]),
  );
  const only = (over, env = { HOME: "/h" }) =>
    localChecks({ values: { ...full, ...over }, env, deps: forbidden });
  assert.deepEqual(only({ "venv-dir": undefined }), ["--venv-dir is required"]);
  assert.deepEqual(only({ "project-number": undefined }), ["--project-number is required"]);
  assert.deepEqual(only({ "source-commit": undefined }), ["--source-commit is required"]);
  assert.deepEqual(only({ "project-number": "1" }), ["--project-number is 12 or 13 digits"]);
  assert.deepEqual(only({}, {}), ["HOME is not set"]);
  assert.deepEqual(only({ "source-commit": "x" }), ["--source-commit is a full SHA"]);
});

test("the result file's own error names the reason", () => {
  const d = tempDir("pc-gap-");
  assert.equal(resultOf(join(d, "missing")).why, "the run's result file cannot be read (ENOENT)");
  writeFileSync(join(d, "bad"), "{");
  assert.equal(resultOf(join(d, "bad")).why, "the run's result file cannot be read (not JSON)");
  writeFileSync(join(d, "empty"), "{}");
  assert.equal(
    resultOf(join(d, "empty")).why,
    "the run's result has no list of unconfirmed creates",
  );
});

test("the working tree check agrees with git, and the read-back's messages and header are exact", async () => {
  const here = dirname(fileURLToPath(import.meta.url));
  const git =
    execFileSync("git", ["status", "--porcelain", "--ignored=no"], {
      encoding: "utf8",
      cwd: here,
    }).trim() !== "";
  assert.equal(realDeps.gitDirty(), git);
  const d = tempDir("pc-gap-");
  const at = Date.parse("2026-11-05T00:00:00Z");
  writeFileSync(
    join(d, `journal-${RUN}.jsonl`),
    JSON.stringify({ dispatchAt: new Date(at).toISOString() }) + "\n",
  );
  const out = [];
  const err = [];
  const deps = {
    token: () => "tok-abcdefgh",
    readback: async () => ({ allAbsent: true, attempted: 0, unknown: 0 }),
    now: () => at + 599_000,
  };
  const argv = [
    "readback",
    "--run-dir",
    d,
    "--project-number",
    "123456789012",
    "--run-id",
    RUN,
    "--send",
    "--expect-digest",
    "d".repeat(64),
  ];
  const code = await main(argv, {
    env: { HOME: "/h" },
    deps,
    out: (m) => out.push(m),
    err: (m) => err.push(m),
    digest: "d".repeat(64),
  });
  assert.equal(code, 2);
  assert.equal(
    err[0],
    `the last request of run ${RUN} was 599 seconds ago; wait until ten minutes have passed`,
  );
  assert.equal(
    out[0],
    JSON.stringify(
      {
        project: "fireemu-oracle-events",
        command: "readback",
        maxRequests: 130,
        packetDigest: "d".repeat(64),
      },
      null,
      2,
    ),
  );
  writeFileSync(
    join(d, `result-${RUN}.json`),
    JSON.stringify({ unconfirmedCreates: [], bucket: "b" }),
  );
  const long = await main(
    [
      "readback",
      "--run-dir",
      d,
      "--project-number",
      "1234567890123",
      "--run-id",
      RUN,
      "--send",
      "--expect-digest",
      "d".repeat(64),
    ],
    {
      env: { HOME: "/h" },
      deps: { ...deps, now: () => at + SETTLE_MS + 5000 },
      out: () => {},
      err: (m) => err.push(m),
      digest: "d".repeat(64),
    },
  );
  assert.equal(long, 0);
  const tooLong = await main(
    ["readback", "--run-dir", d, "--project-number", "12345678901234", "--run-id", RUN],
    { env: { HOME: "/h" }, deps, out: () => {}, err: (m) => err.push(m), digest: "d".repeat(64) },
  );
  assert.equal(tooLong, 2);
  assert.match(err.at(-1), /--project-number is 12 or 13 digits/);
});
