// The second presend review's findings (r2 delta), replayed against the in-memory world: a confirmed create that
// vanishes without an own 2xx delete stays unsettled (M1-r2), the read-back never closes an unconfirmed create
// (M2-r2), a refresh that fails sends and journals nothing (S1-r2), the CLI's end time counts for the ten-minute
// guard (S2-r2), a run that cannot close is not labelled recorded (S3-r2), and the read-back looks at the
// subscriptions Google puts on the v1 topics (S4-r2). Every case has a near miss that must still close.
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { lastActivity, main } from "./main.mjs";
import {
  ALL_FUNCTIONS,
  FUNCTIONS,
  extraJobId,
  functionName,
  jobName,
  pullSubscriptionId,
  scheduleId,
  subscriptionName,
  topicName,
} from "./plan.mjs";
import { SETTLE_MS, readbackRun } from "./readback.mjs";
import { record } from "./run.mjs";
import { NUMBER, START, createWorld, reply } from "./world.mjs";

const RUN = "0123456789abcdef";
const SHORT = { passes: 1, naturalWindowMs: 60_000 };
const PUBSUB = "pubsub.googleapis.com/v1/projects/fireemu-oracle-sbx";
const JOBS =
  "cloudscheduler.googleapis.com/v1/projects/fireemu-oracle-sbx/locations/us-central1/jobs";
const SUB1 = pullSubscriptionId(RUN, "schedFailV1");
const SUB1_URL = `${PUBSUB}/subscriptions/${SUB1}`;
const notFound = (what) =>
  reply(404, { error: { code: 404, message: what + " not found", status: "NOT_FOUND" } });
const unavailable = () => reply(503, { error: { code: 503, message: "x", status: "UNAVAILABLE" } });

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

// ---- M1-r2: a confirmed create that disappears without an own 2xx delete -----------------------------------

test("a confirmed subscription whose own DELETE answers 404 and then reads 404 stays unsettled (probe A)", async () => {
  const { result } = await go({
    hooks: {
      ["DELETE " + SUB1_URL]: async ({ w }) => {
        w.subs.delete(subscriptionName(SUB1));
        return notFound("subscription");
      },
    },
  });
  assert.deepEqual(labels(result.vanishedAfterCreate), ["subscription-schedFailV1"]);
  assert.equal(result.vanishedAfterCreate[0].class, "vanished-after-create");
  assert.equal(result.closureReady, false);
  assert.equal(result.readBackRequired, true);
  assert.equal(result.outcome, "calendar-delivery-needs-review");
  assert.equal(result.cleanup.verified, true, "the names are gone; what is open is how they went");
  assert.deepEqual(result.unconfirmedCreates, []);
});

test("near miss: the same subscription deleted with a 2xx closes the run", async () => {
  const { result } = await go();
  assert.deepEqual(result.vanishedAfterCreate, []);
  assert.deepEqual(result.unconfirmedCreates, []);
  assert.equal(result.closureReady, true);
  assert.equal(result.readBackRequired, false);
  assert.equal(result.outcome, "calendar-delivery-recorded");
});

test("a confirmed extra job missing from the cleanup list, never deleted, reading 404, stays unsettled (probe B)", async () => {
  const extra = extraJobId(RUN, "count");
  const { result, world } = await go({
    hooks: {
      ["GET " + JOBS]: async ({ w }) => {
        if (w.cliRuns.includes("delete"))
          for (const id of w.jobs.keys()) if (id.startsWith("fe-sd-")) w.jobs.delete(id);
        return undefined;
      },
    },
  });
  assert.equal(
    world.calls.some(
      (c) =>
        c ===
        "DELETE cloudscheduler.googleapis.com/v1/projects/fireemu-oracle-sbx/locations/us-central1/jobs/" +
          extra,
    ),
    false,
    "the run never deleted it",
  );
  assert.ok(labels(result.vanishedAfterCreate).includes("job-" + extra));
  assert.equal(result.closureReady, false);
  assert.equal(result.readBackRequired, true);
  assert.equal(result.outcome, "calendar-delivery-needs-review");
});

test("near miss: a confirmed extra job that the list holds and the run deletes with a 2xx closes", async () => {
  const { result, world } = await go();
  assert.ok(world.creates.includes(extraJobId(RUN, "count")));
  assert.deepEqual(result.vanishedAfterCreate, []);
  assert.equal(result.closureReady, true);
});

test("CLI-made names that went without a clean CLI delete or an own 2xx delete stay unsettled; a clean CLI delete settles them", async () => {
  const dirtyDelete = async (o, w) => {
    const real = await w.runCli(o);
    return o.action === "delete" ? { ...real, exitCode: 1, errored: 2 } : real;
  };
  const dirty = await go({}, {}, dirtyDelete);
  const names = labels(dirty.result.vanishedAfterCreate);
  for (const fn of ALL_FUNCTIONS) {
    assert.ok(names.includes("function-" + fn), fn);
    assert.ok(names.includes("job-" + scheduleId(fn)), fn);
  }
  for (const fn of FUNCTIONS.v1) assert.ok(names.includes("topic-" + fn), fn);
  assert.equal(
    names.some((n) => n.startsWith("subscription-") || n.includes("fe-sd-")),
    false,
    "the REST names were deleted by the run with a 2xx",
  );
  assert.equal(dirty.result.closureReady, false);
  const clean = await go();
  assert.deepEqual(clean.result.vanishedAfterCreate, []);
});

test("a leftover function deleted through REST with a 2xx is the run's own delete, the others are not", async () => {
  const dirtyDelete = async (o, w) => {
    const real = await w.runCli(o);
    if (o.action !== "delete") return real;
    w.functionsV2.set(functionName("declNullV2"), {
      name: functionName("declNullV2"),
      state: "ACTIVE",
      environment: "GEN_2",
    });
    w.runServices.add("declnullv2");
    return { ...real, exitCode: 1, errored: 1 };
  };
  const { result } = await go({}, {}, dirtyDelete);
  const names = labels(result.vanishedAfterCreate);
  assert.equal(names.includes("function-declNullV2"), false);
  assert.ok(names.includes("function-schedRetryV2"));
});

test("a v1 topic the CLI delete left and the run deleted with a 2xx is the run's own delete; a 404 answer to that DELETE is not", async () => {
  const topic = scheduleId("schedFailV1");
  const leaveTopic = async (o, w) => {
    const real = await w.runCli(o);
    if (o.action !== "delete") return real;
    w.topics.add(topic);
    return { ...real, exitCode: 1, errored: 1 };
  };
  const own = await go({}, {}, leaveTopic);
  assert.equal(labels(own.result.vanishedAfterCreate).includes("topic-schedFailV1"), false);
  assert.ok(labels(own.result.vanishedAfterCreate).includes("topic-schedRetryV1"));
  const gone = await go(
    {
      hooks: {
        ["DELETE " + PUBSUB + "/topics/" + topic]: async ({ w }) => {
          w.topics.delete(topic);
          return notFound("topic");
        },
      },
    },
    {},
    leaveTopic,
  );
  assert.ok(labels(gone.result.vanishedAfterCreate).includes("topic-schedFailV1"));
});

// ---- M2-r2: unconfirmed unknown creates ---------------------------------------------------------------------

test("a subscription PUT that answers 503 and whose settle read answers 404 is unconfirmed, not settled (probe C)", async () => {
  const { result } = await go({ hooks: { ["PUT " + SUB1_URL]: async () => unavailable() } });
  assert.deepEqual(result.unconfirmedCreates, [
    {
      label: "subscription-schedFailV1",
      id: "create-subscription-schedFailV1",
      name: subscriptionName(SUB1),
      class: "unknown-status",
    },
  ]);
  assert.equal(result.closureReady, false);
  assert.equal(result.readBackRequired, true);
  assert.equal(result.outcome, "calendar-delivery-needs-review");
});

test("near miss: the same 503 whose settle read is a 2xx showing the name is confirmed (and stays an unknown answer)", async () => {
  const { result } = await go({
    hooks: {
      ["PUT " + SUB1_URL]: async ({ w, body }) => {
        w.subs.set(subscriptionName(SUB1), { topic: body.topic, queue: [] });
        return unavailable();
      },
    },
  });
  assert.deepEqual(result.unconfirmedCreates, []);
  assert.equal(result.unknownMutations, 1);
  assert.equal(result.readBackRequired, true);
  assert.equal(result.closureReady, false);
  assert.equal(result.cleanup.verified, true, "the confirmed name was deleted with a 2xx");
});

test("a 200 settle read that names something else does not confirm", async () => {
  const { result } = await go({
    hooks: {
      ["PUT " + SUB1_URL]: async () => unavailable(),
      ["GET " + SUB1_URL]: async () =>
        reply(200, { name: "projects/fireemu-oracle-sbx/subscriptions/other" }),
    },
  });
  assert.deepEqual(labels(result.unconfirmedCreates), ["subscription-schedFailV1"]);
});

test("a refused create (400) is neither unknown nor unconfirmed", async () => {
  const { result } = await go({
    hooks: {
      ["PUT " + SUB1_URL]: async () =>
        reply(400, { error: { code: 400, message: "x", status: "INVALID_ARGUMENT" } }),
    },
  });
  assert.deepEqual(result.unconfirmedCreates, []);
  assert.equal(result.unknownMutations, 0);
  assert.equal(result.closureReady, true);
});

test("an extra job POST that answers 503 and reads 404 is unconfirmed; a later 2xx list naming it confirms it", async () => {
  const extra = extraJobId(RUN, "double1");
  const key = "POST " + JOBS;
  const unconfirmed = await go({
    hooks: {
      [key]: async ({ body }) => (body.name.endsWith(extra) ? unavailable() : undefined),
    },
  });
  assert.deepEqual(unconfirmed.result.unconfirmedCreates, [
    {
      label: "job-" + extra,
      id: "create-extra-double1",
      name: jobName(extra),
      class: "unknown-status",
    },
  ]);
  assert.equal(unconfirmed.result.closureReady, false);
  const listed = await go({
    hooks: {
      [key]: async ({ w, body }) => {
        if (!body.name.endsWith(extra)) return undefined;
        w.jobs.set(extra, { ...body, state: "ENABLED", manualOnly: true });
        return unavailable();
      },
      // The settle read answers 404, as a lagging read would; the cleanup list names the job.
      ["GET " + JOBS + "/" + extra]: async ({ w }) =>
        w.cliRuns.includes("delete") ? undefined : notFound("job"),
    },
  });
  assert.deepEqual(listed.result.unconfirmedCreates, []);
});

const timedOutDeploy = (keep) => async (o, w) => {
  const real = await w.runCli(o);
  if (o.action !== "deploy") return real;
  keep?.(w);
  return { ...real, exitCode: null, signal: "SIGTERM", timedOut: true, errored: null };
};

test("a timed-out deploy leaves unconfirmed exactly the CLI names no own 2xx read showed", async () => {
  const { result } = await go(
    {},
    {},
    timedOutDeploy((w) => {
      w.jobs.clear();
      w.topics.clear();
    }),
  );
  assert.deepEqual(
    labels(result.unconfirmedCreates),
    [
      ...ALL_FUNCTIONS.map((fn) => "job-" + scheduleId(fn)),
      ...FUNCTIONS.v1.map((fn) => "topic-" + fn),
    ].toSorted(),
  );
  assert.deepEqual(
    result.unconfirmedCreates.toSorted((a, b) => a.label.localeCompare(b.label)),
    [
      ...ALL_FUNCTIONS.map((fn) => ["job-" + scheduleId(fn), jobName(scheduleId(fn))]),
      ...FUNCTIONS.v1.map((fn) => ["topic-" + fn, topicName(scheduleId(fn))]),
    ]
      .toSorted((a, b) => a[0].localeCompare(b[0]))
      .map(([label, name]) => ({ label, id: "cli-deploy", name, class: "cli-timeout" })),
  );
  assert.equal(result.closureReady, false);
});

test("two unknown creates in one run are both listed", async () => {
  const sub2 = pullSubscriptionId(RUN, "schedRetryV1");
  const { result } = await go({
    hooks: {
      ["PUT " + SUB1_URL]: async () => unavailable(),
      ["PUT " + PUBSUB + "/subscriptions/" + sub2]: async () => unavailable(),
    },
  });
  assert.deepEqual(labels(result.unconfirmedCreates), [
    "subscription-schedFailV1",
    "subscription-schedRetryV1",
  ]);
  const extras = await go({
    hooks: { ["POST " + JOBS]: async () => unavailable() },
  });
  assert.deepEqual(
    extras.result.unconfirmedCreates.map((c) => c.id),
    ["create-extra-count", "create-extra-double0", "create-extra-double1", "create-extra-double3"],
  );
});

test("a CLI deploy that cannot even be run leaves every CLI-made name unconfirmed as cli-error; a delete that cannot be run does not", async () => {
  const names = [
    ...ALL_FUNCTIONS.flatMap((fn) => ["function-" + fn, "job-" + scheduleId(fn)]),
    ...FUNCTIONS.v1.map((fn) => "topic-" + fn),
  ].toSorted();
  const deployThrows = await go({}, {}, async (o, w) => {
    if (o.action === "deploy") throw new Error("spawn failed");
    return w.runCli(o);
  });
  assert.deepEqual(labels(deployThrows.result.unconfirmedCreates), names);
  assert.ok(
    deployThrows.result.unconfirmedCreates.every(
      (c) => c.class === "cli-error" && c.id === "cli-deploy",
    ),
  );
  assert.equal(deployThrows.result.closureReady, false);
  const deleteThrows = await go({}, {}, async (o, w) => {
    if (o.action === "delete") throw new Error("spawn failed");
    return w.runCli(o);
  });
  assert.deepEqual(deleteThrows.result.unconfirmedCreates, []);
});

test("a name that a list showed before the run issued it is no evidence about its create", async () => {
  const extra = extraJobId(RUN, "count");
  const real =
    "cloudscheduler.googleapis.com/v1/projects/fireemu-oracle-sbx/locations/us-central1/jobs/";
  const { result } = await go(
    {
      hooks: {
        // the create is unknown, its direct reads say 404, and the later lists no longer hold it
        ["POST " + JOBS]: async ({ body }) =>
          body.name.endsWith(extra) ? unavailable() : undefined,
        ["GET " + real + extra]: async () => notFound("job"),
        ["GET " + JOBS]: async ({ w }) => {
          if (w.cliRuns.includes("delete")) w.jobs.delete(extra);
          return undefined;
        },
      },
    },
    {},
    async (o, w) => {
      const done = await w.runCli(o);
      // a job of that name exists when the readbacks list the jobs, before the run issues it
      if (o.action === "deploy")
        w.jobs.set(extra, { name: jobName(extra), state: "ENABLED", manualOnly: true });
      return done;
    },
  );
  assert.deepEqual(labels(result.unconfirmedCreates), ["job-" + extra]);
});

test("near miss: a timed-out deploy whose every name was read 200 has nothing unconfirmed (and is still an unknown answer)", async () => {
  const { result } = await go({}, {}, timedOutDeploy());
  assert.deepEqual(result.unconfirmedCreates, []);
  assert.ok(result.unknownMutationList.some((u) => u.class === "cli-timeout"));
  assert.equal(result.readBackRequired, true);
});

test("a deploy that failed cleanly (non-zero exit, no timeout) leaves nothing unconfirmed", async () => {
  const { result } = await go({ failDeploy: true });
  assert.deepEqual(result.unconfirmedCreates, []);
  assert.equal(result.outcome, "calendar-delivery-incomplete-clean");
});

// ---- M2-r2: the read-back command ----------------------------------------------------------------------------

const DIGEST = "d".repeat(64);
const ENV = { HOME: "/home/test", PATH: "/usr/bin" };
const tmp = () => mkdtempSync(join(tmpdir(), "review3-"));
const args = (run) => [
  "readback",
  "--run-dir",
  run,
  "--project-number",
  NUMBER,
  "--run-id",
  RUN,
  "--send",
  "--expect-digest",
  DIGEST,
];
const runFiles = (run, resultJson) => {
  writeFileSync(
    join(run, "journal-" + RUN + ".jsonl"),
    JSON.stringify({
      id: "x",
      state: "response-persisted",
      responseAt: new Date(START).toISOString(),
    }) + "\n",
  );
  if (resultJson !== undefined)
    writeFileSync(
      join(run, "result-" + RUN + ".json"),
      typeof resultJson === "string" ? resultJson : JSON.stringify(resultJson),
    );
};
async function readbackExit(run, world = createWorld()) {
  const lines = [];
  const code = await main(args(run), {
    env: ENV,
    deps: {
      token: () => "test-token",
      send: world.send,
      readback: (o) => readbackRun({ ...o, clock: () => world.now }),
      now: () => START + SETTLE_MS,
    },
    digest: DIGEST,
    out: (t) => lines.push(String(t)),
    err: (t) => lines.push("ERR " + String(t)),
  });
  return { code, text: lines.join("\n"), world };
}
const CREATE = {
  label: "subscription-schedFailV1",
  id: "create-subscription-schedFailV1",
  name: subscriptionName(SUB1),
  class: "unknown-status",
};

test("the read-back exits 3 and lists an unconfirmed create although every name reads 404", async () => {
  const run = tmp();
  try {
    runFiles(run, { unconfirmedCreates: [CREATE] });
    const { code, text } = await readbackExit(run);
    assert.equal(code, 3);
    assert.ok(text.includes(CREATE.name), "the name is listed");
    assert.match(text, /a 404 never settles an unknown create, here or in the run/);
    assert.ok(text.includes('"allAbsent": true'), "the names themselves did read absent");
    const written = readdirSync(run).find((f) => f.startsWith("readback-result-"));
    assert.deepEqual(JSON.parse(readFileSync(join(run, written), "utf8")).unconfirmedCreates, [
      CREATE,
    ]);
  } finally {
    rmSync(run, { recursive: true, force: true });
  }
});

test("near miss: a run result with no unconfirmed create and every name 404 exits 0", async () => {
  const run = tmp();
  try {
    runFiles(run, { unconfirmedCreates: [] });
    const { code, text } = await readbackExit(run);
    assert.equal(code, 0);
    assert.ok(!text.includes("ERR"));
  } finally {
    rmSync(run, { recursive: true, force: true });
  }
});

test("a missing, unreadable or malformed run result cannot be judged: exit 3, and the names are still read", async () => {
  for (const content of [
    undefined,
    "{not json",
    "[]",
    "{}",
    '{"unconfirmedCreates": "none"}',
    "null",
  ]) {
    const run = tmp();
    try {
      runFiles(run, content);
      const { code, text, world } = await readbackExit(run);
      assert.equal(code, 3, String(content));
      assert.match(text, /creates cannot be judged/, String(content));
      assert.match(
        text,
        content === undefined
          ? /result file cannot be read \(ENOENT\)/
          : content === "{not json"
            ? /result file cannot be read \(not JSON\)/
            : /no list of unconfirmed creates/,
        String(content),
      );
      assert.ok(world.calls.length > 0, "the read-only read still runs");
    } finally {
      rmSync(run, { recursive: true, force: true });
    }
  }
});

test("a name present still exits 3 when no create is unconfirmed", async () => {
  const run = tmp();
  try {
    runFiles(run, { unconfirmedCreates: [] });
    const world = createWorld();
    world.topics.add(scheduleId("schedFailV1"));
    const { code } = await readbackExit(run, world);
    assert.equal(code, 3);
  } finally {
    rmSync(run, { recursive: true, force: true });
  }
});

const COMMIT = "a".repeat(40);
const recordArgs = (run, extra) => [
  "record",
  "--run-dir",
  run,
  "--project-number",
  NUMBER,
  "--source-commit",
  COMMIT,
  "--deps-dir",
  "/deps",
  "--node",
  "/node22/bin/node",
  "--firebase-js",
  "/tools/node_modules/firebase-tools/lib/bin/firebase.js",
  ...extra,
];
/** The command line's dependencies with the in-memory world, as main.test.mjs builds them. */
const commandDeps = (world, send, overrides = {}) => ({
  nodeVersion: () => "22.22.1",
  firebaseToolsVersion: () => "15.28.2",
  gitHead: () => COMMIT,
  gitDirty: () => false,
  adcExists: () => true,
  token: () => "test-token",
  send,
  runCli: ({ action }) => world.runCli({ action }),
  prepareSource: ({ target }) => ({
    configPath: join(target, "firebase.json"),
    fixtureDir: join(target, "fixture"),
  }),
  sourceProblems: () => [],
  repoRoot: () => "/repo",
  record: (options) =>
    record({
      ...options,
      ...SHORT,
      clock: () => world.now,
      sleep: async (ms) => world.advance(ms),
    }),
  ...overrides,
});
const resultOf = (run) => {
  const files = readdirSync(run);
  const runId = files.find((f) => f.startsWith("journal-")).slice(8, 24);
  return {
    runId,
    result: JSON.parse(readFileSync(join(run, "result-" + runId + ".json"), "utf8")),
    journal: readFileSync(join(run, "journal-" + runId + ".jsonl"), "utf8")
      .split("\n")
      .filter(Boolean)
      .map((line) => JSON.parse(line)),
  };
};
/** A whole recording through the command line, then the read-back command on its files. */
async function recordThenReadback(intercept) {
  const run = tmp();
  try {
    const world = createWorld();
    const send = async (request) => (await intercept(request, world)) ?? world.send(request);
    const recorded = await main(recordArgs(run, ["--send", "--expect-digest", DIGEST]), {
      env: ENV,
      deps: commandDeps(world, send),
      digest: DIGEST,
      out: () => {},
      err: () => {},
    });
    const { runId, result } = resultOf(run);
    const lines = [];
    const read = await main(
      [
        "readback",
        "--run-dir",
        run,
        "--project-number",
        NUMBER,
        "--run-id",
        runId,
        "--send",
        "--expect-digest",
        DIGEST,
      ],
      {
        env: ENV,
        deps: {
          token: () => "test-token",
          send: world.send,
          readback: (o) => readbackRun({ ...o, clock: () => world.now }),
          now: () => world.now + SETTLE_MS + 60_000,
        },
        digest: DIGEST,
        out: (t) => lines.push(String(t)),
        err: (t) => lines.push("ERR " + String(t)),
      },
    );
    return { recorded, result, read, text: lines.join("\n") };
  } finally {
    rmSync(run, { recursive: true, force: true });
  }
}

const isOkV1Pull = (request) =>
  request.method === "PUT" && request.url.includes("-pull-schedfailv1");

test("end to end: a recording with an unconfirmed create makes the read-back exit 3; a confirmed one lets it exit 0", async () => {
  const unconfirmed = await recordThenReadback(async (request) =>
    isOkV1Pull(request) ? unavailable() : undefined,
  );
  assert.equal(unconfirmed.recorded, 3);
  assert.deepEqual(labels(unconfirmed.result.unconfirmedCreates), ["subscription-schedFailV1"]);
  assert.equal(unconfirmed.read, 3);
  assert.ok(unconfirmed.text.includes("-pull-schedfailv1"));
  const confirmed = await recordThenReadback(async (request, world) => {
    if (!isOkV1Pull(request)) return undefined;
    world.subs.set(
      "projects/fireemu-oracle-sbx/subscriptions/" +
        new URL(request.url).pathname.split("/").at(-1),
      { topic: JSON.parse(request.body).topic, queue: [] },
    );
    return unavailable();
  });
  assert.equal(confirmed.recorded, 3, "an unknown answer is still not closable in the run");
  assert.deepEqual(confirmed.result.unconfirmedCreates, []);
  assert.equal(confirmed.read, 0, "the later read-back, with every name 404, settles it");
});

// ---- S1-r2: a refresh that fails sends and journals nothing ------------------------------------------------------

test("a request whose token refresh fails is neither journaled nor an unknown answer; it is an error of its own step", async () => {
  let failed = 0;
  const { result, journal, world } = await go(
    {},
    {
      prepareRequest: async (spec) => {
        if (spec.id === "delete-subscription-schedFailV1" && failed++ === 0)
          throw new Error("gcloud failed");
      },
    },
  );
  assert.equal(failed, 1);
  assert.equal(
    journal.some((r) => r.id === "delete-subscription-schedFailV1"),
    false,
    "no row for a request that never left",
  );
  assert.equal(
    world.calls.some((c) => c === "DELETE " + SUB1_URL),
    false,
  );
  assert.equal(result.unknownMutations, 0);
  assert.deepEqual(
    result.cleanup.errors.map((e) => e.step),
    ["subscription-schedFailV1"],
  );
  assert.match(result.cleanup.errors[0].message, /gcloud failed/);
  assert.equal(result.closureReady, false);
});

test("near miss: a refresh that succeeds lets every request through with its own row", async () => {
  const seen = [];
  const { result, journal } = await go(
    {},
    { prepareRequest: async (spec) => void seen.push(spec.id) },
  );
  assert.equal(result.closureReady, true);
  assert.equal(
    seen.length,
    journal.filter((r) => r.state === "before-send").length,
    "asked once before each journaled request",
  );
});

test("through the command line, a token refresh that fails sends nothing and journals no unknown answer", async () => {
  const run = tmp();
  try {
    const world = createWorld();
    let issued = 0;
    const used = [];
    const send = async (request) => {
      used.push(request.headers.authorization);
      return world.send(request);
    };
    const deps = commandDeps(world, send, {
      now: () => world.now,
      token: () => {
        if (++issued === 2) throw new Error("gcloud failed");
        return "token-number-" + issued;
      },
      runCli: async ({ action }) => {
        const result = await world.runCli({ action });
        if (action === "deploy") world.advance(45 * 60_000);
        return result;
      },
    });
    await main(recordArgs(run, ["--send", "--expect-digest", DIGEST]), {
      env: ENV,
      deps,
      digest: DIGEST,
      out: () => {},
      err: () => {},
    });
    const { result, journal } = resultOf(run);
    assert.equal(
      issued,
      3,
      "the first token, the refresh that failed, and the next request's refresh",
    );
    assert.equal(journal.filter((r) => r.state === "transport-unknown").length, 0);
    const before = journal.filter((r) => r.state === "before-send").length;
    assert.equal(world.calls.length, before, "every journaled request left, and nothing else");
    assert.equal(result.unknownMutations, 0);
    assert.match(result.stoppedBecause, /gcloud failed/);
    assert.equal(result.closureReady, false);
    assert.equal(used.at(-1), "Bearer token-number-3");
    assert.ok(!used.includes("Bearer token-number-2"), "the token that was never obtained");
  } finally {
    rmSync(run, { recursive: true, force: true });
  }
});

// ---- S2-r2: the ten-minute guard counts the CLI ----------------------------------------------------------------

test("every CLI result row carries the time the CLI ended", async () => {
  const { journal, world } = await go();
  const rows = journal.filter((r) => r.state === "cli-result");
  assert.deepEqual(
    rows.map((r) => r.id),
    ["cli-dry-run", "cli-deploy", "cli-deploy-r2", "cli-deploy-r3", "cli-delete"],
  );
  for (const row of rows) assert.match(row.responseAt, /^\d{4}-\d\d-\d\dT.*Z$/);
  const del = rows.at(-1);
  assert.ok(
    Date.parse(del.responseAt) >= START + 110_000 + 30_000,
    "after the delete's 30 virtual seconds",
  );
  assert.ok(Date.parse(del.responseAt) <= world.now);
});

test("a CLI that could not even be run still leaves a timed row", async () => {
  const { journal } = await go({}, {}, async (o, w) => {
    if (o.action === "delete") throw new Error("spawn failed");
    return w.runCli(o);
  });
  const row = journal.find((r) => r.id === "cli-delete");
  assert.equal(row.state, "cli-result");
  assert.match(row.responseAt, /^\d{4}-/);
  assert.match(String(row.result.error), /spawn failed/);
});

test("the latest activity of a journal includes a CLI result row, and the guard counts from it", async () => {
  const run = tmp();
  try {
    const path = join(run, "journal-" + RUN + ".jsonl");
    const stamp = (ms) => new Date(ms).toISOString();
    const rows = [
      {
        id: "x",
        state: "response-persisted",
        dispatchAt: stamp(START),
        responseAt: stamp(START + 1000),
      },
      { id: "cli-delete", state: "cli-result", result: {}, responseAt: stamp(START + 9 * 60_000) },
    ];
    writeFileSync(path, rows.map((r) => JSON.stringify(r)).join("\n") + "\n");
    assert.equal(lastActivity(path), START + 9 * 60_000);
    writeFileSync(join(run, "result-" + RUN + ".json"), JSON.stringify({ unconfirmedCreates: [] }));
    const world = createWorld();
    const attempt = (now) =>
      main(args(run), {
        env: ENV,
        deps: {
          token: () => "test-token",
          send: world.send,
          readback: (o) => readbackRun({ ...o, clock: () => world.now }),
          now: () => now,
        },
        digest: DIGEST,
        out: () => {},
        err: () => {},
      });
    assert.equal(await attempt(START + 9 * 60_000 + SETTLE_MS - 1), 2);
    assert.equal(await attempt(START + 9 * 60_000 + SETTLE_MS), 0);
  } finally {
    rmSync(run, { recursive: true, force: true });
  }
});

// ---- S3-r2: only a closable run is labelled recorded ---------------------------------------------------------------

test("an unknown answer to a non-resource mutation, with everything else clean, is needs-review and not closable", async () => {
  const { result } = await go({
    hooks: {
      ["POST cloudscheduler.googleapis.com/v1/projects/fireemu-oracle-sbx/locations/us-central1/jobs/" +
      scheduleId("declNullV2") +
      ":pause"]: async () => unavailable(),
    },
  });
  assert.equal(result.unknownMutations, 1);
  assert.equal(result.closureReady, false);
  assert.equal(result.outcome, "calendar-delivery-needs-review");
});

test("an unknown answer in a run whose passes did not finish is needs-review, not incomplete-clean", async () => {
  const { result } = await go({ failDeploy: true, hooks: {} }, {}, async (o, w) => {
    const real = await w.runCli(o);
    return o.action === "deploy" ? { ...real, timedOut: true } : real;
  });
  assert.equal(result.outcome, "calendar-delivery-needs-review");
});

test("an error in a step of the cleanup, with every name read back, is needs-review", async () => {
  const failing = async (row) => {
    if (row.state === "before-send" && row.id === "inventory-packages") throw new Error("disk");
  };
  const world = createWorld();
  const journal = [];
  const result = await record({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "test-token",
    save: async (row) => {
      await failing(row);
      journal.push(row);
    },
    send: world.send,
    runCli: world.runCli,
    clock: () => world.now,
    sleep: async (ms) => world.advance(ms),
    ...SHORT,
  });
  assert.equal(result.cleanup.verified, true);
  assert.ok(result.cleanup.errors);
  assert.equal(result.outcome, "calendar-delivery-needs-review");
});

// ---- S4-r2: the subscriptions Google puts on the v1 topics ----------------------------------------------------------

const readbackWith = async (setup) => {
  const world = createWorld();
  setup(world);
  return readbackRun({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "test-token",
    save: async () => {},
    send: world.send,
    clock: () => world.now,
  });
};

test("a subscription on a v1 schedule topic that the run did not name is reported and blocks all-absent", async () => {
  for (const fn of FUNCTIONS.v1) {
    const result = await readbackWith((w) =>
      w.subs.set("projects/fireemu-oracle-sbx/subscriptions/gcf-" + fn + "-us-central1", {
        topic: topicName(scheduleId(fn)),
        queue: [],
      }),
    );
    assert.deepEqual(result.lists.subscriptions, ["gcf-" + fn + "-us-central1"]);
    assert.equal(result.allAbsent, false, fn);
  }
});

test("the whole subscriptions list must be empty: whatever its topic says, any subscription is reported (r4: no match on an unrecorded field)", async () => {
  for (const topic of [
    "projects/fireemu-oracle-sbx/topics/unrelated",
    "_deleted-topic_",
    topicName(scheduleId("schedFailV1")) + "-2",
    undefined,
  ]) {
    const result = await readbackWith((w) =>
      w.subs.set("projects/fireemu-oracle-sbx/subscriptions/someone-else", { topic, queue: [] }),
    );
    assert.deepEqual(result.lists.subscriptions, ["someone-else"], String(topic));
    assert.equal(result.allAbsent, false, String(topic));
  }
  const own = await readbackWith((w) =>
    w.subs.set(subscriptionName(SUB1), { topic: "_deleted-topic_", queue: [] }),
  );
  assert.deepEqual(own.lists.subscriptions, [SUB1]);
  assert.equal(own.allAbsent, false);
  const empty = await readbackWith(() => {});
  assert.deepEqual(empty.lists.subscriptions, []);
  assert.equal(empty.allAbsent, true);
});
