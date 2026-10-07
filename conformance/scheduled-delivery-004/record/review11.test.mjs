// Packet delivery-004 (the fourth delivery run; owner ledger 904): the declaration cases `omitted-versus-null-reset` and
// `SDK-attemptDeadline-versus-CLI-timeout` are observed on three deploys, and the retry-backoff formula gets three more
// parameter sets. Round 1 deploys everything; rounds 2 and 3 change the three declaration jobs from outside (a PATCH of
// the job, the one new kind of write) and redeploy only those functions with a source that differs by its ROUND number,
// then read the jobs back.
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { cliPlan, runCli, setRound } from "./deploy.mjs";
import { createGuard } from "./guard.mjs";
import {
  ALL_FUNCTIONS,
  DECLARED,
  DRIFT,
  EXTRA_JOBS,
  FUNCTIONS,
  ROUNDS,
  ROUND_FUNCTIONS,
  jobName,
  scheduleId,
} from "./plan.mjs";
import { record } from "./run.mjs";
import { NUMBER, createWorld, reply } from "./world.mjs";

const RUN = "0123456789abcdef";
const SHORT = { passes: 1, naturalWindowMs: 60_000 };
const SCHED =
  "cloudscheduler.googleapis.com/v1/projects/fireemu-oracle-sbx/locations/us-central1/jobs";
const OPTIONS = {
  configHome: "/cfg",
  configPath: "/src/firebase.json",
  workDir: "/work",
  home: "/home",
  path: "/bin",
};

async function go(worldOptions = {}, options = {}, setup = () => {}) {
  const world = createWorld(worldOptions);
  setup(world);
  const journal = [];
  const cliCalls = [];
  const result = await record({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "test-token",
    save: async (row) => journal.push(row),
    send: world.send,
    runCli: async (o) => {
      cliCalls.push(o);
      return world.runCli(o);
    },
    clock: () => world.now,
    sleep: async (ms) => world.advance(ms),
    ...SHORT,
    ...options,
  });
  return { world, journal, result, cliCalls };
}
const ids = (journal) => journal.filter((r) => r.state === "before-send").map((r) => r.id);

// ---- the plan ----

test("the six functions, and the three that are redeployed", () => {
  assert.deepEqual(
    [...FUNCTIONS.v2],
    ["schedRetryV2", "declNullV2", "declOmitV2", "declTimeoutV2"],
  );
  assert.deepEqual([...FUNCTIONS.v1], ["schedFailV1", "schedRetryV1"]);
  assert.equal(ALL_FUNCTIONS.length, 6);
  assert.deepEqual([...ROUND_FUNCTIONS], ["declNullV2", "declOmitV2", "declTimeoutV2"]);
  assert.equal(ROUNDS, 3);
  assert.deepEqual(DECLARED.declOmitV2.retryConfig, {});
  assert.equal(DECLARED.declTimeoutV2.timeoutSeconds, 540);
  assert.equal(
    Object.values(DECLARED.declNullV2.retryConfig).every((v) => v === null),
    true,
  );
});

test("the drift of each round: a PATCH body and its updateMask that name the same fields, differing between rounds", () => {
  assert.deepEqual(Object.keys(DRIFT).toSorted(), ["2", "3"]);
  for (const round of [2, 3]) {
    assert.deepEqual(Object.keys(DRIFT[round]).toSorted(), [...ROUND_FUNCTIONS].toSorted());
    for (const [fn, { mask, body }] of Object.entries(DRIFT[round])) {
      assert.deepEqual(mask.split(",").toSorted(), Object.keys(body).toSorted(), `${round} ${fn}`);
      assert.ok(!("name" in body));
    }
  }
  for (const fn of ROUND_FUNCTIONS)
    assert.notDeepEqual(DRIFT[2][fn], DRIFT[3][fn], "the two observations are of different drifts");
  // the drifts never put a count and a window together (unrecorded for production), never a count above 5
  for (const round of [2, 3])
    for (const { body } of Object.values(DRIFT[round])) {
      assert.ok(!body.retryConfig || !("maxRetryDuration" in body.retryConfig));
      assert.ok(!body.retryConfig || body.retryConfig.retryCount <= 5);
    }
});

test("the extra jobs: whole seconds, counts to 5, three aimed at the backoff formula", () => {
  assert.deepEqual(
    EXTRA_JOBS.map((job) => job.key),
    ["double0", "double1", "double3"],
  );
  for (const job of EXTRA_JOBS) {
    for (const [k, v] of Object.entries(job.retryConfig)) {
      if (typeof v === "string") assert.match(v, /^\d+s$/, `${job.key} ${k}`);
    }
    assert.ok(job.retryConfig.retryCount >= 1 && job.retryConfig.retryCount <= 5, job.key);
  }
  const by = Object.fromEntries(EXTRA_JOBS.map((j) => [j.key, j.retryConfig]));
  // no window on the probes, and a cap that no gap reaches within six attempts
  for (const key of ["double0", "double1", "double3"]) {
    assert.ok(!("maxRetryDuration" in by[key]));
    assert.equal(by[key].maxBackoffDuration, "100s");
    assert.equal(by[key].retryCount, 5);
  }
  assert.deepEqual(
    ["double0", "double1", "double3"].map((k) => by[k].maxDoublings),
    [0, 1, 3],
  );
});

test("the fixture: the three declaration functions, the ROUND marker, no schedule that runs on its own", () => {
  const source = readFileSync(new URL("../fixture/index.js", import.meta.url), "utf8");
  assert.equal((source.match(/^const ROUND = 1;$/gm) ?? []).length, 1);
  assert.match(source, /require\("firebase-functions\/v2\/options"\)/);
  for (const fn of ROUND_FUNCTIONS) assert.match(source, new RegExp(`exports\\.${fn} = observed`));
  assert.match(source, /timeoutSeconds: 540/);
  assert.match(source, /timeZone: RESET_VALUE/);
  assert.equal((source.match(/schedule: "0 0 1 1 \*"/g) ?? []).length, 3);
  for (const gone of ["schedOkV2", "schedSlowV2", "schedOkV1"])
    assert.ok(!source.includes(gone), gone);
});

// ---- the CLI: a subset of the functions, a source that differs, a file per run ----

test("the deploy of a round names only the declaration functions, and the dry run, deploy and delete keep their exact form", () => {
  const names = [...ROUND_FUNCTIONS];
  const round = cliPlan("deploy", { ...OPTIONS, names });
  assert.equal(
    round.args[round.args.indexOf("--only") + 1],
    names.map((n) => "functions:scheduled-delivery:" + n).join(","),
  );
  // the default is every function, as before
  const all = cliPlan("deploy", OPTIONS);
  assert.equal(
    all.args[all.args.indexOf("--only") + 1],
    ALL_FUNCTIONS.map((n) => "functions:scheduled-delivery:" + n).join(","),
  );
  for (const bad of [["nope"], ["declNullV2", "declnullv2"], ["declNullV2", "declNullV2"], []])
    assert.throws(
      () => cliPlan("deploy", { ...OPTIONS, names: bad }),
      /names/,
      JSON.stringify(bad),
    );
  // the delete is always of every function: a partial delete is not part of this packet
  assert.throws(() => cliPlan("delete", { ...OPTIONS, names }), /delete/);
});

test("setRound rewrites the ROUND number of the source copy and refuses a source without exactly one marker", () => {
  const dir = mkdtempSync(join(tmpdir(), "round-test-"));
  try {
    const file = join(dir, "index.js");
    writeFileSync(file, "a\nconst ROUND = 1;\nb\n");
    setRound(dir, 2);
    assert.equal(readFileSync(file, "utf8"), "a\nconst ROUND = 2;\nb\n");
    setRound(dir, 3);
    assert.equal(readFileSync(file, "utf8"), "a\nconst ROUND = 3;\nb\n");
    for (const content of ["a\n", "const ROUND = 1;\nconst ROUND = 1;\n", "const ROUND = x;\n"]) {
      writeFileSync(file, content);
      assert.throws(() => setRound(dir, 2), /ROUND/);
    }
    writeFileSync(file, "const ROUND = 1;\n");
    for (const bad of [0, 1, 4, 2.5, "2", undefined])
      assert.throws(() => setRound(dir, bad), /round/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a CLI run is named by its label: the three deploys leave three pairs of private files, none overwritten", async () => {
  const dir = mkdtempSync(join(tmpdir(), "label-test-"));
  try {
    const script = join(dir, "fake-firebase.mjs");
    writeFileSync(script, 'console.log("ok"); process.exit(0);\n');
    const run = (label) =>
      runCli({
        action: "deploy",
        ...(label ? { label } : {}),
        plan: { args: [], cwd: dir, env: { PATH: dirname(process.execPath) } },
        firebaseJs: script,
        node: process.execPath,
        directory: join(dir, "out"),
        timeoutMs: 20_000,
      });
    for (const label of ["deploy", "deploy-r2", "deploy-r3"]) {
      const result = await run(label);
      assert.equal(result.exitCode, 0);
      assert.equal(result.action, "deploy");
      assert.equal(readFileSync(join(dir, `out/cli-${label}-stdout.txt`), "utf8"), "ok\n");
      assert.equal(readFileSync(join(dir, `out/cli-${label}-stderr.txt`), "utf8"), "");
    }
    // a repeated label is refused by the exclusive open, and the default label is the action (the existing names)
    assert.throws(() => run("deploy-r2"), /EEXIST/);
    assert.throws(() => run(undefined), /EEXIST/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---- the allowlist: one new write, a PATCH of a declaration job ----

test("the guard lets the recorder PATCH a declaration job with the exact mask and body of a round, and nothing near it", () => {
  const guard = createGuard(RUN, NUMBER);
  const patch = (
    fn,
    mask,
    json,
    name = jobName(scheduleId(fn)),
    host = "cloudscheduler.googleapis.com",
  ) => ({
    method: "PATCH",
    url: `https://${host}/v1/${name}?updateMask=${mask}`,
    json,
  });
  for (const round of [2, 3])
    for (const fn of ROUND_FUNCTIONS) {
      const { mask, body } = DRIFT[round][fn];
      const spec = patch(fn, mask, { name: jobName(scheduleId(fn)), ...body });
      assert.equal(guard.allow(spec), true, `${round} ${fn}`);
      assert.equal(guard.isMutation(spec), true);
    }
  const { mask, body } = DRIFT[2].declNullV2;
  const good = { name: jobName(scheduleId("declNullV2")), ...body };
  const refused = [
    patch("schedRetryV2", mask, { ...good, name: jobName(scheduleId("schedRetryV2")) }), // a job that is not a declaration job
    patch("declNullV2", mask, { ...good, name: jobName(scheduleId("declOmitV2")) }), // a body naming another job
    patch("declNullV2", mask, { ...good, schedule: "* * * * *" }), // a field outside the drift
    patch("declNullV2", mask, { ...good, httpTarget: {} }),
    patch("declNullV2", "schedule", good), // a mask the drift does not use
    patch("declNullV2", "timeZone,retryConfig,schedule", good),
    patch("declNullV2", "", good),
    patch(
      "declNullV2",
      mask,
      good,
      "projects/fireemu-oracle-sbx/locations/us-east1/jobs/" + scheduleId("declNullV2"),
    ),
    patch("declNullV2", mask, undefined),
    patch("declNullV2", mask, { ...good, retryConfig: { ...good.retryConfig, retryCount: 6 } }),
    patch("declNullV2", mask, {
      ...good,
      retryConfig: { ...good.retryConfig, maxRetryDuration: "20s" },
    }),
    patch("declNullV2", mask, { ...good, timeZone: "Not/AZone" }),
    { ...patch("declNullV2", mask, good), url: patch("declNullV2", mask, good).url + "&extra=1" },
    { ...patch("declNullV2", mask, good), method: "PUT" },
  ];
  for (const spec of refused)
    assert.equal(guard.allow(spec), false, JSON.stringify(spec).slice(0, 160));
  // a job name that is only like a declaration job
  assert.equal(
    guard.allow(
      patch("declNullV2", mask, good, jobName("firebase-schedule-declNullV2-us-central1x")),
    ),
    false,
  );
});

// ---- the run: round 1, then two rounds of drift and redeploy ----

test("a clean run: the drift is a PATCH of each declaration job, the redeploy a CLI deploy of those three, the readback of each job follows", async () => {
  const { result, journal, cliCalls, world } = await go();
  assert.equal(result.outcome, "calendar-delivery-recorded");
  assert.equal(result.closureReady, true);
  assert.deepEqual(
    cliCalls.map((c) => [c.action, c.round ?? 1, c.names ? c.names.length : "all"]),
    [
      ["dry-run", 1, "all"],
      ["deploy", 1, "all"],
      ["deploy", 2, 3],
      ["deploy", 3, 3],
      ["delete", 1, "all"],
    ],
  );
  assert.deepEqual(cliCalls[2].names, [...ROUND_FUNCTIONS]);
  const sent = ids(journal);
  for (const round of [2, 3])
    for (const fn of ROUND_FUNCTIONS) {
      assert.ok(sent.includes(`drift-${round}-${fn}`), `drift-${round}-${fn}`);
      assert.ok(sent.includes(`round-${round}-job-${fn}`), `round-${round}-job-${fn}`);
    }
  // the order: the passes, then round 2 (drift, deploy, readback), then round 3, then the pause
  const at = (id) => sent.indexOf(id);
  assert.ok(at("run-1-fe-sd-run-double0") < at("drift-2-declNullV2"));
  assert.ok(at("drift-2-declTimeoutV2") < at("round-2-job-declNullV2"));
  assert.ok(at("round-2-job-declTimeoutV2") < at("drift-3-declNullV2"));
  assert.ok(at("round-3-job-declTimeoutV2") < at("pause-declNullV2-us-central1"));
  // the CLI results are journaled under their own ids
  const cliRows = journal.filter((r) => r.state === "cli-result").map((r) => r.id);
  assert.deepEqual(cliRows, [
    "cli-dry-run",
    "cli-deploy",
    "cli-deploy-r2",
    "cli-deploy-r3",
    "cli-delete",
  ]);
  // the result carries each round: what was changed from outside, the CLI's result, and the job as read back
  assert.equal(result.rounds.length, 2);
  for (const [i, entry] of result.rounds.entries()) {
    assert.equal(entry.round, i + 2);
    assert.deepEqual(
      entry.drift.map((d) => [d.fn, d.status, d.class]),
      ROUND_FUNCTIONS.map((fn) => [fn, 200, "2xx"]),
    );
    assert.equal(entry.cli.exitCode, 0);
    assert.deepEqual(Object.keys(entry.jobs).toSorted(), [...ROUND_FUNCTIONS].toSorted());
    assert.deepEqual(Object.keys(entry.driftJobs).toSorted(), [...ROUND_FUNCTIONS].toSorted());
    assert.equal(entry.ok, true);
  }
  assert.equal(world.jobs.size, 0);
});

test("the PATCH requests carry the drift of their round, with the name in the body and the mask in the query", async () => {
  const { journal } = await go();
  for (const round of [2, 3])
    for (const fn of ROUND_FUNCTIONS) {
      const row = journal.find((r) => r.id === `drift-${round}-${fn}` && r.state === "before-send");
      assert.equal(row.method, "PATCH");
      assert.equal(
        row.url,
        `https://${SCHED}/${scheduleId(fn)}?updateMask=${DRIFT[round][fn].mask}`.replace(
          "/jobs/jobs",
          "/jobs",
        ),
      );
      assert.deepEqual(row.json, { name: jobName(scheduleId(fn)), ...DRIFT[round][fn].body });
    }
});

test("the double behaves as firebase-tools does: a null setting is reset by the redeploy, an omitted one is kept, the attemptDeadline follows the timeout", async () => {
  const { result } = await go();
  const [r2, r3] = result.rounds;
  for (const entry of [r2, r3]) {
    // the drifted job read straight after the PATCH carries the drift
    assert.equal(entry.driftJobs.declNullV2.timeZone, DRIFT[entry.round].declNullV2.body.timeZone);
    assert.equal(
      entry.driftJobs.declTimeoutV2.attemptDeadline,
      DRIFT[entry.round].declTimeoutV2.body.attemptDeadline,
    );
    // the redeploy: the explicit nulls and the default time zone reset, the omitted retryConfig kept
    assert.equal(entry.jobs.declNullV2.timeZone, "UTC");
    assert.equal(entry.jobs.declNullV2.retryConfig?.retryCount ?? 0, 0);
    assert.equal(
      entry.jobs.declOmitV2.retryConfig.retryCount,
      DRIFT[entry.round].declOmitV2.body.retryConfig.retryCount,
    );
    assert.equal(entry.jobs.declTimeoutV2.attemptDeadline, "540s");
  }
});

test("a PATCH that production refuses is a recorded answer: the redeploy still runs, the round is still read", async () => {
  const text = "invalid time zone";
  const { result, journal } = await go({
    hooks: {
      ["PATCH " + SCHED + "/" + scheduleId("declOmitV2")]: async () =>
        reply(400, { error: { code: 400, message: text, status: "INVALID_ARGUMENT" } }),
    },
  });
  assert.equal(result.outcome, "calendar-delivery-recorded");
  assert.deepEqual(
    result.rounds[0].drift.find((d) => d.fn === "declOmitV2"),
    {
      fn: "declOmitV2",
      status: 400,
      class: "4xx",
      message: text,
    },
  );
  assert.equal(result.unknownMutations, 0);
  assert.ok(ids(journal).includes("round-2-job-declOmitV2"));
});

test("a PATCH with an unknown answer is an unknown mutation (read back by the A2 command, not a create): the run needs review, nothing is re-sent", async () => {
  const { result, world } = await go({
    hooks: {
      ["PATCH " + SCHED + "/" + scheduleId("declNullV2")]: async () =>
        reply(503, { error: { code: 503, message: "x", status: "UNAVAILABLE" } }),
    },
  });
  assert.equal(result.outcome, "calendar-delivery-needs-review");
  assert.ok(result.unknownMutations >= 1);
  assert.deepEqual(result.unconfirmedCreates, []);
  assert.equal(result.closureReady, false);
  // each PATCH was sent once
  assert.equal(world.calls.filter((c) => c.startsWith("PATCH")).length, 6);
});

test("a round whose CLI deploy fails is recorded, the other round still runs, and the run is incomplete-clean", async () => {
  const { result, cliCalls } = await go({}, {}, (w) => {
    const real = w.runCli;
    w.runCli = async (o) =>
      o.action === "deploy" && o.round === 2
        ? {
            action: "deploy",
            exitCode: 1,
            signal: null,
            timedOut: false,
            error: null,
            errored: 3,
            unknownWrites: [],
            durationMs: 1,
          }
        : real(o);
  });
  assert.equal(result.outcome, "calendar-delivery-incomplete-clean");
  assert.equal(result.rounds[0].ok, false);
  assert.equal(result.rounds[0].cli.errored, 3);
  assert.equal(result.rounds[1].ok, true);
  assert.equal(result.cleanup.verified, true);
  assert.deepEqual(
    cliCalls.map((c) => c.round ?? 1),
    [1, 1, 2, 3, 1],
  );
});

test("a round deploy that timed out, or answered a write with 5xx, is an unknown mutation; rounds stop after a timeout", async () => {
  const timed = await go({}, {}, (w) => {
    const real = w.runCli;
    w.runCli = async (o) =>
      o.action === "deploy" && o.round === 2
        ? {
            action: "deploy",
            exitCode: null,
            signal: "SIGTERM",
            timedOut: true,
            error: null,
            errored: null,
            unknownWrites: [],
            durationMs: 1,
          }
        : real(o);
  });
  assert.equal(timed.result.outcome, "calendar-delivery-needs-review");
  assert.ok(timed.result.unknownMutations >= 1);
  assert.equal(
    timed.cliCalls.filter((c) => c.action === "deploy").length,
    2,
    "no round 3 after a timeout",
  );
  const five = await go({}, {}, (w) => {
    const real = w.runCli;
    w.runCli = async (o) =>
      o.action === "deploy" && o.round === 3
        ? {
            action: "deploy",
            exitCode: 1,
            signal: null,
            timedOut: false,
            error: null,
            errored: 1,
            unknownWrites: [{ method: "PATCH", host: "cloudscheduler", status: 503 }],
            durationMs: 1,
          }
        : real(o);
  });
  assert.equal(five.result.outcome, "calendar-delivery-needs-review");
  assert.deepEqual(five.result.unconfirmedCreates, []);
});

test("no round runs after a first deploy whose effect is unknown: a round deploy is an update, so its result could not be told apart", async () => {
  for (const unknown of [
    { exitCode: null, signal: "SIGTERM", timedOut: true, error: null, errored: null },
    { exitCode: null, signal: null, timedOut: false, error: "spawn failed", errored: null },
  ]) {
    const { cliCalls, result } = await go({}, {}, (w) => {
      const real = w.runCli;
      w.runCli = async (o) =>
        o.action === "deploy" && !o.round
          ? { action: "deploy", unknownWrites: [], durationMs: 1, ...unknown }
          : real(o);
    });
    assert.equal(cliCalls.filter((c) => c.action === "deploy").length, 1, JSON.stringify(unknown));
    assert.equal(result.rounds?.length ?? 0, 0);
    assert.equal(result.closureReady, false);
  }
});

test("no round runs when the first deploy did not become ready, or when a pass stopped the run", async () => {
  const failed = await go({ failDeploy: true });
  assert.equal(failed.result.rounds?.length ?? 0, 0);
  assert.equal(failed.cliCalls.filter((c) => c.round > 1).length, 0);
});

test("the rounds' reads and writes stay inside the allowlist and the ceilings: a clean run is far inside 500 requests", async () => {
  const { result } = await go({}, { passes: 2, naturalWindowMs: 360_000 });
  assert.ok(result.attempted < 220, String(result.attempted));
  assert.equal(result.closureReady, true);
});
