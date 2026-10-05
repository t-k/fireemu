// r6.1 (coordinator ruling 2026-10-05, option (a) of the r6 presend review): the count job must not re-send the body
// production refused in run 156715222b86ea44, so `count-and-duration-interaction` gets its first observation; the
// refused fractional body gets its own job (`-fraction`, one POST, an expected 400); the test double answers what
// production answered; and one build is read once, however many functions and lists name it.
import assert from "node:assert/strict";
import test from "node:test";
import { createGuard } from "./guard.mjs";
import { EXTRA_JOBS, REGION, extraJobId, functionName, scheduleId } from "./plan.mjs";
import { record } from "./run.mjs";
import { NUMBER, createWorld, reply } from "./world.mjs";

const RUN = "0123456789abcdef";
const SHORT = { passes: 1, naturalWindowMs: 60_000 };
const JOBS =
  "cloudscheduler.googleapis.com/v1/projects/fireemu-oracle-sbx/locations/us-central1/jobs";
const FRACTION = extraJobId(RUN, "fraction");
const COUNT = extraJobId(RUN, "count");
// run 156715222b86ea44: the 400 of the fractional body, 158 bytes, as production wrote it
const NANOS = "retryConfig.max_retry_duration.nanos cannot be set: invalid argument";
const COUNT_REFUSAL =
  "invalid retry count. The retry_count must be a positive integer less than 5: invalid argument";

async function go(worldOptions = {}, options = {}, setup = () => {}) {
  const world = createWorld(worldOptions);
  setup(world);
  const journal = [];
  const result = await record({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "test-token",
    save: async (row) => journal.push(row),
    send: world.send,
    runCli: async (o) => {
      const done = await world.runCli(o);
      if (o.action === "deploy") world.afterDeploy?.(world);
      return done;
    },
    clock: () => world.now,
    sleep: async (ms) => world.advance(ms),
    ...SHORT,
    ...options,
  });
  return { world, journal, result };
}
const post = (world, retryConfig, id = "fe-sd-0123456789abcdef-probe") =>
  world.send({
    method: "POST",
    url: "https://" + JOBS,
    body: JSON.stringify({
      name: "projects/fireemu-oracle-sbx/locations/us-central1/jobs/" + id,
      retryConfig,
    }),
  });

test("the extra jobs: the count job is integer-valued with a window, the fraction job has the refused body", () => {
  assert.deepEqual(
    EXTRA_JOBS.map((job) => job.key),
    ["zero", "duration", "count", "fraction", "retry5"],
  );
  const by = Object.fromEntries(EXTRA_JOBS.map((job) => [job.key, job]));
  assert.deepEqual(by.count.retryConfig, {
    retryCount: 3,
    maxRetryDuration: "20s",
    minBackoffDuration: "4s",
    maxBackoffDuration: "10s",
  });
  assert.deepEqual(by.count.cases, ["count-and-duration-interaction"]);
  // run 156715222b86ea44's refused body, unchanged
  assert.deepEqual(by.fraction.retryConfig, {
    retryCount: 3,
    maxRetryDuration: "20.5s",
    minBackoffDuration: "2.5s",
    maxBackoffDuration: "20s",
    maxDoublings: 1,
  });
  assert.deepEqual(by.fraction.cases, ["fractional-retry-duration"]);
  // nothing fractional is left in the count job, whatever it carries
  for (const value of Object.values(by.count.retryConfig))
    assert.ok(!/\./.test(String(value)), String(value));
  for (const key of ["zero", "duration", "retry5"]) {
    assert.deepEqual(by[key].schedule, "0 0 1 1 *");
    assert.equal(by[key].timeZone, "UTC");
  }
});

test("the count and the window stop the chain at different attempts under the recorded backoff", () => {
  // Recorded gaps (run 156715222b86ea44): min 4 s, max 10 s, no count: attempts at 0, 4.6, 13.2, 23.7 s (gaps of
  // about 4, 8 and 10 s: doubled from the minimum, then held at the maximum, plus about half a second of dispatch
  // latency each). The count job uses the same backoff.
  const { retryCount, maxRetryDuration } = EXTRA_JOBS.find((j) => j.key === "count").retryConfig;
  const window = Number.parseInt(maxRetryDuration, 10);
  const gaps = [4, 8, 10, 10, 10];
  const offsets = [0];
  for (const gap of gaps) offsets.push(offsets.at(-1) + gap);
  const byWindow = offsets.filter((offset) => offset <= window).length;
  const byCount = retryCount + 1;
  assert.equal(
    byWindow,
    3,
    "the window of 20 s allows attempts at 0, 4 and 12 s (the next is at 22 s)",
  );
  assert.equal(byCount, 4);
  assert.notEqual(
    byWindow,
    byCount,
    "an observed chain of 3 shows the window binds, one of 4 the count",
  );
  // with the recorded latency the third attempt is still inside the window and the fourth is not (23.7 s)
  assert.ok(13.2 < window && 23.7 > window);
});

test("production's refusal of a fractional window is answered by the double: 158 bytes, no job", async () => {
  const world = createWorld();
  const answer = await post(world, {
    retryCount: 3,
    maxRetryDuration: "20.5s",
    minBackoffDuration: "2.5s",
    maxBackoffDuration: "20s",
    maxDoublings: 1,
  });
  assert.equal(answer.status, 400);
  const text = await answer.text();
  assert.equal(new TextEncoder().encode(text).length, 158);
  assert.deepEqual(JSON.parse(text), {
    error: { code: 400, message: NANOS, status: "INVALID_ARGUMENT" },
  });
  assert.equal(world.jobs.size, 0);
  // an integer window, and a window of whole seconds with a fractional backoff alone, are accepted (the latter
  // unrecorded: only the window is claimed)
  assert.equal((await post(world, { retryCount: 3, maxRetryDuration: "20s" }, "a")).status, 200);
  assert.equal((await post(world, { retryCount: 3, minBackoffDuration: "2.5s" }, "b")).status, 200);
});

test("production's refusal of a retry count of 6 or more is answered by the double; 0 to 5 are accepted", async () => {
  const world = createWorld();
  for (const count of [6, 7, 100]) {
    const answer = await post(world, { retryCount: count });
    assert.equal(answer.status, 400, String(count));
    assert.equal(JSON.parse(await answer.text()).error.message, COUNT_REFUSAL);
  }
  for (const count of [0, 1, 4, 5])
    assert.equal(
      (await post(world, { retryCount: count }, "ok" + count)).status,
      200,
      String(count),
    );
});

test("a clean run: the count job is created, run, paused and deleted; the fraction job gets one refused POST and nothing else", async () => {
  const { result, world, journal } = await go();
  assert.deepEqual(result.extraAnswers.fraction, { status: 400, class: "4xx", message: NANOS });
  assert.deepEqual(result.extraAnswers.count, { status: 200, class: "2xx", message: null });
  assert.equal(world.jobs.has(FRACTION), false);
  assert.equal(world.creates.includes(COUNT), true);
  const mine = journal.filter(
    (r) => r.state === "before-send" && String(r.id).includes("fraction"),
  );
  // the refused POST, its own direct read (the recorded absence) and the read-back at the end: no run, pause or delete
  assert.deepEqual(
    mine.map((r) => r.id),
    ["create-extra-fraction", "settle-extra-fraction", "readback-gone-job-fe-sd-run-fraction"],
  );
  assert.equal(
    journal.some(
      (r) => String(r.id).includes("fraction") && /^(run-|pause-|delete-job-)/.test(r.id),
    ),
    false,
  );
  assert.ok(
    journal.some(
      (r) => r.id.startsWith("run-1-fe-sd-run-count") && r.state === "response-persisted",
    ),
  );
  assert.equal(result.cleanup.readBack["job-" + FRACTION], true);
  assert.equal(result.unknownMutations, 0);
  assert.equal(result.closureReady, true);
  assert.equal(result.outcome, "calendar-delivery-recorded");
  assert.equal(
    result.passes.every((p) => p.forced.length === 10),
    true,
  );
});

test("the allowlist lets the fraction job be created and nothing near its name", () => {
  const guard = createGuard(RUN, NUMBER);
  const create = (name) => ({
    method: "POST",
    url: "https://" + JOBS,
    json: { name: "projects/fireemu-oracle-sbx/locations/us-central1/jobs/" + name },
  });
  assert.equal(guard.allow(create(FRACTION)), true);
  assert.equal(guard.isMutation(create(FRACTION)), true);
  for (const bad of [
    "fe-sd-" + RUN + "-fractions",
    "fe-sd-" + RUN + "-fract",
    "fe-sd-fedcba9876543210-fraction",
    "fe-sd-" + RUN + "-Fraction",
  ])
    assert.equal(guard.allow(create(bad)), false, bad);
});

// ---- S2: a build is read once ----

const BUILD = "2e6013b5-c892-477d-b683-2e716972055b";
const failedGen1Sharing = (w) => {
  w.afterDeploy = () => {
    for (const fn of ["schedOkV1", "schedFailV1", "schedRetryV1"]) {
      const name = functionName(fn);
      w.functionsV1.set(name, {
        name,
        status: "OFFLINE",
        buildId: BUILD,
        buildName: `projects/${NUMBER}/locations/${REGION}/builds/${BUILD}`,
      });
    }
  };
  w.builds.set(BUILD, { id: BUILD, status: "FAILURE", statusDetail: "x", steps: [] });
  w.buildLogs.set(BUILD, [{ insertId: "l1" }]);
};

test("three Gen1 functions of one failed build, each listed by both function lists, read that build and its log once", async () => {
  const { result, journal } = await go({}, {}, failedGen1Sharing);
  const diagnose = journal.filter((r) => r.state === "before-send" && r.id.startsWith("diagnose-"));
  assert.equal(diagnose.length, 2, diagnose.map((r) => r.id).join());
  assert.equal(diagnose.filter((r) => r.url.includes("/builds/" + BUILD)).length, 1);
  // every function still has its own diagnostic row, with the one build's answer
  assert.deepEqual(result.buildDiagnostics.map((d) => d.function).toSorted(), [
    "schedFailV1",
    "schedOkV1",
    "schedRetryV1",
  ]);
  assert.ok(result.buildDiagnostics.every((d) => d.buildId === BUILD && d.status === "FAILURE"));
});

test("the double lists a Gen1 function in the v2 list as production does (environment GEN_1)", async () => {
  const world = createWorld();
  const name = functionName("schedOkV1");
  world.functionsV1.set(name, {
    name,
    status: "ACTIVE",
    buildName: `projects/${NUMBER}/locations/${REGION}/builds/${BUILD}`,
  });
  const answer = await world.send({
    method: "GET",
    url: "https://cloudfunctions.googleapis.com/v2/projects/fireemu-oracle-sbx/locations/-/functions",
  });
  const list = JSON.parse(await answer.text()).functions;
  const entry = list.find((f) => f.name === name);
  assert.equal(entry.environment, "GEN_1");
  assert.equal(entry.state, "ACTIVE");
  assert.equal(entry.buildConfig.build, `projects/${NUMBER}/locations/${REGION}/builds/${BUILD}`);
});
