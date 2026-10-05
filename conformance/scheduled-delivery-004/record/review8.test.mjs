// The test double answers what production answered (the refused fractional window and the refused retry count of 6),
// and one build is read once, however many functions and lists name it.
import assert from "node:assert/strict";
import test from "node:test";
import { FUNCTIONS, REGION, functionName } from "./plan.mjs";
import { record } from "./run.mjs";
import { NUMBER, createWorld } from "./world.mjs";

const RUN = "0123456789abcdef";
const SHORT = { passes: 1, naturalWindowMs: 60_000 };
const JOBS =
  "cloudscheduler.googleapis.com/v1/projects/fireemu-oracle-sbx/locations/us-central1/jobs";
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

const BUILD = "2e6013b5-c892-477d-b683-2e716972055b";
const failedGen1Sharing = (w) => {
  w.afterDeploy = () => {
    for (const fn of FUNCTIONS.v1) {
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

test("two Gen1 functions of one failed build, each listed by both function lists, read that build and its log once", async () => {
  const { result, journal } = await go({}, {}, failedGen1Sharing);
  const diagnose = journal.filter((r) => r.state === "before-send" && r.id.startsWith("diagnose-"));
  assert.equal(diagnose.length, 2, diagnose.map((r) => r.id).join());
  assert.equal(diagnose.filter((r) => r.url.includes("/builds/" + BUILD)).length, 1);
  // every function still has its own diagnostic row, with the one build's answer
  assert.deepEqual(result.buildDiagnostics.map((d) => d.function).toSorted(), [
    "schedFailV1",
    "schedRetryV1",
  ]);
  assert.ok(result.buildDiagnostics.every((d) => d.buildId === BUILD && d.status === "FAILURE"));
});

test("the double lists a Gen1 function in the v2 list as production does (environment GEN_1)", async () => {
  const world = createWorld();
  const name = functionName("schedFailV1");
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
