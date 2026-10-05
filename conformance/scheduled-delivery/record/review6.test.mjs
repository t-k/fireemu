// Ruling of 2026-10-05 (coordinator): the boundary of Cloud Scheduler's retry count is recorded, not assumed. One more
// extra REST job, `fe-sd-<runId>-retry5` with `retryCount: 5` and the shape of the other extra jobs, is created: a 2xx is
// deleted and read back as 404, a 400 is the recorded refusal.
import assert from "node:assert/strict";
import test from "node:test";
import { createGuard } from "./guard.mjs";
import { EXTRA_JOBS, extraJobId } from "./plan.mjs";
import { NORMAL_CEILING, record } from "./run.mjs";
import { NUMBER, createWorld, reply } from "./world.mjs";

const RUN = "0123456789abcdef";
const SHORT = { passes: 1, naturalWindowMs: 60_000 };
const JOBS =
  "cloudscheduler.googleapis.com/v1/projects/fireemu-oracle-sbx/locations/us-central1/jobs";
const RETRY5 = extraJobId(RUN, "retry5");
const REFUSAL =
  "invalid retry count. The retry_count must be a positive integer less than 5: invalid argument";

async function go(worldOptions = {}, options = {}) {
  const world = createWorld(worldOptions);
  const journal = [];
  const result = await record({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "test-token",
    save: async (row) => journal.push(row),
    send: world.send,
    runCli: (o) => world.runCli(o),
    clock: () => world.now,
    sleep: async (ms) => world.advance(ms),
    ...SHORT,
    ...options,
  });
  return { world, journal, result };
}
const refuseRetry5 = {
  ["POST " + JOBS]: async ({ body }) =>
    body.name.endsWith(RETRY5)
      ? reply(400, { error: { code: 400, message: REFUSAL, status: "INVALID_ARGUMENT" } })
      : undefined,
};

test("the probe is one extra job with retryCount 5 and the shape of the others", async () => {
  const probe = EXTRA_JOBS.find((job) => job.key === "retry5");
  assert.deepEqual(probe.retryConfig, { retryCount: 5 });
  assert.equal(probe.schedule, "0 0 1 1 *");
  assert.equal(probe.timeZone, "UTC");
  const { journal } = await go();
  const create = journal.find((r) => r.id === "create-extra-retry5" && r.state === "before-send");
  const zero = journal.find((r) => r.id === "create-extra-zero" && r.state === "before-send");
  assert.equal(create.json.name.endsWith("/jobs/" + RETRY5), true);
  assert.deepEqual(create.json.retryConfig, { retryCount: 5 });
  assert.deepEqual(create.json.httpTarget, zero.json.httpTarget);
  assert.equal(create.json.schedule, zero.json.schedule);
  assert.equal(create.json.timeZone, zero.json.timeZone);
  assert.deepEqual(Object.keys(create.json).toSorted(), Object.keys(zero.json).toSorted());
});

test("a 2xx is deleted by the run with a 2xx and read back as 404; the answer is in the result", async () => {
  const { result, world, journal } = await go();
  assert.deepEqual(result.extraAnswers.retry5, { status: 200, class: "2xx", message: null });
  assert.equal(world.creates.includes(RETRY5), true);
  assert.equal(world.jobs.has(RETRY5), false);
  assert.ok(
    journal.some(
      (r) =>
        r.id === "delete-job-0-fe-sd-run-retry5" &&
        r.state === "response-persisted" &&
        r.status === 200,
    ),
  );
  assert.ok(journal.some((r) => r.id === "readback-gone-job-fe-sd-run-retry5" && r.status === 404));
  assert.equal(result.cleanup.readBack["job-" + RETRY5], true);
  assert.deepEqual(result.vanishedAfterCreate, []);
  assert.equal(result.closureReady, true);
  assert.equal(result.outcome, "calendar-delivery-recorded");
});

test("a 400 is the recorded refusal: no job, no unknown answer, the message in the result, the run still closes", async () => {
  const { result, world, journal } = await go({ hooks: refuseRetry5 });
  assert.deepEqual(result.extraAnswers.retry5, { status: 400, class: "4xx", message: REFUSAL });
  assert.equal(world.jobs.has(RETRY5), false);
  assert.equal(result.unknownMutations, 0);
  assert.deepEqual(result.unconfirmedCreates, []);
  assert.equal(
    journal.some((r) => String(r.id).includes("retry5") && /^(run-|pause-|delete-job-)/.test(r.id)),
    false,
    "a refused job is neither run, paused nor deleted",
  );
  assert.equal(result.cleanup.readBack["job-" + RETRY5], true);
  assert.equal(result.closureReady, true);
  assert.equal(result.outcome, "calendar-delivery-recorded");
  for (const key of ["zero", "duration", "count"])
    assert.equal(result.extraAnswers[key].status, 200, key);
});

test("a 503 on the probe is an unknown create: unconfirmed until an own 2xx read shows it", async () => {
  const { result } = await go({
    hooks: {
      ["POST " + JOBS]: async ({ body }) =>
        body.name.endsWith(RETRY5)
          ? reply(503, { error: { code: 503, message: "x", status: "UNAVAILABLE" } })
          : undefined,
    },
  });
  assert.equal(result.extraAnswers.retry5.class, "unknown-status");
  assert.deepEqual(
    result.unconfirmedCreates.map((c) => c.label),
    ["job-" + RETRY5],
  );
  assert.equal(result.closureReady, false);
});

test("the allowlist lets the probe be created and refuses a name that is not an extra job of the run", () => {
  const guard = createGuard(RUN, NUMBER);
  const create = (name) => ({
    method: "POST",
    url: "https://" + JOBS,
    json: { name: "projects/fireemu-oracle-sbx/locations/us-central1/jobs/" + name },
  });
  assert.equal(guard.allow(create(RETRY5)), true);
  assert.equal(guard.isMutation(create(RETRY5)), true);
  for (const bad of [
    "fe-sd-" + RUN + "-retry6",
    "fe-sd-" + RUN + "-retry50",
    "fe-sd-fedcba9876543210-retry5",
    "fe-sd-" + RUN + "-retry",
  ])
    assert.equal(guard.allow(create(bad)), false, bad);
});

test("a clean run stays far inside the request ceiling with the probe (200 requests, 22 names issued)", async () => {
  const { result, journal } = await go({}, { passes: 2, naturalWindowMs: 360_000 });
  assert.equal(result.attempted, 200);
  assert.ok(result.attempted < NORMAL_CEILING / 1.5);
  assert.equal(journal.filter((r) => r.state === "issued").length, 22);
});

test("a long refusal message is kept to 300 characters in the result (the journal has it whole)", async () => {
  const long = "m".repeat(450);
  const { result, journal } = await go({
    hooks: {
      ["POST " + JOBS]: async ({ body }) =>
        body.name.endsWith(RETRY5)
          ? reply(400, { error: { code: 400, message: long, status: "INVALID_ARGUMENT" } })
          : undefined,
    },
  });
  assert.equal(result.extraAnswers.retry5.message, "m".repeat(300));
  const row = journal.find(
    (r) => r.id === "create-extra-retry5" && r.state === "response-persisted",
  );
  assert.ok(Buffer.from(row.bodyBase64, "base64").toString().includes(long));
});
