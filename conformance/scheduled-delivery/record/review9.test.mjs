// r6.2 (coordinator ruling 2026-10-05): one more extra REST job, `-zerobackoff`, observes what Cloud Scheduler does
// with `minBackoffDuration "0s"` (the local model releases one retry per clock change; production's answer is unrecorded).
// The window is short (10 s) so that a retry loop with no gap is bounded whatever production does.
import assert from "node:assert/strict";
import test from "node:test";
import { createGuard } from "./guard.mjs";
import { EXTRA_JOBS, extraJobId } from "./plan.mjs";
import { record } from "./run.mjs";
import { NUMBER, createWorld, reply } from "./world.mjs";

const RUN = "0123456789abcdef";
const SHORT = { passes: 1, naturalWindowMs: 60_000 };
const JOBS =
  "cloudscheduler.googleapis.com/v1/projects/fireemu-oracle-sbx/locations/us-central1/jobs";
const ZB = extraJobId(RUN, "zerobackoff");

async function go(worldOptions = {}) {
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
  });
  return { world, journal, result };
}

test("the zero-backoff job: a zero minimum and maximum backoff with a short window, the shape of the other extra jobs", () => {
  assert.deepEqual(
    EXTRA_JOBS.map((job) => job.key),
    ["zero", "duration", "count", "fraction", "zerobackoff", "retry5"],
  );
  const job = EXTRA_JOBS.find((j) => j.key === "zerobackoff");
  assert.deepEqual(job.retryConfig, {
    maxRetryDuration: "10s",
    minBackoffDuration: "0s",
    maxBackoffDuration: "0s",
  });
  assert.deepEqual(job.cases, ["zero-min-backoff"]);
  assert.equal(job.schedule, "0 0 1 1 *");
  assert.equal(job.timeZone, "UTC");
  // bounded: the window is the shortest of the retry windows the packet sends, whatever the gap between attempts
  const seconds = (j) => Number.parseInt(j.retryConfig.maxRetryDuration ?? "99999", 10);
  assert.equal(seconds(job), Math.min(...EXTRA_JOBS.map(seconds)));
});

test("a 2xx is run, paused, deleted and read back like any extra job; the answer is in the result", async () => {
  const { result, world, journal } = await go();
  assert.deepEqual(result.extraAnswers.zerobackoff, { status: 200, class: "2xx", message: null });
  assert.equal(world.creates.includes(ZB), true);
  assert.equal(world.jobs.has(ZB), false);
  assert.ok(
    journal.some((r) => r.id === "run-1-fe-sd-run-zerobackoff" && r.state === "response-persisted"),
  );
  assert.ok(journal.some((r) => r.id === "delete-job-0-fe-sd-run-zerobackoff" && r.status === 200));
  assert.equal(result.cleanup.readBack["job-" + ZB], true);
  assert.equal(
    result.passes.every((p) => p.forced.length === 11),
    true,
  );
  assert.equal(result.closureReady, true);
});

test("a 400 of any text is a recorded answer, not a failure: no job, no run, the run closes", async () => {
  const text = "minBackoffDuration must be positive: invalid argument";
  const { result, world, journal } = await go({
    hooks: {
      ["POST " + JOBS]: async ({ body }) =>
        body.name.endsWith(ZB)
          ? reply(400, { error: { code: 400, message: text, status: "INVALID_ARGUMENT" } })
          : undefined,
    },
  });
  assert.deepEqual(result.extraAnswers.zerobackoff, { status: 400, class: "4xx", message: text });
  assert.equal(world.jobs.has(ZB), false);
  assert.equal(
    journal.some(
      (r) => String(r.id).includes("zerobackoff") && /^(run-|pause-|delete-job-)/.test(r.id),
    ),
    false,
  );
  assert.equal(result.unknownMutations, 0);
  assert.equal(result.closureReady, true);
});

test("a 503 is an unknown create: unconfirmed until an own 2xx read shows it", async () => {
  const { result } = await go({
    hooks: {
      ["POST " + JOBS]: async ({ body }) =>
        body.name.endsWith(ZB)
          ? reply(503, { error: { code: 503, message: "x", status: "UNAVAILABLE" } })
          : undefined,
    },
  });
  assert.deepEqual(
    result.unconfirmedCreates.map((c) => c.label),
    ["job-" + ZB],
  );
  assert.equal(result.closureReady, false);
});

test("the allowlist lets the zero-backoff job be created and nothing near its name", () => {
  const guard = createGuard(RUN, NUMBER);
  const create = (name) => ({
    method: "POST",
    url: "https://" + JOBS,
    json: { name: "projects/fireemu-oracle-sbx/locations/us-central1/jobs/" + name },
  });
  assert.equal(guard.allow(create(ZB)), true);
  for (const bad of [
    "fe-sd-" + RUN + "-zero-backoff",
    "fe-sd-" + RUN + "-zerobackoffs",
    "fe-sd-" + RUN + "-ZeroBackoff",
    "fe-sd-fedcba9876543210-zerobackoff",
  ])
    assert.equal(guard.allow(create(bad)), false, bad);
});
