// Mutation survivors of packet delivery-004 (diff since the r6.3 base): the pinned drift table, what a timed-out round
// deploy or CLI delete does and does not make unknown, the readiness polls of a round (how many, how far apart, what a
// failed list is), the reads that follow a drift and a redeploy, the length of a refusal message.
import assert from "node:assert/strict";
import test from "node:test";
import { DRIFT, functionName, scheduleId } from "./plan.mjs";
import { record } from "./run.mjs";
import { NUMBER, createWorld, reply } from "./world.mjs";

const RUN = "0123456789abcdef";
const SHORT = { passes: 1, naturalWindowMs: 60_000 };
const SCHED =
  "cloudscheduler.googleapis.com/v1/projects/fireemu-oracle-sbx/locations/us-central1/jobs";
const GCF = "cloudfunctions.googleapis.com";
const ids = (journal) => journal.filter((r) => r.state === "before-send").map((r) => r.id);

async function go(worldOptions = {}, options = {}, setup = () => {}) {
  const world = createWorld(worldOptions);
  setup(world);
  const journal = [];
  const sleeps = [];
  const result = await record({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "test-token",
    save: async (row) => journal.push(row),
    send: world.send,
    runCli: async (o) => world.runCli(o),
    clock: () => world.now,
    sleep: async (ms) => {
      sleeps.push({ ms, patches: world.calls.filter((c) => c.startsWith("PATCH ")).length });
      world.advance(ms);
    },
    ...SHORT,
    ...options,
  });
  return { world, journal, result, sleeps };
}

/** Wraps the double's CLI so that `after` runs once the redeploy of `round` has been applied. */
const afterRound = (round, after) => (w) => {
  const real = w.runCli;
  w.runCli = async (o) => {
    const answer = await real(o);
    if (o.action === "deploy" && o.round === round) after(w);
    return answer;
  };
};

test("the drift of each round is exactly the table of the packet", () => {
  const retry = (retryCount, maxBackoffDuration, maxDoublings) => ({
    retryCount,
    minBackoffDuration: "4s",
    maxBackoffDuration,
    maxDoublings,
  });
  assert.deepEqual(JSON.parse(JSON.stringify(DRIFT)), {
    2: {
      declNullV2: {
        mask: "timeZone,retryConfig",
        body: { timeZone: "Asia/Tokyo", retryConfig: retry(2, "30s", 1) },
      },
      declOmitV2: {
        mask: "timeZone,retryConfig",
        body: { timeZone: "Asia/Tokyo", retryConfig: retry(2, "30s", 1) },
      },
      declTimeoutV2: { mask: "attemptDeadline", body: { attemptDeadline: "300s" } },
    },
    3: {
      declNullV2: {
        mask: "timeZone,retryConfig",
        body: { timeZone: "America/New_York", retryConfig: retry(3, "60s", 2) },
      },
      declOmitV2: {
        mask: "timeZone,retryConfig",
        body: { timeZone: "America/New_York", retryConfig: retry(3, "60s", 2) },
      },
      declTimeoutV2: { mask: "attemptDeadline", body: { attemptDeadline: "240s" } },
    },
  });
});

test("a round deploy or a CLI delete that times out is an unknown mutation of existing names, never an unconfirmed create", async () => {
  const timedOut = {
    exitCode: null,
    signal: "SIGTERM",
    timedOut: true,
    error: null,
    errored: null,
    unknownWrites: [],
    durationMs: 1,
  };
  const round = await go({}, {}, (w) => {
    const real = w.runCli;
    w.runCli = async (o) =>
      o.action === "deploy" && o.round === 2 ? { action: "deploy", ...timedOut } : real(o);
  });
  assert.ok(round.result.unknownMutations >= 1);
  assert.deepEqual(round.result.unconfirmedCreates, []);
  const del = await go({}, {}, (w) => {
    const real = w.runCli;
    w.runCli = async (o) => (o.action === "delete" ? { action: "delete", ...timedOut } : real(o));
  });
  assert.ok(del.result.unknownMutations >= 1);
  assert.deepEqual(del.result.unconfirmedCreates, []);
  const dry = await go({}, {}, (w) => {
    const real = w.runCli;
    w.runCli = async (o) => (o.action === "dry-run" ? { action: "dry-run", ...timedOut } : real(o));
  });
  assert.deepEqual(dry.result.unconfirmedCreates, []);
});

test("a drift answer's message is kept to 300 characters", async () => {
  const long = "x".repeat(400);
  const { result } = await go({
    hooks: {
      ["PATCH " + SCHED + "/" + scheduleId("declNullV2")]: async () =>
        reply(400, { error: { code: 400, message: long, status: "INVALID_ARGUMENT" } }),
    },
  });
  const answer = result.rounds[0].drift.find((d) => d.fn === "declNullV2");
  assert.equal(answer.message.length, 300);
});

test("a job that reads 404 after the drift or after the redeploy is not summarized: the round is not ok", async () => {
  const { result } = await go({
    hooks: {
      ["GET " + SCHED + "/" + scheduleId("declNullV2")]: async ({ w }) =>
        w.calls.some((c) => c.startsWith("PATCH "))
          ? reply(404, { error: { code: 404, message: "gone", status: "NOT_FOUND" } })
          : undefined,
    },
  });
  const round = result.rounds[0];
  assert.equal(round.driftJobs.declNullV2, undefined);
  assert.notEqual(round.driftJobs.declOmitV2, undefined);
  assert.equal(round.jobs.declNullV2, undefined);
  assert.notEqual(round.jobs.declOmitV2, undefined);
  assert.equal(round.ready, true);
  assert.equal(round.ok, false);
});

test("the readiness of a round: ready as soon as the three functions are active, with 30 s between polls", async () => {
  const declNull = functionName("declNullV2");
  const hooks = {};
  const polled = await go({ hooks }, {}, (w) =>
    afterRound(2, (world) => {
      world.functionsV2.get(declNull).state = "DEPLOYING";
      let left = 2;
      hooks["GET " + GCF + "/v2/projects/fireemu-oracle-sbx/locations/-/functions"] = async () => {
        if (--left < 0) world.functionsV2.get(declNull).state = "ACTIVE";
        return undefined;
      };
    })(w),
  );
  assert.equal(polled.result.rounds[0].ready, true);
  const between = polled.sleeps.filter((s) => s.ms === 30_000 && s.patches >= 3 && s.patches < 6);
  assert.equal(between.length, 2);
  assert.ok(ids(polled.journal).includes("round-2-ready-3-functions-v2"));
  assert.ok(!ids(polled.journal).includes("round-2-ready-4-functions-v2"));
});

test("a round whose functions never become active reads the lists four times, sleeping 30 s between, and is not ready", async () => {
  const never = await go({}, {}, (w) => {
    afterRound(2, (world) => {
      world.functionsV2.get(functionName("declNullV2")).state = "DEPLOYING";
    })(w);
  });
  const round = never.result.rounds[0];
  assert.equal(round.ready, false);
  assert.equal(round.ok, false);
  const polls = ids(never.journal).filter((id) => /^round-2-ready-\d+-functions-v2$/.test(id));
  assert.deepEqual(
    polls,
    [1, 2, 3, 4].map((n) => `round-2-ready-${n}-functions-v2`),
  );
  const between = never.sleeps.filter((s) => s.patches >= 3 && s.patches < 6 && s.ms === 30_000);
  assert.equal(between.length, 3);
  assert.ok(
    never.sleeps.filter((s) => s.patches >= 3 && s.patches < 6).every((s) => s.ms % 1000 === 0),
  );
});

test("a failed function list is not a readiness answer: the next poll decides", async () => {
  let armed = false;
  let failed = false;
  const { result, journal } = await go(
    {
      hooks: {
        ["GET " + GCF + "/v1/projects/fireemu-oracle-sbx/locations/-/functions"]: async () => {
          if (!armed || failed) return undefined;
          failed = true;
          return reply(503, { error: { code: 503, message: "x", status: "UNAVAILABLE" } });
        },
      },
    },
    {},
    afterRound(2, () => {
      armed = true;
    }),
  );
  assert.equal(failed, true);
  assert.equal(result.rounds[0].ready, true);
  assert.ok(ids(journal).includes("round-2-ready-2-functions-v1"));
  assert.ok(!ids(journal).includes("round-2-ready-3-functions-v1"));
});
