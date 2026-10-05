// What the first mutation pass of the recorder left alive, one test per kind: the golden sequence of a clean
// run, the pins of every constant, pagination, the request ceiling and the cleanup that runs beyond it, the
// observation reads that may answer 403, exact counts of what was seen, and the loops' bounds.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  CLEANUP_CEILING,
  FINAL_LOG_WAIT_MS,
  LOG_POLL_MS,
  MAX_REQUESTS,
  NATURAL_WINDOW_MS,
  NORMAL_CEILING,
  PASSES,
  PROPAGATION_WAIT_MS,
  SETTLE_WAIT_MS,
  record,
} from "./run.mjs";
import { NUMBER, createWorld, reply } from "./world.mjs";

const RUN = "0123456789abcdef";
const golden = JSON.parse(
  readFileSync(new URL("./golden-clean-run.json", import.meta.url), "utf8"),
);
const error = (code, status) => reply(code, { error: { code, message: "x", status } });
const P = "/v1/projects/fireemu-oracle-sbx";
const JOBS = "cloudscheduler.googleapis.com" + P + "/locations/us-central1/jobs";
const GCF2 = "cloudfunctions.googleapis.com/v2/projects/fireemu-oracle-sbx/locations/-/functions";
const empty = (w) =>
  w.jobs.size +
    w.topics.size +
    w.subs.size +
    w.functionsV1.size +
    w.functionsV2.size +
    w.runServices.size ===
  0;

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
    runCli: (o) => world.runCli(o),
    clock: () => world.now,
    sleep: async (ms) => {
      sleeps.push(ms);
      world.advance(ms);
    },
    ...options,
  });
  return { world, journal, sleeps, result };
}
const ids = (journal) => journal.filter((r) => r.state === "before-send").map((r) => r.id);
const SHORT = { passes: 1, naturalWindowMs: 60_000 };

test("the constants are the ones the packet states", () => {
  assert.equal(NORMAL_CEILING, 330);
  assert.equal(CLEANUP_CEILING, 170);
  assert.equal(MAX_REQUESTS, 500);
  assert.equal(PASSES, 2);
  assert.equal(NATURAL_WINDOW_MS, 360_000);
  assert.equal(PROPAGATION_WAIT_MS, 60_000);
  assert.equal(SETTLE_WAIT_MS, 60_000);
  assert.equal(LOG_POLL_MS, 60_000);
  assert.equal(FINAL_LOG_WAIT_MS, 120_000);
});

test("a clean run's requests, issued names and sleeps are the golden sequence, in order", async () => {
  const { journal, sleeps, result } = await go();
  assert.deepEqual(ids(journal), golden.ids);
  assert.deepEqual(
    journal.filter((r) => r.state === "issued").map((r) => r.id),
    golden.issued,
  );
  assert.deepEqual(sleeps, golden.sleeps);
  assert.equal(result.attempted, golden.attempted);
  assert.equal(result.stage, "done");
});

test("a stop at preflight leaves the initial result: no entries, nothing verified, no CLI run", async () => {
  const { result, world } = await go({}, {}, (w) => w.services.delete("compute.googleapis.com"));
  assert.equal(result.stage, "preflight");
  assert.equal(result.stoppedBecause, "services");
  assert.equal(result.schedulerEntries, 0);
  assert.deepEqual(result.cleanup, { verified: false });
  assert.equal(result.closureReady, false);
  assert.deepEqual(result.passes, []);
  assert.deepEqual(result.frames, {});
  assert.deepEqual(world.cliRuns, []);
});

test("the dry run's failure is a stop that never closes", async () => {
  const { result } = await go(
    {},
    {
      runCli: async ({ action }) => ({
        action,
        exitCode: 1,
        timedOut: false,
        error: null,
        errored: null,
      }),
    },
  );
  assert.equal(result.stage, "dry-run");
  assert.equal(result.stoppedBecause, "the CLI dry run failed");
  assert.equal(result.closureReady, false);
});

test("what was seen is counted exactly", async () => {
  const { world, result } = await go({}, SHORT);
  const framed = {};
  for (const entry of world.entries)
    if (entry.textPayload) {
      const handler = JSON.parse(entry.textPayload.slice(entry.textPayload.indexOf("{"))).handler;
      framed[handler] = (framed[handler] ?? 0) + 1;
    }
  assert.deepEqual(result.frames, framed);
  assert.equal(
    result.schedulerEntries,
    world.entries.filter((e) => e.resource.type === "cloud_scheduler_job").length,
  );
  assert.ok(result.pulledMessages >= 2);
  assert.equal(
    result.pulledMessages,
    Object.values(result.pulled).reduce((a, b) => a + b, 0),
  );
});

// ---- pagination ---------------------------------------------------------------------------

const otherV2 = (n) => (w) => {
  for (let i = 0; i < n; i++) {
    const name = "projects/fireemu-oracle-sbx/locations/us-central1/functions/other" + i;
    w.functionsV2.set(name, { name, state: "ACTIVE" });
  }
};

test("a list is read page by page, each page named, and a page token is appended", async () => {
  const { journal, world } = await go({ listPageSize: 2 }, SHORT, otherV2(5));
  const pre = ids(journal).filter((id) => id.startsWith("preflight-functions-v2"));
  assert.deepEqual(pre, [
    "preflight-functions-v2",
    "preflight-functions-v2-page-2",
    "preflight-functions-v2-page-3",
  ]);
  const urls = journal
    .filter((r) => r.state === "before-send" && r.id === "preflight-functions-v2-page-2")
    .map((r) => r.url);
  assert.deepEqual(urls, ["https://" + GCF2 + "?pageToken=2"]);
  assert.ok(world.calls.length > 0);
});

test("the Scheduler list keeps its page size and gets the token after it", async () => {
  const { journal } = await go({ listPageSize: 1 }, SHORT, (w) => {
    w.jobs.set("a", { name: "a" });
    w.jobs.set("b", { name: "b" });
  });
  const urls = journal
    .filter((r) => r.state === "before-send" && r.id.startsWith("preflight-jobs"))
    .map((r) => r.url);
  assert.deepEqual(urls, [
    "https://" + JOBS + "?pageSize=500",
    "https://" + JOBS + "?pageSize=500&pageToken=1",
  ]);
});

test("five pages of one list are read, a sixth is refused as incomplete", async () => {
  const topics = (n) => (w) => {
    for (let i = 0; i < n; i++) w.topics.add("other" + i);
  };
  const five = await go({ listPageSize: 2 }, SHORT, topics(9));
  assert.ok(ids(five.journal).includes("preflight-topics-page-5"));
  assert.equal(five.result.stoppedBecause, "namespace");
  assert.deepEqual(five.result.incompleteReads, []);
  const six = await go({ listPageSize: 2 }, SHORT, topics(11));
  assert.equal(six.result.stoppedBecause, "lists");
  assert.ok(!ids(six.journal).includes("preflight-topics-page-6"));
  assert.deepEqual(six.result.incompleteReads, [
    { id: "preflight-topics", class: "more-than-five-pages" },
  ]);
  assert.deepEqual(six.world.cliRuns, []);
});

test("log pages are read up to five, each named; the window of a poll starts five seconds early", async () => {
  const many = await go({ logPageSize: 1 }, { passes: 1, naturalWindowMs: 120_000 });
  const frames = ids(many.journal).filter((id) => id.startsWith("logs-final-frames"));
  assert.deepEqual(frames, [
    "logs-final-frames",
    "logs-final-frames-page-2",
    "logs-final-frames-page-3",
    "logs-final-frames-page-4",
    "logs-final-frames-page-5",
  ]);
  const window = (id) => {
    const row = many.journal.find((r) => r.state === "before-send" && r.id === id);
    return /timestamp>="([^"]+)"[^]*timestamp<="([^"]+)"/
      .exec(row.json.filter)
      .slice(1)
      .map(Date.parse);
  };
  const a = window("logs-pass1-1-frames");
  const b = window("logs-pass1-2-frames");
  assert.equal(b[0], a[1] - 5000);
  assert.equal(window("logs-final-frames")[0], window("logs-preflight-frames")[0] + 5000);
});

// ---- the request ceiling -------------------------------------------------------------------

test("the ceiling is exact, and the cleanup that follows is not counted against it", async () => {
  const full = ids((await go()).journal);
  const start = full.indexOf("cleanup-1-functions-v1");
  for (const ceiling of [start, 100, 60]) {
    const { journal, result, world } = await go({}, { normalCeiling: ceiling });
    const all = ids(journal);
    assert.equal(
      all.indexOf(all.find((id) => id.startsWith("cleanup-1-"))),
      ceiling,
      "ceiling " + ceiling,
    );
    assert.equal(result.cleanup.verified, true, "ceiling " + ceiling);
    assert.ok(empty(world));
  }
});

test("with the ceiling already reached, leftover deletes and operation reads still run", async () => {
  const opts = { leaveOnDelete: ["schedOkV2", "schedOkV1"], v1Operations: true };
  const start = ids((await go(opts)).journal).indexOf("cleanup-1-functions-v1");
  const { result, world, journal } = await go(opts, { normalCeiling: start });
  assert.equal(result.cleanup.error, undefined);
  assert.equal(result.cleanup.verified, true);
  assert.ok(empty(world));
  const all = ids(journal);
  assert.ok(all.includes("leftover-delete-schedOkV2") && all.includes("leftover-delete-schedOkV1"));
  assert.ok(all.some((id) => id.startsWith("leftover-operation-schedOkV1-")));
});

// ---- observation reads may answer 403 --------------------------------------------------------

test("a 403 on an observation read is data, not a stop", async () => {
  const sub = "fe-sd-" + RUN + "-pull-schedokv1";
  let reads = 0;
  const hooks = {
    ["PUT pubsub.googleapis.com" + P + "/subscriptions/" + sub]: async () =>
      error(503, "UNAVAILABLE"),
    ["GET pubsub.googleapis.com" + P + "/subscriptions/" + sub]: async () =>
      ++reads === 1 ? error(403, "PERMISSION_DENIED") : undefined,
    "GET artifactregistry.googleapis.com/v1/projects/fireemu-oracle-sbx/locations/us-central1/repositories/gcf-artifacts/packages":
      async () => error(403, "PERMISSION_DENIED"),
  };
  const { result } = await go({ hooks }, SHORT);
  assert.notEqual(result.outcome, "calendar-delivery-auth-stop");
  assert.equal(result.inventory.artifactPackages, 403);
  assert.equal(result.cleanup.verified, true);
});

test("a subscription whose create was unknown is created only when the settling read says 200", async () => {
  const sub = "fe-sd-" + RUN + "-pull-schedokv1";
  const key = "PUT pubsub.googleapis.com" + P + "/subscriptions/" + sub;
  const lost = await go({ hooks: { [key]: async () => error(503, "UNAVAILABLE") } }, SHORT);
  assert.equal(
    lost.world.calls.some(
      (c) => c === "DELETE pubsub.googleapis.com" + P + "/subscriptions/" + sub,
    ),
    false,
  );
  assert.ok(lost.result.unknownMutations >= 1);
  const took = await go(
    {
      hooks: {
        [key]: async ({ w, body }) => {
          w.subs.set("projects/fireemu-oracle-sbx/subscriptions/" + sub, {
            topic: body.topic,
            queue: [],
          });
          return error(503, "UNAVAILABLE");
        },
      },
    },
    SHORT,
  );
  assert.equal(
    took.world.calls.some(
      (c) => c === "DELETE pubsub.googleapis.com" + P + "/subscriptions/" + sub,
    ),
    true,
  );
  assert.equal(took.result.cleanup.verified, true);
  assert.equal(took.result.closureReady, false);
});

test("an extra job whose create was unknown is run and deleted only when the settling read says 200", async () => {
  const zero = "fe-sd-" + RUN + "-zero";
  const post = "POST " + JOBS;
  const lost = await go(
    {
      hooks: {
        [post]: async ({ body }) =>
          body.name.endsWith("-zero") ? error(503, "UNAVAILABLE") : undefined,
      },
    },
    SHORT,
  );
  assert.equal(
    ids(lost.journal).some((id) => id.includes("run-1-") && id.endsWith("-zero")),
    false,
  );
  const took = await go(
    {
      hooks: {
        [post]: async ({ w, body }) => {
          if (!body.name.endsWith("-zero")) return undefined;
          w.jobs.set(zero, { ...body, state: "ENABLED", manualOnly: true });
          return error(503, "UNAVAILABLE");
        },
      },
    },
    SHORT,
  );
  assert.equal(
    ids(took.journal).includes("run-1-run-zero".replace("run-zero", "fe-sd-run-zero")) ||
      ids(took.journal).some((id) => id.startsWith("run-1-") && id.endsWith("-zero")),
    true,
  );
  assert.equal(took.result.cleanup.verified, true);
});
