// Stage C v1.3 (presend review M1): a DELETE is settled by its own operation, never by the kind or the position of
// another request's answer. `channel-busy` sends two DELETEs of one channel while the first's operation runs, so the
// ledger holds two pending deletions at once; a later answer (an `ok@d2`, a 409) must not settle the earlier
// pending one, and the cleanup must not send a third DELETE while one is pending or unknown.

import assert from "node:assert/strict";
import test from "node:test";
import { createCapture } from "./pubsub-production/capture.mjs";
import { createLedger } from "./pubsub-production/ledger.mjs";
import { cleanup, ledgerFacts } from "./eventarc-production/cleanup.mjs";
import { channelBusy } from "./eventarc-production/cases/busy.mjs";
import { createClient } from "./eventarc-production/client.mjs";
import { createOwnership } from "./eventarc-production/names.mjs";
import { runCases } from "./eventarc-production/runner.mjs";
import { summarize } from "./eventarc-production/record.mjs";
import { createWorld } from "./eventarc-production/testing/world.mjs";

const RUN = "0123456789ab";
const PROJECT = "demo-project";
const PARENT = `projects/${PROJECT}/locations/us-central1`;
const facts = (deletes, { open = [] } = {}) => ledgerFacts({ creates: ["ok@c1"], deletes, open });

test("the reviewer's two sequences: a later DELETE's answer settles nothing of an earlier pending one", () => {
  // The first DELETE's operation was never read done; the second's was. In-run closure needs both.
  const first = facts(["unknown@d1", "unknown@d2", "unknown@d1", "ok@d2"]);
  assert.deepEqual([first.deletePending, first.deleteDone], [true, false]);
  // The second DELETE was refused (409) and the case stopped before the first's settle line.
  const second = facts(["unknown@d1", "error"]);
  assert.deepEqual([second.deletePending, second.deleteDone], [true, false]);
});

test("near misses of the delete settlement", () => {
  const cases = [
    [["unknown@d1", "error", "unknown@d1"], true, false],
    [["unknown@d1", "unknown@d2", "ok@d1", "unknown@d2"], true, false],
    [["unknown@d1", "unknown@d2", "ok@d1", "ok@d2"], false, true],
    [["unknown@d1", "ok@d1"], false, true],
    [["unknown@d1", "error@d1"], false, false],
    [["unknown@d1", "conflict@d1"], false, false],
    [["unknown@d1", "error@d1", "unknown@d2"], true, false],
    [["unknown@d1", "ok@d2"], true, false],
    [["ok"], false, true],
    [["error"], false, false],
    [["unsent", "ok"], false, true],
    // A plain unknown answer (a 5xx, a timeout: no operation) is sticky: nothing settles it in the run.
    [["unknown"], true, false],
    [["unknown", "ok"], true, false],
    [["unknown", "ok@d1"], true, false],
    [["ok@d1", "unknown"], true, false],
  ];
  for (const [deletes, pending, done] of cases) {
    const got = facts(deletes);
    assert.deepEqual([got.deletePending, got.deleteDone], [pending, done], deletes.join());
  }
  // A DELETE sent and not answered is an unknown one.
  assert.equal(facts([], { open: ["delete"] }).deletePending, true);
  assert.equal(facts(["ok@d1"], { open: ["delete"] }).deletePending, true);
  assert.equal(facts(["ok@d1"]).deletePending, false);
});

test("property: pending is exactly 'an unknown DELETE whose operation has no settlement of its own', in any order", () => {
  const kinds = ["unknown", "ok", "error", "conflict", "unsent"];
  const operations = ["", "@d1", "@d2", "@d3"];
  let seed = 99;
  const next = (n) => {
    seed = (seed * 1103515245 + 12345) & 0x7fffffff;
    return seed % n;
  };
  for (let round = 0; round < 500; round += 1) {
    const deletes = Array.from(
      { length: next(7) },
      () => `${kinds[next(5)]}${operations[next(4)]}`,
    );
    const parsed = deletes.map((kind) => {
      const [base, operation = null] = kind.split("@");
      return { base, operation };
    });
    const settled = new Set(
      parsed
        .filter(
          ({ base, operation }) => operation !== null && ["ok", "error", "conflict"].includes(base),
        )
        .map(({ operation }) => operation),
    );
    const pending = parsed.some(
      ({ base, operation }) =>
        base === "unknown" && (operation === null || !settled.has(operation)),
    );
    const done = !pending && parsed.some(({ base }) => base === "ok");
    const got = facts(deletes);
    assert.deepEqual([got.deletePending, got.deleteDone], [pending, done], deletes.join());
  }
});

/** The cleanup of a ledger whose name `b` has these deletions, against a service where `b` is still there. */
async function cleanupWith(deletes, { later = false, present = true } = {}) {
  const ownership = createOwnership({ project: PROJECT, runId: RUN });
  const ledger = createLedger();
  const name = ownership.channel("us-central1", "bz-b");
  ledger.sent({ name, action: "create", transport: "rest" });
  ledger.answered({ name, action: "create", transport: "rest", kind: "ok@c1" });
  for (const kind of deletes) {
    ledger.sent({ name, action: "delete", transport: "rest" });
    ledger.answered({ name, action: "delete", transport: "rest", kind });
  }
  const world = createWorld({ project: PROJECT, existing: present ? [name] : [] });
  const transport = { name: "rest", request: (call) => world.request(call) };
  const client = createClient({
    transports: { eventarc: transport },
    ownership,
    caseId: "cleanup",
    usageProject: PROJECT,
    ledger,
  });
  const report = await cleanup({
    client,
    ownership,
    project: PROJECT,
    ledger,
    sleep: async () => {},
    mode: later ? "later" : "recording",
  });
  return { report, world, name, ledger };
}

test("the cleanup sends no third DELETE after [unknown@d1, 409] and leaves the name unsettled for A2", async () => {
  const { report, world, name } = await cleanupWith(["unknown@d1", "error"]);
  assert.equal(world.calls.filter((call) => call.op === "deleteChannel").length, 0, "no DELETE");
  assert.ok(report.unsettled.includes(name), "not settled in the run");
  assert.deepEqual(report.deleted, []);
});

test("the cleanup of [unknown@d1, unknown@d2, unknown@d1, ok@d2] leaves the name unsettled: d1 was never read done", async () => {
  const { report, world, name } = await cleanupWith(
    ["unknown@d1", "unknown@d2", "unknown@d1", "ok@d2"],
    {
      present: false,
    },
  );
  assert.equal(world.calls.filter((call) => call.op === "deleteChannel").length, 0);
  // Even a recorded 404 inside the run does not settle it: only the A2 read-back at least ten minutes later does.
  assert.ok(report.unsettled.includes(name));
});

test("the A2 read-back closes such a name on its own recorded 404, and may send one DELETE after its own 2xx read", async () => {
  const gone = await cleanupWith(["unknown@d1", "unknown@d2", "unknown@d1", "ok@d2"], {
    later: true,
    present: false,
  });
  assert.deepEqual(gone.report.unsettled, []);
  assert.ok(gone.report.settled.some((item) => item.name === gone.name));
  const there = await cleanupWith(["unknown@d1", "error"], { later: true });
  assert.equal(there.world.calls.filter((call) => call.op === "deleteChannel").length, 1);
  assert.deepEqual(there.report.unsettled, []);
});

/** `channel-busy` with the operation of every DELETE never done (the case's own reads and the cleanup's alike). */
async function busyWithDeletesNeverDone(busy) {
  const world = createWorld({ project: PROJECT, busy, duplicate: "409", doneAfter: 1 });
  const ownership = createOwnership({ project: PROJECT, runId: RUN });
  const ledger = createLedger();
  const capture = createCapture({ journal: { write() {} } });
  const deleteOperations = new Set();
  const transport = {
    name: "rest",
    request: async (call) => {
      if (call.op === "getOperation") {
        const name = decodeURIComponent(call.path.replace(/^\/v1\//, ""));
        if (deleteOperations.has(name))
          return { status: 200, body: { name, done: false }, unknown: false };
      }
      const reply = await world.request(call);
      if (call.op === "deleteChannel" && reply.status === 200)
        deleteOperations.add(reply.body.name);
      return reply;
    },
  };
  const cleanupClient = createClient({
    transports: { eventarc: transport },
    ownership,
    caseId: "cleanup",
    usageProject: PROJECT,
    ledger,
  });
  const summary = await runCases({
    cases: [{ ...channelBusy, requests: Infinity }],
    transports: { eventarc: transport, publishing: transport, usage: transport },
    cleanupClient,
    ownership,
    capture,
    options: {
      production: false,
      location: "us-central1",
      usageProject: PROJECT,
      publishPrefix: "/v1",
    },
    sleep: async () => {},
    ledger,
  });
  return { world, summary, ledger, ownership, capture, deleteOperations };
}

test("channel-busy with the first DELETE's operation never done: the run is not closable and no third DELETE is sent, in both modes", async () => {
  for (const busy of ["accept", "reject"]) {
    const { world, summary, capture } = await busyWithDeletesNeverDone(busy);
    const b = `${PARENT}/channels/fe${RUN}-bz-b`;
    const deletes = world.calls.filter(
      (call) => call.op === "deleteChannel" && decodeURIComponent(call.path).endsWith("bz-b"),
    );
    // The case's two (the second only when the first named an operation) and not one more, the cleanup included.
    assert.equal(deletes.length, 2, `${busy}: ${deletes.length} DELETEs of the channel`);
    assert.ok(summary.cleanup.unsettled.includes(b), busy);
    const closable = summarize({
      options: { runId: RUN, target: "emulator", project: PROJECT },
      capture,
      summary,
    }).closureReady;
    assert.equal(closable, false, busy);
  }
});
