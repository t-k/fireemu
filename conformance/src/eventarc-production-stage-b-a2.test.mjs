// The three cases of unknown and ambiguous answers (checklist section 3), end to end for the stage B
// recorder: a recording against the model of the service, then the separate A2 read-back at least ten
// minutes later. Never mixed: an unknown create is never settled by a 404, a confirmed create that reads
// 404 stays open until A2, an unknown delete is closed only by A2.

import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { MIN_A2_WAIT_MS, main } from "./eventarc-production/record.mjs";
import { installVirtualClock } from "./eventarc-production/testing/virtual-clock.mjs";
import { createWorld } from "./eventarc-production/testing/world.mjs";
import { serveWorld } from "./eventarc-production/testing/world-server.mjs";

const RUN = "0123456789ab";
const PROJECT = "demo-fireemu-eventarc";
const P1 = `projects/${PROJECT}/locations/us-central1/channels/fe${RUN}-cp-p1`;
// The test's own clock: the recording is stamped by it and the A2 is given a later instant, so that no
// decision here reads the wall clock.
const START = Date.parse("2030-01-01T00:00:00.000Z");
const clock = installVirtualClock(START);
const io = () => ({ stdout: { write: () => true }, stderr: { write: () => true } });

async function record(t, options) {
  clock.set(START);
  const world = createWorld({ project: PROJECT, ...options });
  const service = await serveWorld(world);
  t.after(service.close);
  const dir = mkdtempSync(join(tmpdir(), "eventarc-b-a2-"));
  const code = await main(
    [
      "--target",
      "emulator",
      "--emulator-host",
      service.host,
      "--out",
      dir,
      "--only",
      "preconditions,create-probe",
      "--run-id",
      RUN,
    ],
    {},
    io(),
  );
  const first = JSON.parse(readFileSync(join(dir, `summary-${RUN}.json`), "utf8"));
  return { world, service, dir, code, first };
}

/** The A2 read-back: a separate run in the recording's directory, after the ten minutes. */
async function readBack({ dir, service }, { before = 0 } = {}) {
  const code = await main(
    [
      "--target",
      "emulator",
      "--emulator-host",
      service.host,
      "--out",
      dir,
      "--cleanup-only",
      "--run-id",
      RUN,
      "--from-capture",
      join(dir, `capture-${RUN}.jsonl`),
    ],
    {},
    io(),
    {
      now: () => {
        const instant = START + MIN_A2_WAIT_MS - before + 1000;
        clock.set(instant);
        return instant;
      },
      sleep: async () => {},
    },
  );
  const name = readdirSync(dir).find((file) => /^summary-.*-a2-.*\.json$/.test(file));
  return { code, summary: name ? JSON.parse(readFileSync(join(dir, name), "utf8")) : null };
}

test("an unknown create is never settled by a 404, not in the run and not at A2: it is reported unconfirmed and the run is not closable", async (t) => {
  const state = await record(t, { createAnswer: "unknown-absent" });
  assert.equal(state.first.closureReady, false);
  assert.deepEqual(state.first.cleanup.unconfirmed, [P1]);
  assert.deepEqual(state.first.cleanup.unsettled, [P1]);
  assert.equal(state.first.cases.at(-1).outcome, "stopped");
  assert.equal(
    state.world.calls.some((call) => call.op === "deleteChannel"),
    false,
    "nothing is deleted on a 404",
  );
  const a2 = await readBack(state);
  assert.equal(a2.summary.closureReady, false);
  assert.deepEqual(a2.summary.cleanup.unconfirmed, [P1], "the A2 404 does not settle it either");
});

test("an unknown create followed by an own positive read settles: the channel is deleted and read back as 404", async (t) => {
  const state = await record(t, { createAnswer: "unknown-appears" });
  assert.deepEqual(state.first.cleanup.unconfirmed, []);
  assert.ok(state.first.cleanup.deleted.includes(P1));
  assert.equal(state.world.channels.has(P1), false);
  assert.equal(state.first.closureReady, false, "the 503 itself is an unknown answer of the run");
  const a2 = await readBack(state);
  assert.equal(a2.summary.closureReady, true);
  assert.deepEqual(a2.summary.cleanup.unsettled, []);
});

test("a confirmed create that reads 404 in the run stays open; only the A2 read-back, ten minutes later, settles it", async (t) => {
  const state = await record(t, { createAnswer: "invisible" });
  assert.deepEqual(state.first.cleanup.unsettled, [P1], "open in the run");
  assert.deepEqual(state.first.cleanup.unconfirmed, [], "confirmed by its operation, so not unconfirmed");
  assert.equal(state.first.closureReady, false);
  assert.equal(
    state.world.calls.some((call) => call.op === "deleteChannel"),
    false,
  );
  const a2 = await readBack(state);
  assert.equal(a2.summary.closureReady, true);
  assert.deepEqual(a2.summary.cleanup.unsettled, []);
  assert.ok(a2.summary.cleanup.alreadyGone.includes(P1));
  // Near miss: a read-back before the ten minutes is refused, and nothing is sent or written by it.
  const sent = state.world.calls.length;
  const early = await readBack(state, { before: 5 * 60 * 1000 });
  assert.equal(early.code, 2);
  assert.equal(state.world.calls.length, sent);
});

test("an unknown delete is sticky in the run (never re-sent) and only the A2 read-back showing 404 closes it", async (t) => {
  const state = await record(t, { deleteAnswer: "unknown-effective" });
  const deletes = state.world.calls.filter((call) => call.op === "deleteChannel");
  assert.equal(deletes.length, 1, "the deletion is not sent again");
  assert.equal(state.first.closureReady, false);
  assert.ok(state.first.cleanup.unsettled.includes(P1));
  const a2 = await readBack(state);
  assert.equal(a2.summary.closureReady, true);
  assert.deepEqual(a2.summary.cleanup.unsettled, []);
  assert.equal(
    state.world.calls.filter((call) => call.op === "deleteChannel").length,
    1,
    "A2 sent nothing: it read 404",
  );
});

test("an unknown delete that did not take effect leaves the channel in place, and the run is not closable", async (t) => {
  const state = await record(t, { deleteAnswer: "unknown-noeffect" });
  assert.equal(state.first.closureReady, false);
  assert.ok(state.world.channels.has(P1), "the channel is still there");
  assert.ok(state.first.cleanup.unsettled.includes(P1));
  assert.equal(state.world.calls.filter((call) => call.op === "deleteChannel").length, 1);
});

// A request that never left the machine (refused by a case's ceiling or by the budget before it was sent)
// is not an unknown answer: it leaves nothing to settle (presend review M2).
import { createCapture, createBudget } from "./pubsub-production/capture.mjs";
import { createLedger } from "./pubsub-production/ledger.mjs";
import { createClient } from "./eventarc-production/client.mjs";
import { createOwnership } from "./eventarc-production/names.mjs";
import { ledgerFacts } from "./eventarc-production/cleanup.mjs";
import { runCases } from "./eventarc-production/runner.mjs";
import { createRawRest } from "./eventarc-production/rest.mjs";

const UNSENT_RUN = "0123456789ab";
const unsentName = (id) => `projects/${PROJECT}/locations/us-central1/channels/fe${UNSENT_RUN}-${id}`;

test("a creation or a deletion refused by the case ceiling before it was sent is written as unsent: no open entry, nothing to settle", async () => {
  const ownership = createOwnership({ project: PROJECT, runId: UNSENT_RUN });
  const ledger = createLedger();
  const world = createWorld({ project: PROJECT });
  const calls = [];
  const gate = (limit) => {
    let used = 0;
    return {
      name: "rest",
      request: (call) => {
        if (used >= limit) throw Object.assign(new Error(`the case reached its limit of ${limit} requests`), { name: "CaseLimit", unsent: true });
        used += 1;
        calls.push(call.op);
        return world.request(call);
      },
    };
  };
  const make = (limit) =>
    createClient({
      transports: { eventarc: gate(limit) },
      ownership,
      caseId: "gate",
      usageProject: PROJECT,
      ledger,
    });
  const created = make(0);
  const id = `fe${UNSENT_RUN}-a`;
  await assert.rejects(() => created.createChannel(PROJECT, "us-central1", id), { name: "CaseLimit" });
  const item = ledger.state().get(unsentName("a"));
  assert.deepEqual(item.open, []);
  assert.deepEqual(item.creates, ["unsent"]);
  assert.deepEqual(ledgerFacts(item), {
    mayExist: false,
    createPending: false,
    deleteSent: false,
    deletePending: false,
    deleteDone: false,
  });
  // The same for a deletion: it is not sent, so it is not pending.
  await assert.rejects(() => make(0).deleteChannel(unsentName("b")), { name: "CaseLimit" });
  const deleting = ledger.state().get(unsentName("b"));
  assert.deepEqual([deleting.open, deleting.deletes], [[], ["unsent"]]);
  assert.equal(ledgerFacts(deleting).deleteSent, false);
  assert.equal(ledgerFacts(deleting).deletePending, false);
  assert.deepEqual(calls, []);
  // A request that was sent is still an answer: the next one after the limit is the one refused.
  const two = make(1);
  await two.createChannel(PROJECT, "us-central1", `fe${UNSENT_RUN}-c`);
  await assert.rejects(() => two.createChannel(PROJECT, "us-central1", `fe${UNSENT_RUN}-d`), { name: "CaseLimit" });
  assert.equal(ledger.state().get(unsentName("c")).creates.length, 1);
  assert.notEqual(ledger.state().get(unsentName("c")).creates[0], "unsent");
  assert.deepEqual(ledger.state().get(unsentName("d")).creates, ["unsent"]);
});

test("a creation refused by the run's budget, or by a credential that cannot be had, is unsent too, and the run can still close", async () => {
  const world = createWorld({ project: PROJECT });
  const lines = [];
  const capture = createCapture({ journal: { write: (line) => lines.push(line) } });
  const budget = createBudget(1);
  const base = "http://127.0.0.1:9";
  const rest = createRawRest({
    base,
    budget,
    capture,
    fetchImpl: async (url, init) => {
      const path = url.slice(base.length);
      const answer = await world.request({ op: init.method === "POST" ? "createChannel" : "getChannel", method: init.method, path, body: init.body === undefined ? undefined : JSON.parse(init.body) });
      return new Response(JSON.stringify(answer.body), { status: answer.status });
    },
    getToken: async () => {
      throw new Error("gcloud could not print an access token");
    },
  });
  const ownership = createOwnership({ project: PROJECT, runId: UNSENT_RUN });
  const ledger = createLedger();
  const client = createClient({ transports: { eventarc: rest }, ownership, caseId: "b", usageProject: PROJECT, ledger });
  // No credential: nothing is sent, the creation is unsent.
  await assert.rejects(() => client.createChannel(PROJECT, "us-central1", `fe${UNSENT_RUN}-a`), /gcloud could not print/);
  assert.deepEqual(ledger.state().get(unsentName("a")).creates, ["unsent"]);
  assert.equal(budget.used(), 0, "the budget was not touched either");
  // With a credential: the first request uses the budget of one, the second is refused by it, unsent.
  const second = createRawRest({ base, budget, capture, fetchImpl: async () => new Response("{}", { status: 200 }) });
  const withBudget = createClient({ transports: { eventarc: second }, ownership, caseId: "b", usageProject: PROJECT, ledger });
  await withBudget.getChannel(unsentName("zz"));
  await assert.rejects(() => withBudget.createChannel(PROJECT, "us-central1", `fe${UNSENT_RUN}-e`), { name: "BudgetExceeded" });
  assert.deepEqual(ledger.state().get(unsentName("e")).creates, ["unsent"]);
  assert.deepEqual(ledger.state().get(unsentName("e")).open, []);
});

test("end to end: a case that reaches its ceiling at a creation leaves a run that can still close", async (t) => {
  clock.set(START);
  const world = createWorld({ project: PROJECT });
  const ownership = createOwnership({ project: PROJECT, runId: UNSENT_RUN });
  const ledger = createLedger();
  const notes = [];
  const capture = createCapture({ journal: { write: (line) => notes.push(line) } });
  const transport = { name: "rest", request: (call) => world.request(call) };
  const cleanupClient = createClient({ transports: { eventarc: transport }, ownership, caseId: "cleanup", usageProject: PROJECT, ledger });
  const item = {
    id: "tight",
    short: "ti",
    requests: 3,
    async run(ctx) {
      // Two reads, one creation (the third request), then a second creation that the ceiling refuses.
      await ctx.client.getChannel(ctx.channel("x"));
      await ctx.client.getChannel(ctx.channel("y"));
      await ctx.client.createChannel(PROJECT, "us-central1", `fe${UNSENT_RUN}-ti-x`);
      await ctx.client.createChannel(PROJECT, "us-central1", `fe${UNSENT_RUN}-ti-y`);
    },
  };
  const summary = await runCases({
    cases: [item],
    transports: { eventarc: transport, publishing: transport, usage: transport },
    cleanupClient,
    ownership,
    capture,
    options: { production: false, location: "us-central1", usageProject: PROJECT, publishPrefix: "/v1" },
    sleep: async () => {},
    ledger,
  });
  assert.deepEqual(summary.limited, ["tight"]);
  const y = ledger.state().get(unsentName("ti-y"));
  assert.deepEqual([y.open, y.creates], [[], ["unsent"]]);
  assert.deepEqual(summary.cleanup.unconfirmed, []);
  assert.ok(!summary.cleanup.unsettled.includes(unsentName("ti-y")), "nothing to settle for a request that never left");
  // x: sent, answered 2xx with an operation never read (the case stopped): it is deleted by the cleanup.
  assert.equal(world.channels.has(unsentName("ti-x")), false);
  void t;
});
