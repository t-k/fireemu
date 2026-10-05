import assert from "node:assert/strict";
import test from "node:test";
import { BudgetExceeded, createCapture } from "./pubsub-production/capture.mjs";
import { createLedger } from "./pubsub-production/ledger.mjs";
import { CaseAbort, StopClean } from "./eventarc-production/cases/support.mjs";
import { createClient } from "./eventarc-production/client.mjs";
import { createOwnership } from "./eventarc-production/names.mjs";
import { CaseLimit, runCases } from "./eventarc-production/runner.mjs";

const RUN = "0123456789ab";
const PROJECT = "demo-project";

async function run(cases) {
  const ownership = createOwnership({ project: PROJECT, runId: RUN });
  const ledger = createLedger();
  const capture = createCapture({ journal: { write: () => {} } });
  // Nothing is listed or owned: the cleanup finds nothing to do.
  const transport = {
    name: "rest",
    request: async () => ({ status: 200, body: {}, unknown: false }),
  };
  const cleanupClient = createClient({
    transports: { eventarc: transport },
    ownership,
    caseId: "cleanup",
    usageProject: "p",
    ledger,
  });
  const summary = await runCases({
    cases,
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
  return { summary, ownership };
}

const item = (id, body) => ({ id, short: id.slice(0, 2), requests: 5, run: body });

test("how a case ends is recorded with its reason, and only some endings stop the run", async () => {
  const { summary } = await run([
    item("aborted", async () => {
      throw new CaseAbort("a step did not answer");
    }),
    item("plain", async () => {}),
    item("limited", async () => {
      throw new CaseLimit(7);
    }),
    item("broken", async () => {
      throw new TypeError("not a function");
    }),
    item("stopped", async () => {
      throw new StopClean("the precondition is missing");
    }),
    item("never-run", async () => {}),
  ]);
  assert.deepEqual(
    summary.cases.map(({ id, outcome, reason }) => ({ id, outcome, reason })),
    [
      {
        id: "aborted",
        outcome: "aborted",
        reason: "a step did not answer did not succeed (no answer)",
      },
      { id: "plain", outcome: "completed", reason: undefined },
      {
        id: "limited",
        outcome: "limit",
        reason: "the case reached its limit of 7 requests",
      },
      { id: "broken", outcome: "error", reason: "TypeError: not a function" },
      { id: "stopped", outcome: "stopped", reason: "the precondition is missing" },
    ],
  );
  // An abort and a limit let the run go on; a stop does not run the cases after it.
  assert.equal(summary.stopped, "the precondition is missing");
  assert.deepEqual(summary.limited, ["limited"]);
  assert.equal(summary.cleanup !== null, true, "the cleanup runs after a stop");
});

test("a spent budget stops the run with its message and the cleanup still runs", async () => {
  const { summary } = await run([
    item("spent", async () => {
      throw new BudgetExceeded(3);
    }),
    item("never-run", async () => {}),
  ]);
  assert.deepEqual(
    summary.cases.map(({ id, outcome, reason }) => ({ id, outcome, reason })),
    [{ id: "spent", outcome: "budget", reason: "the request budget of 3 is spent" }],
  );
  assert.equal(summary.stopped, "the request budget of 3 is spent");
  assert.notEqual(summary.cleanup, null);
});

test("the limit error is named, and a probe is listable unless the case says it is not", async () => {
  assert.equal(new CaseLimit(3).name, "CaseLimit");
  assert.equal(new CaseLimit(3).message, "the case reached its limit of 3 requests");
  const { ownership } = await run([
    item("probes", async (ctx) => {
      ctx.probe("goog-a", { location: "europe-west1" });
      ctx.probe("goog-b", { location: "nowhere-1", listable: false });
    }),
  ]);
  assert.deepEqual(ownership.locations().toSorted(), ["europe-west1"]);
});
