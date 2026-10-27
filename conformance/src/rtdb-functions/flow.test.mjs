// The CV14 run from admission to the terminal decision, with every collaborator replaced by a fake:
// the order of the phases, what a failure at each point leaves to clean up, what is never sent twice,
// and when the run counts as recorded, as needing review, or as leaving residue.

import assert from "node:assert/strict";
import { test } from "node:test";

import { FIXTURE_HANDLERS } from "./frames.mjs";
import { STAGE2_WINDOWS, runStage2 } from "./flow.mjs";
import { makeWorld } from "./flow.fake.mjs";
import { STEPS } from "./sequence.mjs";

const names = (events, prefix) => events.filter((e) => e.startsWith(prefix));

test("a complete run: preflight, inventory, RTDB up, eight deploys, nine writes, then the cleanups in order", async () => {
  const w = makeWorld();
  const result = await runStage2(w.deps);
  assert.equal(result.outcome, "recorded", result.reasons.join("; "));
  assert.equal(result.residual, false);
  assert.deepEqual(result.reasons, []);
  const order = w.events.filter((e) => !e.startsWith("sleep") && e !== "logs");
  const idx = (prefix) => order.findIndex((e) => e.startsWith(prefix));
  assert.ok(idx("preflight") < idx("inventory-take"));
  assert.ok(idx("inventory-take") < idx("absent"));
  assert.ok(order.lastIndexOf(order.findLast((e) => e.startsWith("absent"))) < idx("rtdb-setup"));
  assert.ok(idx("rtdb-setup") < idx("deploy"));
  assert.deepEqual(
    names(w.events, "deploy "),
    FIXTURE_HANDLERS.map((h) => `deploy ${h.name}`),
  );
  assert.deepEqual(
    names(w.events, "read "),
    FIXTURE_HANDLERS.map((h) => `read ${h.name}`),
  );
  assert.ok(order.lastIndexOf(order.findLast((e) => e.startsWith("read"))) < idx("write"));
  assert.deepEqual(
    w.written,
    STEPS.map((s) => s.id),
  );
  const cleanupAt = order.findIndex((e) => e.startsWith("cleanup"));
  assert.ok(order.findLast((e) => e.startsWith("write")) !== undefined);
  assert.ok(cleanupAt > order.findLastIndex((e) => e.startsWith("write")));
  assert.deepEqual(
    names(w.events, "cleanup "),
    FIXTURE_HANDLERS.map((h) => `cleanup ${h.name}`),
  );
  assert.ok(idx("inventory-clean") > order.findLastIndex((e) => e.startsWith("cleanup")));
  assert.ok(idx("rtdb-cleanup") > idx("inventory-clean"));
  assert.equal(result.deployed, 8);
  assert.deepEqual(
    Object.keys(result.records),
    FIXTURE_HANDLERS.map((h) => h.name),
  );
  assert.equal(result.report.totals.unattributed, 0);
  assert.equal(result.report.steps.length, 9);
  for (const step of result.report.steps) {
    for (const h of Object.values(step.handlers)) assert.equal(h.matchesDocumented, true, step.id);
  }
});

test("the Eventarc names of the 2nd gen records reach the inventory cleanup", async () => {
  const w = makeWorld();
  let received;
  w.deps.inventory.removeLeftovers = async (before, owned) => {
    received = owned;
    return { ok: true, deleted: [], residual: {}, incomplete: false, error: null };
  };
  await runStage2(w.deps);
  assert.deepEqual(
    received.map((o) => o.trigger).toSorted(),
    FIXTURE_HANDLERS.filter((h) => h.generation === 2)
      .map((h) => `t-${h.name}`)
      .toSorted(),
  );
});

test("a refused preflight sends nothing: no RTDB, no deploy, no cleanup of what never started", async () => {
  const w = makeWorld({ preflightFails: true });
  const result = await runStage2(w.deps);
  assert.equal(result.outcome, "stopped-needs-review");
  assert.match(result.reasons.join(";"), /preflight refused/);
  assert.equal(result.residual, false);
  assert.deepEqual(w.events, ["preflight"]);
});

test("a function that already exists stops the run before any RTDB or deploy request", async () => {
  const w = makeWorld({ present: "rtdbUpdatedV1" });
  const result = await runStage2(w.deps);
  assert.match(result.reasons.join(";"), /already exists/);
  assert.equal(names(w.events, "rtdb-").length, 0);
  assert.equal(names(w.events, "deploy").length, 0);
  assert.equal(result.residual, false);
});

test("a failed RTDB setup deploys nothing, and the RTDB cleanup still runs", async () => {
  const w = makeWorld({ setupFails: true });
  const result = await runStage2(w.deps);
  assert.match(result.reasons.join(";"), /setup refused/);
  assert.equal(names(w.events, "deploy").length, 0);
  assert.equal(names(w.events, "write").length, 0);
  assert.ok(w.events.includes("rtdb-cleanup"));
  assert.equal(names(w.events, "cleanup ").length, 0);
});

test("a deploy that fails stops the deploys, observes nothing, and cleans up what had started", async () => {
  const w = makeWorld({ failDeploy: "rtdbWrittenV1" });
  const result = await runStage2(w.deps);
  assert.equal(result.outcome, "stopped-needs-review");
  assert.match(result.reasons.join(";"), /deploy failed/);
  assert.deepEqual(
    names(w.events, "deploy "),
    ["rtdbCreatedV1", "rtdbUpdatedV1", "rtdbDeletedV1", "rtdbWrittenV1"].map((n) => `deploy ${n}`),
  );
  assert.equal(names(w.events, "write").length, 0);
  assert.deepEqual(
    names(w.events, "cleanup "),
    ["rtdbCreatedV1", "rtdbUpdatedV1", "rtdbDeletedV1", "rtdbWrittenV1"].map((n) => `cleanup ${n}`),
    "the failed one may have made a function; the four that never started are not touched",
  );
  assert.equal(result.residual, false);
  assert.equal(result.report, null);
});

test("an unknown write answer ends the sequence without a second send and still cleans up", async () => {
  const w = makeWorld({ answers: { s3: { outcome: "unknown", status: 0 } } });
  const result = await runStage2(w.deps);
  assert.equal(result.outcome, "stopped-needs-review");
  assert.match(result.reasons.join(";"), /write s3 .*unknown/);
  assert.deepEqual(w.written, ["s1", "s2", "s3"]);
  assert.equal(result.report.steps.find((s) => s.id === "s3").write.outcome, "unknown");
  assert.equal(result.report.steps.find((s) => s.id === "s4").write, null);
  assert.equal(names(w.events, "cleanup ").length, 8);
  assert.ok(w.events.includes("rtdb-cleanup"));
});

test("a refused write is an observation: the sequence goes on", async () => {
  const w = makeWorld({ answers: { s8: { outcome: "refused", status: 401 } } });
  const result = await runStage2(w.deps);
  assert.deepEqual(
    w.written,
    STEPS.map((s) => s.id),
  );
  assert.equal(result.report.steps.find((s) => s.id === "s8").write.status, 401);
  assert.equal(result.outcome, "recorded", result.reasons.join(";"));
});

test("a missing delivery is a finding, not a reason: the run is recorded and the report says what was not delivered", async () => {
  const w = makeWorld({ silent: new Set(["rtdbCreatedV2"]) });
  const result = await runStage2(w.deps);
  assert.equal(result.outcome, "recorded", result.reasons.join(";"));
  const s1 = result.report.steps.find((s) => s.id === "s1");
  assert.equal(s1.handlers.rtdbCreatedV2.frames, 0);
  assert.equal(s1.handlers.rtdbCreatedV2.matchesDocumented, false);
  assert.ok(
    w.events.filter((e) => e === "logs").length > 10,
    "it kept reading for the missing frames",
  );
});

test("the wait for a step is bounded and the run waits a final window after the last write", async () => {
  const w = makeWorld({ silent: new Set(FIXTURE_HANDLERS.map((h) => h.name)) });
  const start = w.clock.now();
  await runStage2(w.deps);
  const elapsed = w.clock.now() - start;
  const w2 = STAGE2_WINDOWS;
  assert.ok(elapsed <= STEPS.length * w2.stepMs + w2.finalMs + 60_000, "bounded");
  assert.ok(
    w.events.filter((e) => e === "logs").length <=
      STEPS.length * Math.ceil(w2.stepMs / w2.pollMs) + Math.ceil(w2.finalMs / w2.pollMs) + 20,
  );
});

test("a log read that is incomplete makes the observation unreliable", async () => {
  const w = makeWorld({ logsIncomplete: true });
  const result = await runStage2(w.deps);
  assert.equal(result.outcome, "stopped-needs-review");
  assert.match(result.reasons.join(";"), /Logging/);
});

test("a stop request ends the sequence at the next step and the cleanups still run", async () => {
  const abort = { stopped: false };
  const w = makeWorld({ abort });
  const original = w.deps.rtdb.write;
  w.deps.rtdb.write = async (step) => {
    const answer = await original(step);
    if (step.id === "s2") abort.stopped = true;
    return answer;
  };
  const result = await runStage2(w.deps);
  assert.deepEqual(w.written, ["s1", "s2"]);
  assert.match(result.reasons.join(";"), /signal/);
  assert.equal(names(w.events, "cleanup ").length, 8);
  assert.ok(w.events.includes("rtdb-cleanup"));
});

test("a target that cannot be cleaned makes the run residual, and the others are still cleaned", async () => {
  const w = makeWorld({ cleanupFails: "rtdbDeletedV2" });
  const result = await runStage2(w.deps);
  assert.equal(result.residual, true);
  assert.equal(result.outcome, "stopped-needs-review");
  assert.equal(names(w.events, "cleanup ").length, 8);
  assert.equal(result.cleanup.targets.rtdbDeletedV2.cleaned, false);
  assert.match(result.cleanup.targets.rtdbDeletedV2.error, /remains/);
});

test("leftovers of the inventory, an RTDB that did not close and an open upload ledger each make the run residual", async () => {
  for (const [options, pattern] of [
    [
      {
        inventory: {
          ok: false,
          deleted: [],
          residual: { triggers: ["t"] },
          incomplete: false,
          error: null,
        },
      },
      /inventory/,
    ],
    [{ rtdb: { closed: false, errors: ["e"], unresolved: [{ step: "x" }] } }, /RTDB/],
    [{ uploadsOpen: true }, /upload ledger/],
  ]) {
    const result = await runStage2(makeWorld(options).deps);
    assert.equal(result.residual, true, JSON.stringify(options));
    assert.equal(result.outcome, "stopped-needs-review");
    assert.match(result.reasons.join(";"), pattern);
  }
});

test("the journal names every phase, in order", async () => {
  const w = makeWorld();
  await runStage2(w.deps);
  const phases = w.log.filter(([a]) => a === "phase").map(([, d]) => d);
  assert.deepEqual(phases, [
    "preflight",
    "inventory",
    "rtdb-up",
    "deploy",
    "observe",
    "cleanup",
    "closed",
  ]);
});
