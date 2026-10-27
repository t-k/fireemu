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

test("a refused write is kept in the report, the sequence goes on, and the run needs review with a reason for that write", async () => {
  const w = makeWorld({ answers: { s8: { outcome: "refused", status: 401 } } });
  const result = await runStage2(w.deps);
  assert.deepEqual(
    w.written,
    STEPS.map((s) => s.id),
  );
  assert.equal(result.report.steps.find((s) => s.id === "s8").write.status, 401);
  assert.equal(result.outcome, "stopped-needs-review");
  assert.equal(result.residual, false);
  assert.deepEqual(result.reasons, ["write s8 was not answered ok (refused, status 401)"]);
});

test("every write refused, with a stranger's frame in the log, is a reason per write and the frame's own reason", async () => {
  const answers = Object.fromEntries(STEPS.map((s) => [s.id, { outcome: "refused", status: 401 }]));
  const w = makeWorld({ answers, strangerFrame: true });
  const result = await runStage2(w.deps);
  assert.equal(result.outcome, "stopped-needs-review");
  assert.equal(
    result.reasons.filter((r) => /was not answered ok \(refused, status 401\)/.test(r)).length,
    9,
  );
  assert.match(result.reasons.join(";"), /could not be attributed to a write/);
  assert.equal(result.residual, false);
});

test("a stranger's frame with no write answered ok at all still ends the run needing review, with its own reason", async () => {
  const w = makeWorld({
    answers: { s1: { outcome: "unknown", status: 0 } },
    strangerFrame: true,
    ignoredCounts: { unparsed: 1 },
  });
  const result = await runStage2(w.deps);
  assert.equal(result.outcome, "stopped-needs-review");
  const text = result.reasons.join(";");
  assert.match(text, /write s1 answer is unknown/);
  assert.match(text, /1 frame\(s\) could not be attributed to a write \(no-match: 1\)/);
  assert.match(text, /dropped by the parser: unparsed 1/);
  assert.doesNotMatch(text, /no frame was read/);
});

test("a missing delivery is kept in the report and makes the run need review, not call it recorded", async () => {
  const w = makeWorld({ silent: new Set(["rtdbCreatedV2"]) });
  const result = await runStage2(w.deps);
  assert.equal(result.outcome, "stopped-needs-review");
  assert.equal(result.residual, false);
  assert.match(result.reasons.join(";"), /documented delivery received no frame: s1 rtdbCreatedV2/);
  const s1 = result.report.steps.find((s) => s.id === "s1");
  assert.equal(s1.handlers.rtdbCreatedV2.frames, 0);
  assert.equal(s1.handlers.rtdbCreatedV2.matchesDocumented, false);
  assert.ok(
    w.events.filter((e) => e === "logs").length > 10,
    "it kept reading for the missing frames",
  );
});

test("the judge's findings each end the run needing review: unattributed frames, dropped log entries, no frame, unnamed members", async () => {
  const cases = [
    [{ strangerFrame: true }, /1 frame\(s\) could not be attributed to a write \(no-match: 1\)/],
    [{ ignoredCounts: { unparsed: 2 } }, /dropped by the parser: unparsed 2/],
    [{ ignoredCounts: { unknownHandler: 1 } }, /unknownHandler 1/],
    [{ ignoredCounts: { foreignOrigin: 4 } }, /foreignOrigin 4/],
    [{ silent: new Set(FIXTURE_HANDLERS.map((h) => h.name)) }, /no frame was read/],
    [{ unnamedMember: true }, /members the fixture did not name: domain, traceparent/],
  ];
  for (const [options, pattern] of cases) {
    const result = await runStage2(makeWorld(options).deps);
    assert.equal(
      result.outcome,
      "stopped-needs-review",
      JSON.stringify(options, (_k, v) => (v instanceof Set ? [...v] : v)),
    );
    assert.match(result.reasons.join(";"), pattern);
    assert.equal(result.residual, false);
  }
  // a note the parser dropped that is harmless does not count
  const harmless = await runStage2(makeWorld({ ignoredCounts: { notFrame: 3, notTyped: 1 } }).deps);
  assert.equal(harmless.outcome, "recorded", harmless.reasons.join(";"));
});

test("the ignored counts of the log reads are kept in the result, the largest of any read", async () => {
  const w = makeWorld({ ignoredCounts: { unparsed: 3, notFrame: 2 } });
  const result = await runStage2(w.deps);
  assert.deepEqual(result.logs.ignored, { unparsed: 3, notFrame: 2 });
});

test("nothing is judged when no write was answered ok", async () => {
  const w = makeWorld({ failDeploy: "rtdbCreatedV1" });
  const result = await runStage2(w.deps);
  assert.ok(!result.reasons.join(";").includes("no frame was read"));
});

test("the wait for a step is bounded and the run waits a final window after the last write", async () => {
  const w = makeWorld({ silent: new Set(FIXTURE_HANDLERS.map((h) => h.name)) });
  const start = w.clock.now();
  await runStage2(w.deps);
  const elapsed = w.clock.now() - start;
  const w2 = STAGE2_WINDOWS;
  assert.ok(
    elapsed <= STEPS.length * w2.stepMs + w2.finalMs + w2.propagationMs + 60_000,
    "bounded",
  );
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

// ---- the waits, the window and the bounds of the sequence ----

const between = (events, from, to) => {
  const start = events.indexOf(from);
  const end = to === undefined ? events.length : events.indexOf(to);
  return events.slice(start + 1, end).filter((e) => e === "logs").length;
};

test("a wait ends as soon as every documented frame is in, and a step with nothing documented waits the short window", async () => {
  const w = makeWorld();
  await runStage2(w.deps);
  const poll = STAGE2_WINDOWS.pollMs;
  assert.equal(
    between(w.events, "write s1", "write s2"),
    1,
    "the frames were there at the first read",
  );
  assert.equal(
    between(w.events, "write s3", "write s4"),
    STAGE2_WINDOWS.quietMs / poll,
    "a no-op waits the short window",
  );
  assert.equal(between(w.events, "write s7", "write s8"), STAGE2_WINDOWS.quietMs / poll);
  assert.equal(
    between(w.events, "write s9"),
    STAGE2_WINDOWS.finalMs / poll + 1,
    "the last write's own wait, then the final window",
  );
});

test("when a documented frame never comes the wait runs to the end of its window", async () => {
  const w = makeWorld({ silent: new Set(FIXTURE_HANDLERS.map((h) => h.name)) });
  await runStage2(w.deps);
  assert.equal(
    between(w.events, "write s1", "write s2"),
    STAGE2_WINDOWS.stepMs / STAGE2_WINDOWS.pollMs,
  );
});

test("a refused write expects no frame, so it waits only the short window", async () => {
  const w = makeWorld({ answers: { s2: { outcome: "refused", status: 401 } } });
  await runStage2(w.deps);
  assert.equal(
    between(w.events, "write s2", "write s3"),
    STAGE2_WINDOWS.quietMs / STAGE2_WINDOWS.pollMs,
  );
});

test("the log window starts before the first deploy and ends after now", async () => {
  const w = makeWorld();
  const startedAt = w.clock.now();
  await runStage2(w.deps);
  assert.ok(w.reads.length > 0);
  for (const range of w.reads) {
    assert.ok(Date.parse(range.start) < startedAt, "the window opens before the run");
    assert.ok(Date.parse(range.end) > Date.parse(range.start));
  }
  assert.ok(Date.parse(w.reads.at(-1).end) > w.clock.now());
});

test("an incomplete inventory before the run stops it before any absence check", async () => {
  const w = makeWorld({ inventoryIncomplete: true });
  const result = await runStage2(w.deps);
  assert.match(result.reasons.join(";"), /inventory before the run is incomplete/);
  assert.equal(names(w.events, "absent").length, 0);
  assert.equal(names(w.events, "rtdb-").length, 0);
});

test("a write that could not be sent ends the sequence; with no write sent there is no final window", async () => {
  const second = makeWorld({ writeThrows: "s2" });
  const result = await runStage2(second.deps);
  assert.deepEqual(result.reasons, ["write s2 was not completed: cap reached before the write"]);
  assert.deepEqual(names(second.events, "write "), ["write s1", "write s2"]);
  const first = makeWorld({ writeThrows: "s1" });
  await runStage2(first.deps);
  assert.deepEqual(names(first.events, "write "), ["write s1"]);
  assert.equal(
    first.events.filter((e) => e === "logs").length,
    0,
    "nothing was written, so nothing is waited for",
  );
});

test("a signal during the final window ends it at once", async () => {
  const abort = { stopped: false };
  const w = makeWorld({
    abort,
    onRead: (count) => {
      // the first reads belong to the steps; stop at the second read after the last write
      if (w.events.includes("write s9") && between(w.events, "write s9") >= 2) abort.stopped = true;
      void count;
    },
  });
  await runStage2(w.deps);
  assert.ok(
    between(w.events, "write s9", "cleanup rtdbCreatedV1") <= 3,
    "the final window did not run on",
  );
});

test("the first write waits for the triggers to go live, and a signal ends that wait", async () => {
  const w = makeWorld();
  const startedAt = w.clock.now();
  const slept = [];
  const original = w.clock.sleep;
  w.deps.clock.sleep = async (ms) => {
    slept.push(ms);
    return original(ms);
  };
  let firstWriteAt;
  const write = w.deps.rtdb.write;
  w.deps.rtdb.write = async (step) => {
    firstWriteAt ??= w.clock.now();
    return write(step);
  };
  await runStage2(w.deps);
  assert.ok(firstWriteAt - startedAt >= STAGE2_WINDOWS.propagationMs, "the wait came first");
  assert.ok(slept.slice(0, 10).every((ms) => ms <= 3 * STAGE2_WINDOWS.pollMs));

  const abort = { stopped: false };
  const stopped = makeWorld({ abort });
  const sleep = stopped.clock.sleep;
  stopped.deps.clock.sleep = async (ms) => {
    abort.stopped = true;
    return sleep(ms);
  };
  const result = await runStage2(stopped.deps);
  assert.equal(
    names(stopped.events, "write ").length,
    0,
    "no write after a signal during the wait",
  );
  assert.match(result.reasons.join(";"), /signal/);
  assert.equal(names(stopped.events, "cleanup ").length, 8);
});

// ---- a failed deploy: refused (nothing made) or an unknown create (review M2) ----

test("a deploy that production refused, and whose function was never there, is not an unknown create", async () => {
  const w = makeWorld({ failDeploy: "rtdbCreatedV2", deployClass: "refused", functionSeen: false });
  const result = await runStage2(w.deps);
  assert.equal(result.outcome, "stopped-needs-review");
  assert.equal(result.residual, false, result.reasons.join(";"));
  assert.match(
    result.reasons.join(";"),
    /the deploy of rtdbCreatedV2 was refused by production \(HTTP 400\); nothing was made/,
  );
  assert.deepEqual(result.deploys.rtdbCreatedV2, {
    class: "refused",
    evidence: [{ status: 400 }],
    functionSeen: false,
  });
});

test("a failed deploy whose function was never read present is an unknown create: residual, for the coordinator to accept", async () => {
  for (const options of [
    { deployClass: "unknown", functionSeen: false },
    { deployClass: "unknown" },
  ]) {
    const w = makeWorld({ failDeploy: "rtdbWrittenV1", ...options });
    const result = await runStage2(w.deps);
    assert.equal(result.residual, true, JSON.stringify(options));
    assert.match(result.reasons.join(";"), /the create of rtdbWrittenV1 is unknown/);
    assert.equal(result.deploys.rtdbWrittenV1.class, "unknown");
  }
});

test("a failed deploy whose function the cleanup read present and deleted is settled by that read", async () => {
  const w = makeWorld({ failDeploy: "rtdbWrittenV1", deployClass: "unknown", functionSeen: true });
  const result = await runStage2(w.deps);
  assert.equal(result.residual, false, result.reasons.join(";"));
  assert.doesNotMatch(result.reasons.join(";"), /is unknown/);
  assert.equal(result.deploys.rtdbWrittenV1.functionSeen, true);
});

test("a refused deploy whose function nevertheless existed is a contradiction for the coordinator, and the exact delete still settled it", async () => {
  const w = makeWorld({ failDeploy: "rtdbCreatedV2", deployClass: "refused", functionSeen: true });
  const result = await runStage2(w.deps);
  assert.equal(result.residual, false);
  assert.match(
    result.reasons.join(";"),
    /rtdbCreatedV2 was refused by production yet the function existed/,
  );
});

test("a deploy that did not fail leaves no deploy record", async () => {
  const result = await runStage2(makeWorld().deps);
  assert.deepEqual(result.deploys, {});
  // a failure with no classification (the CLI never started) is not judged either
  const plain = await runStage2(makeWorld({ failDeploy: "rtdbCreatedV1" }).deps);
  assert.deepEqual(plain.deploys, {});
});
