// A generated test of the run flow: random failures at every point (a refused preflight, a function that
// is already there, a failed RTDB setup, a failed deploy or read at any of the eight functions, any
// write answered unknown or refused, a signal, an incomplete log read, a cleanup that fails or throws,
// leftovers in the inventory, an RTDB that did not close, an open upload ledger) checked against a
// reference model of what happens, plus the safety properties that must hold in every world:
// nothing is cleaned that was not started, nothing is written twice or after an unknown answer, and
// nothing is cleaned before the writes are over. The seed is fixed, so a failure names its case.

import assert from "node:assert/strict";
import { test } from "node:test";

import { STAGE2_WINDOWS, runStage2 } from "./flow.mjs";
import { makeWorld, targets } from "./flow.fake.mjs";
import { STEPS } from "./sequence.mjs";

const BASE_SEED = 0x14c0de14;
const CASES = 400;

function prng(seed) {
  let a = seed >>> 0;
  const next = () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4_294_967_296;
  };
  return {
    int: (n) => Math.floor(next() * n),
    pick: (list) => list[Math.floor(next() * list.length)],
    chance: (p) => next() < p,
  };
}

/** One random world: every fault is independent and rare, some worlds have none. */
function generate(rng) {
  const name = () => rng.pick(targets).functionName;
  const fault = {};
  if (rng.chance(0.08)) fault.preflightFails = true;
  if (rng.chance(0.08)) fault.present = name();
  if (rng.chance(0.08)) fault.setupFails = true;
  if (rng.chance(0.15)) fault.failDeploy = name();
  if (rng.chance(0.08)) fault.failRead = name();
  if (rng.chance(0.2)) {
    const answers = {};
    for (const step of STEPS) {
      if (rng.chance(0.15))
        answers[step.id] = rng.pick([
          { outcome: "unknown", status: 0 },
          { outcome: "refused", status: 401 },
        ]);
    }
    fault.answers = answers;
  }
  if (rng.chance(0.1)) fault.logsIncomplete = true;
  if (rng.chance(0.12)) fault.cleanupFails = name();
  if (rng.chance(0.06)) fault.cleanupThrows = name();
  if (rng.chance(0.08))
    fault.inventory = {
      ok: false,
      deleted: [],
      residual: { triggers: ["t"] },
      incomplete: false,
      error: null,
    };
  if (rng.chance(0.08)) fault.rtdb = { closed: false, errors: ["e"], unresolved: [] };
  if (rng.chance(0.06)) fault.uploadsOpen = true;
  if (rng.chance(0.1)) fault.silent = new Set([name()]);
  const abortAt = rng.chance(0.12) ? rng.pick(["deploy", "write"]) : null;
  return { fault, abortAt, abortIndex: rng.int(8) };
}

/** What the flow must do in that world, written from the specification, not from the code. */
function reference({ fault, abortAt, abortIndex }) {
  const order = targets.map((t) => t.functionName);
  const model = {
    reasons: false,
    residual: false,
    started: [],
    rtdbAttempted: false,
    written: [],
    inventoryRan: false,
  };
  if (fault.preflightFails) return { ...model, reasons: true };
  if (fault.present) return { ...model, reasons: true };
  model.rtdbAttempted = true;
  if (fault.setupFails)
    return {
      ...model,
      reasons: true,
      rtdbAttempted: true,
      residual: !!fault.rtdb && !fault.rtdb.closed ? true : !!fault.uploadsOpen,
    };
  let deployedAll = true;
  for (const [index, name] of order.entries()) {
    if (abortAt === "deploy" && index === abortIndex) {
      model.reasons = true;
      deployedAll = false;
      break;
    }
    model.started.push(name);
    if (fault.failDeploy === name || fault.failRead === name) {
      model.reasons = true;
      deployedAll = false;
      break;
    }
  }
  if (deployedAll) {
    let sent = 0;
    for (const [index, step] of STEPS.entries()) {
      if (abortAt === "write" && index > abortIndex % STEPS.length) {
        model.reasons = true;
        break;
      }
      model.written.push(step.id);
      sent += 1;
      const answer = fault.answers?.[step.id];
      if (answer?.outcome === "unknown") {
        model.reasons = true;
        break;
      }
      void sent;
    }
  }
  return model;
}

test("generated worlds: the flow does what the specification says and keeps its safety properties", async () => {
  for (let n = 0; n < CASES; n += 1) {
    const world = generate(prng(BASE_SEED + n));
    const label = `case ${n} (seed ${(BASE_SEED + n).toString(16)}): ${JSON.stringify(world, (_k, v) => (v instanceof Set ? [...v] : v))}`;
    const abort = { stopped: false };
    const w = makeWorld({ ...world.fault, abort });
    // the signal arrives when the named point is reached
    if (world.abortAt === "deploy" && world.abortIndex === 0) {
      const preflight = w.deps.preflight;
      w.deps.preflight = async () => {
        await preflight();
        abort.stopped = true;
      };
    } else if (world.abortAt === "deploy") {
      const original = w.deps.ops;
      for (const gen of ["gcfv1", "gcfv2"]) {
        const deploy = original[gen].deploy;
        original[gen].deploy = async (spec, state) => {
          if (targets.findIndex((t) => t.key === spec.key) === world.abortIndex - 1)
            abort.stopped = true;
          return deploy(spec, state);
        };
      }
    }
    if (world.abortAt === "write") {
      const write = w.deps.rtdb.write;
      w.deps.rtdb.write = async (step) => {
        const answer = await write(step);
        if (STEPS.findIndex((s) => s.id === step.id) === world.abortIndex % STEPS.length)
          abort.stopped = true;
        return answer;
      };
    }
    const result = await runStage2(w.deps);
    const events = w.events.filter((e) => !e.startsWith("sleep") && e !== "logs");

    // safety properties, in every world
    const deployed = events.filter((e) => e.startsWith("deploy ")).map((e) => e.slice(7));
    const cleaned = events.filter((e) => e.startsWith("cleanup ")).map((e) => e.slice(8));
    assert.deepEqual(
      cleaned,
      deployed,
      `every started target is cleaned once, in order, and no other: ${label}`,
    );
    const written = events.filter((e) => e.startsWith("write ")).map((e) => e.slice(6));
    assert.equal(new Set(written).size, written.length, `no write twice: ${label}`);
    const unknownAt = STEPS.findIndex(
      (s) => w.deps.rtdb && world.fault.answers?.[s.id]?.outcome === "unknown",
    );
    if (unknownAt >= 0 && written.includes(STEPS[unknownAt].id)) {
      assert.equal(
        written.at(-1),
        STEPS[unknownAt].id,
        `nothing is written after an unknown answer: ${label}`,
      );
    }
    const lastWork = events.findLastIndex((e) => /^(deploy|read|write) /u.test(e));
    const firstCleanup = events.findIndex((e) =>
      /^(cleanup |inventory-clean|rtdb-cleanup)/u.test(e),
    );
    if (firstCleanup >= 0)
      assert.ok(firstCleanup > lastWork, `cleanup comes after the work: ${label}`);
    assert.equal(
      events.includes("rtdb-cleanup"),
      events.includes("rtdb-setup"),
      `RTDB cleanup iff setup: ${label}`,
    );
    assert.equal(
      events.some((e) => e.startsWith("inventory-clean")),
      deployed.length > 0,
      `inventory cleanup iff something started: ${label}`,
    );
    assert.equal(w.deps.abort, abort);

    // the reference model
    const model = reference(world);
    assert.deepEqual(deployed, model.started, `started targets: ${label}`);
    assert.deepEqual(written, model.written, `writes sent: ${label}`);
    const cleanupFault = (name) =>
      world.fault.cleanupFails === name || world.fault.cleanupThrows === name;
    const failedClean = model.started.some(cleanupFault);
    const residual =
      failedClean ||
      (model.started.length > 0 && world.fault.inventory?.ok === false) ||
      (model.rtdbAttempted && world.fault.rtdb?.closed === false) ||
      world.fault.uploadsOpen === true;
    assert.equal(result.residual, residual, `residual: ${label}`);
    const mustReview =
      model.reasons ||
      residual ||
      (world.fault.logsIncomplete === true && events.length > 0 && w.events.includes("logs"));
    assert.equal(result.outcome === "stopped-needs-review", mustReview, `outcome: ${label}`);
    assert.equal(result.reasons.length === 0, !mustReview, `reasons: ${label}`);
  }
  assert.ok(STAGE2_WINDOWS.stepMs > 0);
});
