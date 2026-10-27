// The reference model of the CV14 run flow and the check of one world against it, written from the
// specification (what is started, written and cleaned, and when the run needs review or leaves residue),
// not from the code. Used by the generated test and by the pairwise (PICT) test.

import assert from "node:assert/strict";

import { runStage2 } from "./flow.mjs";
import { makeWorld, targets } from "./flow.fake.mjs";
import { FIXTURE_HANDLERS } from "./frames.mjs";
import { STEPS, documentedFires, itemTransitions } from "./sequence.mjs";

/** What the flow must do in that world, written from the specification, not from the code. */
export function reference({ fault, abortAt, abortIndex }) {
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

/** Runs the flow in `world` and asserts the safety properties and the reference model. */
export async function checkWorld(world, label) {
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
  const firstCleanup = events.findIndex((e) => /^(cleanup |inventory-clean|rtdb-cleanup)/u.test(e));
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
  // a documented delivery that a silent handler never made, for a write that was answered ok
  const transitions = Object.fromEntries(itemTransitions(STEPS).map((t) => [t.step, t]));
  const silent = world.fault.silent ?? new Set();
  const missingDelivery = model.written
    .filter((id) => (world.fault.answers?.[id]?.outcome ?? "ok") === "ok")
    .some((id) =>
      FIXTURE_HANDLERS.some(
        (h) =>
          silent.has(h.name) &&
          documentedFires(h.event, transitions[id].before, transitions[id].after),
      ),
    );
  const mustReview =
    missingDelivery ||
    model.reasons ||
    residual ||
    (world.fault.logsIncomplete === true && events.length > 0 && w.events.includes("logs"));
  assert.equal(result.outcome === "stopped-needs-review", mustReview, `outcome: ${label}`);
  assert.equal(result.reasons.length === 0, !mustReview, `reasons: ${label}`);
}
