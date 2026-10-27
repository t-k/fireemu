// The CV14 run from admission to the terminal decision. Every collaborator comes in through `deps`
// (the REST control, the Firebase CLI, the RTDB administration, the log reader, the clock), so the order
// of the phases and the decisions can be tested without a service. Nothing here knows an endpoint.
//
//   preflight -> inventory -> rtdb-up -> deploy (eight, one CLI call each, in order) -> observe (nine
//   writes, then a final window) -> cleanup (functions, then the inventory, then the RTDB) -> closed
//
// A failure ends the phase it happens in; the cleanup always runs for what was started and for nothing
// that was not. A request whose answer is unknown is never sent again.

import { FIXTURE_HANDLERS } from "./frames.mjs";
import { STEPS, documentedFires, itemTransitions, observe } from "./sequence.mjs";

/** How long the run waits: for a step with a documented delivery, for one without, after the last write. */
export const STAGE2_WINDOWS = Object.freeze({
  stepMs: 90_000,
  quietMs: 30_000,
  finalMs: 120_000,
  pollMs: 10_000,
  // After the last deploy and before the first write: a trigger is not live the moment its deploy ends
  // (the FUNCTIONS-EVENTS recorder waits the same 300 s, deploy.mjs PROPAGATION_WAIT_SECONDS).
  propagationMs: 300_000,
});

const TRANSITIONS = new Map(itemTransitions(STEPS).map((t) => [t.step, t]));

const expectedHandlers = (step) => {
  const { before, after } = TRANSITIONS.get(step.id);
  return FIXTURE_HANDLERS.filter((h) => documentedFires(h.event, before, after)).map((h) => h.name);
};

export async function runStage2(deps) {
  const { targets, ops, clock, windows, abort, log } = deps;
  const states = new Map(targets.map((t) => [t.key, { started: false, cleaned: false }]));
  const reasons = [];
  const result = {
    outcome: "recorded",
    reasons,
    residual: false,
    deployed: 0,
    report: null,
    records: {},
    frames: [],
    logs: { reads: 0, entries: 0, incomplete: false },
    cleanup: { targets: {}, inventory: null, rtdb: null },
  };
  const phase = (name) => log("phase", name);
  const opsOf = (spec) => ops[spec.generation];
  const writes = {};
  let before = null;
  let rtdbAttempted = false;
  let start = null;

  const readLogs = async () => {
    const reply = await deps.logs.read({
      start,
      end: new Date(clock.now() + 300_000).toISOString(),
    });
    result.logs.reads += 1;
    result.logs.entries += reply.entries ?? 0;
    if (!reply.complete && !result.logs.incomplete) {
      result.logs.incomplete = true;
      reasons.push("a Cloud Logging read was incomplete, so the observation is not reliable");
    }
    result.frames.push(...reply.frames.map((entry) => entry.frame ?? entry));
  };

  const delivered = (step, handlers) => {
    const reported = observe({ writes, frames: result.frames }).steps.find((s) => s.id === step.id);
    return handlers.every((name) => reported.handlers[name].frames >= 1);
  };

  const waitForStep = async (step, answer) => {
    const expected = answer.outcome === "ok" ? expectedHandlers(step) : [];
    const limit = expected.length > 0 ? windows.stepMs : windows.quietMs;
    const deadline = clock.now() + limit;
    while (clock.now() < deadline && !abort.stopped) {
      await clock.sleep(windows.pollMs);
      await readLogs();
      if (expected.length > 0 && delivered(step, expected)) return;
    }
  };

  try {
    await phase("preflight");
    await deps.preflight();
    await phase("inventory");
    before = await deps.inventory.take();
    if (!before.complete) throw new Error("the inventory before the run is incomplete");
    for (const spec of targets) await opsOf(spec).assertAbsent(spec);
    await phase("rtdb-up");
    rtdbAttempted = true;
    await deps.rtdb.setup();

    await phase("deploy");
    start = new Date(clock.now() - 60_000).toISOString();
    for (const spec of targets) {
      if (abort.stopped) throw new Error("a signal stopped the run before the next deploy");
      const state = states.get(spec.key);
      await opsOf(spec).deploy(spec, state);
      await opsOf(spec).read(spec, state);
      result.records[spec.key] = state.record ?? null;
      result.deployed += 1;
    }

    await phase("observe");
    await log("propagation-wait", `${windows.propagationMs} ms before the first write`);
    for (
      const until = clock.now() + windows.propagationMs;
      clock.now() < until && !abort.stopped;
    ) {
      await clock.sleep(Math.min(3 * windows.pollMs, until - clock.now()));
    }
    let sent = 0;
    for (const step of STEPS) {
      if (abort.stopped) {
        reasons.push("a signal stopped the sequence");
        break;
      }
      await log("write-intent", step.id);
      let answer;
      try {
        answer = await deps.rtdb.write(step);
      } catch (error) {
        reasons.push(`write ${step.id} was not completed: ${error.message}`);
        break;
      }
      sent += 1;
      writes[step.id] = answer;
      await log("write-answer", `${step.id} ${answer.outcome} ${answer.status}`);
      if (answer.outcome === "unknown") {
        reasons.push(`write ${step.id} answer is unknown; it is not sent again`);
        break;
      }
      await waitForStep(step, answer);
    }
    if (sent > 0 && !abort.stopped) {
      const deadline = clock.now() + windows.finalMs;
      while (clock.now() < deadline && !abort.stopped) {
        await clock.sleep(windows.pollMs);
        await readLogs();
      }
    }
  } catch (error) {
    reasons.push(error.message);
  }
  if (Object.keys(writes).length > 0 || result.frames.length > 0) {
    result.report = observe({ writes, frames: result.frames });
  }

  // ---- cleanup: only what was started, each part on its own ----
  await phase("cleanup");
  const owned = [];
  for (const spec of targets) {
    const state = states.get(spec.key);
    if (!state.started) continue;
    try {
      await opsOf(spec).cleanup(spec, state);
    } catch (error) {
      state.cleanupError = error.message;
    }
    result.cleanup.targets[spec.key] = {
      cleaned: state.cleaned === true,
      error: state.cleanupError ?? null,
    };
    if (state.cleaned !== true) {
      result.residual = true;
      reasons.push(`${spec.key} was not cleaned: ${state.cleanupError ?? "unknown"}`);
    }
    if (state.record) {
      try {
        const names = deps.ownedNames(state.record, spec);
        if (names) owned.push(names);
      } catch (error) {
        reasons.push(`${spec.key}: ${error.message}`);
      }
    }
  }
  const anyStarted = [...states.values()].some((s) => s.started);
  if (anyStarted && before) {
    result.cleanup.inventory = await deps.inventory.removeLeftovers(before, owned);
    if (!result.cleanup.inventory.ok) {
      result.residual = true;
      reasons.push("the inventory shows new resources after the cleanup (or could not be read)");
    }
  }
  if (rtdbAttempted) {
    result.cleanup.rtdb = await deps.rtdb.cleanup();
    if (!result.cleanup.rtdb.closed) {
      result.residual = true;
      reasons.push(
        `the RTDB is not closed (${result.cleanup.rtdb.errors.length} errors, ${result.cleanup.rtdb.unresolved.length} unresolved)`,
      );
    }
  }
  const uploads = deps.uploads.report();
  if (!uploads.closureReady) {
    result.residual = true;
    reasons.push(`source upload ledger is not closed (${uploads.reasons.length} open)`);
  }
  if (reasons.length > 0) result.outcome = "stopped-needs-review";
  await phase("closed");
  return result;
}
