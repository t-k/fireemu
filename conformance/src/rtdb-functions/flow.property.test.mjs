// A generated test of the run flow: random failures at every point (a refused preflight, a function that
// is already there, a failed RTDB setup, a failed deploy or read at any of the eight functions, any
// write answered unknown or refused, a signal, an incomplete log read, a cleanup that fails or throws,
// leftovers in the inventory, an RTDB that did not close, an open upload ledger) checked against a
// reference model of what happens, plus the safety properties that must hold in every world:
// nothing is cleaned that was not started, nothing is written twice or after an unknown answer, and
// nothing is cleaned before the writes are over. The seed is fixed, so a failure names its case.

import { test } from "node:test";

import { targets } from "./flow.fake.mjs";
import { checkWorld } from "./flow.model.mjs";
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

test("generated worlds: the flow does what the specification says and keeps its safety properties", async () => {
  for (let n = 0; n < CASES; n += 1) {
    const world = generate(prng(BASE_SEED + n));
    const label = `case ${n} (seed ${(BASE_SEED + n).toString(16)}): ${JSON.stringify(world, (_k, v) => (v instanceof Set ? [...v] : v))}`;
    await checkWorld(world, label);
  }
});
