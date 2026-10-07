// The ids of the resources a local scenario creates, built the way the production recorder builds them (record/main.mjs):
// "e", 24 random hex digits, the first letter of the role and a decimal counter. The counter a scenario gets is the one it
// gets in the first pass of the production script (the scenarios and their ids are the script's), so an id has the same length
// on both sides and no length difference needs a mask. The production formula itself lives in record/main.mjs (part of the
// recorder's digest); the test pins that it is unchanged.

import { randomBytes } from "node:crypto";
import { buildPass } from "./record/script.mjs";

/** The production formula, for a given counter value and random hex. */
export const buildResourceId = (role, counter, hex) => `e${hex}${role.slice(0, 1)}${counter}`;

let counters;

/**
 * For every step of the first production pass: the counter of the first id it takes, keyed `<scenario>/<role>` (role is
 * `subject` or `positive-control-after`). Found by running the script's own builder with a tagging id function.
 */
export function productionCounters() {
  if (counters === undefined) {
    counters = new Map();
    let n = 0;
    const { steps } = buildPass({ pass: 1, newId: () => `Q${(n += 1)}Q` });
    for (const step of steps) {
      const text = JSON.stringify([step.requests, step.matchKey]);
      const seen = [...text.matchAll(/Q(\d+)Q/g)].map((match) => Number(match[1]));
      if (seen.length > 0) counters.set(`${step.scenarioId}/${step.role}`, Math.min(...seen));
    }
  }
  return counters;
}

/**
 * The id of a resource of `scenarioId`: `role` is the script's role word ("fs", "obj", "user", "msg"), `offset` the index of
 * the id within the scenario (the second user of a bulk delete is 1). `hex` is for tests.
 */
export function resourceId(
  scenarioId,
  role,
  { offset = 0, scenarioRole = "subject", hex = randomBytes(12).toString("hex") } = {},
) {
  const first = productionCounters().get(`${scenarioId}/${scenarioRole}`);
  if (first === undefined) throw new Error(`the production script takes no id for ${scenarioId}`);
  return buildResourceId(role, first + offset, hex);
}
