// The corpus: every scenario both sides run, in the order they run.
//
// Order is part of the contract. Scenarios share one emulator instance per variant, so a
// later scenario may observe state an earlier one wrote; reordering the list changes what is
// recorded and therefore invalidates the fixtures.

import { scenarios as appcheck } from "./appcheck.mjs";
import { scenarios as auth } from "./auth.mjs";
import { scenarios as firestore } from "./firestore.mjs";
import { scenarios as functions } from "./functions.mjs";
import { scenarios as lite } from "./lite.mjs";
import { scenarios as storage } from "./storage.mjs";

export const SCENARIOS = Object.freeze([
  ...firestore,
  ...lite,
  ...auth,
  ...storage,
  ...functions,
  ...appcheck,
]);

/** The scenarios of one variant, in corpus order. */
export const scenariosFor = (variant) => SCENARIOS.filter((s) => s.variant === variant);

/** Every variant the corpus uses, in first-appearance order. */
export const variantsUsed = () => [...new Set(SCENARIOS.map((s) => s.variant))];

const ids = new Set();
for (const scenario of SCENARIOS) {
  if (ids.has(scenario.id)) throw new Error(`duplicate scenario id ${scenario.id}`);
  ids.add(scenario.id);
}
