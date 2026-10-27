// The eight CV14 targets in deploy order: the four 1st gen handlers, then the four 2nd gen ones, each its
// own function of the one codebase that firebase.json (next to this file) names.

import { resolveTarget } from "../../functions-http/harness.mjs";
import { FIXTURE_HANDLERS, LOCATION } from "./frames.mjs";
import { resolveGen1Target } from "./gen1.mjs";

export const CODEBASE = "rtdb-functions-oracle";

export const TARGETS = Object.freeze(
  FIXTURE_HANDLERS.map((handler) => {
    const spec = {
      functionName: handler.name,
      region: LOCATION,
      codebase: CODEBASE,
      generation: handler.generation === 1 ? "gcfv1" : "gcfv2",
    };
    return handler.generation === 1 ? resolveGen1Target(spec) : resolveTarget(spec);
  }),
);
