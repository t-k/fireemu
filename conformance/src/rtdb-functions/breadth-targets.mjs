import { resolveTarget } from "../../functions-http/harness.mjs";
import { FIXTURE_HANDLERS, LOCATION } from "./breadth-frames.mjs";
import { resolveGen1Target } from "./gen1.mjs";

export const CODEBASE = "rtdb-breadth-oracle";
export const TARGETS = Object.freeze(
  FIXTURE_HANDLERS.map((handler) => {
    const spec = {
      functionName: handler.name,
      region: LOCATION,
      codebase: CODEBASE,
      generation: handler.generation === 1 ? "gcfv1" : "gcfv2",
    };
    return {
      ...(handler.generation === 1 ? resolveGen1Target(spec) : resolveTarget(spec)),
      required: handler.retry,
    };
  }),
);
