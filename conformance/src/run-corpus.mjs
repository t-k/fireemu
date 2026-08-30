// Runs one variant of the corpus inside whichever emulator supervisor started it.
//
// Invoked as the command of `firebase emulators:exec` and of `firebase-testd exec`, so its
// only inputs are the emulator host variables in the environment plus two of its own:
//
//   CONFORMANCE_SIDE       oracle | testd        (recorded with the run, never branched on)
//   CONFORMANCE_VARIANT    baseline | appCheckEnforced
//   CONFORMANCE_OUT        file the run's JSON is written to
//   CONFORMANCE_FUNCTIONS_HOST  host:port of the Functions emulator
//
// The process always exits 0 when it produced a run: a scenario that throws is a recorded
// result, not a harness failure. Only a harness fault (a missing variable, an unwritable
// output file) exits non-zero.

import { mkdir, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

import { VARIANTS } from "./config.mjs";
import { scenariosFor } from "./corpus/index.mjs";
import { createContext, hostsFromEnv } from "./corpus/context.mjs";
import { createShared } from "./corpus/shared.mjs";
import { loadRules } from "./rules.mjs";

const required = (name) => {
  const value = process.env[name];
  if (!value) {
    console.error(`run-corpus: ${name} is not set`);
    process.exit(2);
  }
  return value;
};

const side = required("CONFORMANCE_SIDE");
const variant = required("CONFORMANCE_VARIANT");
const out = required("CONFORMANCE_OUT");
if (!Object.values(VARIANTS).includes(variant)) {
  console.error(`run-corpus: unknown variant ${variant}`);
  process.exit(2);
}

// firebase-admin reads the Storage host from its own variable; the official CLI exports the
// `FIREBASE_` spelling only in some versions, so derive the other from it.
if (!process.env.STORAGE_EMULATOR_HOST && process.env.FIREBASE_STORAGE_EMULATOR_HOST) {
  process.env.STORAGE_EMULATOR_HOST = `http://${process.env.FIREBASE_STORAGE_EMULATOR_HOST}`;
}

const hosts = hostsFromEnv();
const shared = createShared(hosts);

// The official suite loads Security Rules from firebase.json at startup; firebase-testd takes
// them through its control API. Loading them here keeps one source of rules text for both.
const rulesLoad = await loadRules(side, hosts);

const scenarios = scenariosFor(variant);
const results = [];
for (const scenario of scenarios) {
  const { ctx, steps } = createContext({ side, variant, hosts, shared });
  let fault = null;
  try {
    await scenario.run(ctx);
  } catch (error) {
    // A scenario that throws outside a step lost the rest of its rows; that is recorded as
    // the scenario's own fault so the diff can report it instead of silently shrinking.
    fault = String(error?.message ?? error);
  }
  results.push({
    id: scenario.id,
    product: scenario.product,
    title: scenario.title,
    sdks: scenario.sdks,
    variant: scenario.variant,
    fault,
    steps,
  });
  console.error(
    `[${side}/${variant}] ${scenario.id}: ${steps.length} steps${fault ? ` (fault: ${fault})` : ""}`,
  );
}

await mkdir(dirname(out), { recursive: true });
await writeFile(
  out,
  `${JSON.stringify({ side, variant, rulesLoad, scenarios: results }, null, 2)}\n`,
  "utf8",
);

// gRPC channels and the Storage SDK keep the event loop alive; the run is complete.
process.exit(0);
