// `pnpm -C conformance run oracle`: record the fixtures.
//
// For each variant the corpus declares, this runs the same corpus twice -- once inside
// `firebase emulators:exec` (the oracle) and once inside `firebase-testd exec` -- then folds
// the two runs into one fixture per scenario, regenerates ORACLE.md from the installed CLI
// and rewrites DEBT.md from whatever did not reach parity.
//
// Recording is the only step that needs Java, a downloaded Firestore emulator jar and several
// minutes. `pnpm run check` replays firebase-testd alone against what this wrote.

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { CONFORMANCE_DIR, RUNS_DIR, STATUS } from "./config.mjs";
import { scenariosFor, variantsUsed } from "./corpus/index.mjs";
import { classifyScenario } from "./diff.mjs";
import { summarize, writeFixture } from "./fixtures.mjs";
import { collectProvenance, renderOracleDoc } from "./provenance.mjs";
import { configFor, runOfficial, runTestd } from "./sides.mjs";
import { renderDebtDoc } from "./debt.mjs";

const annotations = JSON.parse(
  await readFile(join(CONFORMANCE_DIR, "divergences.json"), "utf8"),
).divergences;

const only = process.argv.slice(2).find((a) => !a.startsWith("-")) ?? null;

await mkdir(RUNS_DIR, { recursive: true });
const byScenario = new Map();

for (const variant of variantsUsed()) {
  const scenarios = scenariosFor(variant);
  console.log(`\n=== variant ${variant} (${scenarios.length} scenarios) ===`);

  console.log("  oracle: firebase emulators:exec ...");
  const oracle = await runOfficial({
    variant,
    outPath: join(RUNS_DIR, `oracle.${variant}.json`),
  });

  console.log("  testd:  firebase-testd exec ...");
  const testd = await runTestd({
    variant,
    outPath: join(RUNS_DIR, `testd.${variant}.json`),
    config: configFor(variant),
  });

  const oracleById = new Map(oracle.run.scenarios.map((s) => [s.id, s]));
  const testdById = new Map(testd.run.scenarios.map((s) => [s.id, s]));
  for (const scenario of scenarios) {
    byScenario.set(scenario.id, {
      scenario,
      oracleScenario: oracleById.get(scenario.id),
      testdScenario: testdById.get(scenario.id),
    });
  }
}

const totals = Object.fromEntries(Object.values(STATUS).map((s) => [s, 0]));
const fixtures = [];
let stepCount = 0;

for (const [scenarioId, { scenario, oracleScenario, testdScenario }] of byScenario) {
  if (only && !scenarioId.includes(only)) continue;
  const steps = classifyScenario({ scenarioId, oracleScenario, testdScenario, annotations });
  const summary = summarize(steps);
  for (const [status, count] of Object.entries(summary)) totals[status] += count;
  stepCount += steps.length;
  const fixture = {
    id: scenario.id,
    product: scenario.product,
    title: scenario.title,
    sdks: scenario.sdks,
    variant: scenario.variant,
    oracle: "official Local Emulator Suite, pinned in ORACLE.md",
    summary,
    steps,
  };
  await writeFixture(fixture);
  fixtures.push(fixture);
  const faults = [oracleScenario?.fault, testdScenario?.fault].filter(Boolean);
  console.log(
    `  ${scenarioId}: ${steps.length} steps ` +
      Object.entries(summary)
        .filter(([, n]) => n > 0)
        .map(([s, n]) => `${s}=${n}`)
        .join(" ") +
      (faults.length ? `  FAULT: ${faults.join(" | ")}` : ""),
  );
}

const provenance = await collectProvenance();
await writeFile(
  join(CONFORMANCE_DIR, "ORACLE.md"),
  renderOracleDoc(provenance, { scenarioCount: fixtures.length, stepCount }),
  "utf8",
);
await writeFile(join(CONFORMANCE_DIR, "DEBT.md"), renderDebtDoc(fixtures), "utf8");

console.log(
  `\nrecorded ${fixtures.length} fixtures, ${stepCount} steps: ` +
    Object.entries(totals)
      .map(([s, n]) => `${s}=${n}`)
      .join(" "),
);
console.log("ORACLE.md and DEBT.md regenerated.");
