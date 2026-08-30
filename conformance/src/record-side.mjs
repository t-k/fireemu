// A development aid: run one side of one variant and print where the run landed.
//
//   node src/record-side.mjs testd baseline
//   node src/record-side.mjs oracle appCheckEnforced
//
// `oracle` and `check` drive both sides themselves; this exists so a single side can be
// re-run while a scenario is being written, without re-recording any fixture.

import { mkdir } from "node:fs/promises";
import { join } from "node:path";

import { RUNS_DIR, VARIANTS } from "./config.mjs";
import { configFor, runOfficial, runTestd } from "./sides.mjs";

const [side = "testd", variant = VARIANTS.baseline] = process.argv.slice(2);
if (!["oracle", "testd"].includes(side)) throw new Error(`unknown side ${side}`);
if (!Object.values(VARIANTS).includes(variant)) throw new Error(`unknown variant ${variant}`);

await mkdir(RUNS_DIR, { recursive: true });
const outPath = join(RUNS_DIR, `${side}.${variant}.json`);
const result =
  side === "oracle"
    ? await runOfficial({ variant, outPath })
    : await runTestd({ variant, outPath, config: configFor(variant) });

for (const scenario of result.run.scenarios) {
  const faulted = scenario.fault ? `  FAULT: ${scenario.fault}` : "";
  console.log(`${scenario.id}: ${scenario.steps.length} steps${faulted}`);
}
console.log(`\nwrote ${outPath} (supervisor exit ${result.exitCode})`);
