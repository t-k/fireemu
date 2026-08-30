// `pnpm -C conformance run check`: replay the corpus against firebase-testd and diff.
//
// This side needs no Java, no downloaded emulator and no network: the oracle's answers are
// already committed under `fixtures/`. It exits non-zero on the first kind of drift that
// matters -- a `parity` row that changed, a `documented-divergence` row that moved away from
// its recorded firebase-testd value, a step the fixtures do not describe, or a scenario that
// faulted. Rows recorded as `debt` are reported and never gate.

import { mkdir } from "node:fs/promises";
import { join } from "node:path";

import { RUNS_DIR } from "./config.mjs";
import { scenariosFor, variantsUsed } from "./corpus/index.mjs";
import { compareScenario } from "./diff.mjs";
import { readAllFixtures } from "./fixtures.mjs";
import { configFor, runTestd } from "./sides.mjs";

const fixtures = await readAllFixtures();
if (fixtures.size === 0) {
  console.error(
    "no fixtures under conformance/fixtures: run `pnpm -C conformance run oracle` first",
  );
  process.exit(2);
}

await mkdir(RUNS_DIR, { recursive: true });

const failures = [];
const warnings = [];
let scenariosChecked = 0;
let stepsChecked = 0;

for (const variant of variantsUsed()) {
  const scenarios = scenariosFor(variant);
  console.log(`\n=== variant ${variant} (${scenarios.length} scenarios) ===`);
  const testd = await runTestd({
    variant,
    outPath: join(RUNS_DIR, `check.${variant}.json`),
    config: configFor(variant),
  });
  const byId = new Map(testd.run.scenarios.map((s) => [s.id, s]));

  for (const scenario of scenarios) {
    const fixture = fixtures.get(scenario.id);
    if (!fixture) {
      failures.push(
        `${scenario.id}: the corpus declares this scenario but no fixture records it; run \`pnpm run oracle\``,
      );
      continue;
    }
    scenariosChecked += 1;
    const result = compareScenario({ fixture, testdScenario: byId.get(scenario.id) });
    result.match(
      (okValue) => {
        stepsChecked += okValue.checked;
        warnings.push(...okValue.warnings);
        console.log(`  ok   ${scenario.id} (${okValue.checked} gated steps)`);
      },
      (errValue) => {
        warnings.push(...errValue.warnings);
        failures.push(...errValue.failures);
        console.log(`  FAIL ${scenario.id} (${errValue.failures.length} findings)`);
      },
    );
  }
}

// A fixture with no scenario is a corpus that shrank without re-recording.
for (const id of fixtures.keys()) {
  if (
    !scenariosFor("baseline")
      .concat(scenariosFor("appCheckEnforced"))
      .some((s) => s.id === id)
  ) {
    failures.push(`${id}: a fixture exists but the corpus no longer declares the scenario`);
  }
}

if (warnings.length > 0) {
  console.log(`\n${warnings.length} known-debt row(s) changed since they were recorded:`);
  for (const warning of warnings) console.log(`  - ${warning}`);
}

if (failures.length > 0) {
  console.error(`\n${failures.length} conformance failure(s):\n`);
  for (const failure of failures) console.error(`- ${failure}\n`);
  process.exit(1);
}

console.log(
  `\nconformance ok: ${scenariosChecked} scenarios, ${stepsChecked} gated steps matched their fixtures.`,
);
process.exit(0);
