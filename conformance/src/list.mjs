// `pnpm -C conformance run corpus`: what the suite covers, without starting anything.

import { SCENARIOS, variantsUsed } from "./corpus/index.mjs";
import { readAllFixtures } from "./fixtures.mjs";

const fixtures = await readAllFixtures();

for (const variant of variantsUsed()) {
  console.log(`\n${variant}`);
  for (const scenario of SCENARIOS.filter((s) => s.variant === variant)) {
    const fixture = fixtures.get(scenario.id);
    const summary = fixture
      ? Object.entries(fixture.summary)
          .filter(([, n]) => n > 0)
          .map(([s, n]) => `${s}=${n}`)
          .join(" ")
      : "not recorded";
    console.log(`  ${scenario.id.padEnd(44)} [${scenario.sdks.join(", ")}]`);
    console.log(`    ${scenario.title}`);
    console.log(`    ${summary}`);
  }
}

const totals = {};
for (const fixture of fixtures.values()) {
  for (const [status, count] of Object.entries(fixture.summary)) {
    totals[status] = (totals[status] ?? 0) + count;
  }
}
console.log(
  `\n${SCENARIOS.length} scenarios, ${fixtures.size} recorded: ` +
    Object.entries(totals)
      .map(([s, n]) => `${s}=${n}`)
      .join(" "),
);
