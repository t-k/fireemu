export const EXTERNAL_ORACLE_OWNERSHIP = "external-oracle";

export function fixtureOwnershipFailures(fixtures, scenarios) {
  const scenarioIds = new Set(scenarios.map((scenario) => scenario.id));
  const failures = [];

  for (const [id, fixture] of fixtures) {
    const ownership = fixture.ownership ?? "local-corpus";
    if (ownership === EXTERNAL_ORACLE_OWNERSHIP) continue;
    if (ownership !== "local-corpus") {
      failures.push(`${id}: unsupported fixture ownership ${ownership}`);
      continue;
    }
    if (!scenarioIds.has(id)) {
      failures.push(`${id}: a fixture exists but the corpus no longer declares the scenario`);
    }
  }

  return failures;
}
