import { existsSync } from "node:fs";
import { join } from "node:path";

import { CONFORMANCE_DIR } from "./config.mjs";

export const EXTERNAL_ORACLE_OWNERSHIP = "external-oracle";

/**
 * Datasets under `fixtures/` that a lane records and compares with its own tool: their fixtures have
 * their own schema and are not scenarios of the executable corpus. Each entry names the directory and
 * the comparer (a path below `conformance/`) that owns it. The list is explicit on purpose: a directory
 * that is not on it is checked against the corpus as before, and an entry whose comparer is missing
 * fails the gate, so a dataset cannot stay here after its tool is gone.
 */
export const OWN_COMPARER_DATASETS = Object.freeze([
  Object.freeze({
    directory: "storage-object-production",
    comparer: "src/storage-object-compare/run.mjs",
  }),
]);

const comparerExists = (path) => existsSync(join(CONFORMANCE_DIR, path));

export function fixtureOwnershipFailures(
  fixtures,
  scenarios,
  { datasets = OWN_COMPARER_DATASETS, exists = comparerExists } = {},
) {
  const scenarioIds = new Set(scenarios.map((scenario) => scenario.id));
  const failures = [];

  for (const { directory, comparer } of datasets) {
    if (!exists(comparer)) {
      failures.push(
        `${directory}: its comparer ${comparer} does not exist, so nothing owns these fixtures`,
      );
    }
  }
  const ownedByAComparer = (id) => datasets.some(({ directory }) => id.startsWith(`${directory}/`));

  for (const [id, fixture] of fixtures) {
    const ownership = fixture.ownership ?? "local-corpus";
    if (ownership === EXTERNAL_ORACLE_OWNERSHIP) continue;
    if (ownership !== "local-corpus") {
      failures.push(`${id}: unsupported fixture ownership ${ownership}`);
      continue;
    }
    if (ownedByAComparer(id)) continue;
    if (!scenarioIds.has(id)) {
      failures.push(`${id}: a fixture exists but the corpus no longer declares the scenario`);
    }
  }

  return failures;
}
