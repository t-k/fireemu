import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { relative } from "node:path";
import { promisify } from "node:util";

import { REPO_ROOT } from "../config.mjs";
import { compareProductionToFireemu } from "./run.mjs";

/** Compare only recipes known to be identical to the saved production recording. */
export function checkHistoricalProduction({ saved, live, definitions, excludedKeys = [] }) {
  const excluded = new Set(excludedKeys);
  const savedKeys = new Set(
    saved.programs.flatMap((program) =>
      Object.keys(program.steps).map((step) => `${program.id}#${step}`),
    ),
  );
  const currentKeys = new Set(
    definitions.flatMap((program) => program.steps.map((step) => `${program.id}#${step.id}`)),
  );
  const comparableKeys = [...currentKeys].filter((key) => !excluded.has(key));
  if (
    comparableKeys.some((key) => !savedKeys.has(key)) ||
    [...savedKeys].some((key) => !excluded.has(key) && !currentKeys.has(key))
  ) {
    throw new Error(
      "historical production recipe identity changed; update the reviewed exclusions",
    );
  }

  const filtered = definitions
    .map((program) => ({
      ...program,
      steps: program.steps.filter((step) => !excluded.has(`${program.id}#${step.id}`)),
    }))
    .filter((program) => program.steps.length > 0);
  const baseline = Object.fromEntries(
    saved.programs.map((program) => [
      program.id,
      {
        steps: Object.fromEntries(
          Object.entries(program.steps).map(([id, row]) => [id, row.fireemu]),
        ),
      },
    ]),
  );
  const historical = compareProductionToFireemu({
    production: saved,
    fireemu: baseline,
    programDefinitions: filtered,
  }).rows;
  const current = compareProductionToFireemu({
    production: saved,
    fireemu: live,
    programDefinitions: filtered,
  }).rows;
  const keys = filtered.flatMap((program) =>
    program.steps.map((step) => `${program.id}#${step.id}`),
  );
  const baselineMismatches = keys.filter((_, index) => historical[index].comparison === "mismatch");
  const baselineIndeterminate = new Set(
    keys.filter((_, index) => historical[index].comparison === "indeterminate"),
  );
  const currentMismatches = keys.filter((_, index) => current[index].comparison === "mismatch");
  const indeterminate = keys.filter((_, index) => current[index].comparison === "indeterminate");
  const baselineSet = new Set(baselineMismatches);
  return {
    comparable: keys.length,
    baselineMismatches,
    currentMismatches,
    newMismatches: currentMismatches.filter((key) => !baselineSet.has(key)),
    indeterminate,
    newIndeterminate: indeterminate.filter((key) => !baselineIndeterminate.has(key)),
  };
}

/**
 * The identity of the fireemu artifact the historical check ran, from its SHA-256 before and
 * after the run. An artifact that changed while the check ran is refused, as the FS-DATA-WRITE
 * local check refuses one.
 */
export function historicalArtifactIdentity({ root = REPO_ROOT, binary, before, after, version }) {
  for (const digest of [before, after]) {
    if (!/^[0-9a-f]{64}$/.test(digest)) throw new Error("artifact digest must be a SHA-256");
  }
  if (before !== after) throw new Error("fireemu changed during the historical check");
  return {
    path: relative(root, binary),
    sha256Before: before,
    sha256After: after,
    version: version.trim(),
  };
}

/** The SHA-256 and `--version` of a fireemu artifact, taken before and after the check runs. */
export async function measureArtifact(binary) {
  const sha256 = createHash("sha256")
    .update(await readFile(binary))
    .digest("hex");
  const { stdout } = await promisify(execFile)(binary, ["--version"]);
  return { sha256, version: stdout };
}
