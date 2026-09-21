// Reuse the actual prior pilot and its explicitly derived, test-only fixtures.
// This adapter never creates a production or runtime observation.
import { readFile } from "node:fs/promises";
import { CASE } from "../../production-diff/registry.mjs";
import {
  compareRecords,
  selectProduction,
  resultEnvelope,
  sha256,
} from "../../production-diff/core.mjs";
import { comparatorModuleSource, importText } from "../../production-diff/legacy.mjs";
import { matrixFixture, programFixture } from "../../production-diff/test/fixtures.mjs";

export async function fixtureSubject() {
  const text = await readFile(
    new URL("../../production-diff/test/legacy-comparator.excerpt.txt", import.meta.url),
    "utf8",
  );
  const source = comparatorModuleSource(text);
  if (sha256(source) !== CASE.comparatorSliceSha256)
    throw new Error("fixture-comparator-pin-mismatch");
  const { compareProductionToFireemu: comparator } = await importText(source);
  const entry = CASE,
    program = programFixture(),
    production = selectProduction(matrixFixture(), entry);
  return {
    entry,
    program,
    production,
    compare: (actual, inputProgram) =>
      compareRecords({ entry, program: inputProgram, production, actual, comparator }),
    envelope: (comparison, execution) =>
      resultEnvelope({ entry, comparison, execution, provenance: { testOnly: true } }),
    identity: {
      kind: "derived-test-fixture",
      comparatorSliceSha256: sha256(source),
      observedSourceReference: CASE.observedSource,
      completeRepositoryValidation: false,
    },
    comparator,
  };
}
