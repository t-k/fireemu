import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { validatePrograms } from "./functions-events/programs.mjs";

const readJson = (url) => JSON.parse(readFileSync(fileURLToPath(new URL(url, import.meta.url))));
const closure = readJson("../../spec/compatibility/closure/FUNCTIONS-EVENTS.json");
const corpus = readJson("../functions-events/corpus.json");
const manifest = readJson("../functions-events/programs.json");
const clone = () => structuredClone(manifest);

test("every frozen behavioral recipe has exactly one program and all 109 aspects", () => {
  const result = validatePrograms(manifest, corpus, closure);
  assert.equal(result.programs.length, 20);
  assert.equal(result.aspectCount, 109);
  assert.deepEqual(
    new Set(result.programs.flatMap((program) => program.caseIds)),
    new Set(corpus.cases.map((row) => row.id)),
  );
});

test("the closure-only recipe has no executable program", () => {
  const closureOnly = closure.conditions.filter(({ recipeIds }) =>
    recipeIds.includes("functions-events/"),
  );
  assert.deepEqual(
    closureOnly.map(({ conditionId }) => conditionId),
    ["FUNCTIONS-EVENTS/final-artifact-regression", "FUNCTIONS-EVENTS/closure-review"],
  );
  assert.equal(manifest.programs.some(({ recipeId }) => recipeId === "functions-events/"), false);
  const broken = clone();
  broken.programs[0].recipeId = "functions-events/";
  assert.throws(() => validatePrograms(broken, corpus, closure));
});

test("missing, duplicate, and reassigned aspects fail closed", () => {
  for (const mutate of [
    (value) => value.programs.pop(),
    (value) => value.programs.push(structuredClone(value.programs[0])),
    (value) => value.programs[0].caseIds.pop(),
    (value) => value.programs[0].caseIds.push(value.programs[1].caseIds[0]),
    (value) => value.programs[0].scenarioIds.pop(),
    (value) => value.programs[0].generations.pop(),
  ]) {
    const broken = clone();
    mutate(broken);
    assert.throws(() => validatePrograms(broken, corpus, closure));
  }
});

test("Auth v2, malformed handler bindings, and budget drift fail closed", () => {
  for (const mutate of [
    (value) => value.programs.find(({ recipeId }) => recipeId === "functions-events/auth/create").generations.push(2),
    (value) => delete value.programs[0].handlerExports.v1,
    (value) => value.programs[0].handlerExports.v2 = "unknownHandler",
    (value) => value.programs[0].productionRequestBudgetDraft.deploy = -1,
    (value) => value.productionRequestBudgetDraft.total++,
    (value) => value.budgetStatus = "SEND_READY",
    (value) => value.sendAuthorized = true,
  ]) {
    const broken = clone();
    mutate(broken);
    assert.throws(() => validatePrograms(broken, corpus, closure));
  }
});
