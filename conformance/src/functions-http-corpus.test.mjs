import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const load = (path) =>
  JSON.parse(readFileSync(fileURLToPath(new URL(path, import.meta.url)), "utf8"));

test("FUNCTIONS-HTTP request corpus covers exactly the frozen behavioral cases", () => {
  const closure = load("../../spec/compatibility/closure/FUNCTIONS-HTTP.json");
  const corpus = load("../functions-http/corpus.json");
  const expected = closure.conditions
    .filter(
      ({ conditionId }) =>
        !conditionId.endsWith("/final-artifact-regression") &&
        !conditionId.endsWith("/closure-review"),
    )
    .flatMap(({ recipeIds, cases }) => cases.map((name) => `${recipeIds[0]}#${name}`));
  const actual = corpus.programs.flatMap(({ id, cases }) =>
    cases.map(({ id: name }) => `${id}#${name}`),
  );
  assert.equal(corpus.project, "fireemu-oracle-query");
  assert.equal(corpus.region, "us-central1");
  assert.deepEqual(corpus.functions, {
    http: "fireemuHttpProbe",
    callable: "fireemuCallableProbe",
  });
  assert.equal(corpus.programs.length, new Set(corpus.programs.map(({ id }) => id)).size);
  assert.equal(actual.length, 68);
  assert.deepEqual(actual.toSorted(), expected.toSorted());

  for (const program of corpus.programs) {
    for (const step of program.cases) {
      assert.ok(["http", "callable"].includes(step.target), `${program.id}#${step.id}`);
      assert.ok(["GET", "POST", "HEAD", "OPTIONS"].includes(step.request.method));
      assert.match(step.request.path, /^\/(?!\/)[^:]*$/);
      assert.ok(!JSON.stringify(step.request.body ?? "").includes("https://"));
      assert.ok(
        !step.request.headers.origin || step.request.headers.origin === "https://example.com",
      );
      assert.ok(JSON.stringify(step.request.body ?? "").length <= 4096);
      assert.ok(
        ["complete", "first-chunk-then-abort"].includes(step.capture),
        `${program.id}#${step.id}`,
      );
    }
  }
});
