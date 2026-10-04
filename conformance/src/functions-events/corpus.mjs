import assert from "node:assert/strict";

const requiredNegativeEvidence = [
  "source-result",
  "source-readback",
  "baseline-cursor",
  "run-resource-correlation",
  "positive-control-before",
  "positive-control-after",
  "window-complete",
  "no-capture-loss",
];
const resources = new Set([
  "collection-primary",
  "collection-control",
  "bucket-primary",
  "bucket-control",
  "auth-project",
  "topic-primary",
  "topic-control",
]);
const credentials = new Set(["admin", "anonymous-client", "signed-in-client"]);
const sources = new Set(["firestore", "storage", "auth", "pubsub"]);
const identifier = (value) => typeof value === "string" && /^[a-z][a-z0-9-]*$/.test(value);
const stringList = (value) =>
  Array.isArray(value) &&
  value.length > 0 &&
  value.every(identifier) &&
  new Set(value).size === value.length;

/** Validate preparation data only; this does not validate observations or grant send permission. */
export function validateCorpus(value, closure) {
  assert.equal(closure.parent, "FUNCTIONS-EVENTS");
  assert.equal(closure.inventoryStatus, "FROZEN");
  assert.equal(value.schemaVersion, 1);
  assert.equal(value.parent, closure.parent);
  assert.equal(value.status, "LOCAL_DRAFT");
  assert.equal(value.transport, "none");
  assert.equal(value.productionEvidence, null);
  assert.equal(value.sendAuthorized, false);
  assert.equal(value.requestBudget, null);
  assert.ok(stringList(value.notPrepared));
  assert.ok(value.notPrepared.includes("production-recording-1"));
  assert.ok(value.notPrepared.includes("production-recording-2"));
  assert.ok(value.notPrepared.includes("independent-closure-review"));
  assert.ok(Array.isArray(value.scenarios) && value.scenarios.length <= 64);
  const scenarios = new Map();
  for (const scenario of value.scenarios) {
    assert.ok(identifier(scenario.id) && !scenarios.has(scenario.id), "unique scenario ID");
    assert.ok(sources.has(scenario.source));
    assert.ok(scenario.mutation.startsWith(`${scenario.source}.`));
    assert.ok(resources.has(scenario.resource));
    assert.ok(credentials.has(scenario.credential));
    assert.ok(["typed-success", "typed-refusal"].includes(scenario.sourceResult));
    assert.ok(stringList(scenario.readback));
    assert.ok(stringList(scenario.preconditions));
    assert.ok(scenario.preconditions.includes("owned-resource-binding"));
    assert.ok(scenario.preconditions.includes("handler-readiness-readback"));
    assert.ok(stringList(scenario.cleanup), "cleanup obligations required");
    if (scenario.message) {
      assert.ok(Number.isInteger(scenario.message.maximumBytes));
      assert.ok(scenario.message.maximumBytes > 0 && scenario.message.maximumBytes <= 1024);
      assert.ok(
        Buffer.byteLength(JSON.stringify(scenario.message)) <= scenario.message.maximumBytes,
      );
    }
    scenarios.set(scenario.id, scenario);
  }
  const expected = new Map(
    closure.conditions
      .filter((c) => c.generations)
      .flatMap((c) =>
        c.cases.flatMap((name) =>
          c.generations.map((generation) => [
            `${c.conditionId}#${name}#v${generation}`,
            { condition: c, name, generation },
          ]),
        ),
      ),
  );
  assert.ok(Array.isArray(value.cases));
  assert.equal(value.cases.length, expected.size, "complete frozen coverage required");
  const seen = new Set();
  for (const row of value.cases) {
    assert.ok(expected.has(row.id) && !seen.has(row.id), "unknown or duplicate case");
    seen.add(row.id);
    const { condition, name, generation } = expected.get(row.id);
    assert.equal(row.conditionId, condition.conditionId);
    assert.equal(row.case, name);
    assert.equal(row.observation, name);
    assert.equal(row.generation, generation);
    assert.ok(condition.recipeIds.includes(row.recipeId));
    const scenario = scenarios.get(row.scenario);
    assert.ok(scenario, "known source scenario required");
    assert.equal(row.source, scenario.source);
    assert.ok(identifier(row.handlerEvent));
    assert.ok(resources.has(row.handlerResource));
    assert.ok(
      ["none-in-window", "at-least-one", "failed-then-succeeded-same-event"].includes(row.delivery),
    );
    assert.ok(
      Number.isInteger(row.window.maximumSeconds) &&
        row.window.maximumSeconds > 0 &&
        row.window.maximumSeconds <= 600,
    );
    assert.equal(row.window.provesPermanentAbsence, false);
    assert.ok(stringList(row.evidenceRequired));
    for (const required of [
      "source-result",
      "source-readback",
      "baseline-cursor",
      "run-resource-correlation",
      "no-capture-loss",
    ]) {
      assert.ok(row.evidenceRequired.includes(required), required);
    }
    if (row.delivery === "none-in-window") {
      assert.deepEqual(row.evidenceRequired, requiredNegativeEvidence);
      assert.equal(row.window.timeoutMeans, "bounded-observation-only");
      const control = scenarios.get(row.positiveControlScenario);
      assert.ok(control && control.id !== scenario.id, "separate positive control required");
      assert.equal(control.source, row.source);
      assert.equal(control.resource, row.handlerResource);
      assert.equal(control.sourceResult, "typed-success");
      assert.equal(row.positiveControlGeneration, row.generation);
      assert.ok(
        value.cases.some(
          (positive) =>
            positive.scenario === control.id &&
            positive.delivery === "at-least-one" &&
            positive.source === row.source &&
            positive.generation === row.generation &&
            positive.handlerEvent === row.handlerEvent &&
            positive.handlerResource === row.handlerResource,
        ),
        "positive control must cover the same handler event",
      );
    } else {
      assert.equal(row.window.timeoutMeans, "incomplete");
      for (const required of ["raw-handler-event", "raw-event-identity", "raw-event-time"]) {
        assert.ok(row.evidenceRequired.includes(required), required);
      }
    }
    if (condition.conditionId.endsWith("/delivery-retry-identity")) {
      assert.equal(row.delivery, "failed-then-succeeded-same-event");
      assert.equal(row.source, "firestore");
      assert.equal(row.generation, 2);
      assert.deepEqual(row.retry, {
        stableIdentity: true,
        exactAttempts: null,
        exactDelay: null,
        independentEventOrder: null,
      });
      assert.ok(row.evidenceRequired.includes("same-event-failed-and-succeeded"));
    } else {
      assert.equal(row.retry, undefined);
    }
  }
  return value;
}
