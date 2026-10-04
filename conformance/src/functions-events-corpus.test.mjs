import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { validateCorpus } from "./functions-events/corpus.mjs";

const read = (path) => JSON.parse(readFileSync(new URL(path, import.meta.url), "utf8"));
const closure = read("../../spec/compatibility/closure/FUNCTIONS-EVENTS.json");
const corpus = () => read("../functions-events/corpus.json");
const find = (value, condition, name, generation = 1) =>
  value.cases.find(
    (row) =>
      row.conditionId === `FUNCTIONS-EVENTS/${condition}` &&
      row.case === name &&
      row.generation === generation,
  );
const scenario = (value, row) => value.scenarios.find(({ id }) => id === row.scenario);

test("draft covers all 109 frozen case-generation obligations without claiming observations", () => {
  const value = corpus();
  validateCorpus(value, closure);
  assert.equal(value.status, "LOCAL_DRAFT");
  assert.equal(value.cases.length, 109);
  assert.equal(value.transport, "none");
  assert.equal(value.productionEvidence, null);
  assert.equal(value.sendAuthorized, false);
  assert.equal(value.requestBudget, null);
  const expected = closure.conditions
    .filter((c) => c.generations)
    .flatMap((c) =>
      c.cases.flatMap((name) =>
        c.generations.map((generation) => `${c.conditionId}#${name}#v${generation}`),
      ),
    );
  assert.deepEqual(new Set(value.cases.map((c) => c.id)), new Set(expected));
  assert.equal(value.cases.length, new Set(value.cases.map((c) => c.id)).size);
});

test("cases select distinct source operations and preserve generation scope", () => {
  const value = corpus();
  for (const operation of ["create", "update", "delete"]) {
    const row = find(value, "firestore-written", operation);
    assert.equal(scenario(value, row).mutation, `firestore.${operation}`);
  }
  assert.equal(scenario(value, find(value, "auth-created", "admin-create")).credential, "admin");
  assert.equal(
    scenario(value, find(value, "auth-created", "email-password-create")).credential,
    "anonymous-client",
  );
  assert.equal(
    scenario(value, find(value, "firestore-auth-context", "authenticated-write", 2)).credential,
    "signed-in-client",
  );
  assert.equal(
    scenario(value, find(value, "firestore-auth-context", "admin-write", 2)).credential,
    "admin",
  );
  assert.ok(
    value.cases.filter((r) => r.conditionId.includes("/auth-")).every((r) => r.generation === 1),
  );
});

test("negative observations require source evidence, live controls and a complete bounded window", () => {
  const value = corpus();
  const negatives = value.cases.filter((r) => r.delivery === "none-in-window");
  assert.equal(negatives.length, 14);
  for (const row of negatives) {
    assert.deepEqual(row.evidenceRequired, [
      "source-result",
      "source-readback",
      "baseline-cursor",
      "run-resource-correlation",
      "positive-control-before",
      "positive-control-after",
      "window-complete",
      "no-capture-loss",
    ]);
    assert.ok(row.window.maximumSeconds > 0 && row.window.maximumSeconds <= 600);
    assert.equal(row.window.timeoutMeans, "bounded-observation-only");
    assert.equal(row.window.provesPermanentAbsence, false);
    assert.notEqual(row.positiveControlScenario, row.scenario);
    assert.equal(row.positiveControlGeneration, row.generation);
    assert.ok(scenario(value, { scenario: row.positiveControlScenario }));
  }
});

test("routing includes another bucket/topic and a same-bucket other-prefix positive", () => {
  const value = corpus();
  for (const [condition, negative, primary, other] of [
    ["storage-bucket-routing", "nonmatching-bucket", "bucket-primary", "bucket-control"],
    ["pubsub-topic-routing", "nonmatching-topic", "topic-primary", "topic-control"],
  ]) {
    const row = find(value, condition, negative);
    assert.equal(row.handlerResource, primary);
    assert.equal(scenario(value, row).resource, other);
    assert.equal(row.delivery, "none-in-window");
  }
  const sameBucket = find(value, "storage-bucket-routing", "same-bucket-other-prefix-delivered");
  assert.equal(sameBucket.delivery, "at-least-one");
  assert.equal(scenario(value, sameBucket).resource, "bucket-primary");
  assert.equal(scenario(value, sameBucket).objectRole, "other-prefix");
});

test("archive and retry retain configuration and identity obligations", () => {
  const value = corpus();
  for (const row of value.cases.filter((r) => r.conditionId.endsWith("/storage-archived"))) {
    const recipe = scenario(value, row);
    assert.ok(recipe.preconditions.includes("versioning-readback-enabled"));
    assert.ok(recipe.cleanup.includes("all-owned-object-generations"));
    assert.ok(recipe.cleanup.includes("versioning-restoration-readback"));
  }
  for (const row of value.cases.filter((r) => r.conditionId.endsWith("/delivery-retry-identity"))) {
    assert.equal(row.generation, 2);
    assert.equal(row.source, "firestore");
    assert.equal(row.delivery, "failed-then-succeeded-same-event");
    assert.deepEqual(row.retry, {
      stableIdentity: true,
      exactAttempts: null,
      exactDelay: null,
      independentEventOrder: null,
    });
    assert.ok(row.evidenceRequired.includes("same-event-failed-and-succeeded"));
  }
});

test("validator rejects coverage loss, false evidence and incomplete negative obligations", () => {
  const variants = [
    (v) => v.cases.pop(),
    (v) => v.cases.push(structuredClone(v.cases[0])),
    (v) => {
      v.cases[0].generation = 3;
    },
    (v) => {
      v.sendAuthorized = true;
    },
    (v) => {
      v.productionEvidence = { recorded: true };
    },
    (v) => {
      v.cases.find((r) => r.delivery === "none-in-window").evidenceRequired.pop();
    },
    (v) => {
      v.cases.find((r) => r.delivery === "none-in-window").positiveControlScenario = "missing";
    },
    (v) => {
      v.cases.find((r) => r.delivery === "none-in-window").positiveControlGeneration = 3;
    },
    (v) => {
      v.cases[0].window.maximumSeconds = Infinity;
    },
    (v) => {
      v.scenarios[0].cleanup = [];
    },
    (v) => {
      v.cases[0].scenario = "missing";
    },
  ];
  for (const mutate of variants) {
    const value = corpus();
    mutate(value);
    assert.throws(() => validateCorpus(value, closure));
  }
});

test("a positive control must exercise the same handler event", () => {
  const value = corpus();
  const deletion = find(value, "storage-deleted", "no-event-for-missing-object");
  deletion.positiveControlScenario = "storage-upload";
  assert.throws(() => validateCorpus(value, closure), /handler event/);
});

test("storage-failed-upload is a precondition failure on a seeded object, as the v6 recorder script sends it", () => {
  // v5's invalid-checksum upload was accepted by production (HTTP 200), so it could not be a refusal.
  const value = corpus();
  const failed = value.scenarios.find(({ id }) => id === "storage-failed-upload");
  assert.equal(failed.mutation, "storage.upload-precondition-failed");
  assert.equal(failed.sourceResult, "typed-refusal");
  assert.ok(failed.preconditions.includes("seeded-object-generation-readback"));
  assert.ok(failed.preconditions.includes("seed-event-drained"));
  assert.ok(!failed.preconditions.includes("object-absent"));
  assert.equal(JSON.stringify(value).includes("invalid-checksum"), false);
});
