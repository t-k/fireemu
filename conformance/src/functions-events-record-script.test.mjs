import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  ALLOWED_HOSTS,
  CONTROL_BUCKET,
  DECLARED_COLLECTIONS,
  DECLARED_TOPICS,
  NEGATIVE_WINDOW_SECONDS,
  PRIMARY_BUCKET,
  PROJECT,
  SCENARIO_ORDER,
  SCENARIO_EVENTS,
  buildPass,
  passSummary,
} from "./functions-events/record/script.mjs";

const read = (path) => JSON.parse(readFileSync(new URL(path, import.meta.url), "utf8"));
const corpus = read("../functions-events/corpus.json");
const programs = read("../functions-events/programs.json");

const sequence = () => {
  let n = 0;
  return (role) => `e${String(++n).padStart(4, "0")}${role}`;
};
const pass1 = () => buildPass({ pass: 1, newId: sequence() });

test("the pass runs every frozen scenario of the corpus exactly once", () => {
  assert.deepEqual([...SCENARIO_ORDER].sort(), corpus.scenarios.map(({ id }) => id).sort());
  assert.equal(new Set(SCENARIO_ORDER).size, SCENARIO_ORDER.length);
  assert.deepEqual(
    pass1().steps.map((step) => step.scenarioId),
    SCENARIO_ORDER,
  );
});

test("the handlers each scenario delivers to or must stay silent for follow programs.json", () => {
  for (const program of programs.programs) {
    for (const handler of Object.values(program.handlerExports)) {
      for (const scenarioId of program.scenarioIds) {
        const entry = SCENARIO_EVENTS[scenarioId];
        assert.ok(entry, scenarioId);
        const known = [...entry.delivers, ...entry.silent];
        assert.ok(known.includes(handler), `${scenarioId} does not say whether ${handler} gets an event`);
      }
    }
  }
});

test("a pass sends only declared requests to declared hosts, projects and resources", () => {
  const { steps } = pass1();
  for (const request of steps.flatMap((step) => step.requests)) {
    const url = new URL(request.url);
    assert.ok(ALLOWED_HOSTS.includes(url.hostname), `${request.id}: host ${url.hostname}`);
    assert.ok(["GET", "POST", "PUT", "PATCH", "DELETE"].includes(request.method), request.id);
    assert.ok(["oauth", "idtoken", "apikey"].includes(request.auth), request.id);
    assert.equal(typeof request.mutation, "boolean", request.id);
    assert.ok(Array.isArray(request.expect) && request.expect.length > 0, request.id);
    const projects = [...request.url.matchAll(/projects\/([^/?:]+)/g)].map((m) => m[1]);
    assert.ok(projects.every((p) => p === PROJECT || p === "_"), `${request.id}: ${projects}`);
    const collections = [...request.url.matchAll(/documents\/([a-z_]+)/g)].map((m) => m[1]);
    assert.ok(collections.every((c) => DECLARED_COLLECTIONS.includes(c)), `${request.id}: ${collections}`);
    const buckets = [...request.url.matchAll(/\/b\/([^/?]+)/g)].map((m) => decodeURIComponent(m[1]));
    assert.ok(buckets.every((b) => [PRIMARY_BUCKET, CONTROL_BUCKET].includes(b)), `${request.id}: ${buckets}`);
    const topics = [...request.url.matchAll(/topics\/([a-z0-9-]+)/g)].map((m) => m[1]);
    assert.ok(topics.every((t) => DECLARED_TOPICS.includes(t)), `${request.id}: ${topics}`);
    if (request.mutation) assert.ok(request.method !== "GET", request.id);
  }
});

test("request ids are unique inside a pass and no resource name repeats across the two passes", () => {
  const ids = sequence();
  const first = buildPass({ pass: 1, newId: ids });
  const second = buildPass({ pass: 2, newId: ids });
  for (const pass of [first, second]) {
    const requestIds = pass.steps.flatMap((step) => step.requests.map(({ id }) => id));
    assert.equal(new Set(requestIds).size, requestIds.length);
  }
  const keys = [...first.steps, ...second.steps]
    .map((step) => step.matchKey?.value)
    .filter((value) => value && !value.includes("${"));
  assert.equal(new Set(keys).size, keys.length, "a matchKey was reused");
});

test("every negative observation has a delivering scenario before it and after it, a full window apart", () => {
  const { steps } = pass1();
  steps.forEach((step, index) => {
    const entry = SCENARIO_EVENTS[step.scenarioId];
    for (const handler of entry.silent) {
      const before = steps.slice(0, index).some((s) => SCENARIO_EVENTS[s.scenarioId].delivers.includes(handler));
      const after = steps.slice(index + 1).some((s) => SCENARIO_EVENTS[s.scenarioId].delivers.includes(handler));
      assert.ok(before, `${step.scenarioId}: no positive control for ${handler} before it`);
      assert.ok(after, `${step.scenarioId}: no positive control for ${handler} after it`);
    }
    if (entry.silent.length > 0) {
      assert.ok(step.settleSeconds >= NEGATIVE_WINDOW_SECONDS, `${step.scenarioId}: window`);
    }
  });
});

test("the pass sizes match the design (writes and all requests per pass)", () => {
  const summary = passSummary(pass1());
  assert.deepEqual(summary.perFamily.mutations, { firestore: 21, storage: 22, auth: 12, pubsub: 3 });
  assert.equal(summary.mutations, 58);
  assert.equal(summary.requests, 101);
  assert.ok(summary.minutes >= 25 && summary.minutes <= 40, `pass takes ${summary.minutes} minutes`);
});

test("a step names where its matchKey comes from and what the subject request returned", () => {
  for (const step of pass1().steps) {
    assert.ok(step.matchKey?.kind, step.scenarioId);
    assert.ok(["typed-success", "typed-refusal", "typed-absent"].includes(step.expectedSourceResult), step.scenarioId);
    assert.ok(step.subject.length > 0 && step.subject.every((id) => step.requests.some((r) => r.id === id)), step.scenarioId);
  }
});
