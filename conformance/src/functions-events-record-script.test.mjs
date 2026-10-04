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
  pubsubPublication,
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
  assert.deepEqual(SCENARIO_ORDER.toSorted(), corpus.scenarios.map(({ id }) => id).toSorted());
  assert.equal(new Set(SCENARIO_ORDER).size, SCENARIO_ORDER.length);
  assert.deepEqual(
    pass1()
      .steps.filter((step) => step.role === "subject")
      .map((step) => step.scenarioId),
    SCENARIO_ORDER,
  );
  const controls = pass1().steps.filter((step) => step.role !== "subject");
  assert.deepEqual(
    controls.map((step) => [step.scenarioId, step.role]),
    [
      ["storage-delete", "positive-control-after"],
      ["auth-delete", "positive-control-after"],
    ],
  );
});

test("the handlers each scenario delivers to or must stay silent for follow programs.json", () => {
  for (const program of programs.programs) {
    for (const handler of Object.values(program.handlerExports)) {
      for (const scenarioId of program.scenarioIds) {
        const entry = SCENARIO_EVENTS[scenarioId];
        assert.ok(entry, scenarioId);
        const known = [...entry.delivers, ...entry.silent];
        assert.ok(
          known.includes(handler),
          `${scenarioId} does not say whether ${handler} gets an event`,
        );
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
    assert.ok(
      projects.every((p) => p === PROJECT || p === "_"),
      `${request.id}: ${projects}`,
    );
    const collections = [...request.url.matchAll(/documents\/([a-z_]+)/g)].map((m) => m[1]);
    assert.ok(
      collections.every((c) => DECLARED_COLLECTIONS.includes(c)),
      `${request.id}: ${collections}`,
    );
    const buckets = [...request.url.matchAll(/\/b\/([^/?]+)/g)].map((m) =>
      decodeURIComponent(m[1]),
    );
    assert.ok(
      buckets.every((b) => [PRIMARY_BUCKET, CONTROL_BUCKET].includes(b)),
      `${request.id}: ${buckets}`,
    );
    const topics = [...request.url.matchAll(/topics\/([a-z0-9-]+)/g)].map((m) => m[1]);
    assert.ok(
      topics.every((t) => DECLARED_TOPICS.includes(t)),
      `${request.id}: ${topics}`,
    );
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
      const before = steps
        .slice(0, index)
        .some((s) => SCENARIO_EVENTS[s.scenarioId].delivers.includes(handler));
      const after = steps
        .slice(index + 1)
        .some((s) => SCENARIO_EVENTS[s.scenarioId].delivers.includes(handler));
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
  assert.deepEqual(summary.perFamily.mutations, {
    firestore: 21,
    storage: 26,
    auth: 14,
    pubsub: 3,
  });
  assert.equal(summary.mutations, 64);
  assert.equal(summary.requests, 111);
  assert.ok(
    summary.minutes >= 25 && summary.minutes <= 42,
    `pass takes ${summary.minutes} minutes`,
  );
});

test("a step names where its matchKey comes from and what the subject request returned", () => {
  for (const step of pass1().steps) {
    assert.ok(step.matchKey?.kind, step.scenarioId);
    assert.ok(
      ["typed-success", "typed-refusal", "typed-absent"].includes(step.expectedSourceResult),
      step.scenarioId,
    );
    assert.ok(
      step.subject.length > 0 && step.subject.every((id) => step.requests.some((r) => r.id === id)),
      step.scenarioId,
    );
  }
});

test("a Pub/Sub publication is the message id as data and as the probe attribute, on the scenario's topic, with the ordering key only for ordering", () => {
  assert.deepEqual(pubsubPublication("pubsub-publish", "eabc"), {
    topic: "fe-events-primary",
    text: "eabc",
    attributes: { probe: "eabc" },
    extra: {},
  });
  assert.deepEqual(pubsubPublication("pubsub-other-topic", "eabc"), {
    topic: "fe-events-control",
    text: "eabc",
    attributes: { probe: "eabc" },
    extra: {},
  });
  assert.deepEqual(pubsubPublication("pubsub-ordering", "eabc"), {
    topic: "fe-events-primary",
    text: "eabc",
    attributes: { probe: "eabc" },
    extra: { orderingKey: "fe-events-order" },
  });
  assert.throws(() => pubsubPublication("fs-create", "eabc"), /not a Pub\/Sub scenario/);
  // the pass publishes exactly this
  const steps = pass1().steps.filter((step) => step.scenarioId.startsWith("pubsub-"));
  for (const step of steps) {
    const publication = pubsubPublication(step.scenarioId, step.matchKey.probe);
    const request = step.requests.find((r) => r.role === "subject");
    assert.ok(request.url.includes(`/topics/${publication.topic}:publish`));
    assert.deepEqual(request.body, {
      messages: [
        {
          data: Buffer.from(publication.text).toString("base64"),
          attributes: publication.attributes,
          ...publication.extra,
        },
      ],
    });
  }
});

test("storage-failed-upload seeds an object, then writes it with a non-matching ifGenerationMatch that production refuses with 412", () => {
  const step = pass1().steps.find((s) => s.scenarioId === "storage-failed-upload");
  const roles = step.requests.map((r) => r.role);
  assert.deepEqual(roles, ["setup", "subject", "readback", "readback", "cleanup"]);
  const [seed, subject, get, versions, cleanup] = step.requests;
  assert.ok(seed.url.includes("ifGenerationMatch=0"));
  assert.equal(seed.method, "POST");
  assert.ok(subject.url.includes("ifGenerationMatch=1"), subject.url);
  assert.ok(!subject.url.includes("ifGenerationMatch=0"));
  assert.deepEqual(subject.expect, [412]);
  assert.equal(subject.headers, undefined);
  assert.equal(subject.mutation, true);
  assert.notEqual(subject.body, seed.body, "the refused write has its own body");
  assert.equal(get.method, "GET");
  assert.deepEqual(get.expect, [200]);
  assert.ok(versions.url.includes("versions=true"));
  assert.equal(cleanup.method, "DELETE");
  assert.deepEqual(step.subject, [subject.id]);
  assert.equal(
    step.seedWaitSeconds > 0,
    true,
    "the seed finalize is drained before the refused write",
  );
  assert.equal(step.matchKey.kind, "storage");
  assert.equal(step.expectedSourceResult, "typed-refusal");
  assert.equal(step.settleSeconds, NEGATIVE_WINDOW_SECONDS);
  // one object, one name for all five requests
  const names = step.requests.map((r) =>
    decodeURIComponent(r.url.match(/(?:name=|\/o\/|prefix=)([^&?]+)/)[1]),
  );
  assert.equal(new Set(names).size, 1);
});
