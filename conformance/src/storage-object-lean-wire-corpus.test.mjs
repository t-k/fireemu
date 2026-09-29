// Every request the two corpora declare, built the way the sender builds it, goes through the lean
// wire to the right real origin with no refusal. A route table that refuses the corpus's own
// requests would stop a production recording at the first one, and one that is too loose would
// send a request the corpus never declared, so the table is held to exactly this set.

import assert from "node:assert/strict";
import test from "node:test";
import { buildAuthCorpus } from "./storage-object/auth-corpus.mjs";
import { buildCorpus } from "./storage-object/corpus.mjs";
import {
  createLeanWire,
  LEAN_PLACEHOLDER_ADMIN,
  LEAN_PLACEHOLDER_API_KEY,
} from "./storage-object/lean-wire.mjs";
import { buildStage3DraftPlan } from "./storage-object/stage3-plan.mjs";

const BUCKET = "fireemu-oracle-query.firebasestorage.app";
const PROJECT = "fireemu-oracle-query";
const STORAGE = "http://127.0.0.1:19199";
const AUTH = "http://127.0.0.1:19099";
const CONTROL = "http://127.0.0.1:19198";
const REAL_HOSTS = new Set([
  "https://firebasestorage.googleapis.com",
  "https://storage.googleapis.com",
  "https://identitytoolkit.googleapis.com",
  "https://securetoken.googleapis.com",
]);

const plan = buildStage3DraftPlan({
  projectId: PROJECT,
  bucket: BUCKET,
  runIds: ["a".repeat(20), "b".repeat(20)],
});

function requestsOf(recording) {
  const { prefix, runId } = plan.recordings[recording];
  const recipes = [
    ...buildCorpus({ bucket: BUCKET, prefix }).recipes,
    ...buildAuthCorpus({ projectId: PROJECT, bucket: BUCKET, runId }).recipes,
  ];
  const out = [];
  const walk = (node, recipe) => {
    if (Array.isArray(node)) return node.forEach((item) => walk(item, recipe));
    if (!node || typeof node !== "object") return;
    if (typeof node.method === "string" && typeof node.path === "string")
      out.push({ step: node, recipe });
    for (const value of Object.values(node)) walk(value, recipe);
  };
  for (const recipe of recipes) walk(recipe, recipe.id);
  return out.map(({ step, recipe }) => {
    // The sender builds a URL from the step's path and sets each query value as a string; a value
    // it resolves at run time (a generation read from a response) is stood in for by a number.
    const query = Object.fromEntries(
      Object.entries(step.query ?? {}).map(([key, value]) => [
        key,
        typeof value === "string" ? value : "1",
      ]),
    );
    if (step.service === "identitytoolkit") {
      const owner = step.credential === "owner";
      const deletion = step.id.endsWith("-delete");
      // As local-auth-state.mjs builds the path.
      const path = owner
        ? `/identitytoolkit.googleapis.com/v1/projects/${PROJECT}/accounts:${deletion ? "delete" : "lookup"}`
        : `/identitytoolkit.googleapis.com${step.path}`;
      const url = new URL(path, AUTH);
      if (!owner) url.searchParams.set("key", LEAN_PLACEHOLDER_API_KEY);
      return { recipe, id: step.id, method: step.method, href: url.href, owner };
    }
    const url = new URL(step.path, STORAGE);
    for (const [key, value] of Object.entries(query)) url.searchParams.set(key, value);
    return {
      recipe,
      id: step.id,
      method: step.method,
      href: url.href,
      owner: step.credential === "admin",
    };
  });
}

function wireFor(recording) {
  const { prefix } = plan.recordings[recording];
  const calls = [];
  const wire = createLeanWire({
    bucket: BUCKET,
    projectId: PROJECT,
    prefix,
    origins: { storage: STORAGE, auth: AUTH, control: CONTROL },
    adminToken: async () => "ya29.synthetic-owner-access-token-value",
    authApiKey: "AIzaSyD-synthetic-web-api-key-value-000000",
    readRules: async () => ({ source: "x", requests: 0 }),
    fetchImpl: async (url) => {
      calls.push(String(url));
      return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
    },
    capture: async () => {},
    pacer: { dispatch: (_name, attempt) => attempt() },
  });
  return { wire, calls };
}

for (const recording of [0, 1]) {
  test(`every declared request of recording ${recording + 1} is sent to a real origin, none refused`, async () => {
    const requests = requestsOf(recording);
    assert.ok(requests.length > 2000, `the walk found ${requests.length} requests`);
    const { wire, calls } = wireFor(recording);
    const refused = [];
    for (const request of requests) {
      const before = calls.length;
      try {
        await wire.fetch(request.href, {
          method: request.method,
          headers: request.owner ? { authorization: LEAN_PLACEHOLDER_ADMIN } : {},
          body: request.method === "GET" || request.method === "DELETE" ? undefined : "x",
        });
      } catch (error) {
        refused.push(`${request.recipe} ${request.id}: ${error.message}`);
        continue;
      }
      assert.equal(calls.length, before + 1);
      assert.ok(REAL_HOSTS.has(new URL(calls.at(-1)).origin), calls.at(-1));
    }
    assert.deepEqual(refused, []);
  });
}

test("the declared requests are exactly what the table lets through, the first one refused is not", async () => {
  // A request no corpus declares stays refused: the table is not widened to fit the corpus.
  const { wire } = wireFor(0);
  const prefix = plan.recordings[0].prefix;
  for (const href of [
    `${STORAGE}/storage/v1/b/${BUCKET}/o/${encodeURIComponent(`${prefix}x`)}/compose`,
    `${STORAGE}/storage/v1/b/${BUCKET}/iam`,
    `${AUTH}/identitytoolkit.googleapis.com/v1/accounts:update`,
    `${AUTH}/identitytoolkit.googleapis.com/v1/accounts:sendOobCode`,
  ]) {
    await assert.rejects(wire.fetch(href, { method: "POST", headers: {}, body: "{}" }), href);
  }
});
