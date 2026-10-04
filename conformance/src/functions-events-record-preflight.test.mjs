import assert from "node:assert/strict";
import test from "node:test";

import { destination } from "./functions-events/record/guard.mjs";
import { PREFLIGHT, REQUIRED_APIS, iamDiff, iamPairs, runPreflight } from "./functions-events/record/preflight.mjs";
import { PRIMARY_COLLECTION, PROJECT } from "./functions-events/record/script.mjs";

import { NUMBER, healthy } from "./functions-events-record-world.mjs";

const runWith = async (bodies) => {
  const seen = [];
  const result = await runPreflight(async (spec, vars) => {
    seen.push({ spec, vars: { ...vars } });
    const answer = bodies[spec.id];
    return { id: spec.id, status: answer.status, json: answer.json, kind: answer.status >= 500 ? "unknown" : answer.status < 300 ? "success" : "refusal" };
  });
  return { ...result, seen };
};

test("a prepared project passes and every preflight request is a read the guard allows", async () => {
  const { problems, projectNumber, seen } = await runWith(healthy());
  assert.deepEqual(problems, []);
  assert.equal(projectNumber, NUMBER);
  assert.equal(seen.length, PREFLIGHT.length);
  for (const { spec, vars } of seen) {
    assert.equal(spec.mutation, false, spec.id);
    const url = spec.url.replace("${rulesetId}", vars.rulesetId ?? "x");
    assert.equal(destination({ method: spec.method, url, mutation: false }).problem, undefined, spec.id);
  }
});

const broken = [
  ["an API that is not enabled", "preflight.services", { json: { services: REQUIRED_APIS.slice(1).map((name) => ({ config: { name } })) } }, /APIs not enabled/],
  ["a missing Firestore database", "preflight.firestore-database", { status: 404, json: {} }, /HTTP 404/],
  ["a primary bucket with versioning already on", "preflight.primary-bucket", { json: { versioning: { enabled: true } } }, /already has versioning/],
  ["a control bucket that already exists", "preflight.control-bucket", { status: 200, json: {} }, /HTTP 200/],
  ["a topic that already exists", "preflight.topics", { json: { topics: [{ name: `projects/${PROJECT}/topics/fe-events-primary` }] } }, /topics already exist/],
  ["no Eventarc service agent role", "preflight.iam", { json: { bindings: [] } }, /eventarc\.serviceAgent/],
  ["a conditional Eventarc binding", "preflight.iam", { json: { bindings: [{ role: "roles/eventarc.serviceAgent", condition: { title: "x" }, members: [`serviceAccount:service-${NUMBER}@gcp-sa-eventarc.iam.gserviceaccount.com`] }] } }, /eventarc\.serviceAgent/],
  ["Auth not initialized", "preflight.auth-config", { status: 404, json: {} }, /HTTP 404/],
  ["no Rules release", "preflight.rules-release", { status: 404, json: {} }, /HTTP 404/],
  ["Rules that do not allow the client write", "preflight.rules-ruleset", { json: { source: { files: [{ content: "allow read: if false;" }] } } }, /Rules do not mention/],
  ["a function of ours already deployed (Gen1)", "preflight.functions-v1", { json: { functions: [{ name: "projects/p/locations/l/functions/fsCreatedV1" }] } }, /Gen1 functions already deployed/],
  ["a function of ours already deployed (Gen2)", "preflight.functions-v2", { json: { functions: [{ name: "projects/p/locations/l/functions/fscreatedv2" }] } }, /Gen2 functions already deployed/],
  ["a Cloud Run service of ours", "preflight.run-services", { json: { services: [{ name: "projects/p/locations/l/services/fscreatedv2" }] } }, /Cloud Run services/],
  ["an Eventarc trigger of ours", "preflight.eventarc-triggers", { json: { triggers: [{ name: "projects/p/locations/l/triggers/fscreatedv2-123" }] } }, /Eventarc triggers/],
  ["a repository that is missing", "preflight.artifact-repository", { status: 404, json: {} }, /HTTP 404/],
  ["a project that is not active", "preflight.project", { json: { projectId: PROJECT, lifecycleState: "DELETE_REQUESTED", projectNumber: NUMBER } }, /not the active/],
];
for (const [label, id, change, pattern] of broken) {
  test(`the preflight stops for ${label}`, async () => {
    const bodies = healthy();
    bodies[id] = { ...bodies[id], ...change };
    const { problems } = await runWith(bodies);
    assert.ok(problems.some((p) => p.startsWith(id) && pattern.test(p)), JSON.stringify(problems));
  });
}

test("a step that gets no usable answer is a problem, not a pass", async () => {
  const { problems } = await runPreflight(async (spec) => ({ id: spec.id, kind: "unknown" }));
  assert.equal(problems.length, PREFLIGHT.length);
});

test("an unrelated function in the region does not stop the preflight", async () => {
  assert.deepEqual((await runWith(healthy())).problems, []);
});

test("IAM pairs redact user accounts and the diff names what was added and removed", () => {
  const before = { bindings: [{ role: "roles/owner", members: ["user:someone@example.com"] }, { role: "roles/run.invoker", members: ["serviceAccount:a@x"] }] };
  const after = { bindings: [{ role: "roles/owner", members: ["user:someone@example.com"] }, { role: "roles/pubsub.publisher", members: ["serviceAccount:b@x"], condition: { title: "t" } }] };
  assert.deepEqual(iamPairs(before), ["roles/owner user:<redacted>", "roles/run.invoker serviceAccount:a@x"]);
  assert.deepEqual(iamDiff(before, after), { added: ["roles/pubsub.publisher serviceAccount:b@x (conditional)"], removed: ["roles/run.invoker serviceAccount:a@x"] });
});
