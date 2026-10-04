import assert from "node:assert/strict";
import test from "node:test";

import { destination } from "./functions-events/record/guard.mjs";
import {
  PREFLIGHT,
  REQUIRED_APIS,
  iamDiff,
  iamPairs,
  runPreflight,
} from "./functions-events/record/preflight.mjs";

import { PROJECT } from "./functions-events/record/script.mjs";
import { NUMBER, healthy } from "./functions-events-record-world.mjs";

const runWith = async (bodies) => {
  const seen = [];
  const result = await runPreflight(async (spec, vars) => {
    seen.push({ spec, vars: { ...vars } });
    const answer = bodies[spec.id];
    return {
      id: spec.id,
      status: answer.status,
      json: answer.json,
      kind: answer.status >= 500 ? "unknown" : answer.status < 300 ? "success" : "refusal",
    };
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
    assert.equal(
      destination({ method: spec.method, url, mutation: false, body: spec.body }).problem,
      undefined,
      spec.id,
    );
  }
});

const broken = [
  [
    "an API that is not enabled",
    "preflight.services",
    { json: { services: REQUIRED_APIS.slice(1).map((name) => ({ config: { name } })) } },
    /APIs not enabled/,
  ],
  [
    "a missing Firestore database",
    "preflight.firestore-database",
    { status: 404, json: {} },
    /HTTP 404/,
  ],
  [
    "a primary bucket with versioning already on",
    "preflight.primary-bucket",
    { json: { versioning: { enabled: true } } },
    /already has versioning/,
  ],
  [
    "a control bucket that already exists",
    "preflight.control-bucket",
    { status: 200, json: {} },
    /HTTP 200/,
  ],
  [
    "a topic that already exists",
    "preflight.topics",
    { json: { topics: [{ name: `projects/${PROJECT}/topics/fe-events-primary` }] } },
    /topics already exist/,
  ],
  [
    "no Eventarc service agent role",
    "preflight.iam",
    { json: { bindings: [] } },
    /eventarc\.serviceAgent/,
  ],
  [
    "a conditional Eventarc binding",
    "preflight.iam",
    {
      json: {
        bindings: [
          {
            role: "roles/eventarc.serviceAgent",
            condition: { title: "x" },
            members: [`serviceAccount:service-${NUMBER}@gcp-sa-eventarc.iam.gserviceaccount.com`],
          },
        ],
      },
    },
    /eventarc\.serviceAgent/,
  ],
  ["Auth not initialized", "preflight.auth-config", { status: 404, json: {} }, /HTTP 404/],
  ["no Rules release", "preflight.rules-release", { status: 404, json: {} }, /HTTP 404/],
  [
    "Rules that do not allow the client write",
    "preflight.rules-ruleset",
    { json: { source: { files: [{ content: "allow read: if false;" }] } } },
    /Rules do not mention/,
  ],
  [
    "a function of ours already deployed (Gen1)",
    "preflight.functions-v1",
    { json: { functions: [{ name: "projects/p/locations/l/functions/fsCreatedV1" }] } },
    /Gen1 functions already exist/,
  ],
  [
    "a function of ours already deployed (Gen2)",
    "preflight.functions-v2",
    { json: { functions: [{ name: "projects/p/locations/l/functions/fscreatedv2" }] } },
    /Gen2 functions already exist/,
  ],
  [
    "a Cloud Run service of ours",
    "preflight.run-services",
    { json: { services: [{ name: "projects/p/locations/l/services/fscreatedv2" }] } },
    /Cloud Run services/,
  ],
  [
    "an Eventarc trigger of ours",
    "preflight.eventarc-triggers",
    { json: { triggers: [{ name: "projects/p/locations/l/triggers/fscreatedv2-123" }] } },
    /Eventarc triggers/,
  ],
  [
    "a repository that is missing",
    "preflight.artifact-repository",
    { status: 404, json: {} },
    /HTTP 404/,
  ],
  [
    "a project that is not active",
    "preflight.project",
    { json: { projectId: PROJECT, lifecycleState: "DELETE_REQUESTED", projectNumber: NUMBER } },
    /not the active/,
  ],
];
for (const [label, id, change, pattern] of broken) {
  test(`the preflight stops for ${label}`, async () => {
    const bodies = healthy();
    bodies[id] = { ...bodies[id], ...change };
    const { problems } = await runWith(bodies);
    assert.ok(
      problems.some((p) => p.startsWith(id) && pattern.test(p)),
      JSON.stringify(problems),
    );
  });
}

test("a step that gets no usable answer is a problem, not a pass", async () => {
  const { problems } = await runPreflight(async (spec) => ({ id: spec.id, kind: "unknown" }));
  assert.equal(problems.length, PREFLIGHT.length);
});

test("any function in the region stops the preflight, not only ours (the CLI's name filters are prefix matches)", async () => {
  const bodies = healthy();
  bodies["preflight.functions-v2"] = {
    status: 200,
    json: { functions: [{ name: "projects/p/locations/l/functions/unrelated" }] },
  };
  const { problems } = await runWith(bodies);
  assert.ok(
    problems.some((p) => p.startsWith("preflight.functions-v2") && /already exist/.test(p)),
  );
});

const namespace = [
  [
    "objects under fe-events/",
    "preflight.objects-fe-events",
    { json: { items: [{ name: "fe-events/x.txt" }] } },
    /objects under fe-events\/ in the primary bucket already exist/,
  ],
  [
    "objects under other/",
    "preflight.objects-other",
    { json: { items: [{ name: "other/x.txt" }] } },
    /already exist/,
  ],
  [
    "a second page of objects",
    "preflight.objects-other",
    { json: { nextPageToken: "t" } },
    /more than one page/,
  ],
  [
    "a document in the primary collection",
    "preflight.collection-fe_events_primary",
    { json: [{ document: { name: "x" } }] },
    /not empty/,
  ],
  [
    "a marker document",
    "preflight.collection-fe_events_retry_markers",
    { json: [{ document: { name: "x" } }] },
    /not empty/,
  ],
  [
    "a query that does not answer with a list",
    "preflight.collection-fe_events_control",
    { json: { error: "x" } },
    /did not answer with a list/,
  ],
  [
    "an API key of another project (another project number)",
    "preflight.api-key-project",
    { json: { authorizedDomains: [], projectId: "999999999999" } },
    /does not belong to the sandbox project/,
  ],
  [
    "an API key answer that names the project by its id string",
    "preflight.api-key-project",
    { json: { projectId: "fireemu-oracle-events" } },
    /not a project number/,
  ],
  [
    "an API key answer that names another project id string",
    "preflight.api-key-project",
    { json: { projectId: "another-project" } },
    /not a project number/,
  ],
  [
    "an API key read that names no project",
    "preflight.api-key-project",
    { json: {} },
    /not a project number/,
  ],
  [
    "an API key answer whose projectId is a number, not a digit string",
    "preflight.api-key-project",
    { json: { projectId: 123456789012 } },
    /not a project number/,
  ],
  [
    "an API key answer with digits and a suffix",
    "preflight.api-key-project",
    { json: { projectId: `${NUMBER}x` } },
    /not a project number/,
  ],
];
for (const [label, id, change, pattern] of namespace) {
  test(`the preflight stops for ${label}`, async () => {
    const bodies = healthy();
    bodies[id] = { status: 200, ...change };
    const { problems } = await runWith(bodies);
    assert.ok(
      problems.some((p) => p.startsWith(id) && pattern.test(p)),
      JSON.stringify(problems),
    );
  });
}

test("IAM pairs redact user accounts and the diff names what was added and removed", () => {
  const before = {
    bindings: [
      { role: "roles/owner", members: ["user:someone@example.com"] },
      { role: "roles/run.invoker", members: ["serviceAccount:a@x"] },
    ],
  };
  const after = {
    bindings: [
      { role: "roles/owner", members: ["user:someone@example.com"] },
      {
        role: "roles/pubsub.publisher",
        members: ["serviceAccount:b@x"],
        condition: { title: "t" },
      },
    ],
  };
  assert.deepEqual(iamPairs(before), [
    "roles/owner user:<redacted>",
    "roles/run.invoker serviceAccount:a@x",
  ]);
  assert.deepEqual(iamDiff(before, after), {
    added: ["roles/pubsub.publisher serviceAccount:b@x (conditional)"],
    removed: ["roles/run.invoker serviceAccount:a@x"],
  });
});

test("the key is bound to the project number read in the same run, never to a fixed number", async () => {
  // the same answer is right for one run and wrong for another whose project read gives another number
  const other = healthy();
  other["preflight.project"] = {
    status: 200,
    json: { projectId: PROJECT, lifecycleState: "ACTIVE", projectNumber: "555555555555" },
  };
  const { problems } = await runWith(other);
  assert.ok(
    problems.some((p) => p.startsWith("preflight.api-key-project") && /does not belong/.test(p)),
  );
  other["preflight.api-key-project"] = { status: 200, json: { projectId: "555555555555" } };
  assert.ok(
    !(await runWith(other)).problems.some((p) => p.startsWith("preflight.api-key-project")),
  );
});

test("without a project number from this run the key cannot be bound: fail closed", async () => {
  for (const json of [
    { projectId: PROJECT, lifecycleState: "ACTIVE" },
    { projectId: PROJECT, lifecycleState: "ACTIVE", projectNumber: "not-digits" },
    { projectId: PROJECT, lifecycleState: "DELETE_REQUESTED", projectNumber: NUMBER },
  ]) {
    const bodies = healthy();
    bodies["preflight.project"] = { status: 200, json };
    const { problems } = await runWith(bodies);
    assert.ok(
      problems.some(
        (p) => p.startsWith("preflight.api-key-project") && /project number of this run/.test(p),
      ),
      JSON.stringify(problems),
    );
  }
});
