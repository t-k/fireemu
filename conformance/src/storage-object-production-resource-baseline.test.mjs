import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { buildProductionStage3DraftPlan } from "./storage-object/stage3-plan.mjs";

let implementation;
try {
  implementation = await import("./storage-object/production-resource-baseline.mjs");
} catch (error) {
  if (error.code !== "ERR_MODULE_NOT_FOUND") throw error;
  implementation = {};
}
const hash = (value) => createHash("sha256").update(value).digest("hex");
const plan = buildProductionStage3DraftPlan({
  projectId: "example-project",
  bucket: "example.appspot.com",
  runIds: ["recordone", "recordtwo"],
});
const resources = {
  projectNumber: "123456789012",
  apiKeyResource: "projects/123456789012/locations/global/keys/fixture-key",
  rulesetResource: "projects/example-project/rulesets/fixture-ruleset",
};
const key = "SYNTHETIC_RESOURCE_BASELINE_KEY";
const baseline = {
  project: {
    projectId: plan.projectId,
    projectNumber: resources.projectNumber,
    lifecycleState: "ACTIVE",
  },
  defaultBucket: {
    name: "projects/example-project/defaultBucket",
    bucket: { name: `projects/example-project/buckets/${plan.bucket}` },
    location: "US-CENTRAL1",
  },
  bucket: {
    kind: "storage#bucket",
    name: plan.bucket,
    projectNumber: resources.projectNumber,
    location: "US-CENTRAL1",
    metageneration: "1",
  },
  auth: {
    name: "projects/example-project/config",
    subtype: "FIREBASE_AUTH",
    signIn: { email: { enabled: true, passwordRequired: true } },
    client: { apiKey: key },
  },
  key: {
    name: resources.apiKeyResource,
    uid: "synthetic-key-uid",
    restrictions: {
      apiTargets: [
        { service: "identitytoolkit.googleapis.com" },
        { service: "securetoken.googleapis.com" },
      ],
    },
  },
  apiKeySha256: hash(key),
};
const kinds = new Map([
  ["project-binding", "project"],
  ["default-bucket", "defaultBucket"],
  ["bucket-config", "bucket"],
  ["auth-config", "auth"],
  ["api-key-metadata", "key"],
]);
function create(input = { plan, resources, baseline }) {
  assert.equal(
    typeof implementation.createProductionResourceBaseline,
    "function",
    "the source-owned baseline factory must exist",
  );
  return implementation.createProductionResourceBaseline(input);
}
function verify(capability, kind, value, changes = {}) {
  return implementation.verifyProductionResourceBaselineReadback(capability, {
    kind,
    status: 200,
    body: Buffer.from(JSON.stringify(value)),
    ...changes,
  });
}
for (const [kind, field] of kinds) {
  test(`pure original baseline verifies its declared ${kind} readback`, () => {
    const cap = create();
    assert.deepEqual(Reflect.ownKeys(cap), []);
    assert.equal(Object.isFrozen(cap), true);
    assert.equal(verify(cap, kind, baseline[field]), true);
    assert.equal(verify({ ...cap }, kind, baseline[field]), false);
    assert.equal(verify(cap, kind, baseline[field], { status: 403 }), false);
    assert.equal(verify(cap, kind, { ...baseline[field], unknownCapability: "opaque" }), false);
  });
}
test("verified API key stays memory-only and is bound to the declared SHA", () => {
  const cap = create(),
    row = { status: 200, body: Buffer.from(JSON.stringify({ keyString: key })) };
  assert.equal(implementation.readVerifiedProductionResourceApiKey(cap, row), key);
  assert.equal(
    implementation.readVerifiedProductionResourceApiKey(cap, {
      ...row,
      body: Buffer.from(JSON.stringify({ keyString: key + "foreign" })),
    }),
    null,
  );
  assert.equal(implementation.readVerifiedProductionResourceApiKey({ ...cap }, row), null);
  assert.equal(
    implementation.readVerifiedProductionResourceApiKey(cap, { ...row, status: 404 }),
    null,
  );
});
for (const [label, field, changed] of [
  ["project number", "project", { ...baseline.project, projectNumber: "987654321098" }],
  ["project ID", "project", { ...baseline.project, projectId: "foreign-project" }],
  ["inactive project", "project", { ...baseline.project, lifecycleState: "DELETE_REQUESTED" }],
  [
    "default bucket",
    "defaultBucket",
    {
      ...baseline.defaultBucket,
      bucket: { name: "projects/example-project/buckets/foreign.appspot.com" },
    },
  ],
  [
    "default bucket location",
    "defaultBucket",
    { ...baseline.defaultBucket, location: "EUROPE-WEST1" },
  ],
  ["bucket name", "bucket", { ...baseline.bucket, name: "foreign.appspot.com" }],
  ["bucket number", "bucket", { ...baseline.bucket, projectNumber: "987654321098" }],
  ["bucket region", "bucket", { ...baseline.bucket, location: "EUROPE-WEST1" }],
  ["Auth project", "auth", { ...baseline.auth, name: "projects/foreign-project/config" }],
  ["Auth subtype", "auth", { ...baseline.auth, subtype: "IDENTITY_PLATFORM" }],
  [
    "email disabled",
    "auth",
    { ...baseline.auth, signIn: { email: { enabled: false, passwordRequired: true } } },
  ],
  [
    "password disabled",
    "auth",
    { ...baseline.auth, signIn: { email: { enabled: true, passwordRequired: false } } },
  ],
  [
    "key resource",
    "key",
    { ...baseline.key, name: "projects/123456789012/locations/global/keys/foreign-key" },
  ],
  ["broader key", "key", { ...baseline.key, restrictions: {} }],
  [
    "extra API target",
    "key",
    {
      ...baseline.key,
      restrictions: {
        apiTargets: [
          ...baseline.key.restrictions.apiTargets,
          { service: "storage.googleapis.com" },
        ],
      },
    },
  ],
  [
    "method restriction",
    "key",
    {
      ...baseline.key,
      restrictions: {
        apiTargets: [
          { service: "identitytoolkit.googleapis.com", methods: ["*"] },
          { service: "securetoken.googleapis.com" },
        ],
      },
    },
  ],
  [
    "application restriction",
    "key",
    {
      ...baseline.key,
      restrictions: {
        ...baseline.key.restrictions,
        browserKeyRestrictions: { allowedReferrers: ["https://example.invalid/*"] },
      },
    },
  ],
]) {
  test(`baseline rejects ${label} before any control request`, () => {
    assert.throws(
      () => create({ plan, resources, baseline: { ...baseline, [field]: changed } }),
      /invalid production resource baseline/,
    );
  });
}
test("configuration drift is rejected against the original immutable baseline", () => {
  const supplied = structuredClone(baseline),
    cap = create({ plan, resources, baseline: supplied });
  supplied.bucket.metageneration = "2";
  assert.equal(verify(cap, "bucket-config", supplied.bucket), false);
  assert.equal(verify(cap, "bucket-config", baseline.bucket), true);
});
test("duplicate JSON members cannot conceal a different project", () => {
  const cap = create();
  const body = Buffer.from(
    `{"projectId":"foreign-project","projectId":"${plan.projectId}","projectNumber":"${resources.projectNumber}","lifecycleState":"ACTIVE"}`,
  );
  assert.equal(verify(cap, "project-binding", {}, { body }), false);
});
test("data-only boundaries reject getters and proxies without invoking them", () => {
  let calls = 0;
  const getter = { plan, resources };
  Object.defineProperty(getter, "baseline", {
    enumerable: true,
    get() {
      calls++;
      return baseline;
    },
  });
  assert.throws(() => create(getter), /invalid production resource baseline/);
  assert.throws(
    () =>
      create(
        new Proxy(
          { plan, resources, baseline },
          {
            ownKeys() {
              calls++;
              return [];
            },
          },
        ),
      ),
    /invalid production resource baseline/,
  );
  const cap = create(),
    row = { kind: "project-binding", status: 200 };
  Object.defineProperty(row, "body", {
    enumerable: true,
    get() {
      calls++;
      return Buffer.from(JSON.stringify(baseline.project));
    },
  });
  assert.equal(implementation.verifyProductionResourceBaselineReadback(cap, row), false);
  assert.equal(calls, 0);
});
test("unbounded and malformed bodies are refused before baseline comparison", () => {
  const cap = create();
  for (const body of [
    Buffer.alloc(2 * 1024 * 1024 + 1),
    Buffer.from([255]),
    Buffer.from("{bad"),
    Buffer.from("[]"),
  ])
    assert.equal(verify(cap, "project-binding", {}, { body }), false);
  assert.throws(
    () =>
      create({
        plan,
        resources,
        baseline: { ...baseline, bucket: { ...baseline.bucket, name: "x".repeat(8193) } },
      }),
    /invalid production resource baseline/,
  );
});

test("the existing Firebase browser key is distinct from the restricted task key", () => {
  const browserKey = "SYNTHETIC_EXISTING_FIREBASE_BROWSER_KEY";
  const supplied = { ...baseline, auth: { ...baseline.auth, client: { apiKey: browserKey } } };
  const cap = create({ plan, resources, baseline: supplied });
  assert.equal(verify(cap, "auth-config", supplied.auth), true);
  assert.equal(
    implementation.readVerifiedProductionResourceApiKey(cap, {
      status: 200,
      body: Buffer.from(JSON.stringify({ keyString: key })),
    }),
    key,
  );
  assert.equal(
    implementation.readVerifiedProductionResourceApiKey(cap, {
      status: 200,
      body: Buffer.from(JSON.stringify({ keyString: browserKey })),
    }),
    null,
  );
});
test("a changed Auth client key is configuration drift, not the task key source", () => {
  const cap = create();
  assert.equal(
    verify(cap, "auth-config", {
      ...baseline.auth,
      client: { apiKey: "SYNTHETIC_CHANGED_BROWSER_KEY" },
    }),
    false,
  );
});

test("an original pure baseline is bound to its whole canonical plan and resource tuple", () => {
  const cap = create();
  assert.equal(typeof implementation.productionResourceBaselineUsesContext, "function");
  assert.equal(
    implementation.productionResourceBaselineUsesContext(cap, { plan, resources }),
    true,
  );
  assert.equal(
    implementation.productionResourceBaselineUsesContext(cap, {
      plan,
      resources: { ...resources, apiKeyResource: resources.apiKeyResource + "-foreign" },
    }),
    false,
  );
  const otherPlan = buildProductionStage3DraftPlan({
    projectId: plan.projectId,
    bucket: plan.bucket,
    runIds: ["recordtwo", "recordone"],
  });
  assert.equal(
    implementation.productionResourceBaselineUsesContext(cap, { plan: otherPlan, resources }),
    false,
  );
  assert.equal(
    implementation.productionResourceBaselineUsesContext({ ...cap }, { plan, resources }),
    false,
  );
  let calls = 0;
  const supplied = { resources };
  Object.defineProperty(supplied, "plan", {
    enumerable: true,
    get() {
      calls++;
      return plan;
    },
  });
  assert.equal(implementation.productionResourceBaselineUsesContext(cap, supplied), false);
  assert.equal(calls, 0);
});
