import assert from "node:assert/strict";
import test from "node:test";
import * as policy from "./storage-object/production-artifact-policy.mjs";
import { buildProductionStage3DraftPlan } from "./storage-object/stage3-plan.mjs";
import { createProductionSecretRegistry } from "./storage-object/production-secret-registry.mjs";

const plan = buildProductionStage3DraftPlan({
  projectId: "example-project",
  bucket: "example.appspot.com",
  runIds: ["recordone", "recordtwo"],
});
function fixture(action) {
  const registry = createProductionSecretRegistry({
    maxValues: 81,
    maxUtf8Bytes: 65536,
    maxIndexNodes: 200000,
    maxScanCodeUnits: 16777216,
  });
  const profile = policy.createProductionArtifactProfile({
    plan,
    resources: {
      projectNumber: "123456789012",
      apiKeyResource: "projects/123456789012/locations/global/keys/fixture-key",
      rulesetResource: "projects/example-project/rulesets/fixture-ruleset",
    },
    secretRegistry: registry,
  });
  try {
    assert.equal(typeof policy.productionArtifactProfileUsesPlan, "function");
    return action({ profile, registry, matches: policy.productionArtifactProfileUsesPlan });
  } finally {
    registry.close();
  }
}

test("the original profile binds the whole canonical plan without exposing it", () => {
  fixture(({ profile, matches }) => {
    assert.equal(matches(profile, plan), true);
    assert.equal(matches(profile, structuredClone(plan)), true);
    assert.deepEqual(Object.keys(profile), []);
    const context = policy.originalProductionArtifactContext(profile);
    assert.deepEqual(Object.keys(context).toSorted(), ["runIds", "secretRegistry"]);
  });
});

for (const variant of ["project", "bucket", "run-id", "lowered-cap", "extra-field"]) {
  test(`the original profile rejects a ${variant} plan even with plausible run IDs`, () => {
    fixture(({ profile, registry, matches }) => {
      const changed = structuredClone(plan);
      if (variant === "project") changed.projectId = "other-project";
      if (variant === "bucket") changed.bucket = "other.appspot.com";
      if (variant === "run-id") changed.recordings[1].runId = "otherrecord";
      if (variant === "lowered-cap") changed.maxRequests--;
      if (variant === "extra-field") changed.extra = true;
      assert.equal(matches(profile, changed), false);
      assert.equal(registry.snapshot().closed, false);
      assert.equal(matches(profile, plan), true);
    });
  });
}

test("forged profile identities and plan Proxy/accessor inputs execute no hooks", () => {
  fixture(({ profile, registry, matches }) => {
    let hooks = 0;
    const proxy = new Proxy(plan, {
      ownKeys() {
        hooks++;
        throw new Error("hook");
      },
      getPrototypeOf() {
        hooks++;
        throw new Error("hook");
      },
      get() {
        hooks++;
        throw new Error("hook");
      },
    });
    const getter = structuredClone(plan);
    Object.defineProperty(getter, "projectId", {
      enumerable: true,
      get() {
        hooks++;
        throw new Error("hook");
      },
    });
    for (const value of [{}, Object.create(profile), new Proxy(profile, {})])
      assert.equal(matches(value, plan), false);
    assert.equal(matches(profile, proxy), false);
    assert.equal(matches(profile, getter), false);
    assert.equal(hooks, 0);
    assert.equal(registry.snapshot().closed, false);
  });
});

test("a closed task cannot authorize a new artifact channel plan binding", () => {
  fixture(({ profile, registry, matches }) => {
    registry.close();
    assert.equal(matches(profile, plan), false);
  });
});
