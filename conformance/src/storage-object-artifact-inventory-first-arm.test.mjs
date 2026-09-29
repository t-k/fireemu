import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, realpathSync, rmSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { createProductionArtifactProfile } from "./storage-object/production-artifact-policy.mjs";
import { createProductionSecretRegistry } from "./storage-object/production-secret-registry.mjs";
import { createProductionStandaloneFailStop } from "./storage-object/production-standalone-fail-stop.mjs";
import { ensureProductionArtifactInventory } from "./storage-object/production-artifact-inventory.mjs";
import { buildProductionStage3DraftPlan } from "./storage-object/stage3-plan.mjs";
test("the first arm rejects a foreign original profile before installing an inventory", () => {
  const directory = realpathSync(mkdtempSync(join(tmpdir(), "fireemu-first-arm-")));
  chmodSync(directory, 0o700);
  const registry = createProductionSecretRegistry({
    maxValues: 81,
    maxUtf8Bytes: 65536,
    maxIndexNodes: 200000,
    maxScanCodeUnits: 16777216,
  });
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
  const profile = createProductionArtifactProfile({ plan, resources, secretRegistry: registry }),
    otherProfile = createProductionArtifactProfile({ plan, resources, secretRegistry: registry }),
    boundary = createProductionStandaloneFailStop({ directory, profile });
  try {
    assert.throws(
      () => ensureProductionArtifactInventory({ directory, profile: otherProfile, boundary }),
      /invalid production artifact inventory/,
    );
    const inventory = ensureProductionArtifactInventory({ directory, profile, boundary });
    assert.equal(ensureProductionArtifactInventory({ directory, profile, boundary }), inventory);
    assert.equal(readdirSync(directory).length, 0);
    assert.equal(registry.snapshot().closed, false);
  } finally {
    registry.close();
    rmSync(directory, { recursive: true });
  }
});
