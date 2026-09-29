import assert from "node:assert/strict";
import fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import * as work from "./storage-object/production-artifact-work-profile.mjs";
import * as registryModule from "./storage-object/production-secret-registry.mjs";
import { createProductionArtifactProfile } from "./storage-object/production-artifact-policy.mjs";
import { createProductionStandaloneFailStop } from "./storage-object/production-standalone-fail-stop.mjs";
import { createProductionArtifactWriter } from "./storage-object/production-artifact-writer.mjs";
import * as inventoryModule from "./storage-object/production-artifact-inventory.mjs";
import * as sharedModule from "./storage-object/production-shared-file-inspector.mjs";
import {
  createProductionSharedReportWriter,
  originalProductionSharedReportWriterContext,
} from "./storage-object/production-shared-report-file.mjs";
import { buildProductionStage3DraftPlan } from "./storage-object/stage3-plan.mjs";
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
const limits = { maxValues: 1000, maxUtf8Bytes: 1048576, maxIndexNodes: 200000 };
const profile = work.createProductionArtifactWorkProfile({ plan, limits }),
  bounds = work.originalProductionArtifactWorkProfile(profile, { plan }),
  registryInput = {
    ...limits,
    maxScanCodeUnits: bounds.maxSingleScanCodeUnits,
    workProfile: profile,
  };
function fixture(action) {
  const root = fs.realpathSync(fs.mkdtempSync(join(tmpdir(), "fireemu-work-composition-"))),
    directory = join(root, "owned"),
    shared = join(root, "shared");
  fs.chmodSync(root, 0o700);
  fs.mkdirSync(directory, { mode: 0o700 });
  fs.mkdirSync(shared, { mode: 0o700 });
  let registry;
  try {
    registry = registryModule.createProductionSecretRegistry(registryInput);
    const artifactProfile = createProductionArtifactProfile({
        plan,
        resources,
        secretRegistry: registry,
      }),
      boundary = createProductionStandaloneFailStop({ directory, profile: artifactProfile }),
      inventory = inventoryModule.ensureProductionArtifactInventory({
        directory,
        profile: artifactProfile,
        boundary,
      });
    return action({ root, directory, shared, registry, artifactProfile, boundary, inventory });
  } finally {
    registry?.close();
    fs.rmSync(root, { recursive: true });
  }
}
test("registry selects only the original bound work profile and exact limits", () => {
  assert.equal(typeof registryModule.originalProductionSecretRegistryWorkProfile, "function");
  const registry = registryModule.createProductionSecretRegistry(registryInput);
  try {
    assert.equal(registryModule.originalProductionSecretRegistryWorkProfile(registry), profile);
    assert.equal(registryModule.originalProductionSecretRegistryWorkProfile({ ...registry }), null);
    assert.equal(registry.openScan().snapshot().maxScanCodeUnits, bounds.maxSingleScanCodeUnits);
    for (const changed of [
      { ...registryInput, workProfile: { ...profile } },
      { ...registryInput, maxValues: 999 },
      { ...registryInput, maxScanCodeUnits: bounds.maxSingleScanCodeUnits + 1 },
    ])
      assert.throws(() => registryModule.createProductionSecretRegistry(changed));
  } finally {
    registry.close();
  }
});
test("artifact profile cannot pair a registry work profile with a foreign canonical plan", () => {
  const registry = registryModule.createProductionSecretRegistry(registryInput);
  try {
    assert.throws(() =>
      createProductionArtifactProfile({
        plan: buildProductionStage3DraftPlan({
          projectId: "foreign-project",
          bucket: plan.bucket,
          runIds: ["recordone", "recordtwo"],
        }),
        resources,
        secretRegistry: registry,
      }),
    );
    assert.ok(createProductionArtifactProfile({ plan, resources, secretRegistry: registry }));
  } finally {
    registry.close();
  }
});
test("owned inventory keeps exact task charge across original writer recordings", () =>
  fixture(({ directory, registry, artifactProfile, boundary, inventory }) => {
    const writer = createProductionArtifactWriter({
      directory,
      profile: artifactProfile,
      boundary,
    });
    writer.write({
      recording: 1,
      operationId: `r1/control/${"a".repeat(64)}`,
      kind: "journal",
      value: { type: "receipt", recording: 1, sequence: 1 },
    });
    registry.register("SYNTHETIC_BOUNDED_VALUE_ALPHA");
    const first = inventoryModule.originalProductionArtifactInventoryWork(inventory);
    assert.equal(typeof first, "bigint");
    assert.ok(first > 0n);
    writer.write({
      recording: 2,
      operationId: `r2/control/${"b".repeat(64)}`,
      kind: "journal",
      value: { type: "receipt", recording: 2, sequence: 2 },
    });
    registry.register("SYNTHETIC_BOUNDED_VALUE_BETA");
    const second = inventoryModule.originalProductionArtifactInventoryWork(inventory);
    assert.ok(second > first * 2n);
    assert.equal(inventoryModule.originalProductionArtifactInventoryWork({ ...inventory }), null);
    assert.equal(registry.snapshot().failed, false);
  }));
test("shared and owned accounts consume the same exact aggregate without changing shared bytes", () =>
  fixture(({ directory, shared, registry, artifactProfile, boundary, inventory }) => {
    const path = join(shared, "ledger.md"),
      bytes = Buffer.from("unrelated!\n");
    fs.writeFileSync(path, bytes, { mode: 0o600 });
    const inspector = sharedModule.createProductionSharedFileInspector({
        directory,
        profile: artifactProfile,
        boundary,
        files: [{ kind: "sandbox-ledger", path }],
      }),
      reportWriter = createProductionSharedReportWriter({
        directory,
        profile: artifactProfile,
        boundary,
        inspector,
      });
    inventoryModule.attachProductionSharedArtifactInspection({
      inventory,
      inspector,
      reportWriter,
    });
    registry.register("SYNTHETIC_BOUNDED_VALUE_ALPHA");
    const first = sharedModule.originalProductionSharedInspectorWork(inspector);
    assert.equal(typeof first, "bigint");
    const expectedScan = registry.openScan();
    expectedScan.findSecretCopyLines(bytes.toString("utf8"));
    assert.equal(
      first,
      BigInt(bytes.length + expectedScan.snapshot().scanCodeUnits),
      "shared read and scan charges must both be present",
    );
    assert.equal(inventoryModule.originalProductionArtifactInventoryWork(inventory), first);
    assert.equal(originalProductionSharedReportWriterContext(reportWriter).work, 0n);
    const writer = createProductionArtifactWriter({
        directory,
        profile: artifactProfile,
        boundary,
      }),
      receipt = writer.write({
        recording: 1,
        operationId: `r1/control/${"a".repeat(64)}`,
        kind: "journal",
        value: { type: "receipt", recording: 1, sequence: 1 },
      }),
      saved = fs.readFileSync(join(directory, receipt.file));
    registry.register("SYNTHETIC_BOUNDED_VALUE_BETA");
    const scan = registry.openScan();
    assert.equal(scan.hasSecretCopy(saved.toString("utf8")), false);
    assert.equal(
      inventoryModule.originalProductionArtifactInventoryWork(inventory),
      first * 2n + BigInt(saved.length + scan.snapshot().scanCodeUnits),
    );
    assert.deepEqual(fs.readFileSync(path), bytes);
    assert.equal(sharedModule.originalProductionSharedInspectorWork(inspector), first * 2n);
  }));
