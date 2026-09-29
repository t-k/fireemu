import assert from "node:assert/strict";
import fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import * as work from "./storage-object/production-artifact-work-profile.mjs";
import * as registryModule from "./storage-object/production-secret-registry.mjs";
import { createProductionArtifactProfile } from "./storage-object/production-artifact-policy.mjs";
import { createProductionStandaloneFailStop } from "./storage-object/production-standalone-fail-stop.mjs";
import * as inventoryModule from "./storage-object/production-artifact-inventory.mjs";
import * as sharedModule from "./storage-object/production-shared-file-inspector.mjs";
import {
  createProductionSharedReportWriter,
  bindProductionSharedReportWriterBroker,
  writeProductionSharedPrivacyReport,
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
function fixture(action, profiled = true) {
  const root = fs.realpathSync(fs.mkdtempSync(join(tmpdir(), "fireemu-work-composition-"))),
    directory = join(root, "owned"),
    shared = join(root, "shared");
  fs.chmodSync(root, 0o700);
  fs.mkdirSync(directory, { mode: 0o700 });
  fs.mkdirSync(shared, { mode: 0o700 });
  let registry;
  try {
    registry = registryModule.createProductionSecretRegistry(
      profiled ? registryInput : { ...limits, maxScanCodeUnits: 16777216 },
    );
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
function pair(f) {
  const path = join(f.shared, "ledger.md");
  fs.writeFileSync(path, "unrelated!\n", { mode: 0o600 });
  const inspector = sharedModule.createProductionSharedFileInspector({
    directory: f.directory,
    profile: f.artifactProfile,
    boundary: f.boundary,
    files: [{ kind: "sandbox-ledger", path }],
  });
  const reportWriter = createProductionSharedReportWriter({
    directory: f.directory,
    profile: f.artifactProfile,
    boundary: f.boundary,
    inspector,
  });
  return { inspector, reportWriter };
}
test("profiled inspector rejects unbound inspection without work or authority", () =>
  fixture((f) => {
    const { inspector } = pair(f);
    assert.throws(
      () => sharedModule.inspectProductionSharedFiles(inspector),
      /production shared files uncheckable/,
    );
    assert.equal(sharedModule.originalProductionSharedInspectorWork(inspector), 0n);
    assert.equal(inventoryModule.originalProductionArtifactInventoryWork(f.inventory), 0n);
  }));
test("bound inspector and report cannot expose a permit through original diagnostic contexts", () =>
  fixture((f) => {
    const { inspector, reportWriter } = pair(f);
    inventoryModule.attachProductionSharedArtifactInspection({
      inventory: f.inventory,
      inspector,
      reportWriter,
    });
    for (const supplied of [
      undefined,
      {},
      f.inventory,
      { ...f.inventory },
      new Proxy({}, {}),
      inventoryModule.originalProductionArtifactInventoryObserver(f.inventory, f.registry),
    ]) {
      assert.throws(
        () => sharedModule.inspectProductionSharedFiles(inspector, undefined, supplied),
        /production shared files uncheckable/,
      );
      assert.equal(sharedModule.originalProductionSharedInspectorWork(inspector), 0n);
    }
    assert.deepEqual(
      Object.keys(originalProductionSharedReportWriterContext(reportWriter)).toSorted(),
      ["boundary", "directory", "inspector", "outcome", "profile", "registry", "work"],
    );
    f.registry.register("SYNTHETIC_BOUNDED_VALUE_ALPHA");
    const total = inventoryModule.originalProductionArtifactInventoryWork(f.inventory);
    assert.ok(total > 0n);
    assert.equal(total, sharedModule.originalProductionSharedInspectorWork(inspector));
    assert.throws(
      () => sharedModule.inspectProductionSharedFiles(inspector),
      /production shared files uncheckable/,
    );
    assert.equal(inventoryModule.originalProductionArtifactInventoryWork(f.inventory), total);
    f.registry.register("SYNTHETIC_BOUNDED_VALUE_BETA");
    assert.equal(inventoryModule.originalProductionArtifactInventoryWork(f.inventory), total * 2n);
  }));
test("legacy standalone work cannot be silently promoted into a joint inventory", () =>
  fixture((f) => {
    const { inspector, reportWriter } = pair(f);
    assert.ok(sharedModule.inspectProductionSharedFiles(inspector));
    const standalone = sharedModule.originalProductionSharedInspectorWork(inspector);
    assert.equal(typeof standalone, "number");
    assert.ok(standalone > 0);
    assert.throws(
      () =>
        inventoryModule.attachProductionSharedArtifactInspection({
          inventory: f.inventory,
          inspector,
          reportWriter,
        }),
      /invalid production shared artifact inspection/,
    );
    assert.equal(sharedModule.originalProductionSharedInspectorWork(inspector), standalone);
    assert.equal(inventoryModule.originalProductionArtifactInventoryWork(f.inventory), 0);
  }, false));
test("legacy pristine attachment retains Number accounting and rejects external inspection", () =>
  fixture((f) => {
    const { inspector, reportWriter } = pair(f);
    inventoryModule.attachProductionSharedArtifactInspection({
      inventory: f.inventory,
      inspector,
      reportWriter,
    });
    assert.throws(
      () => sharedModule.inspectProductionSharedFiles(inspector),
      /production shared files uncheckable/,
    );
    f.registry.register("SYNTHETIC_BOUNDED_VALUE_ALPHA");
    const total = inventoryModule.originalProductionArtifactInventoryWork(f.inventory);
    assert.equal(typeof total, "number");
    assert.ok(total > 0);
    assert.equal(total, sharedModule.originalProductionSharedInspectorWork(inspector));
  }, false));

test("foreign permits never bind, invoke hooks, poison a pristine cap or disclose original authority", () =>
  fixture((f) => {
    const { inspector, reportWriter } = pair(f);
    let hooks = 0;
    const proxy = new Proxy(
      {},
      {
        get() {
          hooks++;
          throw new Error("unused");
        },
        ownKeys() {
          hooks++;
          throw new Error("unused");
        },
      },
    );
    for (const fake of [
      undefined,
      {},
      proxy,
      f.inventory,
      { ...f.inventory },
      originalProductionSharedReportWriterContext(reportWriter),
    ]) {
      assert.equal(
        inventoryModule.productionSharedArtifactBrokerAllows(fake, inspector, "inspect"),
        false,
      );
      assert.throws(() => sharedModule.bindProductionSharedFileInspectorBroker(inspector, fake));
      assert.throws(() => bindProductionSharedReportWriterBroker(reportWriter, fake));
    }
    inventoryModule.attachProductionSharedArtifactInspection({
      inventory: f.inventory,
      inspector,
      reportWriter,
    });
    assert.throws(
      () => writeProductionSharedPrivacyReport(reportWriter, proxy, proxy),
      /production shared report uncertain/,
    );
    assert.equal(hooks, 0);
    assert.equal(originalProductionSharedReportWriterContext(reportWriter).work, 0n);
    assert.equal(originalProductionSharedReportWriterContext(reportWriter).outcome, "NONE");
    f.registry.register("SYNTHETIC_BOUNDED_VALUE_ALPHA");
    assert.equal(
      inventoryModule.originalProductionArtifactInventoryWork(f.inventory),
      sharedModule.originalProductionSharedInspectorWork(inspector),
    );
  }));
