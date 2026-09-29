import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, chmodSync, realpathSync, rmSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";
import {
  createProductionSecretRegistry,
  bindProductionSecretArtifactInventory,
  registerProductionSecretBatch,
} from "./storage-object/production-secret-registry.mjs";
import { createProductionArtifactProfile } from "./storage-object/production-artifact-policy.mjs";
import { createProductionStandaloneFailStop } from "./storage-object/production-standalone-fail-stop.mjs";
import { createProductionArtifactWriter } from "./storage-object/production-artifact-writer.mjs";
import { createPrototypeWireFileWriter } from "./storage-object/production-owned-wire-files.mjs";
import {
  ensureProductionArtifactInventory,
  ensurePrototypeArtifactInventory,
  trackProductionArtifactFile,
  reserveProductionArtifactFile,
  originalProductionArtifactInventoryObserver,
} from "./storage-object/production-artifact-inventory.mjs";
import { buildProductionStage3DraftPlan } from "./storage-object/stage3-plan.mjs";
const limits = {
  maxValues: 81,
  maxUtf8Bytes: 65536,
  maxIndexNodes: 200000,
  maxScanCodeUnits: 16777216,
};
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
function fixture(action) {
  const directory = realpathSync(mkdtempSync(join(tmpdir(), "fireemu-inventory-identity-")));
  chmodSync(directory, 0o700);
  const registry = createProductionSecretRegistry(limits),
    profile = createProductionArtifactProfile({ plan, resources, secretRegistry: registry }),
    boundary = createProductionStandaloneFailStop({ directory, profile });
  try {
    return action({ directory, registry, profile, boundary });
  } finally {
    registry.close();
    rmSync(directory, { recursive: true });
  }
}
test("the original inventory has one task identity and rejects observer copies and rebinding without hooks", () =>
  fixture(({ directory, registry, profile, boundary }) => {
    const inventory = ensureProductionArtifactInventory({ directory, profile, boundary });
    assert.equal(ensureProductionArtifactInventory({ directory, profile, boundary }), inventory);
    assert.equal(
      typeof originalProductionArtifactInventoryObserver(inventory, registry),
      "function",
    );
    assert.equal(originalProductionArtifactInventoryObserver({ ...inventory }, registry), null);
    assert.equal(originalProductionArtifactInventoryObserver(inventory, {}), null);
    assert.equal(originalProductionArtifactInventoryObserver({}, undefined), null);
    assert.throws(
      () => bindProductionSecretArtifactInventory(registry, inventory),
      /invalid production secret artifact inventory/,
    );
    let hooks = 0;
    const proxy = new Proxy(inventory, {
      get() {
        hooks++;
        throw new Error("hook");
      },
      ownKeys() {
        hooks++;
        throw new Error("hook");
      },
    });
    assert.equal(originalProductionArtifactInventoryObserver(proxy, registry), null);
    assert.throws(
      () => bindProductionSecretArtifactInventory(registry, proxy),
      /invalid production secret artifact inventory/,
    );
    assert.equal(hooks, 0);
  }));
test("original profile, registry, directory and boundary are bound before any writer opens a file", () =>
  fixture(({ directory, registry, profile, boundary }) => {
    ensureProductionArtifactInventory({ directory, profile, boundary });
    const otherProfile = createProductionArtifactProfile({
      plan,
      resources,
      secretRegistry: registry,
    });
    const otherBoundary = createProductionStandaloneFailStop({ directory, profile });
    for (const input of [
      { directory, profile: otherProfile, boundary },
      { directory, profile, boundary: otherBoundary },
      { directory, profile: { ...profile }, boundary },
      { directory, profile, boundary: { ...boundary } },
    ])
      assert.throws(
        () => ensureProductionArtifactInventory(input),
        /invalid production artifact inventory/,
      );
    assert.throws(
      () => ensurePrototypeArtifactInventory({ directory, registry }),
      /invalid prototype artifact inventory/,
    );
  }));
test("copied receipts, private path guesses and foreign writers never enroll removal authority", () =>
  fixture(({ directory, registry, profile, boundary }) => {
    const inventory = ensureProductionArtifactInventory({ directory, profile, boundary }),
      writer = createProductionArtifactWriter({ directory, profile, boundary });
    const receipt = writer.write({
      recording: 1,
      operationId: "r1/control/" + "a".repeat(64),
      kind: "journal",
      value: { type: "receipt", recording: 1, sequence: 1 },
    });
    const before = readFileSync(join(directory, receipt.file));
    assert.throws(
      () => trackProductionArtifactFile(inventory, writer, { ...receipt }),
      /invalid production artifact receipt/,
    );
    assert.throws(
      () => trackProductionArtifactFile(inventory, { ...writer }, receipt),
      /invalid production artifact receipt/,
    );
    assert.throws(
      () => trackProductionArtifactFile(inventory, writer, receipt),
      /unreserved production artifact receipt/,
    );
    assert.throws(
      () => reserveProductionArtifactFile(inventory, writer),
      /invalid production artifact reservation/,
    );
    let hooks = 0;
    const proxy = new Proxy(receipt, {
      get() {
        hooks++;
        throw new Error("hook");
      },
      ownKeys() {
        hooks++;
        throw new Error("hook");
      },
    });
    assert.throws(
      () => trackProductionArtifactFile(inventory, writer, proxy),
      /invalid production artifact receipt/,
    );
    assert.equal(hooks, 0);
    assert.deepEqual(readFileSync(join(directory, receipt.file)), before);
    assert.equal(registry.snapshot().closed, false);
  }));
test("inventory constructor rejects getters, proxies and injected callbacks without invoking them", () =>
  fixture(({ directory, profile, boundary }) => {
    let hooks = 0;
    const supplied = { directory, profile, boundary };
    Object.defineProperty(supplied, "observer", {
      enumerable: true,
      get() {
        hooks++;
        throw new Error("hook");
      },
    });
    assert.throws(
      () => ensureProductionArtifactInventory(supplied),
      /invalid production artifact inventory/,
    );
    const proxy = new Proxy(
      { directory, profile, boundary },
      {
        getPrototypeOf() {
          hooks++;
          throw new Error("hook");
        },
        ownKeys() {
          hooks++;
          throw new Error("hook");
        },
      },
    );
    assert.throws(
      () => ensureProductionArtifactInventory(proxy),
      /invalid production artifact inventory/,
    );
    assert.equal(hooks, 0);
  }));
test("the bounded original batch retains exact memberships and rejects untrusted arrays without hooks", () => {
  const registry = createProductionSecretRegistry(limits);
  try {
    registerProductionSecretBatch(registry, ["fixture-known", "fixture-known", "other-fixture"]);
    assert.equal(registry.snapshot().values, 2);
    assert.equal(registry.openScan(500).hasSecretCopy("fixture-known"), true);
    for (const maximum of [0, -1, limits.maxScanCodeUnits + 1, {}, NaN])
      assert.throws(() => registry.openScan(maximum), /SECRET_REGISTRY_UNAVAILABLE/);
    let hooks = 0;
    const values = ["fixture"];
    Object.defineProperty(values, "0", {
      enumerable: true,
      get() {
        hooks++;
        throw new Error("hook");
      },
    });
    assert.throws(
      () => registerProductionSecretBatch(registry, values),
      /SECRET_REGISTRY_UNAVAILABLE/,
    );
    assert.equal(hooks, 0);
    assert.equal(registry.snapshot().failed, true);
  } finally {
    registry.close();
  }
});
test("duplicate-only batches preserve an original durable file and never reset its task identity", () =>
  fixture(({ directory, registry, profile, boundary }) => {
    registry.register("fixture-known-private-value");
    const inventory = ensureProductionArtifactInventory({ directory, profile, boundary }),
      writer = createProductionArtifactWriter({ directory, profile, boundary });
    const receipt = writer.write({
      recording: 1,
      operationId: "r1/control/" + "a".repeat(64),
      kind: "journal",
      value: { type: "receipt", recording: 1, sequence: 1 },
    });
    const before = readFileSync(join(directory, receipt.file));
    registerProductionSecretBatch(registry, [
      "fixture-known-private-value",
      "fixture-known-private-value",
    ]);
    assert.deepEqual(readFileSync(join(directory, receipt.file)), before);
    assert.equal(createHash("sha256").update(before).digest("hex"), receipt.sha256);
    assert.equal(ensureProductionArtifactInventory({ directory, profile, boundary }), inventory);
  }));
test("an original prototype writer cannot replace the owned task inventory", () =>
  fixture(({ directory, registry, profile, boundary }) => {
    ensureProductionArtifactInventory({ directory, profile, boundary });
    assert.throws(
      () =>
        createPrototypeWireFileWriter({
          directory,
          registry,
          operationId: "prototype",
          sequence: 1,
        }),
      /invalid prototype artifact inventory/,
    );
  }));
