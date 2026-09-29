import assert from "node:assert/strict";
import fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { buildProductionStage3DraftPlan } from "./storage-object/stage3-plan.mjs";
import { createProductionSecretRegistry } from "./storage-object/production-secret-registry.mjs";
import { createProductionArtifactProfile } from "./storage-object/production-artifact-policy.mjs";
import { createProductionStandaloneFailStop } from "./storage-object/production-standalone-fail-stop.mjs";
import * as providersApi from "./storage-object/production-provider-boundary.mjs";
import * as wireApi from "./storage-object/production-wire-transport.mjs";
import * as countersApi from "./storage-object/request-counter.mjs";
import * as controlsApi from "./storage-object/production-controls.mjs";
import * as ownersApi from "./storage-object/production-owner.mjs";
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
async function fixture(action) {
  const directory = fs.realpathSync(fs.mkdtempSync(join(tmpdir(), "fireemu-original-lineage-")));
  fs.chmodSync(directory, 0o700);
  const wires = [];
  let registry;
  try {
    registry = createProductionSecretRegistry({
      maxValues: 81,
      maxUtf8Bytes: 65536,
      maxIndexNodes: 200000,
      maxScanCodeUnits: 16777216,
    });
    const profile = createProductionArtifactProfile({ plan, resources, secretRegistry: registry });
    const boundary = createProductionStandaloneFailStop({ directory, profile });
    let callbacks = 0;
    const createProviders = () =>
      providersApi.createProductionCredentialProviders({ boundary, registry });
    const createWire = (credentialProviders) => {
      const wire = wireApi.createProductionWireTransport({
        plan,
        resources,
        captureDirectory: directory,
        artifactProfile: profile,
        standaloneBoundary: boundary,
        credentialProviders,
        secretRegistry: registry,
        onByteReserve: async () => {
          callbacks++;
        },
        verifyAdmission: () => {
          callbacks++;
          return true;
        },
      });
      wires.push(wire);
      return wire;
    };
    const createCounter = () =>
      countersApi.createStage3RequestCounter(plan, {
        artifactProfile: profile,
        onStart: async () => {
          callbacks++;
        },
        onReserve: async () => {
          callbacks++;
        },
      });
    const providers = createProviders(),
      wire = createWire(providers),
      counter = createCounter();
    const createControls = (selectedCounter, selectedWire, suppliedPlan = plan) =>
      controlsApi.createProductionControlDispatcher({
        plan: suppliedPlan,
        counter: selectedCounter,
        wire: selectedWire,
        onProof: async () => {
          callbacks++;
        },
      });
    const controls = createControls(counter, wire);
    const adcPath = join(directory, "absent-synthetic-adc.json");
    const createOwner = (recording, selectedControls) =>
      ownersApi.createProductionOwnerState({
        recording,
        controls: selectedControls,
        adcInput: {
          path: adcPath,
          expectedSha256: "a".repeat(64),
          expectedClientId: "synthetic-client",
          expectedQuotaProjectId: plan.projectId,
        },
        principal: {
          subject: "synthetic-owner",
          clientId: "synthetic-client",
          requiredScopes: ["https://www.googleapis.com/auth/cloud-platform"],
        },
        verifyAdmission: () => {
          callbacks++;
          return true;
        },
        onProof: async () => {
          callbacks++;
        },
        onSecret: () => {
          callbacks++;
        },
      });
    const owners = [createOwner(1, controls), createOwner(2, controls)];
    return await action({
      directory,
      adcPath,
      registry,
      profile,
      boundary,
      plan,
      providers,
      wire,
      counter,
      controls,
      owners,
      createProviders,
      createWire,
      createCounter,
      createControls,
      createOwner,
      callbacks: () => callbacks,
    });
  } finally {
    for (const wire of wires) await wire.close();
    registry?.close();
    fs.rmSync(directory, { recursive: true });
  }
}
const context = ({ profile, plan: selectedPlan, counter, wire }) => ({
  profile,
  plan: selectedPlan,
  counter,
  wire,
});
test("original owner bootstrap binds the same counter, wire, profile and controls without ADC or dispatch", () =>
  fixture((f) => {
    assert.equal(typeof controlsApi.productionControlDispatcherUsesArtifactContext, "function");
    assert.equal(
      countersApi.productionStage3CounterUsesArtifactContext(f.counter, {
        profile: f.profile,
        plan,
      }),
      true,
    );
    assert.equal(
      wireApi.productionWireUsesArtifactContext(f.wire, { profile: f.profile, plan }),
      true,
    );
    assert.equal(
      controlsApi.productionControlDispatcherUsesArtifactContext(f.controls, context(f)),
      true,
    );
    for (const recording of [1, 2]) {
      const owner = f.owners[recording - 1];
      assert.equal(
        ownersApi.productionOwnerUsesArtifactContext(owner, { ...context(f), recording }),
        false,
        "an unbound original owner is not linked to the wire",
      );
      f.providers.bindOwner(recording, owner);
      assert.equal(
        providersApi.productionCredentialProvidersUseOwner(f.providers, recording, owner),
        true,
      );
      assert.equal(
        wireApi.productionWireUsesOwner(f.wire, { profile: f.profile, plan, recording, owner }),
        true,
      );
      assert.equal(
        ownersApi.productionOwnerUsesArtifactContext(owner, { ...context(f), recording }),
        true,
      );
      assert.throws(
        () => f.providers.bindOwner(recording, owner),
        /invalid production credential binding/,
      );
    }
    assert.equal(f.callbacks(), 0);
    assert.equal(f.wire.snapshot().attempts, 0);
    assert.equal(fs.existsSync(f.adcPath), false);
  }));

test("original lineage rejects same-run foreign plans, clones and foreign original pairs", () =>
  fixture((f) => {
    f.providers.bindOwner(1, f.owners[0]);
    for (const foreignPlan of [
      buildProductionStage3DraftPlan({
        projectId: "foreign-project",
        bucket: plan.bucket,
        runIds: ["recordone", "recordtwo"],
      }),
      buildProductionStage3DraftPlan({
        projectId: plan.projectId,
        bucket: "foreign.appspot.com",
        runIds: ["recordone", "recordtwo"],
      }),
    ]) {
      assert.equal(
        countersApi.productionStage3CounterUsesArtifactContext(f.counter, {
          profile: f.profile,
          plan: foreignPlan,
        }),
        false,
      );
      assert.equal(
        wireApi.productionWireUsesArtifactContext(f.wire, {
          profile: f.profile,
          plan: foreignPlan,
        }),
        false,
      );
      assert.equal(
        controlsApi.productionControlDispatcherUsesArtifactContext(f.controls, {
          ...context(f),
          plan: foreignPlan,
        }),
        false,
      );
      assert.equal(
        ownersApi.productionOwnerUsesArtifactContext(f.owners[0], {
          ...context(f),
          plan: foreignPlan,
          recording: 1,
        }),
        false,
      );
      const foreignControls = f.createControls(f.counter, f.wire, foreignPlan);
      assert.equal(
        controlsApi.productionControlDispatcherUsesArtifactContext(foreignControls, context(f)),
        false,
      );
    }
    assert.equal(
      countersApi.productionStage3CounterUsesArtifactContext(
        { ...f.counter },
        { profile: f.profile, plan },
      ),
      false,
    );
    assert.equal(
      wireApi.productionWireUsesArtifactContext({ ...f.wire }, { profile: f.profile, plan }),
      false,
    );
    assert.equal(
      controlsApi.productionControlDispatcherUsesArtifactContext({ ...f.controls }, context(f)),
      false,
    );
    assert.equal(
      ownersApi.productionOwnerUsesArtifactContext(
        { ...f.owners[0] },
        { ...context(f), recording: 1 },
      ),
      false,
    );
    const otherCounter = f.createCounter(),
      otherWire = f.createWire(f.providers);
    assert.equal(
      controlsApi.productionControlDispatcherUsesArtifactContext(f.controls, {
        ...context(f),
        counter: otherCounter,
      }),
      false,
    );
    assert.equal(
      controlsApi.productionControlDispatcherUsesArtifactContext(f.controls, {
        ...context(f),
        wire: otherWire,
      }),
      false,
    );
    assert.equal(
      ownersApi.productionOwnerUsesArtifactContext(f.owners[1], { ...context(f), recording: 1 }),
      false,
    );
    const foreignOwner = f.createOwner(1, f.controls);
    assert.equal(
      wireApi.productionWireUsesOwner(f.wire, {
        profile: f.profile,
        plan,
        recording: 1,
        owner: foreignOwner,
      }),
      false,
    );
    assert.equal(
      ownersApi.productionOwnerUsesArtifactContext(foreignOwner, { ...context(f), recording: 1 }),
      false,
    );
    assert.equal(f.callbacks(), 0);
    assert.equal(f.wire.snapshot().attempts, 0);
  }));

test("shape-only controls cannot upgrade an original owner into an original wire lineage", () =>
  fixture((f) => {
    const shape = {
      send: async () => {
        throw new Error("must not dispatch");
      },
      snapshot: () => ({ attempted: 0, busy: false, failed: false }),
    };
    const owner = f.createOwner(1, shape);
    f.providers.bindOwner(1, owner);
    assert.equal(providersApi.productionCredentialProvidersUseOwner(f.providers, 1, owner), true);
    assert.equal(
      ownersApi.productionOwnerUsesArtifactContext(owner, { ...context(f), recording: 1 }),
      false,
    );
    assert.equal(
      controlsApi.productionControlDispatcherUsesArtifactContext(shape, context(f)),
      false,
    );
    assert.equal(f.callbacks(), 0);
  }));

test("lineage queries reject getters, proxies and modified original counter methods without hooks", () =>
  fixture((f) => {
    f.providers.bindOwner(1, f.owners[0]);
    let hooks = 0;
    for (const [query, cap, input] of [
      [
        countersApi.productionStage3CounterUsesArtifactContext,
        f.counter,
        { profile: f.profile, plan },
      ],
      [wireApi.productionWireUsesArtifactContext, f.wire, { profile: f.profile, plan }],
      [controlsApi.productionControlDispatcherUsesArtifactContext, f.controls, context(f)],
      [ownersApi.productionOwnerUsesArtifactContext, f.owners[0], { ...context(f), recording: 1 }],
    ]) {
      const hooked = { ...input };
      Object.defineProperty(hooked, "plan", {
        enumerable: true,
        get() {
          hooks++;
          return plan;
        },
      });
      assert.equal(query(cap, hooked), false);
      const nested = { ...plan };
      Object.defineProperty(nested, "projectId", {
        enumerable: true,
        get() {
          hooks++;
          return plan.projectId;
        },
      });
      assert.equal(query(cap, { ...input, plan: nested }), false);
      const proxy = new Proxy(input, {
        get() {
          hooks++;
          throw new Error("hook");
        },
      });
      assert.equal(query(cap, proxy), false);
      const revoked = Proxy.revocable(input, {});
      revoked.revoke();
      assert.equal(query(cap, revoked.proxy), false);
    }
    const original = Object.getOwnPropertyDescriptor(f.counter, "snapshot");
    Object.defineProperty(f.counter, "snapshot", {
      configurable: true,
      get() {
        hooks++;
        throw new Error("hook");
      },
    });
    try {
      assert.equal(
        countersApi.productionStage3CounterUsesArtifactContext(f.counter, {
          profile: f.profile,
          plan,
        }),
        false,
      );
      assert.equal(
        controlsApi.productionControlDispatcherUsesArtifactContext(f.controls, context(f)),
        false,
      );
      assert.equal(
        ownersApi.productionOwnerUsesArtifactContext(f.owners[0], { ...context(f), recording: 1 }),
        false,
      );
    } finally {
      Object.defineProperty(f.counter, "snapshot", original);
    }
    assert.equal(hooks, 0);
    assert.equal(f.callbacks(), 0);
  }));

test("closed original wire cannot supply an active controls or owner lineage", () =>
  fixture(async (f) => {
    f.providers.bindOwner(1, f.owners[0]);
    await f.wire.close();
    assert.equal(
      wireApi.productionWireUsesArtifactContext(f.wire, { profile: f.profile, plan }),
      false,
    );
    assert.equal(
      controlsApi.productionControlDispatcherUsesArtifactContext(f.controls, context(f)),
      false,
    );
    assert.equal(
      ownersApi.productionOwnerUsesArtifactContext(f.owners[0], { ...context(f), recording: 1 }),
      false,
    );
    assert.equal(f.callbacks(), 0);
  }));

test("original lineage rejects foreign profiles, extra fields and modified counter functions", () =>
  fixture((f) => {
    f.providers.bindOwner(1, f.owners[0]);
    const foreignProfile = createProductionArtifactProfile({
      plan,
      resources,
      secretRegistry: f.registry,
    });
    for (const selectedProfile of [foreignProfile, { ...f.profile }]) {
      assert.equal(
        countersApi.productionStage3CounterUsesArtifactContext(f.counter, {
          profile: selectedProfile,
          plan,
        }),
        false,
      );
      assert.equal(
        wireApi.productionWireUsesArtifactContext(f.wire, { profile: selectedProfile, plan }),
        false,
      );
      assert.equal(
        controlsApi.productionControlDispatcherUsesArtifactContext(f.controls, {
          ...context(f),
          profile: selectedProfile,
        }),
        false,
      );
      assert.equal(
        ownersApi.productionOwnerUsesArtifactContext(f.owners[0], {
          ...context(f),
          profile: selectedProfile,
          recording: 1,
        }),
        false,
      );
    }
    for (const [query, cap, input] of [
      [
        countersApi.productionStage3CounterUsesArtifactContext,
        f.counter,
        { profile: f.profile, plan },
      ],
      [wireApi.productionWireUsesArtifactContext, f.wire, { profile: f.profile, plan }],
      [controlsApi.productionControlDispatcherUsesArtifactContext, f.controls, context(f)],
      [ownersApi.productionOwnerUsesArtifactContext, f.owners[0], { ...context(f), recording: 1 }],
    ]) {
      assert.equal(query(cap, { ...input, ignored: true }), false);
      assert.equal(query(new Proxy(cap, {}), input), false);
    }
    const original = f.counter.snapshot;
    f.counter.snapshot = () => {
      throw new Error("must not read caller method");
    };
    try {
      assert.equal(
        countersApi.productionStage3CounterUsesArtifactContext(f.counter, {
          profile: f.profile,
          plan,
        }),
        false,
      );
      assert.equal(
        controlsApi.productionControlDispatcherUsesArtifactContext(f.controls, context(f)),
        false,
      );
      assert.equal(
        ownersApi.productionOwnerUsesArtifactContext(f.owners[0], { ...context(f), recording: 1 }),
        false,
      );
    } finally {
      f.counter.snapshot = original;
    }
    assert.equal(f.callbacks(), 0);
  }));

test("closed owners and provider boundaries cannot supply owner lineage", () =>
  fixture((f) => {
    f.providers.bindOwner(1, f.owners[0]);
    f.owners[0].close();
    assert.equal(
      ownersApi.productionOwnerUsesArtifactContext(f.owners[0], { ...context(f), recording: 1 }),
      false,
    );
    f.providers.close();
    assert.equal(
      providersApi.productionCredentialProvidersUseOwner(f.providers, 1, f.owners[0]),
      false,
    );
    assert.equal(
      wireApi.productionWireUsesOwner(f.wire, {
        profile: f.profile,
        plan,
        recording: 1,
        owner: f.owners[0],
      }),
      false,
    );
    assert.equal(f.callbacks(), 0);
  }));

test("failed original wire is rejected while its registry remains open and no request is sent", () =>
  fixture((f) => {
    f.providers.bindOwner(1, f.owners[0]);
    assert.equal(
      wireApi.productionWireUsesArtifactContext(f.wire, { profile: f.profile, plan }),
      true,
    );
    assert.throws(() => f.wire.bindSession(1, {}), /PRODUCTION_SESSION_BINDING_REJECTED/);
    assert.doesNotThrow(() => f.registry.openScan());
    assert.equal(
      wireApi.productionWireUsesArtifactContext(f.wire, { profile: f.profile, plan }),
      false,
    );
    assert.equal(
      controlsApi.productionControlDispatcherUsesArtifactContext(f.controls, context(f)),
      false,
    );
    assert.equal(
      ownersApi.productionOwnerUsesArtifactContext(f.owners[0], { ...context(f), recording: 1 }),
      false,
    );
    assert.equal(f.wire.snapshot().attempts, 0);
    assert.equal(f.callbacks(), 0);
  }));
