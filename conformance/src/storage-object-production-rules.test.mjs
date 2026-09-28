import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { FIXED_PRODUCTION_RULES_SHA256 } from "./storage-object/auth-plan.mjs";
import { buildProductionStage3DraftPlan } from "./storage-object/stage3-plan.mjs";
import { createStage3RequestCounter } from "./storage-object/request-counter.mjs";
import {
  buildProductionControlInventory,
  createProductionControlDispatcher,
} from "./storage-object/production-controls.mjs";

const module = await import("./storage-object/production-rules.mjs").catch((error) => {
  if (error.code !== "ERR_MODULE_NOT_FOUND") throw error;
  return {};
});
const source =
  "rules_version = '2';\nservice firebase.storage {\n  match /b/{bucket}/o {\n    match /storage-object/{run}/{allPaths=**} {\n      allow read, write: if request.auth != null && request.auth.token.email == 'storage-object@example.com';\n    }\n  }\n}\n";
const plan = buildProductionStage3DraftPlan({
  projectId: "example-project",
  bucket: "example.appspot.com",
  runIds: ["recordone", "recordtwo"],
});
const release = {
  name: `projects/${plan.projectId}/releases/firebase.storage/${plan.bucket}`,
  rulesetName: `projects/${plan.projectId}/rulesets/fixture-ruleset`,
  createTime: "2026-09-25T00:00:00Z",
  updateTime: "2026-09-25T00:00:00Z",
};
const ruleset = {
  name: release.rulesetName,
  createTime: "2026-09-25T00:00:00Z",
  source: { files: [{ name: "storage.rules", content: source }] },
  metadata: { services: ["firebase.storage"] },
};
const checkpoints = [
  "initial",
  "rules-before-1",
  "rules-after-1",
  "rules-before-2",
  "rules-after-2",
  "final",
];
async function fixture(action, changes = {}) {
  assert.equal(
    typeof module.createProductionRulesState,
    "function",
    "production Rules state is missing",
  );
  assert.equal(createHash("sha256").update(source).digest("hex"), FIXED_PRODUCTION_RULES_SHA256);
  const calls = [],
    proofs = [],
    config = [],
    sharedChecks = [];
  let releaseExists = true,
    rulesetExists = true,
    admitted = true;
  const memoryControls = Object.freeze({
    send: async (id, request) => {
      calls.push({ id, request });
      let status = 200,
        data;
      if (id === "r2/rules-delete-release") {
        assert.equal(config.at(-1)?.state, "release-delete-intent");
        releaseExists = false;
        data = {};
      } else if (id === "r2/rules-delete-ruleset") {
        assert.equal(config.at(-1)?.state, "ruleset-delete-intent");
        rulesetExists = false;
        data = {};
      } else if (id.includes("rules-delete-list-")) {
        const page = Number(id.at(-1)),
          pages = changes.pages ?? 1;
        if (page > 1) assert.equal(request.parameters.pageToken, `SYNTHETIC_PAGE_${page}`);
        const own = releaseExists && page === 1 ? [release] : [];
        data = {
          releases: own,
          ...(page < pages ? { nextPageToken: `SYNTHETIC_PAGE_${page + 1}` } : {}),
        };
      } else if (id.endsWith("rules-release") || id.endsWith("release-absence")) {
        if (releaseExists) data = release;
        else {
          status = 404;
          data = { error: { code: 404, status: "NOT_FOUND" } };
        }
      } else if (
        id.endsWith("rules-ruleset") ||
        id.endsWith("ruleset-recheck") ||
        id.endsWith("ruleset-absence")
      ) {
        if (rulesetExists) data = ruleset;
        else {
          status = 404;
          data = { error: { code: 404, status: "NOT_FOUND" } };
        }
      } else {
        assert.ok(id.endsWith("rules-bucketless") || id.endsWith("bucketless-absence"));
        status = 404;
        data = { error: { code: 404, status: "NOT_FOUND" } };
      }
      if (changes.response)
        ({ data, status } = changes.response({ id, data: structuredClone(data), status }));
      return { status, arrayBuffer: async () => Buffer.from(JSON.stringify(data)) };
    },
  });
  let controls = memoryControls,
    counter;
  const controlProofs = [],
    reservations = [];
  const recipeIds = [
    ...Array.from({ length: 24 }, (_, index) => `storage-object/fixture-${index}`),
    "storage-object/errors/authorization",
    "storage-object/auth/firebase-id-token",
  ];
  if (changes.actualControls) {
    counter = createStage3RequestCounter(plan, {
      onStart: async () => {},
      onReserve: async (row) => {
        reservations.push(row);
      },
      recipeLifecycle: {
        recipeIds,
        onBegin: async () => {},
        onFinish: async () => {},
        verifyTerminal: async () => true,
      },
    });
    await counter.start();
    // Empty prior-recipe lifecycle fixtures grant no aggregate completion claim.
    for (const id of recipeIds) {
      const capability = await counter.beginRecipe(id);
      counter.beginCleanup(capability);
      await counter.finishRecipe(capability);
    }
    await counter.startNextProductionRecording();
    const slots = new Map(
      buildProductionControlInventory(plan).map((slot) => [
        `r${slot.recording}/control/${createHash("sha256").update(slot.id).digest("hex")}`,
        slot,
      ]),
    );
    controls = createProductionControlDispatcher({
      plan,
      counter,
      wire: Object.freeze({
        fetchControl: async (recording, kind, parameters, init) => {
          const slot = slots.get(init.operationId);
          assert.equal(slot.recording, recording);
          assert.equal(slot.kind, kind);
          assert.equal(slot.phase, init.accountingPhase);
          return memoryControls.send(slot.id, { parameters, body: init.body });
        },
      }),
      onProof: async (row) => {
        controlProofs.push(row);
      },
    });
  }
  const state = module.createProductionRulesState({
    plan,
    recording: changes.recording ?? 2,
    baseline: { release, ruleset, ownedInStage2: true },
    controls,
    verifyAdmission: (context) =>
      admitted &&
      (!counter ||
        (counter.snapshot().recording === context.recording &&
          counter.snapshot().mode === context.phase)),
    verifySharedUse: (row) => {
      sharedChecks.push(row);
      return true;
    },
    onProof: async (row) => {
      proofs.push(row);
    },
    onConfigChange: async (row) => {
      config.push(row);
    },
    ...changes.options,
  });
  try {
    await action({
      state,
      calls,
      proofs,
      config,
      sharedChecks,
      counter,
      recipeIds,
      controlProofs,
      reservations,
      revoke() {
        admitted = false;
      },
    });
  } finally {
    state.close();
  }
}
async function readAll(state) {
  for (const checkpoint of checkpoints)
    await state.checkpoint(
      checkpoint,
      checkpoint.startsWith("rules-") ? Object.freeze({}) : undefined,
    );
}

test("six fixed Rules checkpoints bind release, immutable source and bucketless absence", async () => {
  await fixture(async (f) => {
    await assert.rejects(f.state.checkpoint("final"), /Rules checkpoint/);
    await readAll(f.state);
    assert.equal(f.calls.length, 18);
    assert.equal(f.proofs.length, 6);
    assert.equal(f.state.snapshot().completedCheckpoints, 6);
    await assert.rejects(f.state.checkpoint("final"), /Rules checkpoint/);
    assert.equal(f.calls.length, 18);
    assert.equal(f.config.length, 0);
    assert.equal(
      f.proofs.every((row) => row.sourceSha256 === FIXED_PRODUCTION_RULES_SHA256),
      true,
    );
    assert.equal(JSON.stringify(f.proofs).includes(source), false);
  });
});

test("second recording cleanup uses at most fifteen slots with fresh ownership and config intents", async () => {
  await fixture(
    async (f) => {
      await assert.rejects(f.state.cleanup(), /Rules cleanup/);
      await readAll(f.state);
      await f.state.cleanup();
      assert.equal(f.calls.length, 33);
      assert.equal(new Set(f.calls.map((row) => row.id)).size, 33);
      assert.equal(f.calls.filter((row) => row.id.includes("rules-delete-")).length, 15);
      assert.equal(f.sharedChecks.length >= 3, true);
      assert.deepEqual(
        f.config.map((row) => row.state),
        ["release-delete-intent", "release-absent", "ruleset-delete-intent", "ruleset-absent"],
      );
      assert.equal(f.state.snapshot().mutationState, "complete");
      assert.equal(f.state.snapshot().needsRecovery, false);
      await assert.rejects(f.state.cleanup(), /Rules cleanup/);
      assert.equal(f.calls.length, 33);
      assert.equal(JSON.stringify([...f.proofs, ...f.config]).includes("SYNTHETIC_PAGE"), false);
    },
    { pages: 3 },
  );
});

test("release/source/bucketless drift stops readback before any mutation and cannot be retried", async () => {
  for (const failure of [
    "release",
    "ruleset",
    "ruleset-time",
    "source",
    "bucketless",
    "bucketless-status",
  ]) {
    await fixture(
      async (f) => {
        await assert.rejects(f.state.checkpoint("initial"), /unavailable/);
        const before = f.calls.length;
        await assert.rejects(f.state.checkpoint("initial"), /unavailable/);
        await assert.rejects(f.state.cleanup(), /unavailable|Rules cleanup/);
        assert.equal(f.calls.length, before);
        assert.equal(f.config.length, 0);
        assert.equal(f.proofs.length, 0);
      },
      {
        response: ({ id, data, status }) => {
          if (failure === "release" && id.endsWith("rules-release"))
            data.updateTime = "2026-09-26T00:00:00Z";
          if (failure === "ruleset" && id.endsWith("rules-ruleset"))
            data.name = `projects/${plan.projectId}/rulesets/foreign`;
          if (failure === "ruleset-time" && id.endsWith("rules-ruleset"))
            data.createTime = "2026-09-26T00:00:00Z";
          if (failure === "source" && id.endsWith("rules-ruleset"))
            data.source.files[0].content = "allow read, write: if true;";
          if (failure === "bucketless" && id.endsWith("rules-bucketless")) {
            status = 200;
            data = release;
          }
          if (failure === "bucketless-status" && id.endsWith("rules-bucketless")) status = 503;
          return { data, status };
        },
      },
    );
  }
});

test("baseline requires the approved source and rejects descriptor and Proxy hooks before controls", async () => {
  let hooks = 0;
  const badSource = structuredClone(ruleset);
  badSource.source.files[0].content = "allow read, write: if true;";
  const accessor = { release, ownedInStage2: true };
  Object.defineProperty(accessor, "ruleset", {
    enumerable: true,
    get() {
      hooks++;
      return ruleset;
    },
  });
  const nested = {
    release,
    ruleset: new Proxy(ruleset, {
      getPrototypeOf() {
        hooks++;
        return Object.prototype;
      },
    }),
    ownedInStage2: true,
  };
  for (const baseline of [{ release, ruleset: badSource, ownedInStage2: true }, accessor, nested])
    await assert.rejects(
      fixture(() => assert.fail("invalid Rules baseline reached controls"), {
        options: { baseline },
      }),
      /^Error: invalid production Rules configuration$/,
    );
  assert.equal(hooks, 0);
});

test("first recording, unowned stage2 resources and shared-use refusal cannot delete Rules", async () => {
  for (const changes of [
    { recording: 1 },
    { options: { baseline: { release, ruleset, ownedInStage2: false } } },
    { options: { verifySharedUse: () => false } },
  ])
    await fixture(async (f) => {
      await readAll(f.state);
      await assert.rejects(f.state.cleanup(), /unavailable|Rules cleanup/);
      assert.equal(
        f.calls.some((row) => row.id.includes("rules-delete-")),
        false,
      );
      assert.equal(f.config.length, 0);
    }, changes);
});

test("incomplete listing, duplicate pages or another reference stop before release deletion", async () => {
  for (const failure of ["incomplete", "duplicate", "reference"]) {
    await fixture(
      async (f) => {
        await readAll(f.state);
        await assert.rejects(f.state.cleanup(), /unavailable/);
        assert.equal(
          f.calls.some((row) => row.id === "r2/rules-delete-release"),
          false,
        );
        assert.equal(f.config.length, 0);
      },
      {
        pages: 3,
        response: ({ id, data, status }) => {
          if (id.includes("rules-delete-list-before")) {
            if (failure === "incomplete" && id.endsWith("3"))
              data.nextPageToken = "SYNTHETIC_PAGE_4";
            if (failure === "duplicate") data.nextPageToken = "SYNTHETIC_PAGE_2";
            if (failure === "reference" && id.endsWith("1"))
              data.releases.push({
                ...release,
                name: `projects/${plan.projectId}/releases/another-release`,
              });
          }
          return { data, status };
        },
      },
    );
  }
});

test("post-delete uncertainty retains recovery state and never sends a second mutation", async () => {
  await fixture(
    async (f) => {
      await readAll(f.state);
      await assert.rejects(f.state.cleanup(), /unavailable/);
      assert.equal(f.calls.filter((row) => row.id === "r2/rules-delete-release").length, 1);
      assert.equal(
        f.calls.some((row) => row.id === "r2/rules-delete-ruleset"),
        false,
      );
      assert.equal(f.state.snapshot().needsRecovery, true);
      const before = f.calls.length;
      await assert.rejects(f.state.cleanup(), /unavailable|Rules cleanup/);
      assert.equal(f.calls.length, before);
    },
    {
      response: ({ id, data, status }) =>
        id.endsWith("release-absence") ? { data: release, status: 200 } : { data, status },
    },
  );
});

test("duplicate release names and an own release reappearing after deletion cannot reach another DELETE", async () => {
  for (const failure of ["duplicate-name", "reappeared"]) {
    await fixture(
      async (f) => {
        await readAll(f.state);
        await assert.rejects(f.state.cleanup(), /unavailable/);
        const releaseDeletes = f.calls.filter((row) => row.id === "r2/rules-delete-release");
        assert.equal(releaseDeletes.length, failure === "reappeared" ? 1 : 0);
        assert.equal(
          f.calls.some((row) => row.id === "r2/rules-delete-ruleset"),
          false,
        );
        assert.equal(
          f.proofs.some((row) => row.type === "production-rules-cleanup"),
          false,
        );
        assert.equal(f.state.snapshot().needsRecovery, failure === "reappeared");
        assert.deepEqual(
          f.config.map((row) => row.state),
          failure === "reappeared" ? ["release-delete-intent", "release-absent"] : [],
        );
        const before = f.calls.length;
        await assert.rejects(f.state.cleanup(), /unavailable/);
        assert.equal(f.calls.length, before);
      },
      {
        pages: 3,
        response: ({ id, data, status }) => {
          if (
            (failure === "duplicate-name" && id === "r2/rules-delete-list-before-2") ||
            (failure === "reappeared" && id === "r2/rules-delete-list-after-1")
          )
            data.releases = [structuredClone(release)];
          return { data, status };
        },
      },
    );
  }
});

test("missing admission and failed config fsync dispatch no mutation", async () => {
  await fixture(async (f) => {
    f.revoke();
    await assert.rejects(f.state.checkpoint("initial"), /unavailable/);
    assert.equal(f.calls.length, 0);
    assert.equal(f.proofs.length, 0);
  });
  await fixture(
    async (f) => {
      await readAll(f.state);
      await assert.rejects(f.state.cleanup(), /unavailable/);
      assert.equal(
        f.calls.some((row) => row.id === "r2/rules-delete-release"),
        false,
      );
    },
    {
      options: {
        onConfigChange: async () => {
          throw new Error("RAW_CONFIG_SECRET");
        },
      },
    },
  );
});

test("actual finite controls reserve all thirty-three Rules slots in their recording and phase", async () => {
  await fixture(
    async (f) => {
      await f.state.checkpoint("initial");
      for (const recipeId of f.recipeIds.slice(0, 24)) {
        const capability = await f.counter.beginRecipe(recipeId);
        f.counter.beginCleanup(capability);
        await f.counter.finishRecipe(capability);
      }
      for (const [index, recipeId] of f.recipeIds.slice(24).entries()) {
        const capability = await f.counter.beginRecipe(recipeId);
        await f.state.checkpoint(`rules-before-${index + 1}`, capability);
        f.counter.beginCleanup(capability);
        await f.state.checkpoint(`rules-after-${index + 1}`, capability);
        await f.counter.finishRecipe(capability);
      }
      await f.state.checkpoint("final");
      await f.state.cleanup();
      assert.equal(f.counter.snapshot().total, 33);
      assert.deepEqual(f.counter.snapshot().recordings[1], { subject: 9, cleanup: 24 });
      assert.equal(f.controlProofs.length, 33);
      assert.equal(f.reservations.length, 33);
      for (let index = 0; index < 33; index++) {
        assert.equal(f.controlProofs[index].sequence, index + 1);
        assert.equal(f.controlProofs[index].recording, 2);
        assert.equal(f.controlProofs[index].operationId, f.reservations[index].operationId);
        assert.equal(f.controlProofs[index].phase, f.reservations[index].phase);
        assert.equal(f.controlProofs[index].recipeId, f.reservations[index].recipeId);
      }
      assert.equal(f.state.snapshot().needsRecovery, false);
    },
    { actualControls: true, pages: 3 },
  );
});
