import assert from "node:assert/strict";
import test from "node:test";
import { buildCorpus } from "./storage-object/corpus.mjs";
import { buildAuthCorpus } from "./storage-object/auth-corpus.mjs";
import { replayLocalBasic } from "./storage-object/basic-replay.mjs";
import {
  buildProductionStage3DraftPlan,
  buildStage3DraftPlan,
} from "./storage-object/stage3-plan.mjs";
import { createStage3RequestCounter } from "./storage-object/request-counter.mjs";
import { resolveProductionStorageRoute } from "./storage-object/production-routes.mjs";
import { validateProductionCredentialDeclaration } from "./storage-object/production-credentials.mjs";

const module = await import("./storage-object/sender.mjs");
const plan = buildProductionStage3DraftPlan({
  projectId: "example-project",
  bucket: "example.appspot.com",
  runIds: ["recordone", "recordtwo"],
});
const recipes = buildCorpus({ bucket: plan.bucket, prefix: plan.recordings[0].prefix }).recipes;
const recipeIds = [
  ...recipes.map((recipe) => recipe.id),
  ...buildAuthCorpus({
    projectId: plan.projectId,
    bucket: plan.bucket,
    runId: "recordone",
  }).recipes.map((recipe) => recipe.id),
];

async function fixture(action, changes = {}) {
  assert.equal(
    typeof module.createProductionStorageSender,
    "function",
    "production sender is missing",
  );
  assert.equal(typeof module.verifyProductionRecipeTerminal, "function");
  const objects = new Map(),
    calls = [],
    reservations = [],
    journals = [],
    senders = new Map();
  let admitted = true,
    generation = 1n;
  const counter = createStage3RequestCounter(plan, {
    onStart: async () => {},
    onReserve: async (row) => {
      reservations.push(row);
    },
    recipeLifecycle: {
      recipeIds,
      onBegin: async () => {},
      onFinish: async () => {},
      verifyTerminal: (proof) =>
        module.verifyProductionRecipeTerminal(senders.get(proof.recipeToken), proof),
    },
  });
  await counter.start();
  const recipe = recipes[0],
    recipeToken = await counter.beginRecipe(recipe.id);
  const wire = Object.freeze({
    fetchStorage: async (recording, step, init) => {
      assert.equal(recording, counter.snapshot().recording);
      const boundary = { bucket: plan.bucket, prefix: plan.recordings[recording - 1].prefix },
        route = resolveProductionStorageRoute(step, boundary),
        declaration = validateProductionCredentialDeclaration(step);
      assert.equal(init.headers.authorization, undefined);
      assert.equal(init.headers.Authorization, undefined);
      assert.equal(init.accountingPhase, counter.snapshot().mode);
      calls.push({ recording, step, init, declaration });
      const url = new URL(route.url);
      if (step.collection) {
        return Response.json({
          kind: "storage#objects",
          items: [...objects.values()]
            .map((row) => row.metadata)
            .filter((row) => row.name.startsWith(step.query.prefix)),
        });
      }
      const name = step.objectName;
      if (step.method === "POST") {
        assert.ok(journals.some((row) => row.name === name && row.method === "POST"));
        const bytes = Buffer.from(init.body),
          metadata = {
            kind: "storage#object",
            bucket: plan.bucket,
            name,
            generation: `${generation++}`,
            metageneration: "1",
            size: `${bytes.length}`,
          };
        objects.set(name, { metadata, bytes });
        return Response.json(metadata);
      }
      const object = objects.get(name);
      if (!object) return Response.json({ error: { code: 404 } }, { status: 404 });
      if (step.method === "DELETE") {
        assert.equal(step.query.ifGenerationMatch, object.metadata.generation);
        objects.delete(name);
        return new Response(null, { status: 204 });
      }
      return url.searchParams.get("alt") === "media"
        ? new Response(object.bytes)
        : Response.json(object.metadata);
    },
  });
  const config = {
    plan,
    recipeToken,
    wire,
    verifyAdmission: (context) =>
      admitted &&
      context.recording === counter.snapshot().recording &&
      context.phase === counter.snapshot().mode,
    onJournal: async (row) => {
      if (changes.onJournal) await changes.onJournal(row);
      journals.push(row);
    },
  };
  const sender = changes.construct === false ? null : module.createProductionStorageSender(config);
  if (sender) senders.set(recipeToken, sender);
  await action({
    sender,
    config,
    recipe,
    recipeToken,
    counter,
    objects,
    calls,
    reservations,
    journals,
    senders,
    revoke: () => {
      admitted = false;
    },
  });
}

test("production sender reuses basic ownership and the actual finite recipe counter", async () => {
  await fixture(async (f) => {
    const result = await replayLocalBasic({
      sender: f.sender,
      recipe: f.recipe,
      bucket: plan.bucket,
    });
    assert.equal(result.status, "LOCAL_COMPLETE");
    assert.equal(f.objects.size, 0);
    assert.equal(f.counter.snapshot().total, f.calls.length);
    assert.ok(f.calls.length > 5);
    for (let index = 0; index < f.calls.length; index++) {
      assert.equal(f.calls[index].init.operationId, f.reservations[index].operationId);
      assert.equal(f.calls[index].init.accountingPhase, f.reservations[index].phase);
      assert.equal(f.calls[index].declaration.credential, "admin");
      assert.match(f.calls[index].init.operationId, /^r1\/p1\/[a-f0-9]{64}$/);
    }
    await f.counter.finishRecipe(f.recipeToken);
    assert.equal(f.counter.snapshot().completedRecipes[0], 1);
    assert.equal(
      module.verifyProductionRecipeTerminal({ ...f.sender }, { recipeToken: f.recipeToken }),
      false,
    );
  });
});

test("production construction rejects arbitrary origins, fetch providers, credentials and missing capability", async () => {
  for (const change of [
    { origin: "https://storage.googleapis.com" },
    { fetchImpl: async () => Response.json({}) },
    { credentials: { admin: "Bearer SYNTHETIC_OWNER" } },
    { recipeToken: undefined },
    { plan: { ...plan, maxRequests: 6600 } },
  ])
    await fixture(
      async (f) => {
        assert.throws(
          () => module.createProductionStorageSender({ ...f.config, ...change }),
          /invalid production sender/,
        );
        assert.equal(f.calls.length, 0);
        assert.equal(f.reservations.length, 0);
        assert.equal(typeof module.createProductionStorageSender(f.config).sendStep, "function");
      },
      { construct: false },
    );
});

test("production declarations require explicit credentials and never inherit owner authorization", async () => {
  await fixture(async (f) => {
    await f.sender.start();
    await f.sender.admitNamespace();
    const name = f.recipe.objects[0],
      step = {
        id: "anonymous-read",
        dialect: "firebase",
        method: "GET",
        objectName: name,
        path: `/v0/b/${plan.bucket}/o/${encodeURIComponent(name)}`,
        query: { alt: "media" },
        credential: "none",
      };
    for (const candidate of [
      { ...step, credential: undefined },
      { ...step, credential: "admin", credentialRef: { kind: "anonymous" } },
      { ...step, headers: { Authorization: "Bearer SYNTHETIC_OWNER" } },
    ])
      await assert.rejects(f.sender.sendStep(candidate), /credential|production/);
    assert.equal(f.calls.length, 1);
    assert.equal(f.reservations.length, 1);
    assert.equal((await f.sender.sendStep(step)).status, 404);
    assert.equal(f.calls.at(-1).declaration.credential, "none");
  });
});

test("production input descriptors and nested Proxy values cannot execute hooks", async () => {
  let hooks = 0;
  await fixture(
    async (f) => {
      const config = new Proxy(f.config, {
        getPrototypeOf() {
          hooks++;
          return Object.prototype;
        },
      });
      assert.throws(
        () => module.createProductionStorageSender(config),
        /invalid production sender/,
      );
      assert.equal(hooks, 0);
      assert.equal(typeof module.createProductionStorageSender(f.config).sendStep, "function");
      assert.equal(f.calls.length, 0);
    },
    { construct: false },
  );
  await fixture(async (f) => {
    const config = { ...f.config };
    Object.defineProperty(config, "wire", {
      enumerable: true,
      get: () => {
        hooks++;
        return f.config.wire;
      },
    });
    assert.throws(() => module.createProductionStorageSender(config), /invalid production sender/);
    await f.sender.start();
    await f.sender.admitNamespace();
    const step = {
      ...f.recipe.preflight[0],
      query: new Proxy(
        {},
        {
          getPrototypeOf: () => {
            hooks++;
            return Object.prototype;
          },
        },
      ),
    };
    await assert.rejects(f.sender.sendStep(step), /production/);
    assert.equal(hooks, 0);
    assert.equal(f.calls.length, 1);
    assert.equal(f.reservations.length, 1);
  });
});

test("fresh production admission fails before reservation and stops after the mutation journal await", async () => {
  await fixture(async (f) => {
    await f.sender.start();
    f.revoke();
    await assert.rejects(f.sender.admitNamespace(), /production/);
    assert.equal(f.calls.length, 0);
    assert.equal(f.reservations.length, 0);
  });
  let current;
  await fixture(
    async (f) => {
      current = f;
      await f.sender.start();
      await f.sender.admitNamespace();
      f.sender.admitObject(f.recipe.objects[0]);
      await assert.rejects(f.sender.sendStep(f.recipe.steps[0]), /production/);
      assert.equal(f.calls.length, 1);
      assert.equal(f.reservations.length, 2);
      assert.equal(f.sender.unresolved().length, 1);
      await assert.rejects(f.sender.sendStep(f.recipe.preflight[0]), /production/);
      assert.equal(f.reservations.length, 2);
    },
    {
      onJournal: async (row) => {
        if (row.method === "POST") current.revoke();
      },
    },
  );
});

test("failed durable terminal proof cannot close or complete a production recipe", async () => {
  let failures = 0;
  await fixture(
    async (f) => {
      await f.sender.start();
      await f.sender.admitNamespace();
      f.sender.beginCleanup();
      await assert.rejects(f.sender.verifyRunEmpty(), /SYNTHETIC_FSYNC_FAILURE|production/);
      const total = f.counter.snapshot().total;
      await assert.rejects(f.sender.verifyRunEmpty(), /production/);
      await assert.rejects(f.sender.sendStep(f.recipe.preflight[0]), /production/);
      assert.equal(f.counter.snapshot().total, total);
      assert.equal(f.reservations.length, 2);
      assert.throws(() => f.sender.close(), /terminal proof/);
      await assert.rejects(f.counter.finishRecipe(f.recipeToken), /terminal/);
      assert.equal(f.counter.snapshot().completedRecipes[0], 0);
      assert.equal(f.calls.length, 2);
    },
    {
      onJournal: async (row) => {
        if (row.type === "recipe-terminal" && failures++ === 0)
          throw new Error("SYNTHETIC_FSYNC_FAILURE");
      },
    },
  );
});

test("admission revoked during terminal persistence cannot publish a durable terminal proof", async () => {
  let current;
  await fixture(
    async (f) => {
      current = f;
      await f.sender.start();
      await f.sender.admitNamespace();
      f.sender.beginCleanup();
      await assert.rejects(f.sender.verifyRunEmpty(), /production/);
      assert.throws(() => f.sender.close(), /terminal proof/);
      await assert.rejects(f.counter.finishRecipe(f.recipeToken), /terminal/);
      await assert.rejects(f.sender.verifyRunEmpty(), /production/);
      assert.equal(f.counter.snapshot().total, 2);
      assert.equal(f.calls.length, 2);
      assert.equal(f.counter.snapshot().completedRecipes[0], 0);
    },
    {
      onJournal: async (row) => {
        if (row.type === "recipe-terminal") current.revoke();
      },
    },
  );
});

test("a valid local sender terminal identity cannot be adopted as production evidence", async () => {
  assert.equal(typeof module.verifyProductionRecipeTerminal, "function");
  const localPlan = buildStage3DraftPlan({
    projectId: plan.projectId,
    bucket: plan.bucket,
    runIds: plan.recordings.map((row) => row.runId),
  });
  const counter = createStage3RequestCounter(localPlan, {
    onStart: async () => {},
    onReserve: async () => {},
    recipeLifecycle: {
      recipeIds,
      onBegin: async () => {},
      onFinish: async () => {},
      verifyTerminal: async () => true,
    },
  });
  await counter.start();
  const recipeToken = await counter.beginRecipe(recipeIds[0]);
  const sender = module.createLocalStorageSender({
    plan: localPlan,
    recipeToken,
    origin: "http://127.0.0.1:9199",
    credentials: { admin: "Bearer SYNTHETIC_OWNER" },
    onJournal: async () => {},
    fetchImpl: async () => Response.json({ kind: "storage#objects", items: [] }),
  });
  await sender.start();
  await sender.admitNamespace();
  sender.beginCleanup();
  await sender.verifyRunEmpty();
  sender.close();
  const proof = {
    recipeToken,
    recording: 1,
    recipeId: recipeIds[0],
    prefix: localPlan.recordings[0].prefix,
    sequence: 2,
  };
  assert.equal(module.verifyLocalRecipeTerminal(sender, proof), true);
  assert.equal(module.verifyProductionRecipeTerminal(sender, proof), false);
});
