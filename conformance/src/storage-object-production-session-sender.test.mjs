import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { buildCorpus } from "./storage-object/corpus.mjs";
import { buildAuthCorpus } from "./storage-object/auth-corpus.mjs";
import { buildProductionStage3DraftPlan } from "./storage-object/stage3-plan.mjs";
import { createStage3RequestCounter } from "./storage-object/request-counter.mjs";
import { createProductionStorageSender } from "./storage-object/sender.mjs";

const digest = (value) => createHash("sha256").update(value).digest("hex");
const plan = buildProductionStage3DraftPlan({
  projectId: "example-project",
  bucket: "example.appspot.com",
  runIds: ["recordone", "recordtwo"],
});
const recipes = buildCorpus({ bucket: plan.bucket, prefix: plan.recordings[0].prefix }).recipes;
const ids = [
  ...recipes.map((row) => row.id),
  ...buildAuthCorpus({
    projectId: plan.projectId,
    bucket: plan.bucket,
    runId: "recordone",
  }).recipes.map((row) => row.id),
];

async function fixture(action, changes = {}) {
  const reservations = [],
    journals = [],
    bindings = [],
    requests = [];
  const recipe = recipes.find((row) => row.id === "storage-object/gcs/resumable-upload");
  const counter = createStage3RequestCounter(plan, {
    onStart: async () => {},
    onReserve: async (row) => {
      reservations.push(row);
    },
    recipeLifecycle: {
      recipeIds: ids,
      onBegin: async () => {},
      onFinish: async () => {},
      // Prior recipes are omitted setup, not aggregate evidence.
      verifyTerminal: () => true,
    },
  });
  await counter.start();
  for (const id of ids.slice(0, ids.indexOf(recipe.id))) {
    const token = await counter.beginRecipe(id);
    counter.beginCleanup(token);
    await counter.finishRecipe(token);
  }
  const recipeToken = await counter.beginRecipe(recipe.id);
  const uri = `https://storage.googleapis.com/upload/storage/v1/b/${plan.bucket}/o?upload_id=SYNTHETIC_PRIVATE_SESSION&uploadType=resumable`;
  const capability = Object.freeze({ sessionUriSha256: digest(uri) });
  let initiation;
  const wire = {
    async fetchStorage(recording, step, init) {
      requests.push({ recording, step, init });
      if (step.collection) return Response.json({ kind: "storage#objects", items: [] });
      if (step.id === "initiate") {
        initiation = new Response(null, { status: 200, headers: { location: uri } });
        return initiation;
      }
      return Response.json({ error: { code: 404, message: "Not Found" } }, { status: 404 });
    },
    bindSession(recording, response) {
      assert.equal(recording, 1);
      assert.equal(response, initiation);
      bindings.push(response);
      return changes.bindingReceipt ?? capability;
    },
    async fetchSession(recording, actual, step, init) {
      assert.equal(recording, 1);
      assert.equal(actual, capability);
      assert.deepEqual(step, recipe.steps[1]);
      assert.equal(init.operationId, `r1/p${ids.indexOf(recipe.id) + 1}/${digest(step.id)}`);
      assert.equal(
        Object.keys(init.headers).some((key) => key.toLowerCase() === "authorization"),
        false,
      );
      requests.push({ recording, step, init });
      if (changes.failContinuation) throw new Error(uri);
      return new Response(null, { status: 308, headers: { range: "bytes=0-262143" } });
    },
  };
  const sender = createProductionStorageSender({
    plan,
    recipeToken,
    wire,
    verifyAdmission: () => true,
    onJournal: async (row) => {
      journals.push(row);
    },
  });
  await sender.start();
  await sender.admitNamespace();
  sender.admitObject(recipe.objects[0]);
  const response = await sender.sendStep(recipe.steps[0]);
  await action({
    sender,
    recipe,
    response,
    uri,
    counter,
    reservations,
    journals,
    bindings,
    requests,
  });
}

test("the shared sender binds the original production response and dispatches its private session capability", async () => {
  await fixture(async (f) => {
    f.response.headers.location = "https://foreign.example/forged";
    const receipt = f.sender.bindSession({ recipe: f.recipe, initiateOperationId: "initiate" });
    assert.equal(receipt.sessionUriSha256, digest(f.uri));
    assert.equal(f.bindings.length, 1);
    const response = await f.sender.sendSessionStep({ recipe: f.recipe, stepIndex: 1 });
    assert.equal(response.status, 308);
    assert.equal(f.requests.length, 3);
    assert.equal(f.reservations.length, 3);
    assert.equal(f.journals.length, 2);
    assert.equal(f.journals[1].continuationOf, "initiate");
    assert.equal(f.journals[1].sessionUriSha256, digest(f.uri));
    assert.equal(JSON.stringify(f.journals).includes(f.uri), false);
  });
});

test("a production continuation failure is sanitized and permanently stops subsequent dispatch", async () => {
  await fixture(
    async (f) => {
      f.sender.bindSession({ recipe: f.recipe, initiateOperationId: "initiate" });
      await assert.rejects(
        f.sender.sendSessionStep({ recipe: f.recipe, stepIndex: 1 }),
        (error) => {
          assert.equal(error.message.includes(f.uri), false);
          assert.equal(error.cause, undefined);
          return true;
        },
      );
      const count = f.reservations.length;
      await assert.rejects(
        f.sender.sendSessionStep({ recipe: f.recipe, stepIndex: 1 }),
        /production|attempted|prerequisite/,
      );
      assert.equal(f.reservations.length, count);
      assert.deepEqual(f.sender.unresolved(), [f.recipe.objects[0]]);
    },
    { failContinuation: true },
  );
});

test("a session commitment cannot invoke string coercion hooks or publish an invalid binding", async () => {
  let hooks = 0;
  await fixture(
    async (f) => {
      assert.throws(
        () => f.sender.bindSession({ recipe: f.recipe, initiateOperationId: "initiate" }),
        /production/,
      );
      assert.equal(hooks, 0);
      const reservations = f.reservations.length;
      await assert.rejects(
        f.sender.sendStep({ ...f.recipe.steps[4], id: "post-binding-failure-probe" }),
        /production/,
      );
      assert.equal(f.reservations.length, reservations);
    },
    {
      bindingReceipt: Object.freeze({
        sessionUriSha256: {
          toString() {
            hooks++;
            return "a".repeat(64);
          },
        },
      }),
    },
  );
});

test("production session options reject getters, nested proxies and coercion before binding or dispatch", async () => {
  for (const method of ["bindSession", "sendSessionStep"])
    for (const kind of [
      "root-getter",
      "recipe-getter",
      "nested-proxy",
      "revoked-proxy",
      "coercion",
    ]) {
      await fixture(async (f) => {
        if (method === "sendSessionStep")
          f.sender.bindSession({ recipe: f.recipe, initiateOperationId: "initiate" });
        let hooks = 0;
        const options =
          method === "bindSession"
            ? { recipe: f.recipe, initiateOperationId: "initiate" }
            : { recipe: f.recipe, stepIndex: 1 };
        if (kind === "root-getter")
          Object.defineProperty(options, "recipe", {
            enumerable: true,
            get() {
              hooks++;
              return f.recipe;
            },
          });
        else if (kind === "recipe-getter") {
          options.recipe = { ...f.recipe };
          Object.defineProperty(options.recipe, "id", {
            enumerable: true,
            get() {
              hooks++;
              return f.recipe.id;
            },
          });
        } else if (kind === "nested-proxy")
          options.recipe = {
            ...f.recipe,
            steps: new Proxy(f.recipe.steps, {
              get() {
                hooks++;
                throw new Error("HOOK");
              },
            }),
          };
        else if (kind === "revoked-proxy") {
          const proxy = Proxy.revocable(f.recipe, {});
          proxy.revoke();
          options.recipe = proxy.proxy;
        } else {
          const name = method === "bindSession" ? "initiateOperationId" : "stepIndex";
          options[name] = {
            [Symbol.toPrimitive]() {
              hooks++;
              return method === "bindSession" ? "initiate" : 1;
            },
          };
        }
        const before = {
          bindings: f.bindings.length,
          requests: f.requests.length,
          reservations: f.reservations.length,
        };
        if (method === "bindSession") assert.throws(() => f.sender.bindSession(options));
        else await assert.rejects(f.sender.sendSessionStep(options));
        assert.equal(hooks, 0);
        assert.equal(f.bindings.length, before.bindings);
        assert.equal(f.requests.length, before.requests);
        assert.equal(f.reservations.length, before.reservations);
      });
    }
});
