import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { buildCorpus } from "./storage-object/corpus.mjs";
import { buildAuthCorpus } from "./storage-object/auth-corpus.mjs";
import * as authModule from "./storage-object/production-auth.mjs";
import { createProductionRulesState } from "./storage-object/production-rules.mjs";
import {
  buildProductionControlInventory,
  createProductionControlDispatcher,
} from "./storage-object/production-controls.mjs";
import { buildProductionStage3DraftPlan } from "./storage-object/stage3-plan.mjs";
import { createStage3RequestCounter } from "./storage-object/request-counter.mjs";
import {
  createProductionStorageSender,
  verifyProductionRecipeTerminal,
} from "./storage-object/sender.mjs";

const module = await import("./storage-object/production-auth-replay.mjs").catch((error) => {
  if (error.code !== "ERR_MODULE_NOT_FOUND") throw error;
  return {};
});
const hash = (value) => createHash("sha256").update(value).digest("hex");
function response(body, { status = 200 } = {}) {
  const bytes = Buffer.from(body ?? "");
  return Object.freeze({
    status,
    headers: new Headers(),
    arrayBuffer: async () => Buffer.from(bytes),
  });
}
const json = (value, options) => response(Buffer.from(JSON.stringify(value)), options);
const plan = buildProductionStage3DraftPlan({
  projectId: "example-project",
  bucket: "example.appspot.com",
  runIds: ["recordone", "recordtwo"],
});
const recipes = buildAuthCorpus({
  projectId: plan.projectId,
  bucket: plan.bucket,
  runId: "recordone",
}).recipes;
const ids = [
  ...buildCorpus({ bucket: plan.bucket, prefix: plan.recordings[0].prefix }).recipes.map(
    (r) => r.id,
  ),
  ...recipes.map((r) => r.id),
];
const source =
  "rules_version = '2';\nservice firebase.storage {\n  match /b/{bucket}/o {\n    match /storage-object/{run}/{allPaths=**} {\n      allow read, write: if request.auth != null && request.auth.token.email == 'storage-object@example.com';\n    }\n  }\n}\n";
const release = {
  name: `projects/${plan.projectId}/releases/firebase.storage/${plan.bucket}`,
  rulesetName: `projects/${plan.projectId}/rulesets/fixture-ruleset`,
  createTime: "2026-09-25T00:00:00Z",
  updateTime: "2026-09-25T00:00:00Z",
};
const ruleset = {
  name: release.rulesetName,
  createTime: release.createTime,
  source: { files: [{ name: "storage.rules", content: source }] },
  metadata: { services: ["firebase.storage"] },
};
const key = "SYNTHETIC_AUTH_REPLAY_KEY",
  projectNumber = "123456789012";
function tokenFor(account) {
  const now = Math.floor(Date.now() / 1000);
  return [
    { alg: "RS256", kid: "synthetic-key" },
    {
      sub: account.uid,
      user_id: account.uid,
      email: account.email,
      aud: plan.projectId,
      iss: `https://securetoken.google.com/${plan.projectId}`,
      iat: now,
      exp: now + 3600,
      firebase: { sign_in_provider: "password" },
      revision: account.revision,
    },
  ]
    .map((v) => Buffer.from(JSON.stringify(v)).toString("base64url"))
    .concat(Buffer.from("synthetic-signature").toString("base64url"))
    .join(".");
}

async function fixture(action, changes = {}) {
  assert.equal(typeof module.replayProductionAuth, "function", "production Auth replay is missing");
  assert.equal(
    typeof authModule.verifyProductionAuthRecipeTerminal,
    "function",
    "private Auth terminal verification is missing",
  );
  const objects = new Map(),
    accounts = new Map(),
    calls = [],
    reservations = [],
    captures = [],
    journals = [],
    proofs = [],
    secrets = [key],
    results = [];
  for (const [index, recipe] of recipes.entries())
    for (const kind of ["valid", "competitor"])
      accounts.set(
        `auth${index + 1}-${kind}`,
        Object.assign({}, recipe.accounts[kind], {
          kind,
          uid: `synthetic-${index + 1}-${kind}`,
          present: false,
          revision: 1,
        }),
      );
  let auth,
    rules,
    current = null,
    generation = 0;
  const counter = createStage3RequestCounter(plan, {
    onStart: async () => {},
    onReserve: async (row) => {
      reservations.push(row);
    },
    recipeLifecycle: {
      recipeIds: ids,
      onBegin: async () => {},
      onFinish: async () => {},
      verifyTerminal: (proof) =>
        current === null ||
        (current.result?.status === "PRODUCTION_REPLAY_COMPLETE" &&
          current.result.requests === counter.snapshot().total &&
          verifyProductionRecipeTerminal(current.sender, proof) &&
          authModule.verifyProductionAuthRecipeTerminal(auth, {
            recipeId: proof.recipeId,
            recipeToken: proof.recipeToken,
          })),
    },
  });
  const admission = (row) => row.recording === 1 && row.phase === counter.snapshot().mode;
  const slots = new Map(
    buildProductionControlInventory(plan).map((slot) => [
      `r${slot.recording}/control/${hash(slot.id)}`,
      slot,
    ]),
  );
  const metadata = (name) => ({
    bucket: plan.bucket,
    name,
    generation: objects.get(name).generation,
    metageneration: "1",
    size: String(objects.get(name).bytes.length),
  });
  const missing = () =>
    json({ error: { code: 404, status: "NOT_FOUND", message: "Not Found" } }, { status: 404 });
  const wire = Object.freeze({
    async fetchStorage(recording, step, init) {
      assert.equal(recording, 1);
      calls.push({
        kind: "storage",
        step,
        phase: init.accountingPhase,
        operationId: init.operationId,
      });
      if (step.credentialRef) {
        const authorization =
          step.credentialRef.kind === "anonymous"
            ? null
            : auth.accountAuthorization(step.credentialRef, {
                recording,
                kind: "storage",
                phase: init.accountingPhase,
                operationId: init.operationId,
              });
        const account = [...accounts.values()].find((a) => `Firebase ${a.token}` === authorization);
        if (!account || account.kind !== "valid")
          return json({ error: { code: 403, message: "Forbidden" } }, { status: 403 });
        if (changes.failSubject)
          return json({ error: { code: 500, message: "Synthetic failure" } }, { status: 500 });
      }
      if (step.collection)
        return json({
          kind: "storage#objects",
          items: [...objects.keys()]
            .filter((name) => name.startsWith(step.query.prefix))
            .map(metadata),
        });
      const name = step.objectName;
      if (step.method === "POST") {
        assert.equal(objects.has(name), false);
        objects.set(name, {
          generation: String(++generation),
          bytes: Buffer.from(init.body ?? ""),
        });
        return json(metadata(name));
      }
      if (step.method === "DELETE") {
        assert.equal(step.query.ifGenerationMatch, objects.get(name)?.generation);
        objects.delete(name);
        return response(null, { status: 204 });
      }
      assert.equal(step.method, "GET");
      if (!objects.has(name)) return missing();
      return step.query.alt === "media" ? response(objects.get(name).bytes) : json(metadata(name));
    },
    async fetchControl(recording, kind, parameters, init) {
      const slot = slots.get(init.operationId);
      assert.equal(recording, 1);
      assert.equal(slot.kind, kind);
      assert.equal(slot.phase, init.accountingPhase);
      calls.push({ kind, slotId: slot.id, phase: init.accountingPhase });
      if (kind === "rules-release") return json(release);
      if (kind === "rules-ruleset") return json(ruleset);
      if (kind === "rules-bucketless") return missing();
      const match = /^r1\/(auth[12]-(?:valid|competitor))-(setup|refresh|cleanup)-(.+)$/.exec(
        slot.id,
      );
      assert.ok(match);
      const account = accounts.get(match[1]),
        stage = match[2],
        suffix = match[3];
      let data;
      if (suffix === "signup") {
        const body = JSON.parse(init.body.toString());
        assert.equal(body.email, account.email);
        assert.ok(secrets.includes(body.password));
        assert.equal(parameters.apiKey, key);
        account.present = true;
        account.token = tokenFor(account);
        account.refreshToken = `SYNTHETIC_REFRESH_${account.uid}_1`;
        data = {
          localId: account.uid,
          email: account.email,
          idToken: account.token,
          refreshToken: account.refreshToken,
          expiresIn: "3600",
        };
      } else if (stage === "refresh" && suffix === "refresh") {
        assert.equal(
          new URLSearchParams(init.body.toString()).get("refresh_token"),
          account.refreshToken,
        );
        account.revision++;
        account.token = tokenFor(account);
        account.refreshToken = `SYNTHETIC_REFRESH_${account.uid}_2`;
        data = {
          user_id: account.uid,
          project_id: projectNumber,
          id_token: account.token,
          refresh_token: account.refreshToken,
          expires_in: "3600",
          token_type: "Bearer",
        };
      } else if (suffix === "delete") {
        const body = JSON.parse(init.body.toString());
        assert.equal(body.localId, account.uid);
        assert.equal(body.targetProjectId, plan.projectId);
        assert.ok(
          journals.some((r) => r.accountMutation === "delete" && r.accountRef === account.ref),
        );
        account.present = false;
        data = {};
      } else {
        const body = JSON.parse(init.body.toString());
        if (suffix === "client-lookup") assert.equal(body.idToken, account.token);
        else if (suffix === "email-absence") assert.deepEqual(body.email, [account.email]);
        else assert.deepEqual(body.localId, [account.uid]);
        data = account.present
          ? { users: [{ localId: account.uid, email: account.email, disabled: false }] }
          : {};
      }
      return json(data);
    },
  });
  const controls = createProductionControlDispatcher({
    plan,
    counter,
    wire,
    onProof: async (row) => {
      proofs.push(row);
    },
  });
  const onProof = async (row) => {
    if (
      changes.failAuthTerminal &&
      row.type === "production-auth-cleanup" &&
      row.accountRef.endsWith(":competitor")
    )
      throw new Error("SYNTHETIC_AUTH_TERMINAL_WRITE_FAILED");
    proofs.push(row);
  };
  auth = authModule.createProductionAuthState({
    plan,
    recording: 1,
    projectNumber,
    apiKey: key,
    controls,
    verifyAdmission: admission,
    onSecret: (v) => {
      secrets.push(v);
    },
    onJournal: async (row) => {
      journals.push(row);
    },
    onProof,
  });
  rules = createProductionRulesState({
    plan,
    recording: 1,
    baseline: { release, ruleset, ownedInStage2: true },
    controls,
    verifyAdmission: admission,
    verifySharedUse: () => true,
    onProof,
    onConfigChange: async () => {
      throw new Error("NO_RECORDING_ONE_RULES_MUTATION");
    },
  });
  try {
    await counter.start();
    await rules.checkpoint("initial");
    // The first 24 recipes are omitted setup, never full aggregate evidence.
    for (const id of ids.slice(0, 24)) {
      const token = await counter.beginRecipe(id);
      counter.beginCleanup(token);
      await counter.finishRecipe(token);
    }
    const run = async (index, beforeReplay) => {
      const recipe = recipes[index],
        recipeToken = await counter.beginRecipe(recipe.id);
      const sender = createProductionStorageSender({
        plan,
        recipeToken,
        wire,
        verifyAdmission: admission,
        onJournal: async (row) => {
          journals.push(row);
        },
      });
      current = { sender, recipeToken };
      const options = {
        sender,
        auth,
        rules,
        recipe,
        recipeToken,
        plan,
        recording: 1,
        onCapture: async (row) => {
          captures.push(row);
        },
      };
      if (beforeReplay) await beforeReplay(options);
      const result = await module.replayProductionAuth(options);
      current.result = result;
      results.push(result);
      return { result, sender, recipe, recipeToken };
    };
    await action({
      run,
      auth,
      rules,
      counter,
      objects,
      accounts,
      calls,
      reservations,
      captures,
      journals,
      proofs,
      secrets,
      results,
    });
  } finally {
    auth.close();
    rules.close();
  }
}

test("both production Auth recipes use finite controls and real sender terminal evidence", async () => {
  await fixture(async (f) => {
    for (const index of [0, 1]) {
      const r = await f.run(index);
      assert.equal(r.result.status, "PRODUCTION_REPLAY_COMPLETE");
      assert.equal(f.objects.size, 0);
      assert.ok([...f.accounts.values()].every((a) => !a.present));
      assert.equal(
        authModule.verifyProductionAuthRecipeTerminal(f.auth, {
          recipeId: r.recipe.id,
          recipeToken: r.recipeToken,
        }),
        true,
      );
      assert.equal(
        authModule.verifyProductionAuthRecipeTerminal(
          { ...f.auth },
          { recipeId: r.recipe.id, recipeToken: r.recipeToken },
        ),
        false,
      );
      assert.equal(
        authModule.verifyProductionAuthRecipeTerminal(f.auth, {
          recipeId: r.recipe.id,
          recipeToken: {},
        }),
        false,
      );
      await f.counter.finishRecipe(r.recipeToken);
    }
    await f.rules.checkpoint("final");
    assert.equal(f.calls.length, f.reservations.length);
    assert.equal(f.calls.filter((c) => c.slotId?.includes("/auth")).length, 44);
    assert.equal(f.calls.filter((c) => c.kind.startsWith("rules-")).length, 18);
    assert.equal(f.counter.snapshot().completedRecipes[0], 26);
    for (const secret of f.secrets)
      assert.equal(JSON.stringify(f.captures).includes(secret), false);
    assert.ok(
      f.captures.every(
        (c) =>
          c.bodyBase64 === undefined &&
          c.headers === undefined &&
          /^[a-f0-9]{64}$/.test(c.bodySha256),
      ),
    );
  });
});

test("an Auth subject failure closes known objects and accounts without starting the next program", async () => {
  await fixture(
    async (f) => {
      const r = await f.run(0);
      assert.equal(r.result.status, "PRODUCTION_REPLAY_BLOCKED");
      assert.equal(f.objects.size, 0);
      assert.ok([...f.accounts.values()].every((a) => !a.present));
      assert.ok(r.result.failure);
      assert.equal(r.result.cleanupFailures.length, 0);
      assert.equal(
        f.calls.some((c) => c.slotId?.includes("auth2-")),
        false,
      );
      const before = f.reservations.length;
      await assert.rejects(f.counter.finishRecipe(r.recipeToken));
      assert.equal(f.reservations.length, before);
    },
    { failSubject: true },
  );
});

test("an Auth terminal persistence failure cannot publish a private cleanup proof", async () => {
  await fixture(
    async (f) => {
      const r = await f.run(0);
      assert.equal(r.result.status, "PRODUCTION_REPLAY_NEEDS_RECOVERY");
      assert.equal(
        authModule.verifyProductionAuthRecipeTerminal(f.auth, {
          recipeId: r.recipe.id,
          recipeToken: r.recipeToken,
        }),
        false,
      );
      await assert.rejects(f.counter.finishRecipe(r.recipeToken));
      assert.ok(r.result.cleanupFailures.length > 0);
    },
    { failAuthTerminal: true },
  );
});

test("production Auth replay rejects cloned states and a foreign capability before any reservation", async () => {
  await fixture(async (f) => {
    const r = await f.run(0, async (options) => {
      const before = f.reservations.length,
        calls = f.calls.length;
      const controls = Object.freeze({
        send: async () => {
          throw new Error("UNUSED_FOREIGN_CONTROL");
        },
        snapshot: () => ({}),
      });
      const foreignPlan = buildProductionStage3DraftPlan({
        projectId: "foreign-project",
        bucket: "foreign.appspot.com",
        runIds: ["recordone", "recordtwo"],
      });
      const foreignStates = [2, foreignPlan].map((binding) => {
        const statePlan = typeof binding === "number" ? plan : binding,
          recording = typeof binding === "number" ? binding : 1;
        const auth = authModule.createProductionAuthState({
          plan: statePlan,
          recording,
          projectNumber,
          apiKey: key,
          controls,
          verifyAdmission: () => true,
          onSecret: () => {},
          onJournal: async () => {},
          onProof: async () => {},
        });
        const stateRelease = {
          ...release,
          name: `projects/${statePlan.projectId}/releases/firebase.storage/${statePlan.bucket}`,
          rulesetName: `projects/${statePlan.projectId}/rulesets/fixture-ruleset`,
        };
        const rules = createProductionRulesState({
          plan: statePlan,
          recording,
          baseline: {
            release: stateRelease,
            ruleset: { ...ruleset, name: stateRelease.rulesetName },
            ownedInStage2: true,
          },
          controls,
          verifyAdmission: () => true,
          verifySharedUse: () => true,
          onProof: async () => {},
          onConfigChange: async () => {},
        });
        return { auth, rules };
      });
      try {
        for (const change of [
          { sender: { ...options.sender } },
          { auth: { ...options.auth } },
          { rules: { ...options.rules } },
          { recipeToken: {} },
          { recording: 2 },
          ...foreignStates.flatMap(({ auth, rules }) => [{ auth }, { rules }]),
        ]) {
          await assert.rejects(
            module.replayProductionAuth({ ...options, ...change }),
            /invalid production Auth replay configuration/,
          );
          assert.equal(f.reservations.length, before);
          assert.equal(f.calls.length, calls);
        }
        let hooks = 0;
        const getter = Object.defineProperty({}, "sender", {
          enumerable: true,
          get() {
            hooks++;
            return options.sender;
          },
        });
        const proxy = Proxy.revocable({}, {});
        proxy.revoke();
        for (const input of [
          getter,
          proxy.proxy,
          {
            ...options,
            recipe: Object.defineProperty({}, "id", {
              enumerable: true,
              get() {
                hooks++;
                return options.recipe.id;
              },
            }),
          },
        ])
          await assert.rejects(
            module.replayProductionAuth(input),
            /invalid production Auth replay configuration/,
          );
        assert.equal(hooks, 0);
        assert.equal(f.reservations.length, before);
        assert.equal(f.calls.length, calls);
      } finally {
        for (const state of foreignStates) {
          state.auth.close();
          state.rules.close();
        }
      }
    });
    assert.equal(r.result.status, "PRODUCTION_REPLAY_COMPLETE");
    await f.counter.finishRecipe(r.recipeToken);
  });
});

test("Auth terminal proof rejects accessor and revoked-proxy evidence without invoking hooks", async () => {
  await fixture(async (f) => {
    const r = await f.run(0);
    assert.equal(r.result.status, "PRODUCTION_REPLAY_COMPLETE");
    let hooks = 0;
    const getter = { recipeToken: r.recipeToken };
    Object.defineProperty(getter, "recipeId", {
      enumerable: true,
      get() {
        hooks++;
        return r.recipe.id;
      },
    });
    const proxy = Proxy.revocable({}, {});
    proxy.revoke();
    for (const evidence of [
      getter,
      proxy.proxy,
      { recipeId: r.recipe.id, recipeToken: r.recipeToken, extra: true },
      {
        recipeId: {
          toString() {
            hooks++;
            return r.recipe.id;
          },
        },
        recipeToken: r.recipeToken,
      },
    ])
      assert.equal(authModule.verifyProductionAuthRecipeTerminal(f.auth, evidence), false);
    assert.equal(hooks, 0);
    await f.counter.finishRecipe(r.recipeToken);
    f.auth.close();
    assert.equal(
      authModule.verifyProductionAuthRecipeTerminal(f.auth, {
        recipeId: r.recipe.id,
        recipeToken: r.recipeToken,
      }),
      false,
    );
  });
});
