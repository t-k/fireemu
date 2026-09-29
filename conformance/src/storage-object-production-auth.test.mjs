import assert from "node:assert/strict";
import test from "node:test";
import { performance } from "node:perf_hooks";
import { createHash } from "node:crypto";
import { createStage3RequestCounter } from "./storage-object/request-counter.mjs";
import {
  buildProductionControlInventory,
  createProductionControlDispatcher,
} from "./storage-object/production-controls.mjs";
import { buildProductionStage3DraftPlan } from "./storage-object/stage3-plan.mjs";
import { buildAuthCorpus } from "./storage-object/auth-corpus.mjs";

const module = await import("./storage-object/production-auth.mjs").catch((error) => {
  if (error.code !== "ERR_MODULE_NOT_FOUND") throw error;
  return {};
});
const plan = buildProductionStage3DraftPlan({
  projectId: "example-project",
  bucket: "example.appspot.com",
  runIds: ["recordone", "recordtwo"],
});
const key = "SYNTHETIC_PRODUCTION_AUTH_KEY",
  projectNumber = "123456789012";
const recipes = buildAuthCorpus({
  projectId: plan.projectId,
  bucket: plan.bucket,
  runId: plan.recordings[0].runId,
}).recipes;
function tokenFor(account, changes = {}, revision = 1) {
  const seconds = Math.floor(Date.now() / 1000);
  return [
    Buffer.from(JSON.stringify({ alg: "RS256", kid: "synthetic-key" })).toString("base64url"),
    Buffer.from(
      JSON.stringify({
        sub: account.uid,
        user_id: account.uid,
        email: account.email,
        aud: plan.projectId,
        iss: `https://securetoken.google.com/${plan.projectId}`,
        iat: seconds,
        exp: seconds + 3600,
        auth_time: seconds,
        firebase: { sign_in_provider: "password" },
        ...changes,
      }),
    ).toString("base64url"),
    Buffer.from(`synthetic-signature-${revision}`).toString("base64url"),
  ].join(".");
}
async function fixture(action, changes = {}) {
  assert.equal(
    typeof module.createProductionAuthState,
    "function",
    "production Auth state is missing",
  );
  const accounts = new Map(
    recipes.flatMap((recipe, index) =>
      ["valid", "competitor"].map((kind) => {
        const account = {
          ...recipe.accounts[kind],
          uid: `fixture-uid-${index + 1}-${kind}`,
          present: false,
          revision: 1,
        };
        return [`auth${index + 1}-${kind}`, account];
      }),
    ),
  );
  const calls = [],
    proofs = [],
    journal = [],
    secrets = [];
  let admitted = true;
  const memoryControls = Object.freeze({
    send: async (id, request) => {
      calls.push({ id, request });
      const match = /^r1\/(auth[12]-(?:valid|competitor))-(setup|refresh|cleanup)-(.+)$/.exec(id);
      assert.ok(match, "the actual slot must be declared");
      const account = accounts.get(match[1]),
        stage = match[2],
        kind = match[3];
      let data;
      if (kind === "signup") {
        const body = JSON.parse(request.body.toString());
        assert.equal(body.email, account.email);
        assert.equal(body.returnSecureToken, true);
        assert.ok(body.password.length >= 32);
        assert.ok(secrets.includes(body.password), "register the password before dispatch");
        assert.equal(request.parameters.apiKey, key);
        account.present = true;
        account.currentToken = tokenFor(account);
        data = {
          localId: account.uid,
          email: account.email,
          idToken: account.currentToken,
          refreshToken: `SYNTHETIC_REFRESH_${account.uid}_1`,
          expiresIn: "3600",
        };
      } else if (stage === "refresh" && kind === "refresh") {
        const form = new URLSearchParams(request.body.toString());
        assert.equal(form.get("grant_type"), "refresh_token");
        assert.equal(form.get("refresh_token"), `SYNTHETIC_REFRESH_${account.uid}_1`);
        assert.ok(secrets.includes(form.get("refresh_token")));
        account.revision = 2;
        account.currentToken = tokenFor(account, {}, 2);
        data = {
          user_id: account.uid,
          project_id: projectNumber,
          id_token: account.currentToken,
          refresh_token: `SYNTHETIC_REFRESH_${account.uid}_2`,
          expires_in: "3600",
          token_type: "Bearer",
        };
      } else if (kind === "delete") {
        const body = JSON.parse(request.body.toString());
        assert.equal(body.localId, account.uid);
        assert.equal(body.targetProjectId, plan.projectId);
        assert.ok(
          journal.some((row) => row.accountRef === account.ref && row.accountMutation === "delete"),
        );
        account.present = false;
        data = {};
      } else {
        const body = JSON.parse(request.body.toString());
        if (kind === "client-lookup") {
          assert.equal(body.idToken, account.currentToken);
          assert.equal(request.parameters.apiKey, key);
        } else if (kind === "email-absence") assert.deepEqual(body.email, [account.email]);
        else assert.deepEqual(body.localId, [account.uid]);
        data = account.present
          ? {
              users: [
                {
                  localId: account.uid,
                  email: account.email,
                  disabled: false,
                  passwordHash: "SYNTHETIC_PASSWORD_HASH",
                },
              ],
            }
          : {};
      }
      if (changes.response) data = changes.response({ id, data, account, stage, kind });
      if (kind === "signup" && typeof data.idToken === "string")
        account.currentToken = data.idToken;
      if (kind === "refresh" && typeof data.id_token === "string")
        account.currentToken = data.id_token;
      return { status: 200, arrayBuffer: async () => Buffer.from(JSON.stringify(data)) };
    },
  });
  let controls = memoryControls,
    counter;
  const controlProofs = [],
    reserves = [];
  if (changes.actualControls) {
    const recipeIds = [
      ...Array.from({ length: 24 }, (_, index) => `storage-object/fixture-${index}`),
      ...recipes.map((recipe) => recipe.id),
    ];
    counter = createStage3RequestCounter(plan, {
      onStart: async () => {},
      onReserve: async (row) => {
        reserves.push(row);
      },
      recipeLifecycle: {
        recipeIds,
        onBegin: async () => {},
        onFinish: async () => {},
        verifyTerminal: async () => true,
      },
    });
    await counter.start();
    // Prior recipes are empty lifecycle fixtures; this does not prove aggregate completion.
    for (const id of recipeIds.slice(0, 24)) {
      const capability = await counter.beginRecipe(id);
      counter.beginCleanup(capability);
      await counter.finishRecipe(capability);
    }
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
          assert.equal(slot.phase, init.accountingPhase);
          assert.equal(slot.kind, kind);
          return memoryControls.send(slot.id, { recipeToken: null, parameters, body: init.body });
        },
      }),
      onProof: async (row) => {
        controlProofs.push(row);
      },
    });
  }
  const state = module.createProductionAuthState({
    plan,
    recording: 1,
    projectNumber,
    apiKey: key,
    controls,
    verifyAdmission: (context) =>
      admitted &&
      (!counter ||
        (counter.snapshot().mode === context.phase &&
          counter.snapshot().recording === context.recording)),
    onSecret: (value) => {
      secrets.push(value);
    },
    onProof: async (row) => {
      proofs.push(row);
    },
    ...changes.options,
    onJournal: async (row) => {
      await changes.options?.onJournal?.(row);
      journal.push(row);
    },
  });
  try {
    await action({
      state,
      calls,
      proofs,
      journal,
      secrets,
      accounts,
      counter,
      controlProofs,
      reserves,
      revoke() {
        admitted = false;
      },
    });
  } finally {
    state.close();
  }
}
const context = (index = 0) => ({
  recording: 1,
  kind: "storage",
  phase: "subject",
  operationId: `r1/p${25 + index}/${"a".repeat(64)}`,
});

test("the synchronous Auth provider preserves original recording identity without accepting copied methods", async () => {
  await fixture(async ({ state, calls }) => {
    assert.equal(typeof module.originalProductionAuthAuthorizationProvider, "function");
    const provider = module.originalProductionAuthAuthorizationProvider(state, 1);
    assert.equal(provider, state.accountAuthorization);
    const ref = { kind: "valid", accountRef: recipes[0].accounts.valid.ref };
    assert.throws(() => provider(ref, context()), /unavailable/);
    assert.equal(calls.length, 0);
    let hooks = 0;
    const fake = {
      get accountAuthorization() {
        hooks++;
        return provider;
      },
    };
    const proxy = new Proxy(state, {
      get() {
        hooks++;
        return provider;
      },
      getPrototypeOf() {
        hooks++;
        return Object.prototype;
      },
    });
    const revoked = Proxy.revocable(state, {});
    revoked.revoke();
    for (const value of [{ ...state }, fake, proxy, revoked.proxy, null])
      assert.throws(
        () => module.originalProductionAuthAuthorizationProvider(value, 1),
        /invalid original production Auth provider/,
      );
    for (const recording of [
      2,
      0,
      undefined,
      new Number(1),
      {
        valueOf() {
          hooks++;
          return 1;
        },
      },
    ])
      assert.throws(
        () => module.originalProductionAuthAuthorizationProvider(state, recording),
        /invalid original production Auth provider/,
      );
    assert.equal(hooks, 0);
    assert.equal(calls.length, 0);
    await state.setup(recipes[0].id, Object.freeze({}));
    assert.match(provider(ref, context()), /^Firebase /);
    assert.equal(calls.length, 8);
    state.close();
    assert.throws(() => provider(ref, context()), /unavailable/);
    assert.equal(calls.length, 8);
  });
});

test("four production accounts use only their eleven declared slots and proved Firebase credentials", async () => {
  await fixture(async (f) => {
    const capability = Object.freeze({});
    for (const [index, recipe] of recipes.entries()) {
      await f.state.setup(recipe.id, capability);
      assert.equal(f.secrets.includes(key), true);
      for (const kind of ["valid", "competitor"]) {
        const ref = { kind, accountRef: recipe.accounts[kind].ref };
        assert.match(f.state.accountAuthorization(ref, context(index)), /^Firebase /);
      }
      await f.state.refresh(recipe.id, capability);
      await assert.rejects(f.state.refresh(recipe.id, capability), /Auth stage/);
      await f.state.cleanup(recipe.id, capability);
      for (const kind of ["valid", "competitor"])
        assert.throws(
          () =>
            f.state.accountAuthorization(
              { kind, accountRef: recipe.accounts[kind].ref },
              context(index),
            ),
          /unavailable/,
        );
    }
    assert.equal(f.calls.length, 44);
    assert.equal(new Set(f.calls.map((row) => row.id)).size, 44);
    assert.equal(
      f.calls.every((row) => row.request.recipeToken === capability),
      true,
    );
    assert.equal(
      f.calls.some((row) => row.id.includes("signin")),
      false,
    );
    assert.equal(f.state.snapshot().unresolved.length, 0);
    const persisted = JSON.stringify([...f.proofs, ...f.journal, f.state.snapshot()]);
    for (const secret of f.secrets) assert.equal(persisted.includes(secret), false);
    assert.equal(persisted.includes("SYNTHETIC_PASSWORD_HASH"), false);
  });
});

test("an existing email prevents signup and an unowned account is never deleted", async () => {
  await fixture(
    async (f) => {
      await assert.rejects(f.state.setup(recipes[0].id, {}), /unavailable/);
      assert.equal(f.calls.length, 1);
      await f.state.cleanup(recipes[0].id, {});
      assert.equal(f.calls.length, 1);
      assert.equal(
        f.journal.some((row) => row.accountMutation === "delete"),
        false,
      );
    },
    {
      response: ({ data, kind, account }) =>
        kind === "email-absence"
          ? { users: [{ localId: "existing-unowned", email: account.email }] }
          : data,
    },
  );
});

test("foreign signup, client, Admin and refresh identity never produce a subject credential", async () => {
  for (const failure of [
    "signup-email",
    "client-uid",
    "admin-email",
    "refresh-project",
    "refresh-token-aud",
    "refresh-token-tenant",
  ]) {
    await fixture(
      async (f) => {
        const recipe = recipes[0];
        if (failure.startsWith("refresh")) await f.state.setup(recipe.id, {});
        await assert.rejects(
          failure.startsWith("refresh")
            ? f.state.refresh(recipe.id, {})
            : f.state.setup(recipe.id, {}),
          /unavailable/,
        );
        const before = f.calls.length;
        assert.throws(
          () =>
            f.state.accountAuthorization(
              { kind: "valid", accountRef: recipe.accounts.valid.ref },
              context(),
            ),
          /unavailable/,
        );
        await assert.rejects(f.state.setup(recipe.id, {}), /unavailable|Auth stage/);
        assert.equal(f.calls.length, before);
      },
      {
        response: ({ data, kind, stage, account }) => {
          if (failure === "signup-email" && kind === "signup")
            return { ...data, email: "foreign@example.com" };
          if (failure === "client-uid" && stage === "setup" && kind === "client-lookup")
            return { users: [{ localId: "foreign-uid", email: account.email }] };
          if (failure === "admin-email" && stage === "setup" && kind === "admin-lookup")
            return { users: [{ localId: account.uid, email: "foreign@example.com" }] };
          if (failure === "refresh-project" && kind === "refresh")
            return { ...data, project_id: "987654321098" };
          if (failure === "refresh-token-aud" && kind === "refresh")
            return { ...data, id_token: tokenFor(account, { aud: "foreign-project" }, 2) };
          if (failure === "refresh-token-tenant" && kind === "refresh")
            return {
              ...data,
              id_token: tokenFor(
                account,
                { firebase: { sign_in_provider: "password", tenant: "foreign-tenant" } },
                2,
              ),
            };
          return data;
        },
      },
    );
  }
});

test("admission refusal performs no helper or secret callback and no cleanup bypass", async () => {
  await fixture(async (f) => {
    f.revoke();
    await assert.rejects(f.state.setup(recipes[0].id, {}), /unavailable/);
    await assert.rejects(f.state.cleanup(recipes[0].id, {}), /unavailable/);
    assert.equal(f.calls.length, 0);
    assert.equal(f.secrets.length, 0);
    assert.equal(f.journal.length, 0);
  });
});

test("signup uncertainty retains ownership intent without retrying or deleting an unknown UID", async () => {
  await fixture(
    async (f) => {
      await assert.rejects(f.state.setup(recipes[0].id, {}), /unavailable/);
      assert.equal(f.calls.length, 2);
      assert.equal(f.state.snapshot().unresolved[0].state, "creating");
      await f.state.cleanup(recipes[0].id, {});
      assert.equal(f.calls.length, 2);
      assert.equal(
        f.journal.some((row) => row.accountMutation === "create"),
        true,
      );
      assert.equal(
        f.journal.some((row) => row.accountMutation === "delete"),
        false,
      );
    },
    {
      response: ({ data, kind }) => {
        if (kind === "signup") throw new Error("RAW_PROVIDER_SECRET");
        return data;
      },
    },
  );
});

test("foreign recipe, recording, role and phase cannot use an otherwise verified token", async () => {
  await fixture(async (f) => {
    const recipe = recipes[0];
    await f.state.setup(recipe.id, {});
    for (const [ref, supplied] of [
      [{ kind: "valid", accountRef: recipe.accounts.valid.ref }, context(1)],
      [{ kind: "competitor", accountRef: recipe.accounts.valid.ref }, context()],
      [
        { kind: "valid", accountRef: recipe.accounts.valid.ref },
        { ...context(), recording: 2 },
      ],
      [
        { kind: "valid", accountRef: recipe.accounts.valid.ref },
        { ...context(), phase: "cleanup" },
      ],
    ])
      assert.throws(() => f.state.accountAuthorization(ref, supplied), /unavailable/);
    assert.match(
      f.state.accountAuthorization(
        { kind: "valid", accountRef: recipe.accounts.valid.ref },
        context(),
      ),
      /^Firebase /,
    );
    assert.equal(f.calls.length, 8);
    f.state.close();
    assert.throws(
      () =>
        f.state.accountAuthorization(
          { kind: "valid", accountRef: recipe.accounts.valid.ref },
          context(),
        ),
      /unavailable/,
    );
  });
});

test("configuration coercion, Proxy and accessors cannot execute hooks before admission", async () => {
  let hooks = 0;
  for (const options of [
    {
      projectNumber: {
        toString() {
          hooks++;
          return projectNumber;
        },
      },
    },
    {
      controls: Object.defineProperty({}, "send", {
        enumerable: true,
        get() {
          hooks++;
          return async () => {};
        },
      }),
    },
    {
      verifyAdmission: new Proxy(() => true, {
        apply() {
          hooks++;
          return true;
        },
      }),
    },
    {
      plan: new Proxy(plan, {
        get() {
          hooks++;
          assert.fail();
        },
      }),
    },
  ])
    await assert.rejects(
      fixture(async () => {}, { options }),
      /^Error: invalid production Auth configuration$/,
    );
  assert.equal(hooks, 0);
});

test("expired and regressing clocks stop subjects without automatic refresh and retain owned cleanup", async () => {
  const nowDescriptor = Object.getOwnPropertyDescriptor(performance, "now"),
    originalWall = Date.now;
  let monotonic = 1000,
    wall = originalWall();
  Object.defineProperty(performance, "now", { configurable: true, value: () => monotonic });
  Date.now = () => wall;
  try {
    for (const failure of ["expiry", "backward", "wall-drift"]) {
      monotonic = 1000;
      wall = originalWall();
      await fixture(async (f) => {
        const recipe = recipes[0];
        await f.state.setup(recipe.id, {});
        if (failure === "expiry") {
          monotonic += 3540000;
          wall += 3540000;
        } else if (failure === "backward") monotonic--;
        else wall += 6000;
        assert.throws(
          () =>
            f.state.accountAuthorization(
              { kind: "valid", accountRef: recipe.accounts.valid.ref },
              context(),
            ),
          /unavailable/,
        );
        assert.equal(f.state.snapshot().subjectFailed, true);
        await assert.rejects(f.state.refresh(recipe.id, {}), /unavailable/);
        assert.equal(f.calls.length, 8);
        assert.equal(f.state.snapshot().unresolved.length, 2);
      });
    }
  } finally {
    Date.now = originalWall;
    if (nowDescriptor) Object.defineProperty(performance, "now", nowDescriptor);
    else delete performance.now;
  }
});

test("mutation intent and identity receipt writers gate signup and proven UID cleanup", async () => {
  let writes = 0;
  await fixture(
    async (f) => {
      await assert.rejects(f.state.setup(recipes[0].id, {}), /unavailable/);
      assert.equal(f.calls.length, 1);
      assert.equal(writes, 1);
      assert.equal(f.state.snapshot().unresolved.length, 0);
    },
    {
      options: {
        onJournal: async () => {
          writes++;
          throw new Error("RAW_JOURNAL_SECRET");
        },
      },
    },
  );
  writes = 0;
  await fixture(
    async (f) => {
      await assert.rejects(f.state.setup(recipes[0].id, {}), /unavailable/);
      assert.equal(f.calls.length, 2);
      assert.equal(f.state.snapshot().unresolved[0].state, "owned");
      await f.state.cleanup(recipes[0].id, {});
      assert.equal(f.calls.filter((row) => row.id.includes("cleanup-delete")).length, 1);
      assert.equal(f.state.snapshot().unresolved.length, 0);
    },
    {
      options: {
        onJournal: async () => {
          writes++;
          if (writes === 2) throw new Error("RAW_RECEIPT_SECRET");
        },
      },
    },
  );
});

test("actual finite controls bind all forty-four Auth helpers to their recipe, phase and reservations", async () => {
  await fixture(
    async (f) => {
      for (const recipe of recipes) {
        const capability = await f.counter.beginRecipe(recipe.id);
        await f.state.setup(recipe.id, capability);
        await f.state.refresh(recipe.id, capability);
        f.counter.beginCleanup(capability);
        await f.state.cleanup(recipe.id, capability);
        await f.counter.finishRecipe(capability);
      }
      assert.equal(f.counter.snapshot().total, 44);
      assert.deepEqual(f.counter.snapshot().recordings[0], { subject: 28, cleanup: 16 });
      assert.equal(f.controlProofs.length, 44);
      assert.equal(f.reserves.length, 44);
      for (let index = 0; index < 44; index++) {
        assert.equal(f.controlProofs[index].sequence, index + 1);
        assert.equal(f.reserves[index].sequence, index + 1);
        assert.equal(f.controlProofs[index].operationId, f.reserves[index].operationId);
        assert.equal(f.controlProofs[index].recipeId, f.reserves[index].recipeId);
        assert.equal(f.controlProofs[index].phase, f.reserves[index].phase);
      }
      assert.equal(f.state.snapshot().unresolved.length, 0);
    },
    { actualControls: true },
  );
});

test("close inside secret registration cannot dispatch a later account helper", async () => {
  let state,
    registrations = 0;
  await fixture(
    async (f) => {
      state = f.state;
      await assert.rejects(state.setup(recipes[0].id, {}), /unavailable/);
      assert.equal(registrations, 1);
      assert.equal(f.calls.length, 0);
      assert.equal(f.state.snapshot().closed, true);
    },
    {
      options: {
        onSecret: () => {
          registrations++;
          state.close();
        },
      },
    },
  );
});

test("private Auth terminal evidence binds setup, refresh and cleanup to the original capability", async () => {
  for (const changedStage of ["setup", "refresh", "cleanup"])
    await fixture(async (f) => {
      const capability = Object.freeze({}),
        foreign = Object.freeze({}),
        recipe = recipes[0];
      await f.state.setup(recipe.id, changedStage === "setup" ? foreign : capability);
      await f.state.refresh(recipe.id, changedStage === "refresh" ? foreign : capability);
      await f.state.cleanup(recipe.id, changedStage === "cleanup" ? foreign : capability);
      // This mock accepts foreign capabilities; the real finite dispatcher rejects them earlier.
      assert.equal(f.state.snapshot().unresolved.length, 0);
      assert.equal(
        module.verifyProductionAuthRecipeTerminal(f.state, {
          recipeId: recipe.id,
          recipeToken: capability,
        }),
        false,
      );
      assert.equal(
        module.verifyProductionAuthRecipeTerminal(f.state, {
          recipeId: recipe.id,
          recipeToken: foreign,
        }),
        false,
      );
    });
});

test("closing during final Auth cleanup persistence prevents terminal publication", async () => {
  let state;
  await fixture(
    async (f) => {
      state = f.state;
      const capability = Object.freeze({}),
        recipe = recipes[0];
      await state.setup(recipe.id, capability);
      await state.refresh(recipe.id, capability);
      await assert.rejects(state.cleanup(recipe.id, capability), /unavailable/);
      assert.equal(f.calls.length, 22);
      assert.equal(
        module.verifyProductionAuthRecipeTerminal(state, {
          recipeId: recipe.id,
          recipeToken: capability,
        }),
        false,
      );
    },
    {
      options: {
        onProof: async (row) => {
          if (row.type === "production-auth-cleanup" && row.accountRef.endsWith(":competitor"))
            state.close();
        },
      },
    },
  );
});

test("dispatch context rejects coercion and nested Proxy values without stopping the valid pair", async () => {
  let hooks = 0;
  const revoked = Proxy.revocable({}, {});
  revoked.revoke();
  const operationIds = [
    {
      toString() {
        hooks++;
        return context().operationId;
      },
    },
    {
      [Symbol.toPrimitive]() {
        hooks++;
        return context().operationId;
      },
    },
    new Proxy(
      {},
      {
        get() {
          hooks++;
          return () => context().operationId;
        },
      },
    ),
    revoked.proxy,
  ];
  await fixture(async (f) => {
    const ref = { kind: "valid", accountRef: recipes[0].accounts.valid.ref };
    await f.state.setup(recipes[0].id, {});
    for (const operationId of operationIds)
      assert.throws(
        () => f.state.accountAuthorization(ref, { ...context(), operationId }),
        /^Error: production Auth is unavailable$/,
      );
    assert.equal(hooks, 0);
    assert.equal(f.state.snapshot().subjectFailed, false);
    assert.match(f.state.accountAuthorization(ref, context()), /^Firebase /);
    assert.equal(f.calls.length, 8);
  });
});

test("first and cached malformed subjects require a valid nonregressing clock", async () => {
  const descriptor = Object.getOwnPropertyDescriptor(performance, "now"),
    originalWall = Date.now;
  let monotonic = 1000;
  const wall = originalWall();
  Object.defineProperty(performance, "now", { configurable: true, value: () => monotonic });
  Date.now = () => wall;
  try {
    for (const cached of [false, true])
      for (const invalid of [false, true]) {
        monotonic = 1000;
        await fixture(async (f) => {
          await f.state.setup(recipes[0].id, {});
          if (cached)
            assert.match(
              f.state.accountAuthorization({ kind: "malformed" }, context()),
              /^Firebase /,
            );
          monotonic = invalid ? NaN : 999;
          assert.throws(
            () => f.state.accountAuthorization({ kind: "malformed" }, context()),
            /^Error: production Auth is unavailable$/,
          );
          assert.equal(f.state.snapshot().subjectFailed, true);
          assert.equal(f.state.snapshot().unresolved.length, 2);
          assert.equal(f.calls.length, 8);
          await assert.rejects(f.state.refresh(recipes[0].id, {}), /unavailable/);
        });
      }
  } finally {
    Date.now = originalWall;
    if (descriptor) Object.defineProperty(performance, "now", descriptor);
    else delete performance.now;
  }
});
