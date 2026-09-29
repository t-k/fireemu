import assert from "node:assert/strict";
import { test } from "node:test";

import { createSession } from "./auth-fs-cross/session.mjs";
import { createContext, SANDBOX_PROJECT } from "./fs-rules/harness.mjs";
import { EXPECTED_ACTIONS, localSetupDigest, withLocalMultiTenancy } from "./harness-target/local-tenancy.mjs";

const PROJECT = SANDBOX_PROJECT;
const CONFIG = `/identitytoolkit.googleapis.com/admin/v2/projects/${PROJECT}/config`;
const MASK = "?updateMask=multiTenant.allowTenants";

/** A fake auth emulator's config endpoint that records every request. */
function fakeAuth({ enabled = false, patchTakesEffect = true } = {}) {
  const state = { enabled, requests: [] };
  const fetchImpl = async (url, init = {}) => {
    const parsed = new URL(url);
    const method = init.method ?? "GET";
    state.requests.push({
      method,
      target: `${parsed.host}${parsed.pathname}${parsed.search}`,
      body: init.body === undefined ? undefined : JSON.parse(init.body),
      authorization: init.headers?.authorization,
      headerNames: Object.keys(init.headers ?? {}).toSorted(),
    });
    if (parsed.pathname === CONFIG && method === "GET")
      return Response.json({ multiTenant: { allowTenants: state.enabled } });
    if (parsed.pathname === CONFIG && method === "PATCH") {
      if (patchTakesEffect) state.enabled = JSON.parse(init.body).multiTenant.allowTenants;
      return Response.json({ multiTenant: { allowTenants: state.enabled } });
    }
    return new Response("{}", { status: 404 });
  };
  return { state, fetchImpl };
}

const localCtx = (authOrigin = "http://127.0.0.1:9099") => ({
  project: PROJECT,
  target: { kind: "local", authOrigin },
});
const ctxWithOrigin = (authOrigin) => ({ project: PROJECT, target: { kind: "local", authOrigin } });

test("it turns multi-tenancy on, runs, and restores it, reading both back", async () => {
  const { state, fetchImpl } = fakeAuth();
  let seenEnabled;
  const out = await withLocalMultiTenancy(
    localCtx(),
    async () => {
      seenEnabled = state.enabled;
      return "done";
    },
    { fetchImpl },
  );
  assert.equal(out.value, "done");
  assert.equal(seenEnabled, true);
  assert.equal(state.enabled, false);
  assert.deepEqual(out.actions, EXPECTED_ACTIONS);
  assert.deepEqual(
    state.requests.map(({ method, target, body }) => [method, target, body]),
    [
      ["GET", `127.0.0.1:9099${CONFIG}`, undefined],
      ["PATCH", `127.0.0.1:9099${CONFIG}${MASK}`, { multiTenant: { allowTenants: true } }],
      ["GET", `127.0.0.1:9099${CONFIG}`, undefined],
      ["PATCH", `127.0.0.1:9099${CONFIG}${MASK}`, { multiTenant: { allowTenants: false } }],
      ["GET", `127.0.0.1:9099${CONFIG}`, undefined],
    ],
  );
});

test("every request is a config read or the one update mask, as the local owner", async () => {
  const { state, fetchImpl } = fakeAuth();
  await withLocalMultiTenancy(localCtx(), async () => {}, { fetchImpl });
  for (const request of state.requests) {
    const url = new URL(`http://${request.target}`);
    assert.equal(url.pathname, CONFIG);
    assert.ok(["GET", "PATCH"].includes(request.method));
    if (request.method === "PATCH") {
      // The mask is exactly this field: nothing else of the configuration can change.
      assert.equal(url.search, MASK);
      assert.deepEqual(Object.keys(request.body), ["multiTenant"]);
      assert.deepEqual(Object.keys(request.body.multiTenant), ["allowTenants"]);
    } else assert.equal(url.search, "");
    assert.equal(request.authorization, "Bearer owner");
    assert.ok(request.headerNames.every((n) => ["authorization", "content-type"].includes(n)));
  }
});

test("when multi-tenancy is already on it changes nothing", async () => {
  const { state, fetchImpl } = fakeAuth({ enabled: true });
  const out = await withLocalMultiTenancy(localCtx(), async () => 1, { fetchImpl });
  assert.equal(state.enabled, true);
  assert.deepEqual(
    state.requests.map(({ method }) => method),
    ["GET"],
  );
  assert.deepEqual(out.actions, []);
});

test("it restores multi-tenancy when the run throws, and the run's error wins", async () => {
  const { state, fetchImpl } = fakeAuth();
  await assert.rejects(
    withLocalMultiTenancy(
      localCtx(),
      async () => {
        assert.equal(state.enabled, true);
        throw new Error("run failed");
      },
      { fetchImpl },
    ),
    /run failed/,
  );
  assert.equal(state.enabled, false);
  assert.equal(state.requests.at(-2).method, "PATCH");
  assert.deepEqual(state.requests.at(-2).body, { multiTenant: { allowTenants: false } });
});

/** A fake whose restore is accepted but does not take effect. */
function stuckOn() {
  const base = fakeAuth();
  return async (url, init) => {
    if (init?.method === "PATCH" && JSON.parse(init.body).multiTenant.allowTenants === false)
      return Response.json({});
    return base.fetchImpl(url, init);
  };
}

test("a restore that does not read back is an error, named next to a run error", async () => {
  await assert.rejects(
    withLocalMultiTenancy(localCtx(), async () => "ok", { fetchImpl: stuckOn() }),
    /did not read back as restored/,
  );
  await assert.rejects(
    withLocalMultiTenancy(
      localCtx(),
      async () => {
        throw new Error("run failed");
      },
      { fetchImpl: stuckOn() },
    ),
    (error) =>
      /run failed/.test(error.message) && /did not read back as restored/.test(error.message),
  );
});

test("an enable that does not read back stops before the run, and still restores", async () => {
  const { state, fetchImpl } = fakeAuth({ patchTakesEffect: false });
  let ran = false;
  await assert.rejects(
    withLocalMultiTenancy(
      localCtx(),
      async () => {
        ran = true;
      },
      { fetchImpl },
    ),
    /did not read back as enabled/,
  );
  assert.equal(ran, false);
  assert.equal(state.enabled, false);
  assert.equal(state.requests.at(-2).method, "PATCH");
});

test("a target that is production is refused before any request", async () => {
  const { state, fetchImpl } = fakeAuth();
  for (const target of [
    { kind: "production", authOrigin: "http://127.0.0.1:9099" },
    { kind: "production" },
    { kind: undefined, authOrigin: "http://127.0.0.1:9099" },
    { authOrigin: "http://127.0.0.1:9099" },
    { kind: "Local", authOrigin: "http://127.0.0.1:9099" },
  ]) {
    await assert.rejects(
      withLocalMultiTenancy({ project: PROJECT, target }, async () => "ran", { fetchImpl }),
      /local target/,
    );
  }
  assert.deepEqual(state.requests, []);
});

test("an origin that is not loopback is refused before any request", async () => {
  const { state, fetchImpl } = fakeAuth();
  for (const origin of [
    "https://identitytoolkit.googleapis.com",
    "http://example.com:9099",
    "http://10.0.0.5:9099",
    "http://127.0.0.1.evil.example:9099",
    "http://localhost.evil.example:9099",
    "http://0.0.0.0:9099",
    "http://[::2]:9099",
    "https://127.0.0.1:9099",
    "https://localhost:9099",
    "ws://127.0.0.1:9099",
    "http://user:secret@127.0.0.1:9099",
    "http://127.0.0.1:9099/extra",
    "http://127.0.0.1:9099?x=1",
    "http://127.0.0.1:9099#frag",
    "not a url",
    "",
    undefined,
  ]) {
    await assert.rejects(
      withLocalMultiTenancy(ctxWithOrigin(origin), async () => "ran", { fetchImpl }),
      /loopback|origin/,
      String(origin),
    );
  }
  assert.deepEqual(state.requests, []);
});

test("loopback origins are accepted", async () => {
  for (const origin of ["http://127.0.0.1:9099", "http://localhost:9099", "http://[::1]:9099"]) {
    const { fetchImpl } = fakeAuth();
    const out = await withLocalMultiTenancy(localCtx(origin), async () => origin, { fetchImpl });
    assert.equal(out.value, origin);
  }
});

test("a project id that could redirect the request is refused", async () => {
  const { state, fetchImpl } = fakeAuth();
  for (const project of ["a/b", "a?x=1", "a#b", "", "../x", undefined])
    await assert.rejects(
      withLocalMultiTenancy({ ...localCtx(), project }, async () => "ran", { fetchImpl }),
      /project/,
    );
  assert.deepEqual(state.requests, []);
});

test("the setup digest names the helper's tokens and is stable across comment edits", () => {
  assert.match(localSetupDigest(), /^[0-9a-f]{64}$/);
});

test("it sends the requests the recorded session sends to production", async () => {
  // Production: the session's own createTenant / deleteTenants against a fake project that has
  // multi-tenancy off. The helper must ask the same config questions with the same updates.
  const production = fakeAuth();
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    const parsed = new URL(url);
    if (parsed.pathname.endsWith("/tenants") && init?.method === "POST")
      return Response.json({ name: `projects/${PROJECT}/tenants/T-1` });
    if (parsed.pathname.endsWith("/tenants")) return Response.json({ tenants: [] });
    if (init?.method === "DELETE") return Response.json({});
    // The production config path, as identitytoolkit.googleapis.com/admin/v2/...
    return production.fetchImpl(
      `http://prod.invalid/identitytoolkit.googleapis.com${parsed.pathname.replace(/^\/identitytoolkit\.googleapis\.com/, "")}${parsed.search}`,
      init,
    );
  };
  const ctx = createContext({
    run: "1790000000000",
    target: {
      kind: "production",
      apiKey: "k",
      adminToken: "t",
      quotaProject: SANDBOX_PROJECT,
      projectNumber: "123456789012",
      foreign: { project: "other", apiKey: "k2", projectNumber: "2" },
    },
  });
  const session = createSession(ctx, {});
  try {
    await session.createTenant("t1");
    await session.deleteTenants();
  } finally {
    globalThis.fetch = realFetch;
    await session.close();
  }
  const configOf = (requests) =>
    requests
      .filter(({ target }) => new URL(`http://${target}`).pathname === CONFIG)
      .map(({ method, target, body }) => [method, target.replace(/^[^/]*/, ""), body]);
  const local = fakeAuth();
  await withLocalMultiTenancy(localCtx(), async () => {}, { fetchImpl: local.fetchImpl });
  const updates = (rows) => rows.filter(([method]) => method === "PATCH");
  assert.equal(
    updates(configOf(production.state.requests)).length,
    2,
    "the session enabled and restored",
  );
  assert.deepEqual(
    updates(configOf(local.state.requests)),
    updates(configOf(production.state.requests)),
  );
  const productionReads = new Set(
    configOf(production.state.requests)
      .filter(([m]) => m === "GET")
      .map(([, t]) => t),
  );
  for (const [, target] of configOf(local.state.requests).filter(([m]) => m === "GET"))
    assert.ok(productionReads.has(target));
});

test("an answer other than 200 stops the setup, and nothing after it is sent", async () => {
  const { state, fetchImpl } = fakeAuth();
  const failing = async (url, init) => {
    await fetchImpl(url, init);
    return new Response("{}", { status: 500 });
  };
  let ran = false;
  await assert.rejects(
    withLocalMultiTenancy(localCtx(), async () => { ran = true; }, { fetchImpl: failing }),
    /HTTP 500/,
  );
  assert.equal(ran, false);
  assert.deepEqual(state.requests.map(({ method }) => method), ["GET"]);
});

test("an update that took effect but was answered with an error is still restored", async () => {
  const { state, fetchImpl } = fakeAuth();
  let firstPatch = true;
  const flaky = async (url, init) => {
    const response = await fetchImpl(url, init);
    if (init?.method === "PATCH" && firstPatch) {
      firstPatch = false;
      return new Response("{}", { status: 503 });
    }
    return response;
  };
  await assert.rejects(withLocalMultiTenancy(localCtx(), async () => "ran", { fetchImpl: flaky }), /HTTP 503/);
  assert.equal(state.enabled, false);
});
