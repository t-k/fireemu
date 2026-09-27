// The campaign's single request budget (issue auth-tenant-campaign-total-request-cap, C1-C3).

import assert from "node:assert/strict";
import { test } from "node:test";

import { createContext } from "./auth-account/harness.mjs";
import {
  MAX_CAMPAIGN_REQUESTS,
  chargeExternal,
  createRequestBudget,
  currentKind,
  installBudget,
  withKind,
  withPhase,
} from "./auth-tenant-blocking/budget.mjs";
import {
  cleanupReserveFor as cleanupReserve,
  programCleanupBound,
} from "./auth-tenant-blocking/budget.mjs";
import { PROGRAMS } from "./auth-tenant-blocking/corpus.mjs";
import { createSession } from "./auth-tenant-blocking/session.mjs";

test("the work stops where the cleanup reserve starts, the cleanup at the total (C1, C2)", () => {
  const budget = createRequestBudget({ total: 10, cleanupReserve: 4 });
  for (let i = 0; i < 6; i += 1) budget.take("work");
  assert.throws(() => budget.take("work"), /request budget/);
  for (let i = 0; i < 4; i += 1) budget.take("cleanup");
  assert.throws(() => budget.take("cleanup"), /request budget/);
  assert.deepEqual(budget.snapshot(), { total: 10, cleanupReserve: 4, used: 10, refused: 2 });
});

test("a refused charge is fatal and uses nothing", () => {
  const budget = createRequestBudget({ total: 3, cleanupReserve: 1 });
  budget.take("work", 2);
  const error = (() => {
    try {
      budget.take("work");
    } catch (caught) {
      return caught;
    }
  })();
  assert.equal(error.fatal, true);
  assert.equal(budget.used(), 2);
});

test("a budget is a whole number within the approved maximum", () => {
  assert.equal(MAX_CAMPAIGN_REQUESTS, 2000);
  createRequestBudget({ total: 2000, cleanupReserve: 300 });
  for (const bad of [
    { total: 2001, cleanupReserve: 300 },
    { total: 0, cleanupReserve: 0 },
    { total: 100, cleanupReserve: 100 },
    { total: 100, cleanupReserve: -1 },
    { total: 10.5, cleanupReserve: 1 },
    { total: "100", cleanupReserve: 1 },
  ])
    assert.throws(() => createRequestBudget(bad), /budget/, JSON.stringify(bad));
});

test("every fetch of the process is charged once installed, and refused past the total", async () => {
  const target = { fetch: async () => new Response("{}", { status: 200 }) };
  const budget = createRequestBudget({ total: 3, cleanupReserve: 1 });
  const restore = installBudget(budget, target);
  try {
    await target.fetch("https://identitytoolkit.googleapis.com/x");
    await target.fetch("https://identitytoolkit.googleapis.com/x");
    await assert.rejects(async () => target.fetch("https://x"), /request budget/);
    await withKind("cleanup", () => target.fetch("https://x"));
    assert.equal(budget.used(), 3);
    await assert.rejects(async () => withKind("cleanup", () => target.fetch("https://x")));
  } finally {
    restore();
  }
  // Uninstalled: nothing is charged.
  await target.fetch("https://x");
  assert.equal(budget.used(), 3);
  const again = installBudget(budget, target);
  try {
    assert.throws(() => installBudget(budget, target), /installed/);
  } finally {
    again();
  }
});

test("a phase sets the kind of every charge inside it; an explicit kind wins (C3)", async () => {
  const target = { fetch: async () => new Response("{}") };
  const budget = createRequestBudget({ total: 5, cleanupReserve: 3 });
  const restore = installBudget(budget, target);
  try {
    budget.take("work", 2);
    await assert.rejects(async () => target.fetch("https://x"), /work/);
    await withPhase("cleanup", async () => {
      await target.fetch("https://x");
      chargeExternal(1);
      await assert.rejects(async () => withKind("work", () => target.fetch("https://x")), /work/);
    });
    assert.equal(budget.used(), 4);
    await assert.rejects(async () => target.fetch("https://x"), /work/);
  } finally {
    restore();
  }
});

test("the cleanup reserve covers the largest program's cleanup and the run's final cleanup", () => {
  const largest = Math.max(...PROGRAMS.map(programCleanupBound));
  assert.ok(cleanupReserve(PROGRAMS) > largest);
  for (const program of PROGRAMS) assert.ok(programCleanupBound(program) > 0, program.id);
  // A program that creates more tenants or changes config needs a larger reserve.
  const plain = { id: "x", steps: [], tenants: { a: {} } };
  const more = { ...plain, tenants: { a: {}, b: {}, c: {} }, config: { mfa: {} } };
  assert.ok(programCleanupBound(more) > programCleanupBound(plain));
  // Each owned tenant may be deleted in each of three rounds, next to up to 20 list pages each.
  const tenants = { ...plain, tenants: { a: {}, b: {}, c: {} } };
  assert.equal(programCleanupBound(tenants) - programCleanupBound(plain), 3 * 2);
  assert.equal(programCleanupBound(plain), 40 + 3 * (1 + 20) + 31);
});

/** A fake sandbox (config, tenants, empty accounts); every call is counted. */
function fakeSandbox() {
  const state = { allowTenants: false, tenants: new Map(), seq: 0, calls: 0 };
  const json = (status, body) => new Response(JSON.stringify(body), { status });
  const fetchFake = async (url, init = {}) => {
    state.calls += 1;
    const { pathname } = new URL(url);
    const method = init.method ?? "GET";
    const body = typeof init.body === "string" ? JSON.parse(init.body) : {};
    if (pathname.endsWith("/accounts:batchGet")) return json(200, {});
    if (pathname.endsWith("/config")) {
      if (method === "PATCH") state.allowTenants = body.multiTenant?.allowTenants === true;
      return json(200, { multiTenant: state.allowTenants ? { allowTenants: true } : {} });
    }
    const tenant = /\/tenants\/([^/]+)$/.exec(pathname)?.[1];
    if (pathname.endsWith("/tenants") && method === "POST") {
      state.seq += 1;
      const id = `${body.displayName}-a${String(state.seq).padStart(4, "0")}`;
      state.tenants.set(id, { id, displayName: body.displayName });
      return json(200, { name: `projects/fireemu-oracle-idp/tenants/${id}`, ...body });
    }
    if (pathname.endsWith("/tenants"))
      return json(200, {
        tenants: [...state.tenants.values()].map((t) => ({
          name: `projects/fireemu-oracle-idp/tenants/${t.id}`,
          displayName: t.displayName,
        })),
      });
    if (tenant && method === "DELETE")
      return state.tenants.delete(tenant) ? json(200, {}) : json(404, { error: { code: 404 } });
    return json(200, {});
  };
  return { state, fetchFake };
}

const production = createContext({
  run: "1790000000000",
  project: "fireemu-oracle-idp",
  target: {
    kind: "production",
    apiKey: "AIzaFAKEKEYFORTESTSONLY",
    adminToken: "ya29.owner",
    quotaProject: "fireemu-oracle-idp",
    projectNumber: "637500000000",
  },
  startedMs: 1_790_000_000_000,
});

test("a program that runs out of work budget still cleans up from the reserve (C2)", async () => {
  const { state, fetchFake } = fakeSandbox();
  const program = {
    id: "atb/tenant/x",
    tenants: { a: { displayName: "atb-x-a" }, b: { displayName: "atb-x-b" } },
    steps: Array.from({ length: 50 }, (_, i) => ({
      id: `lookup-${i}`,
      path: "v1/accounts:lookup",
      auth: "key",
      body: {},
    })),
  };
  const reserve = programCleanupBound(program);
  const total = 30 + reserve;
  const budget = createRequestBudget({ total, cleanupReserve: reserve });
  const original = globalThis.fetch;
  globalThis.fetch = fetchFake;
  const restore = installBudget(budget);
  try {
    const session = createSession(production, { configSettleMs: 0 });
    await assert.rejects(session.runProgram(program), /request budget/);
  } finally {
    restore();
    globalThis.fetch = original;
  }
  assert.equal(state.tenants.size, 0);
  assert.equal(state.allowTenants, false);
  assert.ok(budget.used() <= total, `${budget.used()} > ${total}`);
  assert.equal(state.calls, budget.used());
});

test("a campaign names its budget, and one that cannot carry two passes is refused (C1, C6)", async () => {
  const { planCampaignBudget } = await import("./auth-tenant-blocking/budget.mjs");
  const plan = planCampaignBudget(PROGRAMS, "1800");
  assert.equal(plan.total, 1800);
  assert.equal(plan.cleanupReserve, cleanupReserve(PROGRAMS));
  const steps = PROGRAMS.reduce((n, p) => n + p.steps.length, 0);
  assert.ok(plan.minimumWork >= 2 * steps, `${plan.minimumWork}`);
  // Two passes of every step and five read-backs, the owner token, and every signJwt preflight
  // attempt while the binding propagates (review MF-1).
  const { OAUTH_ATTEMPT_WEIGHT, SIGNER_READY_ATTEMPTS } =
    await import("./auth-tenant-blocking/budget.mjs");
  assert.equal(plan.minimumWork, 2 * (5 + steps) + SIGNER_READY_ATTEMPTS + OAUTH_ATTEMPT_WEIGHT);
  assert.equal(plan.minimumWork, 493);
  assert.throws(() => planCampaignBudget(PROGRAMS, undefined), /required/);
  assert.throws(() => planCampaignBudget(PROGRAMS, "2001"), /1\.\.2000/);
  assert.throws(() => planCampaignBudget(PROGRAMS, "1800x"), /whole number/);
  assert.throws(
    () => planCampaignBudget(PROGRAMS, String(plan.minimumWork + plan.cleanupReserve - 1)),
    /cannot carry/,
  );
  planCampaignBudget(PROGRAMS, String(plan.minimumWork + plan.cleanupReserve));
});

test("two passes share one budget: the second fits at the limit and is refused one below (C1)", async () => {
  const program = {
    id: "atb/tenant/x",
    tenants: { a: { displayName: "atb-x-a" } },
    steps: Array.from({ length: 5 }, (_, i) => ({
      id: `lookup-${i}`,
      path: "v1/accounts:lookup",
      auth: "key",
      body: {},
    })),
  };
  const reserve = programCleanupBound(program);
  /** Runs `passes` passes of the program under one installed budget of `total`. */
  const campaign = async (total, passes = 2) => {
    const { state, fetchFake } = fakeSandbox();
    const kinds = [];
    const budget = createRequestBudget({ total, cleanupReserve: reserve });
    const original = globalThis.fetch;
    globalThis.fetch = async (...args) => {
      kinds.push(currentKind());
      return fetchFake(...args);
    };
    const restore = installBudget(budget);
    const outcomes = [];
    try {
      for (let pass = 0; pass < passes; pass += 1)
        outcomes.push(
          await createSession(production, { configSettleMs: 0 })
            .runProgram(program)
            .then(
              () => "done",
              (error) => String(error.message),
            ),
        );
    } finally {
      restore();
      globalThis.fetch = original;
    }
    return { state, kinds, budget, outcomes };
  };
  // One pass on its own: its work requests, then its cleanup.
  const one = await campaign(MAX_CAMPAIGN_REQUESTS, 1);
  assert.deepEqual(one.outcomes, ["done"]);
  const pass = one.kinds.length;
  const work = one.kinds.lastIndexOf("work") + 1;
  // The second pass's last work request is the (pass + work)th: the work share must reach it.
  const least = pass + work + reserve;
  const fits = await campaign(least);
  assert.deepEqual(fits.outcomes, ["done", "done"]);
  assert.equal(fits.budget.used(), 2 * pass);
  assert.equal(fits.budget.snapshot().refused, 0);
  const over = await campaign(least - 1);
  assert.equal(over.outcomes[0], "done");
  assert.match(over.outcomes[1], /request budget: work request/);
  assert.equal(over.budget.snapshot().refused, 1);
  assert.ok(over.budget.used() <= least - 1);
  // The refused pass still cleaned up from the reserve.
  assert.equal(over.state.tenants.size, 0);
  assert.equal(over.state.allowTenants, false);
});
