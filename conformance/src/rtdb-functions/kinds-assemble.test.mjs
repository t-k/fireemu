import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { assembleBreadth } from "./breadth-assemble.mjs";
import { createBreadthBudget } from "./breadth-wiring.mjs";
import { KINDS_SCENARIO, KINDS_WINDOWS } from "./kinds-scenario.mjs";

async function assemble(control, extra = {}) {
  const dir = await mkdtemp(join(tmpdir(), "kinds-assemble-"));
  const assembled = assembleBreadth({
    control,
    auth: {},
    sdk: {},
    packet: {},
    budget: createBreadthBudget(KINDS_SCENARIO),
    runDir: dir,
    projectNumber: "123456789012",
    clock: { now: () => 0, sleep: async () => {} },
    nonce: "nonce",
    scenario: KINDS_SCENARIO,
    log: () => {},
    ...extra,
  });
  return {
    assembled,
    cleanup: () => (assembled.uploads.close(), rm(dir, { recursive: true, force: true })),
  };
}

test("the assembled deps carry the kinds targets, steps, windows and hooks", async () => {
  const { assembled, cleanup } = await assemble(async () => ({ value: { functions: [] } }));
  try {
    const { deps } = assembled;
    assert.deepEqual(
      deps.targets.map((t) => t.functionName),
      KINDS_SCENARIO.targets.map((t) => t.functionName),
    );
    assert.equal(deps.steps.length, 21);
    assert.ok(deps.steps.some((s) => s.path.includes("nonce")) === false);
    assert.equal(deps.steps[0].body.run, "nonce");
    assert.deepEqual(deps.windows, KINDS_WINDOWS);
    assert.equal(deps.observe, KINDS_SCENARIO.observe);
    assert.equal(deps.judge, KINDS_SCENARIO.judge);
    assert.equal(deps.complete, KINDS_SCENARIO.complete);
  } finally {
    await cleanup();
  }
});

test("before-inventory refuses a function already in the kinds codebase, not the breadth one", async () => {
  let codebase = "rtdb-kinds-oracle";
  const { assembled, cleanup } = await assemble(async (_method, url) => {
    assert.ok(!url.includes("/functions?") || url.includes("/locations/-/"));
    return {
      value: {
        functions: [{ name: "unrelated", labels: { "firebase-functions-codebase": codebase } }],
      },
    };
  });
  try {
    await assert.rejects(assembled.deps.inventory.take(), /codebase already has a function/);
    codebase = "rtdb-breadth-oracle";
    assert.equal((await assembled.deps.inventory.take()).complete, true);
  } finally {
    await cleanup();
  }
});

test("the log reader reads the kinds origins", async () => {
  const filters = [];
  const { assembled, cleanup } = await assemble(async (_m, url, body) => {
    if (body?.filter) filters.push(body.filter);
    return { value: { entries: [] } };
  });
  try {
    await assembled.deps.logs.read({ start: "a", end: "b" });
    assert.ok(filters[0].includes('service_name="k9createdv2"'));
    assert.ok(!filters[0].includes("g9writtenv2"));
  } finally {
    await cleanup();
  }
});

test("without a scenario the assembly is the breadth one", async () => {
  const dir = await mkdtemp(join(tmpdir(), "breadth-assemble-"));
  const assembled = assembleBreadth({
    control: async () => ({ value: {} }),
    auth: {},
    sdk: {},
    packet: {},
    budget: createBreadthBudget(),
    runDir: dir,
    projectNumber: "123456789012",
    clock: { now: () => 0, sleep: async () => {} },
    nonce: "n",
  });
  try {
    assert.equal(assembled.deps.targets.length, 3);
    assert.equal(assembled.deps.steps.length, 12);
  } finally {
    assembled.uploads.close();
    await rm(dir, { recursive: true, force: true });
  }
});

test("the assembled RTDB client reads, installs and clears the scenario's prefix and Rules", async () => {
  const calls = [];
  let installed;
  const baseline = "{ }\n";
  const sha = (await import("node:crypto")).createHash("sha256").update(baseline).digest("hex");
  const adminFetch = async (url, init) => {
    calls.push([init.method, url]);
    let value = null;
    if (url.includes("serviceusage"))
      value = {
        name: "projects/123456789012/services/firebasedatabase.googleapis.com",
        state: "ENABLED",
      };
    else if (url.includes("firebasedatabase")) {
      const instance = {
        name: "projects/123456789012/locations/us-central1/instances/fireemu-q-rtdb2",
        type: "USER_DATABASE",
        state: "ACTIVE",
      };
      value = url.endsWith("/instances") ? { instances: [instance] } : instance;
    } else if (url.includes(".settings/rules")) {
      if (init.method === "PUT") installed = init.body;
      else return { status: 200, text: async () => installed ?? baseline };
      value = { status: "ok" };
    }
    return { status: 200, text: async () => JSON.stringify(value) };
  };
  const { assembled, cleanup } = await assemble(async () => ({ value: {} }), {
    adminFetch,
    anonymousFetch: adminFetch,
    packet: { projectNumber: "123456789012", baselineRulesSha256: sha },
  });
  try {
    await assembled.rtdb.setup();
    assert.deepEqual(JSON.parse(installed), KINDS_SCENARIO.rulesFor("k9-rtdb", "nonce"));
    assert.ok(calls.some(([, url]) => url.endsWith("/k9-rtdb.json")));
    assert.ok(!calls.some(([, url]) => url.includes("g9-rtdb")));
    assembled.deps.budget.startCleanup();
    await assembled.rtdb.cleanup();
    assert.ok(calls.some(([method, url]) => method === "DELETE" && url.endsWith("/k9-rtdb.json")));
  } finally {
    await cleanup();
  }
});

test("the upload ledger is bounded by the scenario's upload limit", async () => {
  const { assembled, cleanup } = await assemble(async () => ({ value: {} }));
  try {
    const { budget } = assembled.deps;
    // 100 upload requests used: 20 of the kinds limit (120) left, below the breadth limit (45) it would be none
    for (let i = 0; i < 100; i++) budget.take("upload");
    await assert.doesNotReject(async () => {
      try {
        await assembled.uploads.beginDeploy("a", { generation: 2 });
      } catch (error) {
        if (/budget is short/.test(error.message)) throw error;
      }
    });
    for (let i = 0; i < 18; i++) budget.take("upload");
    await assert.rejects(
      assembled.uploads.beginDeploy("b", { generation: 2 }),
      /upload request budget is short/,
    );
  } finally {
    await cleanup();
  }
});
