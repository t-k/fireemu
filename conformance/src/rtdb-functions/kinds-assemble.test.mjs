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
