import test from "node:test";
import assert from "node:assert/strict";
import { BREADTH_LIMITS, createBreadthBudget } from "./breadth-wiring.mjs";

test("T1 request limits are pinned for three functions", () => {
  assert.deepEqual(BREADTH_LIMITS, {
    cliDeploy: 3,
    upload: 15,
    token: 12,
    control: 38,
    cleanup: 70,
    logs: 40,
    inventory: 100,
    userClient: 6,
    browserHttp: 40,
    browserWs: 4,
  });
});

test("shared budget enforces the normal and cleanup total boundaries", () => {
  const budget = createBreadthBudget();
  for (let i = 0; i < 200; i++) budget.take("rtdbAdmin");
  assert.equal(budget.snapshot().total, 200);
  assert.throws(() => budget.take("control"), /200/);
  budget.startCleanup();
  budget.take("cleanup");
  assert.equal(budget.snapshot().total, 201);
  for (let i = 0; i < 11; i++) budget.take("cleanup");
  assert.equal(budget.snapshot().total, 212);
  assert.throws(() => budget.take("cleanup"), /212/);
  assert.equal(budget.snapshot().total, 212);
});
