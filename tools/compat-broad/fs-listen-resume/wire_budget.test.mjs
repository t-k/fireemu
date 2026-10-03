import test from "node:test";
import assert from "node:assert/strict";

const module = await import("./wire_budget.mjs").catch(() => null);

test("wire budget reserves cleanup requests after observation is exhausted", () => {
  assert.equal(typeof module?.createWireBudget, "function", "wire budget is required");
  const budget = module.createWireBudget({ maxRequests: 5, cleanupReserve: 2 });
  budget.claim("observation", "grpc");
  budget.claim("observation", "auth");
  budget.claim("observation", "grpc");
  assert.throws(() => budget.claim("observation", "grpc"), /wire request budget exhausted/);
  budget.beginCleanup();
  budget.claim("cleanup", "auth");
  budget.claim("cleanup", "admin");
  assert.throws(() => budget.claim("cleanup", "admin"), /wire request budget exhausted/);
  assert.deepEqual(budget.snapshot(), {
    maxRequests: 5,
    cleanupReserve: 2,
    phase: "cleanup",
    observation: 3,
    cleanup: 2,
    total: 5,
    transports: { grpc: 2, auth: 2, admin: 1 },
    exhausted: true,
    failures: { phase: 0, transport: 0, budget: 2 },
  });
});

test("wire budget rejects invalid bounds and phase changes without a claim", () => {
  assert.equal(typeof module?.createWireBudget, "function", "wire budget is required");
  for (const limits of [
    { maxRequests: 0, cleanupReserve: 0 },
    { maxRequests: 3, cleanupReserve: 3 },
    { maxRequests: 3.5, cleanupReserve: 1 },
    { maxRequests: 3, cleanupReserve: -1 },
  ]) {
    assert.throws(() => module.createWireBudget(limits), /wire request bounds/);
  }
  const budget = module.createWireBudget({ maxRequests: 3, cleanupReserve: 1 });
  budget.claim("cleanup", "grpc");
  assert.throws(() => budget.claim("observation", "unknown"), /wire transport/);
  assert.equal(budget.snapshot().total, 1);
  budget.beginCleanup();
  assert.throws(() => budget.claim("observation", "grpc"), /wire request phase/);
  assert.throws(() => budget.beginCleanup(), /wire request phase/);
  assert.equal(budget.snapshot().total, 1);
});

test("between-case cleanup can spend its reserve before later observation", () => {
  const budget = module.createWireBudget({ maxRequests: 5, cleanupReserve: 2 });
  budget.claim("observation", "grpc");
  budget.claim("cleanup", "grpc");
  budget.claim("observation", "grpc");
  budget.claim("observation", "auth");
  assert.throws(() => budget.claim("observation", "grpc"), /wire request budget exhausted/);
  budget.beginCleanup();
  budget.claim("cleanup", "admin");
  assert.equal(budget.snapshot().total, 5);
});

test("wire budget records sticky refusal provenance independently from exhaustion", () => {
  const budget = module.createWireBudget({ maxRequests: 5, cleanupReserve: 2 });
  assert.throws(() => budget.claim("invalid", "grpc"), /phase/);
  assert.throws(() => budget.claim("observation", "invalid"), /transport/);
  assert.equal(budget.snapshot().exhausted, false);
  assert.deepEqual(budget.snapshot().failures, { phase: 1, transport: 1, budget: 0 });
  budget.claim("observation", "grpc");
  const snapshot = budget.snapshot();
  snapshot.transports.grpc = 100;
  snapshot.failures.phase = 100;
  snapshot.observation = 100;
  assert.equal(budget.snapshot().observation, 1);
  assert.equal(budget.snapshot().transports.grpc, 1);
  assert.equal(budget.snapshot().failures.phase, 1);
});

test("wire budget rejects malformed bounds and accepts both exact local limits", () => {
  for (const value of [
    undefined,
    null,
    NaN,
    Infinity,
    -1,
    0,
    1,
    2.5,
    12001,
    Number.MAX_SAFE_INTEGER,
    "5",
  ]) {
    assert.throws(
      () => module.createWireBudget({ maxRequests: value, cleanupReserve: 1 }),
      /bounds/,
    );
  }
  for (const value of [undefined, null, NaN, Infinity, -1, 0, 3, 1.5, "1"]) {
    assert.throws(
      () => module.createWireBudget({ maxRequests: 3, cleanupReserve: value }),
      /bounds/,
    );
  }
  for (const maxRequests of [2, 12000]) {
    const budget = module.createWireBudget({ maxRequests, cleanupReserve: 1 });
    for (let i = 0; i < maxRequests - 1; i++) budget.claim("observation", "grpc");
    assert.throws(() => budget.claim("observation", "grpc"), /exhausted/);
    budget.claim("cleanup", "admin");
    assert.equal(budget.snapshot().total, maxRequests);
    assert.throws(() => budget.claim("cleanup", "admin"), /exhausted/);
  }
});

test("generated budget sequences match an independent state and counter model", () => {
  // Fixed-seed Node properties; this is not Rust proptest or a production cap proof.
  let seed = 0x51a7;
  const next = (n) => {
    seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
    return seed % n;
  };
  const transports = ["grpc", "auth", "admin", "browser", "http", "https"];
  for (let run = 0; run < 100; run++) {
    const maxRequests = 2 + next(30);
    const cleanupReserve = 1 + next(maxRequests - 1);
    const budget = module.createWireBudget({ maxRequests, cleanupReserve });
    const admitted = [];
    const failures = { phase: 0, transport: 0, budget: 0 };
    let cleaning = false;
    for (let step = 0; step < 100; step++) {
      let refusal;
      if (next(7) === 0) {
        if (cleaning) refusal = "phase";
        else cleaning = true;
        if (refusal) assert.throws(() => budget.beginCleanup(), /phase/);
        else budget.beginCleanup();
      } else {
        const requestPhase = ["observation", "cleanup", "invalid", null][next(4)];
        const transport = [...transports, "invalid", null][next(8)];
        const observation = admitted.filter((x) => x.phase === "observation").length;
        const cleanup = admitted.filter((x) => x.phase === "cleanup").length;
        if (
          !["observation", "cleanup"].includes(requestPhase) ||
          (cleaning && requestPhase === "observation")
        )
          refusal = "phase";
        else if (!transports.includes(transport)) refusal = "transport";
        else if (
          admitted.length === maxRequests ||
          (requestPhase === "observation"
            ? observation === maxRequests - cleanupReserve
            : cleanup === cleanupReserve)
        )
          refusal = "budget";
        if (refusal) assert.throws(() => budget.claim(requestPhase, transport));
        else {
          admitted.push({ phase: requestPhase, transport });
          assert.equal(budget.claim(requestPhase, transport), admitted.length);
        }
      }
      if (refusal) failures[refusal]++;
      const counts = {};
      for (const item of admitted) counts[item.transport] = (counts[item.transport] ?? 0) + 1;
      assert.deepEqual(
        budget.snapshot(),
        {
          maxRequests,
          cleanupReserve,
          phase: cleaning ? "cleanup" : "observation",
          observation: admitted.filter((x) => x.phase === "observation").length,
          cleanup: admitted.filter((x) => x.phase === "cleanup").length,
          total: admitted.length,
          transports: counts,
          exhausted: failures.budget > 0,
          failures: { ...failures },
        },
        `run ${run}, step ${step}`,
      );
    }
  }
});
