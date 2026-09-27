import test from 'node:test';
import assert from 'node:assert/strict';

const module = await import('./wire_budget.mjs').catch(() => null);

test('wire budget reserves cleanup requests after observation is exhausted', () => {
  assert.equal(typeof module?.createWireBudget, 'function', 'wire budget is required');
  const budget = module.createWireBudget({ maxRequests: 5, cleanupReserve: 2 });
  budget.claim('observation', 'grpc');
  budget.claim('observation', 'auth');
  budget.claim('observation', 'grpc');
  assert.throws(() => budget.claim('observation', 'grpc'), /wire request budget exhausted/);
  budget.beginCleanup();
  budget.claim('cleanup', 'auth');
  budget.claim('cleanup', 'admin');
  assert.throws(() => budget.claim('cleanup', 'admin'), /wire request budget exhausted/);
  assert.deepEqual(budget.snapshot(), {
    maxRequests: 5,
    cleanupReserve: 2,
    phase: 'cleanup',
    observation: 3,
    cleanup: 2,
    total: 5,
    transports: { grpc: 2, auth: 2, admin: 1 },
    exhausted: true,
  });
});

test('wire budget rejects invalid bounds and phase changes without a claim', () => {
  assert.equal(typeof module?.createWireBudget, 'function', 'wire budget is required');
  for (const limits of [{ maxRequests: 0, cleanupReserve: 0 },
    { maxRequests: 3, cleanupReserve: 3 }, { maxRequests: 3.5, cleanupReserve: 1 },
    { maxRequests: 3, cleanupReserve: -1 }]) {
    assert.throws(() => module.createWireBudget(limits), /wire request bounds/);
  }
  const budget = module.createWireBudget({ maxRequests: 3, cleanupReserve: 1 });
  budget.claim('cleanup', 'grpc');
  assert.throws(() => budget.claim('observation', 'unknown'), /wire transport/);
  assert.equal(budget.snapshot().total, 1);
  budget.beginCleanup();
  assert.throws(() => budget.claim('observation', 'grpc'), /wire request phase/);
  assert.throws(() => budget.beginCleanup(), /wire request phase/);
  assert.equal(budget.snapshot().total, 1);
});

test('between-case cleanup can spend its reserve before later observation', () => {
  const budget = module.createWireBudget({ maxRequests: 5, cleanupReserve: 2 });
  budget.claim('observation', 'grpc');
  budget.claim('cleanup', 'grpc');
  budget.claim('observation', 'grpc');
  budget.claim('observation', 'auth');
  assert.throws(() => budget.claim('observation', 'grpc'), /wire request budget exhausted/);
  budget.beginCleanup();
  budget.claim('cleanup', 'admin');
  assert.equal(budget.snapshot().total, 5);
});
