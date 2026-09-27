import test from 'node:test';
import assert from 'node:assert/strict';
import { createWireBudget } from './wire_budget.mjs';

const module = await import('./wire_browser.mjs').catch(() => null);

const fakeRoute = url => {
  const calls = [];
  return { calls, request: () => ({ url: () => url }),
    continue: async () => calls.push('continue'), abort: async () => calls.push('abort') };
};

test('browser guard claims every allowed request before continuing', async () => {
  assert.equal(typeof module?.installBrowserWireGuard, 'function', 'browser wire guard is required');
  let handler;
  const context = { route: async (_pattern, callback) => { handler = callback; } };
  const budget = createWireBudget({ maxRequests: 3, cleanupReserve: 1 });
  let phase = 'observation';
  const guard = await module.installBrowserWireGuard({ context, budget, phase: () => phase,
    allowUrl: value => value.startsWith('http://127.0.0.1:') });
  const first = fakeRoute('http://127.0.0.1:1/page');
  const second = fakeRoute('http://127.0.0.1:2/Listen');
  const over = fakeRoute('http://127.0.0.1:2/Listen');
  await handler(first);
  await handler(second);
  await handler(over);
  assert.deepEqual(first.calls, ['continue']);
  assert.deepEqual(second.calls, ['continue']);
  assert.deepEqual(over.calls, ['abort']);
  assert.equal(guard.failure(), 'wire-request-budget');
  budget.beginCleanup();
  phase = 'cleanup';
  const cleanup = fakeRoute('http://127.0.0.1:2/cleanup');
  await handler(cleanup);
  assert.deepEqual(cleanup.calls, ['continue']);
  assert.equal(budget.snapshot().total, 3);
});

test('browser guard aborts an unexpected destination without spending budget', async () => {
  assert.equal(typeof module?.installBrowserWireGuard, 'function', 'browser wire guard is required');
  let handler;
  const context = { route: async (_pattern, callback) => { handler = callback; } };
  const budget = createWireBudget({ maxRequests: 3, cleanupReserve: 1 });
  const guard = await module.installBrowserWireGuard({ context, budget, phase: () => 'observation',
    allowUrl: value => value.startsWith('http://127.0.0.1:') });
  const unknown = fakeRoute('https://unapproved.example/path');
  await handler(unknown);
  assert.deepEqual(unknown.calls, ['abort']);
  assert.equal(guard.failure(), 'wire-destination');
  assert.equal(budget.snapshot().total, 0);
});
