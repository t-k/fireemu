import test from 'node:test';
import assert from 'node:assert/strict';
import { createWireBudget } from './wire_budget.mjs';

const module = await import('./wire_transport.mjs').catch(() => null);

test('Node guard claims gRPC streams and Auth fetches before transport calls', async () => {
  assert.equal(typeof module?.installNodeWireGuard, 'function', 'Node wire guard is required');
  const sent = [];
  const session = { request: headers => { sent.push(['grpc', headers]); return 'stream'; } };
  const originalRequest = session.request;
  const http2 = { connect: () => session };
  const globals = { fetch: async url => { sent.push(['auth', url]); return 'response'; } };
  const originalConnect = http2.connect;
  const originalFetch = globals.fetch;
  const budget = createWireBudget({ maxRequests: 3, cleanupReserve: 1 });
  let phase = 'observation';
  const guard = module.installNodeWireGuard({ http2, globals, budget, phase: () => phase });
  try {
    const active = http2.connect('http://127.0.0.1:1');
    assert.equal(active.request({ ':path': '/Listen' }), 'stream');
    assert.equal(await globals.fetch('http://127.0.0.1:2/auth'), 'response');
    assert.throws(() => active.request({ ':path': '/Listen' }), /wire request budget exhausted/);
    assert.equal(sent.length, 2);
    budget.beginCleanup();
    phase = 'cleanup';
    assert.equal(await globals.fetch('http://127.0.0.1:2/cleanup'), 'response');
    assert.deepEqual(budget.snapshot().transports, { grpc: 1, auth: 2 });
  } finally {
    guard.close();
  }
  assert.equal(http2.connect, originalConnect);
  assert.equal(globals.fetch, originalFetch);
  assert.equal(session.request, originalRequest);
});

test('Node guard rejects unknown destinations before any wire claim', async () => {
  assert.equal(typeof module?.installNodeWireGuard, 'function', 'Node wire guard is required');
  const budget = createWireBudget({ maxRequests: 3, cleanupReserve: 1 });
  const http2 = { connect: () => ({ request: () => 'stream' }) };
  const globals = { fetch: async () => 'response' };
  const guard = module.installNodeWireGuard({ http2, globals, budget,
    phase: () => 'observation', allowUrl: url => url.startsWith('http://127.0.0.1:') });
  try {
    assert.throws(() => http2.connect('https://example.com'), /wire destination/);
    await assert.rejects(globals.fetch('https://example.com/auth'), /wire destination/);
    assert.equal(budget.snapshot().total, 0);
  } finally {
    guard.close();
  }
});
