// Transport-independent regressions. Real SDK wiring is tested with an instrumented
// transaction API; no claim about a running Firebase SDK or fireemu is made here.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createBudget, runCleanup, ownedPaths, ownerMarker, runCase } from './listen_collector.mjs';
import { createDeps } from './listen_sdk_adapter.mjs';

const nonce = 'a'.repeat(32);
const paths = ownedPaths(nonce, 'user-owned');
const limits = { reads: 100, writes: 10, deletes: 20, snapshots: 20, listeners: 3 };
const budget = (overrides = {}) => createBudget({ now: () => 0, deadlineMs: 5000, limits, ...overrides });
const absent = () => ({ exists: false, fields: null, updateTime: null });
const present = () => ({ exists: true, fields: { owner: ownerMarker(nonce) }, updateTime: 'version' });

for (const value of [{}, null, false, { exists: 0 }, { exists: 'false' },
  { exists: false, fields: { owner: 'still-present' } }, { exists: false, fromCache: true }]) {
  test(`invalid first read never becomes not-created: ${JSON.stringify(value)}`, async () => {
    let deletes = 0;
    const result = await runCleanup({ firestore: {
      getDoc: async () => value,
      deleteDoc: async () => { deletes += 1; },
      deleteOwnedDoc: async () => { deletes += 1; },
    } }, { client: 'primary', paths, nonce, budget: budget() });
    assert.equal(result.complete, false);
    assert.equal(result.rows.length, 5);
    assert.equal(deletes, 0);
  });
}

for (const value of [{}, null, { exists: 0 }, { exists: false, hasPendingWrites: true }]) {
  test(`invalid final read keeps recovery open: ${JSON.stringify(value)}`, async () => {
    const seen = new Set();
    const result = await runCleanup({ firestore: {
      getDoc: async (_c, path) => {
        if (seen.has(path)) return value;
        seen.add(path); return present();
      },
      deleteDoc: async () => {}, deleteOwnedDoc: async () => {},
    } }, { client: 'primary', paths, nonce, budget: budget() });
    assert.equal(result.complete, false);
    assert.equal(result.rows.length, 5);
  });
}

test('a failed final read is recorded and does not skip later owned resources', async () => {
  const seen = new Set(); const deleted = [];
  const result = await runCleanup({ firestore: {
    getDoc: async (_c, path) => {
      if (seen.has(path)) {
        if (path === paths.alpha) throw { code: 'unavailable' };
        return absent();
      }
      seen.add(path); return present();
    },
    deleteDoc: async (_c, path) => { deleted.push(path); },
    deleteOwnedDoc: async (_c, path) => { deleted.push(path); },
  } }, { client: 'primary', paths, nonce, budget: budget() });
  assert.equal(result.complete, false);
  assert.equal(result.rows.length, 5);
  assert.equal(deleted.length, 5);
  assert.equal(result.rows.filter(row => row.outcome === 'deleted-and-absent').length, 4);
});

test('cleanup refuses an adapter that can only issue unconditional deletes', async () => {
  let calls = 0;
  const result = await runCleanup({ firestore: {
    getDoc: async () => present(),
    deleteDoc: async () => { calls += 1; },
  } }, { client: 'primary', paths, nonce, budget: budget() });
  assert.equal(result.complete, false);
  assert.equal(calls, 0);
});

test('transactional ownership read is charged before the delete', async () => {
  let calls = 0;
  const b = budget({ limits: { ...limits, reads: 1 } });
  const result = await runCleanup({ firestore: {
    getDoc: async () => present(),
    deleteDoc: async () => { calls += 1; }, deleteOwnedDoc: async () => { calls += 1; },
  } }, { client: 'primary', paths, nonce, budget: b });
  assert.equal(result.complete, false);
  assert.equal(calls, 0);
});

for (const amount of [-1, NaN, Infinity, 0.5, '1', true, 0]) {
  test(`invalid budget charge cannot reduce or corrupt counts: ${String(amount)}`, () => {
    const b = budget(); const before = b.snapshot().used;
    assert.equal(b.charge('reads', amount).ok, false);
    assert.deepEqual(b.snapshot().used, before);
  });
}
for (const duration of [NaN, Infinity, -1, 0, '5000', true]) {
  test(`invalid budget duration refused: ${String(duration)}`, () => {
    assert.throws(() => budget({ deadlineMs: duration }));
  });
}
for (const cap of [NaN, Infinity, -1, '20', true, undefined]) {
  test(`invalid budget limit refused: ${String(cap)}`, () => {
    assert.throws(() => budget({ limits: { ...limits, reads: cap } }));
  });
}

test('budget limits are copied and prototype names cannot be charged', () => {
  const caps = { ...limits, reads: 1 }; const b = budget({ limits: caps });
  caps.reads = 100;
  assert.equal(b.charge('reads').ok, true);
  assert.equal(b.charge('reads').ok, false);
  assert.equal(b.charge('constructor').ok, false);
});

test('nonfinite or regressing clock permanently closes budget', () => {
  let clock = 10; const b = budget({ now: () => clock });
  clock = 9; assert.equal(b.charge('reads').ok, false);
  clock = 11; assert.equal(b.charge('reads').ok, false);
});

const fakeSdk = ({ owner = ownerMarker(nonce), exists = true } = {}) => {
  const calls = [];
  const sdk = {
    doc: (db, path) => ({ db, path }),
    getDoc: async () => { calls.push('cached-read'); return { exists: () => false }; },
    getDocFromServer: async () => {
      calls.push('server-read');
      return { exists: () => false, metadata: { fromCache: false, hasPendingWrites: false } };
    },
    deleteDoc: async () => { calls.push('unconditional-delete'); },
    runTransaction: async (db, fn, options) => {
      calls.push(['transaction', options]);
      return fn({
        get: async () => {
          calls.push('transaction-read');
          return { exists: () => exists, data: () => ({ owner }) };
        },
        delete: () => { calls.push('transaction-delete'); },
      });
    },
  };
  return { sdk, calls };
};

test('adapter cleanup reads the server, not a cache fallback', async () => {
  const { sdk, calls } = fakeSdk();
  await createDeps(sdk, { primary: { db: 'db' } }).firestore.getDoc('primary', paths.alpha);
  assert.deepEqual(calls, ['server-read']);
});

test('adapter ownership delete checks marker in a single-attempt transaction', async () => {
  const { sdk, calls } = fakeSdk();
  const deps = createDeps(sdk, { primary: { db: 'db' } });
  assert.equal(typeof deps.firestore.deleteOwnedDoc, 'function');
  await deps.firestore.deleteOwnedDoc('primary', paths.alpha, { owner: ownerMarker(nonce) });
  assert.deepEqual(calls, [['transaction', { maxAttempts: 1 }], 'transaction-read', 'transaction-delete']);
});

test('ownership changed after readback: no transaction delete or fallback', async () => {
  const { sdk, calls } = fakeSdk({ owner: 'foreign-owner' });
  const deps = createDeps(sdk, { primary: { db: 'db' } });
  assert.equal(typeof deps.firestore.deleteOwnedDoc, 'function');
  await assert.rejects(deps.firestore.deleteOwnedDoc('primary', paths.alpha, { owner: ownerMarker(nonce) }));
  assert.equal(calls.includes('transaction-delete'), false);
  assert.equal(calls.includes('unconditional-delete'), false);
});

test('an explicit unsupported version condition is rejected, never discarded', async () => {
  const { sdk, calls } = fakeSdk();
  const deps = createDeps(sdk, { primary: { db: 'db' } });
  await assert.rejects(deps.firestore.deleteDoc('primary', paths.alpha, { updateTime: 'v1' }));
  assert.equal(calls.includes('unconditional-delete'), false);
});

test('unsubscribe failure stays failed and retains its actual finalizer', async () => {
  let calls = 0;
  const b = budget();
  const deps = { now: () => 0, sleep: async () => {}, firestore: {
    onDocSnapshot: () => () => { calls += 1; throw new Error('unsubscribe failed'); },
  } };
  const result = await runCase(deps, {
    caseId: 'cleanup-error', role: 'observation', comparison: 'exact', expectedLocal: [],
    invariants: [], listeners: [{ name: 'primary', kind: 'document', target: 'alpha' }],
    steps: [{ kind: 'listen', listener: 'primary' }, { kind: 'unsubscribe', listener: 'primary' }],
  }, { client: 'primary', clients: {}, budget: b, nonce, paths, nameOf: x => x, stepTimeoutMs: 20, pollMs: 1 });
  assert.equal(result.complete, false);
  assert.equal(result.listenersClosed, false);
  assert.equal(calls, 2);
});

test('awaitServer cannot be satisfied by a terminal error callback', async () => {
  let clock = 0;
  const b = budget({ now: () => clock });
  const result = await runCase({ now: () => clock, sleep: async ms => { clock += ms; }, firestore: {
    onDocSnapshot: (_c, _p, _o, _n, onError) => { onError({ code: 'permission-denied' }); return () => {}; },
  } }, {
    caseId: 'await-server-error', role: 'observation', comparison: 'exact', expectedLocal: [],
    invariants: [], listeners: [{ name: 'primary', kind: 'document', target: 'alpha' }],
    steps: [{ kind: 'listen', listener: 'primary' }, { kind: 'awaitServer', listener: 'primary' }],
  }, { client: 'primary', clients: {}, budget: b, nonce, paths, nameOf: x => x, stepTimeoutMs: 2, pollMs: 1 });
  assert.equal(result.complete, false);
  assert.ok(result.failures.includes('step-timeout'));
});

test('repeated unsubscribe exercises the SDK finalizer, not a fabricated no-op', async () => {
  let calls = 0;
  const result = await runCase({ now: () => 0, sleep: async () => {}, firestore: {
    onDocSnapshot: () => () => { calls += 1; if (calls > 1) throw new Error('not idempotent'); },
  } }, {
    caseId: 'repeat-unsubscribe', role: 'observation', comparison: 'exact', expectedLocal: [],
    invariants: ['repeated-unsubscribe-is-a-no-op'],
    listeners: [{ name: 'primary', kind: 'document', target: 'alpha' }],
    steps: [{ kind: 'listen', listener: 'primary' }, { kind: 'unsubscribe', listener: 'primary' },
      { kind: 'unsubscribe', listener: 'primary', repeat: true }],
  }, { client: 'primary', clients: {}, budget: budget(), nonce, paths, nameOf: x => x, stepTimeoutMs: 2, pollMs: 1 });
  assert.equal(calls, 2);
  assert.equal(result.complete, false);
  assert.equal(result.invariantViolations.length, 1);
});

for (const endpoint of ['localhost:9000', 'example.invalid:9000', '127.0.0.1',
  '127.0.0.1:0', '127.0.0.1:65536', '127.0.0.1:09000', '127.0.0.1:9000/other',
  'user@127.0.0.1:9000', '127.0.0.1:9000#fragment', 'https://127.0.0.1:9000',
  '127.0.0.2:9000', '[::1]:9000?query', '::1:9000']) {
  test(`local SDK entry refuses ${endpoint} before SDK resolution`, async () => {
    const { main } = await import('./listen_sdk_adapter.mjs');
    for (const key of ['FIRESTORE_EMULATOR_HOST', 'FIREBASE_AUTH_EMULATOR_HOST']) {
      const env = { FIRESTORE_EMULATOR_HOST: '127.0.0.1:9000', FIREBASE_AUTH_EMULATOR_HOST: '[::1]:9001',
        O6_FIREBASE_MODULE_DIR: '/must-not-be-resolved', [key]: endpoint };
      await assert.rejects(main({ env, argv: ['node', 'adapter.mjs'] }), /numeric loopback emulator endpoint required/);
    }
  });
}

test('numeric IPv4 and bracketed IPv6 endpoints retain exact host and port', async () => {
  const { localEmulatorEndpoint } = await import('./listen_sdk_adapter.mjs');
  assert.deepEqual(localEmulatorEndpoint('127.0.0.1:9000'), { host: '127.0.0.1', port: 9000, origin: 'http://127.0.0.1:9000' });
  assert.deepEqual(localEmulatorEndpoint('[::1]:9001'), { host: '::1', port: 9001, origin: 'http://[::1]:9001' });
});

test('missing campaign is refused before resolving SDK or creating an account', async () => {
  const { main } = await import('./listen_sdk_adapter.mjs');
  await assert.rejects(main({ env: {
    FIRESTORE_EMULATOR_HOST: '127.0.0.1:9000', FIREBASE_AUTH_EMULATOR_HOST: '127.0.0.1:9001',
    O6_FIREBASE_MODULE_DIR: '/must-not-be-resolved', O6_REPO_ROOT: process.cwd(),
  }, argv: ['node', 'adapter.mjs'] }), /compiled campaign record/);
});
