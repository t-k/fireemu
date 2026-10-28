import test from 'node:test';
import assert from 'node:assert/strict';
import { validateSdkNext, judgeRuns } from './rtdb-residual-judge.mjs';
import { readFileSync } from 'node:fs';

const shape = (v) => JSON.stringify(v);
const row = (type, label, value, extra = {}) => ({ type, label, shape: shape(value), ...extra });
const good = () => [
  row('push', 'a', { label: 'a' }, { key: 'push-a' }), row('push', 'b', { label: 'b' }, { key: 'push-b' }),
  row('get', 'update-preserves-sibling', { keep: 1, edit: 2 }), row('get', 'set-replaces-node', { edit: 3 }),
  row('get', 'atomic-multipath-final', { x: 1, y: 2 }), row('get', 'server-values', { numeric: 12, absent: 5, string: 5, at: 1000 }),
  row('interval', 'server-timestamp', { before: 999, after: 1001, value: 1000 }),
  row('transaction', 'abort', { callbacks: [3], committed: false, value: 3 }), row('transaction', 'applyLocally-false', { callbacks: [4], committed: true, value: 5 }),
  ...['child_added', 'child_changed', 'child_moved'].map((type) => ({ type, key: 'b', prev: 'a' })),
  { step: 'attach', type: 'child_added', label: 'items', key: 'b', prev: 'a' }, { step: 'attach', type: 'child_added', label: 'items', key: 'c', prev: 'b' },
  ...Array.from({ length: 19 }, (_, i) => ({ type: 'operation', code: String(i + 1) })), { type: 'gap', label: 'transaction-retry', code: 'unobserved' },
];

test('typed obligations and unresolved retry', () => {
  assert.deepEqual(validateSdkNext(good()), { valid: true, errors: [], retry: 'unobserved', verdict: 'needs-review' });
  const profiles = ['r1-ws', 'r2-ws', 'r1-lp', 'r2-lp'].map((name) => ({ scenario: 'sdk-next', name, journal: good() }));
  assert.equal(judgeRuns(profiles, profiles).verdict, 'needs-review');
});

test('missing, typed, key, time, failure and cap mutations are rejected', () => {
  const mutations = [
    (a) => a.splice(0, 1), (a) => { a[1].key = a[0].key; }, (a) => { a[4].shape = shape({ x: 1 }); },
    (a) => { a[5].shape = shape({ numeric: '12', absent: 5, string: 5, at: 1000 }); },
    (a) => { a[6].shape = shape({ before: 1, after: 2, value: 900000 }); },
    (a) => a.push({ type: 'error' }), (a) => a.push({ type: 'operation', code: '25' }),
    (a) => a.splice(a.findIndex((r) => r.label === 'transaction-retry'), 1),
  ];
  for (const mutate of mutations) { const rows = good(); mutate(rows); assert.equal(validateSdkNext(rows).valid, false); }
});

test('script uses fixed cap and no fetch or disconnect recapture', () => {
  const source = readFileSync(new URL('./rtdb-residual-page.js', import.meta.url), 'utf8').split('  async function sdkNext() {')[1].split('  async function cv08() {')[0];
  assert.match(source, /\+\+operations > 24/);
  assert.doesNotMatch(source, /\bfetch\s*\(|onDisconnect|goOffline/);
  assert.match(source, /finally \{ for \(const off of unsubs\) off\(\); \}/);
});

test('actual page fails closed and deletes apps when the first SDK write rejects', async () => {
  const vm = await import('node:vm');
  let deleted = 0, calls = 0;
  const events = [];
  const D = { forceWebSockets() {}, forceLongPolling() {}, getDatabase: () => ({}), ref: (_, path) => ({ path }), set: async () => { calls++; throw Error('write failed'); } };
  const source = readFileSync(new URL('./rtdb-residual-page.js', import.meta.url), 'utf8')
    .replace(/^import .*firebase-app\.js';$/m, '')
    .replace(/^import .*firebase-database\.js';$/m, '');
  const context = { window: { __rrEvent: (r) => events.push(r) }, D, initializeApp: () => ({}), deleteApp: async () => { deleted++; }, performance, setTimeout, Date };
  vm.runInNewContext(source, context);
  await assert.rejects(context.window.__rrRun({ scenario: 'sdk-next', transport: 'ws', base: 'test', name: 'r1-ws' }), /write failed/);
  assert.equal(calls, 1);
  assert.equal(deleted, 2);
  assert.equal(events.filter((r) => r.type === 'operation').length, 1);
  assert.equal(events.some((r) => r.type === 'done'), false);
});

test('generated PICT rows exercise positive and negative obligations', () => {
  const matrix = process.env.SDK_NEXT_PICT;
  if (!matrix) return;
  const lines = readFileSync(matrix, 'utf8').trim().split(/\r?\n/);
  const header = lines.shift().split('\t');
  for (const line of lines) {
    const cells = line.split('\t');
    const axes = Object.fromEntries(header.map((key, i) => [key, cells[i]]));
    const rows = good();
    if (axes.Outcome === 'failure') rows.push({ type: 'error' });
    if (axes.Outcome === 'cap') rows.push({ type: 'operation', code: '25' });
    assert.equal(validateSdkNext(rows).valid, axes.Outcome === 'success', JSON.stringify(axes));
  }
});

test('typed increment witness rejects alternate numeric and string values', () => {
  for (let n = -20; n <= 30; n++) {
    for (const value of [n, String(n)]) {
      const rows = good();
      rows.find((r) => r.label === 'server-values').shape = shape({ numeric: value, absent: 5, string: 5, at: 1000 });
      assert.equal(validateSdkNext(rows).valid, value === 12);
    }
  }
});

test('production selection is one fixed packet scenario and invalid profiles stop the loop', () => {
  const source = readFileSync(new URL('./rtdb-residual.mjs', import.meta.url), 'utf8');
  assert.match(source, /packet\.scenario !== 'sdk-next'/);
  assert.match(source, /o\.packet\?\.scenario === 'sdk-next' \? \['sdk-next'\]/);
  assert.match(source, /!validateSdkNext\(out\.journal\)\.valid/);
  assert.match(source, /if \(run\.errors\.length \|\| o\.stop\?\.requested\) break/);
});

test('fixed script completes against a deterministic offline SDK double', async () => {
  const vm = await import('node:vm');
  const events = [], listeners = [], child = new Map();
  let tree = {}, deleted = 0, serial = 0;
  const parts = (ref) => ref.path.split('/').filter(Boolean).slice(1);
  const read = (ref) => parts(ref).reduce((v, k) => v?.[k], tree) ?? null;
  const snapshot = (key, val) => ({ key, val: () => val });
  const assign = (ref, value) => {
    const ps = parts(ref); if (!ps.length) { tree = value; return; }
    let node = tree; for (const p of ps.slice(0, -1)) node = node[p] ??= {};
    node[ps.at(-1)] = value;
  };
  const publish = () => { for (const [r, cb] of listeners) cb(snapshot(null, read(r))); };
  const D = {
    forceWebSockets() {}, forceLongPolling() {}, getDatabase: () => ({}), ref: (_, path) => ({ path }),
    query: (r) => r, orderByChild: () => ({}),
    onChildAdded: (_, cb) => { for (const [key, prev] of [['a', null], ['b', 'a'], ['c', 'b']]) cb(snapshot(key, tree.items[key]), prev); return () => {}; },
    onChildChanged: (_, cb) => { child.set('changed', cb); return () => {}; },
    onChildMoved: (_, cb) => { child.set('moved', cb); return () => {}; },
    onChildRemoved: () => () => {},
    onValue: (r, cb) => { const entry = [r, cb]; listeners.push(entry); cb(snapshot(null, read(r))); return () => { listeners.splice(listeners.indexOf(entry), 1); }; },
    set: async (r, v) => { assign(r, v); publish(); },
    get: async (r) => snapshot(r.path.split('/').at(-1), structuredClone(read(r))),
    push: () => ({ key: `key${++serial}`, path: `test/list/key${serial}` }),
    increment: (n) => ({ increment: n }), serverTimestamp: () => ({ timestamp: true }),
    update: async (r, patch) => {
      for (const [p, v] of Object.entries(patch)) {
        const target = { path: `${r.path}/${p}` }, old = read(target);
        assign(target, v?.timestamp ? Date.now() : v?.increment ? (typeof old === 'number' ? old : 0) + v.increment : v);
      }
      if (r.path.endsWith('items/b')) {
        if ('note' in patch) child.get('changed')?.(snapshot('b', structuredClone(tree.items.b)), 'a');
        if ('score' in patch) child.get('moved')?.(snapshot('b', structuredClone(tree.items.b)), 'c');
      }
      publish();
    },
    runTransaction: async (r, f) => { const old = read(r), next = f(old); if (next !== undefined) { assign(r, next); publish(); } return { committed: next !== undefined, snapshot: snapshot(null, read(r)) }; },
  };
  const source = readFileSync(new URL('./rtdb-residual-page.js', import.meta.url), 'utf8').replace(/^import .*firebase-app\.js';$/m, '').replace(/^import .*firebase-database\.js';$/m, '');
  const context = { window: { __rrEvent: (r) => events.push(r) }, D, initializeApp: () => ({}), deleteApp: async () => { deleted++; }, performance, setTimeout, Date };
  vm.runInNewContext(source, context);
  await context.window.__rrRun({ scenario: 'sdk-next', transport: 'ws', base: 'test', name: 'r1-ws', waitScale: 0.001 });
  assert.equal(validateSdkNext(events).valid, true, JSON.stringify(validateSdkNext(events).errors));
  assert.equal(events.filter((r) => r.type === 'operation').length, 19);
  assert.equal(deleted, 2);
  assert.equal(listeners.length, 0);
});
