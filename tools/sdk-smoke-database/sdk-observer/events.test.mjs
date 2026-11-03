// The events and admin suite code without a database: the recorder (events-sequence.mjs) against a scripted fake SDK,
// the case table (events-actor.mjs), the admin adapter and profile (admin-suite.mjs) and the Rules (events-rules.mjs).
import test from 'node:test';
import assert from 'node:assert/strict';

import { createLog, errorCode, quiesce, runCase, runEventsProfile, shapeOf, waitUntil } from './events-sequence.mjs';
import { CHILD_KINDS, EVENT_CASES, PRIORITY_SEED, SEED, eventCases } from './events-actor.mjs';
import { ADMIN_CASES, adminAdapter, adminCases, runAdminProfile } from './admin-suite.mjs';
import { suiteRules } from './events-rules.mjs';
import { withTimeout } from './sequence.mjs';

const sleep = ms => new Promise(r => setTimeout(r, ms));
/** A snapshot of a plain value: children in insertion order, priority from `.priority`. */
function snap(key, value) {
  const hasKids = value !== null && typeof value === 'object' && Object.keys(value).some(k => !k.startsWith('.'));
  return {
    key, exists: () => value !== null && value !== undefined, val: () => value ?? null, exportVal: () => value ?? null, hasChildren: () => hasKids, getPriority: () => (value && typeof value === 'object' ? value['.priority'] ?? null : null),
    forEach(f) { if (hasKids) for (const [k, v] of Object.entries(value)) if (!k.startsWith('.')) f(snap(k, v)); },
  };
}
/** A fake modular SDK: listeners by label of the target path; `fire(path, kind, snapshot, prev)` raises a callback. */
function fakeD() {
  const live = [], calls = [];
  const register = kind => (target, cb, cancel) => { const l = { path: target.path, kind, cb, cancel }; live.push(l); calls.push(`on ${kind} ${target.path}`); return () => { live.splice(live.indexOf(l), 1); calls.push(`off ${kind} ${target.path}`); }; };
  return {
    live, calls,
    fire: (path, kind, s, prev) => { for (const l of live.filter(x => x.path === path && x.kind === kind)) l.cb(s, prev); },
    deny: (path, error) => { for (const l of live.filter(x => x.path === path)) l.cancel(error); },
    onValue: register('value'), onChildAdded: register('child_added'), onChildChanged: register('child_changed'), onChildMoved: register('child_moved'), onChildRemoved: register('child_removed'),
    runTransaction: null,
  };
}
const ref = path => ({ path });
const at = { w: ref, o: ref, t: ref };
const timing = (extra = {}) => ({ now: () => Date.now(), sleep, stepMs: 400, quietMs: 30, maxMs: 300, ...extra });
const later = (ms, f) => setTimeout(f, ms);

test('shapeOf: ordered children with exported values, the priority when set, or the exported leaf; errorCode keeps codes only', () => {
  assert.deepEqual(shapeOf(snap('k', { b: 1, a: { '.value': 2, '.priority': 3 } })), { children: [['b', 1], ['a', { '.value': 2, '.priority': 3 }]] });
  assert.deepEqual(shapeOf(snap('k', { a: 1, '.priority': 4 })), { children: [['a', 1]], priority: 4 });
  assert.deepEqual(shapeOf(snap('k', 5)), { leaf: 5 }); assert.deepEqual(shapeOf(snap('k', null)), { leaf: null });
  assert.equal(errorCode({ code: 'PERMISSION_DENIED' }), 'PERMISSION_DENIED'); assert.equal(errorCode(new Error('permission_denied at /p/q')), 'permission-denied');
  assert.equal(errorCode(new Error('boom /sdkevents123')), 'other'); assert.equal(errorCode(Object.assign(new Error('x'), { name: 'Timeout' })), 'timeout');
});
test('quiesce: true once nothing was recorded for quietMs, false when callbacks keep coming past maxMs; it never returns before quietMs', async () => {
  let t = 0; const now = () => t, tick = async () => { t += 10; };
  const log = createLog(now);
  assert.equal(await quiesce(log, { quietMs: 100, maxMs: 1000, now, sleep: tick }), true); assert.equal(t, 100);
  t = 0; const busy = createLog(now); const s = async () => { t += 10; busy.touch(); };
  assert.equal(await quiesce(busy, { quietMs: 100, maxMs: 500, now, sleep: s }), false); assert.equal(t, 500);
  t = 0; const late = createLog(now); let n = 0; const once = async () => { t += 10; if (++n === 5) late.touch(); };
  assert.equal(await quiesce(late, { quietMs: 100, maxMs: 1000, now, sleep: once }), true); assert.equal(t, 150);
  t = 0; assert.equal(await waitUntil(() => t >= 60, 100, { now, sleep: tick }), true); t = 0; assert.equal(await waitUntil(() => false, 100, { now, sleep: tick }), false);
});

test('runCase: attach waits for every value listener, then each step owns the callbacks that arrive until the next step starts', async () => {
  const D = fakeD();
  const spec = { id: 'x', listeners: [{ label: 'L', path: 'p', query: null, kinds: ['value', 'child_added'] }, { label: 'M', path: 'q', query: r => ({ path: `${r.path}?` }), kinds: ['value'] }], steps: [
    { kind: 'attach', label: 'attach' },
    { kind: 'write', label: 'w1', run: w => { assert.equal(w('p').path, 'p'); later(5, () => D.fire('p', 'child_added', snap('a', 1), null)); later(15, () => D.fire('p', 'value', snap('p', { a: 1 }))); return Promise.resolve(); } },
    { kind: 'write', label: 'w2', run: () => Promise.resolve() },
  ] };
  later(10, () => D.fire('p', 'value', snap('p', null))); later(40, () => D.fire('q?', 'value', snap('q', 3)));
  const row = await runCase(spec, { D, at, timing: timing() });
  assert.equal(row.ok, true);
  assert.deepEqual(row.steps, [
    { step: 'attach', observer: [{ l: 'L', e: 'value', k: 'p', v: { leaf: null } }, { l: 'M', e: 'value', k: 'q', v: { leaf: 3 } }], writer: [], ready: true, quiet: true },
    { step: 'w1', observer: [{ l: 'L', e: 'child_added', k: 'a', p: null, v: 1 }, { l: 'L', e: 'value', k: 'p', v: { children: [['a', 1]] } }], writer: [], ack: 'ok', quiet: true },
    { step: 'w2', observer: [], writer: [], ack: 'ok', quiet: true },
  ]);
  assert.equal(D.live.length, 0, 'every listener is detached at the end');
});
test('runCase: bounds are recorded, never guessed: a value that never comes (ready false), callbacks that never stop (quiet false)', async () => {
  const D = fakeD(); let timer;
  const spec = { id: 'x', listeners: [{ label: 'L', path: 'p', query: null, kinds: ['value'] }], steps: [{ kind: 'attach', label: 'attach' }, { kind: 'write', label: 'storm', run: () => { timer = setInterval(() => D.fire('p', 'value', snap('p', 1)), 10); return Promise.resolve(); } }] };
  const row = await runCase(spec, { D, at, timing: { ...timing(), stepMs: 80 } }); clearInterval(timer);
  assert.equal(row.steps[0].ready, false); assert.equal(row.steps[0].quiet, true); assert.equal(row.steps[1].quiet, false); assert.ok(row.steps[1].observer.length > 5);
});
test('runCase: a rejected or hanging write and a failed get are recorded as answers; a cancel counts as the first value', async () => {
  const D = fakeD();
  const spec = { id: 'x', listeners: [{ label: 'L', path: 'p', query: null, kinds: ['value'] }], steps: [
    { kind: 'attach', label: 'attach' },
    { kind: 'write', label: 'denied', run: () => Promise.reject(Object.assign(new Error('x'), { code: 'PERMISSION_DENIED' })) },
    { kind: 'write', label: 'hang', run: () => new Promise(() => {}) },
    { kind: 'get', label: 'get', run: () => Promise.resolve(snap('g', { a: 1 })) },
    { kind: 'get', label: 'get-denied', run: () => Promise.reject(new Error('Permission denied')) },
    { kind: 'call', label: 'call', run: async () => ({ key: 'push-id' }) },
  ] };
  later(5, () => D.deny('p', new Error('permission_denied')));
  const row = await runCase(spec, { D, at, timing: { ...timing(), stepMs: 100 } });
  assert.deepEqual(row.steps.map(s => s.ack ?? s.result ?? s.ready), [true, { error: 'PERMISSION_DENIED' }, { error: 'timeout' }, { exists: true, v: { children: [['a', 1]] } }, { error: 'permission-denied' }, { key: 'push-id' }]);
  assert.deepEqual(row.steps[0].observer, [{ l: 'L', e: 'cancel', code: 'permission-denied' }]);
});
test('runCase: a transaction records the updater inputs, then the writer listener events and the resolution in their order, and detaches its listener', async () => {
  const D = fakeD();
  D.runTransaction = (r, update) => new Promise(resolve => {
    const first = update(null), second = update({ n: 1 });
    D.fire('t', 'value', snap('t', second));
    later(5, () => { D.fire('t', 'value', snap('t', second)); resolve({ committed: first !== undefined, snapshot: snap('t', second) }); });
  });
  const spec = { id: 'x', listeners: [], steps: [{ kind: 'transaction', label: 'txn', path: 't', update: v => ({ n: (v?.n ?? 0) + 1 }) }] };
  later(5, () => D.fire('t', 'value', snap('t', null)));
  const row = await runCase(spec, { D, at, timing: timing() });
  assert.deepEqual(row.steps[0], { step: 'txn', observer: [], writer: [{ l: 'W', e: 'value', k: 't', v: { leaf: null } }, { l: 'W', e: 'value', k: 't', v: { children: [['n', 2]] } }, { l: 'W', e: 'value', k: 't', v: { children: [['n', 2]] } }, { l: 'txn', e: 'resolved' }], ready: true, result: { inputs: [null, { n: 1 }], committed: true, snapshot: { children: [['n', 2]] } }, quiet: true });
  assert.deepEqual(D.calls, ['on value t', 'off value t']);
  D.runTransaction = () => Promise.reject(new Error('Permission denied'));
  later(5, () => D.fire('t', 'value', snap('t', null)));
  const failed = await runCase(spec, { D, at, timing: timing() });
  assert.deepEqual([failed.steps[0].result, failed.steps[0].writer.at(-1)], [{ inputs: [], error: 'permission-denied' }, { l: 'txn', e: 'rejected' }]);
});
test('runCase: a recorder fault inside a callback is recorded, not thrown into the SDK; an unknown step kind fails the case with the steps so far and still detaches', async () => {
  const D = fakeD();
  const bad = { key: 'k', exportVal: () => { throw new Error('No index defined for t'); }, hasChildren: () => false };
  const spec = { id: 'x', listeners: [{ label: 'L', path: 'p', query: null, kinds: ['value', 'child_added'] }], steps: [{ kind: 'attach', label: 'attach' }, { kind: 'teleport', label: 'nope' }] };
  later(5, () => D.fire('p', 'child_added', bad, null)); later(8, () => D.fire('p', 'value', snap('p', 1)));
  const row = await runCase(spec, { D, at, timing: timing() });
  assert.equal(row.ok, false); assert.match(row.error, /unknown step kind teleport/); assert.equal(row.steps.length, 2);
  assert.deepEqual(row.steps[0].observer[0], { l: 'L', e: 'recorder-error', error: 'No index defined for t' }); assert.equal(D.live.length, 0);
});

// ---- the profile --------------------------------------------------------------------------------------------------------------------
function fakeApp({ rootValue = null, failSeed = false, hangSeed = false } = {}) {
  const D = fakeD(), log = [];
  Object.assign(D, {
    forceWebSockets: () => log.push('forceWebSockets'), forceLongPolling: () => log.push('forceLongPolling'),
    getDatabase: app => ({ app }), ref: (db, p) => ({ path: p, app: db.app }), child: (r, p) => ({ path: `${r.path}/${p}`, app: r.app }),
    get: r => { log.push(`get ${r.app}`); return Promise.resolve(snap('x', rootValue)); },
    set: r => { log.push(`set ${r.path}`); return hangSeed ? new Promise(() => {}) : failSeed ? Promise.reject(new Error('denied')) : Promise.resolve(); },
    setWithPriority: r => { log.push(`setWithPriority ${r.path}`); return Promise.resolve(); },
  });
  const A = { initializeApp: (opts, name) => { log.push(`init ${name} ${opts.databaseURL}`); return name; }, deleteApp: name => { log.push(`delete ${name}`); return Promise.resolve(); } };
  return { D: new Proxy(D, { get: (t, n) => (n in t ? t[n] : () => null) }), A, log };   // query constructors are only stored by the case table
}
const cfg = (extra = {}) => ({ projectId: 'demo-x', databaseURL: 'http://127.0.0.1:9000?ns=n', local: true, scope: 'pre/sdk-events/r1-lp', transport: 'lp', name: 'r1-lp', closeMs: 50, ...extra });
test('profile: the writer connects over WebSocket before the long-polling switch; then the observer and the transaction writer start; apps are deleted', async () => {
  const { D, A, log } = fakeApp(), rows = [];
  const out = await runEventsProfile({ D, A, cfg: cfg(), emit: r => rows.push(r), cases: [] });
  assert.deepEqual(log.slice(0, 4), ['forceWebSockets', 'init events-writer-r1-lp http://127.0.0.1:9000?ns=n', 'get events-writer-r1-lp', 'forceLongPolling']);
  assert.deepEqual(log.slice(4, 7), ['init events-observer-r1-lp http://127.0.0.1:9000?ns=n', 'init events-txn-r1-lp http://127.0.0.1:9000?ns=n', 'get events-observer-r1-lp']);
  assert.deepEqual(log.filter(l => l.startsWith('set')), ['set pre/sdk-events/r1-lp', ...PRIORITY_SEED.map(([k]) => `setWithPriority pre/sdk-events/r1-lp/pw/${k}`)]);
  assert.deepEqual(log.slice(-3), ['delete events-writer-r1-lp', 'delete events-observer-r1-lp', 'delete events-txn-r1-lp']);
  assert.deepEqual(out.map(r => r.id), ['startup', 'startup-observer', 'seed']); assert.deepEqual(rows.map(r => [r.kind, r.suite]), Array(3).fill(['case', 'events']));
  const ws = fakeApp(); await runEventsProfile({ D: ws.D, A: ws.A, cfg: cfg({ transport: 'ws', name: 'r2-ws' }), cases: [] });
  assert.equal(ws.log.includes('forceLongPolling'), false);
});
test('profile: a non-empty scope or a failed seed stops it before any case; a bad binding is refused before any app exists', async () => {
  const dirty = fakeApp({ rootValue: { left: 1 } }), r1 = await runEventsProfile({ D: dirty.D, A: dirty.A, cfg: cfg() });
  assert.deepEqual(r1, [{ id: 'startup', ok: false, error: 'Error: startup root is not empty' }]); assert.ok(dirty.log.includes('delete events-writer-r1-lp'));
  const seed = fakeApp({ failSeed: true }), r2 = await runEventsProfile({ D: seed.D, A: seed.A, cfg: cfg() });
  assert.deepEqual(r2.map(r => [r.id, r.ok]), [['startup', true], ['startup-observer', true], ['seed', false]]);
  for (const bad of [{ databaseURL: 'http://example.com' }, { databaseURL: 'http://127.0.0.1:1', local: false }, { scope: '../x' }, { transport: 'sse' }, { name: 'r3-ws' }, { projectId: 'A' }]) {
    const f = fakeApp(); await assert.rejects(runEventsProfile({ D: f.D, A: f.A, cfg: cfg(bad) }), /Invalid events binding/, JSON.stringify(bad)); assert.deepEqual(f.log, []);
  }
});

// ---- the case table --------------------------------------------------------------------------------------------------------------------
test('the case table: eight cases in a fixed order, listeners with the five callbacks, each step labelled once', () => {
  const D = new Proxy({}, { get: (_, name) => (...args) => ({ name, args }) }), specs = eventCases(D);
  assert.deepEqual(specs.map(s => s.id), EVENT_CASES);
  for (const s of specs) { const labels = s.steps.map(x => x.label); assert.equal(new Set(labels).size, labels.length, s.id); }
  assert.deepEqual(specs[0].listeners.map(l => [l.label, l.path, l.kinds]), [['Q1', 'kw', CHILD_KINDS], ['Q2', 'kw', CHILD_KINDS]]);
  assert.deepEqual(specs.find(s => s.id === 'fanout').listeners.map(l => [l.label, l.path, l.kinds.length]), [['FO', 'fo', 1], ['FX', 'fo/x', 5], ['FY', 'fo/y', 1]]);
  assert.deepEqual(Object.keys(SEED), ['kw', 'vr', 'eq', 'cp', 'fo', 'tb', 'tc', 'ge']);
});
test('the case table: the writes are the ones the plan names (paths and values)', async () => {
  const D = new Proxy({}, { get: (_, name) => (...args) => ({ name, args: args.map(a => a?.path ?? a) }) }), specs = eventCases(D), w = p => ({ path: p });
  const writes = Object.fromEntries(specs.map(s => [s.id, s.steps.filter(x => x.kind === 'write').map(x => x.run(w))]));
  assert.deepEqual(writes.key_window, [{ name: 'set', args: ['kw/a', 1] }, { name: 'set', args: ['kw/f', 1] }, { name: 'remove', args: ['kw/a'] }, { name: 'set', args: ['kw/b', 2] }]);
  assert.deepEqual(writes.priority_window, [{ name: 'setPriority', args: ['pw/z', 0] }, { name: 'setPriority', args: ['pw/x', 10] }, { name: 'setWithPriority', args: ['pw/v', 5, 1.5] }, { name: 'remove', args: ['pw/y'] }]);
  assert.deepEqual(writes.value_range.map(x => x.args), [['vr/a', 6], ['vr/b', 20], ['vr/c', 5], ['vr/c']]);
  assert.deepEqual(writes.equal_events.map(x => x.args), [['eq/p/t', 2], ['eq/q/t', 3], ['eq/p/t', 2], ['eq/p', { t: 2, u: 1 }]]);
  assert.deepEqual(writes.fanout, [{ name: 'update', args: ['', { 'fo/x/n': 2, 'fo/y/n': 2, 'fo/z': 2 }] }, { name: 'set', args: ['fo', { x: { n: 3 }, w: 1 }] }]);
  const txn = specs.find(s => s.id === 'transactions').steps.filter(x => x.kind === 'transaction');
  assert.deepEqual(txn.map(x => [x.label, x.path, x.update({ n: 1 }), x.update(null)]), [['absent', 'ta', 1, 1], ['abort', 'tb', undefined, undefined], ['object', 'tc', { n: 2 }, { n: 1 }]]);
});

// ---- admin --------------------------------------------------------------------------------------------------------------------------------
function fakeQuery() {
  const handlers = [];
  return { handlers, on(event, f, cancel) { handlers.push([event, f, cancel]); return f; }, off(event, f) { const i = handlers.findIndex(h => h[0] === event && h[1] === f); if (i >= 0) handlers.splice(i, 1); } };
}
test('admin adapter: the modular calls map to the namespaced on/off with the same handler, and to ref.transaction', async () => {
  const q = fakeQuery(), seen = [];
  const off = adminAdapter.onChildAdded(q, (s, prev) => seen.push([s, prev]), () => {});
  assert.equal(q.handlers[0][0], 'child_added'); q.handlers[0][1]('S', 'P'); assert.deepEqual(seen, [['S', 'P']]); off(); assert.equal(q.handlers.length, 0);
  for (const [name, event] of [['onValue', 'value'], ['onChildChanged', 'child_changed'], ['onChildMoved', 'child_moved'], ['onChildRemoved', 'child_removed']]) { const o = adminAdapter[name](q, () => {}, () => {}); assert.equal(q.handlers.at(-1)[0], event); o(); }
  assert.equal(await adminAdapter.runTransaction({ transaction: f => Promise.resolve(f(4)) }, v => v + 1), 5);
});
test('admin profile: startup reads the scope; a non-empty scope stops it, a failed read is recorded and the cases still run', async () => {
  const db = value => ({ ref: p => ({ path: p, get: () => (value instanceof Error ? Promise.reject(value) : Promise.resolve(snap('s', value))), child: c => ({ path: `${p}/${c}` }) }) });
  assert.deepEqual(await runAdminProfile({ db: db({ x: 1 }), cfg: { scope: 'pre/sdk-admin/r1-admin', name: 'r1-admin' } }), [{ id: 'startup', ok: false, error: 'Error: startup root is not empty' }]);
  const rows = [], out = await runAdminProfile({ db: db(new Error('permission_denied')), cfg: { scope: 'pre/sdk-admin/r1-admin', name: 'r1-admin' }, emit: r => rows.push(r), cases: [] });
  assert.equal(out[0].ok, false); assert.equal(rows[0].suite, 'admin');
  await assert.rejects(runAdminProfile({ db: db(null), cfg: { scope: 'pre', name: 'r1-ws' } }), /Invalid admin binding/);
  assert.deepEqual(adminCases().map(c => c.id), ADMIN_CASES);
});
test('admin push records the key shape only, never the key', async () => {
  const push = adminCases().find(c => c.id === 'push').steps[0];
  const w = () => ({ push: () => ({ key: '-OabcdefghijklmnopqR', set: () => Promise.resolve(), get: () => Promise.resolve(snap('k', 'p1')) }) });
  assert.deepEqual(await push.run(w), { key: 'push-id', v: { leaf: 'p1' } });
  const odd = () => ({ push: () => ({ key: 'short', set: () => Promise.resolve(), get: () => Promise.resolve(snap('k', 'p1')) }) });
  assert.deepEqual(await push.run(odd), { key: 'other-5', v: { leaf: 'p1' } });
});

// ---- Rules --------------------------------------------------------------------------------------------------------------------------------
test('suite Rules: deny everywhere except the profile scopes; events scopes open with their indexes, admin scopes denied', () => {
  const { rules } = suiteRules(['events', 'admin'], '/p/q');
  assert.deepEqual([rules['.read'], rules['.write']], [false, false]);
  assert.deepEqual(Object.keys(rules.p.q), ['sdk-events', 'sdk-admin']);
  assert.deepEqual(rules.p.q['sdk-events']['r2-lp'], { '.read': true, '.write': true, vr: { '.indexOn': '.value' }, eq: { '.indexOn': 't' }, cp: { '.indexOn': 's' } });
  assert.deepEqual(rules.p.q['sdk-admin']['r1-admin'], { '.read': false, '.write': false, w: { '.indexOn': 's' }, deny: { '.read': false, '.write': false } });
  assert.deepEqual(Object.keys(suiteRules(['admin'], '/p').rules.p), ['sdk-admin']);
  for (const [suites, prefix] of [[['events'], 'p'], [['events'], '/a/../b'], [['events'], '/__proto__'], [[], '/p'], [['small'], '/p'], [['events', 'events'], '/p'], ['events', '/p'], [['events'], `/${'a'.repeat(300)}`]])
    assert.throws(() => suiteRules(suites, prefix), undefined, JSON.stringify([suites, prefix]));
});
test('withTimeout is the one deadline wrapper the suites share', async () => { await assert.rejects(withTimeout(10, 'x', new Promise(() => {})), /x timed out/); });

// ---- mutation run 1 (2026-11-04) ----
test('shapeOf: an undefined export is recorded as a null leaf', () => {
  assert.deepEqual(shapeOf({ hasChildren: () => false, exportVal: () => undefined }), { leaf: null });
});
test('quiesce: a callback long before the call still waits quietMs from the call', async () => {
  let t = 1000; const now = () => t, log = createLog(() => 0);
  assert.equal(await quiesce(log, { quietMs: 100, maxMs: 1000, now, sleep: async () => { t += 10; } }), true); assert.equal(t, 1100);
});
test('runCase: prevName is null when the SDK passes none; child_removed carries no prevName; a get of a missing path says exists false', async () => {
  const D = fakeD();
  const spec = { id: 'x', listeners: [{ label: 'L', path: 'p', query: null, kinds: ['value', 'child_added', 'child_removed'] }], steps: [{ kind: 'attach', label: 'attach' }, { kind: 'get', label: 'g', run: () => Promise.resolve(snap('m', null)) }] };
  later(5, () => D.fire('p', 'child_added', snap('a', 1), undefined)); later(6, () => D.fire('p', 'child_removed', snap('a', 1), 'z')); later(8, () => D.fire('p', 'value', snap('p', null)));
  const row = await runCase(spec, { D, at, timing: timing() });
  assert.deepEqual(row.steps[0].observer.slice(0, 2), [{ l: 'L', e: 'child_added', k: 'a', p: null, v: 1 }, { l: 'L', e: 'child_removed', k: 'a', v: 1 }]);
  assert.deepEqual(row.steps[1].result, { exists: false, v: { leaf: null } });
});
test('runCase: the updater input is recorded as it was when the updater ran; the transaction runs on the transaction writer', async () => {
  const D = fakeD(), paths = [];
  D.runTransaction = (r, update) => { paths.push(r.path); const input = { n: 1 }; const out = update(input); input.n = 99; return Promise.resolve({ committed: true, snapshot: snap('t', out) }); };
  const spec = { id: 'x', listeners: [], steps: [{ kind: 'transaction', label: 'txn', path: 't', update: v => ({ n: v.n + 1 }) }] };
  later(5, () => D.fire('txn/t', 'value', snap('t', null)));
  const row = await runCase(spec, { D, at: { w: p => ({ path: `writer/${p}` }), o: p => ({ path: `observer/${p}` }), t: p => ({ path: `txn/${p}` }) }, timing: timing() });
  assert.deepEqual(paths, ['txn/t']); assert.deepEqual(row.steps[0].result.inputs, [{ n: 1 }]); assert.equal(row.steps[0].ready, true);
});
test('runCase: a callback the SDK delivers after the case ended is not added to its last step', async () => {
  const D = fakeD(), kept = [];
  const sticky = { ...D, onValue: (target, cb) => { kept.push(cb); return () => {}; } };
  const spec = { id: 'x', listeners: [{ label: 'L', path: 'p', query: null, kinds: ['value'] }], steps: [{ kind: 'attach', label: 'attach' }] };
  later(5, () => kept[0](snap('p', 1)));
  const row = await runCase(spec, { D: sticky, at, timing: timing() });
  kept[0](snap('p', 2)); assert.equal(row.steps[0].observer.length, 1);
});
test('profile: a non-empty scope seen by the observer stops the profile at startup-observer', async () => {
  const f = fakeApp(); const get = f.D.get;
  f.D.get = r => (r.app === 'events-observer-r1-lp' ? Promise.resolve(snap('x', { left: 1 })) : get(r));
  const rows = await runEventsProfile({ D: f.D, A: f.A, cfg: cfg() });
  assert.deepEqual(rows.map(r => [r.id, r.ok]), [['startup', true], ['startup-observer', false]]);
});
test('admin profile: after a failed startup read the cases still run; a transaction runs on its own path', async () => {
  const calls = [];
  const node = p => ({ path: p, get: () => Promise.reject(new Error('permission_denied')), child: c => node(`${p}/${c}`), set: () => { calls.push(`set ${p}`); return Promise.resolve(); },
    on: (event, f) => { calls.push(`on ${event} ${p}`); setTimeout(() => f(snap(p, null)), 5); return f; }, off: () => {}, transaction: u => { calls.push(`transaction ${p}`); return Promise.resolve({ committed: true, snapshot: snap(p, u(null)) }); } });
  const rows = await runAdminProfile({ db: { ref: node }, cfg: { scope: 'pre/sdk-admin/r1-admin', name: 'r1-admin', quietMs: 20 }, cases: ['set', 'transaction_absent'] });
  assert.deepEqual(rows.map(r => [r.id, r.ok]), [['startup', false], ['set', true], ['transaction_absent', true]]);
  assert.deepEqual(calls, ['set pre/sdk-admin/r1-admin/a', 'on value pre/sdk-admin/r1-admin/ta', 'transaction pre/sdk-admin/r1-admin/ta']);
});

// ---- Codex presend review of packet 1 v1, Must 2: a timed-out SDK mutation is an unknown outcome ----
test('runCase: a write, a push call and a transaction that time out are unknown mutations; a rejected write, a hanging get and a clean case are not', async () => {
  const D = fakeD();
  const hang = () => new Promise(() => {});
  const spec = { id: 'x', listeners: [], steps: [
    { kind: 'write', label: 'denied', run: () => Promise.reject(Object.assign(new Error('x'), { code: 'PERMISSION_DENIED' })) },
    { kind: 'get', label: 'slow-get', run: hang },
    { kind: 'write', label: 'hang-write', run: hang },
    { kind: 'call', label: 'hang-push', run: hang },
    { kind: 'transaction', label: 'hang-txn', path: 't', update: () => 1 },
    { kind: 'write', label: 'fine', run: () => Promise.resolve() },
  ] };
  D.runTransaction = hang; later(5, () => D.fire('t', 'value', snap('t', null)));
  const row = await runCase(spec, { D, at, timing: { ...timing(), stepMs: 60 } });
  assert.equal(row.ok, true);
  assert.deepEqual(row.unknown, ['x/hang-write', 'x/hang-push', 'x/hang-txn']);
  const clean = await runCase({ id: 'y', listeners: [], steps: [{ kind: 'write', label: 'w', run: () => Promise.resolve() }, { kind: 'get', label: 'g', run: () => Promise.resolve(snap('g', 1)) }] }, { D: fakeD(), at, timing: timing() });
  assert.equal(Object.hasOwn(clean, 'unknown'), false, 'a case without an unknown mutation keeps its recorded shape');
});
test('runCase: the unknown mutations found before an unknown step kind aborts the case are still reported', async () => {
  const row = await runCase({ id: 'z', listeners: [], steps: [{ kind: 'write', label: 'hang', run: () => new Promise(() => {}) }, { kind: 'nope', label: 'n' }] }, { D: fakeD(), at, timing: { ...timing(), stepMs: 50 } });
  assert.equal(row.ok, false); assert.deepEqual(row.unknown, ['z/hang']);
});
test('events profile: a seed that times out is an unknown mutation of the profile', async () => {
  const f = fakeApp({ hangSeed: true }), rows = await runEventsProfile({ D: f.D, A: f.A, cfg: cfg({ stepMs: 80 }), cases: [] });
  const seed = rows.find(r => r.id === 'seed');
  assert.equal(seed.ok, false); assert.deepEqual(seed.unknown, ['seed']);
  const refused = fakeApp({ failSeed: true }), r2 = await runEventsProfile({ D: refused.D, A: refused.A, cfg: cfg() });
  assert.equal(Object.hasOwn(r2.find(r => r.id === 'seed'), 'unknown'), false, 'a refused seed is an answer, not an unknown');
});
test('admin profile: a timed-out Admin SDK write, push and transaction are reported as unknown mutations', async () => {
  const hang = () => new Promise(() => {});
  const node = p => ({ path: p, get: () => Promise.resolve(snap(p, null)), child: c => node(`${p}/${c}`), set: hang, update: hang, remove: hang, push: () => ({ key: '-OabcdefghijklmnopqR', set: hang, get: hang }), on: (e, f) => f, off: () => {}, transaction: hang });
  const rows = await runAdminProfile({ db: { ref: node }, cfg: { scope: 'pre/sdk-admin/r1-admin', name: 'r1-admin', stepMs: 60, quietMs: 20, maxMs: 100 }, cases: ['set', 'push', 'transaction_absent', 'get'] });
  const unknown = rows.flatMap(r => r.unknown ?? []);
  assert.deepEqual(unknown, ['set/set', 'push/push', 'transaction_absent/absent']);
});
