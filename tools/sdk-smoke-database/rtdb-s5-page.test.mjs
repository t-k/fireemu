// node --test rtdb-s5-page.test.mjs: the S5 scenario (rtdb-s5-page.js) in headless Chromium against a stub of the
// Firebase SDK that plays a server with a switchable answer (A to D) for the question case, so that page and judge are
// tested together: whatever the page records, rtdb-s5-judge.mjs must read the answer back. The failure paths a healthy
// server never takes (nothing arrives, a rejection, a Rules probe that never succeeds) are exercised too. Skipped when
// Chromium cannot be launched, and failing instead when FIREEMU_REQUIRE_BROWSER=1 (require-browser.mjs).
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { launchOrSkip, missingPlaywright } from './require-browser.mjs';
import { classify } from './rtdb-s5-judge.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const PAGE = readFileSync(path.join(here, 'rtdb-s5-page.js'), 'utf8');
const APP = 'https://www.gstatic.com/firebasejs/12.18.0/firebase-app.js';
const DATABASE = 'https://www.gstatic.com/firebasejs/12.18.0/firebase-database.js';
const STUB_APP = 'export const initializeApp = (opts, name) => ({ opts, name }); export const deleteApp = async (app) => { window.__stub.calls.push([\'deleteApp\', app.name]); };';
// The stub server: `data` maps a path to { value, priority }; value listeners hear every change; the onDisconnect
// registrations of a writer app fire when it goes offline, as the answer `S().answer` says for the question case.
const STUB_DATABASE = `
const S = () => window.__stub;
const snap = (path, node) => ({ key: path.split('/').pop(), val: () => (node ? node.value : null), priority: node ? node.priority ?? null : null, forEach() {} });
export const forceWebSockets = () => S().calls.push(['transport', 'ws']);
export const getDatabase = (app) => ({ app });
export const ref = (db, p) => ({ db, path: p });
export const goOffline = (db) => { S().calls.push(['goOffline', db.app.name]); S().offline(db.app.name); };
export const set = async (r, v) => S().put(r.path, v, null);
export const get = async (r) => { S().calls.push(['get', r.path]); if (S().getFails) throw Object.assign(new Error('get failed'), { code: 'unavailable' }); return snap(r.path, S().data[r.path]); };
export const onValue = (q, cb, cancel) => { const l = { path: q.path, cb, cancel }; S().listeners.push(l); S().initial(l, snap); if (S().cancelAll) Promise.resolve().then(() => cancel(Object.assign(new Error('cancelled'), { code: 'permission_denied' }))); return () => { S().calls.push(['unsub', q.path]); }; };
export const onDisconnect = (r) => ({
  set: (v) => S().register(r, { kind: 'set', value: v }),
  setWithPriority: (v, p) => S().register(r, { kind: 'set', value: v, priority: p }),
  cancel: () => S().register(r, { kind: 'cancel' }),
});
`;
const STUB_STATE = `
Object.assign(window.__stub, {
  data: {}, regs: {}, answer: 'B', controls: 'ok', deliver: true, rejectOd: null, probeFails: 0, probes: 0,
  initial(l, snap) { if (this.deliver && !(this.onlyS && l.path.endsWith('/t'))) Promise.resolve().then(() => l.cb(snap(l.path, this.data[l.path]))); },
  put(path, value, priority) {
    if (path.endsWith('/probe') && this.probes++ < this.probeFails) throw Object.assign(new Error('permission_denied'), { code: 'PERMISSION_DENIED' });
    this.data[path] = value === null ? undefined : { value, priority };
    for (const l of this.listeners) if (l.path === path && this.deliver) l.cb({ key: path.split('/').pop(), val: () => (value === null ? null : value), priority, forEach() {} });
  },
  register(r, reg) {
    if (this.rejectOd && r.path.endsWith(this.rejectOd)) return Promise.reject(Object.assign(new Error(this.longError ? 'x'.repeat(300) : 'PERMISSION_DENIED at /' + r.path), { code: 'PERMISSION_DENIED' }));
    const writer = r.db.app.name;
    (this.regs[writer] ??= []).push({ ...reg, path: r.path });
    return Promise.resolve();
  },
  offline(writer) {
    const regs = this.regs[writer] ?? [];
    const kase = writer.split('-')[1];
    if (regs.length < 3) return; // a registration was rejected: the server holds an incomplete set and this stub fires nothing
    const base = regs.find((x) => x.kind === 'set' && x.path.endsWith('/s')).path;
    const t = regs.find((x) => x.path.endsWith('/t')).path;
    const cancelled = regs.find((x) => x.kind === 'cancel').path.slice(base.length + 1);
    const valueReg = regs.find((x) => x.path === base);
    const fireT = () => this.put(t, 1, null);
    const split = () => { const rest = { ...valueReg.value }; delete rest[cancelled]; this.put(base, rest, null); };
    const whole = () => this.put(base, valueReg.value, valueReg.priority ?? null);
    setTimeout(() => {
      if (kase === 'main') {
        if (this.answer === 'A') return;
        if (this.answer === 'B' && this.late) { fireT(); setTimeout(split, 20); } else if (this.answer === 'B') { split(); fireT(); } else if (this.answer === 'C') { whole(); fireT(); } else if (this.answer === 'D') fireT();
        return;
      }
      if (this.controls === 'broken') return;
      if (kase === 'plain') split(); else whole();
      if (this.controls !== 'no-t') fireT();
    }, 5);
  },
});
`;

let chromium;
try {
  chromium = createRequire(path.join(here, 'x.js'))('playwright').chromium;
} catch { /* no playwright */ }

/** Runs the scenario against the stub; `state` is the source of an object literal merged into the stub's state. */
async function run(t, state = '{}', cfg = {}) {
  const browser = await launchOrSkip(chromium, t);
  if (!browser) return null;
  try {
    const page = await (await browser.newContext()).newPage();
    const rows = [];
    await page.exposeFunction('__s5Event', (e) => { rows.push(e); });
    await page.route('**/*', (route) => {
      const url = route.request().url();
      if (url === 'http://page.test/') return route.fulfill({ contentType: 'text/html', body: '<!doctype html><script type="module" src="http://page.test/page.js"></script>' });
      if (url === 'http://page.test/page.js') return route.fulfill({ contentType: 'text/javascript', body: PAGE });
      if (url === APP) return route.fulfill({ contentType: 'text/javascript', headers: { 'access-control-allow-origin': '*' }, body: STUB_APP });
      if (url === DATABASE) return route.fulfill({ contentType: 'text/javascript', headers: { 'access-control-allow-origin': '*' }, body: STUB_DATABASE });
      return route.abort();
    });
    await page.addInitScript(`window.__stub = { calls: [], listeners: [] }; ${STUB_STATE}; Object.assign(window.__stub, ${state});`);
    await page.goto('http://page.test/');
    await page.waitForFunction(() => typeof window.__s5Run === 'function');
    await page.evaluate((c) => window.__s5Run(c), { projectId: 'p', databaseURL: 'https://x.invalid', name: 'r1-ws', base: 'parity1/rr1/s5/r1-ws', waitScale: 0.01, ...cfg });
    const calls = await page.evaluate(() => window.__stub.calls);
    const probes = await page.evaluate(() => window.__stub.probes);
    // The runner appends this row after the page ends.
    rows.push({ scenario: 's5', step: 'runner', type: 'transport', code: calls.some((c) => c[0] === 'transport' && c[1] === 'ws') ? 'ws' : 'lp' });
    return { rows, calls, probes };
  } finally {
    await browser.close();
  }
}
const skip = missingPlaywright(chromium);
const kinds = (rows, type) => rows.filter((r) => r.type === type);

for (const answer of ['A', 'B', 'C', 'D']) {
  test(`the page records what a server answering ${answer} does, and the judge reads ${answer} back`, { skip, timeout: 60000 }, async (t) => {
    const r = await run(t, `{ answer: '${answer}' }`);
    if (!r) return;
    assert.equal(classify(r.rows).outcome, answer, JSON.stringify(classify(r.rows)));
    assert.equal(r.rows.at(-2).type, 'done');
    assert.deepEqual(kinds(r.rows, 'timeout').map((x) => x.label), [], 'no bound was hit');
  });
}

test('the observer waits out a quiet period after the unrelated write fired, so a late split is still read', { skip, timeout: 60000 }, async (t) => {
  const r = await run(t, `{ answer: 'B', late: true }`);
  if (!r) return;
  assert.equal(classify(r.rows).outcome, 'B', 'the split lands 20 ms after t; the final reads come after the quiet period');
});

test('the page registers each case on its own writer connection and takes the writers offline one by one', { skip, timeout: 60000 }, async (t) => {
  const r = await run(t);
  if (!r) return;
  assert.deepEqual(r.calls.filter((c) => c[0] === 'goOffline').map((c) => c[1]), ['w-plain-s5-r1-ws', 'w-whole-s5-r1-ws', 'w-main-s5-r1-ws']);
  assert.deepEqual(kinds(r.rows, 'ack').map((x) => [x.actor, x.label]), ['plain', 'whole', 'main'].flatMap((k) => ['s', 'cancel', 't'].map((p) => ['w', `${k}-register-${p}`])));
  assert.deepEqual(kinds(r.rows, 'offline').map((x) => [x.actor, x.label]), [['w', 'plain'], ['w', 'whole'], ['w', 'main']]);
  assert.deepEqual(kinds(r.rows, 'get').map((x) => x.label), ['plain-s', 'plain-t', 'whole-s', 'whole-t', 'main-s', 'main-t']);
});

test('the priority is registered with the value in main and whole and not in plain, and the cancels name b, zz and b', { skip, timeout: 60000 }, async (t) => {
  const r = await run(t, `{ answer: 'C' }`);
  if (!r) return;
  const mainS = kinds(r.rows, 'get').find((x) => x.label === 'main-s'), plainS = kinds(r.rows, 'get').find((x) => x.label === 'plain-s'), wholeS = kinds(r.rows, 'get').find((x) => x.label === 'whole-s');
  assert.deepEqual([mainS.priority, plainS.priority, wholeS.priority], [1, null, 1]);
  assert.equal(wholeS.shape, '{"9":3,"10":2,"b":1}', 'the cancel of zz left b in place');
});

test('a broken control makes the round unclassified, whatever the question case did', { skip, timeout: 60000 }, async (t) => {
  const r = await run(t, `{ answer: 'A', controls: 'broken' }`);
  if (!r) return;
  assert.equal(classify(r.rows).outcome, 'unclassified');
  assert.deepEqual(kinds(r.rows, 'timeout').map((x) => x.label), ['plain fire', 'whole fire'], 'the controls must fire: their bounds are timeouts; the question\'s is not');
});

test('a server that delivers nothing gives timeouts, never an answer, and the run still ends', { skip, timeout: 60000 }, async (t) => {
  const r = await run(t, `{ deliver: false }`);
  if (!r) return;
  assert.equal(classify(r.rows).outcome, 'unclassified');
  assert.deepEqual(kinds(r.rows, 'timeout').map((x) => x.label), ['first values', 'plain fire', 'first values', 'whole fire', 'first values']);
  assert.equal(r.rows.at(-2).type, 'done');
});

test('a Rules probe that fails a few times is waited out; one that never succeeds is a timeout after 60 tries', { skip, timeout: 60000 }, async (t) => {
  const waited = await run(t, `{ probeFails: 3 }`);
  if (!waited) return;
  assert.equal(waited.rows.find((x) => x.step === 'rules').code, 'allowed');
  assert.equal(classify(waited.rows).outcome, 'B');
  const never = await run(t, `{ probeFails: 1000 }`);
  assert.deepEqual(kinds(never.rows, 'timeout').map((x) => x.label), ['rules-allowed']);
  assert.equal(never.rows.filter((x) => x.step === 'rules').length, 1);
  assert.equal(classify(never.rows).outcome, 'unclassified');
});

test('a rejected registration is a rejected row of the writer with the code and the prefix masked, and the round is unclassified', { skip, timeout: 60000 }, async (t) => {
  const r = await run(t, `{ rejectOd: '/main/t' }`);
  if (!r) return;
  const rejected = kinds(r.rows, 'rejected');
  assert.deepEqual(rejected.map((x) => [x.step, x.actor, x.label, x.code, x.shape]), [['register-main', 'w', 'main-register-t', 'PERMISSION_DENIED', 'permission_denied at /<base>/main/t']]);
  assert.ok(!JSON.stringify(r.rows).includes('parity1/rr1'));
  assert.equal(classify(r.rows).outcome, 'unclassified');
});

test('the observer\'s first values need both listeners, the controls must deliver t, and an unreadable get is a rejected row', { skip, timeout: 60000 }, async (t) => {
  const onlyS = await run(t, `{ onlyS: true }`);
  if (!onlyS) return;
  assert.ok(kinds(onlyS.rows, 'timeout').some((x) => x.label === 'first values'), 'a listener that never delivers is a timeout');
  const noT = await run(t, `{ controls: 'no-t' }`);
  assert.deepEqual(kinds(noT.rows, 'timeout').map((x) => x.label), ['plain fire', 'whole fire'], 'the wait is for t, not for s');
  const getFails = await run(t, `{ getFails: true }`);
  assert.deepEqual(kinds(getFails.rows, 'rejected').map((x) => [x.label, x.code]), ['plain-s', 'plain-t', 'whole-s', 'whole-t', 'main-s', 'main-t'].map((l) => [l, 'unavailable']));
  assert.equal(classify(getFails.rows).outcome, 'unclassified');
});

test('a cancelled listener is a cancel row with its code and fails the round', { skip, timeout: 60000 }, async (t) => {
  const r = await run(t, `{ cancelAll: true }`);
  if (!r) return;
  assert.deepEqual(kinds(r.rows, 'cancel').filter((x) => x.label.startsWith('main-')).map((x) => [x.label, x.code]), [['main-s', 'permission_denied'], ['main-t', 'permission_denied']]);
  assert.equal(classify(r.rows).outcome, 'unclassified');
});

test('listeners are removed and apps deleted at the end of each case, and the probe is tried 60 times', { skip, timeout: 60000 }, async (t) => {
  const r = await run(t);
  if (!r) return;
  assert.equal(r.calls.filter((c) => c[0] === 'unsub').length, 6);
  assert.deepEqual(r.calls.filter((c) => c[0] === 'deleteApp').map((c) => c[1]).sort(), ['o-s5-r1-ws', 'w-main-s5-r1-ws', 'w-plain-s5-r1-ws', 'w-whole-s5-r1-ws']);
  const never = await run(t, `{ probeFails: 1000 }`);
  assert.equal(never.probes, 60, 'the Rules probe gives up after 60 tries');
});

test('a long message is cut at 160 characters and value rows carry the priority they were delivered with', { skip, timeout: 60000 }, async (t) => {
  const long = await run(t, `{ rejectOd: '/main/t', longError: true }`);
  if (!long) return;
  assert.equal(kinds(long.rows, 'rejected')[0].shape.length, 160);
  const c = await run(t, `{ answer: 'C' }`);
  const value = kinds(c.rows, 'value').find((x) => x.label === 'whole-s' && x.shape !== 'null');
  assert.equal(value.priority, 1);
});
