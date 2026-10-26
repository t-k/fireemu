// node --test rtdb-residual-page.test.mjs: the residual scenarios (rtdb-residual-page.js) in headless Chromium
// against a stub of the Firebase SDK, so the failure paths a healthy fireemu never takes are exercised: a wait
// that hits its bound is a recorded `timeout` row, a rejection is a `rejected` row, a Rules probe that never
// sees the change gives up, and the masks. The stub delivers nothing unless a test makes it. The tests are
// skipped when Chromium cannot be launched, and fail instead when FIREEMU_REQUIRE_BROWSER=1 (require-browser.mjs). waitScale shortens every wait of the page.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { launchOrSkip, missingPlaywright } from './require-browser.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const PAGE = readFileSync(path.join(here, 'rtdb-residual-page.js'), 'utf8');
const APP = 'https://www.gstatic.com/firebasejs/12.18.0/firebase-app.js';
const DATABASE = 'https://www.gstatic.com/firebasejs/12.18.0/firebase-database.js';
const STUB_APP = 'export const initializeApp = (opts, name) => ({ opts, name }); export const deleteApp = async () => {};';
const STUB_DATABASE = `
const S = () => window.__stub;
const snap = (path, val) => ({ key: path.split('/').pop(), val: () => val, forEach: (fn) => { for (const [k, v] of Object.entries(val ?? {})) fn({ key: k, val: () => v }); } });
export const forceWebSockets = () => S().calls.push(['transport', 'ws']);
export const forceLongPolling = () => S().calls.push(['transport', 'lp']);
export const getDatabase = (app) => ({ app });
export const ref = (db, p) => ({ db, path: p });
export const query = (r) => r;
export const orderByChild = () => ({}); export const limitToFirst = () => ({}); export const limitToLast = () => ({});
export const goOffline = (db) => { S().calls.push(['goOffline', db.app.name]); S().on?.('goOffline', db.app.name); };
export const goOnline = (db) => { S().calls.push(['goOnline', db.app.name]); S().on?.('goOnline', db.app.name); };
export const set = (r, v) => S().write(r, v);
export const remove = (r) => S().write(r, null);
export const get = async (r) => snap(r.path, S().read(r.path));
const listen = (kind) => (q, cb, cancel) => { const l = { kind, path: q.path, cb, cancel }; S().listeners.push(l); S().initial?.(l, snap); return () => {}; };
export const onValue = listen('value'); export const onChildAdded = listen('added'); export const onChildChanged = listen('changed'); export const onChildMoved = listen('moved'); export const onChildRemoved = listen('removed');
export const increment = (n) => ({ '.sv': { increment: n } });
export const serverTimestamp = () => ({ '.sv': 'timestamp' });
export const onDisconnect = (r) => ({ set: (v) => S().od('set', r, v), update: (v) => S().od('update', r, v), remove: () => S().od('remove', r), cancel: () => S().od('cancel', r) });
`;

let chromium;
try {
  chromium = createRequire(path.join(here, 'x.js'))('playwright').chromium;
} catch { /* no playwright */ }

/** Runs one scenario against the stub. `behaviour` is the source of an object literal for window.__stub. */
async function scenario(t, cfg, behaviour = '{}') {
  const browser = await launchOrSkip(chromium, t);
  if (!browser) return null;
  try {
    const page = await (await browser.newContext()).newPage();
    const rows = [];
    await page.exposeFunction('__rrEvent', (e) => { rows.push(e); });
    await page.exposeFunction('__rrHook', async (name) => { await page.evaluate((n) => window.__stub.hook?.(n), name); return 'ok'; });
    await page.route('**/*', (route) => {
      const url = route.request().url();
      if (url === 'http://page.test/') return route.fulfill({ contentType: 'text/html', body: '<!doctype html><script type="module" src="http://page.test/page.js"></script>' });
      if (url === 'http://page.test/page.js') return route.fulfill({ contentType: 'text/javascript', body: PAGE });
      if (url === APP) return route.fulfill({ contentType: 'text/javascript', headers: { 'access-control-allow-origin': '*' }, body: STUB_APP });
      if (url === DATABASE) return route.fulfill({ contentType: 'text/javascript', headers: { 'access-control-allow-origin': '*' }, body: STUB_DATABASE });
      return route.abort();
    });
    await page.addInitScript(`window.__stub = Object.assign({ calls: [], listeners: [], writes: [], ods: [], read: () => null, write: async function (r, v) { this.writes.push([r.path, v]); }, od: async function (kind, r, v) { this.ods.push([kind, r.path, v]); } }, ${behaviour});
      for (const k of ['write', 'od']) window.__stub[k] = window.__stub[k].bind(window.__stub);`);
    await page.goto('http://page.test/');
    await page.waitForFunction(() => typeof window.__rrRun === 'function');
    await page.evaluate((c) => window.__rrRun(c), { projectId: 'p', databaseURL: 'https://x.invalid', name: 'r1-ws', transport: 'ws', base: 'parity1/rr1/cv/r1-ws', waitScale: 0.001, ...cfg });
    const stub = await page.evaluate(() => ({ calls: window.__stub.calls, writes: window.__stub.writes, ods: window.__stub.ods }));
    return { rows, stub };
  } finally {
    await browser.close();
  }
}
const timeouts = (rows) => rows.filter((r) => r.type === 'timeout').map((r) => `${r.step}:${r.label}`);
const skip = missingPlaywright(chromium);

test('cv08 against an SDK that delivers nothing: every bounded wait is a recorded timeout, and the run still ends', { skip, timeout: 60000 }, async (t) => {
  const r = await scenario(t, { scenario: 'cv08' });
  if (!r) return;
  assert.deepEqual(timeouts(r.rows), ['attach:items+win-v+top-v+gated+other', 'top-off:win-v after top-off', 'reconnect:queued acks and gated answer', 'top-reattach:top2-v', 'after-reconnect:other after reconnect']);
  assert.equal(r.rows.at(-1).type, 'done');
  assert.equal(r.rows.filter((x) => x.type === 'absent').length, 1, 'nothing arrived on the gated listener, which is the absent row');
  assert.ok(r.rows.every((x) => x.scenario === 'cv08' && typeof x.step === 'string'));
  assert.deepEqual(r.stub.calls.filter((c) => c[0] === 'goOffline' || c[0] === 'goOnline').map((c) => c[0]), ['goOffline', 'goOnline']);
});

test('cv10 against an SDK that delivers nothing and Rules that never change: the probe gives up after 60 tries and the marker wait is a timeout', { skip, timeout: 60000 }, async (t) => {
  const r = await scenario(t, { scenario: 'cv10' });
  if (!r) return;
  assert.deepEqual(timeouts(r.rows), ['attach:first values', 'rules-deny:rules-denied', 'disconnect:marker fire']);
  assert.equal(r.stub.writes.filter(([p]) => p.endsWith('/dprobe')).length, 1 + 60, 'one allowed probe, then 60 tries for a denial that never comes');
  const timing = r.rows.find((x) => x.type === 'timing');
  assert.deepEqual([timing.step, timing.actor, typeof timing.seconds], ['fire', 'host', 'number']);
  assert.deepEqual(r.rows.filter((x) => x.type === 'admin').map((x) => [x.step, x.actor, x.code]), [['rules-open', 'host', 'ok'], ['rules-deny', 'host', 'ok']]);
  assert.equal(r.rows.filter((x) => x.step === 'final' && x.type === 'get').length, 10, 'the final reads cover e1 to e9 and the marker');
});

test('cv10 with a Rules change that takes effect: the probe reports allowed, then denied, without a timeout', { skip, timeout: 60000 }, async (t) => {
  const r = await scenario(t, { scenario: 'cv10' }, `{ denied: false, hook(n) { this.denied = n === 'rulesDeny'; }, write: async function (r, v) { this.writes.push([r.path, v]); if (r.path.endsWith('/dprobe') && this.denied) throw Object.assign(new Error('permission_denied at /x'), { code: 'PERMISSION_DENIED' }); } }`);
  if (!r) return;
  assert.deepEqual(r.rows.filter((x) => x.type === 'rules').map((x) => [x.step, x.code]), [['rules-open', 'allowed'], ['rules-deny', 'denied']]);
  assert.ok(!timeouts(r.rows).includes('rules-deny:rules-denied') && !timeouts(r.rows).includes('rules-open:rules-allowed'));
  assert.equal(r.stub.writes.filter(([p]) => p.endsWith('/dprobe')).length, 2);
});

test('a rejection is a rejected row of the writer with the code, and the run prefix is masked in the message', { skip, timeout: 60000 }, async (t) => {
  const reject = `{ od: async function (kind, r, v) { this.ods.push([kind, r.path, v]);
      if (r.path.endsWith('/e8')) throw Object.assign(new Error('PERMISSION_DENIED at /parity1/rr1/cv/r1-ws/e8: Client does not have permission'), { code: 'PERMISSION_DENIED' });
      if (r.path.endsWith('/e7')) throw new Error('Permission denied');
      if (r.path.endsWith('/e5')) throw new Error('something else'); } }`;
  const r = await scenario(t, { scenario: 'cv10' }, reject);
  if (!r) return;
  const rejected = r.rows.filter((x) => x.type === 'rejected').map((x) => [x.step, x.actor, x.label, x.code, x.shape]);
  assert.deepEqual(rejected, [
    ['register', 'w', 'e5-update', 'other', 'something else'],
    ['register', 'w', 'e7-set', 'message:permission-denied', 'permission denied'],
    ['register-denied', 'w', 'e8-set', 'PERMISSION_DENIED', 'permission_denied at /<base>/e8: client does not have permission'],
  ]);
  assert.ok(!JSON.stringify(r.rows).includes('parity1/rr1'), 'the prefix appears in no row');
  assert.ok(r.rows.filter((x) => x.type === 'ack').every((x) => x.actor === 'w'));
});

test('server timestamps are masked by the field name and the distance from the browser clock, nothing else is', { skip, timeout: 60000 }, async (t) => {
  const final = (at) => `{ read(p) { return p.endsWith('/e6') ? { n: 42, at: ${at}, early: 5 } : p.endsWith('/e5') ? { at: 'x' } : null; } }`;
  const near = await scenario(t, { scenario: 'cv10' }, final('Date.now() - 1000'));
  if (!near) return;
  const get = (rows, label) => rows.find((x) => x.type === 'get' && x.label === label).shape;
  assert.equal(get(near.rows, 'e6'), '{"n":42,"at":"<TS>","early":5}');
  assert.equal(get(near.rows, 'e5'), '{"at":"x"}', 'a non-number under at is kept');
  const far = await scenario(t, { scenario: 'cv10' }, final('Date.now() - 3600000'));
  assert.equal(get(far.rows, 'e6'), '{"n":42,"at":"<TS-OFF>","early":5}');
  const edge = await scenario(t, { scenario: 'cv10' }, final('Date.now() - 590000'));
  assert.equal(get(edge.rows, 'e6'), '{"n":42,"at":"<TS>","early":5}');
});

test('the queued writes of the observer are observer rows; the writer acks are writer rows', { skip, timeout: 60000 }, async (t) => {
  const r = await scenario(t, { scenario: 'cv08' });
  if (!r) return;
  const actors = Object.fromEntries(r.rows.filter((x) => x.type === 'ack').map((x) => [x.label, x.actor]));
  assert.deepEqual([actors['queued-1'], actors['queued-2'], actors['queued-3']], ['o', 'o', 'o']);
  assert.deepEqual([actors['seed-items'], actors['w-a-score'], actors['w-gate'], actors['w-g']], ['w', 'w', 'w', 'w']);
});

// A cv10 stub that behaves like a healthy server: every value listener first gets the stored value, and the
// writer going offline fires the onDisconnect writes after `delays` milliseconds.
const healthy = (delays) => `{
  denied: false,
  hook(n) { this.denied = n === 'rulesDeny'; },
  write: async function (r, v) { this.writes.push([r.path, v]); if (r.path.endsWith('/dprobe') && this.denied) throw Object.assign(new Error('permission_denied'), { code: 'PERMISSION_DENIED' }); },
  read(p) { return p.endsWith('/marker') ? false : null; },
  initial(l, snap) { if (l.kind === 'value') Promise.resolve().then(() => l.cb(snap(l.path, this.read(l.path)))); },
  deliver(path, v) { for (const l of this.listeners) if (l.kind === 'value' && l.path.endsWith(path)) l.cb({ key: path.slice(1), val: () => v, forEach() {} }); },
  on(kind, name) { if (kind === 'goOffline' && name.startsWith('w-')) for (const [path, v, ms] of ${JSON.stringify(delays)}) setTimeout(() => this.deliver(path, v), ms); },
}`;
const order = (rows) => rows.filter((x) => (x.type === 'value' && x.step === 'disconnect') || x.type === 'timing').map((x) => (x.type === 'timing' ? 'timing' : `${x.label}=${x.shape}`));

test('cv10 waits for the marker, then a quiet period, and only then reports the fire time', { skip, timeout: 60000 }, async (t) => {
  const r = await scenario(t, { scenario: 'cv10', waitScale: 0.05 }, healthy([['/marker', true, 100], ['/e2', { state: 'offline' }, 200]]));
  if (!r) return;
  assert.deepEqual(timeouts(r.rows), []);
  assert.deepEqual(order(r.rows), ['marker=true', 'e2={"state":"offline"}', 'timing'], 'the marker is awaited, and the later fire still lands before the timing row');
  const seconds = r.rows.find((x) => x.type === 'timing').seconds;
  assert.ok(seconds >= 0.1 && seconds < 5, String(seconds));
});

test('cv10 without a marker fire waits out its bound and records the timeout before the timing row', { skip, timeout: 60000 }, async (t) => {
  const r = await scenario(t, { scenario: 'cv10', waitScale: 0.001, transport: 'lp', name: 'r1-lp' }, healthy([]));
  if (!r) return;
  assert.deepEqual(timeouts(r.rows), ['disconnect:marker fire']);
  assert.ok(r.rows.findIndex((x) => x.type === 'timeout') < r.rows.findIndex((x) => x.type === 'timing'));
  assert.deepEqual(r.stub.calls.filter((c) => c[0] === 'transport'), [['transport', 'lp']]);
});

test('the gated listener is silent only if nothing arrives after the reconnect: the absent row says so', { skip, timeout: 60000 }, async (t) => {
  const arrives = `{ write: async function (r, v) { this.writes.push([r.path, v]); if (r.path.endsWith('/gated/v')) for (const l of this.listeners) if (l.kind === 'value' && l.path.endsWith('/gated')) l.cb({ key: 'gated', val: () => ({ v }), forEach() {} }); } }`;
  const r = await scenario(t, { scenario: 'cv08' }, arrives);
  if (!r) return;
  assert.equal(r.rows.filter((x) => x.type === 'absent').length, 0);
  assert.ok(r.rows.some((x) => x.type === 'value' && x.label === 'gated' && x.step === 'after-reconnect'));
});

test('a long message is cut at 160 characters', { skip, timeout: 60000 }, async (t) => {
  const long = `{ od: async function (kind, r, v) { this.ods.push([kind, r.path, v]); if (r.path.endsWith('/e8')) throw Object.assign(new Error('x'.repeat(300)), { code: 'PERMISSION_DENIED' }); } }`;
  const r = await scenario(t, { scenario: 'cv10' }, long);
  if (!r) return;
  assert.equal(r.rows.find((x) => x.type === 'rejected').shape.length, 160);
});
