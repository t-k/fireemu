// Packet 2 hardening of the observer code shared by every suite (coordinator ruling on the packet 1 v2 Codex round):
// B1 the browser stop margin (16), a source pin on the SDK keepalive path, and fake-page runs of the traffic the 25 s
// keepalive, a reconnect after the transport switch and a slow page close can add; B2 a quiet teardown of the events
// WebSocket profile (no `goOffline` on a database the recorder already deleted).
import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { BROWSER_MARGIN, eventsAppCloser, watchBrowserTraffic } from './observer.mjs';
import { createCounter } from './lib.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SDK = path.join(HERE, '..', 'node_modules', '@firebase', 'database', 'dist', 'index.esm.js');

// ---- B1: margin and keepalive pin ----
test('B1 the browser margin is 16: the page is stopped at cap - 16', () => {
  assert.equal(BROWSER_MARGIN, 16);
});
test('B1 source pin: the SDK keepalive re-issues a poll after 25 s without cancelling the old script request (a version change fails here)', () => {
  const sdk = readFileSync(SDK, 'utf8');
  assert.ok(sdk.includes('const KEEPALIVE_REQUEST_INTERVAL = 25000;'), 'KEEPALIVE_REQUEST_INTERVAL is 25000');
  const keepalive = [
    '    addLongPollTag_(url, serial) {',
    '        //remember that we sent this request.',
    '        this.outstandingRequests.add(serial);',
    '        const doNewRequest = () => {',
    '            this.outstandingRequests.delete(serial);',
    '            this.newRequest_();',
    '        };',
    "        // If this request doesn't return on its own accord (by the server sending us some data), we'll",
    '        // create a new one after the KEEPALIVE interval to make sure we always keep a fresh request open.',
    '        const keepaliveTimeout = setTimeout(doNewRequest, Math.floor(KEEPALIVE_REQUEST_INTERVAL));',
    '        const readyStateCB = () => {',
    '            // Request completed.  Cancel the keepalive.',
    '            clearTimeout(keepaliveTimeout);',
    '            // Trigger a new request so we can continue receiving data.',
    '            doNewRequest();',
    '        };',
    '        this.addTag(url, readyStateCB);',
    '    }',
  ].join('\n');
  assert.ok(sdk.includes(keepalive), 'the keepalive path of addLongPollTag_ is the pinned one');
  assert.ok(sdk.includes('this.outstandingRequests.size < (this.pendingSegs.length > 0 ? 2 : 1)'), 'the outstanding-request limit is the pinned one');
  assert.equal(JSON.parse(readFileSync(path.join(HERE, '..', 'node_modules', '@firebase', 'database', 'package.json'), 'utf8')).version, '1.1.5');
});

// A fake Playwright page: requests and sockets are emitted by the test; close() resolves when the test says so.
function fakePage({ closeDelay = Promise.resolve() } = {}) {
  const page = Object.assign(new EventEmitter(), { closeCalls: 0, closed: false });
  page.close = async () => { page.closeCalls += 1; await closeDelay; page.closed = true; };
  return page;
}
const req = (url = 'db:/.lp?id=1') => ({ url: () => url, method: () => 'GET', postData: () => null });
function world({ cap = 60, closeDelay } = {}) {
  const page = fakePage({ closeDelay }), counter = createCounter({ direct: cap }), aborts = [], rows = [];
  const ctx = { profile: 'r1-lp', counter, abort: reason => aborts.push(reason), journal: { write: row => rows.push(row) } };
  const watch = watchBrowserTraffic(page, ctx, url => url.startsWith('db:'));
  let sent = 0;
  const emit = (event, value) => { sent += event === 'request' || event === 'websocket' ? 1 : 0; assert.doesNotThrow(() => page.emit(event, value), `nothing throws into the page (${event})`); };
  return { page, counter, aborts, rows, watch, emit, sent: () => sent, cap };
}
const socket = () => Object.assign(new EventEmitter(), { url: () => 'db:/.ws' });
function assertStopped(w) {
  const used = w.counter.used();
  assert.equal(w.aborts.length, 1, 'the run is aborted once');
  assert.match(w.aborts[0], new RegExp(`direct ${w.cap - 16} of cap ${w.cap} \\(margin 16\\)`), 'the stop fires at cap - 16');
  assert.equal(used.direct + (used.overflow ?? 0), w.sent(), 'every request is counted: direct plus overflow');
  assert.equal(used.direct, Math.min(w.cap, w.sent()));
  assert.equal(used.overflow ?? 0, Math.max(0, w.sent() - w.cap), 'every request over the cap is in overflow');
  assert.equal(w.page.closeCalls, 1, 'the page is closed once');
}

test('B1 stalled polls across keepalive intervals: requests keep arriving and the old ones never finish; stop at cap - 16, every request counted, the excess in overflow', async () => {
  const w = world({ cap: 60 });
  // Two long-polling connections, each re-issuing a poll per keepalive interval while none of the old ones finishes.
  for (let interval = 0; interval < 40; interval++) for (let conn = 0; conn < 2; conn++) w.emit('request', req(`db:/.lp?conn=${conn}&keepalive=${interval}`));
  assert.equal(w.watch.stats().inFlight, 80, 'stalled polls stay in flight');
  assertStopped(w);
  assert.equal(w.counter.used().overflow, 20);
});
test('B1 a writer reconnect after the transport switch (a third long-polling connection plus a new page socket) is counted the same way', async () => {
  const w = world({ cap: 40 });
  for (let i = 0; i < 20; i++) { w.emit('request', req(`db:/.lp?conn=${i % 2}`)); w.emit('requestfinished', req()); }
  w.emit('websocket', socket());   // the writer's page WebSocket drops and reconnects
  for (let i = 0; i < 30; i++) w.emit('request', req(`db:/.lp?conn=2&start=${i}`));   // the reconnect now polls: a third connection
  assertStopped(w);
  assert.ok(w.counter.used().overflow > 0);
});
test('B1 delayed page closure: close() resolves late while more requests arrive; still one abort, one close, everything counted', async () => {
  let release; const closeDelay = new Promise(r => { release = r; });
  const w = world({ cap: 30, closeDelay });
  for (let i = 0; i < 13; i++) w.emit('request', req());
  assert.equal(w.aborts.length, 0, 'below cap - 16 nothing stops');
  w.emit('request', req());   // the 14th reaches cap - 16: the stop fires, the close is still pending
  assert.equal(w.aborts.length, 1); assert.equal(w.page.closed, false);
  for (let i = 0; i < 25; i++) { w.emit('request', req()); w.emit('requestfinished', req()); }   // completions trigger replacements while the page is closing
  release(); await new Promise(r => setTimeout(r, 0));
  assert.equal(w.page.closed, true);
  for (let i = 0; i < 3; i++) w.emit('request', req());   // late events after close resolved
  assertStopped(w);
});
test('B1 a page close that rejects and a journal that throws never reach the page', async () => {
  const page = fakePage(); page.close = async () => { throw new Error('target closed'); };
  const counter = createCounter({ direct: 20 }), aborts = [];
  watchBrowserTraffic(page, { profile: 'p', counter, abort: r => aborts.push(r), journal: { write() { throw new Error('journal full'); } } }, url => url.startsWith('db:'));
  for (let i = 0; i < 30; i++) assert.doesNotThrow(() => page.emit('request', req()));
  assert.doesNotThrow(() => page.emit('websocket', socket()));
  await new Promise(r => setTimeout(r, 0));
  assert.equal(aborts.length, 1); assert.deepEqual(counter.used(), { direct: 20, reserve: 0, adc: 0, overflow: 11 });
});

// ---- B2: quiet teardown ----
test('B2 the events app closer does not call goOffline on a database the recorder already deleted (no FIREBASE FATAL ERROR on stderr)', async () => {
  const A = await import('firebase/app'), D = await import('firebase/database');
  const errors = [], original = console.error;
  console.error = (...args) => { errors.push(args.map(String).join(' ')); };
  try {
    const app = A.initializeApp({ projectId: 'demo-quiet', databaseURL: 'http://127.0.0.1:9?ns=quiet' }, 'quiet-deleted'), db = D.getDatabase(app);
    D.ref(db, 'x');   // the database is started, as in a profile
    await A.deleteApp(app);   // what runEventsProfile's finally does
    await eventsAppCloser(D, A, app, db)();
    const live = A.initializeApp({ projectId: 'demo-quiet', databaseURL: 'http://127.0.0.1:9?ns=quiet' }, 'quiet-live'), liveDb = D.getDatabase(live);
    D.ref(liveDb, 'x');
    await eventsAppCloser(D, A, live, liveDb)();   // an abandoned profile: the closer still takes the app offline and deletes it
    assert.equal(live.isDeleted, true);
  } finally { console.error = original; }
  assert.deepEqual(errors.filter(e => e.includes('FIREBASE FATAL ERROR')), []);
});
test('B2 a whole events WebSocket profile and its closers write no FIREBASE FATAL ERROR (startup read against a closed port, bounded by the 10 s step)', { timeout: 60000 }, async () => {
  const { eventsWsProfile } = await import('./observer.mjs'), { createServer } = await import('node:net');
  const probe = createServer(); await new Promise(r => probe.listen(0, '127.0.0.1', r)); const port = probe.address().port; await new Promise(r => probe.close(r));   // a port nobody listens on
  const errors = [], original = console.error;
  console.error = (...args) => { errors.push(args.map(String).join(' ')); };
  const ctx = { profile: 'r1-ws', scope: 'p/sdk-events/r1-ws', transport: 'ws', databaseURL: `http://127.0.0.1:${port}?ns=quiet-profile`, projectId: 'demo-quiet', local: true, journal: { write() {} }, counter: createCounter({ direct: 1000 }), abort() {}, closeMs: 1000, closers: [] };
  try {
    const rows = await eventsWsProfile(ctx);
    assert.equal(rows[0].id, 'startup'); assert.equal(rows[0].ok, false);
    assert.ok(ctx.closers.length >= 1, 'the profile registered its app closers');
    for (const close of ctx.closers.splice(0).reverse()) await close();
  } finally { console.error = original; }
  assert.deepEqual(errors.filter(e => e.includes('FIREBASE FATAL ERROR')), []);
});
