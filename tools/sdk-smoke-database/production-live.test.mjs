import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { assertEndpoint, createBudget, relayHttp, runProductionLiveProbe, selectRelayResponseHeaders } from './production-live.mjs';

const limits = { httpAttempts: 8, wsConnections: 4, clientMessages: 10, serverMessages: 10, outboundBytes: 1000, inboundBytes: 1000, responseBytes: 100 };
const config = () => ({ projectId: 'test-project', databaseURL: 'https://test-db.firebaseio.com', namespace: 'test-db', allowedOrigins: ['https://test-db.firebaseio.com', 'wss://test-db.firebaseio.com'], prefixes: ['owned/sdk/round1/ws', 'owned/sdk/round1/lp', 'owned/sdk/round2/ws', 'owned/sdk/round2/lp'], deadlineMs: 1000, limits: { ...limits } });

test('endpoint guard rejects near misses before forwarding', () => {
  const c = config();
  assert.equal(assertEndpoint('https://test-db.firebaseio.com/.lp?ns=test-db', 'http', c).pathname, '/.lp');
  assert.equal(assertEndpoint('wss://test-db.firebaseio.com/.ws?ns=test-db', 'ws', c).pathname, '/.ws');
  for (const url of ['https://other.firebaseio.com/.lp?ns=test-db', 'http://test-db.firebaseio.com/.lp?ns=test-db', 'https://test-db.firebaseio.com/other?ns=test-db', 'https://test-db.firebaseio.com/.lp?ns=other', 'https://test-db.firebaseio.com/.lp?ns=test-db&ns=other', 'https://u:p@test-db.firebaseio.com/.lp?ns=test-db', 'https://test-db.firebaseio.com/.lp?ns=test-db&auth=secret']) {
    assert.throws(() => assertEndpoint(url, 'http', c));
  }
});

test('budget is atomic, fail closed, and cannot resume after exhaustion', () => {
  const events = [];
  const b = createBudget({ limits: { ...limits, outboundBytes: 2 }, deadlineMs: 1000, record: e => events.push(e) });
  b.reserve({ httpAttempts: 1, outboundBytes: 2 });
  assert.throws(() => b.reserve({ httpAttempts: 1, outboundBytes: 1 }), /outboundBytes/);
  assert.equal(b.snapshot().httpAttempts, 1);
  assert.throws(() => b.reserve({ httpAttempts: 1 }), /stopped/);
  assert.equal(events.at(-1).type, 'stop');
  b.close();
});

test('unknown counters, recorder failure and deadline stop the budget', () => {
  for (const change of [{ mystery: 1 }, { httpAttempts: -1 }, { httpAttempts: NaN }]) {
    const b = createBudget({ limits, deadlineMs: 1000, record() {} });
    assert.throws(() => b.reserve(change));
    assert.throws(() => b.reserve({ httpAttempts: 1 }), /stopped/);
    b.close();
  }
  let now = 2_700_000;
  const b = createBudget({ limits, deadlineMs: 10, now: () => now, record() {} });
  now += 10;
  assert.throws(() => b.reserve({ httpAttempts: 1 }), /deadline/);
  b.close();
  const bad = createBudget({ limits, deadlineMs: 1000, record() { throw Error('disk'); } });
  assert.throws(() => bad.event({ type: 'wire' }), /disk/);
  assert.throws(() => bad.reserve({ httpAttempts: 1 }), /stopped/);
  bad.close();
});

function fakeRequest(status = 200, chunks = ['ok']) {
  const state = { sends: 0, destroyed: 0 };
  state.request = (_url, options, callback) => {
    state.options = options;
    const req = new EventEmitter();
    req.destroy = () => { state.destroyed++; req.emit('error', Error('destroyed')); };
    req.end = () => { state.sends++; queueMicrotask(() => { const response = new EventEmitter(); response.statusCode = status; response.headers = { 'content-type': 'text/plain', location: 'https://other.invalid/' }; response.destroy = () => {}; callback(response); for (const chunk of chunks) response.emit('data', Buffer.from(chunk)); response.emit('end'); }); };
    return req;
  };
  return state;
}

test('HTTP relay reserves before send, refuses redirects and caps body', async () => {
  for (const [status, chunks, error] of [[302, ['redirect'], /redirect/], [200, ['a'.repeat(101)], /responseBytes/]]) {
    const fake = fakeRequest(status, chunks);
    const b = createBudget({ limits, deadlineMs: 1000, record() {} });
    await assert.rejects(relayHttp({ url: 'https://test-db.firebaseio.com/.lp?ns=test-db', method: 'GET', body: null, headers: {} }, { config: config(), budget: b, request: fake.request }), error);
    assert.equal(fake.sends, 1);
    assert.equal(fake.options.headers.cookie, undefined);
    b.close();
  }
  const fake = fakeRequest();
  const b = createBudget({ limits: { ...limits, httpAttempts: 0 }, deadlineMs: 1000, record() {} });
  await assert.rejects(relayHttp({ url: 'https://test-db.firebaseio.com/.lp?ns=test-db', method: 'GET', body: null, headers: {} }, { config: config(), budget: b, request: fake.request }));
  assert.equal(fake.sends, 0);
  b.close();
});

test('HTTP relay destroys a stalled request on the absolute deadline', async () => {
  let destroyed = 0;
  const b = createBudget({ limits, deadlineMs: 15, record() {} });
  await assert.rejects(relayHttp({ url: 'https://test-db.firebaseio.com/.lp?ns=test-db', method: 'GET', body: null, headers: {} }, { config: config(), budget: b, request() { const req = new EventEmitter(); req.end = () => {}; req.destroy = () => { destroyed++; req.emit('error', Error('destroyed')); }; return req; } }));
  assert.equal(destroyed, 1);
  b.close();
});

test('probe rejects invalid configuration without launching', async () => {
  let launches = 0;
  await assert.rejects(runProductionLiveProbe({ playwright: { chromium: { launch() { launches++; } } }, config: { ...config(), prefixes: [''] }, bundlePaths: {}, record() {} }));
  assert.equal(launches, 0);
});

test('probe closes browser and contexts after page failure', async () => {
  const calls = [];
  const page = { route: async () => {}, routeWebSocket: async () => {}, exposeFunction: async () => {}, on() {}, goto: async () => { throw Error('page failure'); }, evaluate: async () => {} };
  const context = { newPage: async () => page, close: async () => calls.push('context') };
  const browser = { newContext: async () => context, close: async () => calls.push('browser') };
  await assert.rejects(runProductionLiveProbe({ playwright: { chromium: { launch: async () => browser } }, config: config(), bundlePaths: { app: new URL(import.meta.url), database: new URL(import.meta.url) }, record() {} }), /page failure/);
  assert.deepEqual(calls, ['context', 'browser']);
});

function browserHarness(onNavigate = () => {}) {
  const calls = [];
  const pages = [];
  const browser = {
    async newContext() {
      const page = { handlers: {}, async route(_pattern, handler) { this.handlers.http = handler; }, async routeWebSocket(_pattern, handler) { this.handlers.ws = handler; }, async exposeFunction() {}, on() {}, async goto() { await onNavigate(this); }, async evaluate() {} };
      pages.push(page);
      return { async newPage() { return page; }, async close() { calls.push('context'); } };
    },
    async close() { calls.push('browser'); },
  };
  return { calls, pages, playwright: { chromium: { launch: async () => browser } } };
}
const bundles = { app: new URL(import.meta.url), database: new URL(import.meta.url) };
function socketPair(url = 'wss://test-db.firebaseio.com/.ws?ns=test-db') {
  const state = { connections: 0, sent: [], closes: 0 };
  const server = { onMessage(fn) { this.receive = fn; }, send(message) { state.sent.push(['out', message]); }, close() { state.closes++; } };
  const client = { url: () => url, connectToServer() { state.connections++; return server; }, onMessage(fn) { this.receive = fn; }, send(message) { state.sent.push(['in', message]); }, close() { state.closes++; } };
  return { state, client, server };
}

test('WS handlers account and explicitly forward both directions before closing all handles', async () => {
  const sockets = [];
  const events = [];
  const harness = browserHarness(page => {
    const pair = socketPair();
    sockets.push(pair);
    page.handlers.ws(pair.client);
    pair.client.receive('é');
    pair.server.receive(Buffer.from([1, 2, 3]));
  });
  const result = await runProductionLiveProbe({ playwright: harness.playwright, config: config(), bundlePaths: bundles, record: event => events.push(event) });
  assert.equal(result.counters.wsConnections, 4);
  assert.equal(result.counters.clientMessages, 4);
  assert.equal(result.counters.outboundBytes, 8);
  assert.equal(result.counters.inboundBytes, 12);
  assert.equal(events.filter(e => e.type === 'ws-message').length, 8);
  assert.deepEqual(sockets[0].state.sent, [['out', 'é'], ['in', Buffer.from([1, 2, 3])]]);
  assert.ok(sockets.every(pair => pair.state.closes >= 2));
  assert.equal(harness.calls.filter(value => value === 'context').length, 4);
  assert.equal(harness.calls.at(-1), 'browser');
});

test('WS byte exhaustion synchronously prevents this and every later forward', async () => {
  const pair = socketPair();
  const harness = browserHarness(page => {
    page.handlers.ws(pair.client);
    pair.client.receive('abc');
    pair.client.receive('x');
    pair.server.receive('y');
  });
  const c = config();
  c.limits.outboundBytes = 2;
  await assert.rejects(runProductionLiveProbe({ playwright: harness.playwright, config: c, bundlePaths: bundles, record() {} }), /stopped/);
  assert.deepEqual(pair.state.sent, []);
  assert.equal(pair.state.connections, 1);
  assert.ok(pair.state.closes >= 2);
});

test('unknown WS endpoint never creates an upstream connection', async () => {
  const pair = socketPair('wss://redirect.firebaseio.com/.ws?ns=test-db');
  const harness = browserHarness(page => page.handlers.ws(pair.client));
  await assert.rejects(runProductionLiveProbe({ playwright: harness.playwright, config: config(), bundlePaths: bundles, record() {} }), /Unapproved/);
  assert.equal(pair.state.connections, 0);
  assert.ok(pair.state.closes >= 1);
});

test('deadline during page navigation closes context and browser', async () => {
  const harness = browserHarness(() => new Promise(() => {}));
  const c = config();
  c.deadlineMs = 15;
  await assert.rejects(runProductionLiveProbe({ playwright: harness.playwright, config: c, bundlePaths: bundles, record() {} }), /deadline/);
  assert.deepEqual(harness.calls, ['context', 'browser']);
});

test('late browser launch is closed and awaited before returning failure', async () => {
  let closed = false;
  const c = config();
  c.deadlineMs = 5;
  const playwright = { chromium: { launch: () => new Promise(resolve => setTimeout(() => resolve({ close: () => new Promise(done => setTimeout(() => { closed = true; done(); }, 15)) }), 15)) } };
  await assert.rejects(runProductionLiveProbe({ playwright, config: c, bundlePaths: bundles, record() {} }), /deadline/);
  assert.equal(closed, true);
});

test('HTTP URL payload consumes outgoing budget before opening a request', async () => {
  const fake = fakeRequest();
  const c = config();
  c.limits.outboundBytes = 10;
  const b = createBudget({ limits: c.limits, deadlineMs: 1000, record() {} });
  await assert.rejects(relayHttp({ url: 'https://test-db.firebaseio.com/.lp?ns=test-db&d=payload', method: 'GET', headers: {}, body: null }, { config: c, budget: b, request: fake.request }), /outboundBytes/);
  assert.equal(fake.sends, 0);
  b.close();
});

test('asynchronous socket closure settles before the helper returns', async () => {
  const pair = socketPair();
  let closed = 0;
  for (const socket of [pair.client, pair.server]) socket.close = () => new Promise(resolve => setTimeout(() => { closed++; resolve(); }, 10));
  const harness = browserHarness(page => page.handlers.ws(pair.client));
  await runProductionLiveProbe({ playwright: harness.playwright, config: config(), bundlePaths: bundles, record() {} });
  assert.equal(closed, 2);
});

test('socket closure failure prevents a successful receipt', async () => {
  const pair = socketPair();
  pair.server.close = async () => { throw Error('socket cleanup failure'); };
  const harness = browserHarness(page => page.handlers.ws(pair.client));
  await assert.rejects(runProductionLiveProbe({ playwright: harness.playwright, config: config(), bundlePaths: bundles, record() {} }), /Probe cleanup failed/);
  assert.equal(harness.calls.at(-1), 'browser');
});

test('final stop recorder failure still closes the browser after all contexts', async () => {
  const harness = browserHarness();
  const failure = Error('final stop persistence failed');
  await assert.rejects(runProductionLiveProbe({ playwright: harness.playwright, config: config(), bundlePaths: bundles, record(event) { if (event.type === 'stop' && event.reason === 'closed') throw failure; } }), error => error instanceof AggregateError && error.errors.includes(failure));
  assert.deepEqual(harness.calls, ['context', 'context', 'context', 'context', 'browser']);
});

test('primary failure survives concurrent recorder and browser cleanup failures', async () => {
  const primary = Error('original page failure');
  const recorder = Error('stop persistence failure');
  const cleanup = Error('browser cleanup failure');
  let browserClosed = false;
  const page = { route: async () => {}, routeWebSocket: async () => {}, exposeFunction: async () => {}, on() {}, goto: async () => { throw primary; }, evaluate: async () => {} };
  const browser = { newContext: async () => ({ newPage: async () => page, close: async () => {} }), close: async () => { browserClosed = true; throw cleanup; } };
  await assert.rejects(runProductionLiveProbe({ playwright: { chromium: { launch: async () => browser } }, config: config(), bundlePaths: bundles, record(event) { if (event.type === 'stop') throw recorder; } }), error => error instanceof AggregateError && [primary, recorder, cleanup].every(failure => error.errors.includes(failure)));
  assert.equal(browserClosed, true);
});

test('HTTP receipts expose real cumulative inbound bytes and no per-response limit counter', async () => {
  const c = config();
  c.limits.responseBytes = 5;
  const events = [];
  const budget = createBudget({ limits: c.limits, deadlineMs: 1000, record: event => events.push(event) });
  try {
    for (let i = 0; i < 2; i++) {
      const fake = fakeRequest(200, ['ab', 'cd']);
      const result = await relayHttp({ url: 'https://test-db.firebaseio.com/.lp?ns=test-db', method: 'GET', body: null, headers: {} }, { config: c, budget, request: fake.request });
      assert.equal(result.body.toString(), 'abcd');
    }
    assert.equal(budget.snapshot().inboundBytes, 8);
    assert.equal(Object.hasOwn(budget.snapshot(), 'responseBytes'), false);
    assert.deepEqual(events.filter(event => event.type === 'http-chunk').map(event => event.counters.inboundBytes), [2, 4, 6, 8]);
    assert.ok(events.every(event => !Object.hasOwn(event.counters, 'responseBytes')));
  } finally { budget.close(); }
});

test('public primary namespace hosts allow omitted ns for WS and LP', () => {
  for (const host of ['test-db.firebaseio.com', 'test-db.us-central1.firebasedatabase.app', 'test-db.europe-west1.firebasedatabase.app', 'test-db.asia-southeast1.firebasedatabase.app']) {
    const c = { ...config(), databaseURL: `https://${host}`, allowedOrigins: [`https://${host}`, `wss://${host}`] };
    for (const [scheme, path, kind] of [['wss', '/.ws', 'ws'], ['https', '/.lp', 'http']]) {
      const url = `${scheme}://${host}${path}?v=5`;
      assert.equal(assertEndpoint(url, kind, c).href, url);
      assert.throws(() => assertEndpoint(`${url}&ns=wrong`, kind, c));
      assert.throws(() => assertEndpoint(`${url}&ns=test-db&ns=test-db`, kind, c));
    }
  }
});

test('omitted ns cannot infer identity from arbitrary or mismatched allowed hosts', () => {
  for (const host of ['other.firebaseio.com', 'test-db.s-usc1c-nss-1.firebaseio.com', 'test-db.firebaseio.com.evil.invalid', 'test-db.firebaseio.com:8443', 'test-db.unknown1.firebasedatabase.app', 'other.europe-west1.firebasedatabase.app', 'test-db.europe-west1.firebasedatabase.app.evil.invalid', 'test-db.europe-west1.extra.firebasedatabase.app', 'test-db.invalid']) {
    const c = { ...config(), allowedOrigins: [`https://${host}`, `wss://${host}`] };
    assert.throws(() => assertEndpoint(`wss://${host}/.ws?v=5`, 'ws', c));
    assert.throws(() => assertEndpoint(`https://${host}/.lp?v=5`, 'http', c));
  }
  const c = config();
  assert.throws(() => assertEndpoint('wss://test-db.europe-west1.firebasedatabase.app/.ws?v=5', 'ws', c));
  assert.throws(() => assertEndpoint('wss://s-internal.firebaseio.com/.ws?v=5&ns=test-db', 'ws', c));
});


test('relay preserves end-to-end policies, CORS, representation and passive metadata without mutation', () => {
  const raw = Object.freeze({ 'Permissions-Policy': 'unload=()', 'Content-Security-Policy': "default-src 'none'; frame-ancestors 'self'", 'X-Frame-Options': 'SAMEORIGIN', 'Cross-Origin-Resource-Policy': 'same-origin', 'Cross-Origin-Embedder-Policy': 'require-corp', 'Cross-Origin-Opener-Policy': 'same-origin', 'Referrer-Policy': 'no-referrer', 'Access-Control-Allow-Origin': 'https://client.invalid', 'Cache-Control': 'no-cache', ETag: '"original"', 'Content-Type': 'text/javascript; charset=utf-8', 'Content-Encoding': 'gzip', 'X-Passive-Unknown': 'original-value' });
  const selected = selectRelayResponseHeaders(raw);
  assert.deepEqual(selected, Object.fromEntries(Object.entries(raw).map(([name, value]) => [name.toLowerCase(), value])));
  assert.equal(raw['Permissions-Policy'], 'unload=()');
});

test('relay removes fixed and Connection-nominated hop headers, framing and transport hints', () => {
  const headers = { CONNECTION: 'keep-alive, X-Private-Hop', 'x-private-hop': 'remove', 'Keep-Alive': 'timeout=5', 'Proxy-Connection': 'close', 'Proxy-Authenticate': 'Basic', 'Proxy-Authorization': 'secret', TE: 'trailers', Trailer: 'digest', 'Transfer-Encoding': 'chunked', Upgrade: 'websocket', 'Content-Length': '999', 'Alt-Svc': 'h3=":443"', 'content-type': 'text/plain' };
  assert.deepEqual(selectRelayResponseHeaders(headers), { 'content-type': 'text/plain' });
});

test('relay refuses session, reporting, navigation and network-hint response features', () => {
  for (const [name, value] of [['Set-Cookie', ['a=1', 'b=2']], ['set-cookie2', 'a=1'], ['Report-To', '{}'], ['Reporting-Endpoints', 'default="https://collector.invalid"'], ['NEL', '{}'], ['Refresh', '1; url=https://other.invalid'], ['Link', '</other>; rel=prefetch'], ['Location', 'https://other.invalid'], ['Content-Security-Policy', "default-src 'self'; REPORT-URI /report"], ['Content-Security-Policy-Report-Only', "default-src 'self'; report-to group"], ['Content-Security-Policy', "default-src 'self', report-uri /report"]]) {
    assert.throws(() => selectRelayResponseHeaders({ [name]: value }), /Unsupported/);
    assert.throws(() => selectRelayResponseHeaders({ Connection: name, [name]: value }), /Unsupported/);
  }
});

test('relay explicitly combines list-valued arrays and rejects ambiguous or malformed multiplicity', () => {
  const raw = Object.freeze({ Vary: Object.freeze(['Origin', 'Accept-Encoding']), 'Cache-Control': Object.freeze(['no-store', 'max-age=0']) });
  assert.deepEqual(selectRelayResponseHeaders(raw), { vary: 'Origin, Accept-Encoding', 'cache-control': 'no-store, max-age=0' });
  assert.deepEqual(raw.Vary, ['Origin', 'Accept-Encoding']);
  for (const headers of [{ 'content-type': ['text/plain', 'text/html'] }, { 'x-unknown': ['one', 'two'] }, { 'x-empty': [] }, { 'x-value': 42 }, { 'Bad Name': 'x' }, { 'x-value': 'a\r\nb' }]) assert.throws(() => selectRelayResponseHeaders(headers));
});


test('relay keeps compressed bytes unchanged and records raw response header pairs', async () => {
  const rawHeaders = ['Content-Encoding', 'gzip', 'Permissions-Policy', 'unload=()'];
  const headers = { 'content-encoding': 'gzip', 'permissions-policy': 'unload=()' };
  const encoded = Buffer.from([0x1f, 0x8b, 0x08, 0x00]);
  const events = [];
  const budget = createBudget({ limits, deadlineMs: 1000, record: event => events.push(event) });
  const request = (_url, _options, callback) => {
    const req = new EventEmitter();
    req.destroy = () => {};
    req.end = () => queueMicrotask(() => {
      const response = new EventEmitter();
      Object.assign(response, { statusCode: 200, headers, rawHeaders, destroy() {} });
      callback(response);
      response.emit('data', encoded);
      response.emit('end');
    });
    return req;
  };
  try {
    const result = await relayHttp({ url: 'https://test-db.firebaseio.com/.lp?ns=test-db', method: 'GET', headers: {}, body: null }, { config: config(), budget, request });
    assert.deepEqual(result.body, encoded);
    assert.deepEqual(selectRelayResponseHeaders(result.headers), headers);
    assert.deepEqual(events.find(event => event.type === 'http-response').rawHeaders, rawHeaders);
    assert.deepEqual(events.find(event => event.type === 'http-response').headers, headers);
  } finally { budget.close(); }
});
