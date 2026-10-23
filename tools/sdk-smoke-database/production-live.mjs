// This helper supplies bounded transport mechanics; configuration is not authorization.
import { readFile } from 'node:fs/promises';
import { request as httpsRequest } from 'node:https';
import { performance } from 'node:perf_hooks';

const COUNTERS = ['httpAttempts', 'wsConnections', 'clientMessages', 'serverMessages', 'outboundBytes', 'inboundBytes', 'responseBytes'];
const APP = 'https://www.gstatic.com/firebasejs/12.18.0/firebase-app.js';
const DATABASE = 'https://www.gstatic.com/firebasejs/12.18.0/firebase-database.js';
const PAGE = 'http://rtdb-probe.invalid/';

export function assertEndpoint(raw, kind, config) {
  const url = new URL(raw);
  if (!['http', 'ws'].includes(kind) || url.username || url.password || url.hash || !config.allowedOrigins.includes(url.origin) || url.protocol !== (kind === 'ws' ? 'wss:' : 'https:') || url.pathname !== (kind === 'ws' ? '/.ws' : '/.lp') || url.searchParams.getAll('ns').length !== 1 || url.searchParams.get('ns') !== config.namespace || [...url.searchParams.keys()].some(k => /auth|token|credential/i.test(k))) {
    throw Error(`Unapproved ${kind} endpoint: ${raw}`);
  }
  return url;
}

export function createBudget({ limits, deadlineMs, record, now = () => performance.now() }) {
  for (const key of COUNTERS) if (!Number.isSafeInteger(limits?.[key]) || limits[key] < 0) throw Error(`Invalid limit: ${key}`);
  if (!Number.isSafeInteger(deadlineMs) || deadlineMs <= 0 || typeof record !== 'function') throw Error('Invalid deadline or recorder');
  const counters = Object.fromEntries(COUNTERS.map(k => [k, 0]));
  const end = now() + deadlineMs;
  let stopped = false;
  let reason;
  let sequence = 0;
  const listeners = new Set();
  const event = data => {
    try {
      const result = record({ ...data, sequence: ++sequence, monotonicMs: now(), counters: { ...counters } });
      if (result && typeof result.then === 'function') throw Error('Recorder must synchronously persist events');
    } catch (error) { stop(`recorder: ${error.message}`, false); throw error; }
  };
  const stop = (why, persist = true) => {
    if (stopped) return;
    stopped = true;
    reason = String(why);
    clearTimeout(timer);
    for (const listener of [...listeners]) { try { listener(reason); } catch {} }
    if (persist) event({ type: 'stop', reason });
  };
  const timer = setTimeout(() => { try { stop('deadline'); } catch {} }, deadlineMs);
  const check = () => {
    if (stopped) throw Error(`Budget stopped: ${reason}`);
    if (now() >= end) { stop('deadline'); throw Error('Budget deadline'); }
  };
  return {
    event, stop, check,
    remaining() { check(); return Math.max(1, end - now()); },
    reserve(changes) {
      check();
      for (const [key, value] of Object.entries(changes)) {
        if (!COUNTERS.includes(key) || !Number.isSafeInteger(value) || value < 0 || counters[key] + value > limits[key]) {
          stop(`limit: ${key}`);
          throw Error(`Budget exceeded: ${key}`);
        }
      }
      for (const [key, value] of Object.entries(changes)) counters[key] += value;
    },
    snapshot: () => ({ ...counters }),
    onStop(fn) { if (stopped) fn(reason); else listeners.add(fn); return () => listeners.delete(fn); },
    close() { clearTimeout(timer); },
  };
}

export async function relayHttp(input, { config, budget, request = httpsRequest }) {
  let url;
  try {
    budget.check();
    budget.event({ type: 'http-attempt', url: input.url, method: input.method });
    url = assertEndpoint(input.url, 'http', config);
    if (!['GET', 'POST'].includes(input.method)) throw Error('Unapproved HTTP method');
    const body = input.body === null || input.body === undefined ? Buffer.alloc(0) : Buffer.from(input.body);
    budget.reserve({ httpAttempts: 1, outboundBytes: Buffer.byteLength(url.href, 'utf8') + body.length });
    budget.event({ type: 'http-forward', url: url.href, method: input.method, bodyBase64: body.toString('base64') });
    budget.check();
    return await new Promise((resolve, reject) => {
      let req;
      let response;
      let settled = false;
      let unregister = () => {};
      const finish = (error, result) => {
        if (settled) return;
        settled = true;
        unregister();
        if (error) {
          response?.destroy();
          req?.destroy();
          reject(error);
        } else resolve(result);
      };
      req = request(url, { method: input.method, headers: { ...(input.headers?.['content-type'] ? { 'content-type': input.headers['content-type'] } : {}), ...(body.length ? { 'content-length': String(body.length) } : {}) }, timeout: Math.ceil(budget.remaining()) }, res => {
        response = res;
        let size = 0;
        const chunks = [];
        try {
          budget.event({ type: 'http-response', url: url.href, status: res.statusCode, headers: res.headers });
          if (!Number.isInteger(res.statusCode) || res.statusCode < 200 || res.statusCode >= 300) throw Error(`HTTP status/redirect: ${res.statusCode}`);
        } catch (error) { finish(error); return; }
        res.on('data', chunk => {
          if (settled) return;
          try {
            const bytes = Buffer.from(chunk);
            budget.reserve({ inboundBytes: bytes.length });
            size += bytes.length;
            if (size > config.limits.responseBytes) throw Error('HTTP responseBytes exceeded');
            budget.event({ type: 'http-chunk', url: url.href, bodyBase64: bytes.toString('base64') });
            chunks.push(bytes);
          } catch (error) { budget.stop(error.message); finish(error); }
        });
        res.on('error', error => finish(error));
        res.on('aborted', () => finish(Error('HTTP response aborted')));
        res.on('end', () => finish(null, { status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
      });
      req.on('error', error => finish(error));
      req.on('timeout', () => { budget.stop('HTTP timeout'); finish(Error('HTTP timeout')); });
      unregister = budget.onStop(reason => finish(Error(`Budget stopped: ${reason}`)));
      if (!settled) req.end(body);
    });
  } catch (error) {
    budget.stop(error.message);
    throw error;
  }
}

function validateConfig(config) {
  if (!config || !/^[a-z][a-z0-9-]*$/.test(config.projectId) || !/^[a-z0-9-]+$/.test(config.namespace)) throw Error('Invalid project or namespace');
  const db = new URL(config.databaseURL);
  if (db.protocol !== 'https:' || db.pathname !== '/' || db.search || db.hash || db.username || db.password) throw Error('Invalid databaseURL');
  if (!Array.isArray(config.allowedOrigins) || config.allowedOrigins.length !== 2 || !config.allowedOrigins.includes(db.origin) || !config.allowedOrigins.includes(db.origin.replace('https:', 'wss:'))) throw Error('Expected exact database HTTP/WS origins');
  if (!Array.isArray(config.prefixes) || config.prefixes.length !== 4 || new Set(config.prefixes).size !== 4 || config.prefixes.some((prefix, i) => typeof prefix !== 'string' || !/^[A-Za-z0-9_-]+(?:\/[A-Za-z0-9_-]+)+$/.test(prefix) || !prefix.endsWith(`/round${Math.floor(i / 2) + 1}/${i % 2 ? 'lp' : 'ws'}`)) || new Set(config.prefixes.map(p => p.replace(/\/round[12]\/(?:ws|lp)$/, ''))).size !== 1) throw Error('Expected four unique scoped round/transport prefixes');
}

// Executed inside a synthetic page. Each callback is durably relayed before advancing.
async function sdkScenario({ appUrl, databaseUrl, config, prefix, transport }) {
  const app = await import(appUrl);
  const sdk = await import(databaseUrl);
  const emit = event => window.__probeRecord(event);
  const apps = [];
  const dbs = [];
  const unsubscribes = [];
  window.__probeCleanup = async () => {
    for (const unsubscribe of unsubscribes.splice(0)) unsubscribe();
    for (const db of dbs) sdk.goOffline(db);
    await Promise.all(apps.splice(0).map(a => app.deleteApp(a)));
  };
  try {
    if (transport === 'ws') sdk.forceWebSockets(); else sdk.forceLongPolling();
    for (const role of ['writer', 'observer']) {
      const a = app.initializeApp({ projectId: config.projectId, databaseURL: config.databaseURL }, `${prefix}:${role}`);
      apps.push(a);
      dbs.push(sdk.getDatabase(a));
    }
    const writer = sdk.ref(dbs[0], `${prefix}/presence`);
    const observer = sdk.ref(dbs[1], `${prefix}/presence`);
    await emit({ type: 'sdk-step', step: 'set-online', prefix, transport });
    await sdk.set(writer, { state: 'online' });
    await emit({ type: 'sdk-ack', step: 'set-online' });
    let resolveOnline, resolveOffline, rejectOnline, rejectOffline;
    const online = new Promise((resolve, reject) => { resolveOnline = resolve; rejectOnline = reject; });
    const offline = new Promise((resolve, reject) => { resolveOffline = resolve; rejectOffline = reject; });
    // The offline rejection can arrive while the online promise is still pending.
    offline.catch(() => {});
    unsubscribes.push(sdk.onValue(observer, snapshot => {
      const value = snapshot.val();
      emit({ type: 'sdk-callback', value }).then(() => {
        if (value?.state === 'online') resolveOnline();
        if (value?.state === 'offline') resolveOffline();
      }, error => { rejectOnline(error); rejectOffline(error); });
    }, error => { emit({ type: 'sdk-cancel', code: error.code, message: error.message }).then(() => { rejectOnline(error); rejectOffline(error); }, failure => { rejectOnline(failure); rejectOffline(failure); }); }));
    await online;
    await sdk.onDisconnect(writer).set({ state: 'offline' });
    await emit({ type: 'sdk-ack', step: 'onDisconnect-offline' });
    sdk.goOffline(dbs[0]);
    await emit({ type: 'sdk-step', step: 'writer-offline' });
    await offline;
    const snapshot = await sdk.get(observer);
    await emit({ type: 'sdk-get', value: snapshot.val() });
    await sdk.remove(observer);
    await emit({ type: 'sdk-ack', step: 'remove' });
  } catch (error) {
    await emit({ type: 'sdk-error', name: error.name, code: error.code, message: error.message });
    throw error;
  } finally {
    await window.__probeCleanup();
  }
}

export async function runProductionLiveProbe({ playwright, config, bundlePaths, record }) {
  validateConfig(config);
  const budget = createBudget({ limits: config.limits, deadlineMs: config.deadlineMs, record });
  const contexts = new Set();
  const sockets = new Set();
  const pending = new Set();
  const closingSockets = new Set();
  const cleanupFailures = [];
  let browser;
  let stoppedReason;
  let rejectStopped;
  const stopped = new Promise((_, reject) => { rejectStopped = reject; });
  stopped.catch(() => {});
  const track = promise => { pending.add(promise); promise.finally(() => pending.delete(promise)).catch(() => {}); return promise; };
  const closeSocket = socket => {
    if (closingSockets.has(socket)) return;
    closingSockets.add(socket);
    try { track(Promise.resolve(socket.close({ code: 1000, reason: 'probe stopped' })).catch(error => { cleanupFailures.push(error); })); } catch (error) { cleanupFailures.push(error); }
  };
  const unregister = budget.onStop(reason => {
    stoppedReason = reason;
    for (const socket of sockets) closeSocket(socket);
    rejectStopped(Error(`Probe stopped: ${reason}`));
  });
  const bounded = operation => Promise.race([operation, stopped]);
  try {
    const [appBytes, dbBytes] = await bounded(Promise.all([readFile(bundlePaths.app), readFile(bundlePaths.database)]));
    budget.check();
    // Retain the launch promise so a browser arriving after the deadline is still closed.
    const launch = track(playwright.chromium.launch({ headless: true, timeout: Math.ceil(budget.remaining()) }));
    launch.then(value => { browser = value; if (stoppedReason) track(value.close()); }, () => {});
    browser = await bounded(launch);
    for (let i = 0; i < config.prefixes.length; i++) {
      budget.check();
      const contextPromise = track(browser.newContext({ serviceWorkers: 'block' }));
      contextPromise.then(value => { contexts.add(value); if (stoppedReason) track(value.close()); }, () => {});
      const context = await bounded(contextPromise);
      let page;
      try {
        page = await bounded(context.newPage());
        await page.exposeFunction('__probeRecord', event => budget.event({ ...event, prefix: config.prefixes[i], transport: i % 2 ? 'lp' : 'ws' }));
        page.on('pageerror', error => { try { budget.event({ type: 'page-error', message: error.message }); budget.stop('page-error'); } catch {} });
        await page.route('**/*', async route => {
          try {
            budget.check();
            const req = route.request();
            const url = req.url();
            if (url === PAGE || url === APP || url === DATABASE) {
              budget.event({ type: 'local-fulfill', url });
              await route.fulfill({ status: 200, headers: { 'access-control-allow-origin': '*' }, contentType: url === PAGE ? 'text/html' : 'text/javascript', body: url === PAGE ? '<!doctype html><html><head><link rel="icon" href="data:,"></head><body></body></html>' : url === APP ? appBytes : dbBytes });
              return;
            }
            const response = await track(relayHttp({ url, method: req.method(), headers: req.headers(), body: req.postDataBuffer() }, { config, budget }));
            budget.check();
            const headers = Object.fromEntries(Object.entries(response.headers).filter(([key]) => ['content-type', 'cache-control'].includes(key)).map(([key, value]) => [key, String(value)]));
            await route.fulfill({ ...response, headers });
          } catch (error) {
            budget.stop(error.message);
            try { await route.abort('blockedbyclient'); } catch {}
          }
        });
        await page.routeWebSocket('**/*', socket => {
          sockets.add(socket);
          try {
            budget.check();
            budget.event({ type: 'ws-attempt', url: socket.url() });
            assertEndpoint(socket.url(), 'ws', config);
            budget.reserve({ wsConnections: 1 });
            budget.event({ type: 'ws-connect', url: socket.url() });
            budget.check();
            const server = socket.connectToServer();
            sockets.add(server);
            for (const [source, target, direction] of [[socket, server, 'client'], [server, socket, 'server']]) {
              source.onMessage(message => {
                try {
                  if (typeof message !== 'string' && !Buffer.isBuffer(message)) throw Error('Unknown WS payload');
                  const bytes = Buffer.isBuffer(message) ? message : Buffer.from(message, 'utf8');
                  budget.reserve({ [direction === 'client' ? 'clientMessages' : 'serverMessages']: 1, [direction === 'client' ? 'outboundBytes' : 'inboundBytes']: bytes.length });
                  budget.event({ type: 'ws-message', direction, url: socket.url(), encoding: typeof message === 'string' ? 'utf8' : 'base64', message: typeof message === 'string' ? message : message.toString('base64') });
                  budget.check();
                  target.send(message);
                } catch (error) { budget.stop(error.message); }
              });
            }
          } catch (error) { budget.stop(error.message); closeSocket(socket); }
        });
        await bounded(page.goto(PAGE, { timeout: Math.ceil(budget.remaining()), waitUntil: 'load' }));
        await bounded(page.evaluate(sdkScenario, { appUrl: APP, databaseUrl: DATABASE, config: { projectId: config.projectId, databaseURL: config.databaseURL }, prefix: config.prefixes[i], transport: i % 2 ? 'lp' : 'ws' }));
      } finally {
        // Browser teardown also closes all SDK transports when page evaluation failed.
        if (page && !stoppedReason) await bounded(page.evaluate(() => window.__probeCleanup?.())).catch(() => {});
        await context.close();
        contexts.delete(context);
      }
    }
    budget.event({ type: 'probe-complete' });
    return { complete: true, counters: budget.snapshot() };
  } catch (error) {
    budget.stop(error.message);
    throw error;
  } finally {
    budget.stop('closed');
    unregister();
    for (const socket of sockets) closeSocket(socket);
    const cleanup = await Promise.allSettled([...contexts].map(context => context.close()));
    const browserCleanup = browser ? await Promise.allSettled([browser.close()]) : [];
    while (pending.size) await Promise.allSettled([...pending]);
    budget.close();
    const failures = [...cleanup, ...browserCleanup].filter(result => result.status === 'rejected').map(result => result.reason);
    failures.push(...cleanupFailures);
    if (failures.length) throw new AggregateError(failures, 'Probe cleanup failed');
  }
}
