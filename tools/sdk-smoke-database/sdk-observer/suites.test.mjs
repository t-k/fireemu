// The observer's events (G6) and admin (G13) suites: the run plan, Rules, approval binding, caps, the admin token
// hand-over, the Admin SDK socket counter, and that the small suite's recorded case code is untouched.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, cpSync, realpathSync, readFileSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import tls from 'node:tls';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { SUITES, countConnects, endpointOf, expectedObservations, run } from './observer.mjs';
import { checkApproval, createCounter, scriptManifest, sha256 } from './lib.mjs';
import { suiteRules } from './events-rules.mjs';
import { EVENT_CASES } from './events-actor.mjs';
import { ADMIN_CASES } from './admin-suite.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BASELINE = '{\n  "rules": {\n    ".read": false,\n    ".write": false\n  }\n}\n', PREFIX = '/sdkeventstest';
async function fakeServer() {
  const state = { rules: BASELINE, prefix: null, log: [], puts: [] };
  const server = createServer((req, res) => {
    let body = ''; req.on('data', c => { body += c; });
    req.on('end', () => {
      const url = new URL(req.url, 'http://x'); state.log.push(`${req.method} ${url.pathname}`);
      if (url.pathname === '/.settings/rules.json') { if (req.method === 'PUT') { state.rules = body; state.puts.push(body); res.writeHead(200).end('{"status":"ok"}'); } else res.writeHead(200).end(state.rules); return; }
      if (url.pathname === `${PREFIX}.json`) { if (req.method === 'DELETE') state.prefix = null; res.writeHead(200).end(JSON.stringify(state.prefix)); return; }
      res.writeHead(404).end('{}');
    });
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  return { state, host: `127.0.0.1:${server.address().port}`, close: () => { server.closeAllConnections(); server.close(); } };
}
const setupRows = suite => (suite === 'events' ? ['startup', 'startup-observer', 'seed'] : ['startup']).map(id => ({ id, ok: true }));
const caseRows = (suite, fail) => [...setupRows(suite), ...(suite === 'events' ? EVENT_CASES : ADMIN_CASES).map(id => ({ id, ok: id !== fail, steps: [] }))];
function fakeSuites(seen, { fail = {} } = {}) {
  const profile = suite => async ctx => { seen.push({ profile: ctx.profile, scope: ctx.scope, transport: ctx.transport, adminToken: ctx.adminToken }); return caseRows(suite, fail[ctx.profile]); };
  return { events: { ws: profile('events'), lp: profile('events') }, admin: { admin: profile('admin') } };
}
async function harness(suite, { fail, opts = {} } = {}) {
  const server = await fakeServer(), out = mkdtempSync(path.join(tmpdir(), 'events-observer-')), seen = [];
  const target = { kind: 'emulator', host: server.host, namespace: 'ns', projectId: 'demo-x' };
  const outcome = await run({ target, runId: 'TEST-EVENTS-01', prefix: PREFIX, directCap: 40, outDir: path.join(out, 'run'), suite, ...opts }, { suiteProfiles: fakeSuites(seen, { fail }), profiles: { ws: () => { throw new Error('small profile used'); }, lp: () => { throw new Error('small profile used'); } } });
  server.close(); rmSync(out, { recursive: true, force: true });
  return { ...outcome, server, seen };
}

test('events+admin: four events profiles then two admin profiles, each in its own scope; the suite Rules are installed and restored; 52 observations', async () => {
  const h = await harness('events+admin');
  assert.equal(h.exit, 0, JSON.stringify(h.result)); assert.equal(h.result.status, 'complete'); assert.equal(h.result.observed, 52); assert.equal(h.result.suite, 'events+admin');
  assert.deepEqual(h.seen.map(s => [s.profile, s.transport, s.scope]), [
    ['r1-ws', 'ws', 'sdkeventstest/sdk-events/r1-ws'], ['r1-lp', 'lp', 'sdkeventstest/sdk-events/r1-lp'], ['r2-ws', 'ws', 'sdkeventstest/sdk-events/r2-ws'], ['r2-lp', 'lp', 'sdkeventstest/sdk-events/r2-lp'],
    ['r1-admin', 'admin', 'sdkeventstest/sdk-admin/r1-admin'], ['r2-admin', 'admin', 'sdkeventstest/sdk-admin/r2-admin']]);
  assert.deepEqual(JSON.parse(h.server.state.puts[0]), suiteRules(['events', 'admin'], PREFIX)); assert.equal(h.server.state.rules, BASELINE);
  assert.deepEqual(h.result.cleanup, { prefix: 'verified', rules: 'verified' }); assert.ok(h.result.cases.every(c => !('steps' in c)));
  assert.deepEqual([expectedObservations('small'), expectedObservations('events'), expectedObservations('admin'), expectedObservations('events+admin')], [32, 32, 20, 52]);
});
test('single suites run only their own profiles and Rules', async () => {
  const e = await harness('events'), a = await harness('admin');
  assert.deepEqual([e.exit, e.result.observed, e.seen.length], [0, 32, 4]); assert.deepEqual(Object.keys(JSON.parse(e.server.state.puts[0]).rules.sdkeventstest), ['sdk-events']);
  assert.deepEqual([a.exit, a.result.observed, a.seen.map(s => s.profile)], [0, 20, ['r1-admin', 'r2-admin']]); assert.deepEqual(Object.keys(JSON.parse(a.server.state.puts[0]).rules.sdkeventstest), ['sdk-admin']);
});
test('a failed case makes the run incomplete; without --continue-on-failure the later profiles do not run, with it they do', async () => {
  const stop = await harness('events+admin', { fail: { 'r1-lp': 'fanout' } });
  assert.equal(stop.exit, 1); assert.equal(stop.result.status, 'incomplete'); assert.deepEqual(stop.seen.map(s => s.profile), ['r1-ws', 'r1-lp']);
  const go = await harness('events+admin', { fail: { 'r1-lp': 'fanout', 'r1-admin': 'push' }, opts: { continueOnFailure: true } });
  assert.equal(go.exit, 1); assert.equal(go.result.observed, 50); assert.equal(go.seen.length, 6); assert.deepEqual(go.result.cleanup, { prefix: 'verified', rules: 'verified' });
});
test('the run deadline and profile deadline of the new suites are their own; small keeps 90 s and 10 min', () => {
  assert.deepEqual([SUITES.small.profileMs, SUITES.small.runMs, SUITES.small.capMax, SUITES.small.basis], [90000, 600000, 180, '2196']);
  for (const s of ['events', 'admin', 'events+admin']) assert.deepEqual([SUITES[s].capMax, SUITES[s].basis], [250, '2217']);
});

// ---- approval line ----
const line = (fields, runId = 'R1') => `- d | RTDB-SMALL-OBSERVER ${runId} | ${fields} | coordinator | s`;
const SHA = 'a'.repeat(64);
test('approval: the new suites need suite=<suite> and basis=2217; small keeps its exact line', () => {
  const want = suite => ({ runId: 'R1', scriptSha256: SHA, directCap: 200, prefix: '/p', suite });
  const ok = `decision=APPROVE; scriptSha256=${SHA}; directCap=200; adc=1; prefix=/p; suite=events+admin; basis=2217`;
  checkApproval(line(ok), want('events+admin'));
  for (const bad of [ok.replace('basis=2217', 'basis=2196'), ok.replace('; suite=events+admin', ''), ok.replace('suite=events+admin', 'suite=events'), ok.replace('suite=events+admin', 'suite=small'), ok.replace('directCap=200', 'directCap=250'), `${ok}; extra=1`])
    assert.throws(() => checkApproval(line(bad), want('events+admin')), undefined, bad);
  assert.throws(() => checkApproval(line(ok), want('events')));
  const small = `decision=APPROVE; scriptSha256=${SHA}; directCap=200; adc=1; prefix=/p; basis=2196`;
  checkApproval(line(small), want(undefined)); checkApproval(line(small), want('small'));
  assert.throws(() => checkApproval(line(small.replace('2196', '2217')), want('small'))); assert.throws(() => checkApproval(line(`${small}; suite=small`), want('small')));
  assert.throws(() => checkApproval(line(ok), want('everything')), /approval suite/);
});

// ---- production: the admin profiles get the token, nothing else does, the journal never holds it ----
test('production: the minted token is handed to the admin profiles only and never reaches the journal', async () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'events-observer-prod-')), paths = { owner: path.join(dir, 'owner.md'), lease: path.join(dir, 'lease'), recording: path.join(dir, 'RECORDING') };
  const sha = scriptManifest(HERE).sha256, TOKEN = 'ya29.TESTTOKEN-events-not-a-real-credential';
  writeFileSync(paths.owner, `${line(`decision=APPROVE; scriptSha256=${sha}; directCap=200; adc=1; prefix=${PREFIX}; suite=events+admin; basis=2217`, 'PROD-EVENTS-01')}\n`);
  let rules = BASELINE;
  const fetchImpl = async (url, init) => {
    const u = new URL(url);
    if (u.hostname === 'oauth2.googleapis.com') return new Response(JSON.stringify({ scope: 'https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/userinfo.email', email: 'tester@example.com' }));
    if (u.hostname === 'firebasedatabase.googleapis.com') return new Response(JSON.stringify({ name: 'projects/1/locations/r/instances/ns', type: 'USER_DATABASE', state: 'ACTIVE' }));
    if (u.pathname === '/.settings/rules.json') { if (init.method === 'PUT') { rules = init.body; return new Response('{"status":"ok"}'); } return new Response(rules); }
    return new Response('null');
  };
  const seen = [], target = { kind: 'production', projectId: 'demo-prod', projectNumber: '1', region: 'r', namespace: 'ns', principalSha256: sha256('tester@example.com'), baselineRulesSha256: sha256(BASELINE), gcloud: '/x', paths };
  const outcome = await run({ target, runId: 'PROD-EVENTS-01', prefix: PREFIX, directCap: 200, outDir: path.join(dir, 'run'), suite: 'events+admin' }, { suiteProfiles: fakeSuites(seen), fetchImpl, mint: () => TOKEN });
  const journal = readFileSync(path.join(dir, 'run/journal.jsonl'), 'utf8');
  assert.equal(outcome.exit, 0, JSON.stringify(outcome.result)); assert.ok(!journal.includes(TOKEN)); assert.equal(rules, BASELINE);
  assert.deepEqual(seen.map(s => [s.profile, s.adminToken]), [['r1-ws', undefined], ['r1-lp', undefined], ['r2-ws', undefined], ['r2-lp', undefined], ['r1-admin', TOKEN], ['r2-admin', TOKEN]]);
  assert.deepEqual(outcome.result.counts, { direct: 6, reserve: 4, adc: 1 }); assert.equal(existsSync(paths.lease), false);
  writeFileSync(paths.owner, `${line(`decision=APPROVE; scriptSha256=${sha}; directCap=200; adc=1; prefix=${PREFIX}; basis=2196`, 'PROD-EVENTS-02')}\n`);
  const refused = await run({ target, runId: 'PROD-EVENTS-02', prefix: PREFIX, directCap: 200, outDir: path.join(dir, 'run2'), suite: 'events' }, { suiteProfiles: fakeSuites([]), fetchImpl, mint: () => TOKEN });
  assert.equal(refused.exit, 2); assert.match(refused.result.error, /approval fields differ/);
  rmSync(dir, { recursive: true, force: true });
});

// ---- command line ----
test('command line: --suite names a known suite; the cap range is 20..180 for small and 20..250 for the new suites; production refuses an emulator host', () => {
  const script = path.join(HERE, 'observer.mjs'), base = ['--target', 'emulator', '--run-id', 'TEST-CLI-02', '--prefix', PREFIX, '--out', path.join(tmpdir(), 'never-created-events')];
  const cli = (args, env = {}) => spawnSync(process.execPath, ['--max-old-space-size=1024', script, ...args], { env: { PATH: process.env.PATH, HOME: process.env.HOME, ...env }, encoding: 'utf8' });
  assert.match(cli([...base, '--suite', 'all', '--direct-cap', '40']).stderr, /--suite small\|events\|admin\|events\+admin/);
  assert.match(cli([...base, '--direct-cap', '181']).stderr, /20\.\.180/);
  assert.match(cli([...base, '--suite', 'events', '--direct-cap', '251']).stderr, /20\.\.250/);
  assert.match(cli([...base, '--suite', 'events', '--direct-cap', '250']).stderr, /FIREBASE_DATABASE_EMULATOR_HOST must be/);   // past the cap check
  const prod = cli(['--target', 'production', '--suite', 'admin', '--run-id', 'TEST-CLI-03', '--prefix', PREFIX, '--direct-cap', '40', '--out', path.join(tmpdir(), 'never-created-events')], { FIREBASE_DATABASE_EMULATOR_HOST: '127.0.0.1:9000' });
  assert.equal(prod.status, 2); assert.match(prod.stderr, /environment variable set: FIREBASE_DATABASE_EMULATOR_HOST/);
  const manifest = JSON.parse(cli(['--print-manifest']).stdout);
  for (const f of ['admin-suite.mjs', 'events-actor.mjs', 'events-page.html', 'events-page.mjs', 'events-rules.mjs', 'events-sequence.mjs', 'actor.mjs', 'observer.mjs', 'lib.mjs']) assert.ok(manifest.files.includes(f), f);
  assert.equal(manifest.sha256, scriptManifest(HERE).sha256);
});

// ---- the Admin SDK socket counter ----
test('endpointOf reads both connect call forms', () => {
  assert.deepEqual(endpointOf([{ host: 'a.firebaseio.com', port: 443 }, () => {}]), { host: 'a.firebaseio.com', port: 443 });
  assert.deepEqual(endpointOf([{ servername: 's.firebaseio.com', port: '443' }]), { host: 's.firebaseio.com', port: 443 });
  assert.deepEqual(endpointOf([9000, '127.0.0.1']), { host: '127.0.0.1', port: 9000 }); assert.deepEqual(endpointOf([9000]), { host: 'localhost', port: 9000 });
});
test('countConnects counts every database connect before it dials, refuses over the cap without dialling, ignores other hosts and restores the originals', async () => {
  const listener = net.createServer(s => s.destroy()); await new Promise(r => listener.listen(0, '127.0.0.1', r));
  const port = listener.address().port, counter = createCounter({ direct: 1 }), rows = [], before = { tls: tls.connect, net: net.connect };
  const restore = countConnects(at => at.host === '127.0.0.1' && at.port === port, () => counter.take('admin-ws-attempt'), { write: row => rows.push(row) });
  try {
    assert.notEqual(net.connect, before.net); assert.notEqual(tls.connect, before.tls);
    const a = net.connect(port, '127.0.0.1'); a.on('error', () => {}); a.destroy();
    let dialled = false; listener.once('connection', () => { dialled = true; });
    assert.throws(() => net.connect({ host: '127.0.0.1', port }), /direct cap 1/);
    const other = net.connect({ host: '127.0.0.1', port: 1 }); other.on('error', () => {}); other.destroy();
    await new Promise(r => setTimeout(r, 100)); assert.equal(dialled, false);
    assert.deepEqual(counter.used(), { direct: 1, reserve: 0, adc: 0 }); assert.deepEqual(rows.map(r => [r.kind, r.via, r.port]), [['raw-admin-connect', 'net', port]]);
  } finally { restore(); listener.close(); }
  assert.equal(net.connect, before.net); assert.equal(tls.connect, before.tls);
});

// ---- the recorded small case code is untouched ----
test('the small suite\'s case code is byte-identical to the bytes pinned by the production fixture', () => {
  const pinned = JSON.parse(readFileSync(path.join(HERE, '..', 'fixtures', 'production-sdk-small.json'), 'utf8')).provenance.caseSources;
  for (const [name, digest] of Object.entries(pinned)) assert.equal(sha256(readFileSync(path.join(HERE, name))), digest, name);
});

// ---- mutation run 1 (2026-11-04) ----
test('the process backstop is the suite\'s run deadline plus two minutes (small: 12 minutes as before)', async () => {
  const { backstopMs } = await import('./observer.mjs');
  assert.deepEqual(['small', 'events', 'admin', 'events+admin', 'unknown'].map(backstopMs), [720000, 1020000, 1020000, 1020000, 720000]);
});
test('LP events page: the WebSocket the page opens for the writer is counted when it is created', async () => {
  const { eventsLpProfile } = await import('./observer.mjs'), { withTimeout } = await import('./sequence.mjs');
  const server = await fakeServer(), counter = createCounter({ direct: 200 }), rows = [];
  const ctx = { profile: 'r1-lp', scope: 'p/sdk-events/r1-lp', transport: 'lp', databaseURL: `http://${server.host}?ns=ns`, projectId: 'demo-x', local: true, target: { host: server.host }, journal: { write: row => rows.push(row) }, counter, abort: () => {}, caseMs: 5000, closeMs: 1000, closers: [] };
  await withTimeout(6000, 'events lp', eventsLpProfile(ctx)).catch(() => {});
  for (const close of ctx.closers.splice(0).reverse()) await close().catch(() => {});
  server.close();
  const sockets = rows.filter(r => r.kind === 'raw-page-ws');
  assert.ok(sockets.length >= 1, JSON.stringify(rows.map(r => r.kind))); assert.ok(counter.used().direct >= sockets.length);
});

test('the quiescence window of a step is at least 800 ms: a production round trip (about 150 to 300 ms, more over long polling) must not move an event into the next step', async () => {
  const { QUIET_MS, SETTLE_MAX_MS } = await import('./events-sequence.mjs');
  assert.ok(QUIET_MS >= 800, `QUIET_MS is ${QUIET_MS}`);
  assert.ok(SETTLE_MAX_MS >= 4 * QUIET_MS, `SETTLE_MAX_MS ${SETTLE_MAX_MS} must leave room for several quiet windows`);
});

// ---- Opus/Codex presend review of packet 1 v1: browser traffic is stopped at a margin below the cap (nothing is routed) ----
async function marginWorld({ cap, margin }) {
  const { chromium } = await import('playwright'), { watchBrowserTraffic } = await import('./observer.mjs');
  const hits = { http: 0, upgrades: 0 };
  const server = createServer((req, res) => { if (req.url.startsWith('/hit')) { hits.http += 1; setTimeout(() => res.writeHead(200).end('ok'), 20); } else res.writeHead(200, { 'content-type': 'text/html' }).end('<!doctype html><title>x</title>'); });
  server.on('upgrade', (req, socket) => { hits.upgrades += 1; socket.destroy(); });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  const host = `127.0.0.1:${server.address().port}`, counter = createCounter({ direct: cap }), aborts = [], rows = [];
  const browser = await chromium.launch({ headless: true }), close = async () => { await browser.close().catch(() => {}); server.closeAllConnections(); server.close(); };
  try {
    const page = await browser.newPage(), ctx = { profile: 'r1-lp', counter, abort: m => aborts.push(m), journal: { write: row => rows.push(row) } };
    const watch = watchBrowserTraffic(page, ctx, url => { try { const u = new URL(url); return u.host === host && (u.pathname === '/hit' || u.pathname === '/.ws'); } catch { return false; } }, margin);   // the page itself is served from the same host
    await page.goto(`http://${host}/`);
    return { page, host, hits, counter, aborts, rows, watch, close };
  } catch (error) { await close(); throw error; }
}
test('browser margin: the page is stopped once direct reaches cap - margin; with at most `margin` requests in flight the hard cap is never passed and nothing is counted as overflow', async () => {
  const w = await marginWorld({ cap: 30, margin: 8 });
  try {
    // a pool of 6 parallel requests (fewer than the margin) until the page is closed under it
    await w.page.evaluate(async () => { let n = 0; const until = Date.now() + 3000, worker = async () => { while (Date.now() < until) { try { await fetch(`/hit?i=${n++}`); } catch { return; } } };   // bounded: a page that is never stopped must fail the test, not hang it await Promise.allSettled(Array.from({ length: 6 }, worker)); }).catch(() => {});
    await new Promise(r => setTimeout(r, 300));
    assert.equal(w.page.isClosed(), true, 'the page is closed at the margin');
    const used = w.counter.used();
    assert.ok(used.direct >= 22 && used.direct <= 30, JSON.stringify(used)); assert.equal(used.overflow, undefined);
    assert.equal(w.aborts.length, 1); assert.match(w.aborts[0], /browser traffic stopped at the margin: direct 22 of cap 30 \(margin 8\)/);
    assert.ok(w.hits.http <= 30 && w.hits.http >= used.direct - 1, `server ${w.hits.http} counted ${used.direct}`);
    assert.ok(w.watch.stats().stopped);
  } finally { await w.close(); }
});
test('browser margin: page WebSockets count like requests and stop the page the same way', async () => {
  const w = await marginWorld({ cap: 12, margin: 6 });
  try {
    await w.page.evaluate(async host => { for (let i = 0; i < 20; i++) { try { const s = new WebSocket(`ws://${host}/.ws`); await new Promise(resolve => { s.onerror = s.onclose = resolve; setTimeout(resolve, 500); }); } catch { return; } } }, w.host).catch(() => {});
    await new Promise(r => setTimeout(r, 300));
    assert.equal(w.page.isClosed(), true); assert.equal(w.counter.used().direct, 6); assert.equal(w.counter.used().overflow, undefined);
    assert.match(w.aborts[0], /direct 6 of cap 12 \(margin 6\)/); assert.equal(w.rows.filter(r => r.kind === 'raw-page-ws').length, 6);
  } finally { await w.close(); }
});
test('browser margin: other hosts and paths are neither counted nor stopped', async () => {
  const w = await marginWorld({ cap: 8, margin: 6 });
  try {
    await w.page.evaluate(async host => { await fetch('/other.html'); await new Promise(resolve => { const s = new WebSocket(`ws://${host}/other.ws`); s.onerror = s.onclose = resolve; setTimeout(resolve, 600); }); }, w.host);
    assert.deepEqual(w.counter.used(), { direct: 0, reserve: 0, adc: 0 }); assert.deepEqual(w.aborts, []); assert.equal(w.page.isClosed(), false);
  } finally { await w.close(); }
});
test('browser margin: BROWSER_MARGIN covers the most requests the code can have in flight (SDK bound from its source, measured bound on a real events page)', async () => {
  const { BROWSER_MARGIN, eventsLpProfile } = await import('./observer.mjs'), { withTimeout } = await import('./sequence.mjs');
  // From the SDK source: a long-polling connection never has more than 2 script-tag requests outstanding.
  const sdk = readFileSync(path.join(HERE, '..', 'node_modules', '@firebase', 'database', 'dist', 'index.esm.js'), 'utf8');
  assert.ok(sdk.includes('this.outstandingRequests.size < (this.pendingSegs.length > 0 ? 2 : 1)'), 'the SDK still limits a long-polling connection to 2 outstanding requests');
  const LP_CONNECTIONS = 2, OUTSTANDING_PER_CONNECTION = 2, PAGE_SOCKETS = 1, HANDSHAKE_DOCUMENTS = 2;   // observer and transaction writer poll; the writer is one page WebSocket; each connection loads one iframe document
  const bound = LP_CONNECTIONS * OUTSTANDING_PER_CONNECTION + PAGE_SOCKETS + HANDSHAKE_DOCUMENTS;
  assert.ok(BROWSER_MARGIN >= bound + 1, `margin ${BROWSER_MARGIN} must exceed the structural bound ${bound}`);
  const server = await fakeServer(), counter = createCounter({ direct: 200 }), rows = [];
  const ctx = { profile: 'r1-lp', scope: 'p/sdk-events/r1-lp', transport: 'lp', databaseURL: `http://${server.host}?ns=ns`, projectId: 'demo-x', local: true, target: { host: server.host }, journal: { write: row => rows.push(row) }, counter, abort: () => {}, caseMs: 5000, closeMs: 1000, closers: [] };
  await withTimeout(8000, 'events lp', eventsLpProfile(ctx)).catch(() => {});
  for (const close of ctx.closers.splice(0).reverse()) await close().catch(() => {});
  server.close();
  const row = rows.find(r => r.kind === 'lp-inflight');
  assert.ok(row, JSON.stringify(rows.map(r => r.kind))); assert.ok(row.maxInFlight >= 1 && row.maxInFlight <= bound, `measured ${row.maxInFlight} against the structural bound ${bound}`);
});

// ---- Codex presend review of packet 1 v1, Must 2 (observer side) ----
async function harnessWith(suite, suiteProfiles, opts = {}) {
  const server = await fakeServer(), out = mkdtempSync(path.join(tmpdir(), 'events-observer-'));
  const target = { kind: 'emulator', host: server.host, namespace: 'ns', projectId: 'demo-x' };
  const outcome = await run({ target, runId: 'TEST-EVENTS-02', prefix: PREFIX, directCap: 40, outDir: path.join(out, 'run'), suite, ...opts }, { suiteProfiles, profiles: { ws: () => { throw new Error('small profile used'); }, lp: () => { throw new Error('small profile used'); } } });
  server.close(); rmSync(out, { recursive: true, force: true });
  return { ...outcome, server };
}
test('an SDK mutation that timed out is carried into the result: unverified, exit 3, the case stays observed', async () => {
  const withUnknown = suite => async ctx => caseRows(suite, null).map(r => (r.id === 'fanout' || r.id === 'push' ? { ...r, unknown: [`${r.id}/hang`] } : r));
  const h = await harnessWith('events+admin', { events: { ws: withUnknown('events'), lp: withUnknown('events') }, admin: { admin: withUnknown('admin') } });
  assert.equal(h.exit, 3); assert.equal(h.result.status, 'unverified');
  assert.ok(h.result.unverified.includes('unknown SDK mutation outcome: r1-ws/fanout/hang'), JSON.stringify(h.result.unverified));
  assert.ok(h.result.unverified.includes('unknown SDK mutation outcome: r2-admin/push/hang'));
  assert.equal(h.result.unverified.filter(u => u.startsWith('unknown SDK mutation outcome')).length, 4 + 2, 'one per profile: fanout in the four events profiles, push in the two admin profiles');
  assert.equal(h.result.observed, 52); assert.deepEqual(h.result.cleanup, { prefix: 'verified', rules: 'verified' });
});
test('an events or admin profile that is abandoned at its deadline may have mutations in flight: unverified, exit 3', async () => {
  const ok = suite => async ctx => caseRows(suite, null);
  const h = await harnessWith('events+admin', { events: { ws: ok('events'), lp: async () => new Promise(() => {}) }, admin: { admin: ok('admin') } }, { profileMs: 150, closeMs: 100, continueOnFailure: true });
  assert.equal(h.exit, 3); assert.ok(h.result.unverified.some(u => /^SDK mutations possibly in flight: profile r1-lp aborted/.test(u)), JSON.stringify(h.result.unverified));
});
test('a clean run has no unverified entry and keeps exit 0', async () => {
  const h = await harness('events+admin'); assert.equal(h.exit, 0); assert.deepEqual(h.result.unverified, []);
});

// ---- Codex presend review of packet 1 v1, Should: the Admin SDK version is pinned at startup ----
test('SDK pins: the installed versions are the pinned ones; the Admin SDK is checked only for suites that use it; the small result keeps its recorded sdk members', async () => {
  const { checkSdkPins, adminVersion, sdkVersions } = await import('./observer.mjs');
  const fake = versions => { const dir = mkdtempSync(path.join(tmpdir(), 'pins-')); for (const [pkg, version] of Object.entries(versions)) { const d = path.join(dir, pkg); mkdirSync(d, { recursive: true }); writeFileSync(path.join(d, 'package.json'), JSON.stringify({ version })); } return dir; };
  const good = { firebase: '12.18.0', '@firebase/database': '1.1.5', playwright: '1.62.1' }, dirs = [fake(good), fake({ ...good, 'firebase-admin': '14.3.0' }), fake({ ...good, 'firebase-admin': '14.2.0' }), fake({ ...good, playwright: '1.0.0', 'firebase-admin': '14.3.0' })];
  try {
    checkSdkPins('small', dirs[0]); checkSdkPins('events', dirs[0]); checkSdkPins('admin', dirs[1]); checkSdkPins('events+admin', dirs[1]);
    assert.throws(() => checkSdkPins('admin', dirs[0]), /ENOENT/); assert.throws(() => checkSdkPins('events+admin', dirs[2]), /firebase-admin is not 14.3.0/);
    assert.throws(() => checkSdkPins('small', dirs[3]), /playwright is not 1.62.1/); checkSdkPins('small', dirs[2]);
    assert.equal(adminVersion(dirs[1]), '14.3.0');
  } finally { for (const d of dirs) rmSync(d, { recursive: true, force: true }); }
  assert.deepEqual(Object.keys(sdkVersions()), ['firebase', 'database', 'playwright']);
  checkSdkPins('events+admin');   // the installed tree is the pinned one
});
test('the Admin SDK version is part of the result of the admin suites only', async () => {
  const a = await harness('admin'), s = await harness('events');
  assert.equal(a.result.sdk.firebaseAdmin, '14.3.0'); assert.equal(Object.hasOwn(s.result.sdk, 'firebaseAdmin'), false);
});

test('the CLI refuses a tree whose firebase-admin is not the pinned version before anything else (admin suites only)', () => {
  const dir = realpathSync(mkdtempSync(path.join(tmpdir(), 'cli-pins-'))), tree = (admin) => { for (const [pkg, version] of Object.entries({ firebase: '12.18.0', '@firebase/database': '1.1.5', playwright: '1.62.1', ...(admin ? { 'firebase-admin': admin } : {}) })) { const d = path.join(dir, 'node_modules', pkg); mkdirSync(d, { recursive: true }); writeFileSync(path.join(d, 'package.json'), JSON.stringify({ version })); } };
  try {
    cpSync(HERE, path.join(dir, 'sdk-observer'), { recursive: true });
    tree('14.2.0');
    const argv = suite => [path.join(dir, 'sdk-observer', 'observer.mjs'), '--target', 'emulator', '--suite', suite, '--run-id', 'CLI-PINS-01', '--prefix', '/clipins', '--direct-cap', '20', '--out', path.join(dir, `out-${suite}`)];
    const admin = spawnSync(process.execPath, argv('admin'), { encoding: 'utf8', env: { PATH: process.env.PATH } });
    assert.equal(admin.status, 2); assert.match(admin.stderr, /firebase-admin is not 14\.3\.0/);
    const small = spawnSync(process.execPath, argv('small'), { encoding: 'utf8', env: { PATH: process.env.PATH } });
    assert.doesNotMatch(small.stderr, /firebase-admin/, 'the small suite does not look at the Admin SDK');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// ---- Opus presend review of packet 1 v1, Should 3: a REVOKED line names the run ----
test('checkApproval refuses a run that a later REVOKED line names (topic or envelope), and ignores a REVOKED line of another run', () => {
  const run = 'RTDB-EVENTS-20261104-01', sha = '6154f48257ab2027db21bfb7b646160ab6c5a9ba4f795c546aa6ef1ddb4f745f';
  const approve = `- 2026-11-04 | RTDB-SMALL-OBSERVER ${run} | decision=APPROVE; scriptSha256=${sha}; directCap=200; adc=1; prefix=/sdkevents20261104; suite=events+admin; basis=2217 | coordinator | review.md`;
  const want = { runId: run, scriptSha256: sha, directCap: 200, prefix: '/sdkevents20261104', suite: 'events+admin' };
  const other = `- 2026-11-04 | REVOKED RTDB-SMALL-OBSERVER RTDB-SMALL-20261102-01 | envelopeId=RTDB-SMALL-20261102-01; consumed | coordinator | x`;
  checkApproval(`${other}\n${approve}\n`, want);
  for (const revoked of [`- 2026-11-04 | REVOKED RTDB-SMALL-OBSERVER ${run} | envelopeId=${run}; consumed | coordinator | x`, `- 2026-11-04 | REVOKED V ${run} | envelopeId=${run};packetSha256=abc | coordinator | x`, `- 2026-11-04 | REVOKED E ${run} | scoped retirement | coordinator | x`]) {
    assert.throws(() => checkApproval(`${approve}\n${revoked}\n`, want), /revoked/, revoked);
    assert.throws(() => checkApproval(`${revoked}\n${approve}\n`, want), /revoked/, 'also when the REVOKED line comes first');
  }
  assert.throws(() => checkApproval(`${approve}\n- 2026-11-04 | note | mentions ${run} but REVOKED is only a word here | coordinator | x\n`.replace('note', 'REVOKED note'), want), /revoked/, 'any line whose topic starts with REVOKED and that names the run');
  checkApproval(`${approve}\n- 2026-11-04 | V ${run} | envelopeId=${run}; REVOKED appears only in the body | coordinator | x\n`, want);
});

// ---- Opus presend review of packet 1 v1, Should 2: a refused Admin SDK credential is not G13 evidence ----
test('an admin profile whose startup failed (credential refused) is a credential outcome: its cases are not observed, the run is incomplete', async () => {
  const profile = suite => async ctx => caseRows(suite, null).map(r => (suite === 'admin' && ctx.profile === 'r1-admin' && r.id === 'startup' ? { id: 'startup', ok: false, error: 'PermissionError: gauth refused' } : r));
  const h = await harnessWith('events+admin', { events: { ws: profile('events'), lp: profile('events') }, admin: { admin: profile('admin') } }, { continueOnFailure: true });
  assert.equal(h.exit, 1); assert.equal(h.result.status, 'incomplete');
  assert.equal(h.result.observed, 52 - 10, 'the ten cases of the refused admin profile do not count');
  assert.deepEqual(h.result.credentialOutcome, ['r1-admin']); assert.deepEqual(h.result.adminStartup, { 'r1-admin': false, 'r2-admin': true });
  assert.deepEqual(h.result.cleanup, { prefix: 'verified', rules: 'verified' });
  const ok = await harnessWith('events+admin', { events: { ws: profile('events'), lp: profile('events') }, admin: { admin: async ctx => caseRows('admin', null) } });
  assert.equal(ok.exit, 0); assert.equal(ok.result.observed, 52); assert.equal(Object.hasOwn(ok.result, 'credentialOutcome'), false); assert.deepEqual(ok.result.adminStartup, { 'r1-admin': true, 'r2-admin': true });
  const ev = await harnessWith('events', { events: { ws: profile('events'), lp: profile('events') } });
  assert.equal(Object.hasOwn(ev.result, 'adminStartup'), false, 'a suite without admin profiles has no admin members');
});

// ---- the result records the prefix (the read-back needs it) and the CLI has a read-back command ----
test('the result of the events and admin suites records the prefix; the small result keeps its recorded members', async () => {
  const h = await harness('events'); assert.equal(h.result.prefix, PREFIX);
  const key = Object.keys(h.result), small = Object.keys((await import('./observer.mjs')).SUITES.small).length;
  assert.ok(small > 0 && key.includes('prefix'));
});
test('the CLI read-back command: usage is refused before anything else, and it needs the same environment as a production run', () => {
  const observer = path.join(HERE, 'observer.mjs');
  const bare = spawnSync(process.execPath, [observer, 'readback'], { encoding: 'utf8', env: { PATH: process.env.PATH } });
  assert.equal(bare.status, 2); assert.match(bare.stderr, /usage: readback --run-dir/);
  const env = spawnSync(process.execPath, ['--max-old-space-size=1024', observer, 'readback', '--run-dir', '/x', '--production-config', '/y', '--out', '/z'], { encoding: 'utf8', env: { PATH: process.env.PATH, FIREBASE_TOKEN: 'x' } });
  assert.equal(env.status, 2); assert.match(env.stderr, /environment variable set: FIREBASE_TOKEN/);
});

// ---- mutation round of the v2 delta ----
test('browser margin: the in-flight tracker follows requests and sockets (a fake page, no browser)', async () => {
  const { watchBrowserTraffic } = await import('./observer.mjs'), { EventEmitter } = await import('node:events');
  const page = Object.assign(new EventEmitter(), { close: async () => { page.closed = true; } }), counter = createCounter({ direct: 100 });
  const watch = watchBrowserTraffic(page, { profile: 'p', counter, abort: () => {}, journal: { write() {} } }, url => url.startsWith('db:'), 10);
  const req = url => ({ url: () => url, method: () => 'GET', postData: () => null }), sock = new EventEmitter(); sock.url = () => 'db:ws';
  for (let i = 0; i < 3; i++) page.emit('request', req('db:a'));
  page.emit('request', req('other:b')); page.emit('websocket', sock);
  assert.deepEqual(watch.stats(), { maxInFlight: 4, inFlight: 4, stopped: false });
  page.emit('requestfinished', req('db:a')); page.emit('requestfailed', req('db:a')); page.emit('requestfinished', req('other:b')); sock.emit('close');
  assert.deepEqual(watch.stats(), { maxInFlight: 4, inFlight: 1, stopped: false });
  page.emit('requestfinished', req('db:a')); page.emit('requestfinished', req('db:a')); assert.equal(watch.stats().inFlight, 0, 'never below zero');
  assert.deepEqual(counter.used(), { direct: 4, reserve: 0, adc: 0 });
});
test('the small suite result keeps its recorded members: no prefix', async () => {
  const server = await fakeServer(), out = mkdtempSync(path.join(tmpdir(), 'small-prefix-'));
  const rows = [['observer', 'key_range'], ['observer', 'value_equal'], ['observer', 'priority_range'], ['writer', 'push'], ['writer', 'update'], ['writer', 'multipath'], ['writer', 'server_timestamp'], ['writer', 'increment']].map(([role, id]) => ({ role, id, ok: true }));
  const profile = async () => rows;
  try {
    const target = { kind: 'emulator', host: server.host, namespace: 'ns', projectId: 'demo-x' };
    const { result } = await run({ target, runId: 'TEST-SMALL-01', prefix: PREFIX, directCap: 40, outDir: path.join(out, 'run') }, { profiles: { ws: profile, lp: profile } });
    assert.equal(Object.hasOwn(result, 'prefix'), false); assert.equal(Object.hasOwn(result, 'suite'), false); assert.equal(Object.hasOwn(result, 'adminStartup'), false);
  } finally { server.close(); rmSync(out, { recursive: true, force: true }); }
});
