// The observer's events (G6) and admin (G13) suites: the run plan, Rules, approval binding, caps, the admin token
// hand-over, the Admin SDK socket counter, and that the small suite's recorded case code is untouched.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, rmSync, existsSync } from 'node:fs';
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
