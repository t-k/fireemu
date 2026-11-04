import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtempSync, readFileSync, existsSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { run, PROFILES, captureWs, lpProfile } from './observer.mjs';
import { CASE_ORDER, runCases, withTimeout } from './sequence.mjs';
import { checkApproval, createCounter, createJournal, scriptManifest, sha256, claim } from './lib.mjs';
import { packetRules } from './rules.mjs';

const BASELINE = '{\n  "rules": {\n    ".read": false,\n    ".write": false\n  }\n}\n', PREFIX = '/sdksmalltest';
// A fake RTDB admin surface: Rules and one prefix in memory, a request log, and per-request failure injection.
async function fakeServer(inject = () => null) {
  const state = { rules: BASELINE, prefix: null, log: [] };
  const server = createServer((req, res) => {
    let body = ''; req.on('data', c => { body += c; });
    req.on('end', async () => {
      const url = new URL(req.url, 'http://x'), key = `${req.method} ${url.pathname}`; state.log.push(key);
      const fault = inject(key, state);
      if (fault === 'hang') return;
      if (fault === 'slow') await new Promise(r => setTimeout(r, 400));   // answered late, but applied
      if (fault && fault !== 'ignore' && fault !== 'slow') { res.writeHead(fault).end('{"error":"injected"}'); return; }
      if (url.pathname === '/.settings/rules.json') { if (req.method === 'PUT') { if (fault !== 'ignore') state.rules = body; res.writeHead(200).end('{"status":"ok"}'); } else res.writeHead(200).end(state.rules); return; }
      if (url.pathname === `${PREFIX}.json`) { if (req.method === 'DELETE' && fault !== 'ignore') state.prefix = null; res.writeHead(200).end(JSON.stringify(state.prefix)); return; }
      res.writeHead(404).end('{}');
    });
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  return { state, host: `127.0.0.1:${server.address().port}`, close: () => { server.closeAllConnections(); server.close(); } };
}
const rowsFor = profile => [['writer', 'startup'], ['observer', 'startup'], ['writer', 'seed'], ...CASE_ORDER].map(([role, id]) => ({ role, id, ok: true, value: null, ms: 1 }));
const goodProfiles = { ws: async () => rowsFor(), lp: async () => rowsFor() };
async function harness(options = {}, deps = {}, serverInject) {
  const server = await fakeServer(serverInject), out = mkdtempSync(path.join(tmpdir(), 'small-observer-'));
  const target = { kind: 'emulator', host: server.host, namespace: 'ns', projectId: 'demo-x' };
  const outcome = await run({ target, runId: 'TEST-RUN-01', prefix: PREFIX, directCap: 40, outDir: path.join(out, 'run'), ...options }, { profiles: goodProfiles, ...deps, ...(typeof deps.profiles === 'function' ? { profiles: deps.profiles(server) } : {}) });
  const journal = readFileSync(path.join(out, 'run/journal.jsonl'), 'utf8');
  server.close(); rmSync(out, { recursive: true, force: true });
  return { ...outcome, server, journal };
}
const tail = h => h.server.state.log.slice(-4);
const CLEANUP = ['DELETE /sdksmalltest.json', 'GET /sdksmalltest.json', 'PUT /.settings/rules.json', 'GET /.settings/rules.json'];

test('happy path: install, 32 observations, then the fixed cleanup order; counts stay under the caps', async () => {
  const h = await harness();
  assert.equal(h.exit, 0); assert.equal(h.result.observed, 32); assert.equal(h.result.status, 'complete'); assert.deepEqual(h.result.cleanup, { prefix: 'verified', rules: 'verified' });
  assert.deepEqual(h.server.state.log, ['GET /.settings/rules.json', 'GET /sdksmalltest.json', 'PUT /.settings/rules.json', 'GET /.settings/rules.json', ...CLEANUP]);
  assert.equal(h.server.state.rules, BASELINE); assert.deepEqual(h.result.counts, { direct: 4, reserve: 4, adc: 0 });
  assert.equal(PROFILES.length * CASE_ORDER.length, 32);
});
test('a thrown error in the middle of the observation still deletes the prefix and restores the Rules byte-equal', async () => {
  const h = await harness({}, { profiles: { ws: async () => rowsFor(), lp: async () => { throw new Error('boom in the page'); } } });
  assert.equal(h.exit, 1); assert.equal(h.result.status, 'incomplete'); assert.ok(h.result.cases.some(c => c.id === 'profile' && !c.ok));
  assert.deepEqual(tail(h), CLEANUP); assert.equal(h.server.state.rules, BASELINE); assert.equal(h.result.cleanup.rules, 'verified');
});
test('data written under the prefix is deleted even when the profile crashed', async () => {
  const h = await harness({}, { profiles: server => ({ ws: async () => { server.state.prefix = { sdk: 'left over' }; throw new Error('crash'); }, lp: goodProfiles.lp }) });
  assert.equal(h.server.state.prefix, null); assert.equal(h.server.state.rules, BASELINE); assert.equal(h.exit, 1); assert.equal(h.result.cleanup.prefix, 'verified');
});
test('a hanging profile hits the profile deadline, the run goes on to the cleanup', async () => {
  const h = await harness({ profileMs: 150, closeMs: 100 }, { profiles: { ws: () => new Promise(() => {}), lp: goodProfiles.lp } });
  assert.equal(h.exit, 3); assert.deepEqual(h.result.unverified, ['profile r1-ws did not settle']);   // a profile that never settles is reported, not forgotten
  assert.match(JSON.stringify(h.result.cases[0]), /timed out/); assert.deepEqual(tail(h), CLEANUP); assert.equal(h.server.state.rules, BASELINE);
});
test('the whole-run deadline aborts a hanging profile and the cleanup still runs', async () => {
  const h = await harness({ runMs: 150, profileMs: 60000, closeMs: 100 }, { profiles: { ws: () => new Promise(() => {}), lp: goodProfiles.lp } });
  assert.equal(h.exit, 3); assert.match(h.result.error, /aborted: run deadline/); assert.deepEqual(tail(h), CLEANUP); assert.equal(h.server.state.rules, BASELINE);
});
test('the direct cap stops the run; the cleanup is paid from the reserve and still runs', async () => {
  const h = await harness({ directCap: 3 });
  assert.equal(h.exit, 1); assert.match(h.journal, /direct cap 3 reached/); assert.deepEqual(tail(h), CLEANUP); assert.equal(h.server.state.rules, BASELINE); assert.equal(h.result.counts.direct, 3); assert.equal(h.result.counts.reserve, 4);
});
test('an unknown answer to the Rules install is never re-sent, the Rules are restored, and the unknown outcome still forces exit 3', async () => {
  let puts = 0;
  const h = await harness({ adminMs: 150 }, {}, (key, state) => { if (key === 'PUT /.settings/rules.json' && puts++ === 0) { state.rules = '{"rules":{"applied":true}}'; return 'hang'; } return null; });
  assert.equal(h.exit, 3); assert.equal(h.server.state.log.filter(k => k === 'PUT /.settings/rules.json').length, 2); assert.equal(h.server.state.rules, BASELINE); assert.equal(h.result.cleanup.rules, 'verified'); assert.deepEqual(h.result.unverified, ['unknown mutation outcome: rules-install']);
});
test('an unverified restoration exits 3 and says which part', async () => {
  const h = await harness({ adminMs: 150 }, {}, (key, state) => (key === 'PUT /.settings/rules.json' && state.rules !== BASELINE && state.log.length > 6 ? 500 : null));
  assert.equal(h.exit, 3); assert.equal(h.result.status, 'unverified'); assert.deepEqual(h.result.unverified, ['cleanup']); assert.equal(h.result.cleanup.rules, 'unverified'); assert.equal(h.result.cleanup.prefix, 'verified');
});
test('every restoration step is checked against what the server answers: a refused or ignored delete or restore is unverified, the other part still runs', async () => {
  const late = (state) => state.log.length > 6;
  const deleteRefused = await harness({}, {}, (key, state) => (key === 'DELETE /sdksmalltest.json' ? 500 : null));
  assert.equal(deleteRefused.exit, 3); assert.deepEqual(deleteRefused.result.cleanup, { prefix: 'unverified', rules: 'verified' });
  const deleteIgnored = await harness({}, { profiles: server => ({ ws: async () => { server.state.prefix = { left: 1 }; return rowsFor(); }, lp: goodProfiles.lp }) }, key => (key === 'DELETE /sdksmalltest.json' ? 'ignore' : null));
  assert.equal(deleteIgnored.exit, 3); assert.equal(deleteIgnored.result.cleanup.prefix, 'unverified'); assert.equal(deleteIgnored.result.cleanup.rules, 'verified');
  const restoreIgnored = await harness({}, {}, (key, state) => (key === 'PUT /.settings/rules.json' && late(state) ? 'ignore' : null));
  assert.equal(restoreIgnored.exit, 3); assert.deepEqual(restoreIgnored.result.cleanup, { prefix: 'verified', rules: 'unverified' });
  const restoreRefused = await harness({}, {}, (key, state) => (key === 'PUT /.settings/rules.json' && late(state) ? 500 : null));
  assert.equal(restoreRefused.exit, 3); assert.equal(restoreRefused.result.cleanup.rules, 'unverified');
});
test('Rules that are not readable, or a prefix that is not null, refuse before anything is changed', async () => {
  const h = await harness({}, {}, key => (key === 'GET /.settings/rules.json' ? 500 : null));
  assert.equal(h.exit, 2); assert.deepEqual(h.server.state.log, ['GET /.settings/rules.json']);
  const g = await harness({}, {}, (key, state) => { if (key === 'GET /sdksmalltest.json') state.prefix = { foreign: 1 }; return null; });
  assert.equal(g.exit, 2); assert.ok(!g.server.state.log.includes('PUT /.settings/rules.json'));
});
test('an existing out directory (same run id) is refused before any request', async () => {
  const server = await fakeServer(), out = mkdtempSync(path.join(tmpdir(), 'small-observer-'));
  await assert.rejects(run({ target: { kind: 'emulator', host: server.host, namespace: 'ns', projectId: 'p' }, runId: 'TEST-RUN-03', prefix: PREFIX, directCap: 40, outDir: out }, { profiles: goodProfiles }));
  assert.equal(server.state.log.length, 0); server.close(); rmSync(out, { recursive: true, force: true });
});

// ---- production-mode gates with injected fetch (no network) ----
const SCRIPT_SHA = scriptManifest(path.dirname(new URL(import.meta.url).pathname)).sha256, TOKEN = 'ya29.TESTTOKEN-not-a-real-credential';
async function production({ approval = true, existingLease = false, failRestore = false, profiles = goodProfiles, hangRulesInstall = false, lateApply = false, opts = {} } = {}) {
  const dir = mkdtempSync(path.join(tmpdir(), 'small-observer-prod-')), paths = { owner: path.join(dir, 'owner.md'), lease: path.join(dir, 'lease'), recording: path.join(dir, 'RECORDING') };
  const line = `- 2026-11-02 | RTDB-SMALL-OBSERVER PROD-RUN-01 | decision=APPROVE; scriptSha256=${SCRIPT_SHA}; directCap=40; adc=1; prefix=${PREFIX}; basis=2196 | coordinator | test`;
  writeFileSync(paths.owner, approval ? `${line}\n` : '\n'); if (existingLease) writeFileSync(paths.lease, 'other');
  const state = { rules: BASELINE, log: [], headers: [] };
  const fetchImpl = async (url, init) => {
    const u = new URL(url), key = `${init?.method ?? 'GET'} ${u.hostname}${u.pathname}`; state.log.push(key); state.headers.push(init?.headers ?? {});
    if (u.hostname === 'oauth2.googleapis.com') return new Response(JSON.stringify({ scope: 'https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/userinfo.email', email: 'tester@example.com' }));
    if (u.hostname === 'firebasedatabase.googleapis.com') return new Response(JSON.stringify({ name: 'projects/1/locations/r/instances/ns', type: 'USER_DATABASE', state: 'ACTIVE' }));
    if (u.pathname === '/.settings/rules.json') { if (init.method === 'PUT' && hangRulesInstall && init.body !== BASELINE) return new Promise(() => {});
      if (init.method === 'PUT' && lateApply && init.body !== BASELINE) { setTimeout(() => { state.rules = init.body; }, 300); return new Promise((_, reject) => setTimeout(() => reject(Object.assign(new Error('timed out'), { name: 'TimeoutError' })), 30)); } if (init.method === 'PUT') { if (failRestore && init.body === BASELINE) return new Response('{}', { status: 500 }); state.rules = init.body; return new Response('{"status":"ok"}'); } return new Response(state.rules); }
    return new Response('null');
  };
  const target = { kind: 'production', projectId: 'demo-prod', projectNumber: '1', region: 'r', namespace: 'ns', principalSha256: sha256('tester@example.com'), baselineRulesSha256: sha256(BASELINE), gcloud: '/x', paths };
  let outcome, thrown; try { outcome = await run({ target, runId: 'PROD-RUN-01', prefix: PREFIX, directCap: 40, outDir: path.join(dir, 'run'), ...opts }, { profiles, fetchImpl, mint: () => TOKEN }); } catch (error) { thrown = error; }
  const read = f => (existsSync(f) ? readFileSync(f, 'utf8') : null);
  const res = { dir, paths, state, outcome, thrown, journal: read(path.join(dir, 'run/journal.jsonl')), leaseLeft: existsSync(paths.lease), recordingLeft: existsSync(paths.recording) };
  return res;
}
test('production: without the exact approval line nothing is claimed and nothing is sent', async () => {
  const r = await production({ approval: false }); assert.equal(r.outcome.exit, 2); assert.equal(r.state.log.length, 0); assert.equal(r.leaseLeft, false); assert.equal(r.recordingLeft, false);
});
test('production: with the approval the claims exist during the run and are released after a verified cleanup; the token never reaches the journal', async () => {
  const r = await production(); assert.equal(r.outcome.exit, 0); assert.equal(r.leaseLeft, false); assert.equal(r.recordingLeft, false); assert.ok(!r.journal.includes(TOKEN));
  assert.equal(r.state.log[0], 'POST oauth2.googleapis.com/tokeninfo'); assert.equal(r.state.headers[1].authorization, `Bearer ${TOKEN}`); assert.deepEqual(r.outcome.result.counts, { direct: 6, reserve: 4, adc: 1 });
});
test('production: an unverified cleanup leaves the lease and RECORDING in place; an existing lease refuses the start', async () => {
  const r = await production({ failRestore: true }); assert.equal(r.outcome.exit, 3); assert.equal(r.leaseLeft, true); assert.equal(r.recordingLeft, true);
  const s = await production({ existingLease: true }); assert.equal(s.outcome.exit, 2); assert.equal(s.state.log.length, 0); assert.equal(s.leaseLeft, true);
});
test('approval line: exact fields only, exactly one line', () => {
  const want = { runId: 'R1', scriptSha256: 'a'.repeat(64), directCap: 50, prefix: '/p' }, ok = `- d | RTDB-SMALL-OBSERVER R1 | decision=APPROVE; scriptSha256=${'a'.repeat(64)}; directCap=50; adc=1; prefix=/p; basis=2196 | coordinator | s`;
  checkApproval(ok, want);
  for (const bad of [ok.replace('APPROVE', 'DENY'), ok.replace('directCap=50', 'directCap=51'), ok.replace('a'.repeat(64), 'b'.repeat(64)), ok.replace('; basis=2196', ''), ok.replace('| coordinator |', '| someone |'), ok.replace('adc=1', 'adc=2')]) assert.throws(() => checkApproval(bad, want));
  assert.throws(() => checkApproval(`${ok}\n${ok}`, want)); assert.throws(() => checkApproval('', want));
});
test('counter: the direct cap and the reserve are separate, the ADC is once', () => {
  const c = createCounter({ direct: 2, reserve: 1 }); c.take('a'); c.take('b'); assert.throws(() => c.take('c'), /direct cap 2/); c.take('r', 'reserve'); assert.throws(() => c.take('r2', 'reserve')); c.take('adc', 'adc'); assert.throws(() => c.take('adc2', 'adc'));
});
test('deadline: a never-settling await and a slow case end as Timeout rows; a non-null startup root is a failure', async () => {
  await assert.rejects(withTimeout(20, 'x', new Promise(() => {})), /x timed out/);
  const rows = await runCases({ writer: { execute: () => new Promise(() => {}) }, observer: { execute: async () => null } }, { caseMs: 20 }); assert.equal(rows.length, 1); assert.equal(rows[0].ok, false); assert.match(rows[0].error, /Timeout/);
  const dirty = await runCases({ writer: { execute: async () => ({ x: 1 }) }, observer: { execute: async () => null } }); assert.match(dirty[0].error, /not empty/);
});
test('journal: O_EXCL create, secrets refused, raw rows dropped past the soft cap', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'small-observer-j-')), file = path.join(dir, 'j.jsonl'), j = createJournal(file, { softBytes: 400, maxBytes: 2000 }); j.addSecret('SECRET-VALUE-123');
  assert.throws(() => createJournal(file)); assert.throws(() => j.write({ kind: 'x', body: 'has SECRET-VALUE-123 inside' })); assert.equal(j.write({ kind: 'ok' }), true);
  for (let i = 0; i < 20; i++) j.write({ kind: 'raw', data: 'x'.repeat(50) }, { optional: true }); assert.ok(readFileSync(file, 'utf8').length < 600); j.close(); rmSync(dir, { recursive: true });
});
test('claim files are O_EXCL and released only when still ours; the manifest changes with any file', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'small-observer-c-')), f = path.join(dir, 'lease'), release = claim(f, 'mine'); assert.throws(() => claim(f, 'other')); release(); assert.equal(existsSync(f), false);
  writeFileSync(path.join(dir, 'a.mjs'), '1'); const one = scriptManifest(dir).sha256; writeFileSync(path.join(dir, 'a.mjs'), '2'); assert.notEqual(scriptManifest(dir).sha256, one); rmSync(dir, { recursive: true });
});
test('the Rules the run installs are the packet Rules for the prefix', () => { assert.deepEqual(Object.keys(packetRules(PREFIX).rules.sdksmalltest['sdk-next']).sort(), ['r1-lp', 'r1-ws', 'r2-lp', 'r2-ws']); });

// ---- Codex review r1 (2026-11-02) ----
test('r1.1 an abort while the Rules install is in flight waits for it before restoring: the install cannot land after the restore', async () => {
  const h = await harness({ runMs: 100, adminMs: 2000 }, {}, (key, state) => (key === 'PUT /.settings/rules.json' && state.log.filter(k => k === key).length === 1 ? 'slow' : null));
  assert.equal(h.exit, 1); assert.match(h.result.error, /aborted: run deadline/); assert.equal(h.server.state.rules, BASELINE); assert.deepEqual(tail(h), CLEANUP);
});
test('r1.1 an in-flight mutation that never settles keeps the claims and exits 3', async () => {
  const r = await production({ hangRulesInstall: true, opts: { adminMs: 100, runMs: 5000 } });
  assert.equal(r.outcome.exit, 3); assert.ok(r.outcome.result.unverified.includes('in-flight admin request')); assert.equal(r.leaseLeft, true); assert.equal(r.recordingLeft, true);
});
test('r1.2 a timed out or aborted profile has its actors and page closed and awaited before the cleanup starts', async () => {
  let closed = false;
  const h = await harness({ profileMs: 100, closeMs: 100 }, { profiles: server => ({ ws: async ctx => { ctx.closers.push(async () => { server.state.log.push('CLOSER'); closed = true; }); return new Promise(() => {}); }, lp: goodProfiles.lp }) });
  assert.ok(closed); const log = h.server.state.log; assert.ok(log.indexOf('CLOSER') > 0 && log.indexOf('CLOSER') < log.indexOf(CLEANUP[0])); assert.deepEqual(h.result.unverified, ['profile r1-ws did not settle']);
});
test('r1.2 a close that cannot be confirmed keeps the claims', async () => {
  const r = await production({ profiles: { ws: async ctx => { ctx.closers.push(() => new Promise(() => {})); return rowsFor(); }, lp: goodProfiles.lp }, opts: { closeMs: 100 } });
  assert.equal(r.outcome.exit, 3); assert.ok(r.outcome.result.unverified.includes('close r1-ws')); assert.equal(r.leaseLeft, true);
});
test('r1.3 every WebSocket the SDK creates is counted when it is created; over the cap nothing is dialled and the run is aborted', async () => {
  const counter = createCounter({ direct: 2 }), aborts = []; await captureWs({ write() {} }, () => { try { counter.take('ws-attempt'); } catch (error) { aborts.push(error.message); throw error; } });
  const { default: Ws } = await import('faye-websocket'), dial = () => { const c = new Ws.Client('ws://127.0.0.1:1/.ws'); c.on('error', () => {}); return c; };
  dial().close(); dial().close(); assert.throws(() => dial(), /direct cap 2/); assert.equal(aborts.length, 1); assert.deepEqual(counter.used(), { direct: 2, reserve: 0, adc: 0 });
});
test('r1.3 LP: the page is stopped at the margin below the cap and the abort names it', async () => {
  const server = await fakeServer(), counter = createCounter({ direct: 12 }), aborts = [], ctx = { profile: 'r1-lp', scope: 'p/sdk-next/r1-lp', databaseURL: `http://${server.host}?ns=ns`, projectId: 'demo-x', local: true, target: { host: server.host }, journal: { write() {} }, counter, abort: m => aborts.push(m), caseMs: 5000, closeMs: 2000, closers: [], browserMargin: 6 };
  const profile = lpProfile(ctx).catch(() => {});
  try {
    for (let i = 0; i < 100 && !aborts.length; i++) await new Promise(r => setTimeout(r, 50));
    await new Promise(r => setTimeout(r, 500));
    assert.match(aborts[0] ?? '', /browser traffic stopped at the margin: direct \d+ of cap 12 \(margin 6\)/);
  } finally { for (const close of ctx.closers.splice(0).reverse()) await close().catch(() => {}); await Promise.race([profile, new Promise(r => setTimeout(r, 3000))]); server.close(); }
});
test('r2.3 LP: after the stop the hard cap still holds: every request the server received was counted and none is overflow', async () => {
  const server = await fakeServer(), counter = createCounter({ direct: 12 }), aborts = [], ctx = { profile: 'r1-lp', scope: 'p/sdk-next/r1-lp', databaseURL: `http://${server.host}?ns=ns`, projectId: 'demo-x', local: true, target: { host: server.host }, journal: { write() {} }, counter, abort: m => aborts.push(m), caseMs: 5000, closeMs: 2000, closers: [], browserMargin: 6 };
  const profile = lpProfile(ctx).catch(() => {});
  try {
    for (let i = 0; i < 100 && !aborts.length; i++) await new Promise(r => setTimeout(r, 50));
    await new Promise(r => setTimeout(r, 500));
  } finally { for (const close of ctx.closers.splice(0).reverse()) await close().catch(() => {}); await Promise.race([profile, new Promise(r => setTimeout(r, 3000))]); }
  await new Promise(resolve => setTimeout(resolve, 300));
  const received = server.state.log.filter(k => k.includes('/.lp')).length, used = counter.used(); server.close();
  assert.ok(received >= 1); assert.ok(used.direct >= 6 && used.direct <= 12, JSON.stringify(used)); assert.equal(used.overflow, undefined); assert.ok(received <= used.direct, JSON.stringify({ used, received }));
});
test('r1.3 LP: without an injected margin the page stops at cap - BROWSER_MARGIN', async () => {
  const { BROWSER_MARGIN } = await import('./observer.mjs');
  const server = await fakeServer(), counter = createCounter({ direct: BROWSER_MARGIN + 3 }), aborts = [], ctx = { profile: 'r1-lp', scope: 'p/sdk-next/r1-lp', databaseURL: `http://${server.host}?ns=ns`, projectId: 'demo-x', local: true, target: { host: server.host }, journal: { write() {} }, counter, abort: m => aborts.push(m), caseMs: 5000, closeMs: 2000, closers: [] };
  const profile = lpProfile(ctx).catch(() => {});
  try {
    for (let i = 0; i < 100 && !aborts.length; i++) await new Promise(r => setTimeout(r, 50));
    assert.match(aborts[0] ?? '', new RegExp(`direct 3 of cap ${BROWSER_MARGIN + 3} \\(margin ${BROWSER_MARGIN}\\)`));
  } finally { for (const close of ctx.closers.splice(0).reverse()) await close().catch(() => {}); await Promise.race([profile, new Promise(r => setTimeout(r, 3000))]); server.close(); }
});
test('r1.5 the cleanup does not depend on the journal: with every journal write failing the restoration still happens', async () => {
  let down = false;
  const h = await harness({}, { createJournal: file => { const j = createJournal(file); return { ...j, write: row => { if (down) throw new Error('ENOSPC'); return j.write(row); } }; }, profiles: { ws: async () => { down = true; throw new Error('disk gone'); }, lp: goodProfiles.lp } }).catch(error => ({ error }));
  assert.ok(!h.error, String(h.error)); assert.equal(h.server.state.rules, BASELINE); assert.equal(h.server.state.prefix, null); assert.deepEqual(tail(h), CLEANUP); assert.equal(h.result.cleanup.rules, 'verified'); assert.equal(h.exit, 1);
});
test('r1.5 an error thrown in an SDK or page callback aborts into the cleanup instead of ending the process', async () => {
  for (const [event, raise] of [['uncaughtException', e => process.emit('uncaughtException', e)], ['unhandledRejection', e => process.emit('unhandledRejection', e, Promise.resolve())]]) {
    const saved = process.listeners(event); process.removeAllListeners(event);   // node:test's own listener would fail the test on purpose
    try {
      const h = await harness({ closeMs: 100 }, { profiles: { ws: () => new Promise(() => setTimeout(() => raise(new Error('callback boom')), 30)), lp: goodProfiles.lp } });
      assert.equal(h.exit, 3); assert.match(h.result.error, /aborted: uncaught: callback boom/); assert.deepEqual(tail(h), CLEANUP); assert.equal(h.server.state.rules, BASELINE); assert.equal(process.listeners(event).length, 0);
    } finally { for (const l of saved) process.on(event, l); }
  }
});

// ---- Codex review r2 (2026-11-02) ----
test('r2.1 a mutation whose outcome was unknown forces exit 3 and keeps the claims even though the cleanup read back clean; the late write is what the cleanup could not see', async () => {
  const r = await production({ lateApply: true });
  assert.equal(r.outcome.exit, 3); assert.deepEqual(r.outcome.result.cleanup, { prefix: 'verified', rules: 'verified' }); assert.ok(r.outcome.result.unverified.some(u => u.startsWith('unknown mutation outcome: rules-install')));
  assert.equal(r.leaseLeft, true); assert.equal(r.recordingLeft, true);
  await new Promise(resolve => setTimeout(resolve, 400)); assert.notEqual(r.state.rules, BASELINE);   // the late install did land after the "verified" restore
});
test('r2.2 a profile that finishes starting after its deadline is awaited and its late resources are closed before the cleanup', async () => {
  let lateClosed = false, sawCancelled = null;
  const late = server => ({ ws: async ctx => { await new Promise(r => setTimeout(r, 350)); sawCancelled = ctx.cancelled; ctx.closers.push(async () => { lateClosed = true; server.state.log.push('LATE-CLOSER'); }); if (ctx.cancelled) throw new Error('cancelled'); return rowsFor(); }, lp: goodProfiles.lp });
  const h = await harness({ profileMs: 100, closeMs: 1500 }, { profiles: late });
  assert.equal(sawCancelled, true); assert.equal(lateClosed, true); assert.deepEqual(h.result.unverified, []);
  const log = h.server.state.log; assert.ok(log.indexOf('LATE-CLOSER') > 0 && log.indexOf('LATE-CLOSER') < log.indexOf(CLEANUP[0]));
});
test('r2.2 a profile that never finishes starting keeps the claims', async () => {
  const r = await production({ profiles: { ws: () => new Promise(() => {}), lp: goodProfiles.lp }, opts: { profileMs: 100, closeMs: 100 } });
  assert.equal(r.outcome.exit, 3); assert.ok(r.outcome.result.unverified.includes('profile r1-ws did not settle')); assert.equal(r.leaseLeft, true);
});

// ---- repository copy (2026-11-03): private production inputs come from --production-config, output from --out ----
test('the production config accepts exactly the private fields with absolute paths', async () => {
  const { productionConfig } = await import('./observer.mjs');
  const good = { principalSha256: 'a'.repeat(64), legacyPacket: '/x/packet.json', runtimeProposal: '/x/runtime.json', paths: { owner: '/x/owner.md', lease: '/x/lease', recording: '/x/RECORDING' } };
  const target = productionConfig(good);
  assert.deepEqual([target.kind, target.projectId, target.namespace, target.region, target.paths.lease], ['production', 'fireemu-oracle-query', 'fireemu-q-rtdb2', 'us-central1', '/x/lease']);
  for (const bad of [null, {}, { ...good, extra: 1 }, { ...good, principalSha256: 'A'.repeat(64) }, { ...good, legacyPacket: 'x/packet.json' }, { ...good, paths: { ...good.paths, recording: 'RECORDING' } }, { ...good, paths: { owner: '/o', lease: '/l' } }, { ...good, paths: { ...good.paths, more: '/m' } }])
    assert.throws(() => productionConfig(bad), /--production-config/, JSON.stringify(bad));
});
test('the command line needs --out, and production needs a readable --production-config, before anything is sent', async () => {
  const { spawnSync } = await import('node:child_process');
  const script = new URL('./observer.mjs', import.meta.url).pathname, env = { PATH: process.env.PATH, HOME: process.env.HOME };
  const base = ['--run-id', 'TEST-CLI-01', '--prefix', PREFIX, '--direct-cap', '40'];
  const noOut = spawnSync(process.execPath, [script, '--target', 'emulator', ...base], { env, encoding: 'utf8' });
  assert.equal(noOut.status, 2); assert.match(noOut.stderr, /--out/);
  const noConfig = spawnSync(process.execPath, ['--max-old-space-size=1024', script, '--target', 'production', ...base, '--out', path.join(tmpdir(), 'never-created')], { env, encoding: 'utf8' });
  assert.equal(noConfig.status, 2); assert.match(noConfig.stderr, /ENOENT|production-config/);
});
