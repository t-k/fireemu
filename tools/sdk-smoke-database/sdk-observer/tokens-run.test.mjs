// The tokens suite (G10, packet 5) inside the observer run: the global Rules installed and restored byte-equal, the
// case requests under each profile scope, the credential requests carrying no admin header, the request count, the
// deadlines, the approval line, the read-back, the command line, and the ADC token as auth= never in the journal.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { TABLE, TOKENS_AREA, TOKENS_CASES, TOKENS_PROFILES, credentials, tokensRules } from './tokens-suite.mjs';
import { MAX_PROBES } from './rules-suite.mjs';
import { checkApproval, scriptManifest, sha256 } from './lib.mjs';
import { PROBE_DELAY_MS, SUITES, backstopMs, expectedObservations, run } from './observer.mjs';
import { READBACK_SUITES, readback } from './readback.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BASELINE = '{\n  "rules": {\n    ".read": false,\n    ".write": false\n  }\n}\n', PREFIX = '/sdktokens0test001';
const DENIED = '{\n  "error" : "Permission denied"\n}\n';

/** A fake database: the first Rules PUT and the baseline are accepted; ready reads 200 once installed; authreq needs a credential; the answer echoes the query. */
async function fakeDatabase({ readyAfter = 0 } = {}) {
  const state = { rules: BASELINE, puts: [], log: [], readyMisses: 0 };
  const server = createServer((req, res) => {
    let body = ''; req.on('data', d => { body += d; });
    req.on('end', () => {
      const u = new URL(req.url, 'http://x'); state.log.push({ method: req.method, path: u.pathname, search: u.search, headers: req.headers });
      if (u.pathname === '/.settings/rules.json') {
        if (req.method === 'PUT') { if (state.puts.length === 0 || body === BASELINE) { state.rules = body; state.puts.push(body); res.writeHead(200).end('{"status":"ok"}'); } else res.writeHead(400).end('{"error":"x"}'); }
        else res.writeHead(200).end(state.rules);
        return;
      }
      if (u.pathname === `${PREFIX}.json`) { res.writeHead(200).end('null'); return; }
      if (u.pathname.endsWith('/ready.json')) { const inEffect = state.rules === state.puts[0] && state.readyMisses++ >= readyAfter; res.writeHead(inEffect ? 200 : 401).end('null'); return; }
      const credential = req.headers.authorization || u.searchParams.has('auth') || u.searchParams.has('access_token');
      if (u.pathname.endsWith('/authreq.json') && !credential) { res.writeHead(401, { 'content-type': 'application/json; charset=utf-8' }).end(DENIED); return; }
      res.writeHead(200, { 'content-type': 'application/json; charset=utf-8' }).end(JSON.stringify({ q: u.search }));
    });
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  return { state, host: `127.0.0.1:${server.address().port}`, close: () => { server.closeAllConnections(); server.close(); } };
}
const local = host => ({ kind: 'emulator', host, namespace: 'ns', projectId: 'demo-tokens-observer' });
const journalRows = dir => readFileSync(path.join(dir, 'journal.jsonl'), 'utf8').trim().split('\n').map(l => JSON.parse(l));

test('run --suite tokens: the global Rules installed and restored, 2 x 27 cases, 60 direct requests locally plus the 4 cleanup requests; the owner token resolves {adc}', async () => {
  const db = await fakeDatabase(), out = mkdtempSync(path.join(tmpdir(), 'tokens-run-'));
  try {
    const { exit, result } = await run({ target: local(db.host), runId: 'TEST-TOKENS-01', prefix: PREFIX, directCap: 80, outDir: path.join(out, 'run'), suite: 'tokens', probeDelayMs: 1 });
    assert.equal(exit, 0, JSON.stringify(result)); assert.equal(result.status, 'complete'); assert.equal(result.observed, 54);
    assert.equal(result.suite, 'tokens'); assert.equal(result.prefix, PREFIX);
    assert.deepEqual(JSON.parse(db.state.puts[0]), tokensRules(PREFIX)); assert.equal(db.state.rules, BASELINE);
    assert.deepEqual(result.counts, { direct: 60, reserve: 4, adc: 0 });
    const cases = db.state.log.filter(r => r.path.startsWith(`${PREFIX}/${TOKENS_AREA}/r`) && !r.path.endsWith('/ready.json'));
    assert.equal(cases.length, 54);
    assert.deepEqual([...new Set(cases.map(r => r.path.split('/')[3].replace(/\.json$/, '')))], TOKENS_PROFILES);
    const creds = credentials('demo-tokens-observer');
    for (const [i, r] of cases.entries()) {
      const spec = TABLE[i % TABLE.length], token = spec.credential === 'adc' ? 'owner' : creds[spec.credential];
      assert.equal(r.method, spec.method, spec.id);
      const want = spec.group === 'auth' || spec.group === 'access_token' ? `&${spec.group}=${encodeURIComponent(token)}` : '';
      assert.equal(r.search, `?ns=ns${want}`, spec.id);
      assert.equal(r.headers.authorization, spec.identity === 'admin' ? 'Bearer owner' : spec.group === 'bearer' ? `Bearer ${token}`.trimEnd() : undefined, spec.id);
    }
    const rows = journalRows(path.join(out, 'run'));
    assert.equal(rows.filter(r => r.kind === 'case').length, 54);
    assert.equal(rows.filter(r => r.kind === 'probe').length, 2);
    const adcRows = rows.filter(r => r.kind === 'case' && r.id.startsWith('auth-adc'));
    assert.ok(adcRows.every(r => r.body === '{"q":"?ns=ns&auth={adc}"}'), 'the resolved owner token is masked in the answer');
  } finally { db.close(); rmSync(out, { recursive: true, force: true }); }
});
test('run --suite tokens: a ready probe not yet in effect is repeated with the run\'s probe delay, and every extra probe is a counted request', async () => {
  const db = await fakeDatabase({ readyAfter: 2 }), out = mkdtempSync(path.join(tmpdir(), 'tokens-run-'));
  try {
    const started = Date.now();
    const { exit, result } = await run({ target: local(db.host), runId: 'TEST-TOKENS-02', prefix: PREFIX, directCap: 80, outDir: path.join(out, 'run'), suite: 'tokens', probeDelayMs: 1 });
    assert.equal(exit, 0, JSON.stringify(result)); assert.equal(result.counts.direct, 62);
    assert.ok(Date.now() - started < 1400, `the 1 ms probe delay of the run is used, not the 2 s default (${Date.now() - started} ms)`);
  } finally { db.close(); rmSync(out, { recursive: true, force: true }); }
});
test('run --suite tokens: a profile abandoned at its deadline aborts the run: unverified, exit 3, nothing of r2 sent', async () => {
  const db = await fakeDatabase(), out = mkdtempSync(path.join(tmpdir(), 'tokens-run-'));
  try {
    const { exit, result } = await run({ target: local(db.host), runId: 'TEST-TOKENS-03', prefix: PREFIX, directCap: 80, outDir: path.join(out, 'run'), suite: 'tokens', profileMs: 200, continueOnFailure: true }, { suiteProfiles: { tokens: { tokens: () => new Promise(() => {}) } } });
    assert.equal(exit, 3); assert.ok(result.unverified.includes('REST mutations possibly in flight: profile r1-tokens aborted'), JSON.stringify(result.unverified));
    assert.match(result.error ?? '', /tokens profile r1-tokens hit its deadline/);
    assert.equal(db.state.log.some(r => r.path.includes('/r2-tokens/')), false);
  } finally { db.close(); rmSync(out, { recursive: true, force: true }); }
});
test('run --suite tokens: an unknown answer to the seed keeps the claims (exit 3) and names it', async () => {
  const db = await fakeDatabase(), out = mkdtempSync(path.join(tmpdir(), 'tokens-run-'));
  const fetchImpl = async (u, init) => (String(u).includes('/r2-tokens.json') && init.method === 'PUT' ? new Response('', { status: 503 }) : fetch(u, init));
  try {
    const { exit, result } = await run({ target: local(db.host), runId: 'TEST-TOKENS-04', prefix: PREFIX, directCap: 80, outDir: path.join(out, 'run'), suite: 'tokens', probeDelayMs: 1, continueOnFailure: true }, { fetchImpl });
    assert.equal(exit, 3); assert.ok(result.unverified.includes('unknown REST mutation outcome: r2-tokens/seed'), JSON.stringify(result.unverified));
  } finally { db.close(); rmSync(out, { recursive: true, force: true }); }
});
test('run --suite tokens: the cap is taken before dispatch: a cap of 40 stops r2 at the cap, nothing over it reaches the server', async () => {
  const db = await fakeDatabase(), out = mkdtempSync(path.join(tmpdir(), 'tokens-run-'));
  try {
    const { exit, result } = await run({ target: local(db.host), runId: 'TEST-TOKENS-05', prefix: PREFIX, directCap: 40, outDir: path.join(out, 'run'), suite: 'tokens', probeDelayMs: 1, continueOnFailure: true });
    assert.equal(exit, 1, JSON.stringify(result)); assert.equal(result.counts.direct, 40);
    assert.equal(db.state.log.filter(r => !r.path.startsWith('/.settings') && r.path !== `${PREFIX}.json`).length, 40 - 4, 'the 4 preflight requests and 36 profile requests, the 37th refused');
    const last = result.cases.at(-1); assert.equal(last.outcome, 'not-sent'); assert.equal(last.profile, 'r2-tokens');
    assert.equal(db.state.rules, BASELINE, 'the cleanup still runs from the reserve');
  } finally { db.close(); rmSync(out, { recursive: true, force: true }); }
});
test('tokensProfile is wired to the profile cancellation and the run\'s project: a cancelled context sends nothing', async () => {
  const { tokensProfile } = await import('./observer.mjs'), sent = [];
  const answer = { status: 200, text: 'null', headers: {}, bodyBytes: 4, utf8: true, clipped: false };
  const ctx = { cancelled: true, scope: `${PREFIX.slice(1)}/${TOKENS_AREA}/r1-tokens`, projectId: 'demo-tokens-observer', probeDelayMs: 1, restUrl: (rel, q) => `http://h/${rel}${q ? `?${q}` : ''}`, rest: async (...a) => { sent.push(a); return answer; }, journal: { write() {} }, profile: 'r1-tokens' };
  assert.deepEqual(await tokensProfile(ctx), []); assert.equal(sent.length, 0);
  const live = { ...ctx, cancelled: false }; let n = 0; live.rest = async (...a) => { n += 1; sent.push(a); if (n === 3) live.cancelled = true; return answer; };
  assert.equal((await tokensProfile(live)).length, 2, 'the start probe and two cases, then nothing');
  const own = sent.find(a => a[0] === 'auth-none-own');
  assert.equal(own, undefined);
  const all = []; const full = { ...ctx, projectId: 'demo-wiring-project', cancelled: false, rest: async (...a) => { all.push(a); return answer; } };
  await tokensProfile(full);
  assert.ok(all.find(a => a[0] === 'auth-none-own')[2].includes(encodeURIComponent(credentials('demo-wiring-project').none_own)), 'the own-project token carries the run\'s project');
});
test('the tokens suite deadlines: 120 s per profile, 6 minutes per run, the backstop 8 minutes; observations 54; cap at most 100', () => {
  assert.deepEqual([SUITES.tokens.profileMs, SUITES.tokens.runMs, backstopMs('tokens')], [120000, 360000, 480000]);
  assert.equal(SUITES.tokens.capMax, 100); assert.equal(SUITES.tokens.basis, '2217');
  assert.equal(expectedObservations('tokens'), 2 * TOKENS_CASES.length);
  const worstProbes = (MAX_PROBES - 1) * PROBE_DELAY_MS.production;
  assert.ok(worstProbes + 27 * 2000 <= SUITES.tokens.profileMs, 'worst-case probing plus 2 s per case fits one profile deadline');
  assert.ok(2 * SUITES.tokens.profileMs + 60000 <= SUITES.tokens.runMs, 'two profile deadlines plus the preflight fit the run deadline');
});
test('approval: the tokens suite needs suite=tokens and basis=2217', () => {
  const line = over => `- 2026-11-05 | RTDB-SMALL-OBSERVER RTDB-TOKENS-20261105-01 | ${Object.entries({ decision: 'APPROVE', scriptSha256: 'a'.repeat(64), directCap: '80', adc: '1', prefix: '/sdktokens20261105', suite: 'tokens', basis: '2217', ...over }).map(([k, v]) => `${k}=${v}`).join('; ')} | coordinator | r.md\n`;
  const want = { runId: 'RTDB-TOKENS-20261105-01', scriptSha256: 'a'.repeat(64), directCap: 80, prefix: '/sdktokens20261105', suite: 'tokens' };
  assert.doesNotThrow(() => checkApproval(line(), want));
  assert.throws(() => checkApproval(line({ suite: 'rules' }), want), /approval fields differ/);
  assert.throws(() => checkApproval(line({ basis: '2196' }), want), /approval fields differ/);
  assert.throws(() => checkApproval(line(), { ...want, suite: 'token' }), /approval suite/);
});
test('read-back accepts a finished production run of the tokens suite', async () => {
  assert.ok(READBACK_SUITES.includes('tokens'));
  const EMAIL = 'someone@example.com', SCRIPT = scriptManifest(HERE).sha256, RUN = 'RTDB-TOKENS-20261105-01', P = '/sdktokens20261105';
  const dir = mkdtempSync(path.join(tmpdir(), 'tokens-readback-')), runDir = path.join(dir, 'run'); mkdirSync(runDir);
  writeFileSync(path.join(runDir, 'result.json'), JSON.stringify({ runId: RUN, target: 'production', suite: 'tokens', scriptSha256: SCRIPT, prefix: P, status: 'unverified', exit: 3, endedAt: '2026-11-05T01:00:00.000Z', caps: { direct: 80, reserve: 12, adc: 1 } }));
  const target = { kind: 'production', projectId: 'demo-proj', projectNumber: '1', namespace: 'inst-ns', region: 'us-central1', principalSha256: sha256(EMAIL), baselineRulesSha256: sha256(BASELINE), gcloud: '/nix/store/x/gcloud' };
  const fetchImpl = async u => {
    const s = String(u);
    if (s.startsWith('https://oauth2.googleapis.com/tokeninfo')) return new Response(JSON.stringify({ scope: 'https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/cloud-platform', email: EMAIL }));
    if (s.includes('/instances/')) return new Response(JSON.stringify({ type: 'USER_DATABASE', state: 'ACTIVE', name: 'projects/1/locations/us-central1/instances/inst-ns' }));
    if (s.includes('/.settings/rules.json')) return new Response(BASELINE);
    return new Response('null');
  };
  const ledgerText = `- 2026-11-05 | RTDB-SMALL-OBSERVER ${RUN} | decision=APPROVE; scriptSha256=${SCRIPT}; directCap=80; adc=1; prefix=${P}; suite=tokens; basis=2217 | coordinator | r.md\n`;
  try {
    const { exit, report } = await readback({ runDir, outDir: path.join(dir, 'out'), target, ledgerText }, { fetchImpl, mint: () => `ya29.${'x'.repeat(40)}`, now: () => Date.parse('2026-11-05T01:11:00.000Z') });
    assert.equal(exit, 0); assert.equal(report.suite, 'tokens'); assert.equal(report.verdict, 'settled');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test('command line: --suite tokens takes a cap of 20..100 and is in the usage', () => {
  const observer = path.join(HERE, 'observer.mjs');
  const r = spawnSync(process.execPath, [observer, '--target', 'emulator', '--suite', 'tokens', '--run-id', 'TEST-TOKENS-9', '--prefix', '/p', '--direct-cap', '101', '--out', '/nonexistent/x'], { encoding: 'utf8', env: { PATH: process.env.PATH } });
  assert.equal(r.status, 2); assert.match(r.stderr, /--direct-cap 20\.\.100/);
  const usage = spawnSync(process.execPath, [observer, '--target', 'emulator', '--suite', 'bogus'], { encoding: 'utf8', env: { PATH: process.env.PATH } });
  assert.match(usage.stderr, /--suite small\|events\|admin\|events\+admin\|rest\|rules\|tokens/);
});
test('the local target of the tokens suite has a project id of the production project id\'s length (the {project} mask keeps byte lengths comparable)', async () => {
  const { localTarget } = await import('./observer.mjs');
  assert.equal(localTarget('tokens', '127.0.0.1:1').projectId, 'demo-tokens-observer');
  assert.equal(localTarget('tokens', '127.0.0.1:1').projectId.length, 'fireemu-oracle-query'.length);
  assert.equal(localTarget('rules', '127.0.0.1:1').projectId, 'demo-small-observer', 'the other suites keep their recorded local project');
  assert.deepEqual(localTarget('rest', '127.0.0.1:9'), { kind: 'emulator', host: '127.0.0.1:9', namespace: 'fireemu-small-observer', projectId: 'demo-small-observer' });
});

// ---- production: the credential requests carry no admin header; the ADC token goes only into auth= and never into the journal ----
test('production run --suite tokens: credential requests carry no admin header; auth={adc} carries the ADC token in the URL only; the token is not journalled even when echoed', async () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'tokens-prod-')), SCRIPT = scriptManifest(HERE).sha256, RUN = 'TOKENS-PROD-01', P = '/sdktokens20261105', TOKEN = `ya29.${'t'.repeat(40)}/+=`;
  const paths = { owner: path.join(dir, 'owner.md'), lease: path.join(dir, 'lease'), recording: path.join(dir, 'RECORDING') }, state = { rules: BASELINE, first: null }, seen = [];
  writeFileSync(paths.owner, `- 2026-11-05 | RTDB-SMALL-OBSERVER ${RUN} | decision=APPROVE; scriptSha256=${SCRIPT}; directCap=80; adc=1; prefix=${P}; suite=tokens; basis=2217 | coordinator | r.md\n`);
  const fetchImpl = async (url, init = {}) => {
    const u = new URL(url), method = init.method ?? 'GET'; seen.push({ url: String(url), path: u.pathname, headers: init.headers ?? {} });
    if (u.hostname === 'oauth2.googleapis.com') return new Response(JSON.stringify({ scope: 'https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/userinfo.email', email: 'tester@example.com' }));
    if (u.hostname === 'firebasedatabase.googleapis.com') return new Response(JSON.stringify({ name: 'projects/1/locations/r/instances/ns', type: 'USER_DATABASE', state: 'ACTIVE' }));
    if (u.pathname === '/.settings/rules.json') { if (method === 'PUT') { state.first ??= init.body; state.rules = init.body; return new Response('{"status":"ok"}'); } return new Response(state.rules); }
    if (u.pathname === `${P}.json`) return new Response('null');
    if (u.pathname.endsWith('/ready.json')) return new Response('null');
    return new Response(`{"echo":${JSON.stringify(u.searchParams.get('auth'))}}`, { status: 401, headers: { 'www-authenticate': `Bearer realm="${u.searchParams.get('auth')}"` } });
  };
  const target = { kind: 'production', projectId: 'fireemu-oracle-query', projectNumber: '1', region: 'r', namespace: 'ns', principalSha256: sha256('tester@example.com'), baselineRulesSha256: sha256(BASELINE), gcloud: '/x', paths };
  try {
    const { exit, result } = await run({ target, runId: RUN, prefix: P, directCap: 80, suite: 'tokens', outDir: path.join(dir, 'run') }, { fetchImpl, mint: () => TOKEN });
    assert.equal(exit, 0, JSON.stringify(result)); assert.deepEqual(result.counts, { direct: 62, reserve: 4, adc: 1 });
    const data = seen.filter(s => s.path.startsWith(`${P}/`) && !s.path.endsWith('/ready.json'));
    for (const [i, s] of data.entries()) {
      const spec = TABLE[i % TABLE.length];
      if (spec.identity === 'admin') { assert.equal(s.headers.authorization, `Bearer ${TOKEN}`, spec.id); assert.equal(s.headers['x-goog-user-project'], 'fireemu-oracle-query', spec.id); continue; }
      assert.equal(s.headers['x-goog-user-project'], undefined, spec.id);
      assert.equal(s.headers.authorization === undefined, spec.group !== 'bearer', spec.id);
      assert.equal(s.url.includes(encodeURIComponent(TOKEN)), spec.credential === 'adc', `${spec.id}: only the auth={adc} cases carry the ADC token`);
      if (spec.credential === 'adc') assert.ok(s.url.endsWith(`auth=${encodeURIComponent(TOKEN)}`), spec.id);
    }
    const journal = readFileSync(path.join(dir, 'run', 'journal.jsonl'), 'utf8'), resultText = readFileSync(path.join(dir, 'run', 'result.json'), 'utf8');
    for (const form of [TOKEN, encodeURIComponent(TOKEN)]) { assert.equal(journal.includes(form), false); assert.equal(resultText.includes(form), false); }
    const adcCase = journalRows(path.join(dir, 'run')).find(r => r.kind === 'case' && r.id === 'auth-adc' && r.profile === 'r1-tokens');
    assert.equal(adcCase.body, '{"echo":"{adc}"}'); assert.equal(adcCase.responseHeaders['www-authenticate'], 'Bearer realm="{adc}"');
    assert.equal(existsSync(paths.lease), false);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
