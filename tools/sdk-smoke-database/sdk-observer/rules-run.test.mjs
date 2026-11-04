// The rules suite (G8, packet 3) inside the observer run: the global Rules installed by the observer and restored
// byte-equal, the case requests under each profile scope, anonymous requests without a credential, the request
// count, the deadlines, the approval line, the read-back and the command line.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { RULES_AREA, RULES_CASES, RULES_PROFILES, TABLE, globalRules } from './rules-suite.mjs';
import { checkApproval, scriptManifest, sha256 } from './lib.mjs';
import { PROBE_DELAY_MS, SUITES, backstopMs, expectedObservations, run } from './observer.mjs';
import { READBACK_SUITES, readback } from './readback.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BASELINE = '{\n  "rules": {\n    ".read": false,\n    ".write": false\n  }\n}\n', PREFIX = '/sdkrules0test001';
const VALID = new Set(TABLE.filter(c => c.expectValid).map(c => c.body));

/** A fake database: Rules PUTs of the install text are accepted, the expected-valid load documents too, others refused; ready reads 200 under the install text only. */
async function fakeDatabase({ readyAfter = 0 } = {}) {
  const state = { rules: BASELINE, puts: [], log: [], readyMisses: 0 };
  const server = createServer((req, res) => {
    let body = ''; req.on('data', d => { body += d; });
    req.on('end', () => {
      const u = new URL(req.url, 'http://x'); state.log.push({ method: req.method, path: u.pathname, search: u.search, headers: req.headers });
      if (u.pathname === '/.settings/rules.json') {
        if (req.method === 'PUT') {
          const accepted = state.puts.length === 0 || body === state.puts[0] || body === BASELINE || VALID.has(body);
          if (accepted) { state.rules = body; state.puts.push(body); res.writeHead(200).end('{"status":"ok"}'); } else res.writeHead(400, { 'content-type': 'application/json; charset=utf-8' }).end('{\n  "error" : "1:12: bad"\n}\n');
        } else res.writeHead(200).end(state.rules);
        return;
      }
      if (u.pathname === `${PREFIX}.json`) { res.writeHead(200).end('null'); return; }
      if (u.pathname.endsWith('/ready.json')) { const inEffect = state.rules === state.puts[0] && state.readyMisses++ >= readyAfter; res.writeHead(inEffect ? 200 : 401).end(inEffect ? 'null' : '{\n  "error" : "Permission denied"\n}\n'); return; }
      res.writeHead(200, { 'content-type': 'application/json; charset=utf-8', ...(req.headers['x-firebase-etag'] ? { etag: '"e1"' } : {}) }).end('{}');
    });
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  return { state, host: `127.0.0.1:${server.address().port}`, close: () => { server.closeAllConnections(); server.close(); } };
}
const local = host => ({ kind: 'emulator', host, namespace: 'ns', projectId: 'demo-x' });

test('run --suite rules: the global Rules are installed and restored, 2 x 70 cases, 162 direct requests locally (4 reinstalls and 5 probes per round) plus the 4 cleanup requests', async () => {
  const db = await fakeDatabase(), out = mkdtempSync(path.join(tmpdir(), 'rules-run-'));
  try {
    const { exit, result } = await run({ target: local(db.host), runId: 'TEST-RULES-01', prefix: PREFIX, directCap: 210, outDir: path.join(out, 'run'), suite: 'rules', probeDelayMs: 1 });
    assert.equal(exit, 0, JSON.stringify(result)); assert.equal(result.status, 'complete'); assert.equal(result.observed, 140); assert.equal(result.suite, 'rules'); assert.equal(result.prefix, PREFIX);
    assert.deepEqual(JSON.parse(db.state.puts[0]), globalRules(PREFIX)); assert.equal(db.state.rules, BASELINE);
    assert.equal(db.state.puts.filter(p => p === db.state.puts[0]).length, 1 + 2 * 4, 'the observer install, then one reinstall after each accepted document');
    assert.deepEqual(result.counts, { direct: 162, reserve: 4, adc: 0 });
    const cases = db.state.log.filter(r => r.path.startsWith(`${PREFIX}/${RULES_AREA}/r`) && !r.path.endsWith('/ready.json'));
    assert.deepEqual([...new Set(cases.map(r => r.path.split('/')[3].replace(/\.json$/, '')))], RULES_PROFILES);
    for (const r of cases) {
      const id = TABLE.find(c => RULES_PROFILES.some(p => `${PREFIX}/${RULES_AREA}/${p}${c.path}` === r.path) && r.search === `?ns=ns${c.query ? `&${c.query}` : ''}` && c.method === r.method);
      assert.ok(id, `${r.method} ${r.path}${r.search} is a request of the case table`);
    }
    const anonymous = db.state.log.filter(r => r.headers.authorization === undefined);
    assert.ok(anonymous.length > 0 && anonymous.every(r => r.path.startsWith(`${PREFIX}/${RULES_AREA}/`)), 'only case and probe requests go without the credential');
    const rows = readFileSync(path.join(out, 'run', 'journal.jsonl'), 'utf8').trim().split('\n').map(l => JSON.parse(l));
    assert.equal(rows.filter(r => r.kind === 'case').length, 140);
    assert.deepEqual(rows.filter(r => r.kind === 'install').map(r => `${r.profile}/${r.after}/${r.ok}`), RULES_PROFILES.flatMap(p => ['lex-feff', 'lex-nel', 'lex-lazy', 'lex-number'].map(id => `${p}/${id}/true`)));
    assert.equal(rows.filter(r => r.kind === 'probe').length, 10);
    assert.equal(/authorization/i.test(readFileSync(path.join(out, 'run', 'journal.jsonl'), 'utf8')), false);
  } finally { db.close(); rmSync(out, { recursive: true, force: true }); }
});
test('run --suite rules: a ready probe that is not yet in effect is repeated with the run\'s probe delay, and every extra probe is a counted request', async () => {
  const db = await fakeDatabase({ readyAfter: 2 }), out = mkdtempSync(path.join(tmpdir(), 'rules-run-'));
  try {
    const started = Date.now();
    const { exit, result } = await run({ target: local(db.host), runId: 'TEST-RULES-02', prefix: PREFIX, directCap: 210, outDir: path.join(out, 'run'), suite: 'rules', probeDelayMs: 1 });
    assert.equal(exit, 0, JSON.stringify(result)); assert.equal(result.counts.direct, 164);
    assert.ok(Date.now() - started < 1400, `the 1 ms probe delay of the run is used, not the 1.5 s default (${Date.now() - started} ms)`);
  } finally { db.close(); rmSync(out, { recursive: true, force: true }); }
});
test('run --suite rules: a profile abandoned at its deadline aborts the run: unverified, exit 3, nothing of r2 sent', async () => {
  const db = await fakeDatabase(), out = mkdtempSync(path.join(tmpdir(), 'rules-run-'));
  try {
    const { exit, result } = await run({ target: local(db.host), runId: 'TEST-RULES-03', prefix: PREFIX, directCap: 210, outDir: path.join(out, 'run'), suite: 'rules', profileMs: 200, continueOnFailure: true }, { suiteProfiles: { rules: { rules: () => new Promise(() => {}) } } });
    assert.equal(exit, 3); assert.ok(result.unverified.includes('REST mutations possibly in flight: profile r1-rules aborted'), JSON.stringify(result.unverified));
    assert.match(result.error ?? '', /rules profile r1-rules hit its deadline/);
    assert.equal(db.state.log.some(r => r.path.includes('/r2-rules/')), false);
  } finally { db.close(); rmSync(out, { recursive: true, force: true }); }
});
test('run --suite rules: an unknown answer to a reinstall keeps the claims (exit 3) and names it', async () => {
  const db = await fakeDatabase(), out = mkdtempSync(path.join(tmpdir(), 'rules-run-'));
  let puts = 0;
  const fetchImpl = async (u, init) => { if (String(u).includes('/.settings/rules.json') && init.method === 'PUT' && ++puts === 15) return new Response('', { status: 503 }); return fetch(u, init); };
  try {
    const { exit, result } = await run({ target: local(db.host), runId: 'TEST-RULES-04', prefix: PREFIX, directCap: 210, outDir: path.join(out, 'run'), suite: 'rules', probeDelayMs: 1, continueOnFailure: true }, { fetchImpl });
    assert.equal(exit, 3); assert.ok(result.unverified.some(u => /install-lex-nel/.test(u)), JSON.stringify(result.unverified));
  } finally { db.close(); rmSync(out, { recursive: true, force: true }); }
});
test('rulesProfile is wired to the profile cancellation: a cancelled context sends nothing, a live one stops once cancelled', async () => {
  const { rulesProfile } = await import('./observer.mjs'), sent = [];
  const answer = { status: 200, text: 'null', headers: {}, bodyBytes: 4, utf8: true, clipped: false };
  const ctx = { cancelled: true, scope: `${PREFIX.slice(1)}/${RULES_AREA}/r1-rules`, installBody: JSON.stringify(globalRules(PREFIX)), probeDelayMs: 1, restUrl: (rel, q) => `http://h/${rel}${q ? `?${q}` : ''}`, rest: async (...a) => { sent.push(a); return answer; }, journal: { write() {} }, profile: 'r1-rules' };
  assert.deepEqual(await rulesProfile(ctx), []); assert.equal(sent.length, 0);
  const live = { ...ctx, cancelled: false }; let n = 0; live.rest = async () => { n += 1; if (n === 3) live.cancelled = true; return answer; };
  assert.equal((await rulesProfile(live)).length, 2, 'the start probe and two cases, then nothing');
  assert.equal(n, 3);
});
test('the rules suite deadlines: 180 s per profile, 7 minutes per run, the backstop 9 minutes; observations 140; probe delay 1.5 s in production', () => {
  assert.deepEqual([SUITES.rules.profileMs, SUITES.rules.runMs, backstopMs('rules')], [180000, 420000, 540000]);
  assert.equal(SUITES.rules.capMax, 250); assert.equal(SUITES.rules.basis, '2217');
  assert.equal(expectedObservations('rules'), 2 * RULES_CASES.length);
  assert.deepEqual(PROBE_DELAY_MS, { production: 1500, emulator: 100 });
});
test('approval: the rules suite needs suite=rules and basis=2217', () => {
  const line = over => `- 2026-11-05 | RTDB-SMALL-OBSERVER RTDB-RULES-20261105-01 | ${Object.entries({ decision: 'APPROVE', scriptSha256: 'a'.repeat(64), directCap: '210', adc: '1', prefix: '/sdkrules20261105', suite: 'rules', basis: '2217', ...over }).map(([k, v]) => `${k}=${v}`).join('; ')} | coordinator | r.md\n`;
  const want = { runId: 'RTDB-RULES-20261105-01', scriptSha256: 'a'.repeat(64), directCap: 210, prefix: '/sdkrules20261105', suite: 'rules' };
  assert.doesNotThrow(() => checkApproval(line(), want));
  assert.throws(() => checkApproval(line({ suite: 'rest' }), want), /approval fields differ/);
  assert.throws(() => checkApproval(line({ basis: '2196' }), want), /approval fields differ/);
});
test('read-back accepts a finished production run of the rules suite', async () => {
  assert.ok(READBACK_SUITES.includes('rules'));
  const EMAIL = 'someone@example.com', SCRIPT = scriptManifest(HERE).sha256, RUN = 'RTDB-RULES-20261105-01', P = '/sdkrules20261105';
  const dir = mkdtempSync(path.join(tmpdir(), 'rules-readback-')), runDir = path.join(dir, 'run'); mkdirSync(runDir);
  writeFileSync(path.join(runDir, 'result.json'), JSON.stringify({ runId: RUN, target: 'production', suite: 'rules', scriptSha256: SCRIPT, prefix: P, status: 'unverified', exit: 3, endedAt: '2026-11-05T01:00:00.000Z', caps: { direct: 210, reserve: 12, adc: 1 } }));
  const target = { kind: 'production', projectId: 'demo-proj', projectNumber: '1', namespace: 'inst-ns', region: 'us-central1', principalSha256: sha256(EMAIL), baselineRulesSha256: sha256(BASELINE), gcloud: '/nix/store/x/gcloud' };
  const fetchImpl = async u => {
    const s = String(u);
    if (s.startsWith('https://oauth2.googleapis.com/tokeninfo')) return new Response(JSON.stringify({ scope: 'https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/cloud-platform', email: EMAIL }));
    if (s.includes('/instances/')) return new Response(JSON.stringify({ type: 'USER_DATABASE', state: 'ACTIVE', name: 'projects/1/locations/us-central1/instances/inst-ns' }));
    if (s.includes('/.settings/rules.json')) return new Response(BASELINE);
    return new Response('null');
  };
  const ledgerText = `- 2026-11-05 | RTDB-SMALL-OBSERVER ${RUN} | decision=APPROVE; scriptSha256=${SCRIPT}; directCap=210; adc=1; prefix=${P}; suite=rules; basis=2217 | coordinator | r.md\n`;
  try {
    const { exit, report } = await readback({ runDir, outDir: path.join(dir, 'out'), target, ledgerText }, { fetchImpl, mint: () => `ya29.${'x'.repeat(40)}`, now: () => Date.parse('2026-11-05T01:11:00.000Z') });
    assert.equal(exit, 0); assert.equal(report.suite, 'rules'); assert.equal(report.verdict, 'settled');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test('command line: --suite rules takes a cap of 20..250 and is in the usage', () => {
  const observer = path.join(HERE, 'observer.mjs');
  const r = spawnSync(process.execPath, [observer, '--target', 'emulator', '--suite', 'rules', '--run-id', 'TEST-RULES-9', '--prefix', '/p', '--direct-cap', '251', '--out', '/nonexistent/x'], { encoding: 'utf8', env: { PATH: process.env.PATH } });
  assert.equal(r.status, 2); assert.match(r.stderr, /--direct-cap 20\.\.250/);
  const usage = spawnSync(process.execPath, [observer, '--target', 'emulator', '--suite', 'bogus'], { encoding: 'utf8', env: { PATH: process.env.PATH } });
  assert.match(usage.stderr, /--suite small\|events\|admin\|events\+admin\|rest\|rules/);
});

// ---- production: the anonymous requests carry neither the token nor the user project; the token never reaches the journal ----
test('production run --suite rules: anonymous requests carry no credential header, the others the ADC token; probes 1.5 s apart by default; token not journalled', async () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'rules-prod-')), SCRIPT = scriptManifest(HERE).sha256, RUN = 'RULES-PROD-01', P = '/sdkrules20261105', TOKEN = `ya29.${'t'.repeat(40)}`;
  const paths = { owner: path.join(dir, 'owner.md'), lease: path.join(dir, 'lease'), recording: path.join(dir, 'RECORDING') }, state = { rules: BASELINE, first: null }, seen = [];
  writeFileSync(paths.owner, `- 2026-11-05 | RTDB-SMALL-OBSERVER ${RUN} | decision=APPROVE; scriptSha256=${SCRIPT}; directCap=210; adc=1; prefix=${P}; suite=rules; basis=2217 | coordinator | r.md\n`);
  const fetchImpl = async (url, init = {}) => {
    const u = new URL(url), method = init.method ?? 'GET'; seen.push({ path: u.pathname, headers: init.headers ?? {}, at: Date.now() });
    if (u.hostname === 'oauth2.googleapis.com') return new Response(JSON.stringify({ scope: 'https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/userinfo.email', email: 'tester@example.com' }));
    if (u.hostname === 'firebasedatabase.googleapis.com') return new Response(JSON.stringify({ name: 'projects/1/locations/r/instances/ns', type: 'USER_DATABASE', state: 'ACTIVE' }));
    if (u.pathname === '/.settings/rules.json') { if (method === 'PUT') { state.first ??= init.body; if (init.body === state.first || init.body === BASELINE) { state.rules = init.body; return new Response('{"status":"ok"}'); } return new Response('{"error":"x"}', { status: 400 }); } return new Response(state.rules); }
    if (u.pathname === `${P}.json`) return new Response('null');
    if (init.headers?.['x-firebase-etag']) return new Response('{}', { headers: { etag: '"e1"' } });
    if (u.pathname.endsWith('/ready.json')) return new Response('null', { status: seen.filter(s => s.path.endsWith('/ready.json')).length === 1 ? 401 : 200 });
    return new Response('{}');
  };
  const target = { kind: 'production', projectId: 'demo-prod', projectNumber: '1', region: 'r', namespace: 'ns', principalSha256: sha256('tester@example.com'), baselineRulesSha256: sha256(BASELINE), gcloud: '/x', paths };
  try {
    const { exit, result } = await run({ target, runId: RUN, prefix: P, directCap: 210, suite: 'rules', outDir: path.join(dir, 'run') }, { fetchImpl, mint: () => TOKEN });
    assert.equal(exit, 0, JSON.stringify(result)); assert.equal(existsSync(paths.lease), false);
    const data = seen.filter(s => s.path.startsWith(`${P}/`));
    for (const s of data) {
      const anonymous = s.headers.authorization === undefined;
      if (anonymous) assert.equal(s.headers['x-goog-user-project'], undefined, s.path);
      else { assert.equal(s.headers.authorization, `Bearer ${TOKEN}`, s.path); assert.equal(s.headers['x-goog-user-project'], 'demo-prod', s.path); }
    }
    const probes = seen.filter(s => s.path.endsWith('/ready.json'));
    assert.ok(probes[1].at - probes[0].at >= 1400, `the second probe waited the production delay (${probes[1].at - probes[0].at} ms)`);
    assert.equal(readFileSync(path.join(dir, 'run', 'journal.jsonl'), 'utf8').includes(TOKEN), false);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
