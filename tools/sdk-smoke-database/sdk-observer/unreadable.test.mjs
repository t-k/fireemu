// Codex presend review of packet 2 v1, Must 1 and 2: an unreadable answer to a mutation is an unknown outcome, and an approval line with a
// repeated field is refused. The rest suite runs through the real observer with a fake HTTP world, and the A2 read-back accepts the run.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, existsSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { run } from './observer.mjs';
import { readback } from './readback.mjs';
import { checkApproval, createAdmin, createCounter, scriptManifest, sha256 } from './lib.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url)), SCRIPT = scriptManifest(HERE).sha256;
const BASELINE = '{\n  "rules": {\n    ".read": false,\n    ".write": false\n  }\n}\n', PREFIX = '/sdkrest20261104', RUN = 'REST-UNREADABLE-01', TOKEN = `ya29.${'t'.repeat(40)}`;
const approval = (over = {}) => `- 2026-11-04 | RTDB-SMALL-OBSERVER ${RUN} | ${Object.entries({ decision: 'APPROVE', scriptSha256: SCRIPT, directCap: '190', adc: '1', prefix: PREFIX, suite: 'rest', basis: '2217', ...over }).map(([k, v]) => `${k}=${v}`).join('; ')} | coordinator | review.md\n`;
const INSTANCE = JSON.stringify({ name: 'projects/1/locations/r/instances/ns', type: 'USER_DATABASE', state: 'ACTIVE' });
const BAD = new Uint8Array([0xff, 0xfe]);   // not UTF-8

// One of the four cases the review named, as the request the fake world answers with bytes that are not UTF-8.
async function world(unreadable) {
  const dir = mkdtempSync(path.join(tmpdir(), 'unreadable-')), paths = { owner: path.join(dir, 'owner.md'), lease: path.join(dir, 'lease'), recording: path.join(dir, 'RECORDING') }, state = { rules: BASELINE, sent: [] };
  writeFileSync(paths.owner, approval());
  const fetchImpl = async (url, init = {}) => {
    const u = new URL(url), method = init.method ?? 'GET'; state.sent.push(`${method} ${u.pathname}`);
    if (u.hostname === 'oauth2.googleapis.com') return new Response(JSON.stringify({ scope: 'https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/userinfo.email', email: 'tester@example.com' }));
    if (u.hostname === 'firebasedatabase.googleapis.com') return new Response(INSTANCE);
    if (u.pathname === '/.settings/rules.json') { if (method === 'PUT') { state.rules = init.body; return new Response('{"status":"ok"}'); } return new Response(state.rules); }
    if (unreadable && unreadable(method, u, init)) return new Response(BAD, { status: 200 });
    if (u.pathname.endsWith('/etag.json')) return new Response('{"x":1}', { headers: { etag: '"abc="' } });
    return new Response('null');
  };
  const target = { kind: 'production', projectId: 'demo-prod', projectNumber: '1', region: 'r', namespace: 'ns', principalSha256: sha256('tester@example.com'), baselineRulesSha256: sha256(BASELINE), gcloud: '/x', paths };
  const outcome = await run({ target, runId: RUN, prefix: PREFIX, directCap: 190, suite: 'rest', outDir: path.join(dir, 'run') }, { fetchImpl, mint: () => TOKEN });
  return { dir, paths, state, outcome, target, runDir: path.join(dir, 'run'), cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}
const cases = { 'etag-inm-put': (m, u) => m === 'PUT' && u.pathname.endsWith('/etag2.json'), 'override-delete': (m, u, init) => m === 'POST' && u.pathname.endsWith('/ov1.json') && init.headers?.['x-http-method-override'] === 'DELETE', 'print-silent-delete': (m, u) => m === 'DELETE' && u.pathname.endsWith('/pr.json'), 'sv-overflow-patch': (m, u) => m === 'PATCH' && u.pathname.endsWith('/svo.json') };

test('a clean rest run answers every case, exits 0 and releases the claims (the fake world itself is sound)', async () => {
  const w = await world(null);
  try { assert.equal(w.outcome.exit, 0, JSON.stringify(w.outcome.result.unverified)); assert.deepEqual(w.outcome.result.unverified, []); assert.equal(existsSync(w.paths.lease), false); } finally { w.cleanup(); }
});
for (const [id, match] of Object.entries(cases)) {
  test(`${id}: a 200 whose body is not UTF-8 is an unknown mutation: exit 3, claims kept, the read-back accepts the run`, async () => {
    const w = await world(match);
    try {
      const { result, exit } = w.outcome;
      assert.equal(exit, 3, JSON.stringify(result.unverified)); assert.equal(result.status, 'unverified');
      assert.ok(result.unverified.some(u => u.includes(id)), JSON.stringify(result.unverified));
      assert.equal(existsSync(w.paths.lease), true, 'lease kept'); assert.equal(existsSync(w.paths.recording), true, 'RECORDING kept');
      assert.deepEqual(result.cleanup, { prefix: 'verified', rules: 'verified' }, 'cleanup itself verified; the claims stay because of the unknown');
      const journal = readFileSync(path.join(w.runDir, 'journal.jsonl'), 'utf8').split('\n').filter(Boolean).map(l => JSON.parse(l));
      const row = journal.find(r => r.kind === 'case' && r.id === id && r.profile === 'r1-rest');
      assert.equal(row.ok, false); assert.equal(row.outcome, 'unknown-body'); assert.deepEqual(row.unknown, [id]); assert.equal(row.utf8, false);
      // A2: the read-back is allowed ten minutes after the run ended and finds prefix null, Rules at baseline, instance ACTIVE
      const fetchImpl = async url => { const u = new URL(url); if (u.hostname === 'oauth2.googleapis.com') return new Response(JSON.stringify({ scope: 'https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/userinfo.email', email: 'tester@example.com' })); if (u.hostname === 'firebasedatabase.googleapis.com') return new Response(INSTANCE); if (u.pathname === '/.settings/rules.json') return new Response(BASELINE); return new Response('null'); };
      const out = await readback({ runDir: w.runDir, outDir: path.join(w.dir, 'a2'), target: w.target, ledgerText: readFileSync(w.paths.owner, 'utf8') }, { fetchImpl, mint: () => TOKEN, now: () => Date.parse(result.endedAt) + 11 * 60 * 1000 });
      assert.equal(out.exit, 0); assert.equal(out.report.verdict, 'settled');
    } finally { w.cleanup(); }
  });
}
test('a GET whose body is not UTF-8 is recorded but is not a mutation: nothing is unknown', async () => {
  const w = await world((m, u) => m === 'GET' && u.pathname.endsWith('/mix.json') && u.searchParams.get('timeout') === '5s');
  try { assert.equal(w.outcome.result.unverified.length, 0, JSON.stringify(w.outcome.result.unverified)); assert.equal(w.outcome.exit, 0); } finally { w.cleanup(); }
});
test('createAdmin: an unreadable answer to a non-GET in record mode is listed in unknownMutations; to a GET, or in text mode, it is not', async () => {
  const run1 = async (method, record) => {
    const counter = createCounter({ direct: 10 }), admin = createAdmin({ headers: {}, journal: { write() {} }, counter, fetchImpl: async () => new Response(BAD, { status: 200 }) });
    await admin.rest('x', method, 'http://h/x.json', { record }).catch(() => {}); return admin.unknownMutations;
  };
  assert.deepEqual(await run1('PUT', true), ['x']); assert.deepEqual(await run1('GET', true), []); assert.deepEqual(await run1('PUT', false), []);
});

// ---- Must 2: repeated approval fields ----
test('checkApproval refuses a line that repeats a field (a changed, contradictory line), also when the first value is the expected one', () => {
  const want = { runId: RUN, scriptSha256: SCRIPT, directCap: 190, prefix: PREFIX, suite: 'rest' };
  checkApproval(approval(), want);
  const plain = approval().replace('decision=APPROVE', 'decision=REVOKED; decision=APPROVE');
  assert.throws(() => checkApproval(plain, want), /repeated|duplicate/);
  for (const field of ['scriptSha256', 'directCap', 'adc', 'prefix', 'suite', 'basis']) {
    const line = approval(), value = line.match(new RegExp(`${field}=([^;|]+)`))[1].trim();
    assert.throws(() => checkApproval(line.replace(`${field}=${value}`, `${field}=${value}; ${field}=${value}`), want), /repeated|duplicate/, `${field} repeated with the same value`);
    assert.throws(() => checkApproval(line.replace(`${field}=${value}`, `${field}=other; ${field}=${value}`), want), /repeated|duplicate/, `${field} repeated with another value first`);
  }
  assert.throws(() => checkApproval(approval().replace('adc=1', 'adc=1; ; '), want), /approval fields|repeated|duplicate/, 'an empty field is not a field');
});
