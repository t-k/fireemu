// Hardening after the packet 2 v1.1 Codex round: a mutation still in flight when the run or profile deadline hits (the
// request left, no answer came) and an answer body cut mid-read are unknown outcomes that keep the claims, in the rest
// and the rules suites; the unreadable-body rule applies to record-mode case answers only (the preflight and cleanup
// requests read text); and writeAll refuses a write that makes no progress after one call (a counted fake, so the
// mutant that accepts no progress fails here instead of hanging).
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, existsSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { run } from './observer.mjs';
import { createAdmin, createCounter, scriptManifest, sha256, writeAll } from './lib.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url)), SCRIPT = scriptManifest(HERE).sha256;
const BASELINE = '{\n  "rules": {\n    ".read": false,\n    ".write": false\n  }\n}\n', TOKEN = `ya29.${'t'.repeat(40)}`;
const INSTANCE = JSON.stringify({ name: 'projects/1/locations/r/instances/ns', type: 'USER_DATABASE', state: 'ACTIVE' });
const BAD = new Uint8Array([0xff, 0xfe]);
const PREFIX = { rest: '/sdkrest20261104', rules: '/sdkrules20261104' };
const cap = { rest: 190, rules: 210 };

/** Never answers; rejects when the request's own timeout signal fires (the request left, no answer came). */
const hang = init => new Promise((_, reject) => { init.signal?.addEventListener('abort', () => reject(init.signal.reason), { once: true }); });
/** An answer whose body stream breaks after the first bytes. */
const cut = (status = 200) => new Response(new ReadableStream({ start(c) { c.enqueue(new TextEncoder().encode('{"a":')); c.error(new Error('connection reset')); } }), { status });

/** A production-target world for one suite; `special(method, url, init)` may answer a request instead of the default. */
async function world(suite, special, opts = {}) {
  const dir = mkdtempSync(path.join(tmpdir(), 'inflight-')), runId = `INFLIGHT-${suite.toUpperCase()}-01`;
  const paths = { owner: path.join(dir, 'owner.md'), lease: path.join(dir, 'lease'), recording: path.join(dir, 'RECORDING') }, state = { rules: BASELINE, first: null, sent: [] };
  writeFileSync(paths.owner, `- 2026-11-04 | RTDB-SMALL-OBSERVER ${runId} | decision=APPROVE; scriptSha256=${SCRIPT}; directCap=${cap[suite]}; adc=1; prefix=${PREFIX[suite]}; suite=${suite}; basis=2217 | coordinator | review.md\n`);
  const fetchImpl = async (url, init = {}) => {
    const u = new URL(url), method = init.method ?? 'GET'; state.sent.push(`${method} ${u.pathname}`);
    const answer = special?.(method, u, init);
    if (answer) return answer;
    if (u.hostname === 'oauth2.googleapis.com') return new Response(JSON.stringify({ scope: 'https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/userinfo.email', email: 'tester@example.com' }));
    if (u.hostname === 'firebasedatabase.googleapis.com') return new Response(INSTANCE);
    if (u.pathname === '/.settings/rules.json') { if (method === 'PUT') { state.first ??= init.body; if (init.body === state.first || init.body === BASELINE) { state.rules = init.body; return new Response('{"status":"ok"}'); } return new Response('{"error":"x"}', { status: 400 }); } return new Response(state.rules); }
    if (init.headers?.['x-firebase-etag']) return new Response('{"x":1}', { headers: { etag: '"abc="' } });
    return new Response('null');
  };
  const target = { kind: 'production', projectId: 'demo-prod', projectNumber: '1', region: 'r', namespace: 'ns', principalSha256: sha256('tester@example.com'), baselineRulesSha256: sha256(BASELINE), gcloud: '/x', paths };
  const outcome = await run({ target, runId, prefix: PREFIX[suite], directCap: cap[suite], suite, outDir: path.join(dir, 'run'), probeDelayMs: 1, ...opts }, { fetchImpl, mint: () => TOKEN });
  const journal = () => readFileSync(path.join(dir, 'run', 'journal.jsonl'), 'utf8').split('\n').filter(Boolean).map(l => JSON.parse(l));
  return { outcome, paths, state, journal, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}
const claimsKept = w => { assert.equal(existsSync(w.paths.lease), true, 'lease kept'); assert.equal(existsSync(w.paths.recording), true, 'RECORDING kept'); };
const claimsReleased = w => { assert.equal(existsSync(w.paths.lease), false, 'lease released'); assert.equal(existsSync(w.paths.recording), false, 'RECORDING released'); };

// ---- H1: a mutation in flight when the deadline hits ----
const inflight = {
  rest: { id: 'setup-ints', match: (m, u) => m === 'PUT' && u.pathname.endsWith('/r1-rest/ints.json') },
  rules: { id: 'wv-allow', match: (m, u) => m === 'PUT' && u.pathname.endsWith('/r1-rules/wv/p1.json') },
};
for (const suite of ['rest', 'rules']) {
  for (const [deadline, opts] of [['run', { runMs: 300 }], ['profile', { profileMs: 300 }]]) {
    test(`${suite}: a mutation in flight when the ${deadline} deadline hits is an unknown outcome: exit 3, named, claims kept, nothing sent after it but the cleanup`, async () => {
      const { id, match } = inflight[suite];
      const w = await world(suite, (m, u, init) => (match(m, u) ? hang(init) : null), { adminMs: 800, closeMs: 200, continueOnFailure: true, ...opts });
      try {
        const { exit, result } = w.outcome;
        assert.equal(exit, 3, JSON.stringify(result)); assert.equal(result.status, 'unverified');
        assert.ok(result.unverified.includes(`unknown mutation outcome: ${id}`), JSON.stringify(result.unverified));
        assert.deepEqual(result.cleanup, { prefix: 'verified', rules: 'verified' });
        claimsKept(w);
        const at = w.state.sent.findIndex(l => l.startsWith('PUT ') && (l.endsWith('/ints.json') || l.endsWith('/wv/p1.json')));
        assert.deepEqual(w.state.sent.slice(at + 1), [`DELETE ${PREFIX[suite]}.json`, `GET ${PREFIX[suite]}.json`, 'PUT /.settings/rules.json', 'GET /.settings/rules.json'], 'only the cleanup after the request in flight');
        assert.ok(w.journal().some(r => r.kind === 'admin-unknown' && r.label === id));
      } finally { w.cleanup(); }
    });
  }
}

// ---- H1: an answer body cut mid-read ----
const partial = {
  rest: [['print-pretty-put', (m, u) => m === 'PUT' && u.pathname.endsWith('/r1-rest/pr.json')], ['emptied-patch', (m, u) => m === 'PATCH' && u.pathname.endsWith('/r1-rest/emptied.json')]],
  rules: [['mp-allow', (m, u) => m === 'PATCH' && u.pathname.endsWith('/r1-rules/mp.json')], ['load-ident', (() => { let seen = 0; return (m, u, init) => m === 'PUT' && u.pathname === '/.settings/rules.json' && init.body?.includes('foo == 1') && seen++ === 0; })()]],   // r1 only
};
for (const suite of ['rest', 'rules']) {
  for (const [id, match] of partial[suite]) {
    test(`${suite}: a non-GET (${id}) whose answer body is cut mid-read is unknown: the case row says so, exit 3, claims kept`, async () => {
      const w = await world(suite, (m, u, init) => (match(m, u, init) ? cut() : null), { continueOnFailure: true });
      try {
        const { exit, result } = w.outcome;
        assert.equal(exit, 3, JSON.stringify(result));
        assert.ok(result.unverified.includes(`unknown mutation outcome: ${id}`), JSON.stringify(result.unverified));
        assert.ok(result.unverified.some(u => u.includes(`r1-${suite}/${id}`)), JSON.stringify(result.unverified));
        const row = w.journal().find(r => r.kind === 'case' && r.id === id && r.profile === `r1-${suite}`);
        assert.equal(row.ok, false); assert.equal(row.outcome, 'unknown'); assert.deepEqual(row.unknown, [id]);
        claimsKept(w);
      } finally { w.cleanup(); }
    });
  }
}
test('near miss: a GET whose answer body is cut mid-read stops the profile but is not an unknown mutation', async () => {
  const w = await world('rules', (m, u) => (m === 'GET' && u.pathname.endsWith('/r1-rules/idx.json') && u.searchParams.get('limitToFirst') === '2' ? cut() : null));
  try {
    const { result } = w.outcome;
    assert.notEqual(result.status, 'complete');
    assert.equal(result.unverified.some(u => /ix-b-first/.test(u)), false, JSON.stringify(result.unverified));
    const row = w.journal().find(r => r.kind === 'case' && r.id === 'ix-b-first');
    assert.equal(row.outcome, 'unknown'); assert.equal('unknown' in row, false);
  } finally { w.cleanup(); }
});

// ---- H1: the unreadable-body rule is scoped to record-mode case answers ----
test('near miss: the cleanup DELETE (in a run) and the preflight install and restore (createAdmin) read text: a body that is not UTF-8 there is not an unknown mutation', async () => {
  for (const suite of ['rest', 'rules']) {
    const w = await world(suite, (m, u) => (m === 'DELETE' && u.pathname === `${PREFIX[suite]}.json` ? new Response(BAD, { status: 200 }) : null));
    try {
      const { exit, result } = w.outcome;
      assert.equal(exit, 0, `${suite}: ${JSON.stringify(result.unverified)}`); assert.deepEqual(result.unverified, []);
      assert.deepEqual(result.cleanup, { prefix: 'verified', rules: 'verified' });
      claimsReleased(w);
    } finally { w.cleanup(); }
  }
  const admin = createAdmin({ headers: {}, journal: { write() {} }, counter: createCounter({ direct: 4, reserve: 4 }), fetchImpl: async () => new Response(BAD, { status: 200 }) });
  for (const [label, method, extra] of [['rules-install', 'PUT', {}], ['prefix-delete', 'DELETE', { cleanup: true }], ['rules-restore', 'PUT', { cleanup: true }]]) {
    const r = await admin.rest(label, method, 'http://h/x.json', { body: '1', ...extra });
    assert.equal(r.status, 200); assert.equal(typeof r.text, 'string');
  }
  assert.deepEqual(admin.unknownMutations, [], 'text-mode answers are never unknown for their body');
  await admin.rest('case', 'PUT', 'http://h/x.json', { body: '1', record: true });
  assert.deepEqual(admin.unknownMutations, ['case'], 'the same answer to a record-mode case is');
});

// ---- H2: writeAll and a write that makes no progress, bounded ----
test('writeAll refuses a write that makes no progress at its first call (a counted fake fails after 3 calls instead of looping)', () => {
  for (const result of [0, -1, NaN, undefined]) {
    let calls = 0;
    const fake = () => { calls += 1; if (calls > 3) throw new Error('fake called too often: no progress was accepted'); return result; };
    assert.throws(() => writeAll(7, 'abc', fake), /short write made no progress/, String(result));
    assert.equal(calls, 1, `${result}: one call, then the refusal`);
  }
  let calls = 0;
  const partialWrites = (fd, buf, off, len) => { calls += 1; if (calls > 10) throw new Error('fake called too often'); return Math.min(1, len); };
  writeAll(7, 'abc', partialWrites); assert.equal(calls, 3, 'one byte per call: three calls');
});
