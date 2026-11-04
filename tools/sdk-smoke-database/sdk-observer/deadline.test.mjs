// Opus presend review of packet 2 v1, Must 1 and Shoulds 1 and 3: a rest profile abandoned at its deadline stops sending, and files are written completely.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { run } from './observer.mjs';
import { runRestProfile } from './rest-suite.mjs';
import { writeAll, scriptManifest, sha256 } from './lib.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url)), SCRIPT = scriptManifest(HERE).sha256;
const BASELINE = '{\n  "rules": {\n    ".read": false,\n    ".write": false\n  }\n}\n', PREFIX = '/sdkrest20261104', RUN = 'REST-DEADLINE-01';

/** A fake database that needs `delay` ms per case request and logs every request in order. */
async function slowWorld({ delay, profileMs, closeMs = 100 }) {
  const dir = mkdtempSync(path.join(tmpdir(), 'deadline-')), log = [], state = { rules: BASELINE };
  const fetchImpl = async (url, init = {}) => {
    const u = new URL(url), method = init.method ?? 'GET'; log.push(`${method} ${u.pathname}${u.search}`);
    if (u.hostname === 'oauth2.googleapis.com') return new Response(JSON.stringify({ scope: 'https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/userinfo.email', email: 'tester@example.com' }));
    if (u.hostname === 'firebasedatabase.googleapis.com') return new Response(JSON.stringify({ name: 'projects/1/locations/r/instances/ns', type: 'USER_DATABASE', state: 'ACTIVE' }));
    if (u.pathname === '/.settings/rules.json') { if (method === 'PUT') { state.rules = init.body; return new Response('{"status":"ok"}'); } return new Response(state.rules); }
    if (u.pathname.includes('/sdk-rest/')) await new Promise(r => setTimeout(r, delay));
    if (u.pathname.endsWith('/etag.json')) return new Response('{"x":1}', { headers: { etag: '"abc="' } });
    return new Response('null');
  };
  const paths = { owner: path.join(dir, 'owner.md'), lease: path.join(dir, 'lease'), recording: path.join(dir, 'RECORDING') };
  writeFileSync(paths.owner, `- 2026-11-04 | RTDB-SMALL-OBSERVER ${RUN} | decision=APPROVE; scriptSha256=${SCRIPT}; directCap=190; adc=1; prefix=${PREFIX}; suite=rest; basis=2217 | coordinator | review.md\n`);
  const target = { kind: 'production', projectId: 'demo-prod', projectNumber: '1', region: 'r', namespace: 'ns', principalSha256: sha256('tester@example.com'), baselineRulesSha256: sha256(BASELINE), gcloud: '/x', paths };
  const outcome = await run({ target, runId: RUN, prefix: PREFIX, directCap: 190, suite: 'rest', outDir: path.join(dir, 'run'), profileMs, closeMs, continueOnFailure: true }, { fetchImpl, mint: () => `ya29.${'t'.repeat(40)}` });
  await new Promise(r => setTimeout(r, delay * 3 + 200));   // anything still running would send now
  return { dir, log, outcome, paths, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

test('a rest profile that hits its deadline stops sending: no case request after the cleanup, no profile r1 request after r2 began, exit 3, claims kept', async () => {
  const w = await slowWorld({ delay: 40, profileMs: 600 });
  try {
    const { exit, result } = w.outcome;
    assert.equal(exit, 3, JSON.stringify(result.unverified));
    assert.ok(result.unverified.some(u => /aborted|did not settle|deadline/.test(u)), JSON.stringify(result.unverified));
    const cleanup = w.log.findIndex(l => l.startsWith('DELETE ') && l.includes(PREFIX.slice(1)) && !l.includes('/sdk-rest/'));
    assert.ok(cleanup > 0, `the cleanup DELETE of the prefix is in the log: ${JSON.stringify(w.log.slice(-8))}`);
    const afterCleanup = w.log.slice(cleanup + 1).filter(l => l.includes('/sdk-rest/'));
    assert.deepEqual(afterCleanup, [], 'no case request after the cleanup DELETE');
    const firstR2 = w.log.findIndex(l => l.includes('/r2-rest/'));
    assert.equal(firstR2 === -1 ? 0 : w.log.slice(firstR2).filter(l => l.includes('/r1-rest/')).length, 0, 'no r1 request after r2 began');
    assert.equal(existsSync(w.paths.lease), true); assert.equal(existsSync(w.paths.recording), true);
  } finally { w.cleanup(); }
});
test('runRestProfile: a cancelled profile sends nothing more and records nothing for the cases it skipped', async () => {
  let n = 0, cancelled = false;
  const send = async () => { n += 1; if (n === 5) cancelled = true; return { status: 200, text: 'null', headers: {}, bodyBytes: 4, utf8: true, clipped: false }; };
  const rows = await runRestProfile({ send, url: (rel, q) => `http://h/${rel}${q ? `?${q}` : ''}`, scope: 'pfx/sdk-rest/r1-rest', cancelled: () => cancelled });
  assert.equal(n, 5, 'the fifth request was the last one sent'); assert.equal(rows.length, 5); assert.ok(rows.every(r => r.outcome === 'answered' && !('unknown' in r)));
  const none = await runRestProfile({ send: async () => { throw new Error('sent'); }, url: () => 'http://h/', scope: 'pfx/sdk-rest/r1-rest', cancelled: () => true });
  assert.deepEqual(none, []);
});
test('writeAll: writes every byte through short writes, and refuses a write that makes no progress', () => {
  const chunks = [], fake = (fd, buf, off, len) => { const n = Math.min(3, len); chunks.push(Buffer.from(buf.subarray(off, off + n))); return n; };
  writeAll(7, 'héllo wörld\n', fake); assert.equal(Buffer.concat(chunks).toString(), 'héllo wörld\n'); assert.ok(chunks.length > 4);
  assert.throws(() => writeAll(7, 'abc', () => 0), /no progress|short write/);
  assert.throws(() => writeAll(7, 'abc', () => { throw Object.assign(new Error('ENOSPC'), { code: 'ENOSPC' }); }), /ENOSPC/);
  writeAll(7, '', () => { throw new Error('nothing to write'); });
});
test('the result file, the journal and the read-back report are written completely even when the writes are short', async () => {
  const { createJournal } = await import('./lib.mjs');
  const dir = mkdtempSync(path.join(tmpdir(), 'short-write-')), file = path.join(dir, 'j.jsonl');
  try {
    const journal = createJournal(file, { write: (fd, buf, off, len) => { const n = Math.min(5, len); return fsWrite(fd, buf, off, n); } });
    for (let i = 0; i < 20; i++) journal.write({ kind: 'case', i, text: 'x'.repeat(40) });
    journal.close();
    const rows = readFileSync(file, 'utf8').split('\n').filter(Boolean).map(l => JSON.parse(l)); assert.equal(rows.length, 20); assert.equal(rows[19].i, 19);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
import { writeSync as fsWrite } from 'node:fs';

test('writeNew (result.json) and the read-back report survive short writes', async () => {
  const { writeNew } = await import('./observer.mjs'), { readback } = await import('./readback.mjs');
  const dir = mkdtempSync(path.join(tmpdir(), 'short-result-')), short = (fd, buf, off, len) => fsWrite(fd, buf, off, Math.min(7, len));
  try {
    const text = `${JSON.stringify({ a: 'x'.repeat(300), b: 'é'.repeat(50) }, null, 2)}\n`;
    writeNew(path.join(dir, 'result.json'), text, short); assert.equal(readFileSync(path.join(dir, 'result.json'), 'utf8'), text);
    assert.throws(() => writeNew(path.join(dir, 'result.json'), text, short), /EEXIST/);
    // the read-back report through the same injection
    const run = path.join(dir, 'run'); (await import('node:fs')).mkdirSync(run);
    writeFileSync(path.join(run, 'result.json'), JSON.stringify({ runId: 'RB-SHORT-01', target: 'production', suite: 'rest', scriptSha256: SCRIPT, prefix: PREFIX, status: 'unverified', exit: 3, endedAt: '2026-11-04T01:00:00.000Z', caps: { direct: 190, reserve: 12, adc: 1 } }));
    const BASE = BASELINE, ledger = `- 2026-11-04 | RTDB-SMALL-OBSERVER RB-SHORT-01 | decision=APPROVE; scriptSha256=${SCRIPT}; directCap=190; adc=1; prefix=${PREFIX}; suite=rest; basis=2217 | coordinator | x\n`;
    const fetchImpl = async url => { const u = new URL(url); if (u.hostname === 'oauth2.googleapis.com') return new Response(JSON.stringify({ scope: 'https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/userinfo.email', email: 'tester@example.com' })); if (u.hostname === 'firebasedatabase.googleapis.com') return new Response(JSON.stringify({ name: 'projects/1/locations/r/instances/ns', type: 'USER_DATABASE', state: 'ACTIVE' })); if (u.pathname === '/.settings/rules.json') return new Response(BASE); return new Response('null'); };
    const target = { kind: 'production', projectId: 'demo-prod', projectNumber: '1', region: 'r', namespace: 'ns', principalSha256: sha256('tester@example.com'), baselineRulesSha256: sha256(BASE), gcloud: '/x' };
    const out = await readback({ runDir: run, outDir: path.join(dir, 'a2'), target, ledgerText: ledger }, { fetchImpl, mint: () => `ya29.${'t'.repeat(40)}`, now: () => Date.parse('2026-11-04T01:11:00.000Z'), write: short });
    assert.deepEqual(JSON.parse(readFileSync(path.join(dir, 'a2', 'readback.json'), 'utf8')), JSON.parse(JSON.stringify(out.report)));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
