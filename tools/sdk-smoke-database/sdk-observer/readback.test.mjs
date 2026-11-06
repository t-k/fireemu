// The read-only A2 read-back (Opus presend review of packet 1 v1, Must 1): after a run left unknown outcomes the coordinator
// reads the prefix, the Rules and the instance back, at least ten minutes after the run ended. It sends no write.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { readback } from './readback.mjs';
import { scriptManifest, sha256 } from './lib.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url)), SCRIPT = scriptManifest(HERE).sha256;
const BASELINE = '{\n  "rules": {\n    ".read": false,\n    ".write": false\n  }\n}\n', RUN = 'RTDB-EVENTS-20261104-01', PREFIX = '/sdkevents20261104', EMAIL = 'someone@example.com';
const TARGET = { kind: 'production', projectId: 'demo-proj', projectNumber: '1', namespace: 'inst-ns', region: 'us-central1', principalSha256: sha256(EMAIL), baselineRulesSha256: sha256(BASELINE), gcloud: '/nix/store/x/gcloud' };
const ENDED = '2026-11-04T01:00:00.000Z', MIN = 60 * 1000;
const approval = (over = {}) => `- 2026-11-04 | RTDB-SMALL-OBSERVER ${RUN} | ${Object.entries({ decision: 'APPROVE', scriptSha256: SCRIPT, directCap: '200', adc: '1', prefix: PREFIX, suite: 'events+admin', basis: '2217', ...over }).map(([k, v]) => `${k}=${v}`).join('; ')} | coordinator | review.md\n`;
const INSTANCE = { type: 'USER_DATABASE', state: 'ACTIVE', name: 'projects/1/locations/us-central1/instances/inst-ns' };
function world({ result = {}, prefixBody = 'null', prefixStatus = 200, rules = BASELINE, instance = INSTANCE, failOn = null, tokenEmail = EMAIL } = {}) {
  const dir = mkdtempSync(path.join(tmpdir(), 'readback-')), runDir = path.join(dir, 'run'), seen = [];
  mkdirSync(runDir);
  writeFileSync(path.join(runDir, 'result.json'), JSON.stringify({ runId: RUN, target: 'production', suite: 'events+admin', scriptSha256: SCRIPT, prefix: PREFIX, status: 'unverified', exit: 3, endedAt: ENDED, caps: { direct: 200, reserve: 12, adc: 1 }, ...result }));
  const fetchImpl = async (url, init = {}) => {
    const u = String(url); seen.push({ method: init.method ?? 'GET', url: u });
    if (failOn && u.includes(failOn)) throw new Error('network');
    if (u.startsWith('https://oauth2.googleapis.com/tokeninfo')) return new Response(JSON.stringify({ scope: 'https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/cloud-platform', email: tokenEmail }), { status: 200 });
    if (u.includes('/instances/')) return new Response(JSON.stringify(instance), { status: 200 });
    if (u.includes('/.settings/rules.json')) return new Response(rules, { status: 200 });
    if (u.includes(`${PREFIX.slice(1)}.json`)) return new Response(prefixBody, { status: prefixStatus });
    return new Response('{}', { status: 404 });
  };
  const at = ms => () => Date.parse(ENDED) + ms;
  return { dir, runDir, outDir: path.join(dir, 'out'), seen, fetchImpl, at, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}
const read = (w, over = {}, ms = 11 * MIN, ledgerText = approval()) => readback({ runDir: w.runDir, outDir: w.outDir, target: TARGET, ledgerText, ...over }, { fetchImpl: w.fetchImpl, mint: () => `ya29.${'x'.repeat(40)}`, now: w.at(ms) });

test('read-back: eleven minutes after the run, prefix null, Rules at baseline, instance ACTIVE -> settled, exit 0; three GETs and the tokeninfo POST, nothing else', async () => {
  const w = world();
  try {
    const out = await read(w);
    assert.equal(out.exit, 0); assert.equal(out.report.verdict, 'settled'); assert.deepEqual(out.report.checks, { prefix: 'null', rules: 'baseline', instance: 'ACTIVE' });
    assert.deepEqual(w.seen.map(r => r.method), ['POST', 'GET', 'GET', 'GET']); assert.ok(w.seen[0].url.startsWith('https://oauth2.googleapis.com/tokeninfo'));
    assert.deepEqual(out.report.counts, { direct: 4, reserve: 0, adc: 1 });
    const saved = JSON.parse(readFileSync(path.join(w.outDir, 'readback.json'), 'utf8')); assert.equal(saved.runId, RUN); assert.equal(saved.verdict, 'settled'); assert.equal(saved.endedAt, ENDED);
    assert.ok(existsSync(path.join(w.outDir, 'journal.jsonl')));
    assert.equal(readFileSync(path.join(w.outDir, 'journal.jsonl'), 'utf8').includes('ya29.'), false, 'the token is never journalled');
  } finally { w.cleanup(); }
});
test('read-back: refused before ten minutes after the run ended; nothing is sent and nothing is written', async () => {
  const w = world();
  try {
    for (const ms of [0, 5 * MIN, 10 * MIN - 1, -MIN]) await assert.rejects(read(w, {}, ms), /ten minutes/);
    assert.deepEqual(w.seen, []); assert.equal(existsSync(w.outDir), false);
    assert.equal((await read(w, {}, 10 * MIN)).exit, 0, 'exactly ten minutes is allowed');
  } finally { w.cleanup(); }
});
test('read-back: refused without the approval line, with a changed field, with a revoked line, and when the run is not the approved script', async () => {
  const w = world();
  try {
    await assert.rejects(read(w, {}, 11 * MIN, ''), /approval lines/);
    for (const over of [{ directCap: '201' }, { prefix: '/other' }, { suite: 'events' }, { scriptSha256: 'f'.repeat(64) }]) await assert.rejects(read(w, {}, 11 * MIN, approval(over)), /approval fields differ/, JSON.stringify(over));
    await assert.rejects(read(w, {}, 11 * MIN, `${approval()}- 2026-11-04 | REVOKED RTDB-SMALL-OBSERVER ${RUN} | envelopeId=${RUN}; consumed | coordinator | x\n`), /revoked/);
    assert.deepEqual(w.seen, []);
  } finally { w.cleanup(); }
  const other = world({ result: { scriptSha256: 'e'.repeat(64) } });
  try { await assert.rejects(read(other), /script/); assert.deepEqual(other.seen, []); } finally { other.cleanup(); }
});
test('read-back: refuses a run directory that is not a finished production run of these suites', async () => {
  for (const result of [{ target: 'emulator' }, { suite: 'small' }, { endedAt: undefined }, { endedAt: 'soon' }, { runId: 'bad id' }, { prefix: undefined }, { caps: undefined }]) {
    const w = world({ result });
    try { await assert.rejects(read(w), /run directory|result/, JSON.stringify(result)); assert.deepEqual(w.seen, []); } finally { w.cleanup(); }
  }
});
test('read-back: data left under the prefix, Rules that differ from the baseline, or an instance that is not ACTIVE give exit 1 and name the finding', async () => {
  for (const [world_, key, value] of [[{ prefixBody: '{"a":1}' }, 'prefix', 'data'], [{ rules: BASELINE.replace('false', 'true') }, 'rules', 'differs'], [{ instance: { ...INSTANCE, state: 'DISABLED' } }, 'instance', 'not-active'], [{ instance: { ...INSTANCE, name: 'projects/1/locations/us-central1/instances/other' } }, 'instance', 'not-active']]) {
    const w = world(world_);
    try { const out = await read(w); assert.equal(out.exit, 1, key); assert.equal(out.report.checks[key], value); assert.equal(out.report.verdict, 'not-settled'); } finally { w.cleanup(); }
  }
});
test('read-back: a read that fails or answers outside 200 is unknown (exit 3), never settled', async () => {
  for (const world_ of [{ failOn: '.settings/rules.json' }, { failOn: `${PREFIX.slice(1)}.json` }, { failOn: '/instances/' }, { prefixStatus: 500, prefixBody: 'oops' }, { prefixStatus: 404 }]) {
    const w = world(world_);
    try { const out = await read(w); assert.equal(out.exit, 3, JSON.stringify(world_)); assert.equal(out.report.verdict, 'unknown'); assert.ok(Object.values(out.report.checks).includes('unknown')); } finally { w.cleanup(); }
  }
});
test('read-back: a token of another principal or without the scopes stops it before any read', async () => {
  const w = world({ tokenEmail: 'intruder@example.com' });
  try { await assert.rejects(read(w), /adc-principal/); assert.deepEqual(w.seen.map(r => r.method), ['POST']); } finally { w.cleanup(); }
});
test('read-back: it cannot write: the admin wrapper refuses any method but GET', async () => {
  const { readOnlyAdmin } = await import('./readback.mjs');
  const calls = []; const admin = readOnlyAdmin({ rest: async (...args) => { calls.push(args); return { status: 200, text: 'null' }; } });
  await admin.rest('prefix', 'GET', 'https://x'); assert.equal(calls.length, 1);
  for (const method of ['PUT', 'POST', 'PATCH', 'DELETE', 'get']) await assert.rejects(admin.rest('x', method, 'https://x'), /read-only/);
  assert.equal(calls.length, 1);
});
