// The rules-syntax suite (owner 2350): one Rules document per construct, a refused document's cases recorded as not-loaded
// without a request, an accepted one probed on its own ready path before its cases, every non-200/400 load answer an unknown
// mutation that stops the profile; and the suite inside the observer run: seed, prefix cleanup, baseline restore, counts,
// approval basis 2350, the read-back.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtempSync, readFileSync, rmSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { DOCUMENTS, MAX_PROBES, RULES_SYNTAX_AREA, RULES_SYNTAX_CASES, RULES_SYNTAX_PROFILES, SEED, TABLE, readyPath, runRulesSyntaxProfile, syntaxRules } from './rules-syntax-suite.mjs';
import { CapExceeded, checkApproval, scriptManifest } from './lib.mjs';
import { SUITES, backstopMs, expectedObservations, run } from './observer.mjs';
import { READBACK_SUITES, readback } from './readback.mjs';

const BASELINE = readFileSync(new URL('../rest-observer/baseline.rules.jsonc', import.meta.url), 'utf8');
const PREFIX = '/sdkrulesyntax', SCOPE = `sdkrulesyntax/${RULES_SYNTAX_AREA}/r1-rules-syntax`;
const DENIED = '{\n  "error" : "Permission denied"\n}\n';
const CASES_OF = id => DOCUMENTS.find(d => d.id === id).cases.map(c => c[0]);
const answer = (status, text = '') => ({ status, text, bodyBytes: Buffer.byteLength(text), utf8: true, clipped: false, headers: {} });

/** A fake send: `loads` maps a document id to its load status (default 200); probes read `probe(docId, attempt)`. */
function fakeSend({ loads = {}, probe = () => 200, onCase = () => answer(200, '1') } = {}) {
  const calls = [];
  const send = async (label, method, url, options = {}) => {
    calls.push({ label, method, url, ...options });
    if (label.startsWith('load-')) return answer(loads[label.slice(5)] ?? 200, '{"status":"ok"}');
    const ready = /^ready-([a-z]+)-(\d+)$/.exec(label);
    if (ready) return answer(probe(ready[1], Number(ready[2])), 'null');
    return onCase(label, method, url, options);
  };
  return { send, calls };
}
const url = (rel, query) => `http://h/${rel}${query ? `?${query}` : ''}`;
const profile = (fake, extra = {}) => runRulesSyntaxProfile({ send: fake.send, url, scope: SCOPE, prefix: PREFIX, sleep: async () => {}, probeDelayMs: 0, ...extra });

test('the table: a seed, then each document as a load row and its cases; ids unique; every case has a refused or allowed control', () => {
  assert.equal(TABLE[0].id, 'seed');
  assert.equal(new Set(RULES_SYNTAX_CASES).size, RULES_SYNTAX_CASES.length);
  assert.deepEqual(TABLE.filter(t => t.id.startsWith('load-')).map(t => t.doc), DOCUMENTS.map(d => d.id));
  assert.deepEqual(DOCUMENTS.map(d => d.construct), ['query.endBefore', 'query.isOrderByChild()', 'OrderByKey', 'OrderByValue', 'OrderByPriority', 'http.encodeURL()', 'a method read without a call', 'a method read without a call, through a ternary', 'a call whose callee is a ternary']);
  for (const d of DOCUMENTS) assert.ok(d.cases.some(c => /deny/.test(c[0])) || d.cases.some(c => c[1] === 'PUT'), d.id);
  assert.equal(RULES_SYNTAX_CASES.length, 1 + DOCUMENTS.length + DOCUMENTS.reduce((n, d) => n + d.cases.length, 0));
  assert.equal(RULES_SYNTAX_CASES.length, 43);
});

test('each document grants nothing outside the prefix, holds its own ready path only, and the same scope Rules in both profiles', () => {
  for (const d of DOCUMENTS) {
    const doc = syntaxRules(PREFIX, d.id), area = doc.rules.sdkrulesyntax[RULES_SYNTAX_AREA];
    assert.deepEqual(Object.keys(doc.rules), ['.read', '.write', 'sdkrulesyntax']);
    assert.equal(doc.rules['.read'], false); assert.equal(doc.rules['.write'], false);
    assert.deepEqual(Object.keys(doc.rules.sdkrulesyntax), [RULES_SYNTAX_AREA]);
    assert.deepEqual(area.ready, { [d.id]: { '.read': true } });
    for (const p of RULES_SYNTAX_PROFILES) assert.deepEqual(area[p], d.scope);
    assert.ok(!JSON.stringify(d.scope).includes('"true"') && !JSON.stringify(d.scope).includes(':true'), `${d.id} grants a constant true`);
  }
  assert.throws(() => syntaxRules('/a/../b', 'eb'), /Invalid rules prefix/);
  assert.throws(() => syntaxRules('/a/__proto__', 'eb'), /Invalid rules prefix/);
  assert.throws(() => syntaxRules(PREFIX, 'zz'), /unknown rules-syntax document/);
  assert.equal(readyPath(SCOPE, 'eb'), `sdkrulesyntax/${RULES_SYNTAX_AREA}/ready/eb.json`);
});

test('property: for random prefixes the document nests the area under exactly that path and nothing else', () => {
  let seed = 7; const rand = n => { seed = (seed * 1103515245 + 12345) % 2147483648; return seed % n; };
  const chars = 'abcXYZ09_-';
  for (let i = 0; i < 300; i++) {
    const parts = Array.from({ length: 1 + rand(3) }, () => Array.from({ length: 1 + rand(6) }, () => chars[rand(chars.length)]).join(''));
    const prefix = `/${parts.join('/')}`, id = DOCUMENTS[rand(DOCUMENTS.length)].id, doc = syntaxRules(prefix, id);
    let node = doc.rules;
    for (const part of parts) { assert.deepEqual(Object.keys(node).filter(k => !k.startsWith('.')), [part]); node = node[part]; }
    assert.deepEqual(Object.keys(node), [RULES_SYNTAX_AREA]);
    assert.ok(JSON.stringify(doc).length < 4096);
  }
});

test('all documents accepted: seed, load, one probe, the cases; anonymous cases, raw document bodies, rows in table order', async () => {
  const fake = fakeSend(), rows = await profile(fake);
  assert.deepEqual(rows.map(r => r.id), RULES_SYNTAX_CASES);
  assert.ok(rows.every(r => r.ok && r.outcome === 'answered'));
  const labels = fake.calls.map(c => c.label);
  assert.equal(labels.length, RULES_SYNTAX_CASES.length + DOCUMENTS.length);
  for (const d of DOCUMENTS) assert.deepEqual(labels.slice(labels.indexOf(`load-${d.id}`), labels.indexOf(`load-${d.id}`) + 2), [`load-${d.id}`, `ready-${d.id}-1`]);
  for (const c of fake.calls) {
    if (c.label.startsWith('load-')) { assert.equal(c.body, JSON.stringify(syntaxRules(PREFIX, c.label.slice(5)))); assert.equal(c.anonymous, undefined); assert.equal(c.url, 'http://h/.settings/rules.json'); }
    else if (c.label === 'seed') { assert.equal(c.body, JSON.stringify(SEED)); assert.equal(c.anonymous, undefined); assert.equal(c.url, `http://h/${SCOPE}.json`); }
    else if (c.label.startsWith('ready-')) { assert.equal(c.anonymous, true); assert.equal(c.method, 'GET'); }
    else if (TABLE.find(t => t.id === c.label).identity === 'override') { assert.equal(c.anonymous, undefined, c.label); assert.match(c.url, /[?&]auth_variable_override=%7B%22uid%22%3A%22u1%22%7D$/); assert.equal(c.record, true); }
    else { assert.equal(c.anonymous, true, c.label); assert.equal(c.record, true); assert.doesNotMatch(c.url, /auth_variable_override/); }
  }
  const eb = fake.calls.find(c => c.label === 'eb-allow');
  assert.equal(eb.url, `http://h/${SCOPE}/eb.json?orderBy=%22%24key%22&endBefore=%22b%22&limitToLast=2`);
  assert.deepEqual(eb.headers, { 'accept-encoding': 'identity' });
  assert.deepEqual(TABLE.filter(t => t.identity === 'override').map(t => t.id), ['mnc-allow', 'mnc-write']);
  assert.equal(fake.calls.find(c => c.label === 'mnc-allow').url, `http://h/${SCOPE}/mnc/a.json?auth_variable_override=%7B%22uid%22%3A%22u1%22%7D`);
  const w = fake.calls.find(c => c.label === 'eb-write-null');
  assert.equal(w.method, 'PUT'); assert.equal(w.body, '1');
});

test('a refused document: its cases are not-loaded rows without a request, and the next document still loads', async () => {
  const fake = fakeSend({ loads: { eb: 400, obv: 400 } }), rows = await profile(fake);
  assert.deepEqual(rows.map(r => r.id), RULES_SYNTAX_CASES);
  for (const id of [...CASES_OF('eb'), ...CASES_OF('obv')]) { const r = rows.find(x => x.id === id); assert.equal(r.outcome, 'not-loaded'); assert.equal(r.ok, true); assert.ok(!fake.calls.some(c => c.label === id)); }
  assert.ok(!fake.calls.some(c => c.label.startsWith('ready-eb') || c.label.startsWith('ready-obv')));
  assert.equal(rows.find(r => r.id === 'load-eb').status, 400);
  assert.ok(fake.calls.some(c => c.label === 'ioc-allow'));
  assert.ok(fake.calls.some(c => c.label === 'obp-allow'));
});

for (const status of [500, 503, 302, 199, 403, 429, 201]) {
  test(`a load answered ${status} is an unknown mutation and stops the profile`, async () => {
    const fake = fakeSend({ loads: { ioc: status } }), rows = await profile(fake);
    const last = rows.at(-1);
    assert.equal(last.id, 'load-ioc'); assert.equal(last.ok, false); assert.equal(last.outcome, 'unknown-status'); assert.deepEqual(last.unknown, ['load-ioc']);
    assert.equal(fake.calls.at(-1).label, 'load-ioc');
  });
}

test('a load whose answer is not UTF-8 or clipped stops the profile; not UTF-8 is unknown', async () => {
  const bad = fakeSend(); const send = bad.send;
  bad.send = async (label, ...rest) => (label === 'load-obk' ? { ...answer(200, '?'), utf8: false } : send(label, ...rest));
  let rows = await profile(bad);
  assert.equal(rows.at(-1).outcome, 'unknown-body'); assert.deepEqual(rows.at(-1).unknown, ['load-obk']);
  const clip = fakeSend(); const send2 = clip.send;
  clip.send = async (label, ...rest) => (label === 'load-obk' ? { ...answer(200, '{"status":"ok"}'), clipped: true } : send2(label, ...rest));
  rows = await profile(clip);
  assert.equal(rows.at(-1).id, 'load-obk'); assert.equal(rows.at(-1).outcome, 'clipped'); assert.equal(rows.at(-1).unknown, undefined);
  assert.ok(!clip.calls.some(c => c.label.startsWith('ready-obk')));
});

test('a load that throws is unknown; a case GET that throws is not; a case PUT that throws is', async () => {
  for (const [label, unknown] of [['load-enc', ['load-enc']], ['enc-allow', undefined], ['enc-write', ['enc-write']]]) {
    const fake = fakeSend(); const send = fake.send;
    fake.send = async (l, ...rest) => { if (l === label) throw new Error('reset'); return send(l, ...rest); };
    const rows = await profile(fake);
    assert.equal(rows.at(-1).id, label); assert.equal(rows.at(-1).outcome, 'unknown'); assert.deepEqual(rows.at(-1).unknown, unknown);
  }
  const capped = fakeSend(); const send = capped.send;
  capped.send = async (l, ...rest) => { if (l === 'mnc-allow') throw new CapExceeded('cap'); return send(l, ...rest); };
  const rows = await profile(capped);
  assert.equal(rows.at(-1).outcome, 'not-sent'); assert.equal(rows.at(-1).unknown, undefined);
});

test('a case write answered 5xx is unknown and stops the profile; a 401 is an answer and the profile goes on', async () => {
  const fake = fakeSend({ onCase: label => (label === 'eb-write-null' ? answer(503, 'x') : label === 'eb-deny-value' ? answer(401, DENIED) : answer(200, '1')) });
  const rows = await profile(fake);
  assert.equal(rows.find(r => r.id === 'eb-deny-value').outcome, 'answered');
  assert.equal(rows.at(-1).id, 'eb-write-null'); assert.deepEqual(rows.at(-1).unknown, ['eb-write-null']);
});

test('the probe: retried up to MAX_PROBES, delay between attempts, a never-ready document stops the profile without an unknown', async () => {
  const sleeps = [];
  let fake = fakeSend({ probe: (doc, attempt) => (doc === 'obk' && attempt < 3 ? 401 : 200) });
  let rows = await profile(fake, { sleep: async ms => { sleeps.push(ms); }, probeDelayMs: 7 });
  assert.deepEqual(fake.calls.filter(c => c.label.startsWith('ready-obk')).map(c => c.label), ['ready-obk-1', 'ready-obk-2', 'ready-obk-3']);
  assert.deepEqual(sleeps, [7, 7]);
  assert.equal(rows.length, RULES_SYNTAX_CASES.length);
  const probe = fake.calls.find(c => c.label === 'ready-obk-1');
  assert.equal(probe.anonymous, true); assert.equal(probe.url, `http://h/sdkrulesyntax/${RULES_SYNTAX_AREA}/ready/obk.json`);
  fake = fakeSend({ probe: doc => (doc === 'obk' ? 401 : 200) });
  rows = await profile(fake);
  assert.equal(fake.calls.filter(c => c.label.startsWith('ready-obk')).length, MAX_PROBES);
  assert.deepEqual(rows.at(-1), { id: 'ready-obk', ok: false, outcome: 'not-ready' });
  assert.ok(!fake.calls.some(c => c.label === 'obk-allow-key'));
});

test('a cancelled profile sends nothing more', async () => {
  let n = 0; const fake = fakeSend();
  const rows = await profile(fake, { cancelled: () => ++n > 5 });
  assert.ok(fake.calls.length <= 5); assert.ok(rows.length < RULES_SYNTAX_CASES.length);
});

test('the scope must be the profile scope under the prefix', async () => {
  await assert.rejects(profile(fakeSend(), { scope: 'other/rules-syntax/r1-rules-syntax' }), /scope is not under the prefix/);
  await assert.rejects(profile(fakeSend(), { scope: '/bad' }), /Invalid rules scope/);
});

// ---- the suite inside the observer run ----------------------------------------------------------------------------------------------------------
/** A fake database: Rules PUTs accepted unless refused by id; ready reads 200 for the document in effect; cases echo 200. */
async function fakeDatabase({ refuse = [] } = {}) {
  const state = { rules: BASELINE, puts: [], log: [], data: null };
  const server = createServer((req, res) => {
    let body = ''; req.on('data', d => { body += d; });
    req.on('end', () => {
      const u = new URL(req.url, 'http://x'); state.log.push({ method: req.method, path: u.pathname, search: u.search, headers: req.headers, body });
      if (u.pathname === '/.settings/rules.json') {
        if (req.method === 'PUT') { const id = body === BASELINE ? null : Object.keys(JSON.parse(body).rules.sdkrulesyntax[RULES_SYNTAX_AREA].ready)[0]; state.puts.push(body); if (refuse.includes(id)) { res.writeHead(400).end('{\n  "error" : "1:1: x\\n"\n}\n'); return; } state.rules = body; res.writeHead(200).end('{"status":"ok"}'); }
        else res.writeHead(200).end(state.rules);
        return;
      }
      if (u.pathname === `${PREFIX}.json`) { if (req.method === 'DELETE') state.data = null; res.writeHead(200).end(req.method === 'DELETE' ? 'null' : JSON.stringify(state.data)); return; }
      const ready = /\/ready\/([a-z]+)\.json$/.exec(u.pathname);
      if (ready) { res.writeHead(state.rules.includes(`"ready":{"${ready[1]}"`) ? 200 : 401).end('null'); return; }
      if (req.method === 'PUT') state.data = 'written';
      res.writeHead(200, { 'content-type': 'application/json; charset=utf-8' }).end('1');
    });
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  return { state, host: `127.0.0.1:${server.address().port}`, close: () => { server.closeAllConnections(); server.close(); } };
}
const local = host => ({ kind: 'emulator', host, namespace: 'ns', projectId: 'demo-small-observer' });

test('run --suite rules-syntax: 2 x 43 rows, prefix deleted and read null, baseline Rules restored byte-equal, the counts', async () => {
  const db = await fakeDatabase(), out = mkdtempSync(path.join(tmpdir(), 'syntax-run-'));
  try {
    const { exit, result } = await run({ target: local(db.host), runId: 'TEST-SYNTAX-01', prefix: PREFIX, directCap: 160, outDir: path.join(out, 'run'), suite: 'rules-syntax', probeDelayMs: 1 });
    assert.equal(exit, 0, JSON.stringify(result)); assert.equal(result.status, 'complete'); assert.equal(result.observed, 86);
    assert.equal(expectedObservations('rules-syntax'), 86);
    assert.deepEqual(result.cleanup, { prefix: 'verified', rules: 'verified' });
    assert.equal(db.state.rules, BASELINE);
    // rules-before + prefix-before, then per profile: seed, 9 loads, 9 probes, 33 cases
    assert.deepEqual(result.counts, { direct: 2 + 2 * (1 + 9 + 9 + 33), reserve: 4, adc: 0 });
    assert.deepEqual(db.state.puts.slice(0, 9).map(b => JSON.parse(b)), DOCUMENTS.map(d => syntaxRules(PREFIX, d.id)));
    const cases = db.state.log.filter(r => r.path.startsWith(`${PREFIX}/${RULES_SYNTAX_AREA}/r`) && !r.path.includes('/ready/'));
    assert.deepEqual([...new Set(cases.map(r => r.path.split('/')[3].replace(/\.json$/, '')))], RULES_SYNTAX_PROFILES);
    const seeds = cases.filter(r => RULES_SYNTAX_PROFILES.some(p => r.path.endsWith(`${p}.json`))), overrides = cases.filter(r => r.search.includes('auth_variable_override'));
    assert.equal(seeds.length, 2); assert.equal(overrides.length, 4);
    assert.ok([...seeds, ...overrides].every(r => r.headers.authorization === 'Bearer owner'));
    assert.ok(cases.filter(r => !seeds.includes(r) && !overrides.includes(r)).every(r => r.headers.authorization === undefined && r.headers['x-goog-user-project'] === undefined));
    assert.deepEqual(db.state.log.at(-1), { ...db.state.log.at(-1), method: 'GET', path: '/.settings/rules.json' });
  } finally { db.close(); rmSync(out, { recursive: true, force: true }); }
});

test('run --suite rules-syntax with refused documents: complete, the refused cases not-loaded, nothing sent for them', async () => {
  const db = await fakeDatabase({ refuse: ['eb', 'ioc', 'obk', 'obv', 'obp', 'enc', 'mnt', 'tcl'] }), out = mkdtempSync(path.join(tmpdir(), 'syntax-run-'));
  try {
    const { exit, result } = await run({ target: local(db.host), runId: 'TEST-SYNTAX-02', prefix: PREFIX, directCap: 160, outDir: path.join(out, 'run'), suite: 'rules-syntax', probeDelayMs: 1 });
    assert.equal(exit, 0, JSON.stringify(result)); assert.equal(result.observed, 86);
    assert.equal(result.cases.filter(c => c.outcome === 'not-loaded').length, 2 * 29);
    assert.deepEqual(result.counts, { direct: 2 + 2 * (1 + 9 + 1 + 4), reserve: 4, adc: 0 });
    assert.equal(db.state.rules, BASELINE);
  } finally { db.close(); rmSync(out, { recursive: true, force: true }); }
});

test('the suite constants: cap range, deadlines above the worst probe case, the backstop, approval basis 2350 and the read-back', () => {
  const S = SUITES['rules-syntax'];
  assert.equal(S.capMax, 160); assert.equal(S.basis, '2350');
  // the slowest Rules propagation the probes allow: 9 installs x (MAX_PROBES - 1) delays of 2 s, and a minute for the 53 requests of a profile
  assert.ok(S.profileMs >= DOCUMENTS.length * (MAX_PROBES - 1) * 2000 + 60000);
  assert.ok(S.runMs >= 2 * S.profileMs + 60000);
  assert.equal(backstopMs('rules-syntax'), S.runMs + 120000);
  assert.ok(READBACK_SUITES.includes('rules-syntax'));
  const line = sha => `- 2026-11-08 | RTDB-SMALL-OBSERVER RTDB-RULES-SYNTAX-20261108-01 | decision=APPROVE; scriptSha256=${sha}; directCap=160; adc=1; prefix=${PREFIX}; suite=rules-syntax; basis=2350 | coordinator | x`;
  const want = { runId: 'RTDB-RULES-SYNTAX-20261108-01', scriptSha256: 'a'.repeat(64), directCap: 160, prefix: PREFIX, suite: 'rules-syntax', basis: '2350' };
  checkApproval(line('a'.repeat(64)), want);
  assert.throws(() => checkApproval(line('a'.repeat(64)).replace('basis=2350', 'basis=2217'), want), /approval fields differ/);
  assert.throws(() => checkApproval(line('a'.repeat(64)).replace('suite=rules-syntax', 'suite=rules'), want), /approval fields differ/);
  assert.throws(() => checkApproval(line('a'.repeat(64)), { ...want, basis: '2217' }), /approval basis/);
  checkApproval(line('a'.repeat(64)), { ...want, basis: undefined });
});

test('the production run checks the approval with basis 2350 before anything is sent', async () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'syntax-prod-'));
  try {
    const owner = path.join(dir, 'owner.md'), sha = scriptManifest(new URL('.', import.meta.url).pathname).sha256;
    writeFileSync(owner, `- 2026-11-08 | RTDB-SMALL-OBSERVER RTDB-RULES-SYNTAX-T1 | decision=APPROVE; scriptSha256=${sha}; directCap=160; adc=1; prefix=${PREFIX}; suite=rules-syntax; basis=2217 | coordinator | x\n`);
    let sent = 0;
    const target = { kind: 'production', projectId: 'p', namespace: 'n', region: 'us-central1', paths: { owner, lease: path.join(dir, 'lease'), recording: path.join(dir, 'rec') } };
    const { exit, result } = await run({ target, runId: 'RTDB-RULES-SYNTAX-T1', prefix: PREFIX, directCap: 160, outDir: path.join(dir, 'run'), suite: 'rules-syntax' }, { fetchImpl: async () => { sent++; throw new Error('no'); }, mint: () => { throw new Error('no mint'); } });
    assert.equal(exit, 2); assert.match(result.error, /approval fields differ/); assert.equal(sent, 0);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('the read-back accepts a finished rules-syntax run', async () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'syntax-rb-'));
  try {
    const runDir = path.join(dir, 'run'); mkdirSync(runDir);
    const sha = scriptManifest(new URL('.', import.meta.url).pathname).sha256;
    writeFileSync(path.join(runDir, 'result.json'), JSON.stringify({ target: 'production', suite: 'rules-syntax', runId: 'RTDB-RULES-SYNTAX-T2', prefix: PREFIX, endedAt: '2026-01-01T00:00:00Z', caps: { direct: 160 }, scriptSha256: sha }));
    const owner = `- 2026-11-08 | RTDB-SMALL-OBSERVER RTDB-RULES-SYNTAX-T2 | decision=APPROVE; scriptSha256=${sha}; directCap=160; adc=1; prefix=${PREFIX}; suite=rules-syntax; basis=2350 | coordinator | x\n`;
    await assert.rejects(readback({ runDir, outDir: path.join(dir, 'out'), target: {}, ledgerText: owner }, { now: () => Date.parse('2026-01-01T00:05:00Z') }), /ten minutes after/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
