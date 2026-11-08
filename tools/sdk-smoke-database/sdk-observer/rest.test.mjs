// The observer's rest suite (G7, packet 2 of the RTDB closure): the case table and its request budget, the Rules, the
// masks, the per-profile runner, the admin REST extension (extra request headers, recorded response headers) and the
// wiring into run(), the approval line and the read-back.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { DROP_ORDER, FIXED_REQUEST_HEADERS, PUSH_ID, RECORDED_REQUEST_HEADERS, RECORDED_RESPONSE_HEADERS, REST_AREA, REST_CASES, REST_PROFILES, TABLE, maskText, restRules, runRestProfile } from './rest-suite.mjs';
import { CapExceeded, Unknown, checkApproval, createAdmin, createCounter, createJournal, scriptManifest, sha256, targetUrls } from './lib.mjs';
import { SUITES, expectedObservations, run } from './observer.mjs';
import { READBACK_SUITES, readback } from './readback.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PRODUCTION_PREFLIGHT = ['tokeninfo', 'instance', 'rules-before', 'prefix-before', 'rules-install', 'rules-installed'];

// ---- the case table and the budget ----
test('the case table keeps its order; the drops follow the ruled order and leave 72 requests per round', () => {
  assert.equal(new Set(TABLE.map(c => c.id)).size, TABLE.length, 'ids are unique');
  assert.equal(TABLE.length, 80);
  assert.deepEqual(DROP_ORDER, ['wsl-patch-tiny', 'print-silent-post', 'shallow-export', 'download-escaped', 'malformed-nul', 'callback-dots', 'override-get', 'end-get']);
  assert.deepEqual(REST_CASES, TABLE.map(c => c.id).filter(id => !DROP_ORDER.includes(id)));
  assert.equal(REST_CASES.length, 72);
  assert.deepEqual(REST_CASES.slice(0, 5), ['setup-mix', 'setup-ints', 'setup-leaf', 'setup-emptied', 'setup-etag']);
  assert.deepEqual(REST_CASES.slice(-3), ['emptied-export', 'malformed-zz', 'end-delete']);
  for (const c of TABLE) {
    assert.ok(['GET', 'PUT', 'PATCH', 'POST', 'DELETE'].includes(c.method), c.id);
    assert.ok(c.path === '.json' || /^\/[^?]*\.json$/.test(c.path), c.id);
    assert.ok(typeof c.query === 'string' && !c.query.startsWith('?'), c.id);
    assert.ok(Object.keys(c.headers ?? {}).every(h => RECORDED_REQUEST_HEADERS.includes(h)), c.id);
    assert.ok(c.body === undefined || typeof c.body === 'string', c.id);
  }
});
test('one production run is 150 direct requests (2 rounds x 72 + the 6 preflight requests); the recommended cap is 190', () => {
  const perRun = REST_PROFILES.length * REST_CASES.length + PRODUCTION_PREFLIGHT.length;
  assert.equal(perRun, 150);
  assert.equal(Math.ceil(Math.ceil(1.25 * perRun) / 10) * 10, 190);
  assert.ok(190 <= SUITES.rest.capMax && SUITES.rest.capMax === 250);
  assert.equal(expectedObservations('rest'), 144);
});
test('the bodies are sent as written (no re-serialization): the largest double stays in its exponent spelling', () => {
  const svo = TABLE.find(c => c.id === 'sv-overflow-put');
  assert.equal(svo.body, '{"n":{".sv":{"increment":1.7976931348623157e308}}}');
  assert.equal(TABLE.find(c => c.id === 'setup-mix').body, '{"a":{".value":3,".priority":2},"b":{".value":"x",".priority":"p"},"c":{".value":true,".priority":1},"d":{"h":1,".priority":3},"e":7,"f":"abc"}');
  assert.equal(TABLE.find(c => c.id === 'setup-ints').body, '{"-1":1,"01":2,"2147483648":3,"10":4,"2":5,"a":6,"B":7}');
  assert.equal(TABLE.find(c => c.id === 'order-key-start-end').query, 'orderBy=%22%24key%22&startAt=%2201%22&endAt=%222%22');
  assert.equal(TABLE.find(c => c.id === 'callback-script').query, 'callback=%3C%2Fscript%3E');
});
test('rest Rules: read and write under each profile scope, a .value index under mix, deny elsewhere', () => {
  const r = restRules('/sdkrest20261105');
  assert.deepEqual(r, { rules: { '.read': false, '.write': false, sdkrest20261105: { [REST_AREA]: Object.fromEntries(REST_PROFILES.map(n => [n, { '.read': true, '.write': true, mix: { '.indexOn': ['.value'] } }])) } } });
  for (const bad of ['x', '/a/__proto__', '/a b', '']) assert.throws(() => restRules(bad));
});

// ---- masks ----
test('masks: the scope becomes {scope} and a recorded push id {pushId}; nothing else changes', () => {
  const scope = 'sdkrest20261105/sdk-rest/r1-rest', id = '-OAbCdEfGhIjKlMnOpQr';
  assert.ok(PUSH_ID.test(id));
  assert.equal(maskText(`{"error":"Index not defined, add \\".indexOn\\": \\".value\\", for path \\"/${scope}/ints\\", to the rules"}`, { scope, pushIds: [] }), '{"error":"Index not defined, add \\".indexOn\\": \\".value\\", for path \\"/{scope}/ints\\", to the rules"}');
  assert.equal(maskText(`{"${id}":"hello"}`, { scope, pushIds: [id] }), '{"{pushId}":"hello"}');
  assert.equal(maskText('{"name":"short"}', { scope, pushIds: [] }), '{"name":"short"}');
  assert.equal(maskText(null, { scope, pushIds: [id] }), null);
  for (const bad of ['-OAbCdEfGhIjKlMnOpQ', '-OAbCdEfGhIjKlMnOpQrs', '-OAbCdEfGhIjKlMnOp.r']) assert.equal(PUSH_ID.test(bad), false, bad);
});

// ---- the runner, with a fake send ----
const SCOPE = 'pfx/sdk-rest/r1-rest';
const url = (rel, query) => `http://h/${rel}?ns=n${query ? `&${query}` : ''}`;
function fakeSend(answer = () => null) {
  const sent = [];
  const send = async (label, method, u, extra = {}) => {
    sent.push({ label, method, url: u, ...extra });
    const custom = answer(label, method, u, extra);
    if (custom instanceof Error) throw custom;
    if (custom) return { headers: {}, bodyBytes: Buffer.byteLength(custom.text ?? ''), utf8: true, clipped: false, ...custom };
    if (method === 'POST' && !extra.headers?.['x-http-method-override']) return { status: 200, text: '{"name":"-OAbCdEfGhIjKlMnOpQr"}', headers: { 'content-type': 'application/json; charset=utf-8' }, bodyBytes: 31, utf8: true, clipped: false };
    if (label === 'etag-get') return { status: 200, text: '{"x":1}', headers: { etag: '"abc="' }, bodyBytes: 7, utf8: true, clipped: false };
    return { status: 200, text: `{"at":"/${SCOPE}"}`, headers: {}, bodyBytes: 7 + SCOPE.length, utf8: true, clipped: false };
  };
  return { send, sent };
}
test('runner: every kept case is sent once, in order, with the fixed and selected headers; the rows are masked', async () => {
  const f = fakeSend(), emitted = [];
  const rows = await runRestProfile({ send: f.send, url, scope: SCOPE, emit: r => emitted.push(r) });
  assert.deepEqual(f.sent.map(s => s.label), REST_CASES);
  assert.equal(rows.length, 72); assert.deepEqual(emitted.map(r => r.id), REST_CASES);
  assert.ok(f.sent.every(s => s.record === true && s.headers['accept-encoding'] === FIXED_REQUEST_HEADERS['accept-encoding']));
  const get = rows.find(r => r.id === 'timeout-5s');
  assert.deepEqual(get, { kind: 'case', suite: 'rest', id: 'timeout-5s', ok: true, outcome: 'answered', method: 'GET', path: '{scope}/mix.json', query: 'timeout=5s', requestHeaders: {}, requestBody: null, status: 200, responseHeaders: {}, body: '{"at":"/{scope}"}', bodyBytes: 7 + SCOPE.length, utf8: true, clipped: false });
  const post = rows.find(r => r.id === 'post-scalar');
  assert.equal(post.body, '{"name":"{pushId}"}'); assert.equal(post.pushIdShapeOk, true); assert.equal(post.requestBody, '"hello"');
  assert.ok(f.sent.find(s => s.label === 'post-scalar').url.endsWith(`/${SCOPE}/po1.json?ns=n`));
  assert.ok(rows.every(r => r.id.startsWith('post-') && r.method === 'POST' ? 'pushIdShapeOk' in r : !('pushIdShapeOk' in r)));
});
test('runner: the if-none-match value is this side\'s own ETag of the earlier answer, recorded as {etag}; the literal bogus value is kept', async () => {
  const f = fakeSend(), rows = await runRestProfile({ send: f.send, url, scope: SCOPE });
  assert.deepEqual(f.sent.find(s => s.label === 'etag-get').headers['x-firebase-etag'], 'true');
  for (const id of ['etag-inm-match', 'etag-inm-put', 'etag-inm-shallow']) {
    assert.equal(f.sent.find(s => s.label === id).headers['if-none-match'], '"abc="', id);
    assert.deepEqual(rows.find(r => r.id === id).requestHeaders, { 'if-none-match': '{etag}' }, id);
  }
  assert.deepEqual(rows.find(r => r.id === 'etag-inm-bogus').requestHeaders, { 'if-none-match': '"bogus"' });
  assert.equal(rows.find(r => r.id === 'etag-get').responseHeaders.etag, '"abc="', 'the ETag itself is recorded unmasked');
});
test('runner: without an ETag in the earlier answer the dependent cases are blocked and sent nothing', async () => {
  const f = fakeSend(label => (label === 'etag-get' ? { status: 200, text: '{"x":1}' } : null)), rows = await runRestProfile({ send: f.send, url, scope: SCOPE });
  for (const id of ['etag-inm-match', 'etag-inm-put', 'etag-inm-shallow']) {
    assert.equal(f.sent.some(s => s.label === id), false, id);
    assert.deepEqual(rows.find(r => r.id === id), { kind: 'case', suite: 'rest', id, ok: false, outcome: 'blocked', error: 'no ETag in the answer of etag-get' });
  }
  assert.equal(rows.length, 72);
});
test('runner: a complete answer outside 2xx-4xx to a non-GET is an unknown mutation outcome (listed, the profile goes on); to a GET it is only recorded', async () => {
  const f = fakeSend(label => ({ 'print-pretty-put': { status: 503, text: 'x' }, 'etag-inm-put': { status: 304, text: '' }, 'post-null': { status: 199, text: '' }, 'timeout-5': { status: 500, text: 'e' }, 'etag-inm-match': { status: 304, text: '' } }[label] ?? null));
  const rows = await runRestProfile({ send: f.send, url, scope: SCOPE });
  assert.equal(rows.length, 72);
  for (const id of ['print-pretty-put', 'etag-inm-put', 'post-null']) { const r = rows.find(x => x.id === id); assert.equal(r.outcome, 'unknown-status', id); assert.deepEqual(r.unknown, [id]); assert.equal(r.ok, false); }
  for (const id of ['timeout-5', 'etag-inm-match']) { const r = rows.find(x => x.id === id); assert.equal(r.outcome, 'answered', id); assert.equal(r.ok, true); assert.equal('unknown' in r, false); }
});
test('runner: a transport failure stops the profile; a non-GET is listed as unknown, a GET is not; a cap refusal sent nothing and is not unknown', async () => {
  for (const [label, method, unknown] of [['post-priority', 'POST', true], ['shallow-leaf', 'GET', false]]) {
    const f = fakeSend(l => (l === label ? new Unknown(`${l}: unknown outcome`) : null)), rows = await runRestProfile({ send: f.send, url, scope: SCOPE });
    assert.equal(rows.at(-1).id, label); assert.equal(rows.at(-1).outcome, 'unknown'); assert.equal(rows.at(-1).ok, false); assert.equal(rows.at(-1).method, method);
    assert.deepEqual(rows.at(-1).unknown ?? [], unknown ? [label] : []);
    assert.equal(f.sent.at(-1).label, label, 'nothing after the failure');
  }
  const f = fakeSend(l => (l === 'sv-bogus' ? new CapExceeded('direct cap 9 reached at sv-bogus') : null)), rows = await runRestProfile({ send: f.send, url, scope: SCOPE });
  assert.equal(rows.at(-1).outcome, 'not-sent'); assert.equal('unknown' in rows.at(-1), false); assert.equal(f.sent.at(-1).label, 'sv-bogus');
});
test('runner: an overridden POST is not a push: a name in its answer is neither checked nor masked', async () => {
  const f = fakeSend(label => (label === 'override-put' ? { status: 200, text: '{"name":"-OZzZzZzZzZzZzZzZzZz"}' } : label === 'override-put-get' ? { status: 200, text: '{"name":"-OZzZzZzZzZzZzZzZzZz"}' } : null));
  const rows = await runRestProfile({ send: f.send, url, scope: SCOPE });
  for (const id of ['override-put', 'override-put-get']) { assert.equal(rows.find(x => x.id === id).body, '{"name":"-OZzZzZzZzZzZzZzZzZz"}', id); assert.equal('pushIdShapeOk' in rows.find(x => x.id === id), false, id); }
});
test('runner: an invalid scope is refused before anything is sent', async () => {
  for (const scope of ['', '/a', 'a//b', 'a/b c', 'a/../b', 42]) { const f = fakeSend(); await assert.rejects(runRestProfile({ send: f.send, url, scope }), /Invalid rest scope/, String(scope)); assert.equal(f.sent.length, 0); }
});
test('runner: a POST answer whose name is not a 20-character push id is not masked and says so', async () => {
  const f = fakeSend(label => (label === 'post-array' ? { status: 200, text: '{"name":"-short"}' } : null)), rows = await runRestProfile({ send: f.send, url, scope: SCOPE });
  const r = rows.find(x => x.id === 'post-array'); assert.equal(r.pushIdShapeOk, false); assert.equal(r.body, '{"name":"-short"}');
  const refused = rows.find(x => x.id === 'post-sv'); assert.equal(refused.pushIdShapeOk, true);
});

// ---- the admin REST extension ----
test('admin REST with record: extra request headers come from the allowlist only, response headers are filtered to the allowlist, the body keeps its byte length; the token is never journalled', async () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'rest-admin-')), file = path.join(dir, 'j.jsonl'), journal = createJournal(file), counter = createCounter({ direct: 5 }), seen = [];
  const token = `ya29.${'t'.repeat(40)}`; journal.addSecret(token);
  const fetchImpl = async (u, init) => { seen.push(init); return new Response(Buffer.from([0x7b, 0x22, 0xc3, 0xa9, 0x22, 0x3a, 0x31, 0x7d]), { status: 200, headers: { etag: '"e"', 'set-cookie': 'a=b', 'x-other': 'z', 'content-type': 'application/json; charset=utf-8', vary: 'Origin' } }); };
  const admin = createAdmin({ headers: { authorization: `Bearer ${token}`, 'x-goog-user-project': 'p' }, journal, counter, fetchImpl });
  try {
    const r = await admin.rest('c1', 'GET', 'https://ns.firebaseio.com/x.json', { record: true, headers: { 'if-none-match': '"e"', 'accept-encoding': 'identity' } });
    assert.deepEqual(r, { status: 200, text: '{"é":1}', headers: { etag: '"e"', 'content-type': 'application/json; charset=utf-8', vary: 'Origin' }, bodyBytes: 8, utf8: true, clipped: false });
    assert.equal(seen[0].headers['if-none-match'], '"e"'); assert.equal(seen[0].headers.authorization, `Bearer ${token}`); assert.equal(seen[0].redirect, 'manual');
    await assert.rejects(admin.rest('c2', 'GET', 'https://ns.firebaseio.com/x.json', { record: true, headers: { authorization: 'Bearer other' } }), /request header authorization is not recorded/);
    await assert.rejects(admin.rest('c3', 'GET', 'https://ns.firebaseio.com/x.json', { headers: { 'if-none-match': 'x' } }), /extra request headers need record/);
    assert.equal(counter.used().direct, 1, 'a refused header list sends and counts nothing');
    const plain = await admin.rest('c4', 'GET', 'https://ns.firebaseio.com/x.json');
    assert.deepEqual(plain, { status: 200, text: '{"é":1}' }, 'without record the answer is the old shape');
  } finally { journal.close(); }
  const rows = readFileSync(file, 'utf8').trim().split('\n').map(l => JSON.parse(l));
  assert.deepEqual(rows[0].headers, { 'if-none-match': '"e"', 'accept-encoding': 'identity' });
  assert.deepEqual(rows[1].headers, { etag: '"e"', 'content-type': 'application/json; charset=utf-8', vary: 'Origin' }); assert.equal(rows[1].bodyBytes, 8);
  assert.equal(rows.find(r => r.label === 'c4' && r.kind === 'admin-res').headers, undefined, 'the other suites keep their rows');
  const text = readFileSync(file, 'utf8'); assert.equal(text.includes(token), false); assert.equal(/authorization/i.test(text), false);
  rmSync(dir, { recursive: true, force: true });
  assert.deepEqual(RECORDED_RESPONSE_HEADERS, ['etag', 'content-type', 'content-length', 'content-disposition', 'cache-control', 'location', 'allow', 'www-authenticate', 'access-control-allow-origin', 'access-control-expose-headers', 'vary']);
});
test('admin REST with record: a body that is not UTF-8 is recorded as such (utf8 false), and a long body is marked clipped', async () => {
  const counter = createCounter({ direct: 5 }), journal = { write() {} };
  const answers = [Buffer.from([0xff, 0xfe, 0x41]), Buffer.alloc(70000, 0x61)];
  const admin = createAdmin({ headers: {}, journal, counter, fetchImpl: async () => new Response(answers.shift(), { status: 200 }) });
  const bad = await admin.rest('b', 'GET', 'http://h/x.json', { record: true });
  assert.equal(bad.utf8, false); assert.equal(bad.bodyBytes, 3); assert.equal(bad.text, null);
  const long = await admin.rest('l', 'GET', 'http://h/x.json', { record: true });
  assert.equal(long.clipped, true); assert.equal(long.bodyBytes, 70000);
});
test('targetUrls.raw: the case path and query on production, and the ns parameter first locally', () => {
  assert.equal(targetUrls({ kind: 'production', namespace: 'inst' }).raw('a/b/mix.json', 'print=pretty'), 'https://inst.firebaseio.com/a/b/mix.json?print=pretty');
  assert.equal(targetUrls({ kind: 'production', namespace: 'inst' }).raw('a/b.json', ''), 'https://inst.firebaseio.com/a/b.json');
  assert.equal(targetUrls({ kind: 'emulator', host: '127.0.0.1:9', namespace: 'n' }).raw('a/bad%zz.json', 'x=1'), 'http://127.0.0.1:9/a/bad%zz.json?ns=n&x=1');
  assert.equal(targetUrls({ kind: 'emulator', host: '127.0.0.1:9', namespace: 'n' }).raw('a.json', ''), 'http://127.0.0.1:9/a.json?ns=n');
});

// ---- the run ----
const BASELINE = '{\n  "rules": {\n    ".read": false,\n    ".write": false\n  }\n}\n', PREFIX = '/sdkresttest';
async function fakeDatabase() {
  const state = { rules: BASELINE, puts: [], log: [] };
  const server = createServer((req, res) => {
    let body = ''; req.on('data', c => { body += c; });
    req.on('end', () => {
      const u = new URL(req.url, 'http://x'); state.log.push({ method: req.method, path: u.pathname, search: u.search, headers: req.headers });
      if (u.pathname === '/.settings/rules.json') { if (req.method === 'PUT') { state.rules = body; state.puts.push(body); res.writeHead(200).end('{"status":"ok"}'); } else res.writeHead(200).end(state.rules); return; }
      if (u.pathname === `${PREFIX}.json`) { res.writeHead(200).end('null'); return; }
      if (req.method === 'POST' && !req.headers['x-http-method-override']) { res.writeHead(200, { 'content-type': 'application/json; charset=utf-8' }).end('{"name":"-OAbCdEfGhIjKlMnOpQr"}'); return; }
      res.writeHead(200, { 'content-type': 'application/json; charset=utf-8', ...(req.headers['x-firebase-etag'] ? { etag: '"e1"' } : {}) }).end('{}');
    });
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  return { state, host: `127.0.0.1:${server.address().port}`, close: () => { server.closeAllConnections(); server.close(); } };
}
test('run --suite rest: the rest Rules are installed and restored, 2 x 72 cases are recorded, 148 direct requests locally plus the 4 cleanup requests', async () => {
  const db = await fakeDatabase(), out = mkdtempSync(path.join(tmpdir(), 'rest-run-'));
  try {
    const { exit, result } = await run({ target: { kind: 'emulator', host: db.host, namespace: 'ns', projectId: 'demo-x' }, runId: 'TEST-REST-01', prefix: PREFIX, directCap: 190, outDir: path.join(out, 'run'), suite: 'rest' });
    assert.equal(exit, 0, JSON.stringify(result)); assert.equal(result.status, 'complete'); assert.equal(result.observed, 144); assert.equal(result.suite, 'rest'); assert.equal(result.prefix, PREFIX);
    assert.deepEqual(JSON.parse(db.state.puts[0]), restRules(PREFIX)); assert.equal(db.state.rules, BASELINE);
    assert.deepEqual(result.counts, { direct: 148, reserve: 4, adc: 0 });
    const cases = db.state.log.filter(r => r.path.startsWith(`${PREFIX}/`));
    assert.equal(cases.length, 144);
    assert.deepEqual([...new Set(cases.map(r => r.path.split('/')[3].replace(/\.json$/, '')))], REST_PROFILES);
    assert.ok(cases.every(r => r.path.startsWith(`${PREFIX}/${REST_AREA}/`)), 'every case is under <prefix>/sdk-rest/<profile>');
    assert.ok(cases.every(r => r.headers.authorization === 'Bearer owner' && r.headers['accept-encoding'] === 'identity'));
    const rows = readFileSync(path.join(out, 'run', 'journal.jsonl'), 'utf8').trim().split('\n').map(l => JSON.parse(l)).filter(r => r.kind === 'case');
    assert.equal(rows.length, 144); assert.ok(rows.every(r => r.suite === 'rest' && REST_PROFILES.includes(r.profile) && r.ok));
  } finally { db.close(); rmSync(out, { recursive: true, force: true }); }
});
test('run --suite rest: an unknown answer to a case mutation keeps the claims (exit 3) and names the case', async () => {
  const db = await fakeDatabase(), out = mkdtempSync(path.join(tmpdir(), 'rest-run-'));
  const fetchImpl = async (u, init) => (String(u).includes('/r2-rest/svb.json') ? new Response('', { status: 502 }) : fetch(u, init));
  try {
    const { exit, result } = await run({ target: { kind: 'emulator', host: db.host, namespace: 'ns', projectId: 'demo-x' }, runId: 'TEST-REST-02', prefix: PREFIX, directCap: 190, outDir: path.join(out, 'run'), suite: 'rest' }, { fetchImpl });
    assert.equal(exit, 3); assert.ok(result.unverified.includes('unknown REST mutation outcome: r2-rest/sv-bogus'), JSON.stringify(result.unverified));
  } finally { db.close(); rmSync(out, { recursive: true, force: true }); }
});
test('run --suite rest: a profile abandoned at its deadline may have REST mutations in flight: unverified, exit 3', async () => {
  const db = await fakeDatabase(), out = mkdtempSync(path.join(tmpdir(), 'rest-run-'));
  try {
    const { exit, result } = await run({ target: { kind: 'emulator', host: db.host, namespace: 'ns', projectId: 'demo-x' }, runId: 'TEST-REST-03', prefix: PREFIX, directCap: 190, outDir: path.join(out, 'run'), suite: 'rest', profileMs: 200 }, { suiteProfiles: { rest: { rest: () => new Promise(() => {}) } } });
    assert.equal(exit, 3); assert.ok(result.unverified.includes('REST mutations possibly in flight: profile r1-rest aborted'), JSON.stringify(result.unverified));
  } finally { db.close(); rmSync(out, { recursive: true, force: true }); }
});

// ---- approval, read-back, command line ----
test('approval: the rest suite needs suite=rest and basis=2217', () => {
  const line = over => `- 2026-11-05 | RTDB-SMALL-OBSERVER RTDB-REST-20261105-01 | ${Object.entries({ decision: 'APPROVE', scriptSha256: 'a'.repeat(64), directCap: '190', adc: '1', prefix: '/sdkrest20261105', suite: 'rest', basis: '2217', ...over }).map(([k, v]) => `${k}=${v}`).join('; ')} | coordinator | r.md\n`;
  const want = { runId: 'RTDB-REST-20261105-01', scriptSha256: 'a'.repeat(64), directCap: 190, prefix: '/sdkrest20261105', suite: 'rest' };
  assert.doesNotThrow(() => checkApproval(line(), want));
  assert.throws(() => checkApproval(line({ suite: 'events' }), want), /approval fields differ/);
  assert.throws(() => checkApproval(line({ basis: '2196' }), want), /approval fields differ/);
  assert.throws(() => checkApproval(line(), { ...want, suite: 'rest+events' }), /approval suite/);
});
test('read-back accepts a finished production run of the rest suite', async () => {
  assert.ok(READBACK_SUITES.includes('rest'));
  const EMAIL = 'someone@example.com', SCRIPT = scriptManifest(HERE).sha256, RUN = 'RTDB-REST-20261105-01', P = '/sdkrest20261105';
  const dir = mkdtempSync(path.join(tmpdir(), 'rest-readback-')), runDir = path.join(dir, 'run'); mkdirSync(runDir);
  writeFileSync(path.join(runDir, 'result.json'), JSON.stringify({ runId: RUN, target: 'production', suite: 'rest', scriptSha256: SCRIPT, prefix: P, status: 'unverified', exit: 3, endedAt: '2026-11-05T01:00:00.000Z', caps: { direct: 190, reserve: 12, adc: 1 } }));
  const target = { kind: 'production', projectId: 'demo-proj', projectNumber: '1', namespace: 'inst-ns', region: 'us-central1', principalSha256: sha256(EMAIL), baselineRulesSha256: sha256(BASELINE), gcloud: '/nix/store/x/gcloud' };
  const fetchImpl = async u => {
    const s = String(u);
    if (s.startsWith('https://oauth2.googleapis.com/tokeninfo')) return new Response(JSON.stringify({ scope: 'https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/cloud-platform', email: EMAIL }), { status: 200 });
    if (s.includes('/instances/')) return new Response(JSON.stringify({ type: 'USER_DATABASE', state: 'ACTIVE', name: 'projects/1/locations/us-central1/instances/inst-ns' }), { status: 200 });
    if (s.includes('/.settings/rules.json')) return new Response(BASELINE, { status: 200 });
    return new Response('null', { status: 200 });
  };
  const ledgerText = `- 2026-11-05 | RTDB-SMALL-OBSERVER ${RUN} | decision=APPROVE; scriptSha256=${SCRIPT}; directCap=190; adc=1; prefix=${P}; suite=rest; basis=2217 | coordinator | r.md\n`;
  try {
    const { exit, report } = await readback({ runDir, outDir: path.join(dir, 'out'), target, ledgerText }, { fetchImpl, mint: () => `ya29.${'x'.repeat(40)}`, now: () => Date.parse('2026-11-05T01:11:00.000Z') });
    assert.equal(exit, 0); assert.equal(report.suite, 'rest'); assert.equal(report.verdict, 'settled');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test('command line: --suite rest takes a cap of 20..250', () => {
  const observer = path.join(HERE, 'observer.mjs');
  const r = spawnSync(process.execPath, [observer, '--target', 'emulator', '--suite', 'rest', '--run-id', 'TEST-REST-9', '--prefix', '/p', '--direct-cap', '251', '--out', '/nonexistent/x'], { encoding: 'utf8', env: { PATH: process.env.PATH } });
  assert.equal(r.status, 2); assert.match(r.stderr, /--direct-cap 20\.\.250/);
  const usage = spawnSync(process.execPath, [observer, '--target', 'emulator', '--suite', 'bogus'], { encoding: 'utf8', env: { PATH: process.env.PATH } });
  assert.match(usage.stderr, /--suite small\|events\|admin\|events\+admin\|rest/);
});
test('run --suite rest: after the run is aborted no further case is sent, and the case in flight is awaited before the cleanup', async () => {
  const db = await fakeDatabase(), out = mkdtempSync(path.join(tmpdir(), 'rest-run-'));
  const fetchImpl = async (u, init) => { if (String(u).includes('/r1-rest/ints.json')) { await new Promise(r => setTimeout(r, 900)); return fetch(u, { ...init, signal: undefined }); } return fetch(u, init); };   // the second case answers after the run deadline
  try {
    const { exit, result } = await run({ target: { kind: 'emulator', host: db.host, namespace: 'ns', projectId: 'demo-x' }, runId: 'TEST-REST-04', prefix: PREFIX, directCap: 190, outDir: path.join(out, 'run'), suite: 'rest', runMs: 400, closeMs: 3000 }, { fetchImpl });
    const paths = db.state.log.map(r => `${r.method} ${r.path}`), late = paths.indexOf(`PUT ${PREFIX}/${REST_AREA}/r1-rest/ints.json`);
    assert.ok(late > 0, JSON.stringify(paths));
    assert.deepEqual(paths.slice(late + 1), [`DELETE ${PREFIX}.json`, `GET ${PREFIX}.json`, 'PUT /.settings/rules.json', 'GET /.settings/rules.json'], 'the in-flight case lands before the cleanup and nothing else is sent');
    assert.equal(paths.some(p => p.endsWith('/r1-rest/leaf.json')), false);
    assert.notEqual(exit, 0); assert.match(result.error ?? '', /run deadline/);
  } finally { db.close(); rmSync(out, { recursive: true, force: true }); }
});
test('the rest suite deadlines: 120 s per profile, 6 minutes per run, the process backstop 8 minutes (below the local entry\'s 9-minute exec timeout)', async () => {
  const { backstopMs } = await import('./observer.mjs');
  assert.deepEqual([SUITES.rest.profileMs, SUITES.rest.runMs, backstopMs('rest')], [120000, 360000, 480000]);
});

test('runner: an overridden DELETE answered with a name body is neither masked nor treated as a push', async () => {
  const f = fakeSend(label => (label === 'override-delete' ? { status: 200, text: '{"name":"-OZzZzZzZzZzZzZzZzZz"}' } : null)), rows = await runRestProfile({ send: f.send, url, scope: SCOPE });
  const r = rows.find(x => x.id === 'override-delete'); assert.equal(r.body, '{"name":"-OZzZzZzZzZzZzZzZzZz"}'); assert.equal('pushIdShapeOk' in r, false); assert.equal(r.ok, true);
});

test('runner: a clipped answer (over 64 KiB) is not ok: outcome clipped, no unknown label for a mutation whose status is a 2xx, the profile goes on', async () => {
  const f = fakeSend(label => (label === 'wsl-tiny' ? { status: 200, text: 'x'.repeat(100), clipped: true } : label === 'timeout-5s' ? { status: 200, text: 'y', clipped: true } : null));
  const rows = await runRestProfile({ send: f.send, url, scope: SCOPE });
  for (const id of ['wsl-tiny', 'timeout-5s']) { const r = rows.find(x => x.id === id); assert.equal(r.ok, false, id); assert.equal(r.outcome, 'clipped', id); assert.equal('unknown' in r, false, id); assert.equal(r.clipped, true, id); }
  assert.equal(rows.length, 72, 'the profile goes on after a clipped answer');
  assert.equal(rows.find(x => x.id === 'wsl-medium').ok, true);
});

// ---- redaction before clipping (packet 5 review, Codex Must 2) ----
test('admin REST with record: the ADC token is hidden before the body is clipped: a token crossing the 64 KiB boundary leaves no prefix of it (raw or percent-encoded)', async () => {
  const token = `ya29.${'Ab/+='.repeat(10)}`, forms = [token, encodeURIComponent(token)];
  for (const form of forms) for (const pad of [65536 - 3, 65536 - 20, 65536 - form.length, 65536 - form.length - 1, 65536 - 1]) {
    const body = `${'a'.repeat(pad)}${form}${'b'.repeat(300)}`, counter = createCounter({ direct: 5 });
    const admin = createAdmin({ headers: {}, adc: token, journal: { write() {} }, counter, fetchImpl: async () => new Response(Buffer.from(body), { status: 200 }) });
    const r = await admin.rest('c', 'GET', 'http://h/x.json?auth={adc}', { record: true, anonymous: true, resolveAdc: true });
    for (const piece of [token.slice(0, 6), encodeURIComponent(token).slice(0, 6)]) assert.equal(r.text.includes(piece), false, `pad ${pad}: ${piece}`);
    assert.equal(r.clipped, true); assert.equal(r.bodyBytes, Buffer.byteLength(body));
    assert.ok(r.text.length <= 65536, 'the clip bound holds after the replacement');
  }
});
test('journal: a secret is refused in its raw and its percent-encoded form; leaks() and redact() say and hide the same', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'journal-secret-')), journal = createJournal(path.join(dir, 'j.jsonl')), token = `ya29.${'t'.repeat(30)}/+=`;
  try {
    journal.addSecret(token);
    for (const form of [token, encodeURIComponent(token)]) { assert.throws(() => journal.write({ kind: 'x', body: `a ${form} b` }), /Secret in journal row/); assert.equal(journal.leaks(`a ${form} b`), true); assert.equal(journal.redact(`a ${form} b`).includes(form), false); }
    assert.equal(journal.leaks('nothing'), false); assert.equal(journal.redact('nothing'), 'nothing');
    assert.equal(journal.redact(`${token}${encodeURIComponent(token)}`).includes('ya29'), false);
  } finally { journal.close(); rmSync(dir, { recursive: true, force: true }); }
});
test('admin REST with record: when the token is hidden the clip bound applies to what is shown, not to the raw body', async () => {
  const token = `ya29.${'Ab/+='.repeat(10)}`;
  const body = `${token}${'x'.repeat(65536 + 20 - token.length)}`;   // raw: 65556 characters, over the bound; hidden (the placeholder has 5): 65541 minus the token's 55, under it
  const admin = createAdmin({ headers: {}, adc: token, journal: { write() {} }, counter: createCounter({ direct: 5 }), fetchImpl: async () => new Response(Buffer.from(body), { status: 200 }) });
  const r = await admin.rest('c', 'GET', 'http://h/x.json?auth={adc}', { record: true, anonymous: true, resolveAdc: true });
  assert.equal(r.text.length, 5 + 65536 + 20 - token.length); assert.ok(r.text.length < 65536); assert.equal(r.clipped, false, 'nothing was cut off'); assert.equal(r.text.startsWith('{adc}'), true);
});

// ---- packet 5 v1.2: case-insensitive percent escapes and the base64 forms (Codex r2 Must / Should) ----
const lowerEscapes = s => encodeURIComponent(s).replace(/%[0-9A-F]{2}/g, e => e.toLowerCase());
const mixedEscapes = s => { let n = 0; return encodeURIComponent(s).replace(/%[0-9A-F]{2}/g, e => (n++ % 2 ? e.toLowerCase() : e)); };
const SECRET = `ya29.A0Az/+=Tt${'k'.repeat(20)}~!*'()??>>`;   // its base64 form holds + and / (and differs from the base64url form), and it needs padding
test('journal guard (v1.2): percent escapes match in any hex case, base64 and base64url forms are secrets too; literal characters stay case-sensitive', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'journal-forms-')), journal = createJournal(path.join(dir, 'j.jsonl'));
  try {
    journal.addSecret(SECRET);
    assert.notEqual(lowerEscapes(SECRET), encodeURIComponent(SECRET)); assert.notEqual(mixedEscapes(SECRET), lowerEscapes(SECRET));
    const forms = { lower: lowerEscapes(SECRET), mixed: mixedEscapes(SECRET), upper: encodeURIComponent(SECRET), raw: SECRET, base64: Buffer.from(SECRET).toString('base64'), base64nopad: Buffer.from(SECRET).toString('base64').replace(/=+$/, ''), base64url: Buffer.from(SECRET).toString('base64url'), pctBase64: lowerEscapes(Buffer.from(SECRET).toString('base64')) };
    for (const [name, form] of Object.entries(forms)) {
      const text = `{"body":"x ${form} y"}`;
      assert.equal(journal.leaks(text), true, name); assert.throws(() => journal.write({ kind: 'x', body: form }), /Secret in journal row/, name);
      const red = journal.redact(text); assert.equal(journal.leaks(red), false, name); assert.equal(red.includes('{secret}'), true, name);
    }
    // a literal character of the token is case-sensitive: the same text with one letter's case changed is not the secret
    assert.equal(journal.leaks(SECRET.replace('Tt', 'tt')), false); assert.equal(journal.leaks(lowerEscapes(SECRET).replace('Tt', 'tt')), false);
    assert.equal(journal.leaks('%2f%2b plain'), false, 'an escape alone is not the token');
  } finally { journal.close(); rmSync(dir, { recursive: true, force: true }); }
});
test('admin REST with record (v1.2): the ADC token is hidden in any percent-escape case and in base64 forms, before the clip', async () => {
  const token = `ya29.${'Ab/+='.repeat(10)}`, b64 = Buffer.from(token).toString('base64');
  for (const form of [lowerEscapes(token), mixedEscapes(token), b64, Buffer.from(token).toString('base64url')]) for (const pad of [65536 - 7, 65536 - form.length, 65536 - form.length / 2]) {
    const body = `${'a'.repeat(Math.floor(pad))}${form}${'b'.repeat(300)}`;
    const admin = createAdmin({ headers: {}, adc: token, journal: { write() {} }, counter: createCounter({ direct: 5 }), fetchImpl: async () => new Response(Buffer.from(body), { status: 200, headers: { location: `http://h/?auth=${form}` } }) });
    const r = await admin.rest('c', 'GET', 'http://h/x.json?auth={adc}', { record: true, anonymous: true, resolveAdc: true });
    for (const piece of [token.slice(0, 6), form.slice(0, 8)]) assert.equal(r.text.includes(piece), false, `${form.slice(0, 12)} ${piece}`);
    assert.equal(JSON.stringify(r.headers).includes(form.slice(0, 8)), false, 'the location header is hidden too');
  }
});
