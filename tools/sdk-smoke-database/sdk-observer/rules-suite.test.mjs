// The observer's rules suite (G8, packet 3 of the RTDB closure): the case table and its request budget, the global
// Rules document, the load documents, the per-profile runner (identities, the ready probe, the reinstall after an
// accepted load document, unknown answers, cancellation) and the anonymous request of the admin REST.
import test from 'node:test';
import assert from 'node:assert/strict';

import {
  GROUPS, IDENTITIES, LOAD_CASES, MAX_PROBES, OVERRIDE_PARAM, RULES_AREA, RULES_CASES, RULES_PROFILES, TABLE,
  globalRules, readyPath, runRulesProfile,
} from './rules-suite.mjs';
import { CapExceeded, Unknown, createAdmin, createCounter } from './lib.mjs';

const PREFIX = '/sdkrules20261105', SCOPE = 'sdkrules20261105/sdk-rules/r1-rules';
const url = (rel, query) => `http://h/${rel}?ns=n${query ? `&${query}` : ''}`;
const INSTALL = JSON.stringify(globalRules(PREFIX));
const ok = (text = 'null', extra = {}) => ({ status: 200, text, headers: {}, bodyBytes: Buffer.byteLength(text), utf8: true, clipped: false, ...extra });

/** A fake send: every request is logged; `answer(label, method, url, extra)` may return an answer, an Error to throw, or null for the default. */
function fakeSend(answer = () => null) {
  const sent = [];
  const send = async (label, method, u, extra = {}) => {
    sent.push({ label, method, url: u, ...extra });
    const custom = answer(label, method, u, extra);
    if (custom instanceof Error) throw custom;
    if (custom) return { headers: {}, bodyBytes: Buffer.byteLength(custom.text ?? ''), utf8: true, clipped: false, ...custom };
    if (method === 'PUT' && u.includes('/.settings/rules.json')) return ok('{\n  "error" : "1:2: bad"\n}\n', { status: label.startsWith('install-') ? 200 : 400 });
    if (label === 'cw-etag') return ok('{"v":1}', { headers: { etag: '"abc="' } });
    return ok(`{"at":"/${SCOPE}"}`);
  };
  return { send, sent };
}
const runner = (f, over = {}) => runRulesProfile({ send: f.send, url, scope: SCOPE, installBody: INSTALL, sleep: async () => {}, ...over });
const caseLabels = sent => sent.map(s => s.label).filter(l => !l.startsWith('ready-') && !l.startsWith('install-'));

// ---- the case table and the budget ----
test('the case table: unique ids, every group and identity used, the load cases last, at most 4 neighbour GETs', () => {
  assert.equal(new Set(TABLE.map(c => c.id)).size, TABLE.length);
  assert.deepEqual(RULES_CASES, TABLE.map(c => c.id));
  assert.deepEqual([...new Set(TABLE.map(c => c.group))].sort(), [...GROUPS].sort());
  assert.deepEqual([...new Set(TABLE.map(c => c.identity))].sort(), [...IDENTITIES].sort());
  assert.equal(TABLE[0].id, 'seed'); assert.equal(TABLE[0].identity, 'admin'); assert.equal(TABLE[0].method, 'PUT'); assert.equal(TABLE[0].path, '.json');
  const firstLoad = TABLE.findIndex(c => c.group === 'load');
  assert.ok(TABLE.slice(firstLoad).every(c => c.group === 'load'), 'the load documents come last');
  assert.equal(LOAD_CASES.length, 14); assert.deepEqual(LOAD_CASES, TABLE.filter(c => c.group === 'load').map(c => c.id));
  const neighbours = TABLE.filter(c => c.group === 'neighbour');
  assert.ok(neighbours.length <= 4 && neighbours.every(c => c.method === 'GET' && c.identity === 'admin'));
  for (const c of TABLE) {
    assert.ok(['GET', 'PUT', 'PATCH', 'DELETE'].includes(c.method), c.id);
    assert.ok(typeof c.query === 'string' && !c.query.startsWith('?'), c.id);
    assert.ok(c.body === undefined || typeof c.body === 'string', c.id);
    if (c.group === 'load') { assert.equal(c.path, '/.settings/rules.json', c.id); assert.equal(c.method, 'PUT', c.id); assert.equal(c.identity, 'admin', c.id); }
    else assert.ok(c.path === '.json' || /^\/[^?]*\.json$/.test(c.path), c.id);
    assert.equal(c.query.includes(OVERRIDE_PARAM), c.identity === 'override', `${c.id}: the override parameter is the override identity`);
  }
});
test('an override case carries its auth object as compact JSON in auth_variable_override, after the other parameters', () => {
  const admin = TABLE.find(c => c.id === 'tok-admin-allow');
  assert.equal(admin.query, `auth_variable_override=${encodeURIComponent('{"uid":"u1","token":{"admin":true}}')}`);
  const notObject = TABLE.find(c => c.id === 'tok-not-object');
  assert.equal(new URLSearchParams(notObject.query).get('auth_variable_override'), '{"uid":"u1","token":"x"}');
  for (const c of TABLE.filter(x => x.identity === 'override')) {
    const params = [...new URLSearchParams(c.query).keys()];
    assert.equal(params.at(-1), 'auth_variable_override', c.id);
    assert.doesNotThrow(() => JSON.parse(new URLSearchParams(c.query).get('auth_variable_override')), c.id);
  }
});
test('one round is 79 requests with one probe per install (77 cases + the start probe + 4 reinstalls and their probes, minus nothing); one run 164; the recommended cap 210', () => {
  const validLoads = TABLE.filter(c => c.expectValid).length;
  assert.equal(validLoads, 4);
  const perRound = RULES_CASES.length + 1 + 2 * validLoads;
  assert.equal(RULES_CASES.length, 70);
  assert.equal(perRound, 79);
  const perRun = RULES_PROFILES.length * perRound + 6;
  assert.equal(perRun, 164);
  assert.equal(Math.ceil(Math.ceil(1.25 * perRun) / 10) * 10, 210);
  assert.equal(MAX_PROBES, 20);   // the coordinator's ruling: 20 probes, 2 s apart (a slow Rules propagation must not end the run incomplete)
});

// ---- the Rules ----
test('global Rules: root denied, the ready path readable, both profile scopes with every case path, the prefix checked', () => {
  const doc = globalRules(PREFIX), area = doc.rules.sdkrules20261105[RULES_AREA];
  assert.equal(doc.rules['.read'], false); assert.equal(doc.rules['.write'], false);
  assert.deepEqual(Object.keys(doc.rules), ['.read', '.write', 'sdkrules20261105']);
  assert.deepEqual(area.ready, { '.read': true });
  assert.deepEqual(Object.keys(area), ['ready', ...RULES_PROFILES]);
  for (const p of RULES_PROFILES) {
    assert.equal(area[p]['.read'], undefined, 'no grant at the scope itself'); assert.equal(area[p]['.write'], undefined);
    assert.match(area[p].rc.ok['.write'], new RegExp(`root\\.child\\('sdkrules20261105/sdk-rules/${p}/rc/flag'\\)`), 'root.child names the profile scope');
  }
  for (const bad of ['x', '/a/__proto__', '/a b', '', '/a//b', 7]) assert.throws(() => globalRules(bad), /Invalid rules prefix/);
  assert.equal(readyPath(SCOPE), 'sdkrules20261105/sdk-rules/ready.json');
});
test('no grant in the global document reaches beyond the profile scopes: every true or expression rule is below <prefix>/sdk-rules', () => {
  const doc = globalRules(PREFIX);
  const walk = (node, at) => { for (const [k, v] of Object.entries(node)) { if (k === '.read' || k === '.write') { if (v !== false) assert.ok(at.startsWith('sdkrules20261105/sdk-rules/'), `${at}/${k}`); } else if (v && typeof v === 'object') walk(v, at ? `${at}/${k}` : k); } };
  walk(doc.rules, '');
});
test('every load document is safe if production accepts it: no true grant, the root write false or absent, no prefix in it', () => {
  for (const c of TABLE.filter(x => x.group === 'load')) {
    const doc = JSON.parse(c.body);
    assert.deepEqual(Object.keys(doc), ['rules'], c.id);
    assert.equal(c.body.includes('sdkrules'), false, `${c.id}: no prefix, so its error columns do not depend on it`);
    const grants = []; const walk = n => { for (const [k, v] of Object.entries(n)) { if ((k === '.read' || k === '.write') && v === true) grants.push(k); else if (v && typeof v === 'object') walk(v); } };
    walk(doc.rules); assert.deepEqual(grants, [], c.id);
    assert.ok(doc.rules['.write'] === undefined || doc.rules['.write'] === false, c.id);
    if (c.expectValid) assert.equal(doc.rules['.write'], false, `${c.id}: an expected-valid document denies writes at the root`);
  }
});
test('the global document is pinned: a changed expression, index or path changes this digest (case code of the production run)', async () => {
  const { createHash } = await import('node:crypto');
  assert.equal(createHash('sha256').update(JSON.stringify(globalRules('/p'))).digest('hex'), 'f418ff83a63148f7ad345c973c7df1cb297e2afe561270b0ec92ee3682ef3595');
});
test('the concatenation rules compare with the official emulator\'s text and use no exponent literal', () => {
  const cc = globalRules(PREFIX).rules.sdkrules20261105[RULES_AREA]['r1-rules'].cc;
  assert.deepEqual(Object.fromEntries(Object.entries(cc).map(([k, v]) => [k, v['.read']])), { d15: "'a' + 1.5 == 'a1.5'", d1e7: "'a' + 10000000.0 == 'a10000000'", d100: "'a' + 100.0 == 'a100'", dlong: "'a' + 12345678901 == 'a12345678901'", dsmall: "'a' + 0.0001 == 'a1.0E-4'" });
  const expressions = []; const walk = n => { for (const [k, v] of Object.entries(n)) { if (typeof v === 'string' && k.startsWith('.')) expressions.push(v); else if (v && typeof v === 'object') walk(v); } };
  walk(globalRules(PREFIX).rules);
  assert.ok(expressions.length > 40);
  assert.deepEqual(expressions.filter(e => /\de[-+]?\d/i.test(e.replace(/'[^']*'/g, "''"))), [], 'no exponent literal in an expression of the global document');
});
test('the lexing documents carry the exact characters (U+FEFF as whitespace, U+0085 in a name, a trailing lazy +?, an exponent)', () => {
  const body = id => TABLE.find(c => c.id === id).body;
  assert.ok(body('lex-feff').includes('false﻿||﻿false'));
  assert.ok(body('lex-nel').includes('"a\u0085b"'));
  assert.ok(body('lex-lazy').includes('/a+?/'));
  assert.ok(body('lex-number').includes('1e3'));
  assert.ok(Buffer.byteLength(body('load-long')) > 3000);
});

// ---- the runner ----
test('runner: the start probe, then every case once in order; admin and override cases carry the credential, anonymous ones ask for none', async () => {
  const f = fakeSend(), emitted = [];
  const rows = await runner(f, { emit: r => emitted.push(r) });
  assert.equal(f.sent[0].label, 'ready-start-1'); assert.equal(f.sent[0].anonymous, true); assert.equal(f.sent[0].method, 'GET');
  assert.ok(f.sent[0].url.startsWith('http://h/sdkrules20261105/sdk-rules/ready.json'));
  assert.deepEqual(caseLabels(f.sent), RULES_CASES);
  assert.deepEqual(rows.map(r => r.id), RULES_CASES);
  for (const c of TABLE) {
    const s = f.sent.find(x => x.label === c.id);
    assert.equal(s.anonymous === true, c.identity === 'anonymous', c.id);
    assert.equal(s.record, true, c.id); assert.equal(s.headers['accept-encoding'], 'identity', c.id);
    assert.equal(s.method, c.method, c.id);
    assert.equal(s.body, c.body, c.id);
  }
  assert.ok(emitted.some(r => r.kind === 'probe' && r.after === 'start' && r.ready === true));
  const row = rows.find(r => r.id === 'ix-a');
  assert.deepEqual(row, { kind: 'case', suite: 'rules', id: 'ix-a', group: 'index', identity: 'admin', ok: true, outcome: 'answered', method: 'GET', path: '{scope}/idx.json', query: TABLE.find(c => c.id === 'ix-a').query, requestHeaders: {}, requestBody: null, status: 200, responseHeaders: {}, body: '{"at":"/{scope}"}', bodyBytes: 10 + SCOPE.length, utf8: true, clipped: false });
  const load = rows.find(r => r.id === 'load-paren');
  assert.equal(load.path, '/.settings/rules.json'); assert.equal(f.sent.find(s => s.label === 'load-paren').url, url('.settings/rules.json', ''));
});
test('runner: an accepted load document (200) is followed by the global reinstall and a probe; a refused one (400) is not', async () => {
  const f = fakeSend(label => (label === 'load-ident' ? { status: 200, text: '{"status":"ok"}' } : null)), emitted = [];
  await runner(f, { emit: r => emitted.push(r) });
  const labels = f.sent.map(s => s.label);
  const at = labels.indexOf('load-ident');
  assert.deepEqual(labels.slice(at + 1, at + 3), ['install-load-ident', 'ready-load-ident-1']);
  assert.equal(f.sent[at + 1].body, INSTALL); assert.equal(f.sent[at + 1].method, 'PUT'); assert.notEqual(f.sent[at + 1].anonymous, true);
  assert.equal(labels.includes('install-load-paren'), false, 'a refused document leaves the previous Rules: nothing to reinstall');
  const installs = emitted.filter(r => r.kind === 'install').map(r => r.after);
  assert.deepEqual(installs, ['load-ident']);
});
test('runner: the ready probe is repeated (with the delay) until 200, at most 20 times; never ready stops the profile', async () => {
  let n = 0; const sleeps = [];
  const f = fakeSend(label => (label.startsWith('ready-start-') ? (++n < 3 ? { status: 401, text: '{\n  "error" : "Permission denied"\n}\n' } : null) : null));
  const rows = await runner(f, { sleep: async ms => { sleeps.push(ms); } });   // the default delay is the production one
  assert.deepEqual(f.sent.slice(0, 3).map(s => s.label), ['ready-start-1', 'ready-start-2', 'ready-start-3']);
  assert.deepEqual(sleeps.slice(0, 2), [2000, 2000]);
  assert.equal(rows.length, RULES_CASES.length);
  const never = fakeSend(label => (label.startsWith('ready-') ? { status: 401, text: 'x' } : null)), emitted = [];
  const stopped = await runner(never, { emit: r => emitted.push(r) });
  assert.equal(never.sent.length, MAX_PROBES, 'nothing but the probes is sent');
  assert.deepEqual(stopped, [{ id: 'ready-start', ok: false, outcome: 'not-ready' }]);
  assert.equal(emitted.filter(r => r.kind === 'probe').length, MAX_PROBES);
});
test('runner: a probe that is never ready after a reinstall stops the profile there', async () => {
  const f = fakeSend(label => (label === 'lex-feff' ? { status: 200, text: '{"status":"ok"}' } : label.startsWith('ready-lex-feff') ? { status: 401, text: 'x' } : null));
  const rows = await runner(f);
  assert.deepEqual(rows.at(-1), { id: 'ready-lex-feff', ok: false, outcome: 'not-ready' });
  assert.equal(f.sent.at(-1).label, `ready-lex-feff-${MAX_PROBES}`);
});
test('runner: a reinstall that is not answered 200 stops the profile; a 5xx, an unreadable body or no answer is an unknown mutation, a 4xx is not', async () => {
  for (const [answer, unknown] of [[{ status: 500, text: 'e' }, true], [{ status: 200, text: null, utf8: false }, true], [{ status: 400, text: 'x' }, false], [new Unknown('install-lex-nel: unknown outcome'), true]]) {
    const f = fakeSend(label => (label === 'lex-nel' ? { status: 200, text: '{"status":"ok"}' } : label === 'install-lex-nel' ? answer : null)), emitted = [];
    const rows = await runner(f, { emit: r => emitted.push(r) });
    assert.equal(f.sent.at(-1).label, 'install-lex-nel');
    assert.deepEqual(rows.at(-1), { id: 'install-lex-nel', ok: false, outcome: 'install-failed', ...(unknown ? { unknown: ['install-lex-nel'] } : {}) });
    assert.equal(emitted.find(r => r.kind === 'install').ok, false);
  }
});
test('runner: a complete answer outside 2xx-4xx to a non-GET (case or load) is an unknown mutation; a load case that is unknown stops the profile', async () => {
  const f = fakeSend(label => ({ 'wv-allow': { status: 503, text: 'x' }, 'pn-allow': { status: 304, text: '' }, 'ix-a': { status: 500, text: 'e' } }[label] ?? null));
  const rows = await runner(f);
  for (const id of ['wv-allow', 'pn-allow']) { const r = rows.find(x => x.id === id); assert.equal(r.outcome, 'unknown-status', id); assert.deepEqual(r.unknown, [id]); assert.equal(r.ok, false); }
  assert.equal(rows.find(x => x.id === 'ix-a').outcome, 'answered');
  assert.equal(rows.length, RULES_CASES.length, 'a case mutation with an unknown answer does not stop the profile');
  const g = fakeSend(label => (label === 'load-token' ? { status: 502, text: '' } : null)), loadRows = await runner(g);
  assert.equal(loadRows.at(-1).id, 'load-token'); assert.equal(loadRows.at(-1).outcome, 'unknown-status'); assert.deepEqual(loadRows.at(-1).unknown, ['load-token']);
  assert.equal(g.sent.at(-1).label, 'load-token', 'the Rules in effect are unknown: nothing more is sent');
});
test('runner: a body that is not UTF-8 to a non-GET is unknown-body; to a GET it is only recorded', async () => {
  const f = fakeSend(label => (label === 'rc-allow' ? { status: 200, text: null, utf8: false, bodyBytes: 2 } : label === 'q-start' ? { status: 200, text: null, utf8: false, bodyBytes: 2 } : null));
  const rows = await runner(f);
  const w = rows.find(r => r.id === 'rc-allow'); assert.equal(w.outcome, 'unknown-body'); assert.deepEqual(w.unknown, ['rc-allow']);
  const g = rows.find(r => r.id === 'q-start'); assert.equal(g.outcome, 'answered'); assert.equal(g.utf8, false);
});
test('runner: a transport failure stops the profile (a non-GET is unknown, a GET is not); a cap refusal sent nothing and is not unknown', async () => {
  for (const [label, unknown] of [['mp-allow', true], ['ix-b-first', false], ['ready-start-1', false], ['ready-lex-number-1', false]]) {
    const f = fakeSend(l => (l === label ? new Unknown(`${l}: unknown outcome`) : l === 'lex-number' ? { status: 200, text: '{"status":"ok"}' } : null)), rows = await runner(f);
    assert.equal(f.sent.at(-1).label, label);
    assert.equal(rows.at(-1).ok, false); assert.deepEqual(rows.at(-1).unknown ?? [], unknown ? [label] : []);
  }
  const f = fakeSend(l => (l === 'cc-d15' ? new CapExceeded('direct cap reached') : null)), rows = await runner(f);
  assert.equal(rows.at(-1).outcome, 'not-sent'); assert.equal('unknown' in rows.at(-1), false);
});
test('runner: the if-match value is this side\'s own ETag of cw-etag, recorded as {etag}; without an ETag the case is blocked', async () => {
  const f = fakeSend(), rows = await runner(f);
  assert.equal(f.sent.find(s => s.label === 'cw-ifmatch').headers['if-match'], '"abc="');
  assert.deepEqual(rows.find(r => r.id === 'cw-ifmatch').requestHeaders, { 'if-match': '{etag}' });
  assert.equal(f.sent.find(s => s.label === 'cw-etag').headers['x-firebase-etag'], 'true');
  const g = fakeSend(label => (label === 'cw-etag' ? { status: 200, text: '{"v":1}' } : null)), blocked = await runner(g);
  assert.deepEqual(blocked.find(r => r.id === 'cw-ifmatch'), { kind: 'case', suite: 'rules', id: 'cw-ifmatch', group: 'conditional', identity: 'anonymous', ok: false, outcome: 'blocked', error: 'no ETag in the answer of cw-etag' });
  assert.equal(g.sent.some(s => s.label === 'cw-ifmatch'), false);
});
test('runner: cancellation is checked before every request, the probes and reinstalls included', async () => {
  for (const stopAt of [1, 2, 10, 60, 63]) {
    let n = 0, cancelled = false;
    const f = fakeSend(label => { n += 1; if (n === stopAt) cancelled = true; return label === 'lex-lazy' ? { status: 200, text: '{"status":"ok"}' } : null; });
    await runner(f, { cancelled: () => cancelled });
    assert.equal(f.sent.length, stopAt, `stop after request ${stopAt}`);
  }
  const lazy = RULES_CASES.indexOf('lex-lazy') + 2;   // the start probe, then one request per case: lex-lazy is request `lazy`
  for (const stopAt of [lazy, lazy + 1]) {
    let n = 0, cancelled = false;
    const f = fakeSend(label => { n += 1; if (n === stopAt) cancelled = true; return label === 'lex-lazy' ? { status: 200, text: '{"status":"ok"}' } : null; });
    const rows = await runner(f, { cancelled: () => cancelled });
    assert.equal(f.sent.length, stopAt, `a cancel after request ${stopAt} (the accepted document, then its reinstall) sends nothing more`);
    assert.equal(rows.at(-1).id, 'lex-lazy', 'and writes no stop row');
  }
  let cancelled = false; const f = fakeSend(label => (label.startsWith('ready-') ? { status: 401, text: 'x' } : null));
  const rows = await runner(f, { cancelled: () => cancelled, sleep: async () => { cancelled = true; } });
  assert.equal(f.sent.length, 1, 'a cancel during the probe delay sends no further probe');
  assert.deepEqual(rows, [], 'a cancelled probe is not a not-ready stop row');
});
test('runner: an invalid scope or install body is refused before anything is sent', async () => {
  for (const scope of ['', '/a', 'a//b', 'a/b c', 'a', 42]) { const f = fakeSend(); await assert.rejects(runRulesProfile({ send: f.send, url, scope, installBody: INSTALL }), /Invalid rules scope/, String(scope)); assert.equal(f.sent.length, 0); }
  const f = fakeSend(); await assert.rejects(runRulesProfile({ send: f.send, url, scope: SCOPE, installBody: '' }), /install body/); assert.equal(f.sent.length, 0);
});

// ---- the anonymous request of the admin REST ----
test('createAdmin: an anonymous record request sends no Authorization and no user-project header, is journalled as anonymous, needs record', async () => {
  const seen = [], rows = [], counter = createCounter({ direct: 5 });
  const admin = createAdmin({ headers: { authorization: 'Bearer secret-token-xyz', 'x-goog-user-project': 'p' }, journal: { write: r => rows.push(r) }, counter, fetchImpl: async (u, init) => { seen.push(init.headers); return new Response('null'); } });
  await admin.rest('a', 'GET', 'http://h/x.json', { record: true, anonymous: true, headers: { 'accept-encoding': 'identity' } });
  assert.deepEqual(seen[0], { 'accept-encoding': 'identity' });
  assert.equal(rows[0].anonymous, true);
  await admin.rest('b', 'GET', 'http://h/x.json', { record: true });
  assert.equal(seen[1].authorization, 'Bearer secret-token-xyz'); assert.equal('anonymous' in rows[2], false);
  await assert.rejects(admin.rest('c', 'GET', 'http://h/x.json', { anonymous: true }), /anonymous needs record/);
  assert.equal(counter.used().direct, 2, 'a refused request counts nothing');
  assert.equal(JSON.stringify(rows).includes('secret-token-xyz'), false);
});
test('createAdmin: if-match is an allowed request header', async () => {
  const seen = [], admin = createAdmin({ headers: {}, journal: { write() {} }, counter: createCounter({ direct: 2 }), fetchImpl: async (u, init) => { seen.push(init.headers); return new Response('null'); } });
  await admin.rest('a', 'PUT', 'http://h/x.json', { record: true, body: '1', headers: { 'if-match': '"e"' } });
  assert.equal(seen[0]['if-match'], '"e"');
});
