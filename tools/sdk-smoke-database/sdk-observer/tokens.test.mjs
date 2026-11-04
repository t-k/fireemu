// The observer's tokens suite (G10, packet 5 of the RTDB closure): the deterministic credentials and their shapes, the
// case table and its request budget, the global Rules document, the per-profile runner (identities, transports, the
// ready probe, unknown answers, cancellation, masks) and the two token options of the admin REST (`bearer`, `resolveAdc`).
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';

import {
  ADC, CRED, CREDENTIAL_KINDS, GROUPS, HS256_KEY, IDENTITIES, OTHER_PROJECT, TABLE, TOKENS_AREA, TOKENS_CASES, TOKENS_PROFILES, TRANSPORTS,
  credentialRequest, credentials, runTokensProfile, seededBytes, tokensRules,
} from './tokens-suite.mjs';
import { MAX_PROBES } from './rules-suite.mjs';
import { CapExceeded, Unknown, createAdmin, createCounter } from './lib.mjs';

const PREFIX = '/sdktokens20261105', SCOPE = 'sdktokens20261105/sdk-tokens/r1-tokens', PROJECT = 'fireemu-oracle-query';
const url = (rel, query) => `http://h/${rel}?ns=n${query ? `&${query}` : ''}`;
const ok = (text = 'null', extra = {}) => ({ status: 200, text, headers: {}, bodyBytes: Buffer.byteLength(text), utf8: true, clipped: false, ...extra });
const b64 = s => JSON.parse(Buffer.from(s, 'base64url').toString('utf8'));
const seeded = seed => () => { seed = (seed * 1103515245 + 12345) % 2147483648; return seed / 2147483648; };

function fakeSend(answer = () => null) {
  const sent = [];
  const send = async (label, method, u, extra = {}) => {
    sent.push({ label, method, url: u, ...extra });
    const custom = answer(label, method, u, extra);
    if (custom instanceof Error) throw custom;
    if (custom) return { headers: {}, bodyBytes: Buffer.byteLength(custom.text ?? ''), utf8: true, clipped: false, ...custom };
    return ok(`{"at":"/${SCOPE}","p":"${PROJECT}"}`);
  };
  return { send, sent };
}
const runner = (f, over = {}) => runTokensProfile({ send: f.send, url, scope: SCOPE, projectId: PROJECT, sleep: async () => {}, ...over });
const caseLabels = sent => sent.map(s => s.label).filter(l => !l.startsWith('ready-'));

// ---- the credentials ----
test('credentials: deterministic, pinned, one string per kind, the ADC kind only a placeholder', () => {
  const a = credentials(PROJECT), b = credentials(PROJECT);
  assert.deepEqual(a, b);
  assert.deepEqual(Object.keys(a), CREDENTIAL_KINDS);
  assert.equal(a.adc, ADC); assert.equal(ADC, '{adc}'); assert.equal(CRED, '{cred}');
  assert.equal(a.empty, ''); assert.equal(a.null, 'null');
  assert.equal(createHash('sha256').update(JSON.stringify(credentials('demo-x'))).digest('hex'), 'af3242c9e88bd1963bfa41fc99f406c47fe3140adc18f1ef66efed87f2091699');
  assert.deepEqual(seededBytes('x', 40), seededBytes('x', 40)); assert.notDeepEqual(seededBytes('x', 40), seededBytes('y', 40));
  assert.equal(seededBytes('x', 100).length, 100); assert.deepEqual(seededBytes('x', 100).subarray(0, 40), seededBytes('x', 40));
});
test('credentials contain no secret: no OAuth or API key form, no 12-digit number, no PEM, no other credential, printable ASCII only', () => {
  for (const projectId of [PROJECT, 'demo-tokens-observer']) {
    for (const [kind, token] of Object.entries(credentials(projectId))) {
      assert.match(token, /^[\x20-\x7e]*$/, kind);
      assert.equal(/ya29\.|AIza|BEGIN|PRIVATE|owner|gho_|ghp_/.test(token), false, kind);
      for (const part of token.split('.')) {
        let decoded = part; try { decoded = Buffer.from(part, 'base64url').toString('latin1'); } catch { /* not base64 */ }
        assert.equal(/\d{12}/.test(decoded) || /\d{12}/.test(part), false, `${kind}: no 12-digit run`);
      }
    }
  }
});
test('credentials: only the kinds that carry the project as aud depend on the project (seeded property)', () => {
  const rnd = seeded(7), base = credentials('demo-a');
  const dependent = ['none_own', 'rs256', 'hs256', 'two_seg', 'huge'];
  for (let i = 0; i < 40; i++) {
    const p = `demo-${Math.floor(rnd() * 1e9).toString(36)}`, t = credentials(p);
    for (const kind of CREDENTIAL_KINDS) assert.equal(t[kind] === base[kind], !dependent.includes(kind), `${kind} for ${p}`);
    assert.equal(b64(t.none_own.split('.')[1]).aud, p);
    assert.equal(b64(t.none_other.split('.')[1]).aud, OTHER_PROJECT);
  }
  assert.ok(OTHER_PROJECT.startsWith('demo-'), 'the other project is a demo id: it cannot name a real project');
});
test('credentials: the JWT shapes (alg none with past exp, RS256 random signature and kid, HS256 with the throw-away key, two segments, a huge payload, characters needing percent-encoding)', () => {
  const t = credentials(PROJECT);
  for (const kind of ['none_other', 'none_own']) {
    const [h, p, s] = t[kind].split('.');
    assert.equal(t[kind].split('.').length, 3, kind); assert.equal(s, '', kind);
    assert.deepEqual(b64(h), { alg: 'none', typ: 'JWT' });
    const claims = b64(p), aud = kind === 'none_own' ? PROJECT : OTHER_PROJECT;
    assert.equal(claims.aud, aud); assert.equal(claims.iss, `https://securetoken.google.com/${aud}`);
    assert.equal(typeof claims.sub, 'string'); assert.ok(claims.sub.length > 0);
    assert.ok(claims.iat < claims.exp && claims.exp * 1000 < Date.parse('2024-01-01'), `${kind}: exp in the past`);
  }
  const [rh, rp, rs] = t.rs256.split('.');
  assert.equal(b64(rh).alg, 'RS256'); assert.match(b64(rh).kid, /^[0-9a-f]{40}$/);
  assert.equal(Buffer.from(rs, 'base64url').length, 256);
  assert.equal(b64(rp).aud, PROJECT); assert.ok(b64(rp).exp * 1000 > Date.parse('2090-01-01'), 'a signature case: not expired');
  const [hh, hp, hs] = t.hs256.split('.');
  assert.equal(b64(hh).alg, 'HS256');
  assert.equal(hs, createHmac('sha256', HS256_KEY).update(`${hh}.${hp}`).digest('base64url'));
  assert.equal(HS256_KEY.length, 32);
  assert.equal(t.two_seg, `${hh}.${hp}`);
  assert.ok(t.huge.length > 3000 && t.huge.length < 8000, `huge: ${t.huge.length}`); assert.equal(t.huge.split('.').length, 3);
  assert.notEqual(encodeURIComponent(t.pct), t.pct); assert.match(t.pct, /[ +/=%&#?"]/);
  assert.match(t.random, /^[0-9a-f]{40}$/);
});

// ---- the case table and the budget ----
test('the case table: 27 cases, unique ids, the seed first, every group, identity and transport used; the query or header carries the credential placeholder', () => {
  assert.equal(TABLE.length, 27); assert.deepEqual(TOKENS_CASES, TABLE.map(c => c.id));
  assert.equal(new Set(TOKENS_CASES).size, TABLE.length);
  assert.deepEqual(TABLE[0], { id: 'seed', group: 'seed', identity: 'admin', method: 'PUT', path: '.json', query: '', body: TABLE[0].body });
  assert.deepEqual([...new Set(TABLE.map(c => c.group))].sort(), [...GROUPS].sort());
  assert.deepEqual([...new Set(TABLE.map(c => c.identity))].sort(), [...IDENTITIES].sort());
  for (const c of TABLE.slice(1)) {
    assert.equal(c.method, 'GET', c.id); assert.match(c.path, /^\/(pub|deny|authreq)\.json$/, c.id);
    if (c.identity !== 'credential') { assert.equal(c.group, 'control', c.id); assert.equal(c.query, '', c.id); assert.equal(c.headers, undefined, c.id); assert.equal(c.credential, undefined, c.id); continue; }
    assert.ok(TRANSPORTS.includes(c.group), c.id); assert.ok(CREDENTIAL_KINDS.includes(c.credential), c.id);
    if (c.group === 'bearer') { assert.deepEqual(c.headers, { authorization: `Bearer ${CRED}` }, c.id); assert.equal(c.query, '', c.id); }
    else { assert.equal(c.query, `${c.group}=${CRED}`, c.id); assert.equal(c.headers, undefined, c.id); }
    assert.ok(c.credential !== 'adc' || c.group === 'auth', `${c.id}: the ADC token goes only in auth=`);
  }
  assert.deepEqual(TABLE.filter(c => c.credential === 'adc').map(c => c.path).sort(), ['/authreq.json', '/deny.json']);
  assert.deepEqual(TABLE.filter(c => c.group === 'auth' && c.path === '/authreq.json').map(c => c.credential), CREDENTIAL_KINDS);
});
test('one round is 28 requests (27 cases + the start probe); one production run 62 direct (2 x 28 + 6 preflight); the recommended cap 80', () => {
  const perRound = TOKENS_CASES.length + 1, perRun = TOKENS_PROFILES.length * perRound + 6;
  assert.equal(perRound, 28); assert.equal(perRun, 62); assert.ok(perRun + 4 <= 70, 'with the 4 cleanup requests at most 70');
  assert.equal(Math.ceil(Math.ceil(1.25 * perRun) / 10) * 10, 80);
});

// ---- the Rules ----
test('global Rules: root denied, the ready path readable, each profile scope with pub (read/write true), deny (read false) and authreq (auth != null)', () => {
  const doc = tokensRules(PREFIX), area = doc.rules.sdktokens20261105[TOKENS_AREA];
  assert.deepEqual(Object.keys(doc.rules), ['.read', '.write', 'sdktokens20261105']);
  assert.equal(doc.rules['.read'], false); assert.equal(doc.rules['.write'], false);
  assert.deepEqual(Object.keys(area), ['ready', ...TOKENS_PROFILES]);
  assert.deepEqual(area.ready, { '.read': true });
  for (const p of TOKENS_PROFILES) assert.deepEqual(area[p], { pub: { '.read': true, '.write': true }, deny: { '.read': false }, authreq: { '.read': 'auth != null' } });
  for (const bad of ['x', '/a/__proto__', '/a b', '', '/a//b', 7, `/${'a'.repeat(300)}`]) assert.throws(() => tokensRules(bad), /Invalid rules prefix/);
  assert.equal(createHash('sha256').update(JSON.stringify(tokensRules('/p'))).digest('hex'), '54ceaead5e047a190e5382e3b8c0ed8746b068e4e97517c9edd47bd7bdca79a3');
});

// ---- the runner ----
test('runner: the start probe, then every case once in order; transports, identities and the recorded template', async () => {
  const f = fakeSend(), emitted = [], creds = credentials(PROJECT);
  const rows = await runner(f, { emit: r => emitted.push(r) });
  assert.equal(f.sent[0].label, 'ready-start-1'); assert.equal(f.sent[0].anonymous, true);
  assert.equal(f.sent[0].url, url('sdktokens20261105/sdk-tokens/ready.json', ''));
  assert.deepEqual(caseLabels(f.sent), TOKENS_CASES); assert.deepEqual(rows.map(r => r.id), TOKENS_CASES);
  for (const c of TABLE) {
    const s = f.sent.find(x => x.label === c.id), token = creds[c.credential];
    assert.equal(s.record, true, c.id); assert.equal(s.headers['accept-encoding'], 'identity', c.id); assert.equal(s.method, c.method, c.id);
    assert.equal(s.anonymous === true, c.identity !== 'admin', c.id);
    assert.equal(s.bearer, c.group === 'bearer' ? token : undefined, c.id);
    assert.equal(s.resolveAdc === true, c.credential === 'adc', c.id);
    assert.equal(Object.hasOwn(s.headers, 'authorization'), false, `${c.id}: the bearer goes through the admin REST option, never as a plain header`);
    const want = c.group === 'auth' || c.group === 'access_token' ? `${c.group}=${c.credential === 'adc' ? ADC : encodeURIComponent(token)}` : '';
    assert.equal(s.url, url(`${SCOPE}${c.path}`, want), c.id);
  }
  const row = rows.find(r => r.id === 'auth-hs256');
  assert.deepEqual(row, { kind: 'case', suite: 'tokens', id: 'auth-hs256', group: 'auth', identity: 'credential', ok: true, outcome: 'answered', method: 'GET', path: '{scope}/authreq.json', query: 'auth={cred}', requestHeaders: {}, requestBody: null, status: 200, responseHeaders: {}, body: '{"at":"/{scope}","p":"{project}"}', bodyBytes: 17 + SCOPE.length + PROJECT.length, utf8: true, clipped: false });
  assert.deepEqual(rows.find(r => r.id === 'bearer-rs256').requestHeaders, { authorization: 'Bearer {cred}' });
  assert.ok(emitted.some(r => r.kind === 'probe' && r.suite === 'tokens' && r.after === 'start' && r.ready === true));
});
test('runner: the ready probe is repeated (with the delay) until 200, at most 20 times; never ready stops the profile', async () => {
  let n = 0; const sleeps = [];
  const f = fakeSend(label => (label.startsWith('ready-') ? (++n < 3 ? { status: 401, text: 'x' } : null) : null));
  const rows = await runner(f, { sleep: async ms => { sleeps.push(ms); } });
  assert.deepEqual(f.sent.slice(0, 3).map(s => s.label), ['ready-start-1', 'ready-start-2', 'ready-start-3']);
  assert.deepEqual(sleeps, [2000, 2000]); assert.equal(rows.length, TOKENS_CASES.length);
  const never = fakeSend(label => (label.startsWith('ready-') ? { status: 401, text: 'x' } : null)), emitted = [];
  assert.deepEqual(await runner(never, { emit: r => emitted.push(r) }), [{ id: 'ready-start', ok: false, outcome: 'not-ready' }]);
  assert.equal(never.sent.length, MAX_PROBES); assert.equal(emitted.filter(r => r.kind === 'probe').length, MAX_PROBES);
  for (const [error, outcome] of [[new Unknown('x'), 'unknown'], [new CapExceeded('cap'), 'not-sent']]) {
    const g = fakeSend(label => (label === 'ready-start-1' ? error : null));
    assert.deepEqual(await runner(g), [{ id: 'ready-start', ok: false, outcome }]); assert.equal(g.sent.length, 1);
  }
});
test('runner: the seed answered 5xx, 3xx, below 200 or unreadable is an unknown mutation; a GET answered 5xx or unreadable is only recorded', async () => {
  for (const [answer, outcome] of [[{ status: 503, text: 'x' }, 'unknown-status'], [{ status: 304, text: '' }, 'unknown-status'], [{ status: 101, text: '' }, 'unknown-status'], [{ status: 200, text: null, utf8: false }, 'unknown-body']]) {
    const f = fakeSend(label => (label === 'seed' ? answer : label === 'auth-null' ? { status: 500, text: 'e' } : label === 'auth-pct' ? { status: 200, text: null, utf8: false } : null));
    const rows = await runner(f), seed = rows.find(r => r.id === 'seed');
    assert.equal(seed.outcome, outcome); assert.deepEqual(seed.unknown, ['seed']); assert.equal(seed.ok, false);
    assert.equal(rows.length, TOKENS_CASES.length, 'the profile goes on');
    assert.equal(rows.find(r => r.id === 'auth-null').outcome, 'answered'); assert.equal('unknown' in rows.find(r => r.id === 'auth-null'), false);
    assert.equal(rows.find(r => r.id === 'auth-pct').outcome, 'answered'); assert.equal(rows.find(r => r.id === 'auth-pct').utf8, false);
  }
  const g = fakeSend(label => (label === 'seed' ? { status: 400, text: '{"error":"x"}' } : null));
  assert.equal((await runner(g)).find(r => r.id === 'seed').outcome, 'answered', 'a 4xx is a known answer');
});
test('runner: a transport failure stops the profile (the seed is unknown, a GET is not); a cap refusal sent nothing; a clipped answer is not ok', async () => {
  for (const [label, unknown] of [['seed', true], ['auth-rs256', false], ['bearer-null', false]]) {
    const f = fakeSend(l => (l === label ? new Unknown(`${l}: unknown outcome`) : null)), rows = await runner(f);
    assert.equal(f.sent.at(-1).label, label); assert.equal(rows.at(-1).outcome, 'unknown');
    assert.deepEqual(rows.at(-1).unknown ?? [], unknown ? [label] : []);
  }
  const f = fakeSend(l => (l === 'at-rs256' ? new CapExceeded('direct cap reached') : null)), rows = await runner(f);
  assert.equal(rows.at(-1).outcome, 'not-sent'); assert.equal('unknown' in rows.at(-1), false); assert.equal(f.sent.at(-1).label, 'at-rs256');
  const c = fakeSend(l => (l === 'auth-huge' || l === 'seed' ? { status: 200, text: 'x', clipped: true } : null)), clipped = await runner(c);
  for (const id of ['auth-huge', 'seed']) { const r = clipped.find(x => x.id === id); assert.equal(r.ok, false, id); assert.equal(r.outcome, 'clipped', id); assert.equal('unknown' in r, false, id); }
  assert.equal(clipped.length, TOKENS_CASES.length);
});
test('runner: cancellation is checked before every request, the probes included', async () => {
  for (const stopAt of [1, 2, 10, 28]) {
    let n = 0, cancelled = false;
    const f = fakeSend(() => { n += 1; if (n === stopAt) cancelled = true; return null; });
    await runner(f, { cancelled: () => cancelled });
    assert.equal(f.sent.length, stopAt, `stop after request ${stopAt}`);
  }
  let cancelled = false; const f = fakeSend(label => (label.startsWith('ready-') ? { status: 401, text: 'x' } : null));
  assert.deepEqual(await runner(f, { cancelled: () => cancelled, sleep: async () => { cancelled = true; } }), []);
  assert.equal(f.sent.length, 1);
});
test('runner: an invalid scope or project is refused before anything is sent', async () => {
  for (const scope of ['', '/a', 'a//b', 'a/b c', 'a', 42]) { const f = fakeSend(); await assert.rejects(runTokensProfile({ send: f.send, url, scope, projectId: PROJECT }), /Invalid tokens scope/, String(scope)); assert.equal(f.sent.length, 0); }
  for (const projectId of ['', 'A b', 7, '123456789012']) { const f = fakeSend(); await assert.rejects(runTokensProfile({ send: f.send, url, scope: SCOPE, projectId }), /Invalid project id/, String(projectId)); assert.equal(f.sent.length, 0); }
});

// ---- the token options of the admin REST ----
function admin({ adc = 'adc-token-value-0123456789', answer = () => new Response('null') } = {}) {
  const seen = [], rows = [], counter = createCounter({ direct: 20 });
  const a = createAdmin({ headers: { authorization: 'Bearer admin-secret-xyz', 'x-goog-user-project': 'p' }, adc, journal: { write: r => rows.push(r) }, counter, fetchImpl: async (u, init) => { seen.push({ url: u, headers: init.headers }); return answer(u, init); } });
  return { a, seen, rows, counter };
}
test('createAdmin bearer: sent as the only Authorization header, no user project, journalled as a sha256 only; needs record and anonymous; shape checked before the counter', async () => {
  const { a, seen, rows, counter } = admin();
  await a.rest('b', 'GET', 'http://h/x.json', { record: true, anonymous: true, bearer: 'fake.tok en', headers: { 'accept-encoding': 'identity' } });
  assert.deepEqual(seen[0].headers, { 'accept-encoding': 'identity', authorization: 'Bearer fake.tok en' });
  assert.equal(rows[0].bearerSha256, createHash('sha256').update('fake.tok en').digest('hex'));
  assert.equal(JSON.stringify(rows).includes('fake.tok en'), false); assert.equal(JSON.stringify(rows).includes('admin-secret-xyz'), false);
  await a.rest('e', 'GET', 'http://h/x.json', { record: true, anonymous: true, bearer: '' });
  assert.equal(seen[1].headers.authorization, 'Bearer ');
  for (const [extra, re] of [[{ record: true, bearer: 'x' }, /needs record and anonymous/], [{ anonymous: true, bearer: 'x' }, /anonymous needs record/], [{ record: true, anonymous: true, bearer: 'a\nb' }, /bearer token shape/], [{ record: true, anonymous: true, bearer: 7 }, /bearer token shape/], [{ record: true, anonymous: true, bearer: 'x'.repeat(8193) }, /bearer token shape/], [{ record: true, anonymous: true, bearer: 'x', cleanup: true }, /needs record/]])
    await assert.rejects(a.rest('z', 'GET', 'http://h/x.json', extra), re, JSON.stringify(extra).slice(0, 60));
  assert.equal(counter.used().direct, 2, 'a refused request counts nothing');
});
test('createAdmin resolveAdc: {adc} replaced only in the URL that is fetched; the journal keeps the placeholder; the token in the answer body and headers is masked', async () => {
  const ADC_VALUE = 'ya29.adc-secret/+=value', { a, seen, rows } = admin({ adc: ADC_VALUE, answer: u => new Response(`{"echo":"${decodeURIComponent(new URL(u).search)}"}`, { headers: { 'www-authenticate': `Bearer x=${ADC_VALUE}` } }) });
  const r = await a.rest('adc', 'GET', 'http://h/x.json?ns=n&auth={adc}', { record: true, anonymous: true, resolveAdc: true });
  assert.equal(seen[0].url, `http://h/x.json?ns=n&auth=${encodeURIComponent(ADC_VALUE)}`);
  assert.equal(Object.hasOwn(seen[0].headers, 'authorization'), false); assert.equal(Object.hasOwn(seen[0].headers, 'x-goog-user-project'), false);
  assert.equal(rows[0].url, 'http://h/x.json?ns=n&auth={adc}'); assert.equal(rows[0].resolveAdc, true);
  assert.equal(r.text, '{"echo":"?ns=n&auth={adc}"}'); assert.equal(r.headers['www-authenticate'], 'Bearer x={adc}');
  assert.equal(r.bodyBytes, Buffer.byteLength(`{"echo":"?ns=n&auth=${ADC_VALUE}"}`), 'the byte length is the answer\'s own');
  assert.equal(JSON.stringify(rows).includes(ADC_VALUE), false); assert.equal(JSON.stringify(rows).includes(encodeURIComponent(ADC_VALUE)), false);
});
test('createAdmin resolveAdc: refused without record and anonymous, without exactly one placeholder, or without an ADC value; a placeholder is never sent unresolved', async () => {
  const { a, counter } = admin();
  for (const [u, extra, re] of [
    ['http://h/x.json?auth={adc}', { record: true, resolveAdc: true }, /needs record and anonymous/],
    ['http://h/x.json?auth=x', { record: true, anonymous: true, resolveAdc: true }, /one \{adc\} placeholder/],
    ['http://h/x.json?auth={adc}&b={adc}', { record: true, anonymous: true, resolveAdc: true }, /one \{adc\} placeholder/],
    ['http://h/x.json?auth={adc}', { record: true, anonymous: true }, /one \{adc\} placeholder/],
    ['http://h/x.json?auth={adc}', {}, /one \{adc\} placeholder/],
  ]) await assert.rejects(a.rest('z', 'GET', u, extra), re, u);
  const none = admin({ adc: null });
  await assert.rejects(none.a.rest('z', 'GET', 'http://h/x.json?auth={adc}', { record: true, anonymous: true, resolveAdc: true }), /no ADC value/);
  assert.equal(counter.used().direct + none.counter.used().direct, 0);
});
test('credentialRequest: the transport of each identity; the ADC token never as a Bearer', () => {
  const spec = id => TABLE.find(c => c.id === id);
  assert.deepEqual(credentialRequest(spec('seed'), undefined), { query: '', options: {} });
  assert.deepEqual(credentialRequest(spec('ctl-anon-pub'), undefined), { query: '', options: { anonymous: true } });
  assert.deepEqual(credentialRequest(spec('auth-pct'), 'a b'), { query: 'auth=a%20b', options: { anonymous: true } });
  assert.deepEqual(credentialRequest(spec('at-random'), 'r'), { query: 'access_token=r', options: { anonymous: true } });
  assert.deepEqual(credentialRequest(spec('auth-adc'), ADC), { query: `auth=${ADC}`, options: { anonymous: true, resolveAdc: true } });
  assert.deepEqual(credentialRequest(spec('bearer-null'), 'null'), { query: '', options: { anonymous: true, bearer: 'null' } });
  assert.throws(() => credentialRequest({ ...spec('bearer-null'), credential: 'adc' }, ADC), /only in auth=/);
});
test('createAdmin resolveAdc: the percent-encoded form of the token is masked too', async () => {
  const ADC_VALUE = 'ya29.adc-secret/+=value', { a, rows } = admin({ adc: ADC_VALUE, answer: u => new Response(`{"raw":"${new URL(u).search}"}`) });
  const r = await a.rest('adc', 'GET', 'http://h/x.json?auth={adc}', { record: true, anonymous: true, resolveAdc: true });
  assert.equal(r.text, '{"raw":"?auth={adc}"}');
  assert.equal(JSON.stringify(rows).includes(encodeURIComponent(ADC_VALUE)), false);
});
