// The rules suite (G8, packet 3 of the RTDB closure, owner row 2217): the Rules leftovers of the inventory and at most
// four REST neighbour GETs, as plain HTTP requests, no SDK and no browser. Two profiles (r1-rules, r2-rules) run the
// same case table, each under its own scope `<prefix>/sdk-rules/<profile>`, through the observer's admin REST path.
//
// Three request identities: `admin` (production: the ADC Bearer token and x-goog-user-project; local: Bearer owner;
// the Rules are bypassed), `anonymous` (no Authorization header at all) and `override` (the admin credential with
// `auth_variable_override=<json>` in the query: the Rules see that auth object; no further credential, no ID token).
//
// Group A is ONE global Rules document (globalRules) with one path per case: the observer installs it after its own
// preflight and reads it back; each profile starts with the ready probe (an anonymous GET of `<prefix>/sdk-rules/ready`,
// whose `.read` is true only in the global document) repeated at most MAX_PROBES times, `probeDelayMs` apart, until
// it is answered 200. Group B (the load cases, last) PUTs other Rules documents: the answer (status and body bytes)
// is the observation. A refused document leaves the global document in effect; an accepted one (200) replaced it, so
// the global document is put back (an `install` row) and probed again. Every load document is safe if accepted: no
// `true` grant, writes denied at the root, and no prefix in it (so the error columns do not depend on the prefix).
//
// One row per case, as the rest suite writes them (rest-suite.mjs) plus `group` and `identity`. Outcomes: answered;
// unknown-status and unknown-body (a non-GET answered below 200, 3xx, 5xx, or with a body that is not UTF-8);
// unknown (no answer was read: the profile stops); not-sent (the cap refused it: the profile stops); blocked (the ETag
// it needs was not in an earlier answer). A load case with an unknown outcome stops the profile (the Rules in effect
// are unknown). Probe and install rows are journalled separately (kind `probe`, `install`); a profile whose probe
// never reads 200, or whose reinstall is not answered 200, stops there.
import { CapExceeded } from './lib.mjs';
import { FIXED_REQUEST_HEADERS, OWN_ETAG, maskText } from './rest-suite.mjs';

export const RULES_PROFILES = ['r1-rules', 'r2-rules'];
export const RULES_AREA = 'sdk-rules';
export const IDENTITIES = ['admin', 'anonymous', 'override'];
export const GROUPS = ['seed', 'token', 'index', 'grammar', 'query', 'concat', 'conditional', 'neighbour', 'load'];
export const OVERRIDE_PARAM = 'auth_variable_override';
export const MAX_PROBES = 8;
/** Request headers a case may set; they are recorded on the case row. */
export const RECORDED_REQUEST_HEADERS = ['x-firebase-etag', 'if-match'];

const q = s => encodeURIComponent(`"${s}"`);   // a JSON string query value
const as = (auth, query = '') => `${query ? `${query}&` : ''}${OVERRIDE_PARAM}=${encodeURIComponent(JSON.stringify(auth))}`;
const c = (id, group, identity, method, path, { query = '', body, headers, expectValid } = {}) => ({ id, group, identity, method, path, query, ...(body === undefined ? {} : { body }), ...(headers ? { headers } : {}), ...(expectValid ? { expectValid } : {}) });
const tok = token => ({ uid: 'u1', token });
const load = (id, doc, expectValid = false) => c(id, 'load', 'admin', 'PUT', '/.settings/rules.json', { body: doc, expectValid });

/** The seed of one profile scope, one admin PUT (bodies never name the prefix). */
export const SEED = {
  tok: { admin: 1, level: 1, provider: 1, verified: 1, name: 1, email: 1 },
  idx: { k1: { a: 3, b: 1, c: 2 }, k2: { a: 1, b: 3, c: 1 }, k3: { a: 2, b: 2, c: 3 } },
  idxv: { k1: 3, k2: 1, k3: 2 },
  nest: { inner: { k1: { a: 2 }, k2: { a: 1 } } },
  noidx: { k1: { a: 2 }, k2: { a: 1 } },
  vd: 1,
  mp: { a: { x: 1 }, b: { x: 1 }, c: { x: 1 } },
  rc: { flag: true },
  rp: { child: 1, other: 2 },
  qo: { a: { h: 1 }, b: { h: 2 }, c: { h: 3 } },
  ql: { a: 1, b: 2, c: 3 }, qs: { a: 1, b: 2, c: 3 }, qe: { a: 1, b: 2, c: 3 }, qq: { a: 1, b: 2, c: 3 },
  qb: { child: { a: 1 } },
  cc: { d15: 1, d1e7: 1, d100: 1, dlong: 1, dsmall: 1 },
  cw: { v: 1 },
  pn: { '.value': 1, '.priority': 5 },
  pp: { a: { x: 1 } },
  nb: { a: 1, b: 2, c: 3, d: 4, e: 5, f: 6, g: 7, h: 8 },
};

const LONG = `${'false || '.repeat(400)}false`;
/** The case table of one round, in order. Paths are relative to the profile scope, except the load cases. */
export const TABLE = [
  c('seed', 'seed', 'admin', 'PUT', '.json', { body: JSON.stringify(SEED) }),
  // 1. auth.token claims through auth_variable_override: an allow and a deny each, and a token that is not an object
  c('tok-admin-allow', 'token', 'override', 'GET', '/tok/admin.json', { query: as(tok({ admin: true })) }),
  c('tok-admin-deny', 'token', 'override', 'GET', '/tok/admin.json', { query: as(tok({ admin: 'true' })) }),
  c('tok-level-allow', 'token', 'override', 'GET', '/tok/level.json', { query: as(tok({ level: 3 })) }),
  c('tok-level-deny', 'token', 'override', 'GET', '/tok/level.json', { query: as(tok({ level: '3' })) }),
  c('tok-provider-allow', 'token', 'override', 'GET', '/tok/provider.json', { query: as(tok({ firebase: { sign_in_provider: 'password' } })) }),
  c('tok-provider-deny', 'token', 'override', 'GET', '/tok/provider.json', { query: as(tok({ firebase: { sign_in_provider: 'google.com' } })) }),
  c('tok-verified-allow', 'token', 'override', 'GET', '/tok/verified.json', { query: as(tok({ email_verified: true })) }),
  c('tok-verified-deny', 'token', 'override', 'GET', '/tok/verified.json', { query: as(tok({})) }),
  c('tok-name-allow', 'token', 'override', 'GET', '/tok/name.json', { query: as(tok({ name: 'x' })) }),
  c('tok-name-deny', 'token', 'override', 'GET', '/tok/name.json', { query: as(tok({ name: 'y' })) }),
  c('tok-email-allow', 'token', 'override', 'GET', '/tok/email.json', { query: as(tok({ email: 'a@example.com' })) }),
  c('tok-email-deny', 'token', 'override', 'GET', '/tok/email.json', { query: as(tok({ email: 'a@example.org' })) }),
  c('tok-not-object', 'token', 'override', 'GET', '/tok/admin.json', { query: as({ uid: 'u1', token: 'x' }) }),
  // 2. .indexOn variants, admin queries
  c('ix-a', 'index', 'admin', 'GET', '/idx.json', { query: `orderBy=${q('a')}` }),
  c('ix-b-first', 'index', 'admin', 'GET', '/idx.json', { query: `orderBy=${q('b')}&limitToFirst=2` }),
  c('ix-c', 'index', 'admin', 'GET', '/idx.json', { query: `orderBy=${q('c')}` }),
  c('ix-c-last', 'index', 'admin', 'GET', '/idx.json', { query: `orderBy=${q('c')}&limitToLast=1` }),
  c('ix-key-last', 'index', 'admin', 'GET', '/idx.json', { query: `orderBy=${q('$key')}&limitToLast=2` }),
  c('ix-value-unindexed', 'index', 'admin', 'GET', '/idx.json', { query: `orderBy=${q('$value')}` }),
  c('ixv-value-first', 'index', 'admin', 'GET', '/idxv.json', { query: `orderBy=${q('$value')}&limitToFirst=2` }),
  c('ixn-inner', 'index', 'admin', 'GET', '/nest/inner.json', { query: `orderBy=${q('a')}` }),
  c('ixn-parent', 'index', 'admin', 'GET', '/nest.json', { query: `orderBy=${q('a')}` }),
  c('ix-none', 'index', 'admin', 'GET', '/noidx.json', { query: `orderBy=${q('a')}&limitToFirst=1` }),
  // 3. cascade and validation grammar
  c('wv-allow', 'grammar', 'anonymous', 'PUT', '/wv/p1.json', { body: '{"a":1,"b":2}' }),
  c('wv-deny', 'grammar', 'anonymous', 'PUT', '/wv/p2.json', { body: '{"a":1,"b":"s"}' }),
  c('vd-null', 'grammar', 'anonymous', 'PUT', '/vd.json', { body: 'null' }),
  c('mp-allow', 'grammar', 'override', 'PATCH', '/mp.json', { body: '{"a/y":2}', query: as({ uid: 'u1' }) }),
  c('mp-deny', 'grammar', 'override', 'PATCH', '/mp.json', { body: '{"b/y":2,"c/z":3}', query: as({ uid: 'u1' }) }),
  c('rc-allow', 'grammar', 'anonymous', 'PUT', '/rc/ok.json', { body: '1' }),
  c('rc-deny', 'grammar', 'anonymous', 'PUT', '/rc/no.json', { body: '1' }),
  c('nw-allow', 'grammar', 'anonymous', 'PUT', '/nw.json', { body: '1' }),
  c('rp-child', 'grammar', 'anonymous', 'GET', '/rp/child.json'),
  c('rp-parent', 'grammar', 'anonymous', 'GET', '/rp.json'),
  // 4. query.* members in .read
  c('q-ochild-allow', 'query', 'anonymous', 'GET', '/qo.json', { query: `orderBy=${q('h')}` }),
  c('q-ochild-deny', 'query', 'anonymous', 'GET', '/qo.json', { query: `orderBy=${q('$key')}` }),
  c('q-lfirst-allow', 'query', 'anonymous', 'GET', '/ql.json', { query: `orderBy=${q('$key')}&limitToFirst=2` }),
  c('q-lfirst-deny', 'query', 'override', 'GET', '/ql.json', { query: as({ uid: 'u1' }, `orderBy=${q('$key')}&limitToFirst=3`) }),
  c('q-start', 'query', 'anonymous', 'GET', '/qs.json', { query: `orderBy=${q('$key')}&startAt=${q('b')}` }),
  c('q-end', 'query', 'anonymous', 'GET', '/qe.json', { query: `orderBy=${q('$key')}&endAt=${q('b')}` }),
  c('q-equal', 'query', 'anonymous', 'GET', '/qq.json', { query: `orderBy=${q('$value')}&equalTo=2` }),
  c('q-below', 'query', 'anonymous', 'GET', '/qb.json', { query: `orderBy=${q('$key')}` }),
  // 5. string concatenation of numbers, compared with the Java Double.toString text
  c('cc-d15', 'concat', 'anonymous', 'GET', '/cc/d15.json'),
  c('cc-d1e7', 'concat', 'anonymous', 'GET', '/cc/d1e7.json'),
  c('cc-d100', 'concat', 'anonymous', 'GET', '/cc/d100.json'),
  c('cc-dlong', 'concat', 'anonymous', 'GET', '/cc/dlong.json'),
  c('cc-dsmall', 'concat', 'anonymous', 'GET', '/cc/dsmall.json'),
  // 7. conditional writes and priority
  c('cw-etag', 'conditional', 'admin', 'GET', '/cw.json', { headers: { 'x-firebase-etag': 'true' } }),
  c('cw-ifmatch', 'conditional', 'anonymous', 'PUT', '/cw.json', { body: '{"v":2}', headers: { 'if-match': OWN_ETAG } }),
  c('pn-allow', 'conditional', 'anonymous', 'PUT', '/pn/.priority.json', { body: '5' }),
  c('pn-deny', 'conditional', 'anonymous', 'PUT', '/pn/.priority.json', { body: '6' }),
  c('pp-patch', 'conditional', 'anonymous', 'PATCH', '/pp.json', { body: '{"a/.priority":3}' }),
  // 8. REST neighbours (read-only, admin)
  c('nb-timeout-1min', 'neighbour', 'admin', 'GET', '/nb.json', { query: 'timeout=1min' }),
  c('nb-shallow-start', 'neighbour', 'admin', 'GET', '/nb.json', { query: 'shallow=true&startAfter=b' }),
  c('nb-shallow-all', 'neighbour', 'admin', 'GET', '/nb.json', { query: 'shallow=true' }),
  c('nb-range', 'neighbour', 'admin', 'GET', '/nb.json', { query: `orderBy=${q('$key')}&startAt=${q('b')}&endAt=${q('g')}` }),
  // 6. load documents (group B): ten refusals, then four lexing documents that may be valid
  load('load-paren', '{"rules":{".read":"(auth != null"}}'),
  load('load-token', '{"rules":{".read":"auth # null"}}'),
  load('load-ident', '{"rules":{".read":"foo == 1"}}'),
  load('load-types', '{"rules":{".read":"\'a\' - 1"}}'),
  load('load-read-number', '{"rules":{".read":5}}'),
  load('load-indexon-number', '{"rules":{"x":{".indexOn":5}}}'),
  load('load-two-paths', '{"rules":{"a":{".read":"foo"},"b":{".write":"bar"}}}'),
  load('load-validate-write', '{"rules":{"a":{".validate":"1 +",".write":"baz"}}}'),
  load('load-regex', '{"rules":{".read":"\'a\'.matches(/abc)"}}'),
  load('load-long', `{"rules":{".read":"${LONG}","x":{".write":"(("}}}`),
  load('lex-feff', '{"rules":{".read":"false﻿||﻿false",".write":false}}', true),
  load('lex-nel', '{"rules":{".read":false,".write":false,"a\u0085b":{".read":false}}}', true),
  load('lex-lazy', '{"rules":{".read":"\'aaa\'.matches(/a+?/) == false",".write":false}}', true),
  load('lex-number', '{"rules":{".read":"1e3 == 1000 && false",".write":false}}', true),
];
export const RULES_CASES = TABLE.map(x => x.id);
export const LOAD_CASES = TABLE.filter(x => x.group === 'load').map(x => x.id);

const PREFIX_RE = /^\/[A-Za-z0-9_-]+(?:\/[A-Za-z0-9_-]+)*$/;
/** The Rules of one profile scope; `abs` is the scope path without a leading slash (for root.child). */
function scopeRules(abs) {
  return {
    tok: {
      admin: { '.read': 'auth.token.admin === true' },
      level: { '.read': 'auth.token.level >= 2' },
      provider: { '.read': "auth.token.firebase.sign_in_provider === 'password'" },
      verified: { '.read': 'auth.token.email_verified === true' },
      name: { '.read': "auth.token.name == 'x'" },
      email: { '.read': 'auth.token.email.matches(/@example\\.com$/)' },
    },
    idx: { '.indexOn': ['a', 'b'] },
    idxv: { '.indexOn': '.value' },
    nest: { inner: { '.indexOn': ['a'] } },
    wv: { $p: { '.write': true, '.validate': 'newData.hasChildren()', $c: { '.validate': 'newData.isNumber()' } } },
    vd: { '.write': true, '.validate': 'newData.exists()' },
    mp: { $k: { '.write': true, '.validate': "newData.hasChildren(['x', 'y'])" } },
    rc: { ok: { '.write': `root.child('${abs}/rc/flag').val() == true` }, no: { '.write': `root.child('${abs}/rc/flag').val() == false` } },
    nw: { '.write': 'now > 1000000000000' },
    rp: { '.read': false, child: { '.read': true } },
    qo: { '.read': "query.orderByChild == 'h'", '.indexOn': ['h'] },
    ql: { '.read': 'query.limitToFirst <= 2' },
    qs: { '.read': "query.startAt == 'b'" },
    qe: { '.read': "query.endAt == 'b'" },
    qq: { '.read': 'query.equalTo == 2', '.indexOn': '.value' },
    qb: { child: { '.read': 'query.orderByKey == true' } },
    cc: {
      d15: { '.read': "'a' + 1.5 == 'a1.5'" },
      d1e7: { '.read': "'a' + 10000000.0 == 'a1.0E7'" },
      d100: { '.read': "'a' + 100.0 == 'a100.0'" },
      dlong: { '.read': "'a' + 12345678901 == 'a12345678901'" },
      dsmall: { '.read': "'a' + 0.0001 == 'a1.0E-4'" },
    },
    cw: { '.write': true, '.read': false },
    pn: { '.write': true, '.validate': 'newData.getPriority() == 5' },
    pp: { $k: { '.write': true, '.validate': 'newData.getPriority() == null' } },
  };
}
/** The global Rules document of a rules run: root denied, the ready path readable, one path per case in each profile scope. */
export function globalRules(prefix) {
  if (typeof prefix !== 'string' || prefix.length > 256 || !PREFIX_RE.test(prefix)) throw Error('Invalid rules prefix');
  if (prefix.slice(1).split('/').some(part => ['__proto__', 'constructor', 'prototype'].includes(part))) throw Error('Invalid rules prefix');
  const rules = { '.read': false, '.write': false }; let target = rules;
  for (const part of prefix.slice(1).split('/')) target = target[part] = {};
  target[RULES_AREA] = { ready: { '.read': true }, ...Object.fromEntries(RULES_PROFILES.map(name => [name, scopeRules(`${prefix.slice(1)}/${RULES_AREA}/${name}`)])) };
  return { rules };
}
/** The ready path (with its .json) of a profile scope `<prefix>/sdk-rules/<profile>`. */
export const readyPath = scope => `${scope.split('/').slice(0, -1).join('/')}/ready.json`;

const unknownStatus = status => status < 200 || (status >= 300 && status < 400) || status >= 500;
const SCOPE_RE = /^[A-Za-z0-9_-]+(?:\/[A-Za-z0-9_-]+)*\/[A-Za-z0-9_-]+$/;

/**
 * One profile. `send(label, method, url, {body, headers, record, anonymous})` is the observer's admin REST (counted,
 * journalled, never retried); `url(rel, query)` builds a request URL; `installBody` is the global document's text as
 * the observer installed it. Returns the case rows (and a final failure row when the profile stopped on its probe or
 * reinstall); probe and install rows go to `emit` only.
 */
export async function runRulesProfile({ send, url, scope, installBody, emit = () => {}, cases = RULES_CASES, cancelled = () => false, sleep = ms => new Promise(r => setTimeout(r, ms)), probeDelayMs = 1500, maxProbes = MAX_PROBES }) {
  if (typeof scope !== 'string' || !SCOPE_RE.test(scope)) throw Error('Invalid rules scope');
  if (typeof installBody !== 'string' || installBody.length === 0) throw Error('Invalid install body');
  const rows = [], seen = { etag: null }, mask = text => maskText(text, { scope, pushIds: [] });
  const done = row => { const full = { kind: 'case', suite: 'rules', ...row }; rows.push(full); emit(full); return full; };
  const rulesUrl = url('.settings/rules.json', '');
  // The ready probe: 'ready' once it read 200, 'not-ready' when it never did within maxProbes, 'unknown' or 'not-sent'
  // when a probe was not answered or refused by the cap, 'cancelled' when the profile was abandoned meanwhile.
  const probe = async after => {
    for (let attempt = 1; attempt <= maxProbes; attempt++) {
      if (cancelled()) return 'cancelled';
      let answer;
      try { answer = await send(`ready-${after}-${attempt}`, 'GET', url(readyPath(scope), ''), { headers: { ...FIXED_REQUEST_HEADERS }, record: true, anonymous: true }); }
      catch (error) { const outcome = error instanceof CapExceeded ? 'not-sent' : 'unknown'; emit({ kind: 'probe', suite: 'rules', after, attempt, outcome, ready: false }); return outcome; }
      const ready = answer.status === 200;
      emit({ kind: 'probe', suite: 'rules', after, attempt, outcome: 'answered', status: answer.status, ready });
      if (ready) return 'ready';
      if (attempt < maxProbes) await sleep(probeDelayMs);
    }
    return 'not-ready';
  };
  const stopRow = (id, outcome, extra = {}) => { const row = { id, ok: false, outcome, ...extra }; rows.push(row); return rows; };
  const afterProbe = (after, verdict) => (verdict === 'cancelled' ? rows : stopRow(`ready-${after}`, verdict));   // a GET: never an unknown mutation
  const first = await probe('start');
  if (first !== 'ready') return afterProbe('start', first);
  for (const id of cases) {
    if (cancelled()) return rows;   // the profile was abandoned at its deadline: nothing more is sent
    const spec = TABLE.find(x => x.id === id);
    if (!spec) throw Error(`unknown rules case ${id}`);
    const headers = {}, recorded = {};
    let blocked = null;
    for (const [name, value] of Object.entries(spec.headers ?? {})) {
      if (value === OWN_ETAG && seen.etag === null) blocked = 'no ETag in the answer of cw-etag';
      headers[name] = value === OWN_ETAG ? seen.etag : value;
      recorded[name] = value;
    }
    const head = { id, group: spec.group, identity: spec.identity };
    if (blocked) { done({ ...head, ok: false, outcome: 'blocked', error: blocked }); continue; }
    const isLoad = spec.group === 'load', rel = isLoad ? '.settings/rules.json' : `${scope}${spec.path}`;
    const request = { method: spec.method, path: isLoad ? spec.path : `{scope}${spec.path}`, query: spec.query, requestHeaders: recorded, requestBody: spec.body ?? null };
    let answer;
    try { answer = await send(id, spec.method, isLoad ? rulesUrl : url(rel, spec.query), { ...(spec.body === undefined ? {} : { body: spec.body }), headers: { ...FIXED_REQUEST_HEADERS, ...headers }, record: true, ...(spec.identity === 'anonymous' ? { anonymous: true } : {}) }); }
    catch (error) {
      const notSent = error instanceof CapExceeded;
      done({ ...head, ok: false, outcome: notSent ? 'not-sent' : 'unknown', ...request, error: `${error?.name}: ${String(error?.message).slice(0, 200)}`, ...(!notSent && spec.method !== 'GET' ? { unknown: [id] } : {}) });
      return rows;   // transport uncertainty or the cap: nothing more is sent from this profile
    }
    if (id === 'cw-etag' && typeof answer.headers?.etag === 'string') seen.etag = answer.headers.etag;
    const unreadable = spec.method !== 'GET' && answer.utf8 === false, unknown = spec.method !== 'GET' && (unknownStatus(answer.status) || unreadable);
    done({
      ...head, ok: !unknown, outcome: unreadable ? 'unknown-body' : unknown ? 'unknown-status' : 'answered', ...request, status: answer.status, responseHeaders: answer.headers ?? {}, body: mask(answer.text), bodyBytes: answer.bodyBytes, utf8: answer.utf8, clipped: answer.clipped,
      ...(unknown ? { unknown: [id] } : {}),
    });
    if (isLoad && unknown) return rows;   // the Rules in effect are unknown: nothing more is sent
    if (isLoad && answer.status === 200) {   // the document replaced the global one: put it back and wait until it is in effect
      if (cancelled()) return rows;
      const label = `install-${id}`;
      let put = null;
      try { put = await send(label, 'PUT', rulesUrl, { body: installBody, headers: { ...FIXED_REQUEST_HEADERS }, record: true }); } catch (error) { if (error instanceof CapExceeded) { emit({ kind: 'install', suite: 'rules', after: id, ok: false, outcome: 'not-sent' }); return stopRow(label, 'not-sent'); } }
      const installed = put !== null && put.status === 200 && put.utf8 !== false, putUnknown = put === null || unknownStatus(put.status) || put.utf8 === false;
      emit({ kind: 'install', suite: 'rules', after: id, ok: installed, outcome: put === null ? 'unknown' : 'answered', ...(put === null ? {} : { status: put.status }) });
      if (!installed) return stopRow(label, 'install-failed', putUnknown ? { unknown: [label] } : {});   // a refused reinstall (4xx) is known: the accepted document stays; the cleanup restores the baseline
      const again = await probe(id);
      if (again !== 'ready') return afterProbe(id, again);
    }
  }
  return rows;
}
