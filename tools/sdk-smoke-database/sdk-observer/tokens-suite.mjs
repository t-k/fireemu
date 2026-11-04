// The tokens suite (G10, packet 5 of the RTDB closure, owner row 2217): how the REST endpoint answers credentials that
// are NOT valid. Plain HTTP requests, no SDK and no browser, no new credential: every token is generated here from
// fixed bytes (credentials(), the same on both sides), none is a real ID token or API key, and the one real credential
// is the observer's own ADC token, sent once as `auth=` (the `{adc}` placeholder, resolved by the admin REST at send
// time and never journalled; locally the owner token). Two profiles (r1-tokens, r2-tokens) run the same case table,
// each under its own scope `<prefix>/sdk-tokens/<profile>`, through the observer's admin REST path.
//
// One global Rules document (tokensRules), installed once by the observer: the root denied, `<prefix>/sdk-tokens/ready`
// readable, and in each profile scope `pub` (read true), `deny` (read false) and `authreq` (`auth != null`).
// Each profile starts with the ready probe of the rules suite (an anonymous GET of the ready path, at most MAX_PROBES
// times, `probeDelayMs` apart, until it reads 200), then the seed (one admin PUT) and the GETs of the table.
//
// Identities: `admin` (the observer's credential), `anonymous` (no Authorization header) and `credential` (no admin
// header; the case's token as `auth=`, `access_token=` or `Authorization: Bearer`). The rows record the request as a
// template (`auth={cred}`, `Bearer {cred}`): the token is fixed by the case id and this file (pinned by the manifest).
// One row per case in the rules suite's form. Outcomes: answered; clipped; unknown-status and unknown-body (the seed
// PUT is an unknown mutation; a GET is an unknown observation, not ok); unknown (no answer was read: the profile stops); not-sent (the cap refused it: the profile stops).
import { createHash, createHmac } from 'node:crypto';
import { CapExceeded, unknownStatus } from './lib.mjs';
import { FIXED_REQUEST_HEADERS, maskText } from './rest-suite.mjs';
import { MAX_PROBES, readyPath } from './rules-suite.mjs';

export const TOKENS_PROFILES = ['r1-tokens', 'r2-tokens'];
export const TOKENS_AREA = 'sdk-tokens';
export const IDENTITIES = ['admin', 'anonymous', 'credential'];
export const TRANSPORTS = ['auth', 'bearer', 'access_token'];
export const GROUPS = ['seed', 'control', ...TRANSPORTS];
export const CREDENTIAL_KINDS = ['empty', 'random', 'none_other', 'none_own', 'rs256', 'hs256', 'two_seg', 'huge', 'pct', 'null', 'adc'];
/** The case's token in a recorded query or header; the ADC token's placeholder, resolved by the admin REST only. */
export const CRED = '{cred}';
export const ADC = '{adc}';
/** The audience of the wrong-project tokens: a demo id, which no real project can have. */
export const OTHER_PROJECT = 'demo-not-this-project';

/** `n` fixed bytes for `label`: SHA-256 in counter mode over a versioned seed. Nothing random, nothing secret. */
export function seededBytes(label, n) {
  const out = [];
  for (let i = 0, len = 0; len < n; i++) { const block = createHash('sha256').update(`fireemu-tokens-v1:${label}:${i}`).digest(); out.push(block); len += block.length; }
  return Buffer.concat(out).subarray(0, n);
}
/** The throw-away HS256 key (fixed bytes, used nowhere else). */
export const HS256_KEY = seededBytes('hs256-key', 32);
const part = value => Buffer.from(JSON.stringify(value)).toString('base64url');
const claims = (aud, { iat, exp }, extra = {}) => ({ iss: `https://securetoken.google.com/${aud}`, aud, auth_time: iat, user_id: 'tokens-user', sub: 'tokens-user', iat, exp, firebase: { identities: {}, sign_in_provider: 'custom' }, ...extra });
const PAST = { iat: 1700000000, exp: 1700003600 }, FUTURE = { iat: 1700000000, exp: 4102444800 };

/** Every credential of the table for a target project (`projectId` is the aud of the own-project tokens). */
export function credentials(projectId) {
  const none = aud => `${part({ alg: 'none', typ: 'JWT' })}.${part(claims(aud, PAST))}.`;
  const rsHead = part({ alg: 'RS256', kid: seededBytes('rs256-kid', 20).toString('hex'), typ: 'JWT' }), signature = seededBytes('rs256-signature', 256).toString('base64url');
  const hsSigned = `${part({ alg: 'HS256', typ: 'JWT' })}.${part(claims(projectId, FUTURE))}`;
  return {
    empty: '',
    random: seededBytes('random', 20).toString('hex'),
    none_other: none(OTHER_PROJECT),
    none_own: none(projectId),
    rs256: `${rsHead}.${part(claims(projectId, FUTURE))}.${signature}`,
    hs256: `${hsSigned}.${createHmac('sha256', HS256_KEY).update(hsSigned).digest('base64url')}`,
    two_seg: hsSigned,
    huge: `${rsHead}.${part(claims(projectId, FUTURE, { pad: [...seededBytes('huge-pad', 3000)].map(b => String.fromCharCode(97 + (b % 26))).join('') }))}.${signature}`,
    pct: 'a b+c/d=e%f&g#h?i"j',
    null: 'null',
    adc: ADC,
  };
}

const c = (id, group, identity, path, { method = 'GET', query = '', body, headers, credential } = {}) => ({ id, group, identity, method, path, query, ...(body === undefined ? {} : { body }), ...(headers ? { headers } : {}), ...(credential ? { credential } : {}) });
const via = (transport, credential, path = '/authreq.json', id = `${transport === 'access_token' ? 'at' : transport}-${credential.replace('_', '-')}`) =>
  c(id, transport, 'credential', path, transport === 'bearer' ? { headers: { authorization: `Bearer ${CRED}` }, credential } : { query: `${transport}=${CRED}`, credential });

/** The seed of one profile scope, one admin PUT. */
export const SEED = { pub: { v: 1 }, deny: { v: 2 }, authreq: { v: 3 } };
/** The case table of one round, in order: the seed, the controls, then the credentials by transport. */
export const TABLE = [
  c('seed', 'seed', 'admin', '.json', { method: 'PUT', body: JSON.stringify(SEED) }),
  c('ctl-anon-authreq', 'control', 'anonymous', '/authreq.json'),
  c('ctl-anon-pub', 'control', 'anonymous', '/pub.json'),
  c('ctl-admin-authreq', 'control', 'admin', '/authreq.json'),
  ...CREDENTIAL_KINDS.map(kind => via('auth', kind)),
  via('auth', 'adc', '/deny.json', 'auth-adc-deny'),
  via('auth', 'random', '/pub.json', 'auth-random-pub'),
  ...['empty', 'random', 'none_own', 'rs256', 'null'].map(kind => via('bearer', kind)),
  via('bearer', 'random', '/pub.json', 'bearer-random-pub'),
  ...['empty', 'random', 'rs256'].map(kind => via('access_token', kind)),
  via('access_token', 'random', '/pub.json', 'at-random-pub'),
];
export const TOKENS_CASES = TABLE.map(x => x.id);

const PREFIX_RE = /^\/[A-Za-z0-9_-]+(?:\/[A-Za-z0-9_-]+)*$/;
/** The whole Rules document of a tokens run. */
export function tokensRules(prefix) {
  if (typeof prefix !== 'string' || prefix.length > 256 || !PREFIX_RE.test(prefix)) throw Error('Invalid rules prefix');
  if (prefix.slice(1).split('/').some(p => ['__proto__', 'constructor', 'prototype'].includes(p))) throw Error('Invalid rules prefix');
  const rules = { '.read': false, '.write': false }; let target = rules;
  for (const p of prefix.slice(1).split('/')) target = target[p] = {};
  target[TOKENS_AREA] = { ready: { '.read': true }, ...Object.fromEntries(TOKENS_PROFILES.map(name => [name, { pub: { '.read': true }, deny: { '.read': false }, authreq: { '.read': 'auth != null' } }])) };
  return { rules };
}

const SCOPE_RE = /^[A-Za-z0-9_-]+(?:\/[A-Za-z0-9_-]+)*\/[A-Za-z0-9_-]+$/, PROJECT_RE = /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/;
/** The request options and query of one case: the token in its transport; the ADC token left as its placeholder. */
export function credentialRequest(spec, token) {
  if (spec.identity !== 'credential') return { query: spec.query, options: spec.identity === 'anonymous' ? { anonymous: true } : {} };
  if (spec.group === 'bearer') { if (spec.credential === 'adc') throw Error('the ADC token goes only in auth='); return { query: spec.query, options: { anonymous: true, bearer: token } }; }
  const adc = spec.credential === 'adc';
  return { query: spec.query.replace(CRED, adc ? ADC : encodeURIComponent(token)), options: { anonymous: true, ...(adc ? { resolveAdc: true } : {}) } };
}

/**
 * One profile. `send(label, method, url, {body, headers, record, anonymous, bearer, resolveAdc})` is the observer's
 * admin REST (counted, journalled, never retried); `url(rel, query)` builds a request URL; `projectId` is the target's
 * project (the aud of the own-project tokens, masked as {project} in the answers).
 */
export async function runTokensProfile({ send, url, scope, projectId, emit = () => {}, cases = TOKENS_CASES, cancelled = () => false, sleep = ms => new Promise(r => setTimeout(r, ms)), probeDelayMs = 2000, maxProbes = MAX_PROBES }) {
  if (typeof scope !== 'string' || !SCOPE_RE.test(scope)) throw Error('Invalid tokens scope');
  if (typeof projectId !== 'string' || !PROJECT_RE.test(projectId)) throw Error('Invalid project id');
  const rows = [], tokens = credentials(projectId), mask = text => (typeof text === 'string' ? maskText(text, { scope, pushIds: [] }).split(projectId).join('{project}') : text);
  const done = row => { const full = { kind: 'case', suite: 'tokens', ...row }; rows.push(full); emit(full); return full; };
  for (let attempt = 1; ; attempt++) {   // the ready probe: the global document is in effect once this reads 200
    if (cancelled()) return rows;
    let answer;
    try { answer = await send(`ready-start-${attempt}`, 'GET', url(readyPath(scope), ''), { headers: { ...FIXED_REQUEST_HEADERS }, record: true, anonymous: true }); }
    catch (error) { const outcome = error instanceof CapExceeded ? 'not-sent' : 'unknown'; emit({ kind: 'probe', suite: 'tokens', after: 'start', attempt, outcome, ready: false }); rows.push({ id: 'ready-start', ok: false, outcome }); return rows; }
    const ready = answer.status === 200;
    emit({ kind: 'probe', suite: 'tokens', after: 'start', attempt, outcome: 'answered', status: answer.status, ready });
    if (ready) break;
    if (attempt >= maxProbes) { rows.push({ id: 'ready-start', ok: false, outcome: 'not-ready' }); return rows; }
    await sleep(probeDelayMs);
  }
  for (const id of cases) {
    if (cancelled()) return rows;   // the profile was abandoned at its deadline: nothing more is sent
    const spec = TABLE.find(x => x.id === id);
    if (!spec) throw Error(`unknown tokens case ${id}`);
    const head = { id, group: spec.group, identity: spec.identity }, { query, options } = credentialRequest(spec, tokens[spec.credential]);
    const request = { method: spec.method, path: `{scope}${spec.path}`, query: spec.query, requestHeaders: { ...(spec.headers ?? {}) }, requestBody: spec.body ?? null };
    let answer;
    try { answer = await send(id, spec.method, url(`${scope}${spec.path}`, query), { ...(spec.body === undefined ? {} : { body: spec.body }), headers: { ...FIXED_REQUEST_HEADERS }, record: true, ...options }); }
    catch (error) {
      const notSent = error instanceof CapExceeded;
      done({ ...head, ok: false, outcome: notSent ? 'not-sent' : 'unknown', ...request, error: `${error?.name}: ${String(error?.message).slice(0, 200)}`, ...(!notSent ? (spec.method !== 'GET' ? { unknown: [id] } : { unknownObservation: [id] }) : {}) });
      return rows;   // transport uncertainty or the cap: nothing more is sent from this profile
    }
    // A status the case cannot judge (5xx, 3xx, below 200) or a body that is not UTF-8 is no observation. For the seed (a mutation) its outcome is
    // unknown (exit 3, A2); for a GET nothing changed, so the case is only not ok and listed as an unknown observation (it never counts toward the 54).
    const clipped = answer.clipped === true, mutation = spec.method !== 'GET', unreadable = answer.utf8 === false, unjudgeable = unknownStatus(answer.status) || unreadable;
    done({
      ...head, ok: !unjudgeable && !clipped, outcome: unreadable ? 'unknown-body' : unjudgeable ? 'unknown-status' : clipped ? 'clipped' : 'answered', ...request, status: answer.status, responseHeaders: answer.headers ?? {}, body: mask(answer.text), bodyBytes: answer.bodyBytes, utf8: answer.utf8, clipped: answer.clipped,
      ...(unjudgeable ? (mutation ? { unknown: [id] } : { unknownObservation: [id] }) : {}),
    });
  }
  return rows;
}
