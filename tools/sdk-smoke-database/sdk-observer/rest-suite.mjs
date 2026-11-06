// The rest suite (G7, packet 2 of the RTDB closure, owner row 2217): the REST leftovers of the inventory as plain HTTP
// requests, no SDK and no browser. Two profiles (r1-rest, r2-rest) run the same case table, each under its own scope
// `<prefix>/sdk-rest/<profile>`, through the observer's admin REST path (production: the ADC Bearer token and
// x-goog-user-project, as every other admin request of the observer; local: Bearer owner). Each case is one request,
// never retried. Every request carries `accept-encoding: identity` so the recorded content-length is the length of the
// recorded body on both sides.
//
// One row per case: id, method, the path with the scope masked as {scope}, the query string, the selected request
// headers, the request body, the outcome, status, the allowlisted response headers, the body (scope and generated push
// ids masked; a push id is masked only after its 20-character shape is checked, `pushIdShapeOk`) and its byte length.
// Outcomes: answered; clipped (the answer body passed 64 KiB: not complete evidence, the case is not ok, nothing is unknown); unknown-status (a complete answer below 200, 3xx or 5xx to a non-GET: the mutation is unknown); unknown-body (a non-GET answered with a body that is not UTF-8: unknown too);
// unknown (the request may have left and no answer was read: the profile stops); not-sent (the cap refused it: the
// profile stops); blocked (a header value it needs was not in an earlier answer: nothing sent).
import { CapExceeded, RECORDED_RESPONSE_HEADERS, unknownStatus } from './lib.mjs';

export const REST_PROFILES = ['r1-rest', 'r2-rest'];
export const REST_AREA = 'sdk-rest';
export const PUSH_ID = /^[-0-9A-Za-z_]{20}$/;
/** Request headers a case may set; they are recorded on the case row. */
export const RECORDED_REQUEST_HEADERS = ['if-none-match', 'x-http-method-override', 'x-firebase-etag'];
/** Sent with every case, the same on both sides, journalled on the admin-req row only. */
export const FIXED_REQUEST_HEADERS = { 'accept-encoding': 'identity' };
export { RECORDED_RESPONSE_HEADERS };
/** The if-none-match value that stands for this side's own ETag of the etag-get answer. */
export const OWN_ETAG = '{etag}';

const q = s => encodeURIComponent(`"${s}"`);   // a JSON string query value: orderBy="$key" -> orderBy=%22%24key%22
const c = (id, method, path, { query = '', body, headers } = {}) => ({ id, method, path, query, ...(body === undefined ? {} : { body }), ...(headers ? { headers } : {}) });
const own = { 'if-none-match': OWN_ETAG };

/** The case table of one round, in order (the coordinator's G7 list). Paths are relative to the profile scope. */
export const TABLE = [
  c('setup-mix', 'PUT', '/mix.json', { body: '{"a":{".value":3,".priority":2},"b":{".value":"x",".priority":"p"},"c":{".value":true,".priority":1},"d":{"h":1,".priority":3},"e":7,"f":"abc"}' }),
  c('setup-ints', 'PUT', '/ints.json', { body: '{"-1":1,"01":2,"2147483648":3,"10":4,"2":5,"a":6,"B":7}' }),
  c('setup-leaf', 'PUT', '/leaf.json', { body: '"text"' }),
  c('setup-emptied', 'PUT', '/emptied.json', { body: '{"b":{"c":1}}' }),
  c('setup-etag', 'PUT', '/etag.json', { body: '{"x":1}' }),
  c('timeout-5s', 'GET', '/mix.json', { query: 'timeout=5s' }),
  c('timeout-5', 'GET', '/mix.json', { query: 'timeout=5' }),
  c('timeout-abc', 'GET', '/mix.json', { query: 'timeout=abc' }),
  c('timeout-0s', 'GET', '/mix.json', { query: 'timeout=0s' }),
  ...['tiny', 'medium', 'large', 'unlimited', 'foo', '10'].map(v => c(`wsl-${v}`, 'PUT', '/wl.json', { query: `writeSizeLimit=${v}`, body: '{"k":1}' })),
  c('wsl-patch-tiny', 'PATCH', '/wl.json', { query: 'writeSizeLimit=tiny', body: '{"k":1}' }),
  c('print-pretty-get', 'GET', '/mix.json', { query: 'print=pretty' }),
  c('print-pretty-put', 'PUT', '/pr.json', { query: 'print=pretty', body: '{"a":1}' }),
  c('print-bogus-get', 'GET', '/mix.json', { query: 'print=bogus' }),
  c('print-silent-delete', 'DELETE', '/pr.json', { query: 'print=silent' }),
  c('print-silent-post', 'POST', '/prp.json', { query: 'print=silent', body: '"v"' }),
  c('post-scalar', 'POST', '/po1.json', { body: '"hello"' }),
  c('post-scalar-get', 'GET', '/po1.json'),
  c('post-priority', 'POST', '/po2.json', { body: '{"a":1,".priority":5}' }),
  c('post-priority-export', 'GET', '/po2.json', { query: 'format=export' }),
  c('post-null', 'POST', '/po3.json', { body: 'null' }),
  c('post-null-get', 'GET', '/po3.json'),
  c('post-array', 'POST', '/po4.json', { body: '[1,2]' }),
  c('post-array-get', 'GET', '/po4.json'),
  c('post-sv', 'POST', '/po5.json', { body: '{".sv":{"increment":3}}' }),
  c('post-sv-get', 'GET', '/po5.json'),
  c('sv-patch', 'PATCH', '/svp.json', { body: '{"n":{".sv":{"increment":2}}}' }),
  c('sv-patch-get', 'GET', '/svp.json'),
  c('sv-fraction', 'PUT', '/svf.json', { body: '{"n":{".sv":{"increment":1.5}}}' }),
  c('sv-fraction-get', 'GET', '/svf.json'),
  c('sv-bogus', 'PUT', '/svb.json', { body: '{"n":{".sv":"bogus"}}' }),
  c('sv-overflow-put', 'PUT', '/svo.json', { body: '{"n":{".sv":{"increment":1.7976931348623157e308}}}' }),
  c('sv-overflow-patch', 'PATCH', '/svo.json', { body: '{"n":{".sv":{"increment":1.7976931348623157e308}}}' }),
  c('sv-overflow-get', 'GET', '/svo.json'),
  c('order-priority', 'GET', '/mix.json', { query: `orderBy=${q('$priority')}` }),
  c('order-priority-range', 'GET', '/mix.json', { query: `orderBy=${q('$priority')}&startAt=1&endAt=2` }),
  c('order-value-first', 'GET', '/mix.json', { query: `orderBy=${q('$value')}&limitToFirst=3` }),
  c('order-value-last', 'GET', '/mix.json', { query: `orderBy=${q('$value')}&limitToLast=3` }),
  c('order-key-first', 'GET', '/mix.json', { query: `orderBy=${q('$key')}&limitToFirst=3` }),
  c('order-key-ints', 'GET', '/ints.json', { query: `orderBy=${q('$key')}` }),
  c('order-key-start-end', 'GET', '/ints.json', { query: `orderBy=${q('$key')}&startAt=${q('01')}&endAt=${q('2')}` }),
  c('order-key-equal', 'GET', '/ints.json', { query: `orderBy=${q('$key')}&equalTo=${q('10')}` }),
  c('order-key-start-number', 'GET', '/ints.json', { query: `orderBy=${q('$key')}&startAt=2` }),
  c('order-value-unindexed', 'GET', '/ints.json', { query: `orderBy=${q('$value')}&limitToFirst=2` }),
  c('limit-first', 'GET', '/mix.json', { query: 'limitToFirst=2' }),
  c('limit-last', 'GET', '/mix.json', { query: 'limitToLast=2' }),
  c('order-priority-export', 'GET', '/mix.json', { query: `orderBy=${q('$priority')}&limitToFirst=2&format=export` }),
  c('shallow-leaf', 'GET', '/leaf.json', { query: 'shallow=true' }),
  c('shallow-missing', 'GET', '/missing.json', { query: 'shallow=true' }),
  c('shallow-orderby', 'GET', '/mix.json', { query: `shallow=true&orderBy=${q('$key')}` }),
  c('shallow-limit', 'GET', '/mix.json', { query: 'shallow=true&limitToFirst=1' }),
  c('shallow-export', 'GET', '/mix.json', { query: 'shallow=true&format=export' }),
  c('etag-get', 'GET', '/etag.json', { headers: { 'x-firebase-etag': 'true' } }),
  c('etag-inm-match', 'GET', '/etag.json', { headers: own }),
  c('etag-inm-bogus', 'GET', '/etag.json', { headers: { 'if-none-match': '"bogus"' } }),
  c('etag-inm-put', 'PUT', '/etag2.json', { body: '{"x":1}', headers: own }),
  c('etag-inm-shallow', 'GET', '/etag.json', { query: 'shallow=true', headers: own }),
  c('override-put', 'POST', '/ov1.json', { body: '{"a":1}', headers: { 'x-http-method-override': 'PUT' } }),
  c('override-put-get', 'GET', '/ov1.json'),
  c('override-delete', 'POST', '/ov1.json', { headers: { 'x-http-method-override': 'DELETE' } }),
  c('override-delete-get', 'GET', '/ov1.json'),
  c('override-get', 'GET', '/ovg.json', { headers: { 'x-http-method-override': 'DELETE' } }),
  c('callback-cb', 'GET', '/leaf.json', { query: 'callback=cb' }),
  c('callback-script', 'GET', '/leaf.json', { query: `callback=${encodeURIComponent('</script>')}` }),
  c('callback-alert', 'GET', '/leaf.json', { query: `callback=${encodeURIComponent('alert(1)//')}` }),
  c('callback-digit', 'GET', '/leaf.json', { query: 'callback=1a' }),
  c('callback-dots', 'GET', '/leaf.json', { query: `callback=${encodeURIComponent('a.b_$1')}` }),
  c('download-file', 'GET', '/leaf.json', { query: 'download=file.json' }),
  c('download-escaped', 'GET', '/leaf.json', { query: 'download=a%20b%2Fc%22d' }),
  c('emptied-patch', 'PATCH', '/emptied.json', { body: '{"b/c":null,"b/.priority":1}' }),
  c('emptied-export', 'GET', '/emptied.json', { query: 'format=export' }),
  c('malformed-zz', 'GET', '/bad%zz.json'),
  c('malformed-nul', 'GET', '/a%00b.json'),
  c('end-delete', 'DELETE', '.json'),
  c('end-get', 'GET', '.json'),
];
/**
 * Dropped to keep one production run at 150 direct requests or fewer, in the ruled order. The ruled list (the first
 * seven) leaves 2 x 73 + 6 = 152; `end-get` is the one further drop (the run's own cleanup reads the prefix back null).
 */
export const DROP_ORDER = ['wsl-patch-tiny', 'print-silent-post', 'shallow-export', 'download-escaped', 'malformed-nul', 'callback-dots', 'override-get', 'end-get'];
export const REST_CASES = TABLE.map(x => x.id).filter(id => !DROP_ORDER.includes(id));

const profileScope = () => ({ '.read': true, '.write': true, mix: { '.indexOn': ['.value'] } });
/** The whole Rules document of a rest run: the profile scopes open, everything else denied (same safety as events-rules.mjs). */
export function restRules(prefix) {
  if (typeof prefix !== 'string' || prefix.length > 256 || !/^\/[A-Za-z0-9_-]+(?:\/[A-Za-z0-9_-]+)*$/.test(prefix)) throw Error('Invalid rules prefix');
  if (prefix.slice(1).split('/').some(part => ['__proto__', 'constructor', 'prototype'].includes(part))) throw Error('Invalid rules prefix');
  const rules = { '.read': false, '.write': false }; let target = rules;
  for (const part of prefix.slice(1).split('/')) target = target[part] = {};
  target[REST_AREA] = Object.fromEntries(REST_PROFILES.map(name => [name, profileScope()]));
  return { rules };
}

/** Hides the scope and the checked push ids of this side; every other byte stays. */
export function maskText(text, { scope, pushIds }) {
  if (typeof text !== 'string') return text;
  let out = text.split(scope).join('{scope}');
  for (const id of pushIds) out = out.split(id).join('{pushId}');
  return out;
}
const generatedName = text => { try { const v = JSON.parse(text); return v && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === 1 && typeof v.name === 'string' ? v.name : null; } catch { return null; } };

/**
 * One profile: every kept case once, in order. `send(label, method, url, {body, headers, record})` is the observer's
 * admin REST (counted, journalled, never retried); `url(rel, query)` builds the request URL of a path under the scope.
 */
export async function runRestProfile({ send, url, scope, emit = () => {}, cases = REST_CASES, cancelled = () => false }) {
  if (typeof scope !== 'string' || !/^[A-Za-z0-9_-]+(?:\/[A-Za-z0-9_-]+)*$/.test(scope)) throw Error('Invalid rest scope');
  const rows = [], pushIds = [], seen = { etag: null }, mask = text => maskText(text, { scope, pushIds });
  const done = row => { const full = { kind: 'case', suite: 'rest', ...row }; rows.push(full); emit(full); return full; };
  for (const id of cases) {
    if (cancelled()) return rows;   // the profile was abandoned at its deadline: nothing more is sent and the skipped cases are not recorded
    const spec = TABLE.find(x => x.id === id);
    if (!spec) throw Error(`unknown rest case ${id}`);
    const headers = {}, recorded = {};
    let blocked = null;
    for (const [name, value] of Object.entries(spec.headers ?? {})) {
      if (value === OWN_ETAG && seen.etag === null) blocked = 'no ETag in the answer of etag-get';
      headers[name] = value === OWN_ETAG ? seen.etag : value;
      recorded[name] = value;
    }
    if (blocked) { done({ id, ok: false, outcome: 'blocked', error: blocked }); continue; }
    const request = { method: spec.method, path: `{scope}${spec.path}`, query: spec.query, requestHeaders: recorded, requestBody: spec.body ?? null };
    let answer;
    try { answer = await send(id, spec.method, url(`${scope}${spec.path}`, spec.query), { ...(spec.body === undefined ? {} : { body: spec.body }), headers: { ...FIXED_REQUEST_HEADERS, ...headers }, record: true }); }
    catch (error) {
      const notSent = error instanceof CapExceeded;
      done({ id, ok: false, outcome: notSent ? 'not-sent' : 'unknown', ...request, error: `${error?.name}: ${String(error?.message).slice(0, 200)}`, ...(!notSent && spec.method !== 'GET' ? { unknown: [id] } : {}) });
      return rows;   // transport uncertainty or the cap: nothing more is sent from this profile
    }
    if (id === 'etag-get' && typeof answer.headers?.etag === 'string') seen.etag = answer.headers.etag;
    const name = spec.method === 'POST' && !spec.headers?.['x-http-method-override'] && answer.status === 200 ? generatedName(answer.text) : null;
    const shapeOk = name !== null && PUSH_ID.test(name);
    if (shapeOk) pushIds.push(name);
    const isPost = spec.method === 'POST' && !spec.headers?.['x-http-method-override'];
    const clipped = answer.clipped === true, unreadable = spec.method !== 'GET' && answer.utf8 === false, unknown = spec.method !== 'GET' && (unknownStatus(answer.status) || unreadable);   // a body that is not UTF-8 cannot be judged: the mutation's outcome is unknown
    done({
      id, ok: !unknown && !clipped, outcome: unreadable ? 'unknown-body' : unknown ? 'unknown-status' : clipped ? 'clipped' : 'answered', ...request, status: answer.status, responseHeaders: answer.headers ?? {}, body: mask(answer.text), bodyBytes: answer.bodyBytes, utf8: answer.utf8, clipped: answer.clipped,
      ...(isPost ? { pushIdShapeOk: shapeOk } : {}), ...(unknown ? { unknown: [id] } : {}),
    });
  }
  return rows;
}
