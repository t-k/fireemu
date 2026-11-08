// The rules-syntax suite (owner row 2350): the Rules constructs fireemu refuses when Rules load, or reads as a rule error, while
// the official emulator (firebase-database-emulator 4.11.2) loads and evaluates them: `query.endBefore`, `query.isOrderByChild()`,
// the names `OrderByKey`, `OrderByValue` and `OrderByPriority`, `http.encodeURL()`, a method read without a call and a call whose
// callee is a ternary. Plain HTTP, no SDK, no browser. Two profiles (r1-rules-syntax, r2-rules-syntax) run the same table, each
// under its own scope `<prefix>/rules-syntax/<profile>`, through the observer's admin REST path.
//
// Each construct has its own Rules document (DOCUMENTS), so a refusal of one construct does not hide the others. A profile seeds
// its scope as the admin, then for each document: PUTs it to `.settings/rules.json` (the `load-<doc>` row records the answer).
// 400 is a refusal: the Rules in effect are unchanged and the document's cases are recorded as `not-loaded` without a request.
// 200 replaced the Rules: an anonymous GET of `<prefix>/rules-syntax/ready/<doc>` (readable in that document only, so a 200 proves
// that this document is in effect) repeats at most MAX_PROBES times, `probeDelayMs` apart, then the document's cases run.
// Any other load answer stops the profile with the load listed as an unknown mutation (the Rules in effect are unknown).
// Every document grants only reads and writes under the prefix; the observer's cleanup deletes the prefix and puts the baseline
// Rules back byte-equal (observer.mjs `finally`).
//
// Case identities: `admin` (the seed: ADC Bearer token and x-goog-user-project in production, Bearer owner locally), `anonymous`
// (no Authorization and no x-goog-user-project header) and `override` (the admin credential with `auth_variable_override` in the
// query, as packet 3 recorded it: the Rules see that auth object).
import { CapExceeded, unknownStatus } from './lib.mjs';
import { FIXED_REQUEST_HEADERS, maskText } from './rest-suite.mjs';

export const RULES_SYNTAX_PROFILES = ['r1-rules-syntax', 'r2-rules-syntax'];
export const RULES_SYNTAX_AREA = 'rules-syntax';
export const MAX_PROBES = 20;

const q = s => encodeURIComponent(`"${s}"`);   // a JSON string query value
export const OVERRIDE_PARAM = 'auth_variable_override';
/** The `override` identity: the admin credential with `auth_variable_override` naming uid u1, as the rules suite sends it. */
export const OVERRIDE_AUTH = { uid: 'u1' };
const withOverride = query => `${query ? `${query}&` : ''}${OVERRIDE_PARAM}=${encodeURIComponent(JSON.stringify(OVERRIDE_AUTH))}`;

/** The seed of one profile scope, one admin PUT. */
export const SEED = {
  eb: { a: 1, b: 2, c: 3 },
  ioc: { a: { h: 1 }, b: { h: 2 }, c: { h: 3 } },
  obk: { a: 1, b: 2 },
  obv: { a: 1, b: 2, c: 3 },
  obp: { a: { '.value': 1, '.priority': 2 }, b: { '.value': 2, '.priority': 1 } },
  enc: { a: 1, p: 1 },
  mnc: { a: 1, z: 1 },
  mnt: { s: 1, n: 1 },
  tcl: { a: { k: 1 }, n: { k: 1 }, w: { k: 1 } },
};

const TERNARY = "(true ? data.child : data.parent)";
/**
 * One document per construct: `scope` is the Rules of one profile scope (the same in both profiles); `cases` are the requests
 * made while it is in effect, each an allowed or a refused control on the official emulator.
 */
export const DOCUMENTS = [
  {
    id: 'eb', construct: 'query.endBefore',
    scope: { eb: { '.read': "query.endBefore == 'b'", w: { '.write': 'query.endBefore == null' }, x: { '.write': 'query.endBefore != null' } } },
    cases: [
      ['eb-allow', 'GET', '/eb.json', `orderBy=${q('$key')}&endBefore=${q('b')}&limitToLast=2`],
      ['eb-deny-value', 'GET', '/eb.json', `orderBy=${q('$key')}&endBefore=${q('c')}`],
      ['eb-deny-endat', 'GET', '/eb.json', `orderBy=${q('$key')}&endAt=${q('b')}`],
      ['eb-deny-plain', 'GET', '/eb.json', ''],
      ['eb-write-null', 'PUT', '/eb/w.json', '', '1'],
      ['eb-write-set', 'PUT', '/eb/x.json', '', '1'],
    ],
  },
  {
    id: 'ioc', construct: 'query.isOrderByChild()',
    scope: { ioc: { '.read': "query.isOrderByChild('h')", '.indexOn': ['h'], w: { '.write': "!query.isOrderByChild('h')" }, x: { '.write': "query.isOrderByChild('h')" } } },
    cases: [
      ['ioc-allow', 'GET', '/ioc.json', `orderBy=${q('h')}&limitToFirst=2`],
      ['ioc-deny-key', 'GET', '/ioc.json', `orderBy=${q('$key')}`],
      ['ioc-deny-plain', 'GET', '/ioc.json', ''],
      ['ioc-write-not', 'PUT', '/ioc/w.json', '', '1'],
      ['ioc-write-is', 'PUT', '/ioc/x.json', '', '1'],
    ],
  },
  {
    id: 'obk', construct: 'OrderByKey',
    scope: { obk: { '.read': 'query.orderBy == OrderByKey', w: { '.write': 'query.orderBy == OrderByKey' } } },
    cases: [
      ['obk-allow-key', 'GET', '/obk.json', `orderBy=${q('$key')}&limitToFirst=1`],
      ['obk-plain', 'GET', '/obk.json', ''],
      ['obk-deny-priority', 'GET', '/obk.json', `orderBy=${q('$priority')}`],
      ['obk-write', 'PUT', '/obk/w.json', '', '1'],
    ],
  },
  {
    id: 'obv', construct: 'OrderByValue',
    scope: { obv: { '.read': 'query.orderBy == OrderByValue', '.indexOn': '.value' } },
    cases: [
      ['obv-allow', 'GET', '/obv.json', `orderBy=${q('$value')}&equalTo=2`],
      ['obv-deny-key', 'GET', '/obv.json', `orderBy=${q('$key')}&equalTo=${q('b')}`],
      ['obv-deny-plain', 'GET', '/obv.json', ''],
    ],
  },
  {
    id: 'obp', construct: 'OrderByPriority',
    scope: { obp: { '.read': 'query.orderBy == OrderByPriority' } },
    cases: [
      ['obp-allow', 'GET', '/obp.json', `orderBy=${q('$priority')}&limitToFirst=1`],
      ['obp-deny-key', 'GET', '/obp.json', `orderBy=${q('$key')}`],
      ['obp-deny-plain', 'GET', '/obp.json', ''],
    ],
  },
  {
    id: 'enc', construct: 'http.encodeURL()',
    scope: { enc: { a: { '.read': "http.encodeURL('a b') == 'a%20b'" }, p: { '.read': "http.encodeURL('a b') == 'a+b'" }, w: { '.write': "http.encodeURL('a b') == 'a%20b'" } } },
    cases: [
      ['enc-allow', 'GET', '/enc/a.json', ''],
      ['enc-deny', 'GET', '/enc/p.json', ''],
      ['enc-write', 'PUT', '/enc/w.json', '', '1'],
    ],
  },
  {
    id: 'mnc', construct: 'a method read without a call',
    scope: { mnc: { a: { '.read': 'auth.uid.contains != null' }, z: { '.read': 'auth.uid.contains == null' }, w: { '.write': 'auth.uid.contains != null' } } },
    cases: [
      ['mnc-allow', 'GET', '/mnc/a.json', '', undefined, 'override'],
      ['mnc-deny', 'GET', '/mnc/a.json', ''],
      ['mnc-anon-null', 'GET', '/mnc/z.json', ''],
      ['mnc-write', 'PUT', '/mnc/w.json', '', '1', 'override'],
    ],
  },
  {
    id: 'mnt', construct: 'a method read without a call, through a ternary',
    scope: { mnt: { s: { '.read': "(now > 0 ? 'abc'.contains : 'x') != null" }, n: { '.read': "(now > 0 ? data.child : 'x') == null" } } },
    cases: [
      ['mnt-string-allow', 'GET', '/mnt/s.json', ''],
      ['mnt-snapshot-deny', 'GET', '/mnt/n.json', ''],
    ],
  },
  {
    id: 'tcl', construct: 'a call whose callee is a ternary',
    scope: { tcl: { a: { '.read': `${TERNARY}('k').exists()` }, n: { '.read': `${TERNARY}('zz').exists()` }, w: { '.write': `${TERNARY}('k').exists()` } } },
    cases: [
      ['tcl-allow', 'GET', '/tcl/a.json', ''],
      ['tcl-deny', 'GET', '/tcl/n.json', ''],
      ['tcl-write', 'PUT', '/tcl/w.json', '', '1'],
    ],
  },
];

/** The case table of one round, in order: the seed, then for each document its load row and its cases. */
export const TABLE = [
  { id: 'seed', doc: null, identity: 'admin', method: 'PUT', path: '.json', query: '', body: JSON.stringify(SEED) },
  ...DOCUMENTS.flatMap(d => [
    { id: `load-${d.id}`, doc: d.id, identity: 'admin', method: 'PUT', path: '/.settings/rules.json', query: '' },
    ...d.cases.map(([id, method, path, query, body, identity = 'anonymous']) => ({ id, doc: d.id, identity, method, path, query: identity === 'override' ? withOverride(query) : query, ...(body === undefined ? {} : { body }) })),
  ]),
];
export const RULES_SYNTAX_CASES = TABLE.map(x => x.id);

const PREFIX_RE = /^\/[A-Za-z0-9_-]+(?:\/[A-Za-z0-9_-]+)*$/;
/** The Rules document `docId` of a run under `prefix`: root denied, its own ready path readable, its scope Rules in each profile. */
export function syntaxRules(prefix, docId) {
  if (typeof prefix !== 'string' || prefix.length > 256 || !PREFIX_RE.test(prefix)) throw Error('Invalid rules prefix');
  if (prefix.slice(1).split('/').some(part => ['__proto__', 'constructor', 'prototype'].includes(part))) throw Error('Invalid rules prefix');
  const doc = DOCUMENTS.find(d => d.id === docId);
  if (!doc) throw Error(`unknown rules-syntax document ${docId}`);
  const rules = { '.read': false, '.write': false }; let target = rules;
  for (const part of prefix.slice(1).split('/')) target = target[part] = {};
  target[RULES_SYNTAX_AREA] = { ready: { [doc.id]: { '.read': true } }, ...Object.fromEntries(RULES_SYNTAX_PROFILES.map(name => [name, doc.scope])) };
  return { rules };
}
/** The ready path (with its .json) of document `docId`, from a profile scope `<prefix>/rules-syntax/<profile>`. */
export const readyPath = (scope, docId) => `${scope.split('/').slice(0, -1).join('/')}/ready/${docId}.json`;

const SCOPE_RE = /^[A-Za-z0-9_-]+(?:\/[A-Za-z0-9_-]+)*\/[A-Za-z0-9_-]+$/;

/**
 * One profile. `send(label, method, url, {body, headers, record, anonymous})` is the observer's admin REST (counted, journalled,
 * never retried); `url(rel, query)` builds a request URL; `prefix` is the run prefix (with its leading slash) the documents are
 * built for. Returns the case rows (and a final failure row when the profile stopped on a probe); probe rows go to `emit` only.
 */
export async function runRulesSyntaxProfile({ send, url, scope, prefix, emit = () => {}, cancelled = () => false, sleep = ms => new Promise(r => setTimeout(r, ms)), probeDelayMs = 2000, maxProbes = MAX_PROBES }) {
  if (typeof scope !== 'string' || !SCOPE_RE.test(scope)) throw Error('Invalid rules scope');
  if (scope !== `${prefix?.slice(1)}/${RULES_SYNTAX_AREA}/${scope.split('/').at(-1)}`) throw Error('scope is not under the prefix');
  const rows = [], mask = text => maskText(text, { scope, pushIds: [] });
  const done = row => { const full = { kind: 'case', suite: 'rules-syntax', ...row }; rows.push(full); emit(full); return full; };
  const stop = (id, outcome) => { rows.push({ id, ok: false, outcome }); return rows; };
  const probe = async docId => {   // 'ready' once it read 200; 'not-ready', 'unknown', 'not-sent' or 'cancelled' otherwise
    for (let attempt = 1; attempt <= maxProbes; attempt++) {
      if (cancelled()) return 'cancelled';
      let answer;
      try { answer = await send(`ready-${docId}-${attempt}`, 'GET', url(readyPath(scope, docId), ''), { headers: { ...FIXED_REQUEST_HEADERS }, record: true, anonymous: true }); }
      catch (error) { const outcome = error instanceof CapExceeded ? 'not-sent' : 'unknown'; emit({ kind: 'probe', suite: 'rules-syntax', after: docId, attempt, outcome, ready: false }); return outcome; }
      const ready = answer.status === 200;
      emit({ kind: 'probe', suite: 'rules-syntax', after: docId, attempt, outcome: 'answered', status: answer.status, ready });
      if (ready) return 'ready';
      if (attempt < maxProbes) await sleep(probeDelayMs);
    }
    return 'not-ready';
  };
  let loaded = null;   // the last document this profile loaded (200) and probed (200); a case runs only under its own document
  for (const spec of TABLE) {
    if (cancelled()) return rows;
    const head = { id: spec.id, doc: spec.doc, identity: spec.identity };
    const isLoad = spec.id.startsWith('load-');
    if (!isLoad && spec.doc !== null && loaded !== spec.doc) { done({ ...head, ok: true, outcome: 'not-loaded' }); continue; }
    const body = isLoad ? JSON.stringify(syntaxRules(prefix, spec.doc)) : spec.body;
    const rel = isLoad ? '.settings/rules.json' : `${scope}${spec.path}`;
    const request = { method: spec.method, path: isLoad ? spec.path : `{scope}${spec.path}`, query: spec.query, requestBody: body ?? null };
    let answer;
    try { answer = await send(spec.id, spec.method, url(rel, spec.query), { ...(body === undefined ? {} : { body }), headers: { ...FIXED_REQUEST_HEADERS }, record: true, ...(spec.identity === 'anonymous' ? { anonymous: true } : {}) }); }
    catch (error) {
      const notSent = error instanceof CapExceeded;
      done({ ...head, ok: false, outcome: notSent ? 'not-sent' : 'unknown', ...request, error: `${error?.name}: ${String(error?.message).slice(0, 200)}`, ...(!notSent && spec.method !== 'GET' ? { unknown: [spec.id] } : {}) });
      return rows;   // transport uncertainty or the cap: nothing more is sent from this profile
    }
    const clipped = answer.clipped === true, unreadable = spec.method !== 'GET' && answer.utf8 === false;
    // A load is a Rules answer only when it is 200 or 400; anything else leaves the Rules in effect unknown.
    const unknown = spec.method !== 'GET' && (unknownStatus(answer.status) || unreadable || (isLoad && answer.status !== 200 && answer.status !== 400));
    done({
      ...head, ok: !unknown && !clipped, outcome: unreadable ? 'unknown-body' : unknown ? 'unknown-status' : clipped ? 'clipped' : 'answered', ...request, status: answer.status, responseHeaders: answer.headers ?? {}, body: mask(answer.text), bodyBytes: answer.bodyBytes, utf8: answer.utf8, clipped: answer.clipped,
      ...(unknown ? { unknown: [spec.id] } : {}),
    });
    if (unknown || (isLoad && clipped)) return rows;   // a clipped load answer is not a Rules answer: the cleanup restores the baseline
    if (isLoad && answer.status === 200) {
      const verdict = await probe(spec.doc);
      if (verdict === 'cancelled') return rows;
      if (verdict !== 'ready') return stop(`ready-${spec.doc}`, verdict);   // a GET: never an unknown mutation
      loaded = spec.doc;
    }
  }
  return rows;
}
