// The comparison of the rules-syntax suite (owner 2350): a local reduced journal against a recorded one.
//
// Every answer is first given a shape, and only the shapes production has already been recorded answering are known (RECORDED_SHAPES,
// each with the run and case it was recorded in). The layout is judged by the recorded byte counts (bodyBytes and content-length),
// with the exact JSON headers production sent; anything else, an answer outside 200/400/401, other headers, a clipped or unreadable
// body, is `unknown`, and a case with an unknown side is NEEDS_REVIEW, never MATCH or MISMATCH. A case whose two production rounds
// differ is NEEDS_REVIEW too. A case is MATCH when both sides have the same shape, status, body, body bytes and headers.
import { DOCUMENTS, RULES_SYNTAX_PROFILES, TABLE, syntaxRules } from './sdk-observer/rules-syntax-suite.mjs';
import { KIND } from './rtdb-sdk-rules-syntax-fixture.mjs';

/** The production prefix; the local entry uses the same one, so load error columns (which count the prefix) compare. */
export const PREFIX = '/sdkrulesyntax';
export const DENIED_BODY = '{\n  "error" : "Permission denied"\n}\n';
export const ACCEPTED_BODY = '{"status":"ok"}';
/** The shapes a production answer can take, each first recorded in RTDB-RULES-20261104-01 (fixtures/production-sdk-rules.json). */
export const RECORDED_SHAPES = {
  'load-accepted': { status: 200, bodyBytes: 15, recorded: 'RTDB-RULES-20261104-01 r1-rules lex-feff' },
  'load-refused': { status: 400, recorded: 'RTDB-RULES-20261104-01 r1-rules load-paren' },
  allowed: { status: 200, recorded: 'RTDB-RULES-20261104-01 r1-rules tok-admin-allow (GET), wv-allow (PUT)' },
  denied: { status: 401, bodyBytes: 36, recorded: 'RTDB-RULES-20261104-01 r1-rules tok-admin-deny' },
  'index-required': { status: 400, recorded: 'RTDB-RULES-20261104-01 r1-rules ix-c' },
};
const HEADER_NAMES = ['access-control-allow-origin', 'cache-control', 'content-length', 'content-type'];

/** The headers production sent with every recorded Rules and data answer, content-length equal to the body bytes. */
export function jsonHeaders(headers, bodyBytes) {
  if (!headers || typeof headers !== 'object' || Array.isArray(headers)) return false;
  return JSON.stringify(Object.keys(headers).sort()) === JSON.stringify(HEADER_NAMES) && headers['content-type'] === 'application/json; charset=utf-8'
    && headers['cache-control'] === 'no-cache' && headers['access-control-allow-origin'] === '*' && headers['content-length'] === String(bodyBytes);
}

/** The shape of one reduced row: a key of RECORDED_SHAPES, `not-loaded`, or `unknown`. */
export function shapeOf(row) {
  if (!row || typeof row !== 'object') return 'unknown';
  if (row.outcome === 'not-loaded') return row.ok === true && row.status === undefined && row.body === undefined ? 'not-loaded' : 'unknown';
  if (row.ok !== true || row.outcome !== 'answered' || row.utf8 !== true || row.clipped !== false) return 'unknown';
  if (!Number.isInteger(row.status) || !Number.isSafeInteger(row.bodyBytes) || typeof row.body !== 'string' || !jsonHeaders(row.responseHeaders, row.bodyBytes)) return 'unknown';
  const isLoad = typeof row.id === 'string' && row.id.startsWith('load-');
  if (isLoad) {
    if (row.status === 200 && row.bodyBytes === RECORDED_SHAPES['load-accepted'].bodyBytes && row.body === ACCEPTED_BODY) return 'load-accepted';
    if (row.status === 400 && row.body.startsWith('{\n  "error" : "') && row.body.endsWith('"\n}\n')) return 'load-refused';
    return 'unknown';
  }
  if (row.status === 200) return 'allowed';
  if (row.status === 401 && row.bodyBytes === RECORDED_SHAPES.denied.bodyBytes && row.body === DENIED_BODY) return 'denied';
  if (row.status === 400 && row.body.startsWith('{\n  "error" : "Index not defined, add \\".indexOn\\"')) return 'index-required';
  return 'unknown';
}

/** The request a row must carry: the table's, and for a load the document of the recorded prefix. */
function requestMatches(row, spec, prefix) {
  if (row?.id !== spec.id || row.doc !== spec.doc || row.identity !== spec.identity) return false;
  if (row.outcome === 'not-loaded') return true;
  const body = spec.id.startsWith('load-') ? JSON.stringify(syntaxRules(prefix, spec.doc)) : (spec.body ?? null);
  return row.method === spec.method && row.query === spec.query && row.requestBody === body;
}

export const caseCount = () => RULES_SYNTAX_PROFILES.length * TABLE.length;
const answerOf = r => JSON.stringify([shapeOf(r), r.status ?? null, r.body ?? null, r.bodyBytes ?? null, r.responseHeaders ?? null]);

export function summarize(production, local) {
  const counts = { MATCH: 0, MISMATCH: 0, NEEDS_REVIEW: 0 }, rows = [], problems = [];
  for (const [side, doc] of [['production', production], ['local', local]]) {
    if (doc?.kind !== KIND || doc.suite !== 'rules-syntax' || doc.prefix !== PREFIX || doc.result?.status !== 'complete' || doc.result?.exit !== 0 || doc.result?.observed !== caseCount()
      || doc.result?.cleanup?.rules !== 'verified' || doc.result?.cleanup?.prefix !== 'verified' || doc.result?.unverified?.length !== 0 || doc.faults?.length !== 0
      || JSON.stringify(doc.profiles?.map(p => p.name)) !== JSON.stringify(RULES_SYNTAX_PROFILES)) problems.push(`${side}: incomplete or invalid run`);
    else if (doc.profiles.some(p => !Array.isArray(p.rows) || p.rows.length !== TABLE.length)) problems.push(`${side}: missing or extra cases`);
  }
  if (problems.length) return { match: false, counts, problems, rows, documents: [] };
  for (const [j, spec] of TABLE.entries()) {
    const prod = production.profiles.map(p => p.rows[j]), loc = local.profiles.map(p => p.rows[j]);
    const roundsAgree = answerOf(prod[0]) === answerOf(prod[1]);
    for (const [i, profile] of RULES_SYNTAX_PROFILES.entries()) {
      const a = prod[i], b = loc[i], shapes = [shapeOf(a), shapeOf(b)];
      let verdict, reason;
      if (!requestMatches(a, spec, PREFIX) || !requestMatches(b, spec, PREFIX)) [verdict, reason] = ['NEEDS_REVIEW', 'request differs from the table'];
      else if (shapes.includes('unknown')) [verdict, reason] = ['NEEDS_REVIEW', 'unrecorded answer shape'];
      else if (!roundsAgree) [verdict, reason] = ['NEEDS_REVIEW', 'production rounds differ'];
      else if (answerOf(a) === answerOf(b)) [verdict, reason] = ['MATCH', ''];
      else [verdict, reason] = ['MISMATCH', `production ${shapes[0]} ${a.status ?? ''}, local ${shapes[1]} ${b.status ?? ''}`.trim()];
      counts[verdict]++; rows.push({ profile, case: spec.id, doc: spec.doc, verdict, reason, production: shapes[0], local: shapes[1] });
    }
  }
  const documents = DOCUMENTS.map(d => ({ doc: d.id, construct: d.construct, production: rows.filter(r => r.case === `load-${d.id}`).map(r => r.production), local: rows.filter(r => r.case === `load-${d.id}`).map(r => r.local) }));
  return { match: counts.MATCH === caseCount(), counts, problems, rows, documents };
}
