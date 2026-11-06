// The comparison of the rest suite (G7) of the RTDB SDK observer: a local reduced journal against a recorded one
// (rtdb-sdk-rest-fixture.mjs writes both). Pure functions.
//
// Verdict per (profile, case). Compared exactly: the status, every response header the recorded side has (the local
// side must send it with the same value), every allowlisted header the local side sends that the recorded side does not
// (a difference too), the body text after the masks ({scope}, checked {pushId}) and the body byte length. There is no
// semantic policy: orderBy answers are judged by their exact member order. Fail closed (NEEDS_REVIEW): a recorded case
// that is missing, out of place, not answered (unknown, blocked, not sent), a 5xx, a body that is not UTF-8 or was
// clipped, a row with an unrecorded field or header, a request other than the case table's; the same on the local side
// (a local 5xx is also listed as a defect); and at run level an unknown mutation (unverified), an incomplete run, faults,
// an unverified cleanup, or a prefix of another length (the masks hide the scope, its length stays in the bytes).
import { KIND } from './rtdb-sdk-rest-fixture.mjs';
import { REST_CASES, REST_PROFILES, TABLE } from './sdk-observer/rest-suite.mjs';
import { RECORDED_RESPONSE_HEADERS } from './sdk-observer/lib.mjs';

export const caseCount = () => REST_PROFILES.length * REST_CASES.length;
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const isObject = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const sameKeys = (v, keys) => isObject(v) && same(Object.keys(v).sort(), [...keys].sort());
const verdict = (v, reason, extra = {}) => ({ verdict: v, reason, ...extra });
const ANSWERED = ['id', 'ok', 'outcome', 'method', 'path', 'query', 'requestHeaders', 'requestBody', 'status', 'responseHeaders', 'body', 'bodyBytes', 'utf8', 'clipped'];
const isPost = spec => spec.method === 'POST' && !spec.headers?.['x-http-method-override'];

/** A row in the shape an answered case writes, for exactly the request of the case table; returns a reason or null. */
function shapeProblem(r, spec) {
  if (!isObject(r)) return 'missing';
  if (r.outcome !== 'answered' || r.ok !== true) return `not answered (${r.outcome})`;
  if (!sameKeys(r, isPost(spec) ? [...ANSWERED, 'pushIdShapeOk'] : ANSWERED)) return 'fields are not the recorded ones';
  if (r.id !== spec.id || r.method !== spec.method || r.path !== `{scope}${spec.path}` || r.query !== spec.query || r.requestBody !== (spec.body ?? null) || !same(r.requestHeaders, spec.headers ?? {})) return 'not the request of the case table';
  if (!Number.isSafeInteger(r.status) || r.status < 100 || r.status > 599) return 'status';
  if (!isObject(r.responseHeaders) || !Object.entries(r.responseHeaders).every(([k, v]) => RECORDED_RESPONSE_HEADERS.includes(k) && typeof v === 'string')) return 'response headers are not in the allowlist';
  if (typeof r.body !== 'string' || !Number.isSafeInteger(r.bodyBytes) || r.bodyBytes < 0) return 'body';
  if (r.utf8 !== true) return 'body is not UTF-8';
  if (r.clipped !== false) return 'body was clipped';
  if (isPost(spec) && typeof r.pushIdShapeOk !== 'boolean') return 'push id check';
  return null;
}

/** One case; `production` is the recorded side, `spec` the case table entry. */
export function judgeCase(production, local, spec) {
  const p = shapeProblem(production, spec);
  if (p) return verdict('NEEDS_REVIEW', `recorded case: ${p}`, { differences: [] });
  if (production.status >= 500) return verdict('NEEDS_REVIEW', 'recorded case answered 5xx', { differences: [] });
  if (isPost(spec) && production.status === 200 && production.pushIdShapeOk !== true) return verdict('NEEDS_REVIEW', 'recorded push id is not in the 20-character shape', { differences: [] });
  const l = shapeProblem(local, spec);
  if (l) return verdict('NEEDS_REVIEW', `local case: ${l}`, { differences: [] });
  if (local.status >= 500) return verdict('NEEDS_REVIEW', 'local case answered 5xx', { differences: [], defect: 'local 5xx' });
  const differences = [];
  if (local.status !== production.status) differences.push('status');
  for (const [name, value] of Object.entries(production.responseHeaders)) if (local.responseHeaders[name] !== value) differences.push(`header:${name}`);
  for (const name of Object.keys(local.responseHeaders)) if (!Object.hasOwn(production.responseHeaders, name)) differences.push(`header:+${name}`);
  if (local.body !== production.body) differences.push('body');
  if (local.bodyBytes !== production.bodyBytes) differences.push('bodyBytes');
  if (isPost(spec) && local.pushIdShapeOk !== production.pushIdShapeOk) differences.push('pushIdShapeOk');
  return differences.length ? verdict('MISMATCH', 'status, headers or body bytes differ', { differences }) : verdict('MATCH', 'status, recorded headers and body bytes equal', { differences });
}

/** One profile: every case of the table at its fixed position. */
export function judgeProfile(production, local) {
  const problems = [], rows = [];
  const named = production?.name === local?.name && REST_PROFILES.includes(production?.name);
  if (!named) problems.push(`profile names differ: ${production?.name} and ${local?.name}`);
  const n = REST_CASES.length, extra = !Array.isArray(production?.rows) || production.rows.length !== n || !Array.isArray(local?.rows) || local.rows.length !== n;
  if (extra) problems.push(`${production?.name}: a case row is missing or extra`);
  for (const [i, id] of REST_CASES.entries()) {
    const spec = TABLE.find(c => c.id === id), pr = production?.rows?.[i], lr = Array.isArray(local?.rows) ? local.rows[i] : undefined;
    const judged = !named ? verdict('NEEDS_REVIEW', 'profile names differ', { differences: [] })
      : pr?.id !== id ? verdict('NEEDS_REVIEW', 'recorded case is missing or out of place', { differences: [] })
        : lr?.id !== id ? verdict('NEEDS_REVIEW', 'local case is missing or out of place', { differences: [] })
          : judgeCase(pr, lr, spec);
    rows.push({ profile: production?.name, case: id, ...judged });
  }
  return { name: production?.name, extra: extra ? verdict('NEEDS_REVIEW', 'a case row is missing or extra') : null, rows, problems };
}

const RESULT_KEYS = ['status', 'observed', 'exit', 'cleanup', 'unverified', 'prefixLength'];
const completeRun = d => d.result.status === 'complete' && d.result.observed === caseCount() && d.result.exit === 0 && same(d.result.cleanup, { prefix: 'verified', rules: 'verified' });

/** The whole comparison: a match only when every case of both profiles matches and the runs are complete and clean. */
export function summarize(production, local) {
  const counts = { MATCH: 0, MISMATCH: 0, NEEDS_REVIEW: 0 };
  try {
    const problems = [];
    for (const [side, d] of [['production', production], ['local', local]]) {
      if (!sameKeys(d, ['kind', 'suite', 'result', 'faults', 'profiles']) || d.kind !== KIND || d.suite !== 'rest') { problems.push(`${side}: not a reduced SDK rest journal`); continue; }
      if (!Array.isArray(d.profiles) || !same(d.profiles.map(p => (sameKeys(p, ['name', 'rows']) ? p.name : null)), REST_PROFILES)) problems.push(`${side}: profiles are not the rest profiles`);
      if (!sameKeys(d.result, RESULT_KEYS)) { problems.push(`${side}: result is not in the reduced shape`); continue; }
      if (!completeRun(d)) problems.push(`${side}: the run is not complete with a verified cleanup`);
      if (!Array.isArray(d.result.unverified) || d.result.unverified.length) problems.push(`${side}: unknown outcomes: ${JSON.stringify(d.result.unverified)}`);
      if (!Number.isSafeInteger(d.result.prefixLength)) problems.push(`${side}: prefix length is not recorded`);
      if (!Array.isArray(d.faults) || d.faults.length) problems.push(`${side}: the journal records faults`);
    }
    if (!problems.length && production.result.prefixLength !== local.result.prefixLength) problems.push(`prefix lengths differ: ${production.result.prefixLength} and ${local.result.prefixLength} (the masked scope must have the same length)`);
    if (problems.length) return { match: false, counts, problems, rows: [], defects: [] };
    const profiles = production.profiles.map((p, i) => judgeProfile(p, local.profiles[i]));
    const rows = profiles.flatMap(p => p.rows);
    for (const r of rows) counts[r.verdict]++;
    problems.push(...profiles.flatMap(p => p.problems));
    const defects = rows.filter(r => r.defect).map(r => `${r.profile}/${r.case}: ${r.defect}`);
    return { match: rows.length === caseCount() && counts.MATCH === caseCount() && problems.length === 0, counts, problems, rows, defects };
  } catch (error) {
    return { match: false, counts, problems: [`unreadable: ${error?.message}`], rows: [], defects: [] };
  }
}
