// The comparison of the rules suite (G8) of the RTDB SDK observer: a local reduced journal against a recorded one
// (rtdb-sdk-rules-fixture.mjs writes both). Pure functions.
//
// Verdict per (profile, case), as the rest judge: compared exactly are the status, every response header the recorded
// side has, every allowlisted header only the local side sends, the body text after the {scope} mask and the body byte
// length; a Rules load answer is judged the same way (its error text and columns are bytes of the body). There is no
// semantic policy. Fail closed (NEEDS_REVIEW): a recorded case that is missing, out of place, not answered (unknown,
// blocked, not sent), a 5xx, a body that is not UTF-8 or was clipped, a row with an unrecorded field or header, a
// request other than the case table's (method, path, query with its auth_variable_override, identity, headers, body);
// the same on the local side (a local 5xx is also listed as a defect). At run level: an unknown mutation
// (unverified), an incomplete run, faults, an unverified cleanup, a prefix of another length (the mask hides the scope,
// its length stays in the bytes), and on either side a ready probe that did not end ready, a reinstall that was not
// answered 200, or reinstalls that do not follow exactly the load cases answered 200. The number of probe attempts is
// not compared (production Rules take effect after a delay).
import { KIND } from './rtdb-sdk-rules-fixture.mjs';
import { RULES_CASES, RULES_PROFILES, TABLE } from './sdk-observer/rules-suite.mjs';
import { RECORDED_RESPONSE_HEADERS } from './sdk-observer/lib.mjs';

export const caseCount = () => RULES_PROFILES.length * RULES_CASES.length;
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const isObject = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const sameKeys = (v, keys) => isObject(v) && same(Object.keys(v).sort(), [...keys].sort());
const verdict = (v, reason, extra = {}) => ({ verdict: v, reason, ...extra });
const ANSWERED = ['id', 'group', 'identity', 'ok', 'outcome', 'method', 'path', 'query', 'requestHeaders', 'requestBody', 'status', 'responseHeaders', 'body', 'bodyBytes', 'utf8', 'clipped'];
const rowPath = spec => (spec.group === 'load' ? spec.path : `{scope}${spec.path}`);

/** A row in the shape an answered case writes, for exactly the request of the case table; returns a reason or null. */
function shapeProblem(r, spec) {
  if (!isObject(r)) return 'missing';
  if (r.outcome !== 'answered' || r.ok !== true) return `not answered (${r.outcome})`;
  if (!sameKeys(r, ANSWERED)) return 'fields are not the recorded ones';
  if (r.id !== spec.id || r.group !== spec.group || r.identity !== spec.identity || r.method !== spec.method || r.path !== rowPath(spec) || r.query !== spec.query || r.requestBody !== (spec.body ?? null) || !same(r.requestHeaders, spec.headers ?? {})) return 'not the request of the case table';
  if (!Number.isSafeInteger(r.status) || r.status < 100 || r.status > 599) return 'status';
  if (!isObject(r.responseHeaders) || !Object.entries(r.responseHeaders).every(([k, v]) => RECORDED_RESPONSE_HEADERS.includes(k) && typeof v === 'string')) return 'response headers are not in the allowlist';
  if (typeof r.body !== 'string' || !Number.isSafeInteger(r.bodyBytes) || r.bodyBytes < 0) return 'body';
  if (r.utf8 !== true) return 'body is not UTF-8';
  if (r.clipped !== false) return 'body was clipped';
  return null;
}

/** One case; `production` is the recorded side, `spec` the case table entry. */
export function judgeCase(production, local, spec) {
  const p = shapeProblem(production, spec);
  if (p) return verdict('NEEDS_REVIEW', `recorded case: ${p}`, { differences: [] });
  if (production.status >= 500) return verdict('NEEDS_REVIEW', 'recorded case answered 5xx', { differences: [] });
  const l = shapeProblem(local, spec);
  if (l) return verdict('NEEDS_REVIEW', `local case: ${l}`, { differences: [] });
  if (local.status >= 500) return verdict('NEEDS_REVIEW', 'local case answered 5xx', { differences: [], defect: 'local 5xx' });
  const differences = [];
  if (local.status !== production.status) differences.push('status');
  for (const [name, value] of Object.entries(production.responseHeaders)) if (local.responseHeaders[name] !== value) differences.push(`header:${name}`);
  for (const name of Object.keys(local.responseHeaders)) if (!Object.hasOwn(production.responseHeaders, name)) differences.push(`header:+${name}`);
  if (local.body !== production.body) differences.push('body');
  if (local.bodyBytes !== production.bodyBytes) differences.push('bodyBytes');
  return differences.length ? verdict('MISMATCH', 'status, headers or body bytes differ', { differences }) : verdict('MATCH', 'status, recorded headers and body bytes equal', { differences });
}

/** The probes and reinstalls of one side's profile: every probe ended ready, every reinstall answered 200, one reinstall and probe after each load answered 200. */
export function installProblems(p, side) {
  const problems = [], name = p?.name;
  if (!Array.isArray(p?.installs) || !Array.isArray(p?.probes)) return [`${side} ${name}: installs or probes are missing`];
  const accepted = (p.rows ?? []).filter(r => r?.group === 'load' && r.status === 200).map(r => r.id);
  if (!same(p.installs.map(i => i.after), accepted)) problems.push(`${side} ${name}: reinstalls ${JSON.stringify(p.installs.map(i => i.after))} do not follow the accepted load documents ${JSON.stringify(accepted)}`);
  if (p.installs.some(i => i.ok !== true || i.status !== 200)) problems.push(`${side} ${name}: a reinstall was not answered 200`);
  if (!same(p.probes.map(x => x.after), ['start', ...accepted])) problems.push(`${side} ${name}: the ready probes do not follow the start and each reinstall`);
  if (p.probes.some(x => x.ready !== true || !Number.isSafeInteger(x.attempts) || x.attempts < 1)) problems.push(`${side} ${name}: a ready probe did not end ready`);
  return problems;
}

/** One profile: every case of the table at its fixed position. */
export function judgeProfile(production, local) {
  const problems = [], rows = [];
  const named = production?.name === local?.name && RULES_PROFILES.includes(production?.name);
  if (!named) problems.push(`profile names differ: ${production?.name} and ${local?.name}`);
  const n = RULES_CASES.length, extra = !Array.isArray(production?.rows) || production.rows.length !== n || !Array.isArray(local?.rows) || local.rows.length !== n;
  if (extra) problems.push(`${production?.name}: a case row is missing or extra`);
  for (const [i, id] of RULES_CASES.entries()) {
    const spec = TABLE.find(c => c.id === id), pr = production?.rows?.[i], lr = Array.isArray(local?.rows) ? local.rows[i] : undefined;
    const judged = !named ? verdict('NEEDS_REVIEW', 'profile names differ', { differences: [] })
      : pr?.id !== id ? verdict('NEEDS_REVIEW', 'recorded case is missing or out of place', { differences: [] })
        : lr?.id !== id ? verdict('NEEDS_REVIEW', 'local case is missing or out of place', { differences: [] })
          : judgeCase(pr, lr, spec);
    rows.push({ profile: production?.name, case: id, ...judged });
  }
  problems.push(...installProblems(production, 'recorded'), ...installProblems(local, 'local'));
  return { name: production?.name, extra: extra ? verdict('NEEDS_REVIEW', 'a case row is missing or extra') : null, rows, problems };
}

const RESULT_KEYS = ['status', 'observed', 'exit', 'cleanup', 'unverified', 'prefixLength'];
const PROFILE_KEYS = ['name', 'rows', 'installs', 'probes'];
const completeRun = d => d.result.status === 'complete' && d.result.observed === caseCount() && d.result.exit === 0 && same(d.result.cleanup, { prefix: 'verified', rules: 'verified' });

/** The whole comparison: a match only when every case of both profiles matches and the runs are complete and clean. */
export function summarize(production, local) {
  const counts = { MATCH: 0, MISMATCH: 0, NEEDS_REVIEW: 0 };
  try {
    const problems = [];
    for (const [side, d] of [['production', production], ['local', local]]) {
      if (!sameKeys(d, ['kind', 'suite', 'result', 'faults', 'profiles']) || d.kind !== KIND || d.suite !== 'rules') { problems.push(`${side}: not a reduced SDK rules journal`); continue; }
      if (!Array.isArray(d.profiles) || !same(d.profiles.map(p => (sameKeys(p, PROFILE_KEYS) ? p.name : null)), RULES_PROFILES)) problems.push(`${side}: profiles are not the rules profiles`);
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
