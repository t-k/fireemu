// The comparison of the tokens suite (G10) of the RTDB SDK observer: a local reduced journal against a recorded one
// (rtdb-sdk-tokens-fixture.mjs writes both). Pure functions.
//
// Verdict per (profile, case): the rules judge's judgeCase, unchanged (exact status, every response header the recorded
// side has, every allowlisted header only the local side sends, the body text after the {scope} and {project} masks
// and the body byte length; the request must be the case table's template: method, path, query, identity, headers,
// body). There is no semantic policy: the error texts are the observation. Fail closed (NEEDS_REVIEW) as the rules
// judge: a case that is missing, out of place, not answered, a 5xx, not UTF-8, clipped, a row with an unrecorded field
// (a local 5xx is also listed as a defect). At run level: an unknown outcome, an incomplete run, faults, an unverified
// cleanup, a prefix of another length, and on either side a ready probe that did not end ready. The number of probe
// attempts is not compared (production Rules take effect after a delay).
import { KIND } from './rtdb-sdk-tokens-fixture.mjs';
import { judgeCase } from './rtdb-sdk-rules-judge.mjs';
import { TABLE, TOKENS_CASES, TOKENS_PROFILES } from './sdk-observer/tokens-suite.mjs';

export const caseCount = () => TOKENS_PROFILES.length * TOKENS_CASES.length;
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const isObject = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const sameKeys = (v, keys) => isObject(v) && same(Object.keys(v).sort(), [...keys].sort());
const verdict = (v, reason, extra = {}) => ({ verdict: v, reason, ...extra });

/** The ready probe of one side's profile: exactly one, after the start, ended ready. */
export function probeProblems(p, side) {
  const probes = p?.probes;
  if (!Array.isArray(probes) || probes.length !== 1 || probes[0]?.after !== 'start') return [`${side} ${p?.name}: not exactly one start probe`];
  if (probes[0].ready !== true || !Number.isSafeInteger(probes[0].attempts) || probes[0].attempts < 1) return [`${side} ${p?.name}: the ready probe did not end ready`];
  return [];
}

/** One profile: every case of the table at its fixed position. */
export function judgeProfile(production, local) {
  const problems = [], rows = [];
  const named = production?.name === local?.name && TOKENS_PROFILES.includes(production?.name);
  if (!named) problems.push(`profile names differ: ${production?.name} and ${local?.name}`);
  const n = TOKENS_CASES.length, extra = !Array.isArray(production?.rows) || production.rows.length !== n || !Array.isArray(local?.rows) || local.rows.length !== n;
  if (extra) problems.push(`${production?.name}: a case row is missing or extra`);
  for (const [i, id] of TOKENS_CASES.entries()) {
    const spec = TABLE.find(c => c.id === id), pr = Array.isArray(production?.rows) ? production.rows[i] : undefined, lr = Array.isArray(local?.rows) ? local.rows[i] : undefined;
    const judged = !named ? verdict('NEEDS_REVIEW', 'profile names differ', { differences: [] })
      : pr?.id !== id ? verdict('NEEDS_REVIEW', 'recorded case is missing or out of place', { differences: [] })
        : lr?.id !== id ? verdict('NEEDS_REVIEW', 'local case is missing or out of place', { differences: [] })
          : judgeCase(pr, lr, spec);
    rows.push({ profile: production?.name, case: id, ...judged });
  }
  problems.push(...probeProblems(production, 'recorded'), ...probeProblems(local, 'local'));
  return { name: production?.name, rows, problems };
}

const RESULT_KEYS = ['status', 'observed', 'exit', 'cleanup', 'unverified', 'prefixLength'];
const PROFILE_KEYS = ['name', 'rows', 'probes'];
const completeRun = d => d.result.status === 'complete' && d.result.observed === caseCount() && d.result.exit === 0 && same(d.result.cleanup, { prefix: 'verified', rules: 'verified' });

/** The whole comparison: a match only when every case of both profiles matches and the runs are complete and clean. */
export function summarize(production, local) {
  const counts = { MATCH: 0, MISMATCH: 0, NEEDS_REVIEW: 0 };
  try {
    const problems = [];
    for (const [side, d] of [['production', production], ['local', local]]) {
      if (!sameKeys(d, ['kind', 'suite', 'result', 'faults', 'profiles']) || d.kind !== KIND || d.suite !== 'tokens') { problems.push(`${side}: not a reduced SDK tokens journal`); continue; }
      if (!Array.isArray(d.profiles) || !same(d.profiles.map(p => (sameKeys(p, PROFILE_KEYS) ? p.name : null)), TOKENS_PROFILES)) problems.push(`${side}: profiles are not the tokens profiles`);
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
