// The comparison of the rules-load suite: a local reduced journal against a recorded one. A case row records the request body
// (the table's) and the answer; the request itself (PUT to /.settings/rules.json as the operator) is fixed in the suite, so a row
// carries no method, path or request headers to compare. The answer is judged exactly: status, body text, body bytes and headers.
import { KIND } from './rtdb-sdk-rules-load-fixture.mjs';
import { RULES_LOAD_PROFILES, TABLE } from './sdk-observer/rules-load-suite.mjs';

export const caseCount = () => RULES_LOAD_PROFILES.length * TABLE.length;
export function summarize(production, local) {
  const counts = { MATCH: 0, MISMATCH: 0, NEEDS_REVIEW: 0 }, rows = [], problems = [];
  for (const [side, doc] of [['production', production], ['local', local]]) {
    if (doc?.kind !== KIND || doc.suite !== 'rules-load' || doc.result?.status !== 'complete' || doc.result?.exit !== 0 || doc.result?.observed !== caseCount() || doc.result?.cleanup?.rules !== 'verified' || doc.result?.cleanup?.prefix !== 'not-needed' || doc.result?.unverified?.length !== 0 || doc.faults?.length !== 0 || JSON.stringify(doc.profiles?.map(p => p.name)) !== JSON.stringify(RULES_LOAD_PROFILES)) problems.push(`${side}: incomplete or invalid run`);
  }
  if (problems.length) return { match: false, counts, problems, rows, defects: [] };
  for (const [i, profile] of RULES_LOAD_PROFILES.entries()) {
    const pr = production.profiles[i].rows, lr = local.profiles[i].rows;
    if (!Array.isArray(pr) || !Array.isArray(lr) || pr.length !== TABLE.length || lr.length !== TABLE.length) { problems.push(`${profile}: missing or extra cases`); continue; }
    for (const [j, spec] of TABLE.entries()) {
      const a = pr[j], b = lr[j];
      const valid = r => r?.id === spec.id && r.ok === true && r.outcome === 'answered' && r.requestBody === spec.body && r.utf8 === true && r.clipped === false && Number.isInteger(r.status) && typeof r.body === 'string';
      const verdict = !valid(a) || !valid(b) ? 'NEEDS_REVIEW' : JSON.stringify([a.status, a.body, a.bodyBytes, a.responseHeaders]) === JSON.stringify([b.status, b.body, b.bodyBytes, b.responseHeaders]) ? 'MATCH' : 'MISMATCH';
      counts[verdict]++; rows.push({ profile, case: spec.id, verdict, local: b });
    }
  }
  return { match: !problems.length && counts.MATCH === caseCount(), counts, problems, rows, defects: rows.filter(r => r.local?.status >= 500).map(r => `${r.profile}/${r.case}: local 5xx`) };
}
