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

// These are the local emulator and strict profile answers, derived from the official-emulator fixture.
export const FIREEMU_ANSWERS = Object.fromEntries(['emulator', 'strict'].map(profile => [profile, [
  [400, '{\n  "error" : "1:47: \'a\' occurs multiple times.\\n"\n}\n'],
  [400, '{\n  "error" : "1:24: Cannot have multiple \'.read\' rules.\\n"\n}\n'],
  [400, '{\n  "error" : "1:26: Cannot have multiple \'.indexOn\' keys.\\n"\n}\n'],
  [400, '{\n  "error" : "1:22: Invalid key: a.b. Index must be either .value or declared on a valid path\\n"\n}\n'],
  [400, '{\n  "error" : "1:22: Invalid key: $x. Index must be either .value or declared on a valid path\\n"\n}\n'],
  [200, '{"status":"ok"}'],
  [200, '{"status":"ok"}'],
].map(([status, body], i) => ({ id: TABLE[i].id, status, body }))]));
