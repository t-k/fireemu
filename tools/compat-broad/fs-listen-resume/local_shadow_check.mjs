// Compare one local shadow receipt against the frozen expected local results.
//
// Usage: node tools/compat-broad/fs-listen-resume/local_shadow_check.mjs <receipt.json>
//
// It reads a receipt the collector produced against a local fireemu instance and
// reports, per case, whether the compared projection equals the expectation in
// the checked-in case catalog. It contacts nothing and decides nothing about
// production.

import { readFileSync } from 'node:fs';
const r = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const cat = JSON.parse(readFileSync(process.env.O6_LISTEN_CATALOG_PATH ?? 'spec/compatibility/fs-listen-sdk-cases.json', 'utf8'));
const canon = v => Array.isArray(v) ? v.map(canon)
  : (v && typeof v === 'object' ? Object.fromEntries(Object.keys(v).sort().map(k => [k, canon(v[k])])) : v);
const exp = Object.fromEntries(cat.cases.map(c => [c.caseId, c]));
console.log('complete', r.complete, 'cleanup', r.cleanup.complete, 'budget', JSON.stringify(r.budget.used));
let matched = 0;
for (const rec of r.cases) {
  const e = exp[rec.caseId];
  const f = e.comparedFields;
  const norm = x => JSON.stringify(canon(x.map(row => Object.fromEntries(f.map(k => [k, row[k] ?? null])))));
  const same = norm(rec.observed) === norm(e.expectedLocal);
  if (same) matched += 1;
  console.log(rec.caseId, 'complete=' + rec.complete, 'closed=' + rec.listenersClosed, 'inv=' + rec.invariantViolations.length, 'match=' + same, rec.failures.join('|'));
  if (!same) { console.log('  got ', norm(rec.observed)); console.log('  want', norm(e.expectedLocal)); }
  if (rec.invariantViolations.length) console.log('  inv:', JSON.stringify(rec.invariantViolations));
}
console.log('matched', matched, '/', r.cases.length);
process.exitCode = matched === r.cases.length && r.complete ? 0 : 1;
