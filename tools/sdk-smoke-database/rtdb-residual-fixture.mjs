// The committed production journal of the residual recorder (CV08 and CV10), the local journal compared with it, and the
// comparison summary the closure evidence quotes.
//
//   node rtdb-residual-fixture.mjs fixture <journal.json> <fixture.json> --recording <id> --envelope <id> --recorded-on <date>
//   node rtdb-residual-fixture.mjs summary <production fixture.json> <local fixture.json>
//
// `fixture` keeps, per profile, the ordered rows without millisecond timings, counts or any field the judge does not read
// (the same projection as sanitizeProfiles), and refuses anything that is not the eight profiles in order or that holds a
// secret-shaped text. The fixture is a journal file: `rtdb-residual.mjs compare <fixture> <local journal>` reads it as it is.
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { assertNoSecrets } from './cv11-genuine-auth.mjs';
import { judgeRuns, sanitizeProfiles, SCENARIOS } from './rtdb-residual-judge.mjs';

export const PROFILE_NAMES = ['r1-ws', 'r1-lp', 'r2-ws', 'r2-lp'];
const EXPECTED = SCENARIOS.flatMap((scenario) => PROFILE_NAMES.map((name) => `${scenario}:${name}`));

/** The fixture document for a raw journal's profiles; throws unless they are the eight, in order. */
export function buildFixture(profiles, meta) {
  const kept = sanitizeProfiles(profiles);
  if (kept.map((p) => `${p.scenario}:${p.name}`).join() !== EXPECTED.join()) throw Error('expected the eight residual profiles in order (cv08 then cv10, r1-ws r1-lp r2-ws r2-lp)');
  for (const field of ['recording', 'envelope', 'recordedOn']) if (typeof meta?.[field] !== 'string' || !meta[field]) throw Error(`missing --${field.replace(/[A-Z]/g, (c) => `-${c.toLowerCase()}`)}`);
  const doc = { ...meta, project: 'fireemu-oracle-query', instance: 'fireemu-q-rtdb2', sdk: 'firebase 12.18.0 (web, headless Chromium)', rows: kept.map((p) => p.journal.length), profiles: kept };
  assertNoSecrets(JSON.stringify(doc), []);
  return doc;
}

/** The comparison of a local fixture or journal with the production fixture: what the closure evidence quotes. */
export function summarize(production, local) {
  const verdict = judgeRuns(sanitizeProfiles(production.profiles), sanitizeProfiles(local.profiles));
  const rows = { MATCH: 0, DIFFERENCE: 0, NEEDS_REVIEW: 0 };
  for (const p of verdict.profiles) rows[p.verdict === 'match' ? 'MATCH' : p.verdict === 'differences' ? 'DIFFERENCE' : 'NEEDS_REVIEW']++;
  return {
    verdict: verdict.verdict,
    match: verdict.verdict === 'match' && verdict.timing.within,
    profiles: verdict.profiles.map((p) => ({ scenario: p.scenario, name: p.name, verdict: p.verdict, differences: p.differences, unsettled: p.unsettled, localRaced: p.localRaced })),
    rows,
    timing: verdict.timing,
  };
}

function main(argv) {
  const opt = (n) => { const i = argv.indexOf(n); return i >= 0 ? argv[i + 1] : undefined; };
  if (argv[0] === 'fixture') {
    const [input, output] = argv.slice(1, 3);
    const profiles = JSON.parse(readFileSync(input, 'utf8')).profiles;
    const doc = buildFixture(profiles, { recording: opt('--recording'), envelope: opt('--envelope'), recordedOn: opt('--recorded-on') });
    writeFileSync(output, `${JSON.stringify(doc, null, 1)}\n`);
    return 0;
  }
  if (argv[0] === 'summary') {
    const [a, b] = argv.slice(1, 3).map((f) => JSON.parse(readFileSync(f, 'utf8')));
    const result = summarize(a, b);
    console.log(JSON.stringify({ verdict: result.verdict, match: result.match, rows: result.rows, timing: result.timing.within }));
    return result.match ? 0 : 1;
  }
  throw Error('usage: fixture <journal.json> <fixture.json> --recording <id> --envelope <id> --recorded-on <date> | summary <production> <local>');
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try { process.exitCode = main(process.argv.slice(2)); } catch (e) { console.error(`rtdb-residual-fixture: ${e.message}`); process.exitCode = 2; }
}
