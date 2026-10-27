// The committed production journal of the S5 recorder (an onDisconnect value with a priority, then a cancel of one of its
// children), the local journal compared with it, and the comparison summary the closure evidence quotes.
//
//   node rtdb-s5-fixture.mjs fixture <journal.json> <fixture.json> --recording <id> --envelope <id> --recorded-on <date>
//   node rtdb-s5-fixture.mjs summary <production fixture.json> <local fixture.json>
//
// `fixture` keeps, per round, the ordered rows without millisecond timings, counts or any field the judge does not read
// (the projection of sanitizeProfiles), and refuses anything that is not the two rounds in order or that holds a
// secret-shaped text. The fixture is a journal file: `rtdb-s5.mjs judge <fixture>` reads it as it is.
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { assertNoSecrets } from './cv11-genuine-auth.mjs';
import { judgeRounds, ROUNDS, SCENARIO, sanitizeProfiles } from './rtdb-s5-judge.mjs';

const ANSWERS = ['A', 'B', 'C', 'D'];

/** The fixture document for a raw journal's profiles; throws unless they are the two rounds, in order. */
export function buildFixture(profiles, meta) {
  const kept = sanitizeProfiles(profiles);
  if (kept.map((p) => `${p.scenario}:${p.name}`).join() !== ROUNDS.map((n) => `${SCENARIO}:${n}`).join()) throw Error('expected the two S5 rounds in order (r1-ws, r2-ws)');
  for (const field of ['recording', 'envelope', 'recordedOn']) if (typeof meta?.[field] !== 'string' || !meta[field]) throw Error(`missing --${field.replace(/[A-Z]/g, (c) => `-${c.toLowerCase()}`)}`);
  const doc = { ...meta, project: 'fireemu-oracle-query', instance: 'fireemu-q-rtdb2', sdk: 'firebase 12.18.0 (web, headless Chromium)', rows: kept.map((p) => p.journal.length), profiles: kept };
  assertNoSecrets(JSON.stringify(doc), []);
  return doc;
}

/**
 * The comparison of a local fixture or journal with the production fixture: what the closure evidence quotes. It is a
 * match only when both sides gave the same settled answer (A to D); an unsettled or unclassified side never matches,
 * and the controls of both sides must have behaved (the judge checks them).
 */
export function summarize(production, local) {
  const p = judgeRounds(sanitizeProfiles(production.profiles)), l = judgeRounds(sanitizeProfiles(local.profiles));
  const settled = ANSWERS.includes(p.verdict) && ANSWERS.includes(l.verdict);
  return {
    production: p.verdict,
    local: l.verdict,
    match: settled && p.verdict === l.verdict,
    rounds: p.rounds.map((round, i) => ({ name: round.name, production: round.outcome, local: l.rounds[i]?.outcome ?? null })),
    reason: { production: p.reason, local: l.reason },
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
    console.log(JSON.stringify({ production: result.production, local: result.local, match: result.match }));
    return result.match ? 0 : 1;
  }
  throw Error('usage: fixture <journal.json> <fixture.json> --recording <id> --envelope <id> --recorded-on <date> | summary <production> <local>');
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try { process.exitCode = main(process.argv.slice(2)); } catch (e) { console.error(`rtdb-s5-fixture: ${e.message}`); process.exitCode = 2; }
}
