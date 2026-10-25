// CV11: the committed production journal of the genuine-auth recorder, and its comparison with a
// local run.
//
//   node tools/sdk-smoke-database/cv11-fixture.mjs fixture <production journal.json> <fixture.json>
//   node tools/sdk-smoke-database/cv11-fixture.mjs compare <local journal.json> [--out <comparison.json>]
//
// The fixture keeps, per profile, the ordered journal without the millisecond timings. `compare`
// judges a local journal (from `cv11-genuine-auth.mjs local`) against the fixture with
// `compareJournals`: step order must match, and within one step the events are compared sorted
// (the write-after-delete admin acknowledgement and the listener value race).
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { assertNoSecrets, compareJournals, PROFILES } from './cv11-genuine-auth.mjs';

export const FIXTURE = './fixtures/production-cv11-genuine-auth.json';
const KEPT = ['step', 'type', 'epoch', 'code', 'shape', 'present'];

/** One journal without timings: the fields compareJournals reads, in the recorded order. */
export function sanitizeProfiles(profiles) {
  if (!Array.isArray(profiles) || profiles.map((p) => p.name).join() !== PROFILES.map((p) => p.name).join()) throw Error('expected the four CV11 profiles in order');
  return profiles.map((p) => ({ name: p.name, journal: p.journal.map((e) => Object.fromEntries(KEPT.filter((k) => k in e).map((k) => [k, e[k]]))) }));
}

export function fixtureFromJournal(journal) {
  if (journal.mode !== 'production') throw Error('the fixture is made from a production journal');
  const fixture = {
    recording: 'RTDB-CV11-LEAN-20261025-02 production-2',
    recordedOn: '2026-10-25',
    project: 'fireemu-oracle-query',
    instance: 'fireemu-q-rtdb2',
    sdk: 'firebase 12.18.0 (web, headless Chromium), email/password users',
    profiles: sanitizeProfiles(journal.profiles),
  };
  assertNoSecrets(JSON.stringify(fixture), []);
  return fixture;
}

/** The comparison kept as evidence: the verdict and per-profile event counts, no timings. */
export function comparison(fixture, local) {
  const profiles = sanitizeProfiles(local.profiles);
  const verdict = compareJournals(fixture.profiles, profiles);
  return {
    match: verdict.match,
    differences: verdict.differences,
    profiles: profiles.map((p, i) => ({ name: p.name, productionEvents: fixture.profiles[i].journal.length, localEvents: p.journal.length })),
    unorderedWithinStep: true,
  };
}

async function main(argv) {
  if (argv[0] === 'fixture') {
    const fixture = fixtureFromJournal(JSON.parse(readFileSync(argv[1], 'utf8')));
    writeFileSync(argv[2], `${JSON.stringify(fixture, null, 1)}\n`);
    return 0;
  }
  if (argv[0] !== 'compare' || !argv[1]) throw Error('usage: fixture <journal> <out> | compare <local journal> [--out <file>]');
  const fixture = JSON.parse(readFileSync(new URL(FIXTURE, import.meta.url), 'utf8'));
  const result = comparison(fixture, JSON.parse(readFileSync(argv[1], 'utf8')));
  const out = argv.indexOf('--out');
  if (out >= 0) writeFileSync(argv[out + 1], `${JSON.stringify(result, null, 1)}\n`);
  console.log(JSON.stringify({ match: result.match, differences: result.differences.length }));
  return result.match ? 0 : 1;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).then((code) => { process.exitCode = code; }, (e) => { console.error(`cv11-fixture: ${e.message}`); process.exitCode = 2; });
}
