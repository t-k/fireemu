// CV11: the committed production journal of the genuine-auth recorder, and its comparison with a
// local run.
//
//   node tools/sdk-smoke-database/cv11-fixture.mjs fixture <production journal.json> <fixture.json>
//   node tools/sdk-smoke-database/cv11-fixture.mjs compare <local journal.json> [--out <comparison.json>]
//
// The fixture keeps, per profile, the ordered journal without the millisecond timings. `compare`
// judges a local journal (from `cv11-genuine-auth.mjs local`) against the fixture with
// `compareRecorded`: every event must be in the recorded order, except within the steps in
// RACING_STEPS (the write-after-delete admin acknowledgement and the listener value, which
// production itself delivered in both orders), whose events are compared sorted.
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { assertNoSecrets, PROFILES } from './cv11-genuine-auth.mjs';

export const FIXTURE = './fixtures/production-cv11-genuine-auth.json';
const KEPT = ['step', 'type', 'epoch', 'code', 'shape', 'present'];
export const RACING_STEPS = new Set(['write-after-delete']);

/** Profile by profile: strict event order, sorted only inside RACING_STEPS. Timings are not kept. */
export function compareRecorded(a, b) {
  const key = (e) => JSON.stringify(KEPT.map((k) => e[k] ?? null));
  const canonical = (journal = []) => {
    const out = [];
    for (const e of journal) (out.at(-1)?.step === e.step ? out.at(-1).keys : (out.push({ step: e.step, keys: [] }), out.at(-1).keys)).push(key(e));
    return out.flatMap((s) => (RACING_STEPS.has(s.step) ? s.keys.toSorted() : s.keys));
  };
  const differences = [];
  for (const [i, p] of a.entries()) {
    const x = canonical(p.journal), y = canonical(b[i]?.journal), n = x.findIndex((k, j) => k !== y[j]);
    if (n >= 0 || x.length !== y.length) differences.push({ profile: p.name, index: n >= 0 ? n : x.length, left: x[n >= 0 ? n : x.length] ?? null, right: y[n >= 0 ? n : x.length] ?? null });
  }
  return { match: differences.length === 0 && a.length === b.length, differences };
}

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
  const verdict = compareRecorded(fixture.profiles, profiles);
  return {
    match: verdict.match,
    differences: verdict.differences,
    profiles: profiles.map((p, i) => ({ name: p.name, productionEvents: fixture.profiles[i].journal.length, localEvents: p.journal.length })),
    unorderedSteps: [...RACING_STEPS],
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
