import test from 'node:test';
import assert from 'node:assert/strict';

import { KIND, SETUP, reduceEventsJournal, profilesOf } from './rtdb-sdk-events-fixture.mjs';

const RESULT = { status: 'complete', observed: 52, exit: 0, cleanup: { prefix: 'verified', rules: 'verified' }, suite: 'events+admin', target: 'emulator' };
const step = (label, extra = {}) => ({ step: label, observer: [], writer: [], ...extra });
/** A minimal journal of the combined suite: setup rows and one case row per profile, plus the rows the reducer drops. */
function journal({ cases = 1 } = {}) {
  const rows = [{ kind: 'admin-req', label: 'rules-before' }, { kind: 'admin-res', label: 'rules-before', status: 200 }];
  for (const profile of profilesOf('events+admin')) {
    const suite = profile.suite;
    for (const id of SETUP[suite]) rows.push({ t: 'x', kind: 'case', suite, id, ok: true, profile: profile.name });
    rows.push({ t: 'x', kind: 'raw-ws', dir: 'in', conn: 1, data: '{}' }, { kind: 'raw-lp-request', profile: profile.name, url: 'http://x/.lp' });
    for (let i = 0; i < cases; i++) rows.push({ t: '2026-11-04T00:00:00.000Z', kind: 'case', suite, id: suite === 'events' ? 'get_exists' : 'get', ok: true, steps: [step('get', { result: { exists: true, v: { leaf: 1 } }, quiet: true })], profile: profile.name });
  }
  rows.push({ kind: 'result', status: 'complete' });
  return rows;
}

test('reduce: keeps per profile the case rows in journal order, drops timestamps, admin and raw rows', () => {
  const r = reduceEventsJournal(journal(), RESULT);
  assert.equal(r.kind, KIND); assert.equal(r.suite, 'events+admin');
  assert.deepEqual(r.result, { status: 'complete', observed: 52, exit: 0, cleanup: { prefix: 'verified', rules: 'verified' } });
  assert.deepEqual(r.profiles.map(p => p.name), ['r1-ws', 'r1-lp', 'r2-ws', 'r2-lp', 'r1-admin', 'r2-admin']);
  assert.deepEqual(r.profiles.map(p => p.suite), ['events', 'events', 'events', 'events', 'admin', 'admin']);
  assert.deepEqual(r.profiles[0].rows.map(x => x.id), ['startup', 'startup-observer', 'seed', 'get_exists']);
  assert.deepEqual(r.profiles[4].rows.map(x => x.id), ['startup', 'get']);
  assert.deepEqual(r.profiles[0].rows[3], { id: 'get_exists', ok: true, steps: [{ step: 'get', observer: [], writer: [], result: { exists: true, v: { leaf: 1 } }, quiet: true }] });
  assert.deepEqual(r.faults, []);
  assert.ok(!JSON.stringify(r).includes('2026-11-04T'));
});
test('reduce: a failed row keeps its error (cut at 200) and its recorded steps', () => {
  const rows = journal(); rows.push({ kind: 'case', suite: 'events', id: 'fanout', ok: false, error: 'E'.repeat(300), steps: [step('attach', { ready: false, quiet: true })], profile: 'r2-lp' });
  const last = reduceEventsJournal(rows, RESULT).profiles[3].rows.at(-1);
  assert.equal(last.ok, false); assert.equal(last.error.length, 200); assert.deepEqual(last.steps, [step('attach', { ready: false, quiet: true })]);
});
test('reduce: faults are listed with their profile', () => {
  const rows = journal(); rows.push({ kind: 'profile-error', profile: 'r1-lp', error: 'x' }, { kind: 'abort', reason: 'run deadline' }, { kind: 'page-error', profile: 'nowhere', error: 'y' });
  assert.deepEqual(reduceEventsJournal(rows, RESULT).faults, [{ kind: 'profile-error', profile: 'r1-lp' }, { kind: 'abort', profile: null }, { kind: 'page-error', profile: null }]);
});
test('reduce: refuses rows it cannot place', () => {
  const bad = [
    { kind: 'case', suite: 'events', id: 'get_exists', ok: true, steps: [], profile: 'r3-ws' },          // unknown profile
    { kind: 'case', suite: 'admin', id: 'get_exists', ok: true, steps: [], profile: 'r1-ws' },           // suite of another profile
    { kind: 'case', suite: 'events', id: 'push', ok: true, steps: [], profile: 'r1-ws' },                // admin case in an events profile
    { kind: 'case', suite: 'events', id: 'fanout', ok: 'yes', steps: [], profile: 'r1-ws' },             // ok not boolean
    { kind: 'case', suite: 'events', id: 'fanout', ok: true, profile: 'r1-ws' },                         // finished case without steps
    { kind: 'case', suite: 'events', id: 'fanout', ok: true, steps: {}, profile: 'r1-ws' },              // steps not a list
    { kind: 'sdk-event', profile: 'r1-ws', role: 'writer', event: 'connected' },                       // not emitted by these suites
    { kind: 'novel', profile: 'r1-ws' },
    'not an object',
  ];
  for (const row of bad) assert.throws(() => reduceEventsJournal([...journal(), row], RESULT), Error, JSON.stringify(row));
  assert.throws(() => reduceEventsJournal({}, RESULT)); assert.throws(() => reduceEventsJournal(journal(), null));
  assert.throws(() => reduceEventsJournal(journal(), { ...RESULT, suite: 'small' }), /suite/);
});
test('reduce: a single suite run has only its own profiles', () => {
  const rows = journal().filter(r => r.kind !== 'case' || r.suite === 'admin');
  const r = reduceEventsJournal(rows, { ...RESULT, suite: 'admin' });
  assert.deepEqual(r.profiles.map(p => p.name), ['r1-admin', 'r2-admin']);
  assert.throws(() => reduceEventsJournal(journal(), { ...RESULT, suite: 'admin' }), /profile/);
});
