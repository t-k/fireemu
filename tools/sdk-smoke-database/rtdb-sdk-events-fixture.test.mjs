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
  assert.throws(() => reduceEventsJournal({}, RESULT), /journal rows must be an array/); assert.throws(() => reduceEventsJournal(journal(), null), /result.json is missing/);
  assert.throws(() => reduceEventsJournal(journal(), { ...RESULT, suite: 'small' }), /result.json suite small is not an events or admin suite/);
});
test('reduce: a single suite run has only its own profiles', () => {
  const rows = journal().filter(r => r.kind !== 'case' || r.suite === 'admin');
  const r = reduceEventsJournal(rows, { ...RESULT, suite: 'admin' });
  assert.deepEqual(r.profiles.map(p => p.name), ['r1-admin', 'r2-admin']);
  assert.throws(() => reduceEventsJournal(journal(), { ...RESULT, suite: 'admin' }), /profile/);
});

test('reduce: an unknown SDK mutation outcome of a case row (or of the seed) is kept in the reduction', () => {
  const rows = journal();
  const c = rows.find(r => r.kind === 'case' && r.id === 'get_exists'); c.unknown = ['get_exists/get'];
  const seed = rows.find(r => r.kind === 'case' && r.id === 'seed'); seed.ok = false; seed.error = 'Timeout: seed timed out after 10000 ms'; seed.unknown = ['seed'];
  const r = reduceEventsJournal(rows, RESULT);
  assert.deepEqual(r.profiles[0].rows.find(x => x.id === 'get_exists').unknown, ['get_exists/get']);
  assert.deepEqual(r.profiles[0].rows.find(x => x.id === 'seed').unknown, ['seed']);
  assert.equal(Object.hasOwn(r.profiles[1].rows[0], 'unknown'), false);
});

test('reduce: an empty unknown list is not kept', () => {
  const rows = journal(); rows.find(r => r.kind === 'case' && r.id === 'get_exists').unknown = [];
  assert.equal(Object.hasOwn(reduceEventsJournal(rows, RESULT).profiles[0].rows.find(x => x.id === 'get_exists'), 'unknown'), false);
});

test('reduce: the credential outcome of an admin refusal is kept in the reduced result, and absent otherwise', () => {
  const r = reduceEventsJournal(journal(), { ...RESULT, status: 'incomplete', observed: 42, exit: 1, credentialOutcome: ['r1-admin'] });
  assert.deepEqual(r.result, { status: 'incomplete', observed: 42, exit: 1, cleanup: { prefix: 'verified', rules: 'verified' }, credentialOutcome: ['r1-admin'] });
  assert.equal(Object.hasOwn(reduceEventsJournal(journal(), RESULT).result, 'credentialOutcome'), false);
});

test('reduce: the in-flight measurement row of the long-polling page is ignored like the other capture rows', () => {
  const rows = journal(); rows.splice(2, 0, { kind: 'lp-inflight', profile: 'r1-lp', maxInFlight: 7, inFlight: 0, stopped: false });
  assert.deepEqual(reduceEventsJournal(rows, RESULT), reduceEventsJournal(journal(), RESULT));
});

// The production fixture (fixtures/production-sdk-events.json): the builder, its validation and the committed file.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { CASE_SOURCES, CREDENTIAL, buildEventsFixture, maxInFlightOf, recordedJournal } from './rtdb-sdk-events-fixture.mjs';
import { stepCount, summarize } from './rtdb-sdk-events-judge.mjs';
import { scriptManifest } from './sdk-observer/lib.mjs';

const sha = b => createHash('sha256').update(b).digest('hex');
const PROD = { ...RESULT, runId: 'RTDB-EVENTS-20261104-01', target: 'production', scriptSha256: 'e'.repeat(64), sdk: { firebase: '12.18.0', database: '1.1.5', playwright: '1.62.1', firebaseAdmin: '14.3.0' }, startedAt: '2026-11-04T02:02:35.785Z', endedAt: '2026-11-04T02:05:50.755Z', cases: [], unverified: [], adminStartup: { 'r1-admin': true, 'r2-admin': true }, counts: { direct: 184, reserve: 4, adc: 1 }, caps: { direct: 200, reserve: 12, adc: 1 } };
const META = { recordedOn: '2026-11-04', bookingRow: 1252, closeRow: 1253, approvals: [2227, 2228], requests: 188, packetSha256: 'f'.repeat(64), sourceHead: 'd'.repeat(40), credential: CREDENTIAL, journalSha256: 'a'.repeat(64), resultSha256: 'b'.repeat(64) };
const seeded = seed => () => { seed = (seed * 1103515245 + 12345) % 2147483648; return seed / 2147483648; };
const withInflight = () => { const rows = journal(); rows.splice(3, 0, { kind: 'lp-inflight', profile: 'r1-lp', maxInFlight: 5, inFlight: 1, stopped: false }, { kind: 'lp-inflight', profile: 'r2-lp', maxInFlight: 7, inFlight: 3, stopped: false }, { kind: 'lp-inflight', profile: 'r1-lp', maxInFlight: 6, inFlight: 0, stopped: true }); return rows; };

test('build: the reduction plus the provenance of the run, the ledgers and the credential', () => {
  const doc = buildEventsFixture(withInflight(), PROD, META);
  const { provenance, ...reduced } = doc;
  assert.deepEqual(reduced, reduceEventsJournal(withInflight(), PROD));
  assert.deepEqual(Object.keys(provenance), ['runId', 'target', 'project', 'instance', 'suite', 'recordedOn', 'startedAt', 'endedAt', 'scriptSha256', 'sourceHead', 'packetSha256', 'sdk', 'caseSources', 'counts', 'caps', 'maxInFlight', 'adminStartup', 'credential', 'cleanup', 'observations', 'sandboxLedger', 'approvals', 'journalSha256', 'resultSha256']);
  assert.deepEqual(provenance.counts, { requests: 188, direct: 184, reserve: 4, adc: 1, overflow: 0 });
  assert.deepEqual(provenance.maxInFlight, { 'r1-lp': 6, 'r2-lp': 7 });
  assert.deepEqual(provenance.sandboxLedger, { booking: 1252, close: 1253 });
  assert.deepEqual(provenance.approvals, [2227, 2228]);
  assert.deepEqual([provenance.project, provenance.instance, provenance.suite, provenance.observations, provenance.credential], ['fireemu-oracle-query', 'fireemu-q-rtdb2', 'events+admin', 52, CREDENTIAL]);
  assert.deepEqual(provenance.adminStartup, { 'r1-admin': true, 'r2-admin': true });
  assert.deepEqual(Object.keys(provenance.caseSources), CASE_SOURCES);
  for (const name of CASE_SOURCES) assert.equal(provenance.caseSources[name], sha(readFileSync(new URL(`./sdk-observer/${name}`, import.meta.url))), name);
  assert.match(CREDENTIAL, /user OAuth access token/); assert.match(CREDENTIAL, /not a service account/);
});

test('build: only a production run; the counts add up to the ledger, one ADC, no overflow', () => {
  const rows = journal();
  assert.throws(() => buildEventsFixture(rows, { ...PROD, target: 'emulator' }, META), /production/);
  assert.throws(() => buildEventsFixture(rows, { ...PROD, target: undefined }, META), /production/);
  assert.throws(() => buildEventsFixture(rows, PROD, { ...META, requests: 187 }), /requests/);
  assert.throws(() => buildEventsFixture(rows, PROD, { ...META, requests: 189 }), /requests/);
  assert.throws(() => buildEventsFixture(rows, { ...PROD, counts: { ...PROD.counts, adc: 2 } }, META), /ADC/);
  assert.throws(() => buildEventsFixture(rows, { ...PROD, counts: { ...PROD.counts, adc: 0 } }, META), /ADC/);
  assert.throws(() => buildEventsFixture(rows, { ...PROD, counts: { ...PROD.counts, overflow: 1 } }, META), /overflow/);
  assert.throws(() => buildEventsFixture(rows, { ...PROD, counts: undefined }, META), /requests/);
  // property: random count triples are accepted exactly when direct + reserve equals the ledger's requests and adc is 1
  const rnd = seeded(7);
  for (let i = 0; i < 300; i++) {
    const direct = Math.floor(rnd() * 250), reserve = Math.floor(rnd() * 13), adc = Math.floor(rnd() * 3), requests = rnd() < 0.5 ? direct + reserve : Math.floor(rnd() * 260), overflow = rnd() < 0.8 ? undefined : Math.floor(rnd() * 2);
    const counts = { direct, reserve, adc, ...(overflow === undefined ? {} : { overflow }) }, ok = direct + reserve === requests && adc === 1 && !overflow;
    const run = () => buildEventsFixture(rows, { ...PROD, counts }, { ...META, requests });
    if (ok) assert.deepEqual(run().provenance.counts, { requests, direct, reserve, adc, overflow: 0 }, JSON.stringify(counts));
    else assert.throws(run, /requests|ADC|overflow/, JSON.stringify({ counts, requests }));
  }
});

test('build: an admin credential refusal, an admin profile without startup or an unknown write refuses the fixture', () => {
  const rows = journal();
  assert.throws(() => buildEventsFixture(rows, { ...PROD, credentialOutcome: ['r1-admin'] }, META), /credential/);
  assert.throws(() => buildEventsFixture(rows, { ...PROD, adminStartup: { 'r1-admin': true, 'r2-admin': false } }, META), /startup/);
  assert.throws(() => buildEventsFixture(rows, { ...PROD, adminStartup: { 'r1-admin': true } }, META), /startup/);
  assert.throws(() => buildEventsFixture(rows, { ...PROD, adminStartup: undefined }, META), /startup/);
  assert.throws(() => buildEventsFixture(rows, { ...PROD, adminStartup: { 'r1-admin': 'true', 'r2-admin': true } }, META), /startup/);
  assert.throws(() => buildEventsFixture(rows, { ...PROD, unverified: [{ id: 'push' }] }, META), /unverified/);
  assert.throws(() => buildEventsFixture(rows, { ...PROD, unverified: undefined }, META), /unverified/);
  // an events-only run has no admin profiles and needs no admin startup
  const events = rows.filter(r => r.kind !== 'case' || r.suite === 'events');
  assert.deepEqual(buildEventsFixture(events, { ...PROD, suite: 'events', adminStartup: undefined }, META).provenance.adminStartup, {});
});

test('build: every meta field is required', () => {
  for (const field of Object.keys(META)) {
    assert.throws(() => buildEventsFixture(journal(), PROD, { ...META, [field]: undefined }), /missing/, field);
    assert.throws(() => buildEventsFixture(journal(), PROD, { ...META, [field]: '' }), /missing/, field);
  }
  assert.throws(() => buildEventsFixture(journal(), PROD, { ...META, approvals: [] }), /missing/);
  assert.throws(() => buildEventsFixture(journal(), PROD, { ...META, bookingRow: Number.NaN }), /missing/);
  assert.throws(() => buildEventsFixture(journal(), PROD, null), /missing/);
});

test('build: property: secret-shaped text and a 12-digit number anywhere in a kept value refuse the fixture', () => {
  const leaks = ['AIzaSyA-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx', 'ya29.a0AfBx', 'eyJhbGciOiJSUzI1NiJ9', 'owner@example.com', 'p 123456789012 q', 123456789012];
  const rnd = seeded(11);
  for (let i = 0; i < 120; i++) {
    const rows = journal({ cases: 2 }), cases = rows.filter(r => r.kind === 'case' && r.steps), row = cases[Math.floor(rnd() * cases.length)], leak = leaks[Math.floor(rnd() * leaks.length)];
    const where = Math.floor(rnd() * 3);
    if (where === 0) row.steps[0].result = { exists: true, v: { leaf: leak } };
    else if (where === 1) row.steps[0].observer = [{ l: 'L', e: 'value', k: null, v: { children: [['k', leak]] } }];
    else { row.ok = false; row.error = `Error: ${leak}`; }
    assert.throws(() => buildEventsFixture(rows, PROD, META), /secret|number/, JSON.stringify({ leak, where }));
  }
  for (const near of ['12345678901', '1234567890123', 'AIza-short', 'ya29']) {   // near misses stay publishable
    const rows = journal(); rows.find(r => r.kind === 'case' && r.steps).steps[0].result = { exists: true, v: { leaf: near } };
    assert.doesNotThrow(() => buildEventsFixture(rows, PROD, META), near);
  }
});

test('maxInFlightOf: the largest measurement per long-polling profile, none without rows, refuses a malformed row', () => {
  assert.deepEqual(maxInFlightOf(withInflight()), { 'r1-lp': 6, 'r2-lp': 7 });
  assert.deepEqual(maxInFlightOf(journal()), {});
  assert.throws(() => maxInFlightOf([{ kind: 'lp-inflight', profile: 'r1-lp', maxInFlight: '7' }]), /in-flight/);
  assert.throws(() => maxInFlightOf([{ kind: 'lp-inflight', profile: 'r1-ws', maxInFlight: 7 }]), /in-flight/);
});

test('recordedJournal: drops the provenance of a production fixture, passes a plain reduction, refuses any other provenance', () => {
  const doc = buildEventsFixture(journal(), PROD, META), plain = reduceEventsJournal(journal(), PROD);
  assert.deepEqual(recordedJournal(doc), plain);
  assert.equal(recordedJournal(plain), plain);
  assert.throws(() => recordedJournal({ ...doc, provenance: { ...doc.provenance, target: 'emulator' } }), /production/);
  assert.throws(() => recordedJournal({ ...doc, provenance: null }), /production/);
  assert.throws(() => recordedJournal(null), /reduced/);
  assert.equal(summarize(recordedJournal(doc), plain).problems.some(p => p.includes('not a reduced')), false);
  assert.ok(summarize(doc, plain).problems.some(p => p.includes('not a reduced')));   // the judge itself never reads a fixture with its provenance
});

test('the committed fixture: RTDB-EVENTS-20261104-01, 6 profiles, 160 of 160 against itself, bound to the observer bytes that ran', () => {
  const fixture = JSON.parse(readFileSync(new URL('./fixtures/production-sdk-events.json', import.meta.url), 'utf8')), p = fixture.provenance;
  assert.deepEqual([p.runId, p.target, p.suite, p.recordedOn, p.observations], ['RTDB-EVENTS-20261104-01', 'production', 'events+admin', '2026-11-04', 52]);
  assert.deepEqual(p.counts, { requests: 188, direct: 184, reserve: 4, adc: 1, overflow: 0 });
  assert.deepEqual(p.sandboxLedger, { booking: 1252, close: 1253 }); assert.deepEqual(p.approvals, [2227, 2228]);
  assert.deepEqual(p.adminStartup, { 'r1-admin': true, 'r2-admin': true }); assert.deepEqual(p.maxInFlight, { 'r1-lp': 7, 'r2-lp': 7 });
  assert.equal(p.credential, CREDENTIAL); assert.deepEqual(p.cleanup, { prefix: 'verified', rules: 'verified' });
  assert.equal(p.scriptSha256, 'ffb061388fae0e1266e7ff0a84d68d9aa028f45ad6148ea607d3839fd76b3a76');
  assert.equal(scriptManifest(new URL('./sdk-observer/', import.meta.url).pathname).sha256, p.scriptSha256, 'the replay runs the observer bytes of the production run');
  for (const name of CASE_SOURCES) assert.equal(sha(readFileSync(new URL(`./sdk-observer/${name}`, import.meta.url))), p.caseSources[name], name);
  assert.deepEqual(fixture.profiles.map(x => [x.name, x.rows.length]), [['r1-ws', 11], ['r1-lp', 11], ['r2-ws', 11], ['r2-lp', 11], ['r1-admin', 11], ['r2-admin', 11]]);
  const recorded = recordedJournal(fixture), s = summarize(recorded, structuredClone(recorded));
  assert.equal(s.match, true, JSON.stringify(s.problems)); assert.equal(s.counts.MATCH, stepCount('events+admin')); assert.equal(s.counts.MATCH, 160);
});
