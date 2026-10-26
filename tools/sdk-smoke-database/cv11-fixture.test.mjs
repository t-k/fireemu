import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import { comparison, compareRecorded, FIXTURE, fixtureFromJournal, RACING_STEPS, sanitizeProfiles } from './cv11-fixture.mjs';

const fixture = JSON.parse(readFileSync(new URL(FIXTURE, import.meta.url), 'utf8'));
const local = JSON.parse(readFileSync(new URL('./fixtures/local-cv11-genuine-auth.json', import.meta.url), 'utf8'));
const clone = (value) => JSON.parse(JSON.stringify(value));
const STEPS = ['signin-a', 'listen-1', 'refresh-1', 'signout', 'signout-wait', 'resignin-a', 'listen-2', 'signin-b', 'b-read-own', 'b-read-a', 'signout-b', 'delete-a', 'write-after-delete', 'refresh-after-delete', 'post-refresh-wait', 'end', 'runner'];

test('the production fixture holds four profiles of 23 events without timings or secrets', () => {
  assert.deepEqual(fixture.profiles.map((p) => p.name), ['r1-ws', 'r1-lp', 'r2-ws', 'r2-lp']);
  for (const profile of fixture.profiles) {
    assert.equal(profile.journal.length, 23);
    assert.deepEqual([...new Set(profile.journal.map((e) => e.step))], STEPS);
    assert.ok(profile.journal.every((e) => !('ms' in e)));
  }
  assert.doesNotMatch(JSON.stringify(fixture), /AIza|eyJ|ya29\.|@|"ms"|"uid"/);
});

test('the recorded production behaviour: sign-out and deletion cancel the listener, B cannot read A', () => {
  for (const { name, journal } of fixture.profiles) {
    const find = (step, type) => journal.find((e) => e.step === step && e.type === type);
    assert.deepEqual(find('signout-wait', 'cancel'), { step: 'signout-wait', type: 'cancel', epoch: 1, code: 'PERMISSION_DENIED' }, name);
    assert.deepEqual(find('b-read-a', 'error'), { step: 'b-read-a', type: 'error', code: 'message:permission-denied' }, name);
    assert.deepEqual(find('refresh-after-delete', 'error'), { step: 'refresh-after-delete', type: 'error', code: 'auth/user-token-expired' }, name);
    assert.deepEqual(find('post-refresh-wait', 'cancel'), { step: 'post-refresh-wait', type: 'cancel', epoch: 2, code: 'PERMISSION_DENIED' }, name);
    assert.equal(find('runner', 'transport').code, name.slice(3));
  }
});

test('the committed local journal of the closure binary matches the production fixture', () => {
  const result = comparison(fixture, local);
  assert.equal(result.match, true, JSON.stringify(result.differences));
  assert.deepEqual(result.profiles.map((p) => [p.productionEvents, p.localEvents]), [[23, 23], [23, 23], [23, 23], [23, 23]]);
});

test('within one step the order is a race; across steps it is the observation', () => {
  const raced = clone(local);
  const journal = raced.profiles[0].journal;
  const i = journal.findIndex((e) => e.step === 'write-after-delete');
  [journal[i], journal[i + 1]] = [journal[i + 1], journal[i]];
  assert.equal(comparison(fixture, raced).match, true);
  const reordered = clone(local);
  const steps = reordered.profiles[1].journal;
  const a = steps.findIndex((e) => e.step === 'b-read-own');
  [steps[a], steps[a + 1]] = [steps[a + 1], steps[a]];
  assert.equal(comparison(fixture, reordered).match, false);
});

test('every near miss of the local journal is a difference', () => {
  const mutate = (edit) => { const copy = clone(local); edit(copy.profiles); return comparison(fixture, copy).match; };
  assert.equal(mutate((p) => { p[2].journal.find((e) => e.type === 'cancel').code = 'UNAVAILABLE'; }), false);
  assert.equal(mutate((p) => { p[3].journal = p[3].journal.filter((e) => e.step !== 'post-refresh-wait'); }), false);
  assert.equal(mutate((p) => { p[0].journal.find((e) => e.step === 'listen-2').shape = '{"value":2}'; }), false);
  assert.equal(mutate((p) => { p[1].journal.find((e) => e.step === 'runner').code = 'ws'; }), false);
  assert.equal(mutate((p) => { p[0].journal.find((e) => e.type === 'cancel').epoch = 2; }), false);
  assert.throws(() => mutate((p) => { p.pop(); }), /four CV11 profiles/);
});

test('sanitizeProfiles drops timings and unknown fields, and the fixture refuses a local journal', () => {
  const [profile] = sanitizeProfiles([{ name: 'r1-ws', journal: [{ step: 's', type: 'ok', ms: 5, extra: 1 }] }, { name: 'r1-lp', journal: [] }, { name: 'r2-ws', journal: [] }, { name: 'r2-lp', journal: [] }]);
  assert.deepEqual(profile, { name: 'r1-ws', journal: [{ step: 's', type: 'ok' }] });
  assert.throws(() => fixtureFromJournal({ mode: 'local', profiles: local.profiles }), /production journal/);
  assert.throws(() => fixtureFromJournal({ mode: 'production', profiles: [{ name: 'r1-ws', journal: [{ step: 'x', type: 'ok', code: 'a@example.com' }] }, ...local.profiles.slice(1)] }), /secret/);
});

test('only the write-after-delete step is judged unordered; every other multi-event step keeps its order', () => {
  assert.deepEqual([...RACING_STEPS], ['write-after-delete']);
  for (const [step, profile] of [['signin-a', 0], ['signout', 1], ['resignin-a', 2], ['refresh-after-delete', 3], ['write-after-delete', 0]]) {
    const copy = clone(local);
    const journal = copy.profiles[profile].journal;
    const i = journal.findIndex((e) => e.step === step);
    assert.equal(journal[i + 1].step, step, step);
    [journal[i], journal[i + 1]] = [journal[i + 1], journal[i]];
    assert.equal(comparison(fixture, copy).match, step === 'write-after-delete', step);
  }
  assert.deepEqual(compareRecorded(fixture.profiles, clone(local).profiles), { match: true, differences: [] });
});

test('compareRecorded refuses an extra trailing event and an extra profile', () => {
  const longer = clone(local).profiles;
  longer[2].journal.push({ step: 'runner', type: 'transport', code: 'ws' });
  assert.equal(compareRecorded(fixture.profiles, longer).match, false);
  const more = [...clone(local).profiles, { name: 'r3-ws', journal: [] }];
  assert.equal(compareRecorded(fixture.profiles, more).match, false);
});
