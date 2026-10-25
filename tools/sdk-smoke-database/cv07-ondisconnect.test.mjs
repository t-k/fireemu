import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import { compareEvents, FIXTURE, fireDelays, fixtureFromRecording, KEYS, PREFIXES, projectEvent, sanitizeResult, timingJudgement } from './cv07-ondisconnect.mjs';

const fixture = JSON.parse(readFileSync(new URL(FIXTURE, import.meta.url), 'utf8'));
const clone = (value) => JSON.parse(JSON.stringify(value));

test('the production fixture holds four flows of nine projected events and no timing or secret', () => {
  assert.equal(fixture.events.length, 36);
  for (const [i, prefix] of PREFIXES.entries()) {
    const flow = fixture.events.slice(i * 9, i * 9 + 9);
    assert.ok(flow.every((e) => e.prefix === prefix && e.transport === (i % 2 ? 'lp' : 'ws')));
    assert.deepEqual(flow.map((e) => e.type), ['sdk-step', 'sdk-ack', 'sdk-callback', 'sdk-ack', 'sdk-step', 'sdk-callback', 'sdk-get', 'sdk-callback', 'sdk-ack']);
  }
  for (const event of fixture.events) assert.deepEqual(Object.keys(event).filter((k) => !KEYS.includes(k)), []);
  const text = JSON.stringify(fixture);
  assert.doesNotMatch(text, /monotonicMs|"ms"|AIza|eyJ|ya29\.|@/);
  assert.deepEqual(Object.keys(fixture.onDisconnectFireSeconds).toSorted(), PREFIXES.toSorted());
});

test('projectEvent keeps only the eight comparison keys', () => {
  assert.deepEqual(projectEvent({ type: 'sdk-ack', step: 'remove', prefix: 'p', transport: 'ws', ms: 4, sequence: 9, counters: {} }), { type: 'sdk-ack', step: 'remove', prefix: 'p', transport: 'ws' });
  assert.deepEqual(projectEvent({ type: 'sdk-callback', value: null }), { type: 'sdk-callback', value: null });
});

test('the fixture matches itself and every near miss is a mismatch', () => {
  assert.deepEqual(compareEvents(fixture.events, clone(fixture.events)), { matched: true, mismatches: [] });
  const changed = clone(fixture.events);
  changed[5].value = { state: 'online' };
  assert.equal(compareEvents(fixture.events, changed).mismatches[0].index, 5);
  const swapped = clone(fixture.events);
  [swapped[6], swapped[7]] = [swapped[7], swapped[6]];
  assert.equal(compareEvents(fixture.events, swapped).matched, false);
  const short = clone(fixture.events).slice(0, 35);
  assert.deepEqual(compareEvents(fixture.events, short), { matched: false, mismatches: [{ index: 35, native: fixture.events[35], local: null }] });
  const extra = [...clone(fixture.events), { type: 'page-error', message: 'boom' }];
  assert.equal(compareEvents(fixture.events, extra).matched, false);
  const wrongTransport = clone(fixture.events);
  wrongTransport[9].transport = 'ws';
  assert.equal(compareEvents(fixture.events, wrongTransport).matched, false);
});

test('fireDelays measures from writer-offline to the next callback of the same flow', () => {
  const events = [
    { type: 'sdk-step', step: 'writer-offline', prefix: 'a', ms: 1000 },
    { type: 'sdk-callback', prefix: 'a', ms: 1149 },
    { type: 'sdk-callback', prefix: 'a', ms: 5000 },
    { type: 'sdk-step', step: 'writer-offline', prefix: 'b', ms: 2000 },
    { type: 'sdk-callback', prefix: 'b', ms: 105_051 },
  ];
  assert.deepEqual(fireDelays(events), { a: 0.1, b: 103.1 });
  assert.deepEqual(fireDelays([{ type: 'sdk-step', step: 'writer-offline', prefix: 'c', ms: 1 }]), { c: null });
});

test('timingJudgement accepts WS within 2 s and LP within the tolerance around production', () => {
  const ok = { [PREFIXES[0]]: 0.1, [PREFIXES[1]]: 105.0, [PREFIXES[2]]: 0.0, [PREFIXES[3]]: 104.9 };
  assert.deepEqual(timingJudgement(ok, fixture.onDisconnectFireSeconds), { within: true, outside: [] });
  for (const [prefix, seconds] of [[PREFIXES[0], 2.1], [PREFIXES[1], 94.0], [PREFIXES[3], 110.0], [PREFIXES[1], null]]) {
    const judged = timingJudgement({ ...ok, [prefix]: seconds }, fixture.onDisconnectFireSeconds);
    assert.equal(judged.within, false, `${prefix} ${seconds}`);
    assert.deepEqual(judged.outside.map((o) => o.prefix), [prefix]);
  }
});

test('sanitizeResult drops raw millisecond timings and keeps the projection', () => {
  const result = sanitizeResult({ local: [{ type: 'sdk-ack', step: 'x', prefix: 'p', transport: 'ws', ms: 3 }], native: [{ type: 'sdk-ack', step: 'x', prefix: 'p', transport: 'ws' }], fire: { p: 0.1 }, nativeFire: { p: 0.2 } });
  assert.doesNotMatch(JSON.stringify(result), /"ms"/);
  assert.equal(result.matched, true);
  assert.equal(result.localEvents, 1);
  assert.deepEqual(result.onDisconnectFireSeconds, { local: { p: 0.1 }, production: { p: 0.2 } });
});

test('fixtureFromRecording keeps sdk events only, projected, with fire delays from monotonicMs', () => {
  const lines = [
    { type: 'local-fulfill', url: 'x', sequence: 1, monotonicMs: 1 },
    { type: 'sdk-step', step: 'writer-offline', prefix: 'a', transport: 'lp', sequence: 2, monotonicMs: 1000, counters: {} },
    { type: 'http-chunk', sequence: 3, monotonicMs: 2000 },
    { type: 'sdk-callback', value: { state: 'offline' }, prefix: 'a', transport: 'lp', sequence: 4, monotonicMs: 101_800 },
  ].map((e) => JSON.stringify(e));
  const built = fixtureFromRecording(lines);
  assert.deepEqual(built.events, [{ type: 'sdk-step', step: 'writer-offline', prefix: 'a', transport: 'lp' }, { type: 'sdk-callback', value: { state: 'offline' }, prefix: 'a', transport: 'lp' }]);
  assert.deepEqual(built.onDisconnectFireSeconds, { a: 100.8 });
});
