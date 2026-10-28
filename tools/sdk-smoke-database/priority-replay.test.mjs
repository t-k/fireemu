import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { validateFixture, compareObservation, correlatedAck, validAckSet, incomingAllowed, Peer, extractFixture, loadFixture, replayCase, EXPECTED_CASES } from './priority-replay.mjs';

const operations = [
  { action: 'o', path: 's', value: { b: 1, c: 2, '.priority': 1 } },
  { action: 'oc', path: 's/b' },
  { action: 'o', path: 's', value: { z: 1 } },
  { action: 'o', path: 't', value: 1 },
];
const record = () => ({ id: 'heal-reregister', round: 'r1', operations, acknowledgements: [0, 1, 2, 3], writerClosed: true, observerLive: true, observerClosed: true, initial: { s: null, t: null }, updates: [{ path: 's', value: { z: 1 } }, { path: 't', value: 1 }], readback: { s: { z: 1 }, t: 1 } });

test('the reference contains the exact twelve case-round-profile test combinations', () => {
  assert.equal(EXPECTED_CASES.length, 12);
  assert.equal(new Set(EXPECTED_CASES.map(x => x.join('/'))).size, 12);
});

test('an exact settled observation matches; unknowns cannot match', () => {
  const expected = record();
  assert.equal(compareObservation(expected, structuredClone(expected)).verdict, 'MATCH');
  for (const edit of [
    x => x.acknowledgements.pop(), x => x.acknowledgements.push(1), x => x.acknowledgements.reverse(),
    x => { x.writerClosed = false; }, x => { x.observerLive = false; }, x => { x.observerClosed = false; },
    x => { delete x.readback.t; }, x => { x.readback.s = null; }, x => x.updates.push({ path: 't', value: 9 }),
    x => { x.operations[0].value['.priority'] = '1'; },
  ]) {
    const local = structuredClone(expected); edit(local);
    assert.notEqual(compareObservation(expected, local).verdict, 'MATCH');
  }
});

test('fixture rejects partial, duplicated and secret-bearing observations', () => {
  assert.throws(() => validateFixture({ schemaVersion: 1, cases: [record()] }));
  assert.throws(() => validateFixture({ schemaVersion: 1, cases: Array(6).fill(record()) }));
});


test('reviewed fixture covers all generated case, round and profile seeds', async () => {
  const text = await readFile(new URL('./fixtures/production-priority.json', import.meta.url), 'utf8');
  const fixture = loadFixture(text);
  assert.equal(fixture.cases.length, 6);
  for (const [id, round, profile] of EXPECTED_CASES) {
    const expected = fixture.cases.find(row => row.id === id && row.round === round);
    assert.ok(expected, `${id}/${round}/${profile}`);
    assert.equal(compareObservation(expected, structuredClone(expected)).verdict, 'MATCH');
  }
  const changed = structuredClone(fixture);
  changed.cases[0].observerClosed = false;
  assert.throws(() => validateFixture(changed));
  changed.cases[0].observerClosed = true;
  changed.cases[0].extra = 'unexpected';
  assert.throws(() => validateFixture(changed));
  assert.throws(() => loadFixture(text.replace('firebase 12.18.0', 'firebase 0')));
  assert.throws(() => extractFixture('{}', '{}'));
});

test('only one successful reply correlated to the exact request can acknowledge an operation', () => {
  const reply = (id, status) => ({ t: 'd', d: { r: id, b: { s: status } } });
  assert.equal(correlatedAck([reply(7, 'ok')], 7), true);
  assert.equal(correlatedAck([], 7), false);
  assert.equal(correlatedAck([reply(8, 'ok')], 7), false);
  assert.equal(correlatedAck([reply(7, 'denied')], 7), false);
  assert.equal(correlatedAck([reply(7, 'ok'), reply(7, 'ok')], 7), false);
  assert.equal(validAckSet([reply(7, 'ok')], [7]), true);
  assert.equal(validAckSet([reply(7, 'ok'), reply(8, 'ok')], [7]), false);
  assert.equal(validAckSet([reply(7, 'ok'), reply('8', 'ok')], [7]), false);
  assert.equal(validAckSet([reply(7, 'ok'), reply(7, 'ok')], [7]), false);
});

test('local transport rejects non-loopback before opening a network connection', async () => {
  await assert.rejects(replayCase('https://example.invalid', record()), /loopback origin required/);
});

test('each recorded round preserves typed registrations, observed updates and export values', async () => {
  const fixture = loadFixture(await readFile(new URL('./fixtures/production-priority.json', import.meta.url), 'utf8'));
  const expected = {
    'heal-reregister': {
      operations: [
        { action: 'o', path: 's', value: { b: 1, c: 2, '.priority': 1 } },
        { action: 'oc', path: 's/b' },
        { action: 'o', path: 's', value: { z: 1 } },
        { action: 'o', path: 't', value: 1 },
      ],
      updates: [{ path: 's', value: { z: 1 } }, { path: 't', value: 1 }],
      readback: { s: { z: 1 }, t: 1 },
    },
    'nested-priority': {
      operations: [
        { action: 'o', path: 's', value: { k: 1, a: { x: 1, y: 2, '.priority': 1 } } },
        { action: 'oc', path: 's/a/x' },
        { action: 'o', path: 't', value: 1 },
      ],
      updates: [], readback: { s: null, t: null },
    },
    'string-priority': {
      operations: [
        { action: 'o', path: 's', value: { b: 1, c: 2, '.priority': 'p' } },
        { action: 'oc', path: 's/b' },
        { action: 'o', path: 't', value: 1 },
      ],
      updates: [], readback: { s: null, t: null },
    },
  };
  for (const row of fixture.cases) {
    assert.deepEqual(row.operations, expected[row.id].operations, `${row.id}/${row.round}`);
    assert.deepEqual(row.updates, expected[row.id].updates, `${row.id}/${row.round}`);
    assert.deepEqual(row.readback, expected[row.id].readback, `${row.id}/${row.round}`);
  }
});


test('watch cancellation, reset, shutdown and unknown control poison the connection', () => {
  assert.equal(incomingAllowed({ t: 'c', d: { t: 'h' } }, 'observer'), true);
  assert.equal(incomingAllowed({ t: 'd', d: { r: 1, b: { s: 'ok' } } }, 'observer'), true);
  assert.equal(incomingAllowed({ t: 'd', d: { a: 'd', b: { p: 's', d: null } } }, 'observer'), true);
  assert.equal(incomingAllowed({ t: 'd', d: { a: 'c', b: { p: 's' } } }, 'observer'), false);
  for (const control of ['r', 's', 'x']) assert.equal(incomingAllowed({ t: 'c', d: { t: control } }, 'observer'), false);
  assert.equal(incomingAllowed({ t: 'd', d: { a: 'd', b: {} } }, 'writer'), false);
});

test('redirected Rules baseline is rejected without opening sockets or following it', async () => {
  let seen;
  const fetchImpl = async (_url, options) => { seen = options; return { status: 302 }; };
  await assert.rejects(replayCase('http://127.0.0.1:12345', record(), { fetchImpl, peerFactory: () => { throw Error('must not open'); } }), /baseline unresolved/);
  assert.equal(seen.redirect, 'manual');
});


test('a cancellation remains sticky even after a later successful ACK', () => {
  class FakeSocket extends EventTarget { constructor() { super(); this.readyState = 1; } }
  const socket = new FakeSocket();
  const peer = new Peer('ws://unused', 'observer', () => socket);
  socket.dispatchEvent(new MessageEvent('message', { data: JSON.stringify({ t: 'd', d: { a: 'c', b: { p: 's' } } }) }));
  socket.dispatchEvent(new MessageEvent('message', { data: JSON.stringify({ t: 'd', d: { r: 1, b: { s: 'ok' } } }) }));
  assert.equal(peer.failed, true);
  assert.equal(peer.validAcks(), false);
});

test('a failed Rules setup still cleans its owned root and restores the exact baseline', async () => {
  const baseline = '{"rules":{".read":false,".write":false}}';
  let rules = baseline;
  const calls = [];
  const fetchImpl = async (url, options) => {
    calls.push({ url, method: options.method ?? 'GET', redirect: options.redirect });
    if (url.includes('/.settings/rules.json')) {
      if (options.method === 'PUT') {
        if (options.body !== baseline) { rules = options.body; return { status: 500 }; }
        rules = options.body; return { status: 200 };
      }
      return { status: 200, text: async () => rules };
    }
    if (options.method === 'DELETE') return { status: 200 };
    return { status: 200, json: async () => null };
  };
  await assert.rejects(replayCase('http://127.0.0.1:12345', record(), { fetchImpl, peerFactory: () => { throw Error('must not open'); } }), /setup refused/);
  assert.equal(rules, baseline);
  assert.ok(calls.some(call => call.method === 'DELETE'));
  assert.ok(calls.every(call => call.redirect === 'manual'));
});

test('successful replay restores Rules and removes only its owned root', async () => {
  const baseline = '{"rules":{".read":false}}';
  let rules = baseline, writerClosed = false, observer;
  const calls = [];
  const fetchImpl = async (url, options) => {
    calls.push({ url, method: options.method ?? 'GET', redirect: options.redirect });
    if (url.includes('/.settings/rules.json')) {
      if (options.method === 'PUT') rules = options.body;
      return { status: 200, text: async () => rules };
    }
    if (options.method === 'DELETE') return { status: 200 };
    const value = writerClosed && url.includes('/s.json') ? { z: 1 } : writerClosed && url.includes('/t.json') ? 1 : null;
    return { status: 200, json: async () => value };
  };
  class FakePeer {
    constructor(role) { this.role = role; this.closed = false; this.failed = false; this.messages = []; this.sent = []; this.requests = []; this.socket = { readyState: WebSocket.OPEN }; }
    async open() {}
    async request(action, body) { const r = this.requests.length + 1; this.requests.push(r); this.sent.push({ t: 'd', d: { r, a: action, b: body } }); }
    validAcks() { return !this.failed; }
    async close() {
      this.closed = true;
      if (this.role === 'writer') {
        writerClosed = true;
        const root = this.sent[0].d.b.p.replace(/\/s$/, '');
        observer.messages.push({ t: 'd', d: { a: 'd', b: { p: `${root}/s`, d: { z: 1 } } } }, { t: 'd', d: { a: 'd', b: { p: `${root}/t`, d: 1 } } });
      }
      return true;
    }
  }
  const peerFactory = (_url, role) => { const peer = new FakePeer(role); if (role === 'observer') observer = peer; return peer; };
  const result = await replayCase('http://127.0.0.1:12345', record(), { fetchImpl, peerFactory, wait: async () => {}, settleMs: 0 });
  assert.equal(compareObservation(record(), result.actual).verdict, 'MATCH');
  assert.equal(result.evidence.ownedRootAbsent, true);
  assert.equal(result.evidence.rulesRestored, true);
  assert.equal(rules, baseline);
  assert.equal(calls.filter(call => call.method === 'DELETE').length, 1);
  assert.ok(calls.every(call => call.redirect === 'manual'));
});
