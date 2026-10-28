// Local raw-protocol replay of six reviewed RTDB onDisconnect priority observations.
import { createHash, randomBytes } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { isDeepStrictEqual } from 'node:util';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import { assertNoSecrets } from './cv11-genuine-auth.mjs';

const IDS = ['heal-reregister', 'nested-priority', 'string-priority'];
const ROUNDS = ['r1', 'r2'];
const PROFILES = ['strict', 'ordinary'];
export const EXPECTED_CASES = IDS.flatMap(id => ROUNDS.flatMap(round => PROFILES.map(profile => [id, round, profile])));
const FIXTURE_SHA256 = '3957b787fe86b4d37cd89f6756b709577e847471538f54a85d742ba1052e684e';
const EXPECTED_HASHES = {
  events: 'b9014b11abf9ca813e7959e703e5a9b2178045be431d607e068107187a0718ab',
  requests: 'b2949aa7236fec81ce3d3ffdeee6a7857e8cbf7ef221ca54ea28c4b8b6b3d085',
};
const sha = value => createHash('sha256').update(value).digest('hex');
const parseLines = text => text.trim().split('\n').map(line => JSON.parse(line));
const fail = message => { throw Error(message); };
const expectedCount = id => id === 'heal-reregister' ? 4 : 3;
const validId = (id, round) => IDS.includes(id) && ROUNDS.includes(round);
const relpath = (full, id, round) => {
  const match = /^\/?(rnext1_[a-f0-9]{24})\/(r[12])\/([a-z-]+)\/(s(?:\/[a-z]+)*|t)$/.exec(full);
  if (!match || match[2] !== round || match[3] !== id) fail('unexpected source path');
  return { prefix: match[1], path: match[4] };
};
const one = (rows, predicate, message) => {
  const matches = rows.filter(predicate);
  if (matches.length !== 1) fail(message);
  return matches[0];
};

/** Projects reviewed private production journals into a portable, credential-free fixture. */
export function extractFixture(eventsText, requestsText) {
  if (sha(eventsText) !== EXPECTED_HASHES.events || sha(requestsText) !== EXPECTED_HASHES.requests) fail('production journal hash mismatch');
  const events = parseLines(eventsText), requests = parseLines(requestsText), cases = [];
  for (const round of ROUNDS) for (const id of IDS) {
    const scoped = events.map((row, index) => ({ ...row, index })).filter(row => (row.owner?.id ?? row.id) === id && (row.owner?.round ?? row.round) === round);
    const socket = (type, role) => one(scoped, row => row.type === type && row.owner?.role === role, `missing or duplicate ${role} ${type}`);
    const wo = socket('socket-open', 'writer'), wc = socket('socket-close', 'writer');
    const oo = socket('socket-open', 'observer'), oc = socket('socket-close', 'observer');
    if (!(oo.index < wo.index && wo.index < wc.index && wc.index < oc.index)) fail('socket lifecycle order');
    const writerFrames = scoped.filter(row => row.type === 'frame' && row.owner?.role === 'writer').map(row => ({ ...row, parsed: JSON.parse(row.payload) }));
    const sends = writerFrames.filter(row => row.direction === 'sent' && ['o', 'oc'].includes(row.parsed?.d?.a));
    if (sends.length !== expectedCount(id)) fail('registration count');
    const ids = new Set(), operations = [], acknowledgements = [], wireReplies = [];
    let prefix;
    for (const [index, row] of sends.entries()) {
      const d = row.parsed.d, request = d.r;
      if (!Number.isSafeInteger(request) || ids.has(request) || row.index <= wo.index || row.index >= wc.index) fail('registration identity');
      ids.add(request);
      const path = relpath(d.b?.p, id, round);
      if (prefix && prefix !== path.prefix) fail('mixed source prefixes');
      prefix = path.prefix;
      const reply = one(writerFrames, x => x.direction === 'received' && x.parsed?.d?.r === request, 'missing or duplicate wire ACK');
      if (reply.index <= row.index || reply.index >= wc.index || reply.parsed.d?.b?.s !== 'ok') fail('wire ACK not settled');
      operations.push({ action: d.a, path: path.path, ...(d.a === 'o' ? { value: d.b.d } : {}) });
      acknowledgements.push(index);
      wireReplies.push(reply);
    }
    const sdkAcks = scoped.filter(row => row.type === 'sdk-event' && row.role === 'writer' && row.event?.type === 'ack');
    if (sdkAcks.length !== sends.length || sdkAcks.some((row, i) => {
      const op = operations[i], method = op.action === 'oc' ? 'cancel' : op.value && typeof op.value === 'object' && Object.hasOwn(op.value, '.priority') ? 'priority' : 'set';
      return row.event.index !== i || row.event.id !== id || row.event.path !== op.path || row.event.method !== method || row.index <= wireReplies[i].index || row.index >= wc.index;
    })) fail('SDK ACK mismatch');
    if (scoped.some(row => row.type === 'sdk-event' && !['ack', 'value'].includes(row.event?.type))) fail('unexpected SDK event');
    const values = scoped.filter(row => row.type === 'sdk-event' && row.role === 'observer' && row.event?.type === 'value');
    const initial = {};
    for (const leaf of ['s', 't']) {
      const first = one(values, row => row.event.leaf === leaf && row.index < sends[0].index, 'observer initial value unresolved');
      if (first.event.value !== null) fail('observer not initially ready');
      initial[leaf] = first.event.value;
    }
    const updates = values.filter(row => row.index > wc.index).map(row => ({ path: row.event.leaf, value: row.event.value }));
    if (values.some(row => row.index >= sends[0].index && row.index <= wc.index)) fail('unexpected observer update before close');
    const pushes = scoped.filter(row => row.type === 'frame' && row.owner?.role === 'observer' && row.direction === 'received' && row.index > wc.index && row.index < oc.index).map(row => JSON.parse(row.payload)).filter(msg => ['d', 'm'].includes(msg?.d?.a)).map(msg => ({ path: relpath(msg.d.b.p, id, round).path, value: msg.d.b.d }));
    if (!isDeepStrictEqual(pushes, updates)) fail('observer wire/SDK mismatch');
    const readback = {};
    for (const leaf of ['s', 't']) {
      const path = `/${prefix}/${round}/${id}/${leaf}.json`;
      const start = one(requests, row => row.state === 'before-send' && row.method === 'GET' && new URL(row.url).pathname === path && new URL(row.url).searchParams.get('format') === 'export', 'readback request missing');
      const headers = one(requests, row => row.id === start.id && row.state === 'response-headers', 'readback headers missing');
      const body = one(requests, row => row.id === start.id && row.state === 'response-persisted', 'readback body missing');
      const bytes = Buffer.from(body.bodyBase64, 'base64');
      if (headers.status !== 200 || bytes.length !== body.bodyBytes || sha(bytes) !== body.bodySha256) fail('readback not verified');
      readback[leaf] = JSON.parse(bytes.toString('utf8'));
    }
    cases.push({ id, round, operations, acknowledgements, writerClosed: true, observerLive: true, observerClosed: true, initial, updates, readback });
  }
  const fixture = { schemaVersion: 1, provenance: { source: 'reviewed production priority-r1', sdk: 'firebase 12.18.0', reviewSha256: '08cc42a85070a60628f4d2278844b212cc63516f22ff4ccab9bcf0a9eba0f152', eventsSha256: EXPECTED_HASHES.events, requestsSha256: EXPECTED_HASHES.requests }, cases };
  validateFixture(fixture);
  assertNoSecrets(JSON.stringify(fixture), []);
  return fixture;
}

const keysEqual = (value, keys) => value && typeof value === 'object' && !Array.isArray(value) && isDeepStrictEqual(Object.keys(value).sort(), [...keys].sort());
const RECORD_KEYS = ['id', 'round', 'operations', 'acknowledgements', 'writerClosed', 'observerLive', 'observerClosed', 'initial', 'updates', 'readback'];

/** Checks the provenance, exact six identities and settled result structure. */
export function validateFixture(fixture) {
  const provenance = { source: 'reviewed production priority-r1', sdk: 'firebase 12.18.0', reviewSha256: '08cc42a85070a60628f4d2278844b212cc63516f22ff4ccab9bcf0a9eba0f152', eventsSha256: EXPECTED_HASHES.events, requestsSha256: EXPECTED_HASHES.requests };
  if (!keysEqual(fixture, ['schemaVersion', 'provenance', 'cases']) || fixture.schemaVersion !== 1 || !isDeepStrictEqual(fixture.provenance, provenance) || !Array.isArray(fixture.cases) || fixture.cases.length !== 6) fail('invalid fixture');
  const seen = new Set();
  for (const row of fixture.cases) {
    if (!keysEqual(row, RECORD_KEYS) || !validId(row.id, row.round) || seen.has(`${row.id}/${row.round}`)) fail('invalid case identity');
    seen.add(`${row.id}/${row.round}`);
    if (!Array.isArray(row.operations) || row.operations.length !== expectedCount(row.id) || !isDeepStrictEqual(row.acknowledgements, row.operations.map((_, i) => i)) || row.writerClosed !== true || row.observerLive !== true || row.observerClosed !== true || !isDeepStrictEqual(row.initial, { s: null, t: null }) || !Array.isArray(row.updates) || !keysEqual(row.readback, ['s', 't'])) fail('unsettled case');
    if (row.operations.some(op => !['o', 'oc'].includes(op.action) || !keysEqual(op, op.action === 'o' ? ['action', 'path', 'value'] : ['action', 'path']) || !/^(s(?:\/[a-z]+)*|t)$/.test(op.path))) fail('invalid operation');
    if (row.updates.some(update => !keysEqual(update, ['path', 'value']) || !['s', 't'].includes(update.path))) fail('invalid observer update');
  }
  assertNoSecrets(JSON.stringify(fixture), []);
  return fixture;
}

/** Parses only the exact reviewed portable fixture. */
export function loadFixture(text) {
  if (sha(text) !== FIXTURE_SHA256) fail('fixture hash mismatch');
  return validateFixture(JSON.parse(text));
}

/** Compares actual outcomes only after all transport evidence is settled. */
export function compareObservation(expected, actual) {
  if (!keysEqual(actual, RECORD_KEYS) || actual.id !== expected.id || actual.round !== expected.round || !isDeepStrictEqual(actual.operations, expected.operations) || !isDeepStrictEqual(actual.acknowledgements, expected.operations.map((_, i) => i)) || actual.writerClosed !== true || actual.observerLive !== true || actual.observerClosed !== true || !actual.initial || !actual.readback || !Object.hasOwn(actual.initial, 's') || !Object.hasOwn(actual.initial, 't') || !Object.hasOwn(actual.readback, 's') || !Object.hasOwn(actual.readback, 't') || !Array.isArray(actual.updates)) return { verdict: 'UNRESOLVED' };
  const equal = isDeepStrictEqual(actual.initial, expected.initial) && isDeepStrictEqual(actual.updates, expected.updates) && isDeepStrictEqual(actual.readback, expected.readback);
  return { verdict: equal ? 'MATCH' : 'MISMATCH' };
}

/** Checks exactly one successful reply for a sent request ID. */
export function correlatedAck(messages, id) {
  const replies = messages.filter(message => message?.t === 'd' && message.d?.r === id);
  return replies.length === 1 && replies[0].d?.b?.s === 'ok';
}

/** Rejects unsolicited, duplicated, missing or failed replies for a connection. */
export function validAckSet(messages, requestIds) {
  const replies = messages.filter(message => message?.t === 'd' && message.d && Object.hasOwn(message.d, 'r'));
  return replies.every(message => Number.isSafeInteger(message.d.r)) && replies.length === requestIds.length && requestIds.every(id => correlatedAck(replies, id)) && replies.every(message => requestIds.includes(message.d.r));
}

/** Restricts incoming realtime messages to the admitted handshake, replies and observer data. */
export function incomingAllowed(message, role) {
  if (message === 0) return true;
  if (!message || typeof message !== 'object') return false;
  if (message.t === 'c') return message.d?.t === 'h';
  if (message.t !== 'd' || !message.d || typeof message.d !== 'object') return false;
  if (Object.hasOwn(message.d, 'r')) return Number.isSafeInteger(message.d.r);
  return role === 'observer' && ['d', 'm'].includes(message.d.a);
}

const delay = milliseconds => new Promise(resolveDelay => setTimeout(resolveDelay, milliseconds));
async function waitUntil(predicate, label, timeoutMs = 10000) {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() >= deadline) fail(`${label} timeout`);
    await delay(10);
  }
}

export class Peer {
  constructor(url, role, socketFactory = value => new WebSocket(value)) {
    this.role = role;
    this.socket = socketFactory(url);
    this.messages = [];
    this.failed = false;
    this.closed = false;
    this.next = 1;
    this.requests = [];
    this.sent = [];
    this.socket.addEventListener('message', event => {
      try {
        const message = JSON.parse(String(event.data));
        if (!incomingAllowed(message, this.role)) this.failed = true;
        this.messages.push(message);
      } catch { this.failed = true; }
    });
    this.socket.addEventListener('error', () => { this.failed = true; });
    this.socket.addEventListener('close', () => { this.closed = true; });
  }
  async open() {
    await waitUntil(() => this.socket.readyState === WebSocket.OPEN || this.failed, 'socket open');
    if (this.failed || this.closed) fail('socket failed');
  }
  async request(action, body) {
    if (this.failed || this.closed || this.socket.readyState !== WebSocket.OPEN) fail('socket is not live');
    const id = this.next++;
    this.requests.push(id);
    const frame = { t: 'd', d: { r: id, a: action, b: body } };
    this.sent.push(frame);
    this.socket.send(JSON.stringify(frame));
    await waitUntil(() => this.failed || this.closed || this.messages.some(message => message?.t === 'd' && message.d?.r === id), 'ACK');
    if (this.failed || this.closed || !correlatedAck(this.messages, id)) fail('ACK unresolved');
  }
  validAcks() { return !this.failed && validAckSet(this.messages, this.requests); }
  async close() {
    if (this.socket.readyState === WebSocket.OPEN || this.socket.readyState === WebSocket.CONNECTING) this.socket.close();
    await waitUntil(() => this.closed || this.failed, 'socket close');
    return this.closed && !this.failed;
  }
}

/** Runs exactly one local socket pair; no production endpoints or credentials are accepted. */
export async function replayCase(origin, row, { namespace = 'demo-rtdb-priority', settleMs = 20000, fetchImpl = fetch, peerFactory = (url, role) => new Peer(url, role), wait = delay } = {}) {
  const url = new URL(origin);
  if (url.protocol !== 'http:' || !['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname) || url.username || url.password || url.pathname !== '/' || url.search || url.hash) fail('loopback origin required');
  if (!validId(row.id, row.round) || !Number.isInteger(settleMs) || settleMs < 0 || settleMs > 20000 || !/^[a-z0-9-]+$/.test(namespace)) fail('invalid local case');
  const root = `priorityreplay${randomBytes(8).toString('hex')}/${row.round}/${row.id}`;
  const wsUrl = `${url.origin.replace(/^http:/, 'ws:')}/.ws?v=5&ns=${namespace}`;
  const jsonUrl = path => `${url.origin}/${root}/${path}.json?ns=${namespace}&format=export`;
  const read = async path => {
    const response = await fetchImpl(jsonUrl(path), { headers: { authorization: 'Bearer owner' }, redirect: 'manual', signal: AbortSignal.timeout(10000) });
    if (response.status !== 200) fail('readback refused');
    return response.json();
  };
  const rulesUrl = `${url.origin}/.settings/rules.json?ns=${namespace}`;
  const rootUrl = `${url.origin}/${root.split('/')[0]}.json?ns=${namespace}`;
  const headers = { authorization: 'Bearer owner', 'content-type': 'application/json' };
  const baseline = await fetchImpl(rulesUrl, { headers, redirect: 'manual', signal: AbortSignal.timeout(10000) });
  if (baseline.status !== 200) fail('local rules baseline unresolved');
  const originalRules = await baseline.text();
  const rules = { rules: { '.read': false, '.write': false, [root.split('/')[0]]: { '.read': true, '.write': true } } };
  let observer, writer, result;
  try {
    const configured = await fetchImpl(rulesUrl, { method: 'PUT', headers, body: JSON.stringify(rules), redirect: 'manual', signal: AbortSignal.timeout(10000) });
    if (configured.status !== 200) fail('local rules setup refused');
    observer = peerFactory(wsUrl, 'observer');
    await observer.open();
    for (const path of ['s', 't']) await observer.request('q', { p: `/${root}/${path}`, h: '' });
    const initial = { s: await read('s'), t: await read('t') };
    const initialFrames = observer.messages.filter(message => message?.t === 'd' && ['d', 'm'].includes(message.d?.a));
    for (const message of initialFrames) {
      const path = String(message.d.b?.p ?? '').replace(/^\//, '');
      if (message.d.a !== 'd' || ![`${root}/s`, `${root}/t`].includes(path) || message.d.b?.d !== null) fail('initial observer data unresolved');
    }
    if (observer.failed || observer.closed || !observer.validAcks()) fail('initial observer unresolved');
    writer = peerFactory(wsUrl, 'writer');
    await writer.open();
    const firstUpdate = observer.messages.length;
    const acknowledgements = [];
    for (const [index, operation] of row.operations.entries()) {
      await writer.request(operation.action, { p: `/${root}/${operation.path}`, ...(operation.action === 'o' ? { d: operation.value } : {}) });
      acknowledgements.push(index);
    }
    const writerClosed = await writer.close();
    await wait(settleMs);
    const observerLive = !observer.closed && !observer.failed && observer.socket.readyState === WebSocket.OPEN;
    const updates = observer.messages.slice(firstUpdate).filter(message => message?.t === 'd' && ['d', 'm'].includes(message.d?.a)).map(message => {
      const path = String(message.d.b?.p ?? '').replace(/^\//, '');
      if (!path.startsWith(`${root}/`)) fail('unexpected observer path');
      return { path: path.slice(root.length + 1), value: message.d.b?.d, ...(message.d.a === 'm' ? { action: 'm' } : {}) };
    });
    const readback = { s: await read('s'), t: await read('t') };
    if (!writer.validAcks() || !observer.validAcks() || !observerLive || observer.closed || observer.failed) fail('connection evidence unresolved');
    const observerClosed = await observer.close();
    if (!observerClosed) fail('observer close unresolved');
    const operations = writer.sent.map(frame => {
      const path = String(frame.d.b?.p ?? '').replace(/^\//, '');
      if (!path.startsWith(`${root}/`)) fail('unexpected writer path');
      return { action: frame.d.a, path: path.slice(root.length + 1), ...(Object.hasOwn(frame.d.b, 'd') ? { value: frame.d.b.d } : {}) };
    });
    const actual = { id: row.id, round: row.round, operations, acknowledgements, writerClosed, observerLive, observerClosed, initial, updates, readback };
    const evidence = {
      writerAcks: writer.requests.map(id => ({ requestId: id, status: 'ok' })),
      observerAcks: observer.requests.map(id => ({ requestId: id, status: 'ok' })),
      writerCloseObserved: writerClosed,
      observerLiveAtReadback: observerLive,
      observerCloseObserved: observerClosed,
      initialDataFrames: initialFrames.length,
      initialEvidence: 'correlated subscription ACK, live observer, empty-cache hash and independent REST null; SDK callback is not a wire frame',
    };
    result = { actual, evidence };
  } finally {
    let cleanupFailed = false;
    for (const peer of [writer, observer]) {
      if (peer && !peer.closed) {
        try { if (!await peer.close()) cleanupFailed = true; } catch { cleanupFailed = true; }
      }
    }
    try {
      const removed = await fetchImpl(rootUrl, { method: 'DELETE', headers, redirect: 'manual', signal: AbortSignal.timeout(10000) });
      if (removed.status !== 200) cleanupFailed = true;
      const absent = await fetchImpl(rootUrl, { headers, redirect: 'manual', signal: AbortSignal.timeout(10000) });
      if (absent.status !== 200 || await absent.json() !== null) cleanupFailed = true;
    } catch { cleanupFailed = true; }
    try {
      const restored = await fetchImpl(rulesUrl, { method: 'PUT', headers, body: originalRules, redirect: 'manual', signal: AbortSignal.timeout(10000) });
      if (restored.status !== 200) cleanupFailed = true;
      const after = await fetchImpl(rulesUrl, { headers, redirect: 'manual', signal: AbortSignal.timeout(10000) });
      if (after.status !== 200 || await after.text() !== originalRules) cleanupFailed = true;
    } catch { cleanupFailed = true; }
    if (cleanupFailed) fail('local cleanup or Rules restoration unresolved');
  }
  result.evidence.ownedRootAbsent = true;
  result.evidence.rulesRestored = true;
  return result;
}

export async function replayLocal(origin, fixture, profile, options = {}) {
  validateFixture(fixture);
  if (!PROFILES.includes(profile)) fail('invalid profile');
  const rows = [];
  for (const expected of fixture.cases) {
    try {
      const { actual, evidence } = await replayCase(origin, expected, options);
      rows.push({ id: expected.id, round: expected.round, profile, ...compareObservation(expected, actual), actual, evidence });
    } catch {
      rows.push({ id: expected.id, round: expected.round, profile, verdict: 'UNRESOLVED' });
      break;
    }
  }
  return rows;
}

async function main(args) {
  if (args[0] === 'fixture' && args.length === 4) {
    const fixture = extractFixture(await readFile(args[1], 'utf8'), await readFile(args[2], 'utf8'));
    await writeFile(args[3], `${JSON.stringify(fixture, null, 2)}\n`, { flag: 'wx' });
    return;
  }
  if (args[0] === 'local' && args.length === 4) {
    const fixture = loadFixture(await readFile(new URL('./fixtures/production-priority.json', import.meta.url), 'utf8'));
    await mkdir(args[3]);
    const rows = await replayLocal(args[1], fixture, args[2]);
    await writeFile(`${args[3]}/comparison.json`, `${JSON.stringify({ profile: args[2], rows }, null, 2)}\n`, { flag: 'wx' });
    console.log(JSON.stringify({ profile: args[2], rows: rows.length, matched: rows.filter(row => row.verdict === 'MATCH').length }));
    if (rows.length !== 6 || rows.some(row => row.verdict !== 'MATCH')) process.exitCode = 1;
    return;
  }
  fail('usage: fixture <events> <requests> <new fixture> | local <loopback origin> <strict|ordinary> <new directory>');
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main(process.argv.slice(2)).catch(() => { console.error('priority replay stopped'); process.exitCode = 2; });
