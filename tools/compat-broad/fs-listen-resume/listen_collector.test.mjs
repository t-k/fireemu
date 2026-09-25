// Tests for the bounded collector. They use an in-memory fake backend, never a
// socket, never a credential and never the oracle project. The fake models the
// listener behaviour the cases describe; agreement with the fake proves the
// collector machinery works, not that production or fireemu behaves this way.

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  aggregateChanges,
  argvIsClean,
  buildReceipt,
  checkInvariants,
  classifyCleanup,
  createBudget,
  normalizeListenerError,
  ownedPaths,
  ownerMarker,
  planCleanup,
  redact,
  runCase,
  runCatalog,
  runCleanup,
  secondaryPaths,
} from './listen_collector.mjs';

const NONCE = '0123456789abcdef0123456789abcdef';
const UID = 'throwaway-uid';
const UID_B = 'second-uid';

const nowFactory = () => {
  let clock = 0;
  return {
    now: () => clock,
    sleep: async ms => {
      clock += ms;
    },
    advance: ms => {
      clock += ms;
    },
  };
};

const createFake = ({ denyPrivate = false } = {}) => {
  const store = new Map();
  const listeners = [];
  const network = new Map();
  const auth = new Map();
  let stamp = 0;

  const allowed = (client, path) =>
    !path.startsWith('o6_listen_private/') ||
    (!denyPrivate && auth.get(client) === path.split('/')[1]);

  const queryDocs = spec => {
    const prefix = `${spec.parent}/${spec.target}/`;
    return [...store.entries()]
      .filter(([path]) => path.startsWith(prefix))
      .filter(([, value]) => value.fields.rank < spec.where[2])
      .sort((a, b) => a[1].fields.rank - b[1].fields.rank)
      .slice(0, spec.limit)
      .map(([path]) => path);
  };

  const diff = (before, after) => {
    const changes = [];
    for (const path of before) {
      if (!after.includes(path)) {
        changes.push({ type: 'removed', path, oldIndex: before.indexOf(path), newIndex: -1 });
      }
    }
    for (const path of after) {
      if (!before.includes(path)) {
        changes.push({ type: 'added', path, oldIndex: -1, newIndex: after.indexOf(path) });
      }
    }
    return changes;
  };

  const deliver = (listener, { fromCache = false, hasPendingWrites = false, overlay = null } = {}) => {
    const read = path => (overlay && overlay.path === path ? overlay.value : store.get(path));
    if (listener.kind === 'document') {
      if (!allowed(listener.client, listener.path)) {
        listener.onError({ code: 'permission-denied' });
        listener.dead = true;
        return;
      }
      const value = read(listener.path);
      listener.onNext({ path: listener.path, exists: Boolean(value), fromCache, hasPendingWrites });
      return;
    }
    const after = queryDocs(listener.spec);
    const changes = diff(listener.previous, after).map(change => ({
      ...change,
      type:
        change.type === 'added' && listener.previous.includes(change.path) ? 'modified' : change.type,
    }));
    const modified = after.filter(
      path =>
        listener.previous.includes(path) && listener.versions.get(path) !== store.get(path)?.updateTime,
    );
    for (const path of modified) {
      changes.push({
        type: 'modified',
        path,
        oldIndex: listener.previous.indexOf(path),
        newIndex: after.indexOf(path),
      });
    }
    listener.previous = after;
    listener.versions = new Map(after.map(path => [path, store.get(path)?.updateTime]));
    if (changes.length === 0 && !listener.first && !listener.forceMetadata) return;
    listener.first = false;
    listener.forceMetadata = false;
    listener.onNext({ docs: after, changes, fromCache, hasPendingWrites });
  };

  const broadcast = options => {
    for (const listener of listeners) {
      if (listener.dead || listener.closed) continue;
      if (network.get(listener.client) === false) {
        listener.pending = true;
        continue;
      }
      deliver(listener, options);
    }
  };

  const firestore = {
    async setDoc(client, path, fields) {
      if (!allowed(client, path)) throw { code: 'permission-denied' };
      stamp += 1;
      const value = { fields, updateTime: `t${stamp}` };
      for (const listener of listeners) {
        if (listener.dead || listener.closed || listener.client !== client) continue;
        if (!listener.includeMetadataChanges) continue;
        if (listener.kind === 'document' && listener.path !== path) continue;
        deliver(listener, { fromCache: true, hasPendingWrites: true, overlay: { path, value } });
      }
      store.set(path, value);
      broadcast({});
    },
    async deleteDoc(client, path, precondition) {
      const current = store.get(path);
      if (precondition && current && precondition.updateTime !== current.updateTime) {
        throw { code: 'failed-precondition' };
      }
      store.delete(path);
      broadcast({});
    },
    async deleteOwnedDoc(client, path, condition) {
      cleanupCalls.push(['delete', client, path]);
      const current = store.get(path);
      if (current && current.fields.owner !== condition.owner) {
        throw { code: 'failed-precondition' };
      }
      store.delete(path);
      broadcast({});
    },
    async getDoc(client, path) {
      cleanupCalls.push(['read', client, path]);
      const value = store.get(path);
      return value ? { exists: true, ...value } : { exists: false, fields: null, updateTime: null };
    },
    onDocSnapshot(client, path, options, onNext, onError) {
      const listener = {
        kind: 'document',
        client,
        path,
        includeMetadataChanges: options.includeMetadataChanges,
        onNext,
        onError,
        first: true,
      };
      listeners.push(listener);
      // Latency compensation: the real SDK serves the first document callback
      // from the local cache before the server round trip. A default-mode
      // listener sees only that one, because no data changed afterwards.
      deliver(listener, { fromCache: !options.includeMetadataChanges });
      return () => {
        listener.closed = true;
      };
    },
    onQuerySnapshot(client, spec, options, onNext, onError) {
      const listener = {
        kind: 'query',
        client,
        spec,
        includeMetadataChanges: options.includeMetadataChanges,
        onNext,
        onError,
        previous: [],
        versions: new Map(),
        first: true,
      };
      listeners.push(listener);
      deliver(listener, {});
      return () => {
        listener.closed = true;
      };
    },
    async disableNetwork(client) {
      network.set(client, false);
      for (const listener of listeners) {
        if (listener.client === client && listener.includeMetadataChanges && !listener.closed) {
          listener.forceMetadata = true;
          deliver(listener, { fromCache: true });
        }
      }
    },
    async enableNetwork(client) {
      network.set(client, true);
      for (const listener of listeners) {
        if (listener.client === client && listener.pending && !listener.closed) {
          listener.pending = false;
          deliver(listener, { fromCache: false });
        }
      }
    },
  };

  const revoked = [];
  const cleanupCalls = [];
  const authApi = {
    async signIn(client) {
      // The secondary client is the second principal; everything else is the first.
      auth.set(client, client === 'secondary' ? UID_B : UID);
    },
    async revoke(client) {
      revoked.push(auth.get(client));
    },
    async signOut(client) {
      auth.set(client, null);
      for (const listener of listeners) {
        if (listener.client === client && !listener.closed && !listener.dead) {
          if (!allowed(client, listener.path ?? '')) {
            listener.dead = true;
            listener.onError({ code: 'firestore/permission-denied' });
          }
        }
      }
    },
  };

  return { store, listeners, firestore, auth: authApi, revoked, cleanupCalls,
    setUid: (client, uid) => auth.set(client, uid) };
};

const contextFor = (fake, clock, caseSpec, overrides = {}) => {
  const paths = ownedPaths(NONCE, UID);
  const names = new Map(Object.entries(paths).map(([name, path]) => [path, name]));
  return {
    client: 'primary',
    clients: { primary: 'primary', witness: 'witness' },
    nonce: NONCE,
    paths,
    nameOf: path => names.get(path) ?? path.split('/').at(-1),
    stepTimeoutMs: 5_000,
    pollMs: 10,
    budget: createBudget({
      now: clock.now,
      deadlineMs: 600_000,
      limits: { reads: 400, writes: 60, deletes: 20, snapshots: 120, listeners: 4 },
    }),
    ...overrides,
  };
};

const caseFixture = overrides => ({
  caseId: 'FIXTURE',
  role: 'observation',
  comparison: 'ordered-events',
  listeners: [{ name: 'primary', kind: 'document', target: 'alpha', includeMetadataChanges: false }],
  steps: [],
  expectedLocal: [],
  invariants: [],
  ...overrides,
});

test('redact removes secret-shaped keys and bearer-shaped values', () => {
  const dirty = {
    uid: 'u1',
    password: 'hunter2',
    nested: { idToken: 'abc', refresh_token: 'def', note: 'safe' },
    list: [{ Authorization: 'Bearer xyz' }],
    raw: 'eyJhbGciOiJIUzI1NiJ9.payload',
  };
  assert.deepEqual(redact(dirty), {
    uid: 'u1',
    password: '[redacted]',
    nested: { idToken: '[redacted]', refresh_token: '[redacted]', note: 'safe' },
    list: [{ Authorization: '[redacted]' }],
    raw: '[redacted]',
  });
});

test('argv carrying a secret is refused', () => {
  assert.equal(argvIsClean(['node', 'collector.mjs', '--nonce', NONCE]), true);
  assert.equal(argvIsClean(['node', 'collector.mjs', '--password', 'hunter2']), false);
  assert.equal(argvIsClean(['node', 'collector.mjs', 'eyJhbGciOiJIUzI1NiJ9.x']), false);
});

test('the budget refuses a charge past its cap and past its deadline', () => {
  const clock = nowFactory();
  const budget = createBudget({
    now: clock.now,
    deadlineMs: 1_000,
    limits: { reads: 1, writes: 0, deletes: 0, snapshots: 0, listeners: 0 },
  });
  assert.equal(budget.charge('reads').ok, true);
  assert.equal(budget.charge('reads').ok, false);
  assert.equal(budget.charge('writes').error, 'budget-exceeded:writes');
  assert.equal(budget.charge('nope').error, 'unknown-charge:nope');
  clock.advance(2_000);
  assert.equal(budget.charge('reads').error, 'deadline-exceeded');
  const snapshot = budget.snapshot();
  assert.equal(snapshot.exhausted, true);
  assert.ok(snapshot.exceeded.includes('deadline'));
});

test('owned paths are nonce scoped and require a uid for the private document', () => {
  const paths = ownedPaths(NONCE, UID);
  assert.equal(paths.run, `o6_listen/${UID}/runs/${NONCE}`);
  assert.equal(paths.private, `o6_listen_private/${UID}`);
  assert.throws(() => ownedPaths('nope', UID), /128-bit/);
  assert.throws(() => ownedPaths(NONCE, ''), /uid/);
});

test('document listener case records one initial snapshot', async () => {
  const fake = createFake();
  const clock = nowFactory();
  const spec = caseFixture({
    steps: [
      { kind: 'seed', doc: 'alpha', fields: { rank: 1 } },
      { kind: 'listen', listener: 'primary' },
      { kind: 'await', listener: 'primary', events: 1 },
    ],
  });
  const ctx = contextFor(fake, clock, spec);
  const record = await runCase({ ...clock, firestore: fake.firestore, auth: fake.auth }, spec, ctx);
  assert.equal(record.complete, true);
  assert.equal(record.listenersClosed, true);
  assert.deepEqual(record.observed, [
    {
      listener: 'primary',
      snapshotKind: 'initial',
      changes: [],
      docs: ['alpha'],
      exists: true,
      fromCache: true,
      hasPendingWrites: false,
      error: null,
    },
  ]);
});

test('a local write raises hasPendingWrites before the acknowledged snapshot', async () => {
  const fake = createFake();
  const clock = nowFactory();
  const spec = caseFixture({
    listeners: [
      { name: 'primary', kind: 'document', target: 'beta', includeMetadataChanges: true },
    ],
    steps: [
      { kind: 'listen', listener: 'primary' },
      { kind: 'await', listener: 'primary', events: 1 },
      { kind: 'write', client: 'primary', doc: 'beta', fields: { rank: 2 } },
      { kind: 'await', listener: 'primary', events: 3 },
    ],
  });
  const ctx = contextFor(fake, clock, spec);
  const record = await runCase({ ...clock, firestore: fake.firestore, auth: fake.auth }, spec, ctx);
  assert.deepEqual(
    record.observed.map(row => [row.snapshotKind, row.exists, row.hasPendingWrites, row.fromCache]),
    [
      ['initial', false, false, false],
      ['delta', true, true, true],
      ['delta', true, false, false],
    ],
  );
});

test('a write from a second client never raises hasPendingWrites here', async () => {
  const fake = createFake();
  const clock = nowFactory();
  const spec = caseFixture({
    listeners: [
      { name: 'primary', kind: 'document', target: 'beta', includeMetadataChanges: true },
    ],
    steps: [
      { kind: 'listen', listener: 'primary' },
      { kind: 'await', listener: 'primary', events: 1 },
      { kind: 'write', client: 'witness', doc: 'beta', fields: { rank: 2 } },
      { kind: 'await', listener: 'primary', events: 2 },
    ],
  });
  const ctx = contextFor(fake, clock, spec);
  const record = await runCase({ ...clock, firestore: fake.firestore, auth: fake.auth }, spec, ctx);
  assert.equal(record.observed.some(row => row.hasPendingWrites), false);
});

test('an unsubscribed listener records no further event while a witness still does', async () => {
  const fake = createFake();
  const clock = nowFactory();
  const spec = caseFixture({
    invariants: ['no-event-after-unsubscribe', 'repeated-unsubscribe-is-a-no-op'],
    listeners: [
      { name: 'primary', kind: 'document', target: 'alpha', includeMetadataChanges: false },
      { name: 'witness', kind: 'document', target: 'alpha', includeMetadataChanges: false },
    ],
    steps: [
      { kind: 'seed', doc: 'alpha', fields: { rank: 1 } },
      { kind: 'listen', listener: 'primary' },
      { kind: 'listen', listener: 'witness' },
      { kind: 'await', listener: 'primary', events: 1 },
      { kind: 'await', listener: 'witness', events: 1 },
      { kind: 'unsubscribe', listener: 'primary' },
      { kind: 'unsubscribe', listener: 'primary', repeat: true },
      { kind: 'write', client: 'witness', doc: 'alpha', fields: { rank: 1, value: 'a1' } },
      { kind: 'await', listener: 'witness', events: 2 },
      { kind: 'quiet', listener: 'primary', seconds: 3 },
    ],
  });
  const ctx = contextFor(fake, clock, spec);
  const record = await runCase({ ...clock, firestore: fake.firestore, auth: fake.auth }, spec, ctx);
  assert.deepEqual(record.invariantViolations, []);
  assert.equal(record.observed.filter(row => row.listener === 'primary').length, 1);
  assert.equal(record.observed.filter(row => row.listener === 'witness').length, 2);
});

test('signing out terminates a rules-protected listener with permission-denied', async () => {
  const fake = createFake();
  const clock = nowFactory();
  const spec = caseFixture({
    invariants: ['no-event-after-listener-error'],
    listeners: [
      { name: 'primary', kind: 'document', target: 'private', includeMetadataChanges: false },
    ],
    steps: [
      { kind: 'signIn', client: 'primary', account: 'throwaway' },
      { kind: 'seed', doc: 'private', fields: { value: 'p0' } },
      { kind: 'listen', listener: 'primary' },
      { kind: 'await', listener: 'primary', events: 1 },
      { kind: 'signOut', client: 'primary' },
      { kind: 'awaitError', listener: 'primary' },
    ],
  });
  const ctx = contextFor(fake, clock, spec);
  const record = await runCase({ ...clock, firestore: fake.firestore, auth: fake.auth }, spec, ctx);
  assert.deepEqual(
    record.observed.map(row => [row.snapshotKind, row.error]),
    [
      ['initial', null],
      ['error', 'permission-denied'],
    ],
  );
  assert.deepEqual(record.invariantViolations, []);
});

test('a listener started while signed out fails with no snapshot first', async () => {
  const fake = createFake({ denyPrivate: true });
  const clock = nowFactory();
  const spec = caseFixture({
    invariants: ['no-server-snapshot-before-error'],
    ignoreCachedPrefix: true,
    listeners: [
      { name: 'primary', kind: 'document', target: 'private', includeMetadataChanges: false },
    ],
    steps: [
      { kind: 'signOut', client: 'primary' },
      { kind: 'listen', listener: 'primary' },
      { kind: 'awaitError', listener: 'primary' },
    ],
  });
  const ctx = contextFor(fake, clock, spec);
  const record = await runCase({ ...clock, firestore: fake.firestore, auth: fake.auth }, spec, ctx);
  assert.deepEqual(record.observed.map(row => row.snapshotKind), ['error']);
  assert.deepEqual(record.invariantViolations, []);
});

test('resume across a forced break reports only the documents that changed', async () => {
  const fake = createFake();
  const clock = nowFactory();
  const spec = caseFixture({
    comparison: 'aggregate-changes',
    invariants: [
      'no-duplicate-added-for-unchanged-document',
      'from-cache-true-then-false-across-break',
      'terminal-document-set-complete',
    ],
    listeners: [{ name: 'primary', kind: 'query', target: 'docs', where: ['rank', '<', 10], limit: 10, includeMetadataChanges: true }],
    steps: [
      { kind: 'seed', doc: 'alpha', fields: { rank: 1 } },
      { kind: 'seed', doc: 'beta', fields: { rank: 2 } },
      { kind: 'listen', listener: 'primary' },
      { kind: 'await', listener: 'primary', events: 1 },
      { kind: 'baseline' },
      { kind: 'break', client: 'primary', mode: 'disable-network' },
      { kind: 'write', client: 'witness', doc: 'gamma', fields: { rank: 5 } },
      { kind: 'write', client: 'witness', doc: 'alpha', fields: { rank: 4 } },
      { kind: 'resume', client: 'primary', mode: 'enable-network' },
      { kind: 'settle', listener: 'primary', seconds: 5 },
    ],
    expectedLocal: [{ docs: ['beta', 'alpha', 'gamma'] }],
  });
  const ctx = contextFor(fake, clock, spec);
  const record = await runCase({ ...clock, firestore: fake.firestore, auth: fake.auth }, spec, ctx);
  assert.equal(record.observed.length, 1);
  assert.deepEqual(record.observed[0].changes, [
    { type: 'modified', doc: 'alpha', oldIndex: null, newIndex: null },
    { type: 'added', doc: 'gamma', oldIndex: null, newIndex: null },
  ]);
  assert.deepEqual(record.observed[0].docs, ['beta', 'alpha', 'gamma']);
  assert.deepEqual(record.invariantViolations, []);
});

test('a resume that re-adds an unchanged document is reported as a violation', () => {
  const violations = checkInvariants(['no-duplicate-added-for-unchanged-document'], {
    duplicateAdded: ['beta'],
  });
  assert.equal(violations.length, 1);
  assert.match(violations[0].detail, /beta/);
});

test('an unknown invariant name is a violation, never a silent pass', () => {
  assert.deepEqual(checkInvariants(['not-a-real-invariant'], {}), [
    { invariant: 'not-a-real-invariant', detail: 'unknown invariant' },
  ]);
});

test('aggregateChanges collapses add-then-update into a single added row', () => {
  const events = [
    { snapshotKind: 'delta', listener: 'primary', fromCache: false, changes: [{ type: 'added', doc: 'gamma' }], docs: ['gamma'] },
    { snapshotKind: 'delta', listener: 'primary', fromCache: false, changes: [{ type: 'modified', doc: 'gamma' }], docs: ['gamma'] },
  ];
  assert.deepEqual(aggregateChanges(events, []).changes, [
    { type: 'added', doc: 'gamma', oldIndex: null, newIndex: null },
  ]);
});

test('the step machine stops at the deadline instead of running forever', async () => {
  const fake = createFake();
  const clock = nowFactory();
  const spec = caseFixture({
    steps: [
      { kind: 'listen', listener: 'primary' },
      { kind: 'await', listener: 'primary', events: 99 },
      { kind: 'seed', doc: 'alpha', fields: { rank: 1 } },
    ],
  });
  const ctx = contextFor(fake, clock, spec, {
    budget: createBudget({
      now: clock.now,
      deadlineMs: 500,
      limits: { reads: 400, writes: 60, deletes: 20, snapshots: 120, listeners: 4 },
    }),
    stepTimeoutMs: 400,
  });
  const record = await runCase({ ...clock, firestore: fake.firestore, auth: fake.auth }, spec, ctx);
  assert.equal(record.complete, false);
  assert.ok(record.failures.includes('step-timeout') || record.failures.includes('deadline-exceeded'));
  assert.equal(record.listenersClosed, true);
});

test('cleanup deletes only documents this run owns and proves final absence', async () => {
  const fake = createFake();
  const clock = nowFactory();
  const paths = ownedPaths(NONCE, UID);
  const budget = createBudget({
    now: clock.now,
    deadlineMs: 60_000,
    limits: { reads: 400, writes: 60, deletes: 20, snapshots: 120, listeners: 4 },
  });
  await fake.firestore.setDoc('primary', paths.alpha, { owner: ownerMarker(NONCE), rank: 1 });
  await fake.firestore.setDoc('primary', paths.beta, { owner: 'someone-else', rank: 2 });
  const result = await runCleanup(
    { firestore: fake.firestore },
    { client: 'primary', paths, nonce: NONCE, budget },
  );
  assert.ok(result.rows.every(row => !('path' in row)), 'cleanup rows must not publish paths');
  assert.ok(result.rows.every(row => /^[0-9a-f]{64}$/.test(row.pathDigest)));
  const byName = Object.fromEntries(result.rows.map(row => [row.name, row.outcome]));
  assert.equal(byName.alpha, 'deleted-and-absent');
  assert.equal(byName.beta, 'not-owned');
  assert.equal(byName.gamma, 'not-created');
  assert.equal(result.complete, false);
  assert.deepEqual(
    result.unproven.map(row => row.name),
    ['beta'],
  );
  assert.equal(fake.store.has(paths.beta), true);
});

test('a cleanup read failure is retained, never reported as success', async () => {
  const clock = nowFactory();
  const paths = ownedPaths(NONCE, UID);
  const budget = createBudget({
    now: clock.now,
    deadlineMs: 60_000,
    limits: { reads: 400, writes: 60, deletes: 20, snapshots: 120, listeners: 4 },
  });
  const deps = {
    firestore: {
      async getDoc() {
        throw { code: 'unavailable' };
      },
    },
  };
  const result = await runCleanup(deps, { client: 'primary', paths, nonce: NONCE, budget });
  assert.equal(result.complete, false);
  assert.ok(result.rows.every(row => row.outcome === 'read-failed'));
});

test('a document that survives its delete is recorded as still present', async () => {
  const clock = nowFactory();
  const paths = ownedPaths(NONCE, UID);
  const budget = createBudget({
    now: clock.now,
    deadlineMs: 60_000,
    limits: { reads: 400, writes: 60, deletes: 20, snapshots: 120, listeners: 4 },
  });
  const deps = {
    firestore: {
      async getDoc(_client, path) {
        return path.endsWith('/alpha')
          ? { exists: true, fields: { owner: ownerMarker(NONCE) }, updateTime: 't1' }
          : { exists: false, fields: null, updateTime: null };
      },
      async deleteDoc() {},
      async deleteOwnedDoc() {},
    },
  };
  const result = await runCleanup(deps, { client: 'primary', paths, nonce: NONCE, budget });
  assert.equal(result.rows.find(row => row.name === 'alpha').outcome, 'still-present');
  assert.equal(result.complete, false);
});

test('cleanup covers every owned path except the run container', () => {
  const paths = ownedPaths(NONCE, UID);
  const planned = planCleanup(paths, NONCE).map(row => row.name);
  assert.deepEqual(planned.sort(), ['absent', 'alpha', 'beta', 'gamma', 'private']);
  assert.ok(planCleanup(paths, NONCE).every(row => row.requiredMarker === ownerMarker(NONCE)));
});

test('classifyCleanup treats an unattempted row as incomplete', () => {
  assert.equal(classifyCleanup([{ outcome: 'unattempted' }]).complete, false);
  assert.equal(
    classifyCleanup([{ outcome: 'deleted-and-absent' }, { outcome: 'not-created' }]).complete,
    true,
  );
});

test('the receipt is incomplete when cleanup or the budget is unproven', () => {
  const clock = nowFactory();
  const budget = createBudget({
    now: clock.now,
    deadlineMs: 1_000,
    limits: { reads: 1, writes: 1, deletes: 1, snapshots: 1, listeners: 1 },
  });
  const base = {
    campaign: { caseId: 'FS-LISTEN-SDK' },
    campaignDigest: 'a'.repeat(64),
    catalogDigest: 'b'.repeat(64),
    environment: { node: process.versions.node, password: 'hunter2' },
    caseRecords: [{ caseId: 'FS-LISTEN-SDK-101', complete: true, listenersClosed: true }],
    budget,
  };
  const good = buildReceipt({ ...base, cleanup: { complete: true, rows: [] } });
  assert.equal(good.complete, true);
  assert.equal(good.productionExecuted, false);
  assert.equal(good.environment.password, '[redacted]');
  const bad = buildReceipt({ ...base, cleanup: { complete: false, rows: [] } });
  assert.equal(bad.complete, false);
  budget.charge('reads');
  budget.charge('reads');
  const exhausted = buildReceipt({ ...base, cleanup: { complete: true, rows: [] } });
  assert.equal(exhausted.complete, false);
});

test('a listener error code is normalized without its transport prefix', () => {
  assert.equal(normalizeListenerError('primary', { code: 'firestore/permission-denied' }).error, 'permission-denied');
  assert.equal(normalizeListenerError('primary', {}).error, 'unknown');
});

test('cleanup runs on its own reserve when the observation budget is exhausted', async () => {
  const fake = createFake();
  const clock = nowFactory();
  const paths = ownedPaths(NONCE, UID);
  const observation = createBudget({
    now: clock.now,
    deadlineMs: 1_000,
    limits: { reads: 0, writes: 1, deletes: 0, snapshots: 0, listeners: 0 },
  });
  const reserve = createBudget({
    now: clock.now,
    deadlineMs: Number.MAX_SAFE_INTEGER,
    limits: { reads: 100, writes: 0, deletes: 50, snapshots: 0, listeners: 0 },
  });
  await fake.firestore.setDoc('primary', paths.alpha, { owner: ownerMarker(NONCE), rank: 1 });
  observation.charge('writes');
  assert.equal(observation.charge('reads').ok, false);
  const result = await runCleanup(
    { firestore: fake.firestore },
    { client: 'primary', paths, nonce: NONCE, budget: reserve },
  );
  assert.equal(result.complete, true);
  assert.equal(fake.store.has(paths.alpha), false);
  assert.equal(observation.snapshot().exhausted, true);
  assert.equal(reserve.snapshot().exhausted, false);
});

test('an exhausted cleanup reserve makes the receipt incomplete', () => {
  const clock = nowFactory();
  const budget = createBudget({
    now: clock.now,
    deadlineMs: 10_000,
    limits: { reads: 10, writes: 10, deletes: 10, snapshots: 10, listeners: 10 },
  });
  const cleanupBudget = createBudget({
    now: clock.now,
    deadlineMs: 10_000,
    limits: { reads: 0, writes: 0, deletes: 0, snapshots: 0, listeners: 0 },
  });
  cleanupBudget.charge('reads');
  const receipt = buildReceipt({
    campaign: { caseId: 'FS-LISTEN-SDK' },
    campaignDigest: 'a'.repeat(64),
    catalogDigest: 'b'.repeat(64),
    environment: { node: process.versions.node },
    caseRecords: [{ caseId: 'FS-LISTEN-SDK-101', complete: true, listenersClosed: true }],
    cleanup: { complete: true, rows: [] },
    budget,
    cleanupBudget,
  });
  assert.equal(receipt.complete, false);
  assert.equal(receipt.cleanupBudget.exhausted, true);
});

test('the resume case records a connect, disconnect and reconnect it can justify', async () => {
  const fake = createFake();
  const clock = nowFactory();
  const spec = caseFixture({
    comparison: 'aggregate-changes',
    listeners: [{ name: 'primary', kind: 'query', target: 'docs', where: ['rank', '<', 10], limit: 10, includeMetadataChanges: true }],
    steps: [
      { kind: 'seed', doc: 'alpha', fields: { rank: 1 } },
      { kind: 'listen', listener: 'primary' },
      { kind: 'await', listener: 'primary', events: 1 },
      { kind: 'baseline' },
      { kind: 'break', client: 'primary', mode: 'disable-network' },
      { kind: 'write', client: 'witness', doc: 'gamma', fields: { rank: 5 } },
      { kind: 'resume', client: 'primary', mode: 'enable-network' },
      { kind: 'settle', listener: 'primary', seconds: 5 },
    ],
    expectedLocal: [{ docs: ['alpha', 'gamma'] }],
  });
  const ctx = contextFor(fake, clock, spec);
  const record = await runCase({ ...clock, firestore: fake.firestore, auth: fake.auth }, spec, ctx);
  const kinds = record.transportTimeline.map(entry => entry.kind);
  assert.deepEqual(kinds, [
    'connect',
    'break-requested',
    'disconnect',
    'resume-requested',
    'reconnect',
  ]);
  for (const entry of record.transportTimeline) {
    assert.equal(typeof entry.atMs, 'number');
    assert.ok(entry.derivedFrom.length > 0);
  }
  const stamps = record.transportTimeline.map(entry => entry.atMs);
  assert.deepEqual(stamps, [...stamps].sort((a, b) => a - b));
});

test('a case with no break records a connect and nothing else', async () => {
  const fake = createFake();
  const clock = nowFactory();
  const spec = caseFixture({
    listeners: [
      { name: 'primary', kind: 'document', target: 'alpha', includeMetadataChanges: true },
    ],
    steps: [
      { kind: 'seed', doc: 'alpha', fields: { rank: 1 } },
      { kind: 'listen', listener: 'primary' },
      { kind: 'await', listener: 'primary', events: 1 },
    ],
  });
  const ctx = contextFor(fake, clock, spec);
  const record = await runCase({ ...clock, firestore: fake.firestore, auth: fake.auth }, spec, ctx);
  assert.deepEqual(
    record.transportTimeline.map(entry => entry.kind),
    ['connect'],
  );
});

test('a thrown step still runs cleanup and still yields a receipt', async () => {
  const fake = createFake();
  const clock = nowFactory();
  const paths = ownedPaths(NONCE, UID);
  const budget = createBudget({
    now: clock.now,
    deadlineMs: 60_000,
    limits: { reads: 400, writes: 60, deletes: 20, snapshots: 120, listeners: 40 },
  });
  const cleanupBudget = createBudget({
    now: clock.now,
    deadlineMs: 180_000,
    limits: { reads: 200, writes: 0, deletes: 100, snapshots: 0, listeners: 0 },
  });
  let writes = 0;
  const deps = {
    ...clock,
    firestore: {
      ...fake.firestore,
      async setDoc(client, docPath, fields) {
        writes += 1;
        if (writes === 3) throw { code: 'permission-denied' };
        return fake.firestore.setDoc(client, docPath, fields);
      },
    },
    auth: fake.auth,
  };
  const catalog = {
    cases: [
      caseFixture({
        caseId: 'ONE',
        steps: [
          { kind: 'seed', doc: 'alpha', fields: { rank: 1 } },
          { kind: 'listen', listener: 'primary' },
          { kind: 'await', listener: 'primary', events: 1 },
        ],
      }),
      caseFixture({
        caseId: 'TWO',
        steps: [
          { kind: 'seed', doc: 'beta', fields: { rank: 2 } },
          { kind: 'seed', doc: 'gamma', fields: { rank: 3 } },
        ],
      }),
    ],
  };
  const outcome = await runCatalog(deps, {
    catalog,
    budget,
    cleanupBudget,
    paths,
    nonce: NONCE,
    client: 'primary',
    contextFor: caseSpec => contextFor(fake, clock, caseSpec, { budget }),
  });
  // The failing case is recorded rather than aborting the run.
  assert.equal(outcome.caseRecords.length, 2);
  assert.equal(outcome.caseRecords[1].complete, false);
  assert.ok(outcome.caseRecords[1].failures.some(entry => entry.includes('permission-denied')));
  // Cleanup still ran and proved absence for everything the run created.
  assert.equal(outcome.cleanup.complete, true);
  assert.ok(
    outcome.cleanup.rows.every(row =>
      ['deleted-and-absent', 'not-created', 'already-deleted-earlier'].includes(row.outcome),
    ),
  );
  assert.equal(fake.store.size, 0);
  // The final pass alone would understate the run: both cases created a
  // document, and each was deleted by the pass that followed its own case.
  assert.equal(outcome.cleanupPasses.length, 3);
  assert.deepEqual(
    outcome.cleanupPasses.map(pass => pass.pass),
    ['ONE', 'TWO', 'final'],
  );
  assert.equal(outcome.totalDeleted, 2);
  assert.equal(outcome.cleanup.deleted, 0);
  assert.ok(
    outcome.cleanup.rows.some(row => row.outcome === 'already-deleted-earlier'),
    'the final pass labels documents an earlier pass deleted',
  );
  // And a receipt exists, marked incomplete.
  const receipt = buildReceipt({
    campaign: { caseId: 'FS-LISTEN-SDK' },
    campaignDigest: 'a'.repeat(64),
    catalogDigest: 'b'.repeat(64),
    environment: { node: process.versions.node },
    caseRecords: outcome.caseRecords,
    cleanup: outcome.cleanup,
    budget,
    cleanupBudget,
    thrown: outcome.thrown,
  });
  assert.equal(receipt.complete, false);
});

test('an error thrown outside a case is recorded on the receipt', async () => {
  const fake = createFake();
  const clock = nowFactory();
  const paths = ownedPaths(NONCE, UID);
  const budget = createBudget({
    now: clock.now,
    deadlineMs: 60_000,
    limits: { reads: 400, writes: 60, deletes: 20, snapshots: 120, listeners: 40 },
  });
  const cleanupBudget = createBudget({
    now: clock.now,
    deadlineMs: 180_000,
    limits: { reads: 200, writes: 0, deletes: 100, snapshots: 0, listeners: 0 },
  });
  const outcome = await runCatalog(
    { ...clock, firestore: fake.firestore, auth: fake.auth },
    {
      catalog: { cases: [caseFixture({ caseId: 'ONE', steps: [] })] },
      budget,
      cleanupBudget,
      paths,
      nonce: NONCE,
      client: 'primary',
      contextFor: caseSpec => contextFor(fake, clock, caseSpec, { budget }),
      betweenCases: async () => {
        throw new Error('sign-in lost');
      },
    },
  );
  assert.equal(outcome.thrown, 'cleanup-operation-failed');
  assert.equal(outcome.cleanup.complete, true);
  const receipt = buildReceipt({
    campaign: { caseId: 'FS-LISTEN-SDK' },
    campaignDigest: 'a'.repeat(64),
    catalogDigest: 'b'.repeat(64),
    environment: {},
    caseRecords: outcome.caseRecords,
    cleanup: outcome.cleanup,
    budget,
    cleanupBudget,
    thrown: outcome.thrown,
  });
  assert.equal(receipt.complete, false);
  assert.equal(receipt.thrown, 'cleanup-operation-failed');
  assert.ok(!JSON.stringify(receipt).includes('sign-in lost'));
});

test('cleanup stops on its own deadline instead of hanging', async () => {
  const clock = nowFactory();
  const paths = ownedPaths(NONCE, UID);
  const cleanupBudget = createBudget({
    now: clock.now,
    deadlineMs: 1_000,
    limits: { reads: 200, writes: 0, deletes: 100, snapshots: 0, listeners: 0 },
  });
  const deps = {
    firestore: {
      async getDoc() {
        clock.advance(600);
        return { exists: false, fields: null, updateTime: null };
      },
    },
  };
  const result = await runCleanup(deps, {
    client: 'primary',
    paths,
    nonce: NONCE,
    budget: cleanupBudget,
  });
  assert.equal(result.complete, false);
  assert.ok(result.rows.some(row => row.outcome === 'budget-exhausted'));
  assert.ok(cleanupBudget.snapshot().exceeded.includes('deadline'));
});

test('a default-mode listener labels its callbacks initial then delta', async () => {
  const fake = createFake();
  const clock = nowFactory();
  const spec = caseFixture({
    caseId: 'DEFAULT-MODE',
    collapseMetadataOnly: false,
    listeners: [
      { name: 'primary', kind: 'document', target: 'alpha', includeMetadataChanges: false },
    ],
    steps: [
      { kind: 'seed', doc: 'alpha', fields: { rank: 1, value: 'a0' } },
      { kind: 'listen', listener: 'primary' },
      { kind: 'await', listener: 'primary', events: 1 },
      { kind: 'write', client: 'witness', doc: 'alpha', fields: { rank: 1, value: 'a1' } },
      { kind: 'await', listener: 'primary', events: 2 },
    ],
  });
  const ctx = contextFor(fake, clock, spec);
  const record = await runCase({ ...clock, firestore: fake.firestore, auth: fake.auth }, spec, ctx);
  assert.deepEqual(
    record.observed.map(row => row.snapshotKind),
    ['initial', 'delta'],
  );
});

test('a metadata listener still treats a cache-served prefix as the initial snapshot', async () => {
  const fake = createFake();
  const clock = nowFactory();
  const spec = caseFixture({
    caseId: 'METADATA-MODE',
    listeners: [
      { name: 'primary', kind: 'document', target: 'alpha', includeMetadataChanges: true },
    ],
    steps: [
      { kind: 'seed', doc: 'alpha', fields: { rank: 1 } },
      { kind: 'listen', listener: 'primary' },
      { kind: 'await', listener: 'primary', events: 1 },
    ],
  });
  const ctx = contextFor(fake, clock, spec);
  const record = await runCase({ ...clock, firestore: fake.firestore, auth: fake.auth }, spec, ctx);
  assert.ok(record.observed.every(row => row.snapshotKind === 'initial'));
});

test('the session hook runs before the cleanup pass, not after it', async () => {
  const fake = createFake();
  const clock = nowFactory();
  const paths = ownedPaths(NONCE, UID);
  const budget = createBudget({
    now: clock.now,
    deadlineMs: 60_000,
    limits: { reads: 400, writes: 60, deletes: 20, snapshots: 120, listeners: 40 },
  });
  const cleanupBudget = createBudget({
    now: clock.now,
    deadlineMs: 180_000,
    limits: { reads: 200, writes: 0, deletes: 100, snapshots: 0, listeners: 0 },
  });
  const order = [];
  const deps = {
    ...clock,
    firestore: {
      ...fake.firestore,
      async getDoc(client, docPath) {
        order.push('cleanup-read');
        return fake.firestore.getDoc(client, docPath);
      },
    },
    auth: fake.auth,
  };
  await runCatalog(deps, {
    catalog: { cases: [caseFixture({ caseId: 'ONE', steps: [] })] },
    budget,
    cleanupBudget,
    paths,
    nonce: NONCE,
    client: 'primary',
    contextFor: caseSpec => contextFor(fake, clock, caseSpec, { budget }),
    betweenCases: async () => {
      order.push('session-restored');
    },
  });
  assert.equal(order[0], 'session-restored');
  assert.equal(order.indexOf('session-restored') < order.indexOf('cleanup-read'), true);
});

// Two principals: the secondary client is signed in as the second one, whose
// only owned document is privateB.
const twoPrincipalContext = (fake, clock, caseSpec, overrides = {}) => {
  const paths = { ...ownedPaths(NONCE, UID), ...secondaryPaths(NONCE, UID_B) };
  const names = new Map(Object.entries(paths).map(([name, path]) => [path, name]));
  fake.setUid('primary', UID);
  fake.setUid('witness', UID);
  fake.setUid('secondary', UID_B);
  return contextFor(fake, clock, caseSpec, {
    clients: { primary: 'primary', witness: 'witness', secondary: 'secondary' },
    paths, nameOf: path => names.get(path) ?? path.split('/').at(-1), ...overrides,
  });
};

test('secondaryPaths binds the second private document to the second uid only', () => {
  assert.deepEqual(secondaryPaths(NONCE, UID_B), { privateB: `o6_listen_private/${UID_B}` });
  assert.throws(() => secondaryPaths('short', UID_B), /nonce/);
  assert.throws(() => secondaryPaths(NONCE, '../x'), /uid/);
});

test('a listener on the other principal\'s private document errors without a server snapshot', async () => {
  const fake = createFake();
  const clock = nowFactory();
  const caseSpec = caseFixture({
    listeners: [{ name: 'primary', kind: 'document', target: 'privateB', includeMetadataChanges: true }],
    steps: [
      { kind: 'write', client: 'secondary', doc: 'privateB', fields: { value: 'b0' } },
      { kind: 'listen', listener: 'primary' },
      { kind: 'awaitError', listener: 'primary' },
    ],
    expectedLocal: [{ listener: 'primary', snapshotKind: 'error', changes: [], docs: [], exists: null,
      fromCache: false, hasPendingWrites: false, error: 'permission-denied' }],
    invariants: ['no-server-snapshot-before-error'],
    comparedFields: ['listener', 'snapshotKind', 'error'],
  });
  const record = await runCase({ ...fake, now: clock.now, sleep: clock.sleep }, caseSpec,
    twoPrincipalContext(fake, clock, caseSpec));
  assert.equal(record.complete, true);
  assert.deepEqual(record.invariantViolations, []);
  assert.equal(record.observed.at(-1).error, 'permission-denied');
  assert.ok(fake.store.has(`o6_listen_private/${UID_B}`), 'the second principal wrote its document');
});

test('a listener declared for the secondary client subscribes through that client', async () => {
  const fake = createFake();
  const clock = nowFactory();
  const caseSpec = caseFixture({
    listeners: [{ name: 'secondary', kind: 'document', target: 'privateB', client: 'secondary',
      includeMetadataChanges: true }],
    steps: [
      { kind: 'write', client: 'secondary', doc: 'privateB', fields: { value: 'b0' } },
      { kind: 'listen', listener: 'secondary' },
      { kind: 'awaitServer', listener: 'secondary' },
    ],
    expectedLocal: [{ listener: 'secondary', snapshotKind: 'initial', changes: [], docs: ['privateB'],
      exists: true, fromCache: false, hasPendingWrites: false, error: null }],
  });
  const record = await runCase({ ...fake, now: clock.now, sleep: clock.sleep }, caseSpec,
    twoPrincipalContext(fake, clock, caseSpec));
  assert.equal(record.complete, true);
  assert.equal(fake.listeners[0].client, 'secondary');
  assert.deepEqual(record.observed.map(row => [row.listener, row.snapshotKind, row.docs]),
    [['secondary', 'initial', ['privateB']]]);
});

test('signIn, signOut and revoke steps target the client they name', async () => {
  const fake = createFake();
  const clock = nowFactory();
  const caseSpec = caseFixture({
    listeners: [],
    steps: [
      { kind: 'signOut', client: 'witness' },
      { kind: 'signIn', client: 'witness', account: 'throwaway' },
      { kind: 'revoke', client: 'secondary' },
      { kind: 'revoke', client: 'primary' },
    ],
  });
  const record = await runCase({ ...fake, now: clock.now, sleep: clock.sleep }, caseSpec,
    twoPrincipalContext(fake, clock, caseSpec));
  assert.equal(record.complete, true);
  assert.deepEqual(fake.revoked, [UID_B, UID]);
  assert.deepEqual(record.transportTimeline.map(entry => entry.kind),
    ['revoke-requested', 'revoke-requested']);
});

test('cleanup deletes the second principal\'s document through its own client', async () => {
  const fake = createFake();
  const clock = nowFactory();
  const paths = { ...ownedPaths(NONCE, UID), ...secondaryPaths(NONCE, UID_B) };
  fake.setUid('primary', UID);
  fake.setUid('secondary', UID_B);
  await fake.firestore.setDoc('secondary', paths.privateB, { owner: ownerMarker(NONCE) });
  await fake.firestore.setDoc('primary', paths.private, { owner: ownerMarker(NONCE) });
  const budget = createBudget({ now: clock.now, deadlineMs: 60_000,
    limits: { reads: 50, writes: 0, deletes: 20, snapshots: 0, listeners: 0 } });
  const owned = await runCleanup(fake, { client: 'primary', paths, nonce: NONCE, budget,
    clientFor: { privateB: 'secondary' } });
  assert.equal(owned.complete, true);
  assert.equal(owned.rows.find(row => row.name === 'privateB').outcome, 'deleted-and-absent');
  assert.equal(owned.rows.find(row => row.name === 'private').outcome, 'deleted-and-absent');
  assert.ok(!fake.store.has(paths.privateB));
  // Every read and delete of privateB went through the secondary client; the
  // first principal's documents stayed on the case client.
  const byPath = path => fake.cleanupCalls.filter(call => call[2] === path).map(call => call[1]);
  assert.deepEqual([...new Set(byPath(paths.privateB))], ['secondary']);
  assert.deepEqual([...new Set(byPath(paths.private))], ['primary']);
  assert.deepEqual([...new Set(byPath(paths.alpha))], ['primary']);
});
