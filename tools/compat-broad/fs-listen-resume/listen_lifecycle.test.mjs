import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { createServer as createTcpServer } from 'node:net';
import { once } from 'node:events';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import {
  executeLocalLifecycle, main, localAccountRequest, readPasswordFromFd,
} from './listen_sdk_adapter.mjs';
import { createBudget, createRecoveryBudget, ownedPaths, ownerMarker } from './listen_collector.mjs';

const NONCE = 'b'.repeat(32);
const EMAIL = `o6-${NONCE}@example.test`;
const UID = 'owned-local-uid';
const limits = { reads: 200, writes: 60, deletes: 100, snapshots: 120, listeners: 40 };
const sampleCase = { caseId: 'LIFECYCLE-ONE', role: 'local', comparison: 'exact',
  listeners: [], steps: [{ kind: 'seed', doc: 'alpha', fields: { marker: 1 } }],
  expectedLocal: [], invariants: [] };
const config = (clock = () => 0) => ({
  projectId: 'demo-local', firestoreHost: '127.0.0.1:18081', authHost: '127.0.0.1:18082',
  account: { name: 'throwaway', email: EMAIL, password: 'PRIVATE-VALUE' }, nonce: NONCE,
  catalog: { cases: [structuredClone(sampleCase)] }, stepTimeoutMs: 100,
  budget: createBudget({ now: clock, deadlineMs: 300000, limits }),
  cleanupBudget: createRecoveryBudget({ now: clock, deadlineMs: 180000,
    limits: { ...limits, writes: 0, listeners: 0, snapshots: 0 } }),
});

function fixture(fault = null, injected = {}) {
  const calls = [];
  const documents = new Map();
  let account = null;
  let lookupCount = 0;
  const hit = name => {
    calls.push(name);
    if (name === fault) throw new Error('PRIVATE-VALUE should not reach receipt');
  };
  const snapshot = ref => ({
    metadata: { fromCache: false, hasPendingWrites: false },
    exists: () => documents.has(ref.path), data: () => documents.get(ref.path),
  });
  const sdk = {
    initializeApp: (_cfg, name) => {
      const client = name.endsWith('primary') ? 'primary' : 'witness';
      hit(`initialize:${client}`); return { client };
    },
    getFirestore: app => { hit(`database:${app.client}`); return { client: app.client }; },
    connectFirestoreEmulator: db => hit(`connect-database:${db.client}`),
    getAuth: app => { hit(`auth:${app.client}`); return { client: app.client }; },
    connectAuthEmulator: auth => hit(`connect-auth:${auth.client}`),
    createUserWithEmailAndPassword: async auth => {
      hit('signup');
      account = { localId: UID, email: EMAIL };
      auth.currentUser = { uid: UID, email: EMAIL };
      hit('signup-after-create');
      if (injected.signupResponse) return injected.signupResponse;
      return { user: auth.currentUser };
    },
    signInWithEmailAndPassword: async auth => {
      hit(`signin:${auth.client}`);
      return { user: { uid: injected.witnessUid && auth.client === 'witness' ? injected.witnessUid : UID } };
    },
    terminate: async db => hit(`terminate:${db.client}`),
    deleteApp: async app => hit(`delete-app:${app.client}`),
    doc: (db, docPath) => ({ client: db.client, path: docPath }),
    setDoc: async (ref, fields) => { documents.set(ref.path, fields); hit('write'); },
    getDocFromServer: async ref => { hit(`read:${ref.client}`); return snapshot(ref); },
    runTransaction: async (_db, work, options) => {
      hit('transaction'); assert.equal(options.maxAttempts, 1);
      return work({ get: async ref => snapshot(ref), delete: ref => documents.delete(ref.path) });
    },
  };
  const request = async (_endpoint, _project, operation, body, timeout) => {
    assert.ok(timeout > 0 && timeout <= 12000);
    if (operation === 'lookup') {
      lookupCount++;
      hit(`lookup:${lookupCount}`);
      if (injected.lookups?.[lookupCount]) return injected.lookups[lookupCount];
      return { status: 200, body: { users: account ? [{ ...account }] : [] } };
    }
    assert.equal(operation, 'delete'); assert.equal(body.localId, UID);
    hit('account-delete');
    if (injected.deletion) return injected.deletion;
    account = null; return { status: 200, body: {} };
  };
  return { sdk, request, calls, documents, account: () => account };
}

for (const stage of ['initialize', 'database', 'connect-database', 'auth', 'connect-auth']) {
  for (const client of ['primary', 'witness']) {
    test(`partial SDK ${stage}:${client} still releases every constructed app`, async () => {
      const f = fixture(`${stage}:${client}`);
      const out = await executeLocalLifecycle(f.sdk, config(), { request: f.request });
      assert.equal(out.lifecycle.complete, false);
      assert.equal(out.lifecycle.accountCleanup.complete, true);
      assert.ok(!f.calls.includes('signup'));
      const initialized = f.calls.filter(x => x.startsWith('initialize:'));
      for (const entry of initialized) {
        if (entry === `${stage}:${client}`) continue;
        assert.ok(f.calls.includes(`delete-app:${entry.split(':')[1]}`));
      }
      assert.ok(!JSON.stringify(out).includes('PRIVATE-VALUE'));
    });
  }
}

for (const stage of ['signup', 'signup-after-create', 'signin:witness', 'write',
  'terminate:primary', 'delete-app:primary', 'terminate:witness', 'delete-app:witness']) {
  test(`${stage} failure is recorded while remaining cleanup still runs`, async () => {
    const f = fixture(stage);
    const out = await executeLocalLifecycle(f.sdk, config(), { request: f.request });
    assert.ok(out.lifecycle.failure || out.thrown || out.caseRecords.some(r => !r.complete) ||
      !out.lifecycle.clients.complete);
    for (const name of ['primary', 'witness']) {
      assert.ok(f.calls.includes(`terminate:${name}`));
      assert.ok(f.calls.includes(`delete-app:${name}`));
    }
    if (stage === 'signup-after-create') {
      assert.equal(out.lifecycle.accountCleanup.outcome, 'creation-unconfirmed');
      assert.ok(!f.calls.includes('account-delete'));
    } else assert.equal(f.account(), null);
    assert.equal(f.documents.size, 0);
    assert.ok(!JSON.stringify(out).includes('PRIVATE-VALUE'));
  });
}

test('normal catalog creates and deletes documents and the exact account before client teardown', async () => {
  const f = fixture();
  const out = await executeLocalLifecycle(f.sdk, config(), { request: f.request });
  assert.equal(out.lifecycle.complete, true);
  assert.equal(out.cleanup.complete, true);
  assert.equal(out.lifecycle.accountCleanup.outcome, 'deleted-and-absent');
  assert.equal(out.lifecycle.localAdminRequests, 4);
  assert.equal(f.documents.size, 0);
  assert.equal(f.account(), null);
  assert.ok(f.calls.indexOf('account-delete') < f.calls.indexOf('terminate:primary'));
});

test('outer catalog exception after an effect still executes document recovery', async () => {
  const f = fixture();
  const out = await executeLocalLifecycle(f.sdk, config(), { request: f.request,
    run: async deps => {
      await deps.firestore.setDoc('primary', ownedPaths(NONCE, UID).alpha, { owner: ownerMarker(NONCE) });
      throw new Error('PRIVATE-VALUE');
    },
  });
  assert.equal(out.lifecycle.complete, false);
  assert.equal(out.cleanup.complete, true);
  assert.equal(f.documents.size, 0);
  assert.equal(f.account(), null);
});

test('failed document recovery retains the account rather than destroying recovery credentials', async () => {
  const f = fixture('transaction');
  const out = await executeLocalLifecycle(f.sdk, config(), { request: f.request });
  assert.equal(out.cleanup.complete, false);
  assert.equal(out.lifecycle.accountCleanup.outcome, 'retained-for-document-recovery');
  assert.ok(f.account()); assert.ok(!f.calls.includes('account-delete'));
});

for (const body of [{}, { users: null }, { users: [], error: {} },
  { users: [], nextPageToken: 'next' }, { kind: 'wrong' },
  { users: [{ localId: 'other', email: EMAIL }] },
  { users: [{ localId: UID, email: 'foreign@example.invalid' }] },
  { users: [{ localId: UID, email: EMAIL }, { localId: UID, email: EMAIL }] }]) {
  test(`ambiguous cleanup lookup cannot grant deletion: ${JSON.stringify(body)}`, async () => {
    const f = fixture(null, { lookups: { 2: { status: 200, body } } });
    const out = await executeLocalLifecycle(f.sdk, config(), { request: f.request });
    assert.equal(out.lifecycle.accountCleanup.complete, false);
    assert.ok(!f.calls.includes('account-delete'));
  });
}
for (const signupResponse of [{}, { user: { uid: UID, email: 'other' } }, { user: { uid: 1, email: EMAIL } }]) {
  test(`malformed signup does not grant ownership: ${JSON.stringify(signupResponse)}`, async () => {
    const f = fixture(null, { signupResponse });
    const out = await executeLocalLifecycle(f.sdk, config(), { request: f.request });
    assert.equal(out.lifecycle.accountCleanup.complete, false);
    assert.ok(!f.calls.includes('account-delete'));
  });
}
for (const stage of ['lookup:2', 'account-delete', 'lookup:3']) {
  test(`${stage} failure is not masked by successful SDK teardown`, async () => {
    const f = fixture(stage);
    const out = await executeLocalLifecycle(f.sdk, config(), { request: f.request });
    assert.equal(out.lifecycle.accountCleanup.complete, false);
    assert.equal(out.lifecycle.complete, false);
    assert.equal(out.lifecycle.clients.complete, true);
  });
}
for (const deletion of [{ status: 500, body: {} }, { status: 200, body: { error: {} } },
  { status: 200, body: { users: [] } }, { status: 200, body: [] }]) {
  test(`invalid delete acknowledgement remains incomplete: ${JSON.stringify(deletion)}`, async () => {
    const f = fixture(null, { deletion });
    const out = await executeLocalLifecycle(f.sdk, config(), { request: f.request });
    assert.equal(out.lifecycle.complete, false);
  });
}

test('typed occupied preflight prevents signup and never deletes existing account', async () => {
  const f = fixture(null, { lookups: { 1: { status: 200, body: { users: [{ localId: UID, email: EMAIL }] } } } });
  const out = await executeLocalLifecycle(f.sdk, config(), { request: f.request });
  assert.equal(out.lifecycle.complete, false);
  assert.deepEqual(f.calls, ['lookup:1']);
});

test('recovery clock excludes observation but accumulates all cleanup passes and charges', async () => {
  let time = 0;
  const budget = createRecoveryBudget({ now: () => time, deadlineMs: 20, limits });
  time = 1000000;
  assert.equal(budget.charge('reads').ok, false);
  await budget.withPhase(async () => {
    assert.equal(budget.remainingMs(), 20);
    assert.equal(budget.charge('reads').ok, true);
    time += 12;
  });
  time += 2000000;
  await budget.withPhase(async () => {
    assert.equal(budget.remainingMs(), 8);
    assert.equal(budget.snapshot().used.reads, 1);
    time += 8;
    assert.equal(budget.charge('reads').ok, false);
  });
  assert.equal(budget.snapshot().exhausted, true);
});

test('recovery phase is closed on exception and refuses nesting or clock rollback', async () => {
  let time = 10;
  const budget = createRecoveryBudget({ now: () => time, deadlineMs: 20, limits });
  await assert.rejects(budget.withPhase(async () => {
    await assert.rejects(budget.withPhase(async () => {}), /already active/);
    time += 3; throw new Error('stop');
  }), /stop/);
  assert.equal(budget.charge('reads').ok, false);
  time = 1;
  await assert.rejects(budget.withPhase(async () => assert.fail('regressed clock admitted')), /deadline exhausted/);
  assert.equal(budget.snapshot().exhausted, true);
});

for (const uid of ['', 'x/y', '..', '.', 'x%2fy', 'x?y', 'x\\y', 'x\ny', 'a'.repeat(129)]) {
  test(`unsafe uid cannot change document ownership path: ${JSON.stringify(uid)}`, () => {
    assert.throws(() => ownedPaths(NONCE, uid), /safe uid/);
  });
}
for (const fd of ['3junk', '3.0', '+3', '3e0', ' 3 ', '9007199254740992']) {
  test(`partial numeric fd refused: ${fd}`, () => assert.throws(() => readPasswordFromFd(fd), /private descriptor/));
}

function mainEnv(t) {
  const dir = mkdtempSync(path.join(tmpdir(), 'listen-main-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  writeFileSync(path.join(dir, 'cases.json'), JSON.stringify({ cases: [sampleCase] }));
  writeFileSync(path.join(dir, 'campaign.json'), JSON.stringify({ campaign: { sdk: {} }, campaignDigest: 'a'.repeat(64) }));
  return { FIRESTORE_EMULATOR_HOST: '127.0.0.1:18081', FIREBASE_AUTH_EMULATOR_HOST: '127.0.0.1:18082',
    O6_FIREBASE_MODULE_DIR: dir, O6_REPO_ROOT: process.cwd(), O6_LISTEN_NONCE: NONCE,
    GOOGLE_CLOUD_PROJECT: 'demo-local', O6_LISTEN_CATALOG_PATH: path.join(dir, 'cases.json'),
    O6_LISTEN_CAMPAIGN_PATH: path.join(dir, 'campaign.json') };
}

test('whole main returns complete only after typed Auth recovery and SDK finalization', async t => {
  const f = fixture(); let published;
  const previous = process.exitCode; t.after(() => { process.exitCode = previous; });
  const out = await main({ env: mainEnv(t), argv: ['node', 'adapter.mjs'], sdkLoader: async () => f.sdk,
    request: f.request, emit: value => { assert.ok(f.calls.includes('delete-app:witness')); published = value; } });
  assert.equal(out.complete, true); assert.equal(out, published);
  assert.equal(out.lifecycle.accountCleanup.complete, true);
  assert.equal(out.productionExecuted, false);
});

test('whole main returns failure when teardown fails and still publishes non-secret evidence', async t => {
  const f = fixture('terminate:primary'); let published;
  const previous = process.exitCode; t.after(() => { process.exitCode = previous; });
  const out = await main({ env: mainEnv(t), argv: ['node', 'adapter.mjs'], sdkLoader: async () => f.sdk,
    request: f.request, emit: value => { published = value; } });
  assert.equal(out.complete, false); assert.equal(process.exitCode, 2);
  assert.ok(!JSON.stringify(published).includes(UID));
  assert.ok(!JSON.stringify(published).includes(EMAIL));
  assert.ok(!JSON.stringify(published).includes('PRIVATE-VALUE'));
  assert.ok(f.calls.includes('delete-app:witness'));
});

test('receipt publication failure occurs only after cleanup and cannot skip finalizers', async t => {
  const f = fixture();
  await assert.rejects(main({ env: mainEnv(t), argv: ['node', 'adapter.mjs'], sdkLoader: async () => f.sdk,
    request: f.request, emit: () => { throw new Error('disk-full'); } }), /disk-full/);
  assert.equal(f.account(), null); assert.equal(f.documents.size, 0);
  assert.ok(f.calls.includes('delete-app:witness'));
});

for (const [name, value] of [['O6_LISTEN_NONCE', '../unsafe'], ['GOOGLE_CLOUD_PROJECT', 'p/../../p'],
  ['O6_LISTEN_DEADLINE_MS', '1junk'], ['O6_LISTEN_STEP_TIMEOUT_MS', 'Infinity'], ['O6_LISTEN_STEP_TIMEOUT_MS', '0']]) {
  test(`bad ${name} is refused before SDK initialization`, async t => {
    let called = false;
    await assert.rejects(main({ env: { ...mainEnv(t), [name]: value }, argv: ['node', 'adapter.mjs'],
      sdkLoader: async () => { called = true; throw new Error('unexpected import'); } }));
    assert.equal(called, false);
  });
}

async function server(t, handler, tcp = false) {
  const s = tcp ? createTcpServer(handler) : createServer(handler);
  s.listen(0, '127.0.0.1'); await once(s, 'listening');
  t.after(() => { s.closeAllConnections?.(); s.close(); });
  return `127.0.0.1:${s.address().port}`;
}

test('real local account HTTP completes a bounded typed lookup with only local owner auth', async t => {
  const endpoint = await server(t, (req, res) => {
    assert.equal(req.url, '/identitytoolkit.googleapis.com/v1/projects/demo-local/accounts:lookup');
    assert.equal(req.headers.authorization, 'Bearer owner');
    res.setHeader('Content-Type', 'application/json'); res.end('{"users":[]}');
  });
  assert.deepEqual(await localAccountRequest(endpoint, 'demo-local', 'lookup', { email: [EMAIL] }),
    { status: 200, body: { users: [] } });
});
for (const kind of ['short', 'oversize', 'redirect', 'non-json', 'array', 'invalid-utf8']) {
  test(`real local account HTTP refuses ${kind}`, async t => {
    const endpoint = await server(t, socket => socket.once('data', () => {
      let body = Buffer.from('{"users":[]}'); let status = '200 OK'; let contentType = 'application/json';
      if (kind === 'oversize') body = Buffer.from(JSON.stringify({ users: [], x: 'x'.repeat(66000) }));
      if (kind === 'redirect') { status = '302 Found'; body = Buffer.alloc(0); }
      if (kind === 'non-json') contentType = 'text/html';
      if (kind === 'array') body = Buffer.from('[]');
      if (kind === 'invalid-utf8') body = Buffer.from([123,34,120,34,58,34,255,34,125]);
      socket.end(Buffer.concat([Buffer.from(`HTTP/1.1 ${status}\r\nContent-Type: ${contentType}\r\nContent-Length: ${kind === 'short' ? 900 : body.length}\r\nConnection: close\r\n\r\n`), body]));
    }), true);
    await assert.rejects(localAccountRequest(endpoint, 'demo-local', 'lookup', { email: [EMAIL] }));
  });
}

test('whole-call timeout terminates a stalled local account request', async t => {
  let connected;
  const endpoint = await server(t, socket => { connected = socket; }, true);
  t.after(() => connected?.destroy());
  await assert.rejects(localAccountRequest(endpoint, 'demo-local', 'lookup', {}, 20));
});
for (const endpoint of ['remote.invalid:80', 'https://127.0.0.1:80', '127.0.0.1:0', '127.0.0.1:70000']) {
  test(`local Auth recovery refuses ${endpoint} before socket`, () => {
    assert.throws(() => localAccountRequest(endpoint, 'demo-local', 'lookup', {}));
  });
}


test('a late successful signup is recovered without starting the next observation', async () => {
  let time = 0;
  const f = fixture();
  const signup = f.sdk.createUserWithEmailAndPassword;
  f.sdk.createUserWithEmailAndPassword = async (...args) => {
    const value = await signup(...args); time += 300001; return value;
  };
  const out = await executeLocalLifecycle(f.sdk, config(() => time), { request: f.request });
  assert.equal(out.lifecycle.complete, false);
  assert.equal(out.lifecycle.accountCleanup.complete, true);
  assert.equal(f.account(), null);
  assert.ok(!f.calls.includes('signin:witness'));
});

test('an expired recovery phase never calls a restoration hook', async () => {
  let time = 0;
  const budget = createRecoveryBudget({ now: () => time, deadlineMs: 10, limits });
  await budget.withPhase(async () => { time += 11; });
  await assert.rejects(budget.withPhase(async () => assert.fail('expired recovery ran')), /deadline exhausted/);
});


test('an unacknowledged signup remains unknown even after a complete absent lookup', async () => {
  const f = fixture('signup');
  const out = await executeLocalLifecycle(f.sdk, config(), { request: f.request });
  assert.equal(out.lifecycle.accountCleanup.complete, false);
  assert.equal(out.lifecycle.accountCleanup.outcome, 'creation-unconfirmed');
  assert.equal(out.lifecycle.accountCleanup.observedAbsent, true);
  assert.ok(!f.calls.includes('account-delete'));
});

// The lifecycle callbacks below model durable-checkpoint failures, not SDK
// success. Positive journal file/chain tests live in listen_journal.test.mjs.
test('supervised lifecycle records responsibility before each class of data effect', async () => {
  const f = fixture(); const records = [];
  const out = await executeLocalLifecycle(f.sdk, config(), { request: f.request,
    checkpoint: (phase, value) => { records.push({ phase, value }); f.calls.push(`checkpoint:${phase}`); },
  });
  assert.equal(out.lifecycle.complete, true);
  assert.ok(f.calls.indexOf('checkpoint:account-create-intent') < f.calls.indexOf('signup'));
  assert.ok(f.calls.indexOf('checkpoint:account-created') < f.calls.indexOf('signin:witness'));
  assert.ok(f.calls.indexOf('checkpoint:documents-at-risk') < f.calls.indexOf('write'));
  assert.ok(f.calls.indexOf('checkpoint:lifecycle-result') > f.calls.indexOf('delete-app:witness'));
  assert.equal(records.find(r => r.phase === 'account-created').value.uid, UID);
  assert.ok(!JSON.stringify(records).includes('PRIVATE-VALUE'));
});
for (const phase of ['account-create-intent', 'account-created', 'documents-at-risk', 'lifecycle-result']) {
  test(`checkpoint ${phase} failure prevents subsequent data work, but still attempts teardown`, async () => {
    const f = fixture();
    const call = () => executeLocalLifecycle(f.sdk, config(), { request: f.request,
      checkpoint: current => { if (current === phase) throw new Error('disk-write-failed'); },
    });
    if (phase === 'lifecycle-result') await assert.rejects(call, /disk-write-failed/);
    else {
      const out = await call(); assert.equal(out.lifecycle.complete, false);
      assert.ok(!f.calls.includes('write'));
      if (phase === 'account-create-intent') assert.ok(!f.calls.includes('signup'));
    }
    assert.ok(f.calls.includes('delete-app:primary')); assert.ok(f.calls.includes('delete-app:witness'));
    assert.equal(f.account(), null); assert.equal(f.documents.size, 0);
  });
}
