// Tests for the browser adapter boundary. They launch no browser, open no
// socket and read no credential; `runMode` is exercised through injected
// doubles for the page and the management route.

import test from 'node:test';
import assert from 'node:assert/strict';
import { cpSync, existsSync, mkdtempSync, mkdirSync, readdirSync, realpathSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import {
  BROWSER_BOUND_SOURCES,
  LANE_DIR,
  MODES,
  SCHEMA,
  TRANSPORT,
  accountLookup,
  assembleReceipt,
  parseModes,
  runMode,
  validatePageResult,
} from './listen_browser_adapter.mjs';

const catalog = { catalogDigest: 'c'.repeat(64), cases: [{ caseId: 'FS-LISTEN-SDK-101' }, { caseId: 'FS-LISTEN-SDK-101C' }] };
const campaignRecord = { campaignDigest: 'd'.repeat(64), campaign: { permission: null, sdk: { firebase: '12.18.0' } } };
const budget = { used: { reads: 1, writes: 1, deletes: 0, snapshots: 1, listeners: 1 },
  limits: { reads: 10, writes: 10, deletes: 10, snapshots: 10, listeners: 10 }, deadlineMs: 1000, exceeded: [], exhausted: false };
const EMAIL = `o6-${'0'.repeat(32)}@example.test`;
const EMAIL_B = `o6-${'0'.repeat(32)}-b@example.test`;
const cleanupRows = ['alpha', 'beta', 'gamma', 'absent', 'private', 'privateB'].map(name => ({
  name, pathDigest: 'a'.repeat(64), outcome: 'not-created', detail: null }));
const cleanup = { complete: true, rows: cleanupRows, unproven: [], deleted: 0 };
const caseRecord = caseId => ({ caseId, role: 'observation', comparison: 'ordered-events', complete: true,
  failures: [], observed: [], rawEvents: [], rawEventCount: 0, baselineAt: 0, comparedFields: [],
  transportTimeline: [{ kind: 'connect', atMs: 5, derivedFrom: 'first server-backed snapshot' }],
  invariantViolations: [], listenersClosed: true });
const pageResult = (overrides = {}) => ({
  sdkVersion: '12.18.0', mode: 'long-polling',
  principals: { primary: { uid: 'uid-1', signupAttempted: true },
    secondary: { uid: 'uid-2', signupAttempted: true } },
  caseRecords: catalog.cases.map(row => caseRecord(row.caseId)), cleanup,
  cleanupPasses: [...catalog.cases.map(row => ({ pass: row.caseId, complete: true, deleted: 0, rows: cleanupRows })),
    { pass: 'final', complete: true, deleted: 0, rows: cleanupRows }],
  totalDeleted: 0, thrown: null,
  lifecycle: { failure: null, clients: { complete: true, rows: [] } },
  budget, cleanupBudget: budget, ...overrides,
});
const webchannel = {
  rows: [{ atMs: 1, stream: 'Listen', method: 'POST', role: 'handshake', hasSession: false, ci: null, retry: null, status: 200 },
    { atMs: 2, stream: 'Listen', method: 'GET', role: 'backchannel', hasSession: true, ci: 1, retry: null, status: 200 }],
  summary: () => ({ requests: 2, backchannelCi: { streamed: 0, longPolled: 1 } }),
};
const assembled = (overrides = {}) => assembleReceipt({
  env: { O6_LISTEN_SDK_VERSION: '12.18.0', O6_LISTEN_SOURCE_COMMIT: 'f'.repeat(40) },
  repoRoot: process.cwd(), campaignRecord, catalog, boundSources: [], projectId: 'demo-o6',
  nonce: '0'.repeat(32), mode: 'long-polling', pageResult: pageResult(),
  accountCleanup: { complete: true, outcome: 'deleted-and-absent' }, localAdminRequests: 4,
  browser: { name: 'chromium', version: '151.0.0.0' }, webchannel,
  sdkBundleDigests: { '12.18.0/firebase-app.js': 'e'.repeat(64) }, ...overrides,
});

test('both WebChannel modes are accepted, nothing else', () => {
  assert.deepEqual(parseModes(undefined), [...MODES]);
  assert.deepEqual(parseModes('streaming'), ['streaming']);
  assert.deepEqual(parseModes(' long-polling , streaming '), ['long-polling', 'streaming']);
  for (const bad of ['', 'grpc', 'streaming,streaming', 'long-polling,websocket']) {
    assert.throws(() => parseModes(bad), /unique subset/, bad);
  }
});

test('account lookup only accepts the emulator shape naming this run\'s account', () => {
  const lookup = users => ({ status: 200, body: { kind: 'identitytoolkit#GetAccountInfoResponse', users } });
  assert.equal(accountLookup(lookup([]), 'a@example.test'), null);
  assert.equal(accountLookup({ status: 200, body: { kind: 'identitytoolkit#GetAccountInfoResponse' } }, 'a@example.test'), null);
  assert.equal(accountLookup(lookup([{ localId: 'u1', email: 'a@example.test' }]), 'a@example.test'), 'u1');
  assert.throws(() => accountLookup(lookup([{ localId: 'u1', email: 'b@example.test' }]), 'a@example.test'), /identity mismatch/);
  assert.throws(() => accountLookup(lookup([{ localId: 'u2', email: 'a@example.test' }]), 'a@example.test', 'u1'), /identity mismatch/);
  assert.throws(() => accountLookup(lookup([{ localId: 'u1', email: 'a@example.test' }, { localId: 'u2', email: 'a@example.test' }]), 'a@example.test'), /typed account lookup/);
  assert.throws(() => accountLookup({ status: 200, body: { kind: 'other', users: [] } }, 'a@example.test'), /ambiguous/);
  assert.throws(() => accountLookup({ status: 200, body: { users: [], extra: 1 } }, 'a@example.test'), /ambiguous/);
  assert.throws(() => accountLookup({ status: 500, body: {} }, 'a@example.test'), /unavailable/);
});

test('a page result is validated by shape and a page error is surfaced as a code', () => {
  assert.equal(validatePageResult(pageResult(), catalog).principals.primary.uid, 'uid-1');
  assert.throws(() => validatePageResult(null, catalog), /no result/);
  assert.throws(() => validatePageResult({ pageError: 'auth/network-request-failed', sdkVersion: '12.18.0' }, catalog),
    error => error.code === 'auth/network-request-failed');
  const { budget: _budget, ...missing } = pageResult();
  assert.throws(() => validatePageResult(missing, catalog), /missing budget/);
  assert.throws(() => validatePageResult(pageResult({ principals: { primary: { uid: 5, signupAttempted: true } } }), catalog), /wrong shape/);
  assert.throws(() => validatePageResult(pageResult({ caseRecords: [1, 2, 3] }), catalog), /extra cases/);
});

test('the browser receipt keeps the Node receipt shape and adds the transport evidence', () => {
  const receipt = assembled();
  assert.equal(receipt.schema, 'o6-listen-observation-v1');
  assert.equal(receipt.caseId, 'FS-LISTEN-SDK');
  assert.equal(receipt.productionExecuted, false);
  assert.equal(receipt.transport, TRANSPORT);
  assert.equal(receipt.environment.kind, 'local-fireemu');
  assert.equal(receipt.environment.transport, TRANSPORT);
  assert.equal(receipt.environment.webchannelMode, 'long-polling');
  assert.equal(receipt.environment.firebaseSdkReportedByPage, '12.18.0');
  assert.equal(receipt.environment.sdkSource, 'https://www.gstatic.com/firebasejs/12.18.0');
  assert.deepEqual(receipt.environment.browser, { name: 'chromium', version: '151.0.0.0' });
  assert.equal(receipt.campaignDigest, campaignRecord.campaignDigest);
  assert.equal(receipt.catalogDigest, catalog.catalogDigest);
  assert.deepEqual(receipt.budget, budget);
  assert.equal(receipt.permission, null);
  assert.deepEqual(receipt.sdkResolved, { firebase: '12.18.0' });
  assert.deepEqual(receipt.webchannel.columns, ['atMs', 'stream', 'method', 'role', 'ci', 'status']);
  assert.deepEqual(receipt.webchannel.rows, ['1 Listen POST handshake - 200', '2 Listen GET backchannel 1 200']);
  assert.deepEqual(receipt.transportTimeline.map(entry => entry.caseId), ['FS-LISTEN-SDK-101', 'FS-LISTEN-SDK-101C']);
  for (const relative of BROWSER_BOUND_SOURCES) assert.match(receipt.sourceDigests[relative], /^[0-9a-f]{64}$/, relative);
  assert.equal(receipt.lifecycle.complete, true);
  assert.equal(receipt.lifecycle.localAdminRequests, 4);
  assert.equal(receipt.lifecycle.localAdminRequestLimit, 10);
  assert.equal(receipt.complete, true);
  assert.equal(receipt.thrown, null);
});

test('a receipt is incomplete when the page skipped a case or the account survived', () => {
  const short = assembled({ pageResult: pageResult({ caseRecords: [caseRecord('FS-LISTEN-SDK-101')] }) });
  assert.equal(short.complete, false);
  const reordered = assembled({ pageResult: pageResult({ caseRecords: [caseRecord('FS-LISTEN-SDK-101C'), caseRecord('FS-LISTEN-SDK-101')] }) });
  assert.equal(reordered.complete, false);
  const retained = assembled({ accountCleanup: { complete: false, outcome: 'still-present' } });
  assert.equal(retained.complete, false);
  assert.equal(retained.lifecycle.complete, false);
  const failed = assembled({ pageResult: pageResult({ lifecycle: { failure: 'auth/too-many-requests', clients: { complete: true, rows: [] } }, thrown: 'auth/too-many-requests' }) });
  assert.equal(failed.complete, false);
  assert.equal(failed.thrown, 'auth/too-many-requests');
});

const fakeChromium = (result, { onGoto = () => {} } = {}) => {
  const calls = [];
  const exposed = {};
  const page = {
    on: () => {}, exposeFunction: async (name, fn) => { exposed[name] = fn; },
    goto: async url => { calls.push(['goto', url]); onGoto(url); },
    waitForSelector: async () => {},
    evaluate: async (_fn, config) => { calls.push(['evaluate', config]); return typeof result === 'function' ? result(config) : result; },
    close: async () => calls.push(['page-close']),
  };
  const context = { newPage: async () => page, close: async () => calls.push(['context-close']) };
  return { calls, exposed, chromium: { name: 'chromium', version: '151', browser: { newContext: async () => context } } };
};
const modeInput = (chromium, request) => ({
  env: { O6_LISTEN_SDK_VERSION: '12.18.0' }, repoRoot: process.cwd(), chromium, serverOrigin: 'http://127.0.0.1:1',
  firestore: { host: '127.0.0.1', port: 8080 }, auth: { host: '127.0.0.1', port: 9099, raw: '127.0.0.1:9099' },
  projectId: 'demo-o6', nonce: '0'.repeat(32), account: { name: 'throwaway', email: EMAIL, password: 'hunter2' },
  secondaryAccount: { name: 'second', email: EMAIL_B, password: 'hunter3' },
  catalog, campaignRecord, budgetSpec: { cleanupReserveSeconds: 1 }, boundSources: [], mode: 'streaming',
  stepTimeoutMs: 100, deadlineMs: 1000, request,
});
const managementDouble = (script) => {
  const log = [];
  const request = async (endpoint, projectId, operation, body) => {
    log.push({ endpoint, projectId, operation, body });
    return script(operation, body, log.length);
  };
  return { log, request };
};
const lookupResponse = users => ({ status: 200, body: { kind: 'identitytoolkit#GetAccountInfoResponse', users } });

test('runMode refuses an occupied account namespace before opening a page', async () => {
  const { chromium, calls } = fakeChromium(pageResult());
  const { request } = managementDouble((operation, body) =>
    lookupResponse(body.email?.[0] === EMAIL_B ? [{ localId: 'old', email: EMAIL_B }] : []));
  await assert.rejects(runMode(modeInput(chromium, request)), /namespace occupied/);
  assert.deepEqual(calls, []);
});

// A management double that answers lookups from a small account table.
const accountTable = () => {
  const table = new Map([[EMAIL, 'uid-1'], [EMAIL_B, 'uid-2']]);
  const created = new Set();
  return {
    create: email => created.add(email),
    script: (operation, body) => {
      if (operation === 'lookup') {
        const rows = [...table].filter(([email, uid]) => created.has(email) &&
          (body.email ? body.email.includes(email) : body.localId.includes(uid)));
        return lookupResponse(rows.map(([email, localId]) => ({ localId, email })));
      }
      if (operation === 'update') return { status: 200, body: { localId: body.localId } };
      if (operation === 'delete') { for (const [email, uid] of table) if (uid === body.localId) created.delete(email); return { status: 200, body: {} }; }
      throw new Error(`unexpected ${operation}`);
    },
  };
};

test('runMode hands the page both accounts in memory, deletes both afterwards and closes the page', async () => {
  const accounts = accountTable();
  const { chromium, calls } = fakeChromium(config => {
    accounts.create(config.account.email); accounts.create(config.secondaryAccount.email);
    return pageResult({ mode: 'streaming' });
  });
  const { request, log } = managementDouble(accounts.script);
  const receipt = await runMode(modeInput(chromium, request));
  assert.equal(receipt.complete, true);
  assert.equal(receipt.lifecycle.accountCleanup.complete, true);
  assert.equal(receipt.lifecycle.accountCleanup.outcome, 'deleted-and-absent');
  assert.deepEqual(Object.keys(receipt.lifecycle.accountCleanup.accounts), ['primary', 'secondary']);
  assert.equal(receipt.lifecycle.localAdminRequests, 8);
  assert.deepEqual(log.map(row => row.operation),
    ['lookup', 'lookup', 'lookup', 'delete', 'lookup', 'lookup', 'delete', 'lookup']);
  assert.deepEqual(log[3].body, { localId: 'uid-1' });
  assert.deepEqual(log[6].body, { localId: 'uid-2' });
  const gotoUrl = calls.find(call => call[0] === 'goto')[1];
  assert.equal(gotoUrl, 'http://127.0.0.1:1/listen-catalog.html');
  const config = calls.find(call => call[0] === 'evaluate')[1];
  assert.equal(config.account.password, 'hunter2');
  assert.equal(config.secondaryAccount.password, 'hunter3');
  assert.equal(config.mode, 'streaming');
  assert.deepEqual(calls.slice(-2).map(call => call[0]), ['page-close', 'context-close']);
  assert.ok(!JSON.stringify(receipt).includes('hunter2'));
  assert.ok(!JSON.stringify(receipt).includes('hunter3'));
});

test('the exposed revocation only reaches an account this run owns', async () => {
  const accounts = accountTable();
  let revokeOutcomes;
  const { chromium, exposed } = fakeChromium(async config => {
    accounts.create(config.account.email); accounts.create(config.secondaryAccount.email);
    revokeOutcomes = await Promise.allSettled([
      exposed.__o6Revoke('uid-1', EMAIL),
      exposed.__o6Revoke('uid-1', 'stranger@example.test'),
      exposed.__o6Revoke('../x', EMAIL),
    ]);
    return pageResult();
  });
  const { request, log } = managementDouble(accounts.script);
  const receipt = await runMode(modeInput(chromium, request));
  assert.deepEqual(revokeOutcomes.map(row => row.status), ['fulfilled', 'rejected', 'rejected']);
  assert.match(String(revokeOutcomes[1].reason), /outside this run/);
  assert.match(String(revokeOutcomes[2].reason), /outside this run/);
  const updates = log.filter(row => row.operation === 'update');
  assert.equal(updates.length, 1);
  assert.equal(updates[0].body.localId, 'uid-1');
  assert.match(updates[0].body.validSince, /^[0-9]+$/);
  assert.equal(receipt.lifecycle.localAdminRequests, 10);
  assert.equal(receipt.complete, true);
});

test('runMode keeps both accounts whose documents were not proven absent and still closes the page', async () => {
  const unproven = { ...cleanup, complete: false, unproven: [cleanupRows[0]] };
  const { chromium, calls } = fakeChromium(pageResult({ cleanup: unproven }));
  const { request, log } = managementDouble(() => lookupResponse([]));
  const receipt = await runMode(modeInput(chromium, request));
  assert.equal(receipt.complete, false);
  assert.equal(receipt.lifecycle.accountCleanup.complete, false);
  assert.equal(receipt.lifecycle.accountCleanup.outcome, 'retained-for-document-recovery');
  assert.equal(receipt.lifecycle.accountCleanup.accounts.secondary.outcome, 'retained-for-document-recovery');
  assert.deepEqual(log.map(row => row.operation), ['lookup', 'lookup']);
  assert.deepEqual(calls.slice(-2).map(call => call[0]), ['page-close', 'context-close']);
});

test('a page that reports a lifecycle error is surfaced by code and the page is closed', async () => {
  const { chromium, calls } = fakeChromium({ pageError: 'auth/network-request-failed', sdkVersion: '12.18.0' });
  const { request } = managementDouble(() => lookupResponse([]));
  await assert.rejects(runMode(modeInput(chromium, request)), error => error.code === 'auth/network-request-failed');
  assert.deepEqual(calls.slice(-2).map(call => call[0]), ['page-close', 'context-close']);
});

test('the shadow document schema and transport are fixed names', () => {
  assert.equal(SCHEMA, 'o6-listen-browser-shadow-v1');
  assert.equal(TRANSPORT, 'browser-webchannel');
});

test('a revocation whose uid does not resolve to the run\'s account is refused after one lookup', async () => {
  const accounts = accountTable();
  let outcome;
  const { chromium, exposed } = fakeChromium(async config => {
    accounts.create(config.account.email); accounts.create(config.secondaryAccount.email);
    outcome = await Promise.allSettled([exposed.__o6Revoke('uid-9', EMAIL)]);
    return pageResult();
  });
  const { request, log } = managementDouble(accounts.script);
  const receipt = await runMode(modeInput(chromium, request));
  assert.equal(outcome[0].status, 'rejected');
  assert.match(String(outcome[0].reason), /not this run/);
  assert.equal(log.filter(row => row.operation === 'update').length, 0);
  assert.equal(receipt.lifecycle.localAdminRequests, 9);
  assert.equal(receipt.complete, true);
});

test('the lane directory is derived from the module path even with a space, a Japanese character and a percent sign', async () => {
  const here = path.dirname(fileURLToPath(import.meta.url));
  assert.equal(LANE_DIR, here);
  assert.ok(existsSync(path.join(LANE_DIR, 'listen_collector.mjs')));
  // Node resolves module paths through realpath, so compare with the real temporary directory.
  const base = realpathSync(mkdtempSync(path.join(tmpdir(), 'fireemu-awkward-')));
  const tools = path.join(base, 'x y', '日本語%20', 'tools');
  const lane = path.join(tools, 'compat-broad', 'fs-listen-resume');
  const harness = path.join(tools, 'sdk-smoke-browser');
  try {
    mkdirSync(lane, { recursive: true });
    mkdirSync(harness, { recursive: true });
    for (const file of readdirSync(here).filter(name => name.endsWith('.mjs') && !name.endsWith('.test.mjs'))) {
      cpSync(path.join(here, file), path.join(lane, file));
    }
    cpSync(path.join(here, '..', '..', 'sdk-smoke-browser', 'browser_harness.mjs'), path.join(harness, 'browser_harness.mjs'));
    const copied = await import(pathToFileURL(path.join(lane, 'listen_browser_adapter.mjs')).href);
    assert.equal(copied.LANE_DIR, lane);
    assert.ok(existsSync(path.join(copied.LANE_DIR, 'listen_collector.mjs')));
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});
