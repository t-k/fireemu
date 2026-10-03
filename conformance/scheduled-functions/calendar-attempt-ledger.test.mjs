import assert from 'node:assert/strict';
import test from 'node:test';
import * as fs from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createAttemptLedger, reduceAttemptRecords, validateAttemptLedger } from './calendar-attempt-ledger.mjs';

const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');
const bytes = (value) => Buffer.from(JSON.stringify(value));
const day = new Date().toISOString().slice(0, 10);
const clock = () => Date.parse(`${day}T12:00:00Z`);
function authority(root = '/tmp/synthetic-attempt-authority') {
  return bytes({ schema: 'scoped-attempt-authority/v1', authorityId: 'injected-test-only', scope: {
    campaign: 'synthetic', utcDay: day, runRoot: root, harnessH: 'd'.repeat(64),
    buildPins: { sourceCommit: 'a'.repeat(40), binarySha256: 'b'.repeat(64), runnerSha256: 'c'.repeat(64) },
    nativeRoot: { pid: 123, start: 'synthetic-native-start', sid: 456 },
  } });
}
const scope = JSON.parse(authority()).scope;
const birth = (seq = 1, attemptId = 'a') => ({ type: 'birth', seq, scope, attemptId, planSha256: digest(bytes({ plan: 1 })) });
function report(attemptId = 'a', outcome = 'pass', reportScope = scope) {
  return bytes({ schema: 'attempt-report/v1', scope: reportScope, attemptId, outcome });
}
function terminal(seq = 2, attemptId = 'a', raw = report(attemptId), reportFile = 'report-1.json') {
  return { type: 'terminal', seq, scope, attemptId, reportFile: raw === null ? null : reportFile, reportSha256: raw === null ? null : digest(raw), reportBytes: raw?.length ?? 0 };
}
const seal = (seq = 3, tail = 2, births = 1) => ({ type: 'seal', seq, scope, tail, births });
const rows = (records) => Buffer.from(records.map((r) => JSON.stringify(r)).join('\n') + '\n');
function serialized(records, rawAuthority = authority()) {
  return rows([{ type: 'header', seq: 0, scope: JSON.parse(rawAuthority).scope, authoritySha256: digest(rawAuthority) }, ...records]);
}
function validate(records, reports = new Map([['report-1.json', report()]])) {
  const rawAuthority = authority();
  return validateAttemptLedger({ authorityBytes: rawAuthority, authoritySha256: digest(rawAuthority), ledgerBytes: serialized(records), reports });
}
function noCertificate(result) {
  assert.equal(result.allDayCertified, false);
  assert.equal(result.historicalCompleteness, 'UNKNOWN');
  assert.equal(result.externalApprovalVerified, false);
}
async function sandbox(t) {
  const parent = await fs.mkdtemp(path.join(tmpdir(), 'attempt-ledger-test-'));
  const root = await fs.realpath(parent);
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const rawAuthority = authority(root);
  const options = { authorityBytes: rawAuthority, authoritySha256: digest(rawAuthority), now: clock };
  return { root, options, scope: JSON.parse(rawAuthority).scope };
}
async function readback(root, rawAuthority) {
  const dir = path.join(root, 'attempt-ledger');
  const ledgerBytes = await fs.readFile(path.join(dir, 'ledger.jsonl'));
  const reports = new Map();
  for (const record of ledgerBytes.toString().split('\n').filter(Boolean).map(JSON.parse)) {
    if (record.type === 'terminal' && record.reportFile !== null) reports.set(record.reportFile, await fs.readFile(path.join(dir, record.reportFile)));
  }
  return validateAttemptLedger({ authorityBytes: rawAuthority, authoritySha256: digest(rawAuthority), ledgerBytes, reports });
}

test('sealed exact raw reports establish only ledger consistency', () => {
  const result = validate([birth(), terminal(), seal()]);
  assert.equal(result.state, 'complete');
  noCertificate(result);
});

test('unknown evidence remains unknown without explanatory rescue', () => {
  for (const raw of [null, bytes({}), Buffer.from('{'), report('a', 'inconclusive')]) {
    const result = validate([birth(), terminal(2, 'a', raw), seal()], new Map(raw === null ? [] : [['report-1.json', raw]]));
    assert.equal(result.state, 'unknown');
    noCertificate(result);
  }
  assert.equal(validate([birth(), terminal(), seal()], new Map()).state, 'unknown');
  assert.equal(validate([birth()]).state, 'unknown');
});

test('rejects missing births, gaps, duplicates, reordered records and incorrect sealed tails', () => {
  const invalid = [
    [terminal(1), seal(2, 1)], [birth(2)], [birth(), birth(2)],
    [birth(), terminal(), terminal(3), seal(4, 3)], [birth(), seal(2, 1)],
    [birth(), terminal(), seal(3, 1)], [birth(), terminal(), seal(), birth(4, 'late')],
    [birth(), terminal(), seal(3, 2, 2)], [seal(1, 0, 0)],
  ];
  for (const records of invalid) assert.equal(validate(records).state, 'rejected', JSON.stringify(records));
});

test('rejects foreign scope, mismatched raw SHA and native identity substitution', () => {
  const foreign = { ...scope, campaign: 'foreign' };
  assert.equal(validate([{ ...birth(), scope: foreign }]).state, 'rejected');
  assert.equal(validate([birth(), terminal(), seal()], new Map([['report-1.json', report('a', 'fail')]])).state, 'rejected');
  const raw = report('a', 'pass', foreign);
  assert.equal(validate([birth(), terminal(2, 'a', raw), seal()], new Map([['report-1.json', raw]])).state, 'rejected');
  const changedNative = { ...scope, nativeRoot: { ...scope.nativeRoot, sid: 123 } };
  assert.equal(validate([{ ...birth(), scope: changedNative }]).state, 'rejected');
});

test('raw bytes validator fails closed on truncated bytes, authority mismatch and finite limits', () => {
  const auth = authority();
  const valid = serialized([birth(), terminal(), seal()]);
  const input = { authorityBytes: auth, authoritySha256: digest(auth), ledgerBytes: valid, reports: new Map([['report-1.json', report()]]) };
  assert.equal(validateAttemptLedger({ ...input, ledgerBytes: valid.subarray(0, valid.length - 1) }).state, 'unknown');
  assert.equal(validateAttemptLedger({ ...input, ledgerBytes: Buffer.from('{\n') }).state, 'unknown');
  assert.equal(validateAttemptLedger({ ...input, authoritySha256: '0'.repeat(64) }).state, 'rejected');
  assert.equal(validateAttemptLedger({ ...input, limits: { maxBytes: 1 } }).state, 'unknown');
  assert.equal(validateAttemptLedger({ ...input, limits: { maxRecords: 2 } }).state, 'unknown');
  assert.equal(validateAttemptLedger({ ...input, limits: { maxReportBytes: 1 } }).state, 'unknown');
});

test('real FileHandles durably retain authority, births and raw terminal reports before sealing', async (t) => {
  const box = await sandbox(t);
  const ledger = await createAttemptLedger(box.options);
  t.after(() => ledger.close());
  await ledger.registerBirth({ attemptId: 'a', planBytes: bytes({ plan: 1 }) });
  const prelaunch = await readback(box.root, box.options.authorityBytes);
  assert.equal(prelaunch.state, 'unknown', 'prelaunch failure leaves an unresolved durable birth');
  const actualReport = report('a', 'fail', box.scope);
  await ledger.recordTerminal({ attemptId: 'a', reportBytes: actualReport });
  assert.equal((await ledger.seal()).state, 'complete');
  await assert.rejects(ledger.registerBirth({ attemptId: 'late', planBytes: bytes({}) }), /closed|sealed/);
  await ledger.close();
  assert.deepEqual(await fs.readFile(path.join(box.root, 'attempt-ledger', 'authority.json')), box.options.authorityBytes);
  assert.deepEqual(await fs.readFile(path.join(box.root, 'attempt-ledger', 'report-1.json')), actualReport);
  const final = await readback(box.root, box.options.authorityBytes);
  assert.equal(final.state, 'complete');
  noCertificate(final);
});

test('exclusive ownership rejects a second writer and closes every owned handle', async (t) => {
  const box = await sandbox(t);
  const ledger = await createAttemptLedger(box.options);
  t.after(() => ledger.close());
  await assert.rejects(createAttemptLedger(box.options), /EEXIST|exclusive/);
  await ledger.close();
  await assert.rejects(ledger.registerBirth({ attemptId: 'a', planBytes: bytes({}) }), /closed/);
});

test('rejects symlink aliases, normalized root aliases and runtime root substitution', async (t) => {
  const box = await sandbox(t);
  const alias = `${box.root}-alias`;
  await fs.symlink(box.root, alias);
  t.after(() => fs.unlink(alias));
  for (const root of [alias, `${box.root}/../${path.basename(box.root)}`]) {
    const rawAuthority = authority(root);
    await assert.rejects(createAttemptLedger({ ...box.options, authorityBytes: rawAuthority, authoritySha256: digest(rawAuthority) }), /root|alias|scope/);
  }
  const ledger = await createAttemptLedger(box.options);
  t.after(() => ledger.close());
  await fs.rename(box.root, `${box.root}-original`);
  t.after(() => fs.rm(`${box.root}-original`, { recursive: true, force: true }));
  await fs.mkdir(box.root);
  await assert.rejects(ledger.registerBirth({ attemptId: 'a', planBytes: bytes({}) }), /identity|substitut|unknown/);
});

test('rejects UTC day rollover, invalid bounds and terminal references without births', async (t) => {
  const box = await sandbox(t);
  let instant = clock();
  const ledger = await createAttemptLedger({ ...box.options, now: () => instant });
  t.after(() => ledger.close());
  await assert.rejects(ledger.recordTerminal({ attemptId: 'a', reportBytes: report('a', 'pass', box.scope) }), /birth/);
  instant += 86400000;
  await assert.rejects(ledger.registerBirth({ attemptId: 'a', planBytes: bytes({}) }), /day/);
  const other = await sandbox(t);
  await assert.rejects(createAttemptLedger({ ...other.options, limits: { deadlineMs: Infinity } }), /limit/);
});

test('exports the bounded durable ledger and independent bytes validator', async () => {
  const api = await import('./calendar-attempt-ledger.mjs').catch(() => ({}));
  assert.equal(typeof api.createAttemptLedger, 'function', 'durable ledger API is missing');
  assert.equal(typeof api.validateAttemptLedger, 'function', 'raw bytes validator is missing');
  assert.equal(typeof api.reduceAttemptRecords, 'function', 'pure transition validator is missing');
});
