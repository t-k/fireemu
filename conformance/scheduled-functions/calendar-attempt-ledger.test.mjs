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

// Instrument real FileHandles; injection is reserved for syscall failure paths.
function observedIo(intercept = (_event, invoke) => invoke()) {
  const events = [];
  const live = new Set();
  const io = { ...fs, async open(file, ...args) {
    const handle = await fs.open(file, ...args);
    live.add(handle);
    const label = path.basename(file);
    return new Proxy(handle, { get(target, method) {
      if (typeof target[method] !== 'function') return target[method];
      return async (...arguments_) => {
        const event = `${label}:${String(method)}`;
        events.push(`start:${event}`);
        const value = await intercept(event, () => target[method](...arguments_), target, arguments_);
        events.push(`done:${event}`);
        if (method === 'close') live.delete(handle);
        return value;
      };
    } });
  } };
  return { io, events, live };
}

test('birth ack follows completed file sync and initial directory sync with real readback', async (t) => {
  const box = await sandbox(t);
  const traced = observedIo();
  const ledger = await createAttemptLedger({ ...box.options, io: traced.io });
  t.after(() => ledger.close());
  assert.ok(traced.events.includes('done:attempt-ledger:sync'), 'initial directory creation is synced');
  assert.ok(traced.events.includes(`done:${path.basename(box.root)}:sync`), 'root directory publishes ledger directory durably');
  assert.ok(traced.events.includes('done:authority.json:sync'));
  traced.events.length = 0;
  await ledger.registerBirth({ attemptId: 'a', planBytes: bytes({}) });
  traced.events.push('caller:side-effect');
  assert.ok(traced.events.indexOf('done:ledger.jsonl:sync') < traced.events.indexOf('caller:side-effect'));
  assert.ok(traced.events.indexOf('done:ledger.jsonl:sync') >= 0);
  assert.equal((await readback(box.root, box.options.authorityBytes)).state, 'unknown');
  traced.events.length = 0;
  await ledger.recordTerminal({ attemptId: 'a', reportBytes: report('a', 'pass', box.scope) });
  assert.ok(traced.events.indexOf('done:report-1.json:sync') < traced.events.indexOf('start:ledger.jsonl:write'));
  assert.ok(traced.events.indexOf('done:attempt-ledger:sync') < traced.events.indexOf('start:ledger.jsonl:write'));
  assert.ok(traced.events.indexOf('done:report-1.json:sync') >= 0);
  await ledger.close();
  assert.equal(traced.live.size, 0);
});

test('complete partial writes advance until all durable bytes are retained', async (t) => {
  const box = await sandbox(t);
  const traced = observedIo((event, invoke, handle, args) => event.endsWith(':write')
    ? handle.write(args[0], args[1], Math.min(args[2], 17), args[3]) : invoke());
  const ledger = await createAttemptLedger({ ...box.options, io: traced.io });
  t.after(() => ledger.close());
  await ledger.registerBirth({ attemptId: 'a', planBytes: bytes({}) });
  await ledger.recordTerminal({ attemptId: 'a', reportBytes: report('a', 'pass', box.scope) });
  await ledger.seal();
  assert.equal((await readback(box.root, box.options.authorityBytes)).state, 'complete');
  assert.ok(traced.events.filter((event) => event === 'done:ledger.jsonl:write').length > 20);
  await ledger.close();
  assert.equal(traced.live.size, 0);
});

for (const failure of ['zero-write', 'file-sync', 'directory-sync', 'unresolved-write']) {
  test(`${failure} denies durable ack and leaves sticky unknown IO status`, async (t) => {
    const box = await sandbox(t);
    let armed = false;
    const traced = observedIo((event, invoke) => {
      if (armed && failure === 'zero-write' && event === 'ledger.jsonl:write') return { bytesWritten: 0 };
      if (armed && failure === 'file-sync' && event === 'ledger.jsonl:sync') throw new Error('injected sync failure');
      if (armed && failure === 'directory-sync' && event === 'attempt-ledger:sync') throw new Error('injected directory sync failure');
      if (armed && failure === 'unresolved-write' && event === 'ledger.jsonl:write') return new Promise(() => {});
      return invoke();
    });
    const ledger = await createAttemptLedger({ ...box.options, io: traced.io, limits: { deadlineMs: 100 } });
    t.after(() => ledger.close());
    if (failure === 'directory-sync') await ledger.registerBirth({ attemptId: 'a', planBytes: bytes({}) });
    armed = true;
    const action = failure === 'directory-sync'
      ? ledger.recordTerminal({ attemptId: 'a', reportBytes: report('a', 'pass', box.scope) })
      : ledger.registerBirth({ attemptId: 'a', planBytes: bytes({}) });
    await assert.rejects(action, /unknown|sync|progress|deadline/);
    assert.equal(ledger.ioStatus().state, 'unknown');
    assert.equal(ledger.ioStatus().durabilityAcknowledged, false);
    await assert.rejects(ledger.registerBirth({ attemptId: 'second', planBytes: bytes({}) }), /unknown/);
    armed = false;
    await ledger.close();
    assert.equal(traced.live.size, 0);
  });
}

test('initial publication sync failure has no usable ledger and closes owned handles', async (t) => {
  const box = await sandbox(t);
  const traced = observedIo((event, invoke) => {
    if (event === 'authority.json:sync') throw new Error('initial sync failure');
    return invoke();
  });
  await assert.rejects(createAttemptLedger({ ...box.options, io: traced.io }), /sync failure/);
  assert.equal(traced.live.size, 0);
  await assert.rejects(fs.readFile(path.join(box.root, 'attempt-ledger', 'ledger.jsonl')), /ENOENT/);
});

test('seal stops admission immediately and rejects races with an accepted writer', async (t) => {
  const box = await sandbox(t);
  let armed = false;
  let resume;
  let entered;
  const atWrite = new Promise((resolve) => { entered = resolve; });
  const traced = observedIo(async (event, invoke) => {
    if (armed && event === 'ledger.jsonl:write') {
      entered();
      await new Promise((resolve) => { resume = resolve; });
    }
    return invoke();
  });
  const ledger = await createAttemptLedger({ ...box.options, io: traced.io });
  t.after(() => ledger.close());
  armed = true;
  const pending = ledger.registerBirth({ attemptId: 'a', planBytes: bytes({}) });
  await Promise.race([atWrite, pending.then(() => assert.fail('accepted birth bypassed durable write'))]);
  await assert.rejects(ledger.registerBirth({ attemptId: 'b', planBytes: bytes({}) }), /Concurrent/);
  await assert.rejects(ledger.seal(), /raced|unknown/);
  await assert.rejects(ledger.registerBirth({ attemptId: 'late', planBytes: bytes({}) }), /closed/);
  resume();
  await assert.rejects(pending, /unknown/);
  assert.equal(ledger.ioStatus().state, 'unknown');
  await ledger.close();
  assert.equal(traced.live.size, 0);
});

test('a valid seal reports IO ack separately from pure byte consistency', async (t) => {
  const box = await sandbox(t);
  const ledger = await createAttemptLedger(box.options);
  t.after(() => ledger.close());
  await ledger.registerBirth({ attemptId: 'a', planBytes: bytes({}) });
  await ledger.recordTerminal({ attemptId: 'a', reportBytes: report('a', 'pass', box.scope) });
  const sealed = await ledger.seal();
  assert.equal(sealed.durabilityAcknowledged, true);
  assert.equal(ledger.ioStatus().durabilityAcknowledged, true);
  assert.equal((await readback(box.root, box.options.authorityBytes)).durabilityAcknowledged, false);
  noCertificate(sealed);
});

test('seal rejects authority and report alterations, tail substitution and symlink reports', async (t) => {
  for (const alteration of ['authority', 'report', 'tail', 'symlink']) {
    const box = await sandbox(t);
    const ledger = await createAttemptLedger(box.options);
    t.after(() => ledger.close());
    await ledger.registerBirth({ attemptId: 'a', planBytes: bytes({}) });
    await ledger.recordTerminal({ attemptId: 'a', reportBytes: report('a', 'pass', box.scope) });
    const dir = path.join(box.root, 'attempt-ledger');
    if (alteration === 'authority') await fs.writeFile(path.join(dir, 'authority.json'), Buffer.from('altered authority'));
    if (alteration === 'report') await fs.writeFile(path.join(dir, 'report-1.json'), report('a', 'fail', box.scope));
    if (alteration === 'tail') await fs.appendFile(path.join(dir, 'ledger.jsonl'), '{}\n');
    if (alteration === 'symlink') {
      await fs.rename(path.join(dir, 'report-1.json'), path.join(dir, 'alternate.json'));
      await fs.symlink('alternate.json', path.join(dir, 'report-1.json'));
    }
    await assert.rejects(ledger.seal(), /unknown|mismatch|identity|ELOOP/);
    assert.equal(ledger.ioStatus().state, 'unknown');
  }
});

test('crash boundary prefixes cannot supply a certified or durable IO result', () => {
  const full = serialized([birth(), terminal(), seal()]);
  const auth = authority();
  for (let length = 0; length < full.length; length++) {
    const verdict = validateAttemptLedger({ authorityBytes: auth, authoritySha256: digest(auth), ledgerBytes: full.subarray(0, length), reports: new Map([['report-1.json', report()]]) });
    assert.notEqual(verdict.state, 'complete', `prefix ${length}`);
    assert.equal(verdict.durabilityAcknowledged, false);
    noCertificate(verdict);
  }
});

// The reference model consumes semantic actions, not production transition helpers.
test('generated independent state model reaches open, complete, unknown and rejected', () => {
  let seed = 0x271a7;
  const random = () => { seed ^= seed << 13; seed ^= seed >>> 17; seed ^= seed << 5; return seed >>> 0; };
  const reached = new Set();
  for (let trial = 0; trial < 1200; trial++) {
    const records = [];
    const reports = new Map();
    const attempts = new Map();
    let expected = 'open';
    let unresolved = false;
    let sealed = false;
    const length = 1 + random() % 10;
    for (let step = 0; step < length; step++) {
      const action = random() % 5;
      const id = ['a', 'b'][random() % 2];
      const seq = records.length + 1;
      if (action < 2) {
        records.push(birth(seq, id));
        if (sealed || attempts.has(id)) expected = 'rejected';
        else attempts.set(id, { seq, finished: false });
      } else if (action < 4) {
        const known = random() % 3 !== 0;
        const raw = report(id, known ? 'pass' : 'inconclusive');
        const attempt = attempts.get(id);
        const file = `report-${attempt?.seq ?? 999}.json`;
        records.push(terminal(seq, id, raw, file));
        reports.set(file, raw);
        if (sealed || !attempt || attempt.finished) expected = 'rejected';
        else { attempt.finished = true; unresolved ||= !known; }
      } else {
        records.push(seal(seq, seq - 1, attempts.size));
        if (sealed || attempts.size === 0 || [...attempts.values()].some((attempt) => !attempt.finished)) expected = 'rejected';
        else sealed = true;
      }
      if (expected !== 'rejected') expected = unresolved ? 'unknown' : sealed ? 'complete' : 'open';
      const actual = reduceAttemptRecords(scope, records, { reports });
      assert.equal(actual.state, expected, `trial=${trial} step=${step} actions=${JSON.stringify(records)}`);
      noCertificate(actual);
      reached.add(actual.state);
      if (expected === 'rejected') break;
    }
  }
  assert.deepEqual([...reached].sort(), ['complete', 'open', 'rejected', 'unknown']);
});

test('each publication failure boundary denies acknowledgement even if page-cache bytes are complete', async (t) => {
  for (const boundary of ['report-sync', 'report-directory-sync', 'terminal-write', 'terminal-sync', 'seal-sync']) {
    const box = await sandbox(t);
    let armed = false;
    const traced = observedIo(async (event, invoke) => {
      const matches = (boundary === 'report-sync' && event === 'report-1.json:sync') ||
        (boundary === 'report-directory-sync' && event === 'attempt-ledger:sync') ||
        (boundary === 'terminal-write' && event === 'ledger.jsonl:write') ||
        (['terminal-sync', 'seal-sync'].includes(boundary) && event === 'ledger.jsonl:sync');
      const value = await invoke();
      if (armed && matches) throw new Error(`injected completed syscall failure: ${boundary}`);
      return value;
    });
    const ledger = await createAttemptLedger({ ...box.options, io: traced.io });
    t.after(() => ledger.close());
    await ledger.registerBirth({ attemptId: 'a', planBytes: bytes({}) });
    if (boundary === 'seal-sync') await ledger.recordTerminal({ attemptId: 'a', reportBytes: report('a', 'pass', box.scope) });
    armed = true;
    await assert.rejects(boundary === 'seal-sync' ? ledger.seal()
      : ledger.recordTerminal({ attemptId: 'a', reportBytes: report('a', 'pass', box.scope) }), /unknown|failure/);
    assert.equal(ledger.ioStatus().state, 'unknown');
    assert.equal(ledger.ioStatus().durabilityAcknowledged, false);
    const rawOnly = await readback(box.root, box.options.authorityBytes);
    assert.equal(rawOnly.durabilityAcknowledged, false, 'page-cache readback never proves completed sync');
    noCertificate(rawOnly);
    armed = false;
    await ledger.close();
    assert.equal(traced.live.size, 0);
  }
});

test('missing, inconclusive and foreign terminal reports never receive a seal IO ack', async (t) => {
  for (const value of [null, Buffer.from('{'), 'inconclusive', 'foreign']) {
    const box = await sandbox(t);
    const ledger = await createAttemptLedger(box.options);
    t.after(() => ledger.close());
    await ledger.registerBirth({ attemptId: 'a', planBytes: bytes({}) });
    const raw = typeof value === 'string' ? report('a', value === 'foreign' ? 'pass' : value,
      value === 'foreign' ? { ...box.scope, campaign: 'foreign' } : box.scope) : value;
    await ledger.recordTerminal({ attemptId: 'a', reportBytes: raw });
    await assert.rejects(ledger.seal(), /unknown|Inconclusive|Foreign/);
    assert.equal(ledger.ioStatus().state, 'unknown');
    assert.equal(ledger.ioStatus().durabilityAcknowledged, false);
  }
});

test('writer finite limits retain unresolved births and prevent unbounded admission', async (t) => {
  const box = await sandbox(t);
  const ledger = await createAttemptLedger({ ...box.options, limits: { maxRecords: 2 } });
  t.after(() => ledger.close());
  await ledger.registerBirth({ attemptId: 'a', planBytes: bytes({}) });
  await assert.rejects(ledger.registerBirth({ attemptId: 'b', planBytes: bytes({}) }), /bound|unknown/);
  assert.equal((await readback(box.root, box.options.authorityBytes)).state, 'unknown');
  assert.equal(ledger.ioStatus().state, 'unknown');
});

test('hardlink aliases and substituted journal files are rejected without following aliases', async (t) => {
  for (const change of ['hardlink', 'substitute']) {
    const box = await sandbox(t);
    const ledger = await createAttemptLedger(box.options);
    t.after(() => ledger.close());
    const journal = path.join(box.root, 'attempt-ledger', 'ledger.jsonl');
    if (change === 'hardlink') await fs.link(journal, path.join(box.root, 'aliased-ledger'));
    else {
      const retained = await fs.readFile(journal);
      await fs.unlink(journal);
      await fs.writeFile(journal, retained);
    }
    await assert.rejects(ledger.registerBirth({ attemptId: 'a', planBytes: bytes({}) }), /identity|unknown/);
  }
});

test('close continues releasing remaining handles after one close failure', async (t) => {
  const box = await sandbox(t);
  let armed = false;
  let failed = false;
  const traced = observedIo((event, invoke) => {
    if (armed && !failed && event.endsWith(':close')) { failed = true; throw new Error('injected close failure'); }
    return invoke();
  });
  const ledger = await createAttemptLedger({ ...box.options, io: traced.io });
  t.after(() => ledger.close());
  armed = true;
  await assert.rejects(ledger.close(), /unknown|close failure/);
  assert.equal(traced.live.size, 1, 'only the failed handle remains retryable');
  await ledger.close();
  assert.equal(traced.live.size, 0);
});

test('filesystem substitution during birth write prevents an acknowledgement before side effects', async (t) => {
  const box = await sandbox(t);
  let armed = false;
  const traced = observedIo(async (event, invoke) => {
    const value = await invoke();
    if (armed && event === 'ledger.jsonl:write') {
      armed = false;
      await fs.rename(box.root, `${box.root}-original`);
      await fs.mkdir(box.root);
    }
    return value;
  });
  const ledger = await createAttemptLedger({ ...box.options, io: traced.io });
  t.after(() => ledger.close());
  t.after(() => fs.rm(`${box.root}-original`, { recursive: true, force: true }));
  armed = true;
  await assert.rejects(ledger.registerBirth({ attemptId: 'a', planBytes: bytes({}) }), /unknown|identity/);
  assert.equal(ledger.ioStatus().state, 'unknown');
});

test('raw report alteration during seal publication prevents durable seal acknowledgement', async (t) => {
  const box = await sandbox(t);
  let armed = false;
  const traced = observedIo(async (event, invoke) => {
    const value = await invoke();
    if (armed && event === 'ledger.jsonl:write') {
      armed = false;
      await fs.writeFile(path.join(box.root, 'attempt-ledger', 'report-1.json'), report('a', 'fail', box.scope));
    }
    return value;
  });
  const ledger = await createAttemptLedger({ ...box.options, io: traced.io });
  t.after(() => ledger.close());
  await ledger.registerBirth({ attemptId: 'a', planBytes: bytes({}) });
  await ledger.recordTerminal({ attemptId: 'a', reportBytes: report('a', 'pass', box.scope) });
  armed = true;
  await assert.rejects(ledger.seal(), /unknown|mismatch/);
  assert.equal(ledger.ioStatus().state, 'unknown');
});

test('exports the bounded durable ledger and independent bytes validator', async () => {
  const api = await import('./calendar-attempt-ledger.mjs').catch(() => ({}));
  assert.equal(typeof api.createAttemptLedger, 'function', 'durable ledger API is missing');
  assert.equal(typeof api.validateAttemptLedger, 'function', 'raw bytes validator is missing');
  assert.equal(typeof api.reduceAttemptRecords, 'function', 'pure transition validator is missing');
});
