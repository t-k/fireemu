import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, writeFileSync, rmSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { checkShadow, parseEvidence } from './local_shadow_check.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const cli = path.join(root, 'tools/compat-broad/fs-listen-resume/local_shadow_check.mjs');
const historical = JSON.parse(readFileSync(path.join(root, 'spec/compatibility/fs-listen-sdk-local-shadow-historical.json'), 'utf8'));
const currentEvidence = JSON.parse(readFileSync(path.join(root, 'spec/compatibility/fs-listen-sdk-local-shadow.json'), 'utf8'));
const catalog = JSON.parse(readFileSync(path.join(root, 'spec/compatibility/fs-listen-sdk-cases.json'), 'utf8'));
// The catalog the historical receipt ran under: fourteen single-principal cases.
const historicalCatalogPath = path.join(root, 'spec/compatibility/fs-listen-sdk-cases-historical.json');
const historicalCatalog = JSON.parse(readFileSync(historicalCatalogPath, 'utf8'));
const current = () => structuredClone(currentEvidence);

test('historical expected events pass only under the explicit legacy contract and their own catalog', () => {
  assert.equal(checkShadow(historical, historicalCatalog).complete, false);
  assert.equal(checkShadow(historical, catalog, { legacyLifecycle: true }).complete, false,
    'the current catalog has more cases than the historical receipt');
  const result = checkShadow(historical, historicalCatalog, { legacyLifecycle: true });
  assert.equal(result.complete, true);
  assert.equal(result.legacyLifecycle, true);
  assert.equal(result.currentArtifactVerified, false);
  assert.equal(result.productionCompatibilityVerified, false);
});

test('synthetic current lifecycle can pass local expectation checking without claiming execution', () => {
  const result = checkShadow(current(), catalog);
  assert.equal(result.complete, true);
  assert.equal(result.legacyLifecycle, false);
  assert.equal(result.currentArtifactVerified, false);
});

const defects = {
  'empty cases': r => { r.cases = []; },
  'missing case': r => { r.cases.pop(); },
  'duplicate case': r => { r.cases[1] = r.cases[0]; },
  'duplicate-only': r => { r.cases = [r.cases[0], r.cases[0]]; },
  'reordered cases': r => { r.cases.reverse(); },
  'unknown case': r => { r.cases[0].caseId = 'foreign'; },
  'case incomplete': r => { r.cases[0].complete = false; },
  'listeners open': r => { r.cases[0].listenersClosed = false; },
  'invariant failed': r => { r.cases[0].invariantViolations = ['failure']; },
  'case failure': r => { r.cases[0].failures = ['failure']; },
  'non-boolean case flag': r => { r.cases[0].complete = 1; },
  'observed event absent': r => { r.cases[0].observed = []; },
  'missing null field': r => { delete r.cases[0].observed[0].error; },
  'wrong field type': r => { r.cases[0].observed[0].exists = 1; },
  'wrong comparison': r => { r.cases[0].comparison = 'any'; },
  'wrong role': r => { r.cases[0].role = 'any'; },
  'widened compared fields': r => { r.cases[0].comparedFields = []; },
  'top complete false': r => { r.complete = false; },
  'top complete string': r => { r.complete = 'true'; },
  'thrown failure': r => { r.thrown = 'failure'; },
  'thrown absent': r => { delete r.thrown; },
  'production result': r => { r.productionExecuted = true; },
  'wrong environment': r => { r.environment.kind = 'production'; },
  'wrong schema': r => { r.schema = 'unknown'; },
  'wrong catalog': r => { r.catalogDigest = 'a'.repeat(64); },
  'cleanup false': r => { r.cleanup.complete = false; },
  'cleanup empty': r => { r.cleanup.rows = []; },
  'cleanup duplicate': r => { r.cleanup.rows[1] = r.cleanup.rows[0]; },
  'cleanup still present': r => { r.cleanup.rows[0].outcome = 'still-present'; },
  'cleanup detail error': r => { r.cleanup.rows[0].detail = 'failure'; },
  'cleanup unproven': r => { r.cleanup.unproven = ['alpha']; },
  'cleanup count mismatch': r => { r.cleanup.deleted++; },
  'cleanup pass missing': r => { r.cleanupPasses.pop(); },
  'cleanup pass failed': r => { r.cleanupPasses[0].complete = false; },
  'cleanup pass counter': r => { r.cleanupPasses[0].deleted++; },
  'cleanup total mismatch': r => { r.totalDeleted++; },
  'cleanup resource swapped': r => { r.cleanupPasses[0].rows[0].pathDigest = 'a'.repeat(64); },
  'negative budget': r => { r.budget.used.reads = -1; },
  'overspent budget': r => { r.budget.used.reads = r.budget.limits.reads + 1; },
  'exhausted budget': r => { r.budget.exhausted = true; },
  'false flag despite exceeded': r => { r.budget.exceeded = ['reads']; },
  'missing budget': r => { delete r.budget; },
  'wrong budget keys': r => { delete r.budget.used.reads; },
  'float counter': r => { r.budget.used.reads = 0.5; },
  'boolean counter': r => { r.budget.used.reads = true; },
  'invalid deadline': r => { r.cleanupBudget.deadlineMs = Infinity; },
  'exhausted cleanup': r => { r.cleanupBudget.exhausted = true; },
  'lifecycle absent': r => { delete r.lifecycle; },
  'lifecycle incomplete': r => { r.lifecycle.complete = false; },
  'lifecycle failure': r => { r.lifecycle.failure = 'failure'; },
  'account not recovered': r => { r.lifecycle.accountCleanup.complete = false; },
  'clients not closed': r => { r.lifecycle.clients.complete = false; },
};
for (const [name, mutate] of Object.entries(defects)) test(`${name} must not pass`, () => {
  const receipt = current(); mutate(receipt);
  const result = checkShadow(receipt, catalog);
  assert.equal(result.complete, false, name);
  assert.ok(result.issues.length > 0);
});

test('legacy mode does not ignore an explicitly failed current lifecycle', () => {
  const receipt = current(); receipt.lifecycle.complete = false;
  assert.equal(checkShadow(receipt, catalog, { legacyLifecycle: true }).complete, false);
});
for (const input of [null, [], {}, true, 1, 'text']) test(`reject malformed object: ${JSON.stringify(input)}`, () => {
  assert.equal(checkShadow(input, catalog).complete, false);
  assert.equal(checkShadow(current(), input).complete, false);
});

test('editing catalog content without refreshing its digest fails', () => {
  const changed = structuredClone(catalog); changed.cases[0].title = 'new';
  assert.equal(checkShadow(current(), changed).complete, false);
});

for (const raw of ['{"complete":false,"complete":true}', '{"x":{"key":1,"\\u006bey":2}}',
  '[{"a":1,"a":1}]', '{"x":1e9999}', '{"x":NaN}', '{"x":Infinity}', '['.repeat(129)+'0'+']'.repeat(129)])
  test(`reject ambiguous/non-finite local JSON ${raw.slice(0, 45)}`, () => assert.throws(() => parseEvidence(raw)));
for (const raw of ['{"left":{"same":1},"right":{"same":2}}', '[{"same":1},{"same":2}]',
  '{"quote":"\\\"","slash":"\\\\","brackets":"{},[]","next":2}'])
  test(`accept unambiguous local JSON ${raw}`, () => assert.deepEqual(parseEvidence(raw), JSON.parse(raw)));

test('CLI failure codes and strict/legacy evidence remain distinguishable', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'listen-check-'));
  try {
    const file = path.join(dir, 'receipt.json');
    const run = (args, env = {}) => spawnSync(process.execPath, [cli, ...args],
      { cwd: root, encoding: 'utf8', timeout: 5000, env: { ...process.env, ...env } });
    writeFileSync(file, JSON.stringify(current()));
    let result = run([file]); assert.equal(result.status, 0, result.stderr);
    assert.equal(JSON.parse(result.stdout).currentArtifactVerified, false);
    writeFileSync(file, JSON.stringify(historical));
    const historicalEnv = { O6_LISTEN_CATALOG_PATH: historicalCatalogPath };
    assert.equal(run([file], historicalEnv).status, 1);
    assert.equal(run(['--legacy-lifecycle', file]).status, 1);
    assert.equal(run(['--legacy-lifecycle', file], historicalEnv).status, 0);
    const failure = current(); failure.cases = [];
    writeFileSync(file, JSON.stringify(failure)); assert.equal(run([file]).status, 1);
    writeFileSync(file, '{"secret":"PRIVATE-TOKEN",'); result = run([file]);
    assert.equal(result.status, 2); assert.ok(!`${result.stdout}${result.stderr}`.includes('PRIVATE-TOKEN'));
    writeFileSync(file, Buffer.from([0xff, 0xfe, 0x7b, 0x00])); assert.equal(run([file]).status, 2);
    const link = path.join(dir, 'link.json'); symlinkSync(file, link); assert.equal(run([link]).status, 2);
    assert.equal(run([]).status, 2);
    assert.equal(run([dir]).status, 2);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
