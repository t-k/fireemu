import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { compareStreamReceiptsV2, v2Digest, v2TextDigest, writeComparisonArtifact } from './stream_recompare_v2.mjs';
import { compareStreamReceipts } from '../fs-write-txn/stream_comparison.mjs';

const base = { projectId: 'fireemu-test', documentPrefix: 'compat/o3/run-fixed' };
const contract = { version: 1, ...base, resources: ['control', 'locked', { suffix: 'contended-tail', role: 'suffix' }], maxRpc: 24, maxFramesPerRpc: 32 };
const stamp = n => ({ seconds: String(n), nanos: 0 });
const bytes = n => ({ type: 'Buffer', data: [n, 1, 2] });
const status = code => ({ code, details: code ? 'server diagnostic' : '' });
const fields = (owner, role, value) => ({ owner: { stringValue: `o3-stream:${owner}` }, role: { stringValue: role }, ...(value === undefined ? {} : { value: { stringValue: value } }) });

// Public synthetic journal follows transport v2 and collector's exact finite shape.
// No credentials, oracle payloads, or private receipt fixtures are embedded here.
const fixture = ({ projectId = base.projectId, documentPrefix = base.documentPrefix, owner = 'owner-a', shift = 0, tokenShift = 0, reusedToken = false, contentionCode = 10 } = {}) => {
  const database = `projects/${projectId}/databases/(default)`;
  const paths = { control: `${documentPrefix}/control`, locked: `${documentPrefix}/locked`, suffix: `${documentPrefix}/contended-tail` };
  const name = role => `${database}/documents/${paths[role]}`;
  const ts = n => stamp(n + shift);
  const doc = (role, value, time, created) => ({ name: name(role), fields: fields(owner, role, value), createTime: ts(created), updateTime: ts(time) });
  const unary = (operation, request, response, code = 0) => ({ kind: 'grpc_status', complete: true, operation, request, ...(code ? { status: status(code), error: { name: 'Error', ...status(code), message: `${code} server diagnostic` } } : { response }) });
  const get = (role, response, transaction) => unary('GetDocument', { name: name(role), ...(transaction ? { transaction } : {}) }, response, response ? 0 : 5);
  const update = (role, value, create = false) => ({ update: { name: name(role), fields: fields(owner, role, value) }, ...(create ? { currentDocument: { exists: false } } : {}) });
  let serial = 0;
  const write = (writes, time, code = 0) => {
    const token = bytes(++serial + tokenShift);
    const next = reusedToken ? token : bytes(serial + tokenShift + 50);
    const events = [
      { type: 'send', value: { database } },
      { type: 'data', value: { writeResults: [], streamId: `stream-${serial + tokenShift}`, streamToken: token, commitTime: null } },
      { type: 'send', value: { writes, streamToken: token } },
      ...(code === 0 ? [{ type: 'data', value: { writeResults: writes.map(w => ({ updateTime: w.delete ? null : ts(time), transformResults: [] })), streamId: '', streamToken: next, commitTime: ts(time) } }] : []),
      { type: 'status', value: status(code) },
      ...(code ? [{ type: 'error', value: { name: 'Error', ...status(code), message: `${code} server diagnostic` } }] : []),
      { type: code ? 'close' : 'end', value: { status: status(code) } },
    ];
    return { transportReceiptVersion: 2, kind: 'grpc_status', complete: true, status: status(code), sentFrames: 2, completedSendFrames: 2, receivedFrames: code ? 1 : 2, events };
  };
  const observations = [];
  const add = (phase, receipt) => observations.push({ phase, complete: true, receipt });
  add('preflight-create-absence', get('control'));
  add('preflight-create-absence', get('locked'));
  add('setup-control', write([update('control', undefined, true)], 100));
  add('setup-locked', write([update('locked', 'before', true)], 101));
  add('positive-uncontended-stream', write([update('control', 'accepted')], 102));
  add('readback-control', get('control', doc('control', 'accepted', 102, 100)));
  const transaction = bytes(200 + tokenShift);
  add('begin-rw-transaction', unary('BeginTransaction', { database, options: { readWrite: {} } }, { transaction }));
  add('get-locked-with-transaction', get('locked', doc('locked', 'before', 101, 101), transaction));
  add('preflight-suffix-absence', get('suffix'));
  add('contended-multiwrite-stream', write([update('locked', 'must-not-commit'), update('suffix', 'must-not-commit', true)], 103, contentionCode));
  const moved = contentionCode === 0;
  add('readback-contention', { locked: get('locked', doc('locked', moved ? 'must-not-commit' : 'before', moved ? 103 : 101, 101)), suffix: get('suffix', moved ? doc('suffix', 'must-not-commit', 103, 103) : undefined) });
  add('rollback', unary('Rollback', { database, transaction }, {}));
  add('post-rollback-positive-stream', write([update('locked', 'after-rollback')], 104));
  add('readback-post-rollback', get('locked', doc('locked', 'after-rollback', 104, 101)));
  const cleanup = Object.keys(paths).map((role, index) => {
    if (role === 'suffix' && !moved) return { path: paths[role], skipped: true, complete: true, absent: true, receipt: get(role) };
    const time = role === 'control' ? 102 : role === 'locked' ? 104 : 103;
    const value = role === 'control' ? 'accepted' : role === 'locked' ? 'after-rollback' : 'must-not-commit';
    return { path: paths[role], skipped: false, complete: true, absent: true, ownedRead: get(role, doc(role, value, time, role === 'control' ? 100 : role === 'locked' ? 101 : 103)), receipt: write([{ delete: name(role), currentDocument: { updateTime: ts(time) } }], 105 + index), absence: get(role) };
  });
  observations.push({ phase: 'cleanup', complete: true, cleanup });
  return { ownerId: owner, observations, cleanup, contention: observations[9].receipt, readback: { complete: true, lockedUnchanged: !moved, suffixAbsent: !moved, postRollbackWriteAccepted: true }, outcome: { complete: true, semantic: {} } };
};

const bindingFor = (production, local, v1Comparison, overrides = {}) => {
  const v2Sources = { kernel: 'kernel-v2-source', tests: 'tests-v2-source', readme: 'README-v2-source' };
  const artifact = { kind: 'stream-recompare-v2-artifact', localReceipt: local };
  const permission = { permissionDigest: 'permission-fixed' };
  const v1Source = 'stream-comparison-v1-source';
  return {
    productionReceiptSha256: v2Digest(production),
    localReceiptSha256: v2Digest(local),
    permissionSha256: v2Digest(permission),
    v1SourceSha256: v2TextDigest(v1Source),
    v1ComparisonSha256: v2Digest(v1Comparison),
    v2SourcesSha256: v2Digest(v2Sources),
    artifactSha256: v2Digest(artifact),
    permission,
    v1Source,
    v1Comparison,
    v2Sources,
    artifact,
    ...overrides,
  };
};

const pair = ({ differentResources = false } = {}) => {
  const production = fixture();
  const local = differentResources
    ? fixture({ projectId: 'other-project', documentPrefix: 'compat/o3/other-run', owner: 'other-owner', shift: 1000, tokenShift: 10 })
    : fixture();
  const setGrammar = (receipt, grammar) => {
    if (!receipt || typeof receipt !== 'object') return;
    if (receipt.operation === 'GetDocument' && receipt.status?.code === 5) {
      const name = receipt.request.name;
      for (const container of [receipt.status, receipt.error]) {
        if (container) {
          const body = grammar === 'quoted' ? `Document "${name}" not found.` : `Document not found: ${name}`;
          container.details = body;
          container.message = `5 NOT_FOUND: ${body}`;
        }
      }
    }
    for (const value of Object.values(receipt)) if (value && typeof value === 'object') setGrammar(value, grammar);
  };
  setGrammar(production, 'quoted');
  setGrammar(local, 'colon');
  const expected = differentResources
    ? { ...contract, production: { projectId: 'fireemu-test', documentPrefix: 'compat/o3/run-fixed' }, local: { projectId: 'other-project', documentPrefix: 'compat/o3/other-run' } }
    : contract;
  const v1Comparison = compareStreamReceipts({ production, local, expected });
  return { production, local, expected, v1Comparison, binding: bindingFor(production, local, v1Comparison) };
};

test('preserves differing diagnostic grammar after JSON roundtrip', () => {
  const result = compareStreamReceiptsV2(JSON.parse(JSON.stringify(pair())));
  assert.equal(result.v1Classification, 'SEMANTIC_MISMATCH');
  assert.equal(result.classification, 'SEMANTIC_MISMATCH');
  assert.equal(result.acquisitionValidated, false);
  assert.equal(result.promotionReady, false);
});

test('preserves grammar mismatch when resources differ', () => {
  const result = compareStreamReceiptsV2(pair({ differentResources: true }));
  assert.equal(result.v1Classification, 'SEMANTIC_MISMATCH');
  assert.equal(result.classification, 'SEMANTIC_MISMATCH');
});

test('preserves the pre-fix pair as v1 SEMANTIC_MISMATCH and rejects v1 hash drift', () => {
  const input = pair();
  input.binding.v1Comparison = { ...input.v1Comparison, classification: 'MATCH' };
  const result = compareStreamReceiptsV2(input);
  assert.equal(result.classification, 'INDETERMINATE');
});

for (const [name, mutate] of Object.entries({
  'partial resource text': r => { r.local.observations[0].receipt.error.details += ' extra'; },
  'unknown error field': r => { r.local.observations[0].receipt.error.userText = 'projects/fireemu-test'; },
  'user string': r => { r.local.observations[0].receipt.error.message = 'user Document not found: unrelated'; },
  'wrong status code': r => { r.local.observations[0].receipt.status.code = 7; r.local.observations[0].receipt.error.code = 7; },
  'wrong operation': r => { r.local.observations[0].receipt.operation = 'ListDocuments'; },
  'wrong request name': r => { r.local.observations[0].receipt.request.name += '-foreign'; },
})) test(`retains ${name} rather than applying diagnostic normalization`, () => {
  const input = pair();
  mutate(input);
  input.v1Comparison = compareStreamReceipts({ production: input.production, local: input.local, expected: input.expected });
  input.binding = bindingFor(input.production, input.local, input.v1Comparison);
  const result = compareStreamReceiptsV2(input);
  assert.notEqual(result.classification, 'MATCH');
});

test('binds every source, receipt, permission and artifact digest', () => {
  const input = pair();
  input.binding.artifactSha256 = '0'.repeat(64);
  assert.equal(compareStreamReceiptsV2(input).classification, 'INDETERMINATE');
});

for (const [name, mutate] of Object.entries({
  'terminal event': input => { input.local.observations[2].receipt.events.pop(); },
  'cleanup absence': input => { delete input.local.cleanup[0].absence; },
  'acknowledged write': input => { input.local.observations[2].receipt.receivedFrames = 1; },
})) test(`does not rescue v1 ${name} proof failures`, () => {
  const input = pair();
  mutate(input);
  input.v1Comparison = compareStreamReceipts({ production: input.production, local: input.local, expected: input.expected });
  input.binding = bindingFor(input.production, input.local, input.v1Comparison);
  assert.equal(compareStreamReceiptsV2(input).classification, 'INDETERMINATE');
});

test('writes a new private artifact exclusively', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'stream-v2-'));
  const path = join(directory, 'comparison.json');
  await writeComparisonArtifact(path, { classification: 'MATCH' });
  assert.equal(JSON.parse(await readFile(path, 'utf8')).classification, 'MATCH');
  await assert.rejects(() => writeComparisonArtifact(path, { classification: 'MISMATCH' }), /EEXIST/);
});

test('same grammar normalizes exact resources with independently copied cleanup', () => {
  const input = JSON.parse(JSON.stringify(pair({ differentResources: true })));
  const rewrite = value => {
    if (!value || typeof value !== 'object') return;
    for (const [key, child] of Object.entries(value)) {
      if (typeof child === 'string' && child.includes('Document not found: ')) value[key] = child.replace(/Document not found: (.+)$/, 'Document "$1" not found.');
      else rewrite(child);
    }
  };
  rewrite(input.local);
  input.v1Comparison = compareStreamReceipts(input);
  input.binding = bindingFor(input.production, input.local, input.v1Comparison);
  assert.equal(compareStreamReceiptsV2(input).classification, 'EXPECTED_NONDETERMINISM');
});

const assertReservedTagRejected = input => {
  const tag = '\u0000fireemu:v2:not-found:resource-slot\u0000';
  const receipt = input.local.observations[0].receipt;
  for (const container of [receipt.status, receipt.error]) {
    for (const key of ['details', 'message']) {
      container[key] = container[key].replace(receipt.request.name, tag);
    }
  }
  input = JSON.parse(JSON.stringify(input));
  input.v1Comparison = compareStreamReceipts(input);
  assert.equal(input.v1Comparison.classification, 'SEMANTIC_MISMATCH');
  input.binding = bindingFor(input.production, input.local, input.v1Comparison);
  const result = compareStreamReceiptsV2(input);
  assert.equal(result.classification, 'INDETERMINATE');
  assert.match(result.reasons[0].detail, /reserved diagnostic tag/);
};

test('rejects literal resource tag contamination that would otherwise collapse to MATCH', () => {
  const input = pair();
  input.local = JSON.parse(JSON.stringify(input.production));
  assertReservedTagRejected(input);
});

test('rejects the literal resource tag in actual repaired saved JSON', { skip: !process.env.STREAM_RECOMPARE_ROOT }, async () => {
  const outer = JSON.parse(await readFile(join(process.env.STREAM_RECOMPARE_ROOT, 'docs.local/logs/2026-09-17/stream-repair-shadow-567565bdd/owned-run/receipt.json'), 'utf8'));
  const plan = outer.gate.plan;
  assertReservedTagRejected({
    production: outer.collection,
    local: JSON.parse(JSON.stringify(outer.collection)),
    expected: { version: 1, projectId: plan.projectId, documentPrefix: plan.documentPrefix, resources: [{ role: 'control', suffix: 'control' }, { role: 'locked', suffix: 'locked' }, { role: 'suffix', suffix: 'contended-tail' }], maxRpc: 25, maxFramesPerRpc: 32 },
  });
});
