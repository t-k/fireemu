import test from 'node:test';
import assert from 'node:assert/strict';
import { compareStreamReceipts } from './stream_comparison.mjs';
import { base, bytes, contract, fields, fixture, stamp, status } from './stream_row_fixture.mjs';

const compare = (production, local = structuredClone(production), expected = contract) => compareStreamReceipts({ production, local, expected });
const request = (r, i = 2) => r.observations[i].receipt.events.find(e => e.type === 'send' && e.value.writes).value;
const data = (r, i = 2) => r.observations[i].receipt.events.filter(e => e.type === 'data').at(-1).value;

test('matches complete captured proof including skipped absence without duplicate absence field', () => assert.equal(compare(fixture()).classification, 'MATCH'));
test('never elevates comparison to acquisition or promotion authority', () => { const r = compare(fixture()); assert.equal(r.acquisitionValidated, false); assert.equal(r.promotionReady, false); });
test('normalizes declared project, resource, owner, token, stream ID and ordered timestamps only', () => {
  const p = fixture(); const side = { projectId: 'other-project', documentPrefix: 'compat/o3/other-run' };
  const l = fixture({ ...side, owner: 'other-owner', shift: 1000, tokenShift: 10 });
  assert.equal(compare(p, l, { ...contract, production: base, local: side }).classification, 'EXPECTED_NONDETERMINISM');
});
test('opaque stream tokens may repeat without requiring freshness beyond latest-response use', () => assert.equal(compare(fixture({ reusedToken: true })).classification, 'MATCH'));
test('complete unexpected contention is semantic mismatch even if both peers agree', () => assert.equal(compare(fixture({ contentionCode: 0 })).classification, 'SEMANTIC_MISMATCH'));

const invalid = {
  'all terminal events missing': r => { r.observations[2].receipt.events = r.observations[2].receipt.events.filter(e => ['send', 'data'].includes(e.type)); },
  'status without end or close': r => { r.observations[2].receipt.events.pop(); },
  'status summary conflicts with terminal event': r => { r.observations[2].receipt.events.find(e => e.type === 'status').value = status(10); },
  'error conflicts with status': r => { r.observations[9].receipt.events.find(e => e.type === 'error').value.code = 7; },
  'missing unary request': r => { delete r.observations[0].receipt.request; },
  'foreign BeginTransaction database': r => { r.observations[6].receipt.request.database = 'projects/foreign/databases/(default)'; },
  'transactional read token differs from BeginTransaction': r => { r.observations[7].receipt.request.transaction = bytes(201); },
  'rollback token differs from BeginTransaction': r => { r.observations[11].receipt.request.transaction = bytes(201); },
  'extra Write updateMask': r => { request(r).writes[0].updateMask = { fieldPaths: ['value'] }; },
  'extra unary field': r => { r.observations[0].receipt.request.mask = { fieldPaths: ['owner'] }; },
  'foreign write resource': r => { request(r).writes[0].update.name += '-foreign'; },
  'unknown write frame field': r => { request(r).labels = {}; },
  'missing captured send events': r => { r.observations[2].receipt.events = r.observations[2].receipt.events.filter(e => e.type !== 'send'); },
  'stale latest response token': r => { request(r).streamToken = bytes(77); },
  'send attempt not completed': r => { r.observations[2].receipt.completedSendFrames = 1; },
  'received counter differs': r => { r.observations[2].receipt.receivedFrames = 1; },
  'empty successful write results': r => { data(r).writeResults = []; },
  'missing aggregate suffix readback': r => { delete r.observations[10].receipt.suffix; },
  'same cleanup resource repeated three times': r => { r.observations[14].cleanup = Array(3).fill(r.cleanup[0]); r.cleanup = r.observations[14].cleanup; },
  'missing final ownership read': r => { delete r.cleanup[0].ownedRead; },
  'foreign cleanup owner': r => { r.cleanup[0].ownedRead.response.fields.owner.stringValue = 'o3-stream:foreign'; },
  'cleanup read wrong target': r => { r.cleanup[0].ownedRead.request.name = r.cleanup[1].ownedRead.request.name; },
  'delete version not ownership read version': r => { r.cleanup[0].receipt.events[2].value.writes[0].currentDocument.updateTime = stamp(99); },
  'ownership read and delete use stale version': r => { r.cleanup[0].ownedRead.response.updateTime = stamp(99); r.cleanup[0].receipt.events[2].value.writes[0].currentDocument.updateTime = stamp(99); },
  'absence read targets wrong resource': r => { r.cleanup[0].absence.request.name = r.cleanup[1].absence.request.name; },
  'skipped cleanup lacks typed absence': r => { delete r.cleanup[2].receipt.status; },
  'incomplete stream': r => { r.observations[2].receipt.complete = false; },
  'invalid timestamp boolean seconds': r => { data(r).writeResults[0].updateTime.seconds = true; },
  'invalid timestamp range': r => { data(r).writeResults[0].updateTime = { seconds: '1', nanos: 1000000000 }; },
  'malformed token bytes': r => { request(r).streamToken.data = [256]; },
};
for (const [name, mutate] of Object.entries(invalid)) test(`independently rejects ${name}`, () => { const r = fixture(); mutate(r); assert.equal(compare(r).classification, 'INDETERMINATE'); });

test('counts every unary, aggregate read and cleanup RPC against explicit budget', () => assert.equal(compare(fixture(), fixture(), { ...contract, maxRpc: 21 }).classification, 'INDETERMINATE'));
test('counts send and receive frames together against explicit budget', () => assert.equal(compare(fixture(), fixture(), { ...contract, maxFramesPerRpc: 3 }).classification, 'INDETERMINATE'));
for (const field of ['owner-string', 'resource-string', 'timestamp-shaped']) test(`retains arbitrary ${field} user payload literally`, () => {
  const p = fixture(); const l = fixture({ owner: 'other-owner' });
  const a = p.observations[5].receipt.response; const b = l.observations[5].receipt.response;
  if (field === 'owner-string') { a.extra = { userString: p.ownerId }; b.extra = { userString: l.ownerId }; }
  if (field === 'resource-string') { a.extra = { name: a.name }; b.extra = { name: 'different-user-string' }; }
  if (field === 'timestamp-shaped') { a.extra = { updateTime: stamp(1) }; b.extra = { updateTime: { seconds: true, nanos: 0 } }; }
  assert.equal(compare(p, l).classification, 'SEMANTIC_MISMATCH');
});
test('preserves timestamp order rather than first-occurrence labels', () => {
  const p = fixture(); const l = fixture();
  for (const r of [p, l]) r.observations[5].receipt.response.createTime = stamp(r === p ? 90 : 110);
  assert.equal(compare(p, l).classification, 'SEMANTIC_MISMATCH');
});
test('complete unchanged status but moved locked poststate is semantic mismatch', () => { const l = fixture(); l.observations[10].receipt.locked.response.fields.value.stringValue = 'moved'; assert.equal(compare(fixture(), l).classification, 'SEMANTIC_MISMATCH'); });
test('collector outcome booleans cannot conceal raw semantic differences', () => { const l = fixture(); l.observations[13].receipt.response.fields.value.stringValue = 'wrong'; assert.equal(compare(fixture(), l).classification, 'SEMANTIC_MISMATCH'); });
test('redundant collector booleans are not the semantic source', () => { const l = fixture(); l.outcome.semantic = { madeUp: false }; l.readback.lockedUnchanged = false; assert.equal(compare(fixture(), l).classification, 'MATCH'); });
test('malformed public inputs fail closed without throwing', () => { for (const value of [null, [], 'x', 42, {}]) assert.equal(compare(value).classification, 'INDETERMINATE'); });

test('user keys named timestamp cannot collide with generated timestamp tags', () => {
  const p = fixture(); const l = fixture();
  p.observations[5].receipt.response.extra = { timestamp: 'production user content' };
  l.observations[5].receipt.response.extra = { timestamp: 'local user content' };
  assert.equal(compare(p, l).classification, 'SEMANTIC_MISMATCH');
});
test('rejects events after both terminal status and closure have completed the receipt', () => {
  const r = fixture(); r.observations[9].receipt.events.push({ type: 'data', value: data(r) }); r.observations[9].receipt.receivedFrames++;
  assert.equal(compare(r).classification, 'INDETERMINATE');
});
test('rejects an error inserted after terminal status and closure', () => {
  const r = fixture(); const events = r.observations[9].receipt.events; const e = events.splice(events.findIndex(e => e.type === 'error'), 1)[0]; events.push(e);
  assert.equal(compare(r).classification, 'INDETERMINATE');
});
test('cleanup owned read preserves semantic fields as well as ownership and version', () => {
  const r = fixture(); r.cleanup[0].ownedRead.response.fields.value.stringValue = 'changed';
  assert.equal(compare(r).classification, 'SEMANTIC_MISMATCH');
});
test('an acknowledged document unexpectedly absent at cleanup is semantic mismatch', () => {
  const r = fixture(); const item = r.cleanup[0];
  r.cleanup[0] = { path: item.path, complete: true, absent: true, skipped: true, receipt: item.absence }; r.observations[14].cleanup = r.cleanup;
  assert.equal(compare(r).classification, 'SEMANTIC_MISMATCH');
});
test('observation summary booleans do not produce expected nondeterminism', () => {
  const p = fixture(); const l = fixture(); p.observations[5].controlAccepted = true; l.observations[5].controlAccepted = false;
  assert.equal(compare(p, l).classification, 'MATCH');
});
test('unexpected transform results are semantic mismatch even when both sides agree', () => {
  const r = fixture(); data(r).writeResults[0].transformResults = [{ integerValue: '1' }];
  assert.equal(compare(r).classification, 'SEMANTIC_MISMATCH');
});

test('Gate skipped cleanup retains and budgets a separate registered final absence', () => {
  const r = fixture(); r.cleanup[2].absence = structuredClone(r.cleanup[2].receipt);
  assert.equal(compare(r).classification, 'MATCH');
  assert.equal(compare(r, structuredClone(r), { ...contract, maxRpc: 22 }).classification, 'INDETERMINATE');
});
test('Gate separate final absence cannot target a different resource', () => {
  const r = fixture(); r.cleanup[2].absence = structuredClone(r.cleanup[0].absence);
  assert.equal(compare(r).classification, 'INDETERMINATE');
});
test('supports frozen Gate budget of 25 slots without permitting larger budgets', () => {
  assert.equal(compare(fixture(), fixture(), { ...contract, maxRpc: 25 }).classification, 'MATCH');
  assert.equal(compare(fixture(), fixture(), { ...contract, maxRpc: 26 }).classification, 'INDETERMINATE');
});
test('public null input fails closed', () => assert.equal(compareStreamReceipts(null).classification, 'INDETERMINATE'));
test('nonfinite user numbers cannot be silently converted to null', () => {
  const p = fixture(); const l = fixture(); p.observations[5].receipt.response.extra = NaN; l.observations[5].receipt.response.extra = null;
  assert.equal(compare(p, l).classification, 'INDETERMINATE');
});

const recoveryJournal = r => {
  const entries = [{ index: 0, phase: 'rollback-finally', skipped: true }];
  for (const [i, role] of ['control', 'locked', 'suffix'].entries()) {
    const item = r.cleanup[i];
    if (item.skipped) item.absence = structuredClone(item.receipt);
    entries.push({ index: 1 + i * 3, phase: `owned-read-${role}`, skipped: false, receipt: item.skipped ? item.receipt : item.ownedRead });
    entries.push({ index: 2 + i * 3, phase: `conditional-delete-${role}`, skipped: item.skipped, ...(item.skipped ? {} : { receipt: item.receipt }) });
    entries.push({ index: 3 + i * 3, phase: `typed-absence-${role}`, skipped: false, receipt: item.absence });
  }
  r.recoveryObservations = entries;
  return r;
};
test('binds the optional Gate recovery journal to exact canonical cleanup receipts without double counting', () => {
  const r = recoveryJournal(fixture()); assert.equal(compare(r, structuredClone(r), { ...contract, maxRpc: 23 }).classification, 'MATCH');
});
for (const [name, mutate] of Object.entries({
  'missing recovery slot': r => { r.recoveryObservations.pop(); },
  'duplicate recovery index': r => { r.recoveryObservations[2].index = 1; },
  'wrong recovery phase': r => { r.recoveryObservations[1].phase = 'typed-absence-control'; },
  'unbound extra recovery receipt': r => { r.recoveryObservations[1].receipt = structuredClone(r.cleanup[1].ownedRead); },
  'skipped slot has extra receipt': r => { r.recoveryObservations[0].receipt = r.observations[11].receipt; },
  'extra executed rollback after complete nominal sequence': r => { r.recoveryObservations[0].skipped = false; r.recoveryObservations[0].receipt = r.observations[11].receipt; },
})) test(`rejects Gate ${name}`, () => { const r = recoveryJournal(fixture()); mutate(r); assert.equal(compare(r).classification, 'INDETERMINATE'); });

const canonicalByteEncoding = v => Array.isArray(v) ? v.map(canonicalByteEncoding) : v && typeof v === 'object' ? v.type === 'Buffer' ? Buffer.from(v.data).toString('base64') : Object.fromEntries(Object.entries(v).map(([k, x]) => [k, canonicalByteEncoding(x)])) : v;
test('accepts Gate canonical base64 bytes in the declared stream and transaction slots', () => assert.equal(compare(canonicalByteEncoding(recoveryJournal(fixture()))).classification, 'MATCH'));
for (const token of ['', 'not bytes!', 'YQ', 'YR==', '====']) test(`rejects noncanonical base64 token ${JSON.stringify(token)}`, () => {
  const r = canonicalByteEncoding(fixture()); r.observations[2].receipt.events[1].value.streamToken = token; r.observations[2].receipt.events[2].value.streamToken = token;
  assert.equal(compare(r).classification, 'INDETERMINATE');
});
test('same opaque bytes in Buffer JSON and canonical base64 are declared nondeterminism', () => {
  const r = fixture(); assert.equal(compare(r, canonicalByteEncoding(r)).classification, 'EXPECTED_NONDETERMINISM');
});
for (const length of [65535, 65536, 65537, 65538]) test(`canonical base64 token decoded length ${length} obeys the same byte bound as Buffer JSON`, () => {
  const r = canonicalByteEncoding(fixture()); const token = Buffer.alloc(length, 1).toString('base64');
  r.observations[2].receipt.events[1].value.streamToken = token; r.observations[2].receipt.events[2].value.streamToken = token;
  assert.equal(compare(r).classification, length <= 65536 ? 'MATCH' : 'INDETERMINATE');
});
