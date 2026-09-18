// Synthetic finite Write-stream/transaction journal shared by the comparator
// suites. Public data only: no credentials, oracle payloads, or private
// receipt fixtures are embedded here.
export const base = { projectId: 'fireemu-test', documentPrefix: 'compat/o3/run-fixed' };
export const contract = { version: 1, ...base, resources: ['control', 'locked', { suffix: 'contended-tail', role: 'suffix' }], maxRpc: 24, maxFramesPerRpc: 32 };
export const stamp = n => ({ seconds: String(n), nanos: 0 });
export const bytes = n => ({ type: 'Buffer', data: [n, 1, 2] });
export const status = code => ({ code, details: code ? 'server diagnostic' : '' });
export const fields = (owner, role, value) => ({ owner: { stringValue: `o3-stream:${owner}` }, role: { stringValue: role }, ...(value === undefined ? {} : { value: { stringValue: value } }) });

// Public synthetic journal follows transport v2 and collector's exact finite shape.
// No credentials, oracle payloads, or private receipt fixtures are embedded here.
export const fixture = ({ projectId = base.projectId, documentPrefix = base.documentPrefix, owner = 'owner-a', shift = 0, tokenShift = 0, reusedToken = false, contentionCode = 10 } = {}) => {
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
