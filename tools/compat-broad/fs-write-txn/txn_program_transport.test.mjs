import assert from 'node:assert/strict';
import { test } from 'node:test';

const project = 'demo-program';
const database = `projects/${project}/databases/(default)`;
const nonce = 'a'.repeat(32);
const ownerId = 'b'.repeat(32);
const documents = ['a', 'm'];
const states = ['created', 'held', 'moved'];
const name = role => `${database}/documents/oracle/${nonce}/txn-toy/${role}`;
const token = Buffer.from('issued-token').toString('base64');
const module = () => import('./txn_program_transport.mjs');
const local = { kind: 'local', host: '127.0.0.1', port: 12345 };
const spec = (method, request, transport = 'grpc', extra = {}) => ({ kind: 'txn-program-call-v1', transport, target: local, projectId: project, nonce, ownerId, slug: 'txn-toy', documents, states, method, request, bearer: 'owner', deadlineMs: 1000, ...extra });
const fields = (role, state) => Object.fromEntries(Object.entries({ owner: ownerId, nonce, role, state }).map(([key, value]) => [key, { stringValue: value }]));
const write = (role, state, exists = true) => ({ update: { name: name(role), fields: fields(role, state) }, currentDocument: { exists } });
const commit = (writes, withToken = true) => ({ database, writes, ...(withToken ? { transaction: token } : {}) });

for (const transport of ['rest', 'grpc']) {
  test(`${transport}: every owned document and declared state is admitted, in one commit or several`, async () => {
    const { validateCall } = await module();
    for (const state of states) validateCall(spec('Commit', commit([write('a', state)]), transport));
    validateCall(spec('Commit', commit([write('a', 'held'), write('m', 'held')]), transport));
    validateCall(spec('Commit', commit([write('a', 'moved')], false), transport));
    validateCall(spec('GetDocument', { name: name('m') }, transport));
    validateCall(spec('GetDocument', { name: name('a'), transaction: token }, transport));
    validateCall(spec('Rollback', { database, transaction: token }, transport));
    validateCall(spec('BeginTransaction', { database, options: { readWrite: {} } }, transport));
  });

  test(`${transport}: a document, state or owner outside the plan's scope is refused before dispatch`, async () => {
    const { validateCall } = await module();
    const wrongDocument = commit([write('a', 'held')]); wrongDocument.writes[0].update.name = name('z');
    const otherProgram = commit([write('a', 'held')]); otherProgram.writes[0].update.name = name('a').replace('txn-toy', 'txn-other');
    const otherRun = commit([write('a', 'held')]); otherRun.writes[0].update.name = name('a').replace(nonce, 'c'.repeat(32));
    const wrongRole = commit([write('a', 'held')]); wrongRole.writes[0].update.fields.role.stringValue = 'm';
    for (const body of [commit([write('a', 'gone')]), wrongDocument, otherProgram, otherRun, wrongRole, commit([write('a', 'held'), write('a', 'moved')]), commit([], false), commit([write('a', 'held'), write('m', 'held'), write('a', 'moved')])]) assert.throws(() => validateCall(spec('Commit', body, transport)));
    for (const change of ['owner', 'nonce', 'extra', 'precondition']) {
      const body = commit([write('a', 'held')]);
      if (change === 'owner' || change === 'nonce') body.writes[0].update.fields[change].stringValue = 'foreign';
      else if (change === 'extra') body.writes[0].update.fields.extra = { stringValue: 'foreign' };
      else delete body.writes[0].currentDocument;
      assert.throws(() => validateCall(spec('Commit', body, transport)), undefined, change);
    }
    assert.throws(() => validateCall(spec('GetDocument', { name: name('a').replace(nonce, 'c'.repeat(32)) }, transport)));
  });

  test(`${transport}: BeginTransaction is fresh and refuses another mode, and a retry unless it is a REST read-write begin naming a canonical token`, async () => {
    const { validateCall } = await module();
    validateCall(spec('BeginTransaction', { database, options: { readWrite: {} } }, transport));
    validateCall(spec('BeginTransaction', { database, options: { readOnly: {} } }, transport));
    const refused = [{ readOnly: { readTime: '2026-09-30T00:00:00Z' } }, { readWrite: {}, readOnly: {} }, { readWrite: { extra: true } }, { readOnly: { extra: true } }, { other: {} }, {},
      { readWrite: { retryTransaction: 'not canonical' } }, { readWrite: { retryTransaction: '' } }, { readWrite: { retryTransaction: 5 } }, { readWrite: { retryTransaction: token, extra: true } }, { readOnly: { retryTransaction: token } }];
    // a retry is accepted only over REST
    if (transport === 'rest') validateCall(spec('BeginTransaction', { database, options: { readWrite: { retryTransaction: token } } }, transport));
    else refused.push({ readWrite: { retryTransaction: token } });
    for (const options of refused) assert.throws(() => validateCall(spec('BeginTransaction', { database, options }, transport)), undefined, JSON.stringify(options));
  });

  test(`${transport}: a retry begin keeps its transport request body`, async () => {
    if (transport !== 'rest') return;
    const { restRequest } = await module();
    assert.deepEqual(restRequest(spec('BeginTransaction', { database, options: { readWrite: { retryTransaction: token } } }, 'rest')), { method: 'POST', path: `/v1/${database}/documents:beginTransaction`, body: { options: { readWrite: { retryTransaction: token } } } });
  });

  test(`${transport}: protocol, project, token, credential and deadline changes are rejected`, async () => {
    const { validateCall } = await module();
    const base = spec('GetDocument', { name: name('a') }, transport);
    for (const changes of [
      { kind: 'txn-boundary-grpc-call-v1' }, { projectId: 'fireemu-oracle-idp' }, { transport: 'http' },
      { target: { kind: 'local', host: 'localhost', port: 12345 } }, { target: { kind: 'production' } },
      { request: { name: name('a'), transaction: 'bad-token' } }, { request: { name: name('a'), extra: true } },
      { bearer: 'owner\nAuthorization: injected' }, { deadlineMs: 0 }, { deadlineMs: 10001 }, { deadlineMs: 30001 }, { deadlineMs: 1.5 },
      { slug: 'Txn Toy' }, { documents: ['a', 'a'] }, { documents: [] }, { states: [] }, { states: ['UPPER'] }, { extra: true },
    ]) assert.throws(() => validateCall({ ...base, ...changes }), undefined, JSON.stringify(Object.keys(changes)));
  });
}

for (const transport of ['rest', 'grpc']) {
  test(`${transport}: an empty commit must name its transaction, and a batch read names distinct owned documents`, async () => {
    const { validateCall } = await module();
    validateCall(spec('Commit', commit([]), transport));
    assert.throws(() => validateCall(spec('Commit', commit([], false), transport)));
    validateCall(spec('BatchGetDocuments', { database, documents: [name('a'), name('m')] }, transport));
    validateCall(spec('BatchGetDocuments', { database, documents: [name('a')], transaction: token }, transport));
    for (const request of [
      { database, documents: [] }, { database, documents: [name('a'), name('a')] }, { database, documents: [name('a'), name('z')] },
      { database, documents: [name('a'), name('m'), name('a')] }, { database: 'projects/other/databases/(default)', documents: [name('a')] },
      { database, documents: [name('a').replace(nonce, 'c'.repeat(32))] }, { database, documents: [name('a')], transaction: 'bad' }, { database, documents: [name('a')], extra: true }, { documents: [name('a')] },
      { database, documents: 'x' },
    ]) assert.throws(() => validateCall(spec('BatchGetDocuments', request, transport)), undefined, JSON.stringify(request).slice(0, 60));
  });
}

test('REST: a batch read becomes one fixed request and its entries are kept as a list', async () => {
  const { restRequest, runUnary } = await module();
  const call = spec('BatchGetDocuments', { database, documents: [name('a'), name('m')], transaction: token }, 'rest');
  assert.deepEqual(restRequest(call), { method: 'POST', path: `/v1/${database}/documents:batchGet`, body: { documents: [name('a'), name('m')], transaction: token } });
  assert.deepEqual(restRequest(spec('BatchGetDocuments', { database, documents: [name('a')] }, 'rest')).body, { documents: [name('a')] });
  const entries = [{ found: { name: name('a'), fields: {}, updateTime: '2026-09-30T00:00:00.000000001Z' }, readTime: '2026-09-30T00:00:01Z' }, { missing: name('m'), readTime: '2026-09-30T00:00:01Z' }];
  const result = await runUnary(call, exchange([{ status: 200, text: JSON.stringify(entries) }]).run);
  assert.deepEqual([result.code, result.complete, result.http, result.response], [0, true, 200, { responses: entries }]);
});

test('REST: a batch answer that is not a bounded list of entries is an unknown outcome, and an error entry is an error', async () => {
  const { runUnary } = await module();
  const call = spec('BatchGetDocuments', { database, documents: [name('a')] }, 'rest');
  for (const text of [JSON.stringify({ not: 'a list' }), JSON.stringify(['x']), JSON.stringify(Array.from({ length: 17 }, () => ({ missing: name('a') })))]) {
    const result = await runUnary(call, exchange([{ status: 200, text }]).run);
    assert.deepEqual([result.code, result.complete], [2, false], text.slice(0, 40));
  }
  const refused = await runUnary(call, exchange([{ status: 409, text: JSON.stringify([{ error: { code: 409, message: 'contended', status: 'ABORTED' } }]) }]).run);
  assert.deepEqual([refused.code, refused.complete, refused.details], [10, true, 'contended']);
  const plainError = await runUnary(call, exchange([{ status: 404, text: JSON.stringify({ error: { message: 'gone', status: 'NOT_FOUND' } }) }]).run);
  assert.equal(plainError.code, 5);
});

test('REST: a refusal is definite only when its HTTP status is the one its error status maps to; a 3xx or 5xx, or a disagreeing pair, is an unknown outcome', async () => {
  const { runUnary } = await module();
  const call = spec('Commit', commit([write('a', 'held')]), 'rest');
  const answer = async (status, name) => runUnary(call, exchange([{ status, text: JSON.stringify({ error: { message: 'm', status: name } }) }]).run);
  // the pairs production recorded (409 ABORTED, 400 INVALID_ARGUMENT, 404 NOT_FOUND) and the other canonical ones stay definite
  for (const [status, name, code] of [[409, 'ABORTED', 10], [400, 'INVALID_ARGUMENT', 3], [404, 'NOT_FOUND', 5], [400, 'FAILED_PRECONDITION', 9], [409, 'ALREADY_EXISTS', 6], [403, 'PERMISSION_DENIED', 7], [429, 'RESOURCE_EXHAUSTED', 8], [401, 'UNAUTHENTICATED', 16]]) {
    const result = await answer(status, name);
    assert.deepEqual([result.code, result.complete, result.http], [code, true, status], `${status} ${name}`);
  }
  // a 5xx or 3xx that names a definitive status, and a 4xx whose status names another code, are not a refusal
  for (const [status, name] of [[503, 'ABORTED'], [500, 'FAILED_PRECONDITION'], [504, 'NOT_FOUND'], [302, 'ABORTED'], [301, 'INVALID_ARGUMENT'], [409, 'NOT_FOUND'], [404, 'ABORTED'], [400, 'ABORTED'], [429, 'ABORTED']]) {
    const result = await answer(status, name);
    assert.deepEqual([result.code, result.complete, result.http], [2, false, status], `${status} ${name}`);
  }
});

function streamClient(events) {
  const handlers = {};
  const call = { on(name, handler) { handlers[name] = handler; return call; }, cancel() { call.cancelled = true; } };
  return { call, factory: () => ({
    makeServerStreamRequest(path, serialize, _deserialize, request, metadata, options) {
      assert.equal(path, '/google.firestore.v1.Firestore/BatchGetDocuments');
      assert.ok(serialize(request).length > 0); assert.deepEqual(metadata.get('authorization'), ['Bearer owner']); assert.ok(options.deadline instanceof Date);
      queueMicrotask(() => events(handlers));
      return call;
    },
    close() {},
  }) };
}

test('gRPC: a batch read is one server stream whose entries are collected', async () => {
  const { runUnary } = await module();
  const first = { found: { name: name('a'), fields: {}, updateTime: { seconds: '1', nanos: 1 } }, readTime: { seconds: '2', nanos: 0 } };
  const stream = streamClient(handlers => { handlers.data(first); handlers.data({ missing: name('m') }); handlers.end(); });
  const result = await runUnary(spec('BatchGetDocuments', { database, documents: [name('a'), name('m')] }), stream.factory);
  assert.deepEqual([result.code, result.complete, result.transport, result.http], [0, true, 'grpc', null]);
  assert.equal(result.response.responses.length, 2);
});

test('gRPC: an error after entries of a batch that begins a transaction is an unknown outcome', async () => {
  const { runUnary } = await module();
  const starting = { database, documents: [name('a')], newTransaction: { readWrite: {} } };
  for (const code of [10, 9, 8, 3]) {
    const stream = streamClient(handlers => { handlers.data({ transaction: token }); handlers.error({ code, details: 'definitive status after the transaction was handed over' }); });
    const result = await runUnary(spec('BatchGetDocuments', starting), stream.factory);
    assert.deepEqual([result.code, result.complete, result.response], [2, false, null], `code ${code}`);
  }
  // Before any entry the refusal is a plain refusal; and a batch that begins nothing keeps the status it got.
  const early = streamClient(handlers => handlers.error({ code: 10, details: 'contention' }));
  assert.deepEqual([(await runUnary(spec('BatchGetDocuments', starting), early.factory)).code], [10]);
  const plainBatch = streamClient(handlers => { handlers.data({ missing: name('a') }); handlers.error({ code: 10, details: 'late refusal' }); });
  const plain = await runUnary(spec('BatchGetDocuments', { database, documents: [name('a')] }), plainBatch.factory);
  assert.deepEqual([plain.code, plain.complete], [10, true]);
});

test('gRPC: a stream that fails or overflows is an answer, not a success', async () => {
  const { runUnary } = await module();
  const failing = streamClient(handlers => { handlers.data({ missing: name('a') }); handlers.error({ code: 14, details: 'owner unavailable' }); });
  const failed = await runUnary(spec('BatchGetDocuments', { database, documents: [name('a')] }), failing.factory);
  assert.deepEqual([failed.code, failed.complete, failed.details, failed.response], [14, false, '[credential-redacted] unavailable', null]);
  const codeless = streamClient(handlers => handlers.error({ details: 'no status code' }));
  const unknown = await runUnary(spec('BatchGetDocuments', { database, documents: [name('a')] }), codeless.factory);
  assert.deepEqual([unknown.code, unknown.complete], [2, false], 'a stream error without a code is an unknown outcome');
  const refused = streamClient(handlers => handlers.error({ code: 10, details: 'contention' }));
  const aborted = await runUnary(spec('BatchGetDocuments', { database, documents: [name('a')] }), refused.factory);
  assert.deepEqual([aborted.code, aborted.complete], [10, true]);
  const flood = streamClient(handlers => { for (let index = 0; index < 20; index += 1) handlers.data({ missing: name('a') }); handlers.end(); });
  const over = await runUnary(spec('BatchGetDocuments', { database, documents: [name('a')] }), flood.factory);
  assert.deepEqual([over.code, over.complete, over.response], [2, false, null]);
  assert.equal(flood.call.cancelled, true);
});

const at = { seconds: '1788004860', nanos: 123456 };

for (const transport of ['rest', 'grpc']) {
  test(`${transport}: a read time or an embedded new transaction stands in for a transaction, never beside one`, async () => {
    const { validateCall } = await module();
    validateCall(spec('GetDocument', { name: name('a'), readTime: at }, transport));
    validateCall(spec('BatchGetDocuments', { database, documents: [name('a')], readTime: at }, transport));
    validateCall(spec('BatchGetDocuments', { database, documents: [name('a')], newTransaction: { readWrite: {} } }, transport));
    validateCall(spec('BatchGetDocuments', { database, documents: [name('a')], newTransaction: { readOnly: {} } }, transport));
    validateCall(spec('BeginTransaction', { database, options: { readOnly: { readTime: at } } }, transport));
    for (const [method, request] of [
      ['GetDocument', { name: name('a'), readTime: at, transaction: token }], ['GetDocument', { name: name('a'), readTime: '2026-09-30T00:00:00Z' }], ['GetDocument', { name: name('a'), readTime: { seconds: 5, nanos: 0 } }],
      ['BatchGetDocuments', { database, documents: [name('a')], readTime: '2026-09-30T00:00:00Z' }], ['BatchGetDocuments', { database, documents: [name('a')], readTime: { seconds: 5, nanos: 0 } }],
      ['BatchGetDocuments', { database, documents: [name('a')], readTime: at, transaction: token }], ['BatchGetDocuments', { database, documents: [name('a')], newTransaction: { readWrite: {} }, readTime: at }],
      ['BatchGetDocuments', { database, documents: [name('a')], newTransaction: { readWrite: {} }, transaction: token }], ['BatchGetDocuments', { database, documents: [name('a')], newTransaction: {} }],
      ['BatchGetDocuments', { database, documents: [name('a')], newTransaction: { readWrite: { retryTransaction: token } } }], ['BatchGetDocuments', { database, documents: [name('a')], newTransaction: { readOnly: {}, readWrite: {} } }],
      ['BatchGetDocuments', { database, documents: [name('a')], newTransaction: { other: {} } }],
      ['BeginTransaction', { database, options: { readWrite: { readTime: at } } }], ['BeginTransaction', { database, options: { readOnly: { readTime: { seconds: '1', nanos: -1 } } } }],
    ]) assert.throws(() => validateCall(spec(method, request, transport)), undefined, `${method} ${JSON.stringify(request).slice(0, 70)}`);
  });
}

test('REST spells a read time as RFC 3339 with nine digits, wherever the request carries one', async () => {
  const { restRequest, rfc3339 } = await module();
  assert.equal(rfc3339(at), '2026-08-29T12:01:00.000123456Z');
  assert.equal(rfc3339({ seconds: '0', nanos: 5 }), '1970-01-01T00:00:00.000000005Z');
  assert.equal(restRequest(spec('GetDocument', { name: name('a'), readTime: at }, 'rest')).path, `/v1/${name('a')}?readTime=${encodeURIComponent(rfc3339(at))}`);
  assert.deepEqual(restRequest(spec('BatchGetDocuments', { database, documents: [name('a')], readTime: at }, 'rest')).body, { documents: [name('a')], readTime: rfc3339(at) });
  assert.deepEqual(restRequest(spec('BatchGetDocuments', { database, documents: [name('a')], newTransaction: { readOnly: {} } }, 'rest')).body, { documents: [name('a')], newTransaction: { readOnly: {} } });
  assert.deepEqual(restRequest(spec('BeginTransaction', { database, options: { readOnly: { readTime: at } } }, 'rest')).body, { options: { readOnly: { readTime: rfc3339(at) } } });
  assert.deepEqual(restRequest(spec('BeginTransaction', { database, options: { readOnly: {} } }, 'rest')).body, { options: { readOnly: {} } });
});

test('production is the sandbox project alone, and a local target must be a demo project on the loopback', async () => {
  const { validateCall } = await module();
  validateCall({ ...spec('GetDocument', { name: 'projects/fireemu-oracle-sbx/databases/(default)/documents/oracle/' + nonce + '/txn-toy/a' }), target: { kind: 'production' }, projectId: 'fireemu-oracle-sbx', bearer: 'ya29.token-value_1' });
  assert.throws(() => validateCall({ ...spec('GetDocument', { name: name('a') }), target: { kind: 'production' }, bearer: 'ya29.token-value_1' }));
  assert.throws(() => validateCall({ ...spec('GetDocument', { name: name('a') }), bearer: 'not-owner' }));
});

test('production admits the two sandbox projects only, each with its own documents', async () => {
  const { validateCall, SANDBOX_PROJECTS } = await module();
  assert.deepEqual([...SANDBOX_PROJECTS], ['fireemu-oracle-sbx', 'fireemu-oracle-txn']);
  const production = (projectId, documentProject = projectId, transport = 'rest') => ({ ...spec('GetDocument', { name: `projects/${documentProject}/databases/(default)/documents/oracle/${nonce}/txn-toy/a` }, transport), target: { kind: 'production' }, projectId, bearer: 'ya29.token-value_1' });
  for (const transport of ['rest', 'grpc']) for (const projectId of SANDBOX_PROJECTS) validateCall(production(projectId, projectId, transport));
  for (const projectId of ['fireemu-oracle-idp', 'fireemu-oracle-query', 'fireemu-35fe6', 'demo-toy', 'fireemu-oracle-txn2', '']) assert.throws(() => validateCall(production(projectId)), undefined, projectId);
  // a call for one project cannot name the other's documents
  assert.throws(() => validateCall(production('fireemu-oracle-txn', 'fireemu-oracle-sbx')));
  assert.throws(() => validateCall(production('fireemu-oracle-sbx', 'fireemu-oracle-txn')));
});

test('a native version delete is admitted over gRPC only', async () => {
  const { validateCall } = await module();
  const request = { name: name('a'), currentDocument: { updateTime: { seconds: '1788004860', nanos: 123 } } };
  validateCall(spec('DeleteDocument', request, 'grpc'));
  assert.throws(() => validateCall(spec('DeleteDocument', request, 'rest')));
  for (const currentDocument of [{}, { exists: true }, { updateTime: { seconds: '1788004860', nanos: -1 } }]) assert.throws(() => validateCall(spec('DeleteDocument', { name: name('a'), currentDocument }, 'grpc')));
  assert.throws(() => validateCall(spec('ListDocuments', { name: name('a') }, 'grpc')));
});

test('a 90 second deadline is admitted for an outside writer alone and nothing longer', async () => {
  const { validateCall } = await module();
  for (const transport of ['rest', 'grpc']) {
    validateCall(spec('Commit', commit([write('a', 'moved')], false), transport, { deadlineMs: 30000 }));
    validateCall(spec('Commit', commit([write('a', 'moved')], false), transport, { deadlineMs: 90000 }));
    assert.throws(() => validateCall(spec('Commit', commit([write('a', 'moved')], false), transport, { deadlineMs: 90001 })));
    // A transactional commit and every other call stop at 10 s.
    assert.throws(() => validateCall(spec('Commit', commit([write('a', 'moved')], true), transport, { deadlineMs: 30000 })));
    assert.throws(() => validateCall(spec('Rollback', { database, transaction: token }, transport, { deadlineMs: 30000 })));
    assert.throws(() => validateCall(spec('GetDocument', { name: name('a') }, transport, { deadlineMs: 10001 })));
    validateCall(spec('Rollback', { database, transaction: token }, transport, { deadlineMs: 10000 }));
  }
});

test('gRPC: one unary attempt disables retries and retains the raw native refusal', async () => {
  const { runUnary } = await module();
  let calls = 0; let closes = 0;
  const factory = (_endpoint, _credentials, options) => {
    assert.equal(options['grpc.enable_retries'], 0);
    assert.equal(options['grpc.max_send_message_length'], 16384);
    assert.equal(options['grpc.max_receive_message_length'], 65536);
    return {
      makeUnaryRequest(path, serialize, _deserialize, request, metadata, callOptions, callback) {
        calls += 1;
        assert.equal(path, '/google.firestore.v1.Firestore/Commit');
        assert.ok(serialize(request).length > 0);
        assert.deepEqual(metadata.get('authorization'), ['Bearer owner']);
        assert.ok(callOptions.deadline instanceof Date);
        queueMicrotask(() => callback({ code: 10, details: 'native refusal' }));
        return { cancel() {} };
      },
      close() { closes += 1; },
    };
  };
  const result = await runUnary(spec('Commit', commit([write('a', 'held')])), factory);
  assert.deepEqual(result, { kind: 'txn-program-receipt-v1', transport: 'grpc', complete: true, code: 10, details: 'native refusal', response: null, http: null, dispatchedRequests: 1 });
  assert.equal(calls, 1); assert.equal(closes, 1);
});

test('gRPC: unknown results stay incomplete and credential text is redacted', async () => {
  const { runUnary } = await module();
  const factory = () => ({ makeUnaryRequest(_path, _serialize, _deserialize, _request, _metadata, _options, callback) {
    queueMicrotask(() => callback({ code: 14, details: 'owner was unavailable' })); return { cancel() {} };
  }, close() {} });
  const result = await runUnary(spec('Rollback', { database, transaction: token }), factory);
  assert.equal(result.code, 14); assert.equal(result.complete, false);
  assert.equal(result.details, '[credential-redacted] was unavailable');
});

test('a call that fails validation never reaches even the injected network', async () => {
  const { runUnary } = await module();
  let touched = 0;
  await assert.rejects(runUnary(spec('BeginTransaction', { database, options: { readWrite: { retryTransaction: token } } }), () => { touched += 1; throw new Error('must not dispatch'); }));
  await assert.rejects(runUnary(spec('DeleteDocument', { name: name('a'), currentDocument: { updateTime: { seconds: '1788004860', nanos: 1 } } }, 'rest'), () => { touched += 1; }));
  assert.equal(touched, 0);
});

test('injection is a local-target convenience only', async () => {
  const { runUnary } = await module();
  let touched = 0;
  const production = transport => ({ ...spec('GetDocument', { name: 'projects/fireemu-oracle-sbx/databases/(default)/documents/oracle/' + nonce + '/txn-toy/a' }, transport), target: { kind: 'production' }, projectId: 'fireemu-oracle-sbx', bearer: 'ya29.token-value_1' });
  for (const transport of ['rest', 'grpc']) {
    await assert.rejects(runUnary(production(transport), () => { touched += 1; return {}; }), /injection requires a local target/);
  }
  await assert.rejects(runUnary(spec('GetDocument', { name: name('a') }), 'not a function'), /injection requires a local target/);
  assert.equal(touched, 0);
});

test('REST headers carry the credential, and the user project only in production', async () => {
  const { restHeaders } = await module();
  assert.deepEqual(restHeaders(spec('GetDocument', { name: name('a') }, 'rest')), { authorization: 'Bearer owner', accept: 'application/json' });
  for (const projectId of ['fireemu-oracle-sbx', 'fireemu-oracle-txn']) {
    const production = { ...spec('GetDocument', { name: name('a') }, 'rest'), target: { kind: 'production' }, projectId, bearer: 'ya29.token' };
    assert.deepEqual(restHeaders(production), { authorization: 'Bearer ya29.token', accept: 'application/json', 'x-goog-user-project': projectId });
  }
});

test('gRPC metadata carries the credential, and the user project only in production', async () => {
  const { grpcMetadata } = await module();
  const local = grpcMetadata(spec('GetDocument', { name: name('a') }, 'grpc'));
  assert.deepEqual(local.get('authorization'), ['Bearer owner']);
  assert.deepEqual(local.get('x-goog-user-project'), []);
  for (const projectId of ['fireemu-oracle-sbx', 'fireemu-oracle-txn']) {
    const production = { ...spec('GetDocument', { name: name('a') }, 'grpc'), target: { kind: 'production' }, projectId, bearer: 'ya29.token' };
    const metadata = grpcMetadata(production);
    assert.deepEqual(metadata.get('authorization'), ['Bearer ya29.token']);
    assert.deepEqual(metadata.get('x-goog-user-project'), [projectId]);
    assert.deepEqual(metadata.get('x-goog-request-params'), [`name=${encodeURIComponent(production.request.name)}`]);
  }
});

test('the real REST exchange refuses an answer over the size cap', async () => {
  const { httpExchange, restRequest } = await module();
  const http = await import('node:http');
  const server = http.createServer((_req, res) => { res.setHeader('content-type', 'application/json'); res.end(JSON.stringify({ blob: 'x'.repeat(70000) })); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const call = spec('GetDocument', { name: name('a') }, 'rest', { target: { kind: 'local', host: '127.0.0.1', port: server.address().port } });
    const answer = await httpExchange(call, restRequest(call), new AbortController().signal);
    assert.equal(answer.oversize, true); assert.equal(answer.text, null); assert.equal(answer.status, 200);
  } finally { server.close(); }
});

function exchange(answers) {
  const seen = [];
  const run = async (spec_, prepared, signal) => {
    seen.push({ prepared, signal });
    const answer = answers.shift();
    if (answer instanceof Error) throw answer;
    return answer;
  };
  return { run, seen };
}

test('REST: each logical call becomes one fixed request', async () => {
  const { restRequest } = await module();
  assert.deepEqual(restRequest(spec('BeginTransaction', { database, options: { readWrite: {} } }, 'rest')), { method: 'POST', path: `/v1/${database}/documents:beginTransaction`, body: { options: { readWrite: {} } } });
  assert.deepEqual(restRequest(spec('Rollback', { database, transaction: token }, 'rest')), { method: 'POST', path: `/v1/${database}/documents:rollback`, body: { transaction: token } });
  const writes = [write('a', 'held'), write('m', 'held')];
  assert.deepEqual(restRequest(spec('Commit', commit(writes), 'rest')), { method: 'POST', path: `/v1/${database}/documents:commit`, body: { writes, transaction: token } });
  assert.deepEqual(restRequest(spec('Commit', commit(writes, false), 'rest')).body, { writes });
  assert.deepEqual(restRequest(spec('GetDocument', { name: name('a') }, 'rest')), { method: 'GET', path: `/v1/${name('a')}`, body: undefined });
  const withToken = restRequest(spec('GetDocument', { name: name('a'), transaction: 'ab+/=' }, 'rest'));
  assert.equal(withToken.path, `/v1/${name('a')}?transaction=ab%2B%2F%3D`);
});

test('REST: a 2xx answer is a success carrying its body and its HTTP status', async () => {
  const { runUnary } = await module();
  const wire = exchange([{ status: 200, text: JSON.stringify({ transaction: token }) }]);
  const result = await runUnary(spec('BeginTransaction', { database, options: { readWrite: {} } }, 'rest'), wire.run);
  assert.deepEqual(result, { kind: 'txn-program-receipt-v1', transport: 'rest', complete: true, code: 0, details: '', response: { transaction: token }, http: 200, dispatchedRequests: 1 });
  assert.equal(wire.seen.length, 1);
});

test('REST: an error answer maps its status name to the gRPC code and keeps the message', async () => {
  const { runUnary } = await module();
  for (const [status, http, code, complete] of [['ABORTED', 409, 10, true], ['FAILED_PRECONDITION', 400, 9, true], ['NOT_FOUND', 404, 5, true], ['INVALID_ARGUMENT', 400, 3, true], ['PERMISSION_DENIED', 403, 7, true], ['DEADLINE_EXCEEDED', 504, 4, false], ['UNAVAILABLE', 503, 14, false], ['INTERNAL', 500, 13, false], ['UNKNOWN', 500, 2, false]]) {
    const wire = exchange([{ status: http, text: JSON.stringify({ error: { code: http, message: `refused ${status}`, status } }) }]);
    const result = await runUnary(spec('Commit', commit([write('a', 'held')]), 'rest'), wire.run);
    assert.deepEqual([result.code, result.complete, result.http, result.details, result.response], [code, complete, http, `refused ${status}`, null], status);
  }
});

test('REST: an answer that cannot be read is an unknown outcome, never a refusal', async () => {
  const { runUnary } = await module();
  const cases = [
    { status: 200, text: 'not json' }, { status: 502, text: '<html>bad gateway</html>' }, { status: 200, text: '[]' },
    { status: 409, text: JSON.stringify({ error: { message: 'no status' } }) }, { status: 409, text: JSON.stringify({ error: { status: 'MADE_UP', message: 'x' } }) },
    { status: 200, text: null, oversize: true },
  ];
  for (const answer of cases) {
    const result = await runUnary(spec('Rollback', { database, transaction: token }, 'rest'), exchange([answer]).run);
    assert.equal(result.complete, false, JSON.stringify(answer));
    assert.ok([2].includes(result.code), JSON.stringify(answer));
  }
});

test('REST: a non-2xx answer whose status name is OK is never a success', async () => {
  const { runUnary } = await module();
  const wire = exchange([{ status: 500, text: JSON.stringify({ error: { message: 'odd', status: 'OK' } }) }]);
  const result = await runUnary(spec('Commit', commit([write('a', 'held')]), 'rest'), wire.run);
  assert.deepEqual([result.code, result.complete, result.http], [2, false, 500]);
});

test('REST: a network failure is UNAVAILABLE and a slow answer is a deadline, both incomplete', async () => {
  const { runUnary } = await module();
  const failed = await runUnary(spec('Rollback', { database, transaction: token }, 'rest'), exchange([new Error('ECONNRESET')]).run);
  assert.deepEqual([failed.code, failed.complete, failed.http], [14, false, null]);
  let aborted = false;
  const slow = async (_spec, _prepared, signal) => { signal.addEventListener('abort', () => { aborted = true; }); return new Promise(() => {}); };
  const late = await runUnary({ ...spec('Rollback', { database, transaction: token }, 'rest'), deadlineMs: 1 }, slow);
  assert.deepEqual([late.code, late.complete, late.details, aborted], [4, false, 'worker deadline exceeded', true]);
});

test('REST: credential text in an answer is redacted and the receipt stays bounded', async () => {
  const { runUnary } = await module();
  const wire = exchange([{ status: 403, text: JSON.stringify({ error: { message: 'owner is denied', status: 'PERMISSION_DENIED' } }) }]);
  const result = await runUnary(spec('GetDocument', { name: name('a') }, 'rest'), wire.run);
  assert.equal(result.details, '[credential-redacted] is denied');
  const big = await runUnary(spec('GetDocument', { name: name('a') }, 'rest'), exchange([{ status: 200, text: JSON.stringify({ blob: 'x'.repeat(70000) }) }]).run);
  assert.equal(big.complete, false); assert.equal(big.response, null);
});

test('the real REST exchange makes one bounded request with the credential and no user project on a local target', async () => {
  const { httpExchange, restRequest } = await module();
  const http = await import('node:http');
  let seen;
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', chunk => chunks.push(chunk));
    req.on('end', () => { seen = { method: req.method, url: req.url, headers: req.headers, body: Buffer.concat(chunks).toString() }; res.setHeader('content-type', 'application/json'); res.end(JSON.stringify({ transaction: token })); });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const target = { kind: 'local', host: '127.0.0.1', port: server.address().port };
    const call = spec('BeginTransaction', { database, options: { readWrite: {} } }, 'rest', { target });
    const answer = await httpExchange(call, restRequest(call), new AbortController().signal);
    assert.deepEqual(answer, { status: 200, text: JSON.stringify({ transaction: token }) });
    assert.equal(seen.method, 'POST'); assert.equal(seen.url, `/v1/${database}/documents:beginTransaction`);
    assert.equal(seen.headers.authorization, 'Bearer owner'); assert.equal(seen.headers['x-goog-user-project'], undefined);
    assert.equal(seen.body, JSON.stringify({ options: { readWrite: {} } }));
  } finally { server.close(); }
});

const MALFORMED = 'not base64!';
const UNKNOWN = 'ZmlyZWVtdS11bmlzc3VlZC10eG4tdG9rZW4=';

for (const transport of ['rest', 'grpc']) {
  test(`${transport}: an unknown (well-formed, never issued) token is admitted on a read, a batch read, a commit and a rollback`, async () => {
    const { validateCall } = await module();
    validateCall(spec('GetDocument', { name: name('a'), transaction: UNKNOWN }, transport));
    validateCall(spec('BatchGetDocuments', { database, documents: [name('a')], transaction: UNKNOWN }, transport));
    validateCall(spec('Commit', { database, writes: [write('a', 'held')], transaction: UNKNOWN }, transport));
    validateCall(spec('Rollback', { database, transaction: UNKNOWN }, transport));
  });

  test(`${transport}: a token that is neither issued-looking nor one of the two declared literals is still refused`, async () => {
    const { validateCall } = await module();
    for (const bad of ['not canonical', 'AAAA=', '', 'not base64', MALFORMED + ' ']) {
      assert.throws(() => validateCall(spec('GetDocument', { name: name('a'), transaction: bad }, transport)), undefined, JSON.stringify(bad));
    }
  });
}

test('rest: the malformed literal is admitted on every call that names a token', async () => {
  const { validateCall } = await module();
  validateCall(spec('GetDocument', { name: name('a'), transaction: MALFORMED }, 'rest'));
  validateCall(spec('BatchGetDocuments', { database, documents: [name('a')], transaction: MALFORMED }, 'rest'));
  validateCall(spec('Commit', { database, writes: [write('a', 'held')], transaction: MALFORMED }, 'rest'));
  validateCall(spec('Rollback', { database, transaction: MALFORMED }, 'rest'));
});

test('grpc: the malformed literal is refused, a native client cannot send bytes that do not decode', async () => {
  const { validateCall } = await module();
  assert.throws(() => validateCall(spec('GetDocument', { name: name('a'), transaction: MALFORMED }, 'grpc')));
  assert.throws(() => validateCall(spec('Rollback', { database, transaction: MALFORMED }, 'grpc')));
});

test('rest: the malformed literal travels in the request body as the plain string', async () => {
  const { restRequest } = await module();
  const prepared = restRequest(spec('Rollback', { database, transaction: MALFORMED }, 'rest'));
  assert.equal(prepared.body.transaction, MALFORMED);
  const read = restRequest(spec('GetDocument', { name: name('a'), transaction: MALFORMED }, 'rest'));
  assert.ok(read.path.includes(encodeURIComponent(MALFORMED)));
});
