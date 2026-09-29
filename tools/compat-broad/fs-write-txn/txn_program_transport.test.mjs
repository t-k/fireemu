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
    for (const body of [commit([write('a', 'gone')]), wrongDocument, otherProgram, otherRun, wrongRole, commit([write('a', 'held'), write('a', 'moved')]), commit([]), commit([write('a', 'held'), write('m', 'held'), write('a', 'moved')])]) assert.throws(() => validateCall(spec('Commit', body, transport)));
    for (const change of ['owner', 'nonce', 'extra', 'precondition']) {
      const body = commit([write('a', 'held')]);
      if (change === 'owner' || change === 'nonce') body.writes[0].update.fields[change].stringValue = 'foreign';
      else if (change === 'extra') body.writes[0].update.fields.extra = { stringValue: 'foreign' };
      else delete body.writes[0].currentDocument;
      assert.throws(() => validateCall(spec('Commit', body, transport)), undefined, change);
    }
    assert.throws(() => validateCall(spec('GetDocument', { name: name('a').replace(nonce, 'c'.repeat(32)) }, transport)));
  });

  test(`${transport}: BeginTransaction is fresh and refuses retry or another mode`, async () => {
    const { validateCall } = await module();
    for (const options of [{ readWrite: { retryTransaction: token } }, { readOnly: {} }, { readWrite: {}, readOnly: {} }, { readWrite: { extra: true } }]) assert.throws(() => validateCall(spec('BeginTransaction', { database, options }, transport)));
  });

  test(`${transport}: protocol, project, token, credential and deadline changes are rejected`, async () => {
    const { validateCall } = await module();
    const base = spec('GetDocument', { name: name('a') }, transport);
    for (const changes of [
      { kind: 'txn-boundary-grpc-call-v1' }, { projectId: 'fireemu-oracle-idp' }, { transport: 'http' },
      { target: { kind: 'local', host: 'localhost', port: 12345 } }, { target: { kind: 'production' } },
      { request: { name: name('a'), transaction: 'bad-token' } }, { request: { name: name('a'), extra: true } },
      { bearer: 'owner\nAuthorization: injected' }, { deadlineMs: 0 }, { deadlineMs: 30001 }, { deadlineMs: 1.5 },
      { slug: 'Txn Toy' }, { documents: ['a', 'a'] }, { documents: [] }, { states: [] }, { states: ['UPPER'] }, { extra: true },
    ]) assert.throws(() => validateCall({ ...base, ...changes }), undefined, JSON.stringify(Object.keys(changes)));
  });
}

test('production is the sandbox project alone, and a local target must be a demo project on the loopback', async () => {
  const { validateCall } = await module();
  validateCall({ ...spec('GetDocument', { name: 'projects/fireemu-oracle-sbx/databases/(default)/documents/oracle/' + nonce + '/txn-toy/a' }), target: { kind: 'production' }, projectId: 'fireemu-oracle-sbx', bearer: 'ya29.token-value_1' });
  assert.throws(() => validateCall({ ...spec('GetDocument', { name: name('a') }), target: { kind: 'production' }, bearer: 'ya29.token-value_1' }));
  assert.throws(() => validateCall({ ...spec('GetDocument', { name: name('a') }), bearer: 'not-owner' }));
});

test('a native version delete is admitted over gRPC only', async () => {
  const { validateCall } = await module();
  const request = { name: name('a'), currentDocument: { updateTime: { seconds: '1788004860', nanos: 123 } } };
  validateCall(spec('DeleteDocument', request, 'grpc'));
  assert.throws(() => validateCall(spec('DeleteDocument', request, 'rest')));
  for (const currentDocument of [{}, { exists: true }, { updateTime: { seconds: '1788004860', nanos: -1 } }]) assert.throws(() => validateCall(spec('DeleteDocument', { name: name('a'), currentDocument }, 'grpc')));
  assert.throws(() => validateCall(spec('ListDocuments', { name: name('a') }, 'grpc')));
});

test('a 30 second writer deadline is admitted and nothing longer', async () => {
  const { validateCall } = await module();
  validateCall(spec('Commit', commit([write('a', 'moved')], false), 'rest', { deadlineMs: 30000 }));
  assert.throws(() => validateCall(spec('Commit', commit([write('a', 'moved')], false), 'rest', { deadlineMs: 30001 })));
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
  await assert.rejects(runUnary({ ...spec('GetDocument', { name: 'projects/fireemu-oracle-sbx/databases/(default)/documents/oracle/' + nonce + '/txn-toy/a' }), target: { kind: 'production' }, projectId: 'fireemu-oracle-sbx', bearer: 'ya29.token-value_1' }, () => ({})));
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
