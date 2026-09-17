import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';

const requireSdk = createRequire(new URL('../../sdk-smoke/package.json', import.meta.url));
// Resolve the installed SDK from sdk-smoke's package boundary, then load its
// generated gRPC client by absolute path because the package does not export
// the generated v1 subpath.
const firestoreEntry = requireSdk.resolve('@google-cloud/firestore');
const { FirestoreClient } = requireSdk(join(dirname(firestoreEntry), 'v1/index.js'));
const grpc = requireSdk(requireSdk.resolve('@grpc/grpc-js', { paths: [dirname(firestoreEntry)] }));

const LOOPBACK_HOSTS = new Set(['127.0.0.1', '::1', 'localhost']);
const OPERATIONS = new Set(['BeginTransaction', 'GetDocument', 'Rollback']);

const fail = (message, code = 'invalid_options') => {
  const error = new TypeError(message);
  error.code = code;
  return error;
};

const assertInteger = (value, name, minimum, maximum) => {
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    throw fail(`${name} must be an integer between ${minimum} and ${maximum}`);
  }
};

const byteLength = value => {
  const encoded = JSON.stringify(value);
  if (encoded === undefined) throw fail('stream value is not serializable', 'message_limit');
  return Buffer.byteLength(encoded);
};

export const validateTransportOptions = options => {
  if (!options || typeof options !== 'object') throw fail('options are required');
  const { host, port, projectId, documentPrefix } = options;
  if (typeof host !== 'string' || !LOOPBACK_HOSTS.has(host)) {
    throw fail('host must be an explicit loopback address');
  }
  assertInteger(port, 'port', 1, 65535);
  if (typeof projectId !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9-]{4,62}$/.test(projectId)) {
    throw fail('projectId is invalid');
  }
  if (typeof documentPrefix !== 'string' || documentPrefix.length === 0 || documentPrefix.startsWith('/')) {
    throw fail('documentPrefix must be a relative document path');
  }
  const deadlineMs = options.deadlineMs ?? 10_000;
  const maxFrames = options.maxFrames ?? 32;
  const maxMessageBytes = options.maxMessageBytes ?? 1_048_576;
  assertInteger(deadlineMs, 'deadlineMs', 1, 120_000);
  assertInteger(maxFrames, 'maxFrames', 1, 256);
  assertInteger(maxMessageBytes, 'maxMessageBytes', 1, 8 * 1024 * 1024);
  if (options.metadata !== undefined && (typeof options.metadata !== 'object' || options.metadata === null || Array.isArray(options.metadata))) {
    throw fail('metadata must be a plain object');
  }
  for (const [key, value] of Object.entries(options.metadata ?? {})) {
    if (!/^[a-z0-9-]+$/i.test(key) || !(typeof value === 'string' || (Array.isArray(value) && value.every(item => typeof item === 'string')))) {
      throw fail('metadata must contain string header values');
    }
  }
  return { host, port, projectId, documentPrefix, deadlineMs, maxFrames, maxMessageBytes, metadata: options.metadata ?? {} };
};

export const databaseName = projectId => `projects/${projectId}/databases/(default)`;

export const documentName = (projectId, path) => `${databaseName(projectId)}/documents/${path}`;

export const buildUnaryRequest = (operation, options, input = {}) => {
  const validated = validateTransportOptions(options);
  if (!OPERATIONS.has(operation)) throw fail(`unsupported unary operation: ${operation}`);
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw fail('unary input must be an object');
  const protectedFields = operation === 'GetDocument'
    ? ['name', 'database', 'writes', 'streamToken']
    : ['database', 'name', 'path', 'writes', 'streamToken'];
  for (const field of protectedFields) {
    if (Object.hasOwn(input, field)) throw fail(`${field} cannot be supplied for ${operation}`);
  }
  if (operation === 'BeginTransaction') return { database: databaseName(validated.projectId), ...input };
  if (operation === 'Rollback') return { database: databaseName(validated.projectId), ...input };
  const path = input.path;
  if (typeof path !== 'string' || !path.startsWith(`${validated.documentPrefix}/`)) {
    throw fail('document path is outside the owned prefix');
  }
  const { path: _path, ...rest } = input;
  return { name: documentName(validated.projectId, path), ...rest };
};

const requestTargets = request => {
  const targets = [];
  for (const write of request?.writes ?? []) {
    for (const value of [write.update?.name, write.delete, write.transform?.document]) {
      if (typeof value === 'string') targets.push(value);
    }
  }
  return targets;
};

const assertRequest = (request, options) => {
  if (!request || typeof request !== 'object') throw fail('write request must be an object');
  if (Object.hasOwn(request, 'database') && request.database !== databaseName(options.projectId)) {
    throw fail('write database is transport-owned');
  }
  if (byteLength(request) > options.maxMessageBytes) throw fail('write request exceeds maxMessageBytes', 'message_limit');
  const prefix = documentName(options.projectId, options.documentPrefix);
  for (const target of requestTargets(request)) {
    if (!target.startsWith(`${prefix}/`) && target !== prefix) throw fail('write target is outside the owned prefix');
  }
};

const clientFor = options => new FirestoreClient({
  servicePath: options.host,
  port: options.port,
  projectId: options.projectId,
  sslCreds: grpc.credentials.createInsecure(),
  fallback: false,
});

const grpcCallName = operation => operation === 'BeginTransaction' ? 'beginTransaction' : operation === 'GetDocument' ? 'getDocument' : 'rollback';

const statusReceipt = (operation, request, error) => ({
  kind: 'grpc_status',
  complete: true,
  operation,
  request,
  status: { code: error?.code, details: error?.details },
  error,
});

export const runUnary = async (operation, options, input = {}) => {
  const validated = validateTransportOptions(options);
  const request = buildUnaryRequest(operation, validated, input);
  const client = clientFor(validated);
  let timer;
  try {
    const call = client[grpcCallName(operation)](request, {
      deadline: new Date(Date.now() + validated.deadlineMs),
      otherArgs: { headers: { ...validated.metadata } },
    });
    const timeout = new Promise((_, reject) => {
      timer = setTimeout(() => reject(Object.assign(new Error('client deadline exceeded'), { code: 'client_deadline' })), validated.deadlineMs);
    });
    const result = await Promise.race([call, timeout]);
    return { kind: 'grpc_status', complete: true, operation, request, response: result[0] ?? result };
  } catch (error) {
    if (error?.code === 'client_deadline') return { kind: 'client_deadline', complete: false, operation, request, error };
    if (typeof error?.code === 'number') return statusReceipt(operation, request, error);
    return { kind: 'incomplete_stream', complete: false, operation, request, error };
  } finally {
    clearTimeout(timer);
    client.close();
  }
};

export const listWriteFrames = (requests, response) => {
  if (!Array.isArray(requests)) throw fail('write frames must be an array');
  const streamToken = response?.streamToken;
  return requests.map(request => {
    if (!request || typeof request !== 'object' || Array.isArray(request)) throw fail('write request must be an object');
    if (Object.hasOwn(request, 'database')) throw fail('database is transport-owned');
    if (Object.hasOwn(request, 'streamToken')) throw fail('streamToken is transport-owned');
    return streamToken === undefined ? { ...request } : { ...request, streamToken };
  });
};

export const runWrite = async (requests, options) => {
  const validated = validateTransportOptions(options);
  const client = clientFor(validated);
  const stream = client.write({
    deadline: new Date(Date.now() + validated.deadlineMs),
    otherArgs: { headers: { ...validated.metadata } },
  });
  const events = [];
  let frameCount = 0;
  let status;
  let terminalError;
  let sawEnd = false;
  let sawClose = false;
  let settled = false;
  let timer;
  let terminalGraceTimer;
  const responseQueue = [];
  const responseWaiters = [];
  let settleTerminal;
  const terminal = new Promise(resolve => { settleTerminal = resolve; });
  const push = (event, value) => {
    if (byteLength(value) > validated.maxMessageBytes) throw fail('stream event exceeds maxMessageBytes', 'message_limit');
    events.push({ type: event, value });
  };
  const finish = result => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      clearTimeout(terminalGraceTimer);
      settleTerminal({ ...result, events: events.slice() });
  };
  const maybeFinish = () => {
    if (settled || !(sawEnd || sawClose)) return;
    if (status) finish({ kind: 'grpc_status', complete: true, status });
    else if (terminalError) finish({ kind: 'incomplete_stream', complete: false, error: terminalError });
    else finish({ kind: 'incomplete_stream', complete: false });
  };
  const rejectWaiters = error => {
    while (responseWaiters.length > 0) responseWaiters.shift().reject(error);
  };
  const waitResponse = () => new Promise((resolve, reject) => {
    if (responseQueue.length > 0) resolve(responseQueue.shift());
    else if (terminalError) reject(terminalError);
    else responseWaiters.push({ resolve, reject });
  });
  const sendFrame = request => {
    if (++frameCount > validated.maxFrames) throw fail('stream exceeds maxFrames', 'frame_limit');
    assertRequest(request, validated);
    stream.write(request);
  };
  stream.on('data', response => {
    try {
      push('data', response);
      if (++frameCount > validated.maxFrames) {
        stream.destroy(fail('stream exceeds maxFrames', 'frame_limit'));
        return;
      }
      if (responseWaiters.length > 0) responseWaiters.shift().resolve(response);
      else responseQueue.push(response);
    } catch (error) { stream.destroy(error); }
  });
  stream.on('status', value => {
    status = value;
    try { push('status', value); } catch (error) { stream.destroy(error); }
    maybeFinish();
  });
  stream.on('error', error => {
    terminalError = error;
    try { push('error', error); } catch { /* retain the typed error in the receipt */ }
    rejectWaiters(error);
    // grpc-js may emit error before status and close; defer classification until
    // the terminal status/close pair has had a chance to arrive.
    terminalGraceTimer = setTimeout(maybeFinish, 100);
    maybeFinish();
  });
  stream.on('end', () => {
    sawEnd = true;
    try { push('end', { status }); } catch { /* terminal event remains bounded */ }
    maybeFinish();
  });
  stream.on('close', () => {
    sawClose = true;
    try { push('close', { status }); } catch { /* terminal event remains bounded */ }
    maybeFinish();
  });
  timer = setTimeout(() => {
    const error = Object.assign(new Error('client deadline exceeded'), { code: 'client_deadline' });
    terminalError = error;
    rejectWaiters(error);
    stream.destroy(error);
    finish({ kind: 'client_deadline', complete: false, error, status });
  }, validated.deadlineMs);
  try {
    sendFrame({ database: databaseName(validated.projectId) });
    let response = await waitResponse();
    for await (const request of requests) {
      const frame = listWriteFrames([request], response)[0];
      sendFrame(frame);
      response = await waitResponse();
    }
    stream.end();
  } catch (error) {
    if (!terminalError) {
      terminalError = error;
      rejectWaiters(error);
      stream.destroy(error);
    }
  }
  const receipt = await terminal;
  client.close();
  return receipt;
};
