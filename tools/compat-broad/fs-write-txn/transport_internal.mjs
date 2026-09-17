import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';

const requireSdk = createRequire(new URL('../../sdk-smoke/package.json', import.meta.url));
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
  if (!Number.isInteger(value) || value < minimum || value > maximum) throw fail(`${name} must be an integer between ${minimum} and ${maximum}`);
};

const validateDeadlineMs = value => {
  assertInteger(value, 'deadlineMs', 1, 120_000);
  return value;
};

const pathSegments = (value, name) => {
  if (typeof value !== 'string' || value.length === 0 || value.startsWith('/') || value.endsWith('/')) throw fail(`${name} must be a non-empty relative path`);
  const segments = value.split('/');
  if (segments.some(segment => segment.length === 0 || segment === '.' || segment === '..')) throw fail(`${name} contains an invalid path segment`);
  return segments;
};

const byteLength = value => Buffer.byteLength(JSON.stringify(value));

export const databaseName = projectId => `projects/${projectId}/databases/(default)`;
export const documentName = (projectId, path) => `${databaseName(projectId)}/documents/${path}`;

export const validateRequestOptions = options => {
  if (!options || typeof options !== 'object') throw fail('options are required');
  if (typeof options.projectId !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9-]{4,62}$/.test(options.projectId)) throw fail('projectId is invalid');
  pathSegments(options.documentPrefix, 'documentPrefix');
  const deadlineMs = options.deadlineMs ?? 10_000;
  const maxFrames = options.maxFrames ?? 32;
  const maxMessageBytes = options.maxMessageBytes ?? 1_048_576;
  assertInteger(deadlineMs, 'deadlineMs', 1, 120_000);
  assertInteger(maxFrames, 'maxFrames', 1, 256);
  assertInteger(maxMessageBytes, 'maxMessageBytes', 1, 8 * 1024 * 1024);
  if (options.metadata !== undefined && (typeof options.metadata !== 'object' || options.metadata === null || Array.isArray(options.metadata))) throw fail('metadata must be a plain object');
  for (const [key, value] of Object.entries(options.metadata ?? {})) {
    if (!/^[a-z0-9-]+$/.test(key) || !(typeof value === 'string' || (Array.isArray(value) && value.every(item => typeof item === 'string')))) throw fail('metadata must contain lowercase string header values');
  }
  return { projectId: options.projectId, documentPrefix: options.documentPrefix, deadlineMs, maxFrames, maxMessageBytes, metadata: options.metadata ?? {} };
};

const requestTargets = request => (request?.writes ?? []).flatMap(write => [write.update?.name, write.delete, write.transform?.document].filter(value => typeof value === 'string'));

export const validateWriteRequest = (request, options) => {
  const validated = validateRequestOptions(options);
  if (!request || typeof request !== 'object' || Array.isArray(request)) throw fail('write request must be an object');
  if (Object.hasOwn(request, 'database') && request.database !== databaseName(validated.projectId)) throw fail('write database is transport-owned');
  if (byteLength(request) > validated.maxMessageBytes) throw fail('write request exceeds maxMessageBytes', 'message_limit');
  const marker = `${databaseName(validated.projectId)}/documents/`;
  const prefix = pathSegments(validated.documentPrefix, 'documentPrefix');
  for (const target of requestTargets(request)) {
    if (!target.startsWith(marker)) throw fail('write target is outside the owned prefix');
    const targetParts = pathSegments(target.slice(marker.length), 'write target');
    if (targetParts.length <= prefix.length || targetParts.slice(0, prefix.length).join('/') !== validated.documentPrefix) throw fail('write target is outside the owned prefix');
  }
};

export const buildUnaryRequest = (operation, options, input = {}) => {
  const validated = validateRequestOptions(options);
  if (!OPERATIONS.has(operation)) throw fail(`unsupported unary operation: ${operation}`);
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw fail('unary input must be an object');
  const protectedFields = operation === 'GetDocument' ? ['name', 'database', 'writes', 'streamToken'] : ['database', 'name', 'path', 'writes', 'streamToken'];
  for (const field of protectedFields) if (Object.hasOwn(input, field)) throw fail(`${field} cannot be supplied for ${operation}`);
  if (operation === 'BeginTransaction') return { database: databaseName(validated.projectId), ...input };
  if (operation === 'Rollback') return { database: databaseName(validated.projectId), ...input };
  const path = input.path;
  const prefix = pathSegments(validated.documentPrefix, 'documentPrefix');
  const parts = pathSegments(path, 'document path');
  if (parts.length <= prefix.length || parts.slice(0, prefix.length).join('/') !== validated.documentPrefix) throw fail('document path is outside the owned prefix');
  const { path: _path, ...rest } = input;
  return { name: documentName(validated.projectId, path), ...rest };
};

export const plainError = error => Object.freeze({
  name: error?.name,
  code: error?.code,
  details: error?.details,
  message: error?.message,
});

export const plainStatus = status => Object.freeze({
  code: status?.code,
  details: status?.details,
  message: status?.message,
});

export const classifyTerminal = ({ status, error, sawEnd, sawClose }) => {
  if (status && (sawEnd || sawClose)) {
    return { kind: 'grpc_status', complete: true, status: plainStatus(status), error: error ? plainError(error) : undefined };
  }
  return undefined;
};

export const createLocalClient = options => {
  if (!options || !LOOPBACK_HOSTS.has(options.host)) throw fail('local transport requires a loopback host');
  if (!Number.isInteger(options.port) || options.port < 1 || options.port > 65535) throw fail('local transport port is invalid');
  if (typeof options.projectId !== 'string') throw fail('local transport projectId is required');
  return new FirestoreClient({
    servicePath: options.host,
    port: options.port,
    projectId: options.projectId,
    sslCreds: grpc.credentials.createInsecure(),
    fallback: false,
  });
};

const grpcCallName = operation => operation === 'BeginTransaction' ? 'beginTransaction' : operation === 'GetDocument' ? 'getDocument' : 'rollback';

const statusReceipt = (operation, request, error) => ({ kind: 'grpc_status', complete: true, operation, request, status: plainStatus(error), error: plainError(error) });

export const runUnaryCore = async (operation, request, options, { createClient }) => {
  const client = createClient();
  let timer;
  let call;
  try {
    call = client[grpcCallName(operation)](request, {
      deadline: new Date(Date.now() + options.deadlineMs),
      otherArgs: { headers: { ...options.metadata } },
    });
    const timeout = new Promise((_, reject) => {
      timer = setTimeout(() => {
        call?.cancel?.();
        reject(Object.assign(new Error('client deadline exceeded'), { code: 'client_deadline' }));
      }, options.deadlineMs);
    });
    const result = await Promise.race([call, timeout]);
    return { kind: 'grpc_status', complete: true, operation, request, response: result[0] ?? result };
  } catch (error) {
    if (error?.code === 'client_deadline') return { kind: 'client_deadline', complete: false, operation, request, error: plainError(error) };
    if (typeof error?.code === 'number') return statusReceipt(operation, request, error);
    return { kind: 'incomplete_stream', complete: false, operation, request, error: plainError(error) };
  } finally {
    clearTimeout(timer);
    client.close();
  }
};

export const runWriteCore = async (requests, options, { createClient, handshake, buildNextFrame }) => {
  if (Array.isArray(requests)) {
    if (requests.length + 1 > options.maxFrames) throw fail('stream exceeds maxFrames', 'frame_limit');
    for (const request of requests) buildNextFrame.validate(request);
  }
  const client = createClient();
  let stream;
  try {
    stream = client.write({ deadline: new Date(Date.now() + options.deadlineMs), otherArgs: { headers: { ...options.metadata } } });
  } catch (error) {
    client.close();
    return Object.freeze({ kind: 'incomplete_stream', complete: false, error: plainError(error), sentFrames: 0, receivedFrames: 0, events: Object.freeze([]) });
  }
  const events = [];
  let frameCount = 0;
  let sentFrames = 0;
  let receivedFrames = 0;
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
    if (settled) return;
    if (byteLength(value) > options.maxMessageBytes) throw fail('stream event exceeds maxMessageBytes', 'message_limit');
    events.push(Object.freeze({ type: event, value }));
  };
  const finish = result => {
    if (settled) return;
    settled = true;
    clearTimeout(timer);
    clearTimeout(terminalGraceTimer);
    settleTerminal(Object.freeze({ ...result, status: result.status ? plainStatus(result.status) : undefined, error: result.error ? plainError(result.error) : undefined, sentFrames, receivedFrames, events: Object.freeze(events.slice()) }));
  };
  const maybeFinish = () => {
    if (settled || !(sawEnd || sawClose)) return;
    const classified = classifyTerminal({ status, error: terminalError, sawEnd, sawClose });
    if (classified?.kind === 'grpc_status') finish({ kind: 'grpc_status', complete: true, status });
    else if (!terminalGraceTimer) terminalGraceTimer = setTimeout(() => terminalError ? finish({ kind: 'incomplete_stream', complete: false, error: terminalError }) : finish({ kind: 'incomplete_stream', complete: false }), 100);
  };
  const rejectWaiters = error => { while (responseWaiters.length > 0) responseWaiters.shift().reject(error); };
  const waitResponse = () => new Promise((resolve, reject) => {
    if (responseQueue.length > 0) resolve(responseQueue.shift());
    else if (terminalError) reject(terminalError);
    else responseWaiters.push({ resolve, reject });
  });
  const sendFrame = request => {
    if (++frameCount > options.maxFrames) throw fail('stream exceeds maxFrames', 'frame_limit');
    sentFrames += 1;
    buildNextFrame.validate(request);
    stream.write(request);
  };
  stream.on('data', response => {
    if (settled) return;
    try {
      push('data', response);
      receivedFrames += 1;
      if (++frameCount > options.maxFrames) return stream.destroy(fail('stream exceeds maxFrames', 'frame_limit'));
      if (responseWaiters.length > 0) responseWaiters.shift().resolve(response); else responseQueue.push(response);
    } catch (error) { stream.destroy(error); }
  });
  stream.on('status', value => { if (!settled) { status = value; push('status', plainStatus(value)); maybeFinish(); } });
  stream.on('error', error => { if (!settled) { terminalError = error; push('error', plainError(error)); rejectWaiters(error); terminalGraceTimer = setTimeout(maybeFinish, 100); maybeFinish(); } });
  stream.on('end', () => { if (!settled) { sawEnd = true; push('end', { status: status ? plainStatus(status) : undefined }); maybeFinish(); } });
  stream.on('close', () => { if (!settled) { sawClose = true; push('close', { status: status ? plainStatus(status) : undefined }); maybeFinish(); } });
  timer = setTimeout(() => {
    const error = Object.assign(new Error('client deadline exceeded'), { code: 'client_deadline' });
    terminalError = error;
    rejectWaiters(error);
    stream.destroy(error);
    finish({ kind: 'client_deadline', complete: false, error, status });
  }, options.deadlineMs);
  try {
    sendFrame(handshake);
    let response = await waitResponse();
    for await (const request of requests) {
      sendFrame(buildNextFrame(request, response));
      response = await waitResponse();
    }
    stream.end();
  } catch (error) {
    if (!terminalError) { terminalError = error; rejectWaiters(error); stream.destroy(error); }
  }
  const receipt = await terminal;
  client.close();
  return receipt;
};

const validMetadata = metadata => {
  if (!metadata || typeof metadata !== 'object' || Array.isArray(metadata)) throw fail('production metadata is required');
  for (const [key, value] of Object.entries(metadata)) {
    if (!/^[a-z0-9-]+$/.test(key) || !(typeof value === 'string' || (Array.isArray(value) && value.every(item => typeof item === 'string')))) {
      throw fail('metadata must contain lowercase string header values');
    }
  }
  if (typeof metadata.authorization !== 'string' || metadata.authorization.length === 0) {
    throw fail('production authorization metadata is required');
  }
  return Object.freeze({ ...metadata });
};

export const prepareFixedTlsTransport = input => {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw fail('production transport options are required');
  for (const field of ['endpoint', 'apiEndpoint', 'servicePath', 'host', 'port', 'keyFilename', 'credentials', 'sslCreds', 'useADC']) {
    if (Object.hasOwn(input, field)) throw fail(`${field} cannot override the fixed production transport`);
  }
  if (typeof input.projectId !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9-]{4,62}$/.test(input.projectId)) throw fail('projectId is invalid');
  const requestOptions = validateRequestOptions(input);
  if (!Number.isFinite(input.metadataExpiresAt) || !Number.isFinite(input.phaseDeadlineAt)) throw fail('metadata and phase deadlines are required');
  return Object.freeze({
    mode: 'production',
    servicePath: 'firestore.googleapis.com',
    port: 443,
    projectId: input.projectId,
    sslCreds: grpc.credentials.createSsl(),
    fallback: false,
    metadata: validMetadata(input.metadata),
    documentPrefix: requestOptions.documentPrefix,
    deadlineMs: requestOptions.deadlineMs,
    maxFrames: requestOptions.maxFrames,
    maxMessageBytes: requestOptions.maxMessageBytes,
    metadataExpiresAt: input.metadataExpiresAt,
    phaseDeadlineAt: input.phaseDeadlineAt,
  });
};

export const createFixedTlsTransport = (input, { admit } = {}) => {
  const prepared = prepareFixedTlsTransport(input);
  if (typeof admit !== 'function') throw fail('trusted production admission callback is required');
  const beforeWire = ({ deadlineMs = prepared.deadlineMs } = {}) => {
    validateDeadlineMs(deadlineMs);
    return assertReadyForWire(prepared, { waitForReady: admit(), callDeadlineMs: deadlineMs });
  };
  const createClient = () => new FirestoreClient({ servicePath: prepared.servicePath, port: prepared.port, projectId: prepared.projectId, sslCreds: prepared.sslCreds, fallback: false });
  const runUnary = async (operation, input, { deadlineMs = prepared.deadlineMs } = {}) => {
    const request = buildUnaryRequest(operation, prepared, input);
    await beforeWire({ deadlineMs });
    return runUnaryCore(operation, request, { ...prepared, deadlineMs }, { createClient });
  };
  const runWrite = async (requests, { deadlineMs = prepared.deadlineMs } = {}) => {
    if (!Array.isArray(requests)) throw fail('production write requests must be a finite array');
    if (requests.length + 1 > prepared.maxFrames) throw fail('stream exceeds maxFrames', 'frame_limit');
    for (const request of requests) validateWriteRequest(request, prepared);
    await beforeWire({ deadlineMs });
    const buildNextFrame = (request, response) => ({ ...request, streamToken: response?.streamToken });
    buildNextFrame.validate = request => validateWriteRequest(request, prepared);
    return runWriteCore(requests, { ...prepared, deadlineMs }, { createClient, handshake: { database: databaseName(prepared.projectId) }, buildNextFrame });
  };
  return Object.freeze({ prepared, runUnary, runWrite });
};

export const assertReadyForWire = async (prepared, { waitForReady = Promise.resolve(), now = () => Date.now(), callDeadlineMs = prepared.deadlineMs ?? 10_000 } = {}) => {
  await waitForReady;
  const current = now();
  if (prepared.metadataExpiresAt <= current || prepared.metadataExpiresAt <= current + callDeadlineMs) throw fail('metadata expired before wire', 'metadata_expired');
  if (prepared.phaseDeadlineAt <= current || prepared.phaseDeadlineAt <= current + callDeadlineMs) throw fail('phase deadline expired before wire', 'phase_deadline');
  return prepared;
};
