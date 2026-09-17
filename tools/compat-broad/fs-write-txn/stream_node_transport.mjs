import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

const requireSdk = createRequire(new URL('../../sdk-smoke/package.json', import.meta.url));
// Resolve the installed SDK from sdk-smoke's package boundary, then load its
// generated gRPC client by absolute path because the package does not export
// the generated v1 subpath.
const firestoreEntry = requireSdk.resolve('@google-cloud/firestore');
const { FirestoreClient } = requireSdk(join(dirname(firestoreEntry), 'v1/index.js'));
const grpc = requireSdk('@grpc/grpc-js');

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

const byteLength = value => Buffer.byteLength(JSON.stringify(value));

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
  if (byteLength(request) > options.maxMessageBytes) throw fail('write request exceeds maxMessageBytes', 'message_limit');
  const prefix = documentName(options.projectId, options.documentPrefix);
  for (const target of requestTargets(request)) {
    if (!target.startsWith(`${prefix}/`) && target !== prefix) throw fail('write target is outside the owned prefix');
  }
};

const clientFor = options => new FirestoreClient({
  apiEndpoint: `${options.host}:${options.port}`,
  projectId: options.projectId,
  sslCreds: grpc.credentials.createInsecure(),
  fallback: false,
});

export const runUnary = async (operation, options, input = {}) => {
  const validated = validateTransportOptions(options);
  const request = buildUnaryRequest(operation, validated, input);
  const client = clientFor(validated);
  let timer;
  try {
    const call = client[operation === 'BeginTransaction' ? 'beginTransaction' : operation === 'GetDocument' ? 'getDocument' : 'rollback'](request, {
      deadline: new Date(Date.now() + validated.deadlineMs),
      otherArgs: { headers: { ...validated.metadata } },
    });
    const result = await Promise.race([
      call,
      delay(validated.deadlineMs).then(() => { throw Object.assign(new Error('client deadline exceeded'), { code: 'client_deadline' }); }),
    ]);
    return { kind: 'grpc_status', complete: true, operation, request, response: result[0] ?? result };
  } catch (error) {
    if (error?.code === 'client_deadline') return { kind: 'client_deadline', complete: false, operation, request, error };
    return { kind: 'grpc_status', complete: true, operation, request, status: { code: error?.code, details: error?.details }, error };
  } finally {
    clearTimeout(timer);
    client.close();
  }
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
  let ended = false;
  let timer;
  const push = (event, value) => {
    if (byteLength(value) > validated.maxMessageBytes) throw fail('stream event exceeds maxMessageBytes', 'message_limit');
    events.push({ type: event, value });
  };
  const receipt = await new Promise(resolve => {
    const finish = result => {
      if (ended) return;
      ended = true;
      clearTimeout(timer);
      resolve({ ...result, events });
    };
    stream.on('data', response => {
      try {
        frameCount += 1;
        if (frameCount > validated.maxFrames) {
          stream.destroy(fail('stream exceeds maxFrames', 'frame_limit'));
          return;
        }
        push('data', response);
      } catch (error) { stream.destroy(error); }
    });
    stream.on('status', value => {
      status = value;
      try { push('status', value); } catch (error) { stream.destroy(error); }
    });
    stream.on('error', error => {
      try { push('error', error); } catch { /* preserve the original terminal error */ }
      if (error?.code === 'client_deadline') finish({ kind: 'client_deadline', complete: false, error, status });
      else if (status) finish({ kind: 'grpc_status', complete: true, error, status });
      else finish({ kind: 'incomplete_stream', complete: false, error, status });
    });
    stream.on('end', () => {
      push('end', { status });
      if (status && status.code === grpc.status.OK) finish({ kind: 'grpc_status', complete: true, status });
      else if (status) finish({ kind: 'grpc_status', complete: true, status });
      else finish({ kind: 'incomplete_stream', complete: false, status });
    });
    timer = setTimeout(() => {
      const error = Object.assign(new Error('client deadline exceeded'), { code: 'client_deadline' });
      stream.destroy(error);
    }, validated.deadlineMs);
    void (async () => {
      try {
        const handshake = { database: databaseName(validated.projectId) };
        assertRequest(handshake, validated);
        frameCount = 1;
        stream.write(handshake);
        for await (const request of requests) {
          frameCount += 1;
          if (frameCount > validated.maxFrames) throw fail('stream exceeds maxFrames', 'frame_limit');
          assertRequest(request, validated);
          stream.write(request);
        }
        stream.end();
      } catch (error) {
        stream.destroy(error);
      }
    })();
  });
  client.close();
  return receipt;
};
