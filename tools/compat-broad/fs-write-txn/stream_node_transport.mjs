import {
  createLocalClient,
  runUnaryCore,
  runWriteCore,
} from './transport_internal.mjs';

export { classifyTerminal } from './transport_internal.mjs';

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

const pathSegments = (value, name) => {
  if (typeof value !== 'string' || value.length === 0 || value.startsWith('/') || value.endsWith('/')) {
    throw fail(`${name} must be a non-empty relative path`);
  }
  const segments = value.split('/');
  if (segments.some(segment => segment.length === 0 || segment === '.' || segment === '..')) {
    throw fail(`${name} contains an invalid path segment`);
  }
  return segments;
};

const byteLength = value => {
  const encoded = JSON.stringify(value);
  if (encoded === undefined) throw fail('stream value is not serializable', 'message_limit');
  return Buffer.byteLength(encoded);
};

export const validateRequestOptions = options => {
  if (!options || typeof options !== 'object') throw fail('options are required');
  const { projectId, documentPrefix } = options;
  if (typeof projectId !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9-]{4,62}$/.test(projectId)) {
    throw fail('projectId is invalid');
  }
  pathSegments(documentPrefix, 'documentPrefix');
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
    if (!/^[a-z0-9-]+$/.test(key) || !(typeof value === 'string' || (Array.isArray(value) && value.every(item => typeof item === 'string')))) {
      throw fail('metadata must contain string header values');
    }
  }
  return { projectId, documentPrefix, deadlineMs, maxFrames, maxMessageBytes, metadata: options.metadata ?? {} };
};

export const validateTransportOptions = options => {
  if (!options || typeof options !== 'object') throw fail('options are required');
  const { host, port } = options;
  if (typeof host !== 'string' || !LOOPBACK_HOSTS.has(host)) {
    throw fail('host must be an explicit loopback address');
  }
  assertInteger(port, 'port', 1, 65535);
  return { host, port, ...validateRequestOptions(options) };
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
  const prefixSegments = pathSegments(validated.documentPrefix, 'documentPrefix');
  const pathParts = pathSegments(path, 'document path');
  if (pathParts.length <= prefixSegments.length || pathParts.slice(0, prefixSegments.length).join('/') !== validated.documentPrefix) {
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

export const validateWriteRequest = (request, options) => {
  const validated = validateRequestOptions(options);
  if (!request || typeof request !== 'object') throw fail('write request must be an object');
  if (Object.hasOwn(request, 'database') && request.database !== databaseName(validated.projectId)) {
    throw fail('write database is transport-owned');
  }
  if (byteLength(request) > validated.maxMessageBytes) throw fail('write request exceeds maxMessageBytes', 'message_limit');
  for (const target of requestTargets(request)) {
    const marker = `${databaseName(validated.projectId)}/documents/`;
    if (!target.startsWith(marker)) throw fail('write target is outside the owned prefix');
    const targetPath = target.slice(marker.length);
    const targetSegments = pathSegments(targetPath, 'write target');
    const prefixSegments = pathSegments(validated.documentPrefix, 'documentPrefix');
    if (targetSegments.length <= prefixSegments.length || targetSegments.slice(0, prefixSegments.length).join('/') !== validated.documentPrefix) {
      throw fail('write target is outside the owned prefix');
    }
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

export const runUnary = async (operation, options, input = {}) => {
  const validated = validateTransportOptions(options);
  const request = buildUnaryRequest(operation, validated, input);
  return runUnaryCore(operation, request, validated, { createClient: () => createLocalClient(validated) });
};

export const runWrite = async (requests, options) => {
  const validated = validateTransportOptions(options);
  const buildNextFrame = (request, response) => listWriteFrames([request], response)[0];
  buildNextFrame.validate = request => validateWriteRequest(request, validated);
  return runWriteCore(requests, validated, {
    createClient: () => createLocalClient(validated),
    handshake: { database: databaseName(validated.projectId) },
    buildNextFrame,
  });
};
