import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';

const requireSdk = createRequire(new URL('../../sdk-smoke/package.json', import.meta.url));
const firestoreEntry = requireSdk.resolve('@google-cloud/firestore');
const { FirestoreClient } = requireSdk(join(dirname(firestoreEntry), 'v1/index.js'));
const grpc = requireSdk(requireSdk.resolve('@grpc/grpc-js', { paths: [dirname(firestoreEntry)] }));

const fail = (message, code = 'invalid_options') => {
  const error = new TypeError(message);
  error.code = code;
  return error;
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

export const createLocalClient = options => new FirestoreClient({
  servicePath: options.host,
  port: options.port,
  projectId: options.projectId,
  sslCreds: grpc.credentials.createInsecure(),
  fallback: false,
});

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
  for (const field of ['endpoint', 'apiEndpoint', 'servicePath', 'host', 'port', 'keyFilename', 'credentials', 'useADC']) {
    if (Object.hasOwn(input, field)) throw fail(`${field} cannot override the fixed production transport`);
  }
  if (!input.sslCreds || typeof input.sslCreds !== 'object') throw fail('explicit TLS channel credentials are required');
  if (typeof input.projectId !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9-]{4,62}$/.test(input.projectId)) throw fail('projectId is invalid');
  if (!Number.isFinite(input.metadataExpiresAt) || !Number.isFinite(input.phaseDeadlineAt)) throw fail('metadata and phase deadlines are required');
  return Object.freeze({
    mode: 'production',
    servicePath: 'firestore.googleapis.com',
    port: 443,
    projectId: input.projectId,
    sslCreds: input.sslCreds,
    fallback: false,
    metadata: validMetadata(input.metadata),
    metadataExpiresAt: input.metadataExpiresAt,
    phaseDeadlineAt: input.phaseDeadlineAt,
  });
};

export const assertReadyForWire = async (prepared, { waitForReady = Promise.resolve(), now = () => Date.now() } = {}) => {
  await waitForReady;
  const current = now();
  if (prepared.metadataExpiresAt <= current) throw fail('metadata expired before wire', 'metadata_expired');
  if (prepared.phaseDeadlineAt <= current) throw fail('phase deadline expired before wire', 'phase_deadline');
  return prepared;
};
