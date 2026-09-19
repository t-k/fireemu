import { pathToFileURL } from 'node:url';
import { randomUUID } from 'node:crypto';
import {
  documentName,
  runUnary,
  runWrite,
} from './stream_node_transport.mjs';

const DEFAULTS = Object.freeze({
  deadlineMs: 30_000,
  maxFrames: 32,
  maxMessageBytes: 1_048_576,
});
const LOOPBACK_HOSTS = new Set(['127.0.0.1', '::1', 'localhost']);

const fail = message => {
  const error = new TypeError(message);
  error.code = 'invalid_options';
  return error;
};

const plainFailure = error => ({
  name: error?.name ?? 'Error',
  code: error?.code,
  message: error?.message ?? String(error),
});

const ownedPath = (prefix, suffix) => `${prefix}/${suffix}`;

const markerFields = (ownerId, role) => ({
  owner: { stringValue: `o3-stream:${ownerId}` },
  role: { stringValue: role },
});

const updateWrite = (name, fields, currentDocument) => ({
  update: { name, fields },
  ...(currentDocument ? { currentDocument } : {}),
});

const deleteWrite = (name, updateTime) => ({
  delete: name,
  currentDocument: { updateTime },
});

const canonical = value => {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])]));
  return value;
};

const canonicalFields = value => {
  if (Array.isArray(value)) return value.map(canonicalFields);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).filter(key => key !== 'valueType').sort().map(key => [key, canonicalFields(value[key])]));
  return value;
};

const sameDocumentProof = (actual, baseline) => JSON.stringify(canonical({
  name: actual?.name,
  fields: actual?.fields,
  updateTime: actual?.updateTime,
})) === JSON.stringify(canonical({
  name: baseline?.name,
  fields: baseline?.fields,
  updateTime: baseline?.updateTime,
}));

const sameOwnedState = (actual, projectId, path, ownerId, role, fields) => Boolean(
  actual?.name === documentName(projectId, path) &&
  isOwnedDocument(actual, ownerId, role) &&
  JSON.stringify(canonicalFields(actual.fields)) === JSON.stringify(canonicalFields(fields)),
);

export const validateCollectorOptions = options => {
  if (!options || typeof options !== 'object' || Array.isArray(options)) throw fail('options are required');
  const { host = '127.0.0.1', port, projectId, documentPrefix, nonce } = options;
  if (!LOOPBACK_HOSTS.has(host)) throw fail('host must be an explicit loopback address');
  if (!Number.isInteger(port) || port < 1 || port > 65_535) throw fail('port must be a bounded integer');
  if (typeof projectId !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9-]{4,62}$/.test(projectId)) throw fail('projectId is invalid');
  if (typeof documentPrefix !== 'string' || !documentPrefix || documentPrefix.startsWith('/') || documentPrefix.endsWith('/') || documentPrefix.split('/').some(part => !part || part === '.' || part === '..')) {
    throw fail('documentPrefix must be a relative path');
  }
  if (typeof nonce !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_-]{7,127}$/.test(nonce)) throw fail('nonce is invalid');
  const deadlineMs = options.deadlineMs ?? DEFAULTS.deadlineMs;
  const maxFrames = options.maxFrames ?? DEFAULTS.maxFrames;
  const maxMessageBytes = options.maxMessageBytes ?? DEFAULTS.maxMessageBytes;
  if (!Number.isInteger(deadlineMs) || deadlineMs < 1 || deadlineMs > 120_000) throw fail('deadlineMs is invalid');
  if (!Number.isInteger(maxFrames) || maxFrames < 1 || maxFrames > 256) throw fail('maxFrames is invalid');
  if (!Number.isInteger(maxMessageBytes) || maxMessageBytes < 1 || maxMessageBytes > 8 * 1024 * 1024) throw fail('maxMessageBytes is invalid');
  return Object.freeze({ host, port, projectId, documentPrefix, nonce, deadlineMs, maxFrames, maxMessageBytes, metadata: options.metadata ?? {} });
};

export const collectorPaths = options => {
  const validated = validateCollectorOptions(options);
  return Object.freeze({
    locked: ownedPath(validated.documentPrefix, 'locked'),
    control: ownedPath(validated.documentPrefix, 'control'),
    suffix: ownedPath(validated.documentPrefix, 'contended-tail'),
  });
};

const hasUpdateTime = value => (typeof value === 'string' && value.length > 0) || (
  value && typeof value === 'object' && typeof value.seconds !== 'undefined'
);

export const isOwnedDocument = (document, ownerId, role) => Boolean(
  document?.fields?.owner?.stringValue === `o3-stream:${ownerId}` &&
  document?.fields?.role?.stringValue === role &&
  hasUpdateTime(document?.updateTime),
);

export const classifyCollectorOutcome = ({ contention, readback, cleanup, absence }) => Object.freeze({
  complete: [contention, readback, cleanup].every(item => item?.complete === true) &&
    (Array.isArray(absence) ? absence.length > 0 && absence.every(item => item?.complete === true) : absence?.complete === true),
  semantic: Object.freeze({
    contentionAborted: contention?.status?.code === 10,
    lockedUnchanged: readback?.lockedUnchanged === true,
    suffixAbsent: readback?.suffixAbsent === true,
    postRollbackWriteAccepted: readback?.postRollbackWriteAccepted === true,
    cleanupAbsent: Array.isArray(absence)
      ? absence.length > 0 && absence.every(item => item?.absent === true)
      : absence?.absent === true,
  }),
});

const receiptComplete = receipt => receipt?.complete === true;
const responseBody = receipt => receipt?.response ?? receipt?.events?.filter(event => event.type === 'data').at(-1)?.value;
const statusCode = receipt => receipt?.status?.code;

const run = async (options, api, ownerId = randomUUID()) => {
  const paths = collectorPaths(options);
  const name = path => documentName(options.projectId, path);
  const write = (requests, phase) => api.runWrite(requests, options, { phase }).then(receipt => ({ phase, receipt, complete: receiptComplete(receipt) }));
  const read = (path, phase, transaction) => api.runUnary('GetDocument', options, { path, ...(transaction ? { transaction } : {}) }, { phase }).then(receipt => ({ phase, receipt, complete: receiptComplete(receipt) }));
  const created = new Map();
  const candidates = new Map([
    [paths.control, 'control'],
    [paths.locked, 'locked'],
    [paths.suffix, 'suffix'],
  ]);
  const attempted = new Set();
  let transaction;
  const observations = [];
  let contentionReceipt;
  let readback;
  let cleanup = [];
  let failure;
  let transactionReleaseUnknown = false;
  let baselineLocked;
  const recordCreate = (path, receipt, role) => {
    const body = responseBody(receipt);
    const result = body?.writeResults?.[0];
    const updateTime = result?.updateTime;
    if (receiptComplete(receipt) && statusCode(receipt) === 0 && typeof updateTime === 'object' && updateTime !== null) created.set(path, { role, updateTime });
  };
  try {
    const lockedFields = markerFields(ownerId, 'locked');
    const controlFields = markerFields(ownerId, 'control');
    for (const [path, role] of candidates) {
      if (path === paths.suffix) continue;
      const preflight = await read(path, 'preflight-create-absence');
      observations.push(preflight);
      if (!preflight.complete || statusCode(preflight.receipt) !== 5) throw new Error(`${role} preflight was not a typed absence`);
      attempted.add(path);
    }
    const controlCreate = await write([{ writes: [updateWrite(name(paths.control), controlFields, { exists: false })] }], 'setup-control');
    observations.push(controlCreate);
    recordCreate(paths.control, controlCreate.receipt, 'control');
    if (!created.has(paths.control)) throw new Error('setup control create did not complete as an owned create');
    const lockedCreate = await write([{ writes: [updateWrite(name(paths.locked), { ...lockedFields, value: { stringValue: 'before' } }, { exists: false })] }], 'setup-locked');
    observations.push(lockedCreate);
    recordCreate(paths.locked, lockedCreate.receipt, 'locked');
    if (!created.has(paths.locked)) throw new Error('setup locked create did not complete as an owned create');

    const positive = await write([{ writes: [updateWrite(name(paths.control), { ...controlFields, value: { stringValue: 'accepted' } })] }], 'positive-uncontended-stream');
    observations.push(positive);
    const controlPoststate = await read(paths.control, 'readback-control');
    const controlBody = responseBody(controlPoststate.receipt);
    const controlAccepted = controlPoststate.complete && sameOwnedState(controlBody, options.projectId, paths.control, ownerId, 'control', { ...controlFields, value: { stringValue: 'accepted' } });
    observations.push({ phase: 'readback-control', receipt: controlPoststate.receipt, complete: controlPoststate.complete, controlAccepted });
    if (!controlAccepted) throw new Error('positive control stream state was not observed');

    const begin = await api.runUnary('BeginTransaction', options, { options: { readWrite: {} } }, { phase: 'begin-rw-transaction' });
    observations.push({ phase: 'begin-rw-transaction', receipt: begin, complete: receiptComplete(begin) });
    transaction = begin.response?.transaction;
    if (!transaction) throw new Error('begin transaction did not return a transaction token');
    const lockedInTransaction = await api.runUnary('GetDocument', options, { path: paths.locked, transaction }, { phase: 'get-locked-with-transaction' });
    observations.push({ phase: 'get-locked-with-transaction', receipt: lockedInTransaction, complete: receiptComplete(lockedInTransaction) });
    baselineLocked = responseBody(lockedInTransaction);
    if (!lockedInTransaction.complete || !isOwnedDocument(baselineLocked, ownerId, 'locked')) throw new Error('transactional locked read did not provide an owned baseline');

    const suffixPreflight = await read(paths.suffix, 'preflight-suffix-absence');
    observations.push(suffixPreflight);
    if (!suffixPreflight.complete || statusCode(suffixPreflight.receipt) !== 5) throw new Error('suffix preflight was not a typed absence');
    attempted.add(paths.suffix);
    const contention = await write([{ writes: [
      updateWrite(name(paths.locked), { ...lockedFields, value: { stringValue: 'must-not-commit' } }),
      updateWrite(name(paths.suffix), { ...markerFields(ownerId, 'suffix'), value: { stringValue: 'must-not-commit' } }, { exists: false }),
    ] }], 'contended-multiwrite-stream');
    observations.push(contention);
    contentionReceipt = contention.receipt;
    if (!contention.complete) throw new Error('contention stream was incomplete; stopping before later observation writes');
    if (statusCode(contention.receipt) === 0) {
      const body = responseBody(contention.receipt);
      const updateTime = body?.writeResults?.[1]?.updateTime;
      if (typeof updateTime === 'object' && updateTime !== null) created.set(paths.suffix, { role: 'suffix', updateTime });
    }
    const lockedRead = await read(paths.locked, 'readback-locked');
    const suffixRead = await read(paths.suffix, 'readback-suffix');
    const lockedBody = responseBody(lockedRead.receipt);
    const suffixMissing = statusCode(suffixRead.receipt) === 5;
    readback = {
      complete: lockedRead.complete && suffixRead.complete,
      lockedUnchanged: sameDocumentProof(lockedBody, baselineLocked),
      suffixAbsent: suffixMissing,
      postRollbackWriteAccepted: false,
    };
    observations.push({ phase: 'readback-contention', receipt: { locked: lockedRead.receipt, suffix: suffixRead.receipt }, complete: readback.complete, readback });

    const rollback = await api.runUnary('Rollback', options, { transaction }, { phase: 'rollback' });
    observations.push({ phase: 'rollback', receipt: rollback, complete: receiptComplete(rollback) });
    if (receiptComplete(rollback) && !rollback.status) transaction = undefined;
    else transactionReleaseUnknown = true;
    if (transactionReleaseUnknown) throw new Error('rollback did not complete successfully; transaction release is uncertain');
    const released = await write([{ writes: [updateWrite(name(paths.locked), { ...lockedFields, value: { stringValue: 'after-rollback' } })] }], 'post-rollback-positive-stream');
    observations.push(released);
    const releasedRead = await read(paths.locked, 'readback-post-rollback');
    const releasedBody = responseBody(releasedRead.receipt);
    readback.postRollbackWriteAccepted = released.complete && statusCode(released.receipt) === 0 && releasedRead.complete && sameOwnedState(releasedBody, options.projectId, paths.locked, ownerId, 'locked', { ...lockedFields, value: { stringValue: 'after-rollback' } });
    observations.push({ phase: 'readback-post-rollback', receipt: releasedRead.receipt, complete: releasedRead.complete, postRollbackWriteAccepted: readback.postRollbackWriteAccepted });
  } catch (error) {
    failure = plainFailure(error);
  } finally {
    if (api.recover) {
      cleanup = await api.recover(options);
    } else {
      if (transaction) {
        try {
          const rollback = await api.runUnary('Rollback', options, { transaction }, { phase: 'rollback-finally' });
          observations.push({ phase: 'rollback-finally', receipt: rollback, complete: receiptComplete(rollback) });
          if (!(receiptComplete(rollback) && !rollback.status)) transactionReleaseUnknown = true;
          else {
            transaction = undefined;
            transactionReleaseUnknown = false;
          }
        } catch (error) {
          transactionReleaseUnknown = true;
          observations.push({ phase: 'rollback-finally', receipt: { complete: false, error: plainFailure(error) }, complete: false });
        }
      }
      cleanup = [];
      if (transactionReleaseUnknown) {
        for (const path of attempted) cleanup.push({ path, skipped: true, complete: false, absent: false, failure: 'transaction-release-uncertain' });
      } else {
        for (const path of attempted) {
          const role = candidates.get(path);
          try {
            const final = await read(path, 'final-owned-read');
            const body = responseBody(final.receipt);
            if (final.complete && statusCode(final.receipt) === 5) {
              cleanup.push({ path, skipped: true, complete: true, absent: true, receipt: final.receipt });
              continue;
            }
            if (!final.complete || !isOwnedDocument(body, ownerId, role)) {
              cleanup.push({ path, skipped: true, complete: false, absent: false, receipt: final.receipt });
              continue;
            }
            const removed = await write([{ writes: [deleteWrite(name(path), body.updateTime)] }], 'conditional-delete');
            const absent = await read(path, 'typed-absence');
            const removedSucceeded = removed.complete && statusCode(removed.receipt) === 0;
            const absentConfirmed = removedSucceeded && absent.complete && statusCode(absent.receipt) === 5;
            cleanup.push({ path, skipped: false, complete: absentConfirmed, receipt: removed.receipt, ownedRead: final.receipt, absence: absent.receipt, absent: absentConfirmed });
          } catch (error) {
            cleanup.push({ path, skipped: true, complete: false, absent: false, failure: plainFailure(error) });
          }
        }
      }
    }
    observations.push({ phase: 'cleanup', cleanup, complete: cleanup.length > 0 && cleanup.every(item => item.complete && item.absent) });
  }
  const outcome = classifyCollectorOutcome({
    contention: contentionReceipt,
    readback,
    cleanup: { complete: cleanup.length > 0 && cleanup.every(item => item.complete && item.absent) },
    absence: cleanup,
  });
  return { observations, cleanup, readback, contention: contentionReceipt, outcome, failure, ownerId };
};

export const collect = async options => {
  const validated = validateCollectorOptions(options);
  return run(validated, { runWrite, runUnary });
};

export const collectWithApi = async (options, api, ownerId) => {
  const validated = validateCollectorOptions(options);
  return run(validated, api, ownerId);
};

const main = async () => {
  const liveHost = process.env.FIRESTORE_EMULATOR_HOST;
  const [environmentHost, environmentPort] = liveHost?.split(':') ?? [];
  const host = environmentHost || '127.0.0.1';
  const port = Number(process.env.FIREEMU_LIVE_PORT ?? environmentPort);
  const projectId = process.env.GOOGLE_CLOUD_PROJECT;
  if (!Number.isInteger(port) || !projectId) throw new Error('FIREEMU_LIVE_PORT/FIRESTORE_EMULATOR_HOST and GOOGLE_CLOUD_PROJECT are required');
  const nonce = process.env.FIREEMU_O3_NONCE ?? `run-${Date.now().toString(36)}`;
  const deadlineMs = Number(process.env.FIREEMU_O3_DEADLINE_MS ?? 30_000);
  const result = await collect({ host, port, projectId, documentPrefix: `compat/o3/${nonce}`, nonce, deadlineMs, metadata: { authorization: 'Bearer owner' } });
  process.stdout.write(`${JSON.stringify(result)}\n`);
  if (result.failure || !result.outcome.complete || Object.values(result.outcome.semantic).some(value => value !== true)) process.exitCode = 1;
};

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
