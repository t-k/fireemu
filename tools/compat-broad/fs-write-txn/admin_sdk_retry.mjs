/** Offline P17 Admin SDK recorder. Run as a child of fireemu exec with a strict profile. */
import { createRequire } from 'node:module';
import { AsyncLocalStorage } from 'node:async_hooks';
import { createHash, randomBytes } from 'node:crypto';
import { readFileSync, writeFileSync, mkdirSync, realpathSync, existsSync, lstatSync, readSync, writeSync } from 'node:fs';
import { dirname, resolve, relative, sep } from 'node:path';
import { pathToFileURL } from 'node:url';
import { performance } from 'node:perf_hooks';
import { runtimeInfo } from './txn_program_transport.mjs';
import { admitMode } from '../fs-listen-resume/listen_sdk_adapter.mjs';

const require = createRequire(new URL('../../../conformance/package.json', import.meta.url));
const CASES = [{ caseId: 'conflict', maxAttempts: 1 }, { caseId: 'control', maxAttempts: 1 }, { caseId: 'retry', maxAttempts: 2 }, { caseId: 'retry-older', maxAttempts: 2 }];

export function localTarget(host, project) {
  const match = /^127\.0\.0\.1:([1-9][0-9]{0,4})$/.exec(host ?? '');
  if (!match || Number(match[1]) > 65535 || !/^demo-[a-z0-9-]{1,48}$/.test(project ?? '')) throw new Error('local loopback target and demo project required');
  return { host: '127.0.0.1', port: Number(match[1]) };
}

/** Record native calls rather than SDK promises: a callback can contain several RPCs. */
export function rpcRecorder(grpc) {
  const pending = new Set(), inflight = new Set();
  const recorder = { rows: [], storage: new AsyncLocalStorage(), context: {}, onDispatch: null, onStatus: null, journal: () => {}, check: () => {}, blocked: false, observationStopped: false, journalFailure: false, deadline: Infinity };
  const json = value => {
    if (Buffer.isBuffer(value) || value instanceof Uint8Array) return Buffer.from(value).toString('base64');
    if (Array.isArray(value)) return value.map(json);
    if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, json(item)]));
    return value;
  };
  recorder.interceptor = (options, nextCall) => {
    const context = { ...(recorder.storage.getStore() ?? recorder.context) };
    const rpc = options.method_definition.path.split('/').at(-1);
    const frames = [];
    let row, startCall, metadataKeys = [], quotaProject = null;
    return new grpc.InterceptingCall(nextCall(options), {
      sendMessage(message, next) {
        if (recorder.blocked || recorder.observationStopped && context.phase !== 'documentCleanup' && rpc !== 'Rollback') throw new Error('SDK dispatch blocked');
        if (recorder.rows.some(previous => previous.rpc === rpc && previous.site === context.site && previous.phase === context.phase && previous.attempt === context.attempt && previous.result?.code !== 0 && previous.result && JSON.stringify(previous.request) === JSON.stringify(json(message)))) throw new Error('SDK native redispatch blocked');
        if (performance.now() >= recorder.deadline) throw new Error('SDK campaign deadline exceeded');
        recorder.check(context);
        row = { sequence: recorder.rows.length, ...context, transport: 'grpc', rpc, request: json(message), metadataKeys, quotaProject,
          timing: { deadlineSeconds: Math.min(30, Math.max(0, (Number(options.deadline ?? Date.now() + 30_000) - Date.now()) / 1000)), dispatchMonotonic: performance.now() / 1000, dispatchUtc: new Date().toISOString() } };
        recorder.rows.push(row);
        inflight.add(row.sequence);
        try { recorder.journal({ event: 'dispatch', row }); }
        catch (error) { inflight.delete(row.sequence); recorder.journalFailure = recorder.blocked = true; throw error; }
        if (performance.now() >= recorder.deadline) { inflight.delete(row.sequence); recorder.blocked = true; throw new Error('SDK deadline exceeded after journal'); }
        startCall?.();
        next(message);
        recorder.onDispatch?.(row);
      },
      start(metadata, _listener, next) {
        metadataKeys = Object.keys(metadata.getMap()).sort();
        quotaProject = metadata.get('x-goog-user-project')[0] ?? null;
        // Hold metadata too: an RPC must not start before durable admission.
        startCall = () => next(metadata, {
          onReceiveMessage(message, forward) {
            frames.push(json(message));
            try { recorder.journal({ event: 'frame', sequence: row.sequence, frame: frames.at(-1) }); }
            catch { recorder.journalFailure = recorder.blocked = true; }
            forward(message);
          },
          onReceiveStatus(status, forward) {
            if (!row) { forward(status); return; }
            inflight.delete(row.sequence);
            row.frames = frames;
            row.timing.responseMonotonic = performance.now() / 1000;
            row.timing.responseUtc = new Date().toISOString();
            row.result = { kind: 'txn-program-receipt-v1', transport: 'grpc', complete: true, code: status.code, details: String(status.details ?? '').split(recorder.bearer ?? '\0').join('[credential-redacted]'),
              response: status.code !== 0 ? null : rpc === 'BatchGetDocuments' ? { responses: frames } : (frames[0] ?? {}),
              http: null, dispatchedRequests: 1, childPid: null, childReaped: false, workerExitCode: null, ipcComplete: true };
            row.outcomeClass = status.code === 0 ? 'OK' : [1, 2, 4, 13, 14].includes(status.code) ? 'UNKNOWN' : [3, 5, 9, 10].includes(status.code) ? 'REFUSED' : 'OTHER';
            if (status.code !== 0 && rpc === 'BatchGetDocuments' && row.request.newTransaction && frames.length) row.outcomeClass = 'UNKNOWN';
            if (row.outcomeClass === 'UNKNOWN') recorder.blocked = true;
            else if (status.code !== 0 && !(status.code === 10 && rpc === 'Commit' && ['transaction', 'writer'].includes(row.client) || rpc === 'Rollback')) recorder.observationStopped = true;
            try { recorder.journal({ event: 'status', row }); }
            catch { recorder.journalFailure = recorder.blocked = true; }
            const work = Promise.resolve().then(() => recorder.onStatus?.(row)).finally(() => forward(status));
            pending.add(work);
            work.finally(() => pending.delete(work)).catch(() => {});
          },
        });
      },
    });
  };
  recorder.drain = async () => { while (pending.size || inflight.size) { if (pending.size) await Promise.all([...pending]); else await new Promise(resolve => setTimeout(resolve, 5)); } };
  return recorder;
}

export async function recordAdminRetries({ host, project, admission }) {
  const production = admission !== undefined;
  if (production) {
    if (host !== undefined || project !== 'fireemu-oracle-txn' || typeof admission.journal !== 'function' || typeof admission.check !== 'function' || !admission.bearer) throw new Error('SDK production requires admitted parent');
  } else localTarget(host, project);
  for (const [module, version] of [['firebase-admin', '14.3.0'], ['@google-cloud/firestore', '8.7.1'], ['@grpc/grpc-js', '1.14.4']]) {
    if ((module === 'firebase-admin' ? require('firebase-admin').SDK_VERSION : require(`${module}/package.json`).version) !== version) throw new Error('SDK dependency pin differs');
  }
  // Default credential construction is lazy. Explicit offline auth below prevents credential discovery.
  const { initializeApp, deleteApp } = require('firebase-admin/app');
  const { getFirestore } = require('firebase-admin/firestore');
  const grpc = require('@grpc/grpc-js');
  const recorder = rpcRecorder(grpc);
  const nonce = admission?.nonce ?? randomBytes(16).toString('hex'), ownerId = admission?.ownerId ?? randomBytes(16).toString('hex');
  if (!/^[a-f0-9]{32}$/.test(nonce) || !/^[a-f0-9]{32}$/.test(ownerId)) throw new Error('SDK ownership identity differs');
  const started = performance.now();
  recorder.deadline = started + (admission?.observationRemaining ?? 180) * 1000;
  recorder.bearer = admission?.bearer;
  recorder.journal = admission?.journal ?? (() => {});
  recorder.check = admission?.check ?? (() => {});
  const apps = [], clients = [], attempts = [], documents = {};
  const originalHost = process.env.FIRESTORE_EMULATOR_HOST;
  const originalMtls = process.env.GOOGLE_API_USE_CLIENT_CERTIFICATE;
  if (production) delete process.env.FIRESTORE_EMULATOR_HOST; else process.env.FIRESTORE_EMULATOR_HOST = host;
  process.env.GOOGLE_API_USE_CLIENT_CERTIFICATE = 'false';
  let failureType = null, absent = true, graphComplete = false;
  let releaseWriter = () => {}, writerPending = Promise.resolve();
  let writerDispatched = () => {};
  try {
    for (const name of ['transaction', 'writer', 'witness']) {
      const app = initializeApp({ projectId: project }, `p17-${nonce}-${name}`);
      apps.push(app);
      const db = getFirestore(app);
      db.settings({ host: production ? 'firestore.googleapis.com' : host, ssl: production, preferRest: false,
        customHeaders: production ? { 'x-goog-user-project': project } : {},
        auth: { getUniverseDomain: async () => 'googleapis.com', getProjectId: async () => project, getClient: async () => ({ getRequestHeaders: async () => new Headers({ Authorization: `Bearer ${admission.bearer}` }) }) },
        clientConfig: { interfaces: { 'google.firestore.v1.Firestore': { retry_codes: { no_retry: [] }, methods: Object.fromEntries(['BatchGetDocuments', 'Commit', 'Rollback', 'DeleteDocument'].map(method => [method, { retry_codes_name: 'no_retry', timeout_millis: 10000 }])) } } },
        'grpc.enable_retries': 0,
        'grpc.callInvocationTransformer': properties => {
          properties.callOptions.interceptors = [recorder.interceptor];
          properties.callOptions.deadline = new Date(Math.min(Number(properties.callOptions.deadline ?? Infinity), Date.now() + Math.min(30_000, recorder.deadline - performance.now())));
          return properties;
        },
      });
      clients.push(db);
    }
    const [db, writer, witness] = clients;
    for (const spec of CASES) {
      const caseId = spec.caseId;
      const paths = Object.fromEntries(['a', 'b', 'c'].map(role => [role, `oracle/${nonce}/txn-p17-${caseId}/${role}`]));
      const fields = (role, state) => ({ nonce, owner: ownerId, role, state });
      const context = (client, site, attempt = 0, phase = 'observation') => ({ client, site: `${caseId}/${site}`, caseId, attempt, phase });
      const readState = () => recorder.storage.run(context('witness', 'post-state'), async () => {
        const snapshots = await witness.getAll(...Object.values(paths).map(path => witness.doc(path)));
        return Object.fromEntries(snapshots.map((snapshot, i) => [Object.keys(paths)[i], snapshot.exists ? snapshot.data() : null]));
      });
      for (const [role, path] of Object.entries(paths)) {
        await recorder.storage.run(context('witness', `setup/${role}`), async () => {
          if ((await witness.doc(path).get()).exists) throw new Error('owned document already exists');
          documents[`${caseId}-${role}`] = { name: witness.doc(path).formattedName, state: 'baseline', status: 'possibly-owned' };
          recorder.journal({ event: 'responsibility', nonce, ownerId, documents });
          // Pinned SDK batch.commit() adds ABORTED retries; _commit honors an empty retry list.
          await witness.batch().create(witness.doc(path), fields(role, 'baseline'))._commit({ retryCodes: [] });
          documents[`${caseId}-${role}`].status = 'created';
          recorder.journal({ event: 'responsibility', nonce, ownerId, documents });
        });
      }
      const entry = { caseId, callbackCount: 0, refusalCode: 0, refusalMessage: '', attempts: [], finalState: null };
      attempts.push(entry);
      let writerError = null;
      recorder.onDispatch = row => {
        if (row.caseId === caseId && row.client === 'writer' && row.rpc === 'Commit') writerDispatched();
      };
      recorder.onStatus = async row => {
        if (row.caseId !== caseId || row.client !== 'transaction' || row.rpc !== 'Commit') return;
        const attempt = entry.attempts[row.attempt - 1];
        attempt.refusalCode = row.result.code;
        attempt.refusalMessage = row.result.details;
        if (recorder.blocked || recorder.observationStopped) return;
        if (row.attempt === 1 && caseId !== 'control') await writerPending;
        attempt.finalState = await readState();
      };
      let writerReady, dispatched, startWriter;
      if (caseId !== 'control') {
        let ready, failReady;
        dispatched = new Promise(resolve => { writerDispatched = resolve; });
        writerReady = new Promise((resolve, reject) => { ready = resolve; failReady = reject; });
        const canCommit = new Promise(resolve => { releaseWriter = resolve; });
        startWriter = () => recorder.storage.run(context('writer', 'writer'), () => writer.runTransaction(async concurrent => {
          await concurrent.get(writer.doc(paths.b));
          concurrent.set(writer.doc(paths.a), fields('a', 'writer'));
          ready();
          await canCommit;
        }, { maxAttempts: 1 })).catch(error => { writerError = error.code ?? 'writer-failure'; failReady(error); });
        if (caseId === 'retry-older') { writerPending = startWriter(); await writerReady; }
      }
      try {
        await recorder.storage.run(context('transaction', 'transaction'), () => db.runTransaction(async transaction => {
          entry.callbackCount += 1;
          const count = entry.callbackCount;
          recorder.storage.getStore().attempt = count;
          const snapshot = await transaction.get(db.doc(paths.a));
          entry.attempts.push({ callbackCount: count, readState: snapshot.data(), refusalCode: null, refusalMessage: null, finalState: null, rpcSequence: [] });
          if (count === 1) {
            if (caseId === 'control') {
              await recorder.storage.run(context('writer', 'writer'), () => writer.batch().set(writer.doc(paths.c), fields('c', 'writer'))._commit({ retryCodes: [] })).catch(error => {
                if (recorder.rows.find(row => row.caseId === caseId && row.client === 'writer' && row.rpc === 'Commit')?.result?.code !== 10) throw error;
              });
            } else {
              if (caseId !== 'retry-older') { writerPending = startWriter(); await writerReady; }
              releaseWriter();
              await dispatched;
              // The first waiting committer wins strict's deadlock resolution.
              await new Promise(resolve => setTimeout(resolve, 200));
            }
          }
          transaction.set(db.doc(paths.b), fields('b', `transaction-${snapshot.data().state}`));
        }, { maxAttempts: spec.maxAttempts }));
      } catch (error) { entry.refusalCode = error.code ?? 'sdk-failure'; entry.refusalMessage = String(error.details ?? error.message).split(recorder.bearer ?? '\0').join('[credential-redacted]'); }
      finally { releaseWriter(); await writerPending; await recorder.drain(); }
      if (recorder.blocked || recorder.observationStopped) throw new Error('SDK observation stopped; review required');
      if (writerError !== null && writerError !== 10) throw new Error('concurrent writer did not complete');
      const writerCommit = recorder.rows.find(row => row.caseId === caseId && row.client === 'writer' && row.rpc === 'Commit');
      entry.writer = { code: writerCommit.result.code, message: writerCommit.result.details, rpcSequence: recorder.rows.filter(row => row.caseId === caseId && row.client === 'writer').map(row => ({ sequence: row.sequence, rpc: row.rpc, code: row.result.code, message: row.result.details })) };
      entry.finalState = await readState();
      for (const attempt of entry.attempts) {
        attempt.rpcSequence = recorder.rows.filter(row => row.caseId === caseId && row.client === 'transaction' && row.attempt === attempt.callbackCount).map(row => ({ sequence: row.sequence, rpc: row.rpc, code: row.result.code }));
      }
      const issued = new Set(recorder.rows.filter(row => row.caseId === caseId).flatMap(row => (row.frames ?? []).filter(frame => frame?.transaction).map(frame => frame.transaction)));
      for (const row of recorder.rows.filter(row => row.caseId === caseId)) if (row.rpc === 'Commit' && row.result?.code === 0 || row.rpc === 'Rollback' && row.result && row.outcomeClass !== 'UNKNOWN') issued.delete(row.request.transaction);
      if (issued.size) throw new Error('SDK unresolved token before next case');
      recorder.onDispatch = recorder.onStatus = null;
    }
    graphComplete = true;
  } catch (error) { failureType = error.constructor.name; }
  finally {
    releaseWriter();
    await writerPending;
    recorder.onDispatch = recorder.onStatus = null;
    recorder.deadline = Math.min(started + 300_000, performance.now() + 120_000);
    const witness = clients[2];
    if (recorder.blocked) absent = false;
    for (const [role, document] of Object.entries(documents)) {
      if (recorder.blocked) { absent = false; break; }
      try {
        await recorder.storage.run({ client: 'witness', site: `cleanup/${role}`, caseId: null, attempt: 0, phase: 'documentCleanup' }, async () => {
          const ref = witness.doc(document.name.split('/documents/')[1]);
          const snapshot = await ref.get();
          if (snapshot.exists) {
            if (snapshot.data().owner !== ownerId || snapshot.data().nonce !== nonce) throw new Error('cleanup ownership differs');
            await witness.batch().delete(ref, { lastUpdateTime: snapshot.updateTime })._commit({ retryCodes: [] });
          }
          recorder.storage.getStore().site += '/verify';
          if ((await ref.get()).exists) throw new Error('cleanup readback differs');
          document.state = null;
          document.status = 'confirmed-absent';
          recorder.journal({ event: 'responsibility', nonce, ownerId, documents });
        });
      } catch (error) { absent = false; failureType ??= error.constructor.name; }
    }
    await recorder.drain();
    for (const client of clients) await client.terminate();
    for (const app of apps) await deleteApp(app);
    for (const row of recorder.rows) if (row.result) { row.result.childReaped = true; row.result.workerExitCode = 0; }
    if (originalHost === undefined) delete process.env.FIRESTORE_EMULATOR_HOST; else process.env.FIRESTORE_EMULATOR_HOST = originalHost;
    if (originalMtls === undefined) delete process.env.GOOGLE_API_USE_CLIENT_CERTIFICATE; else process.env.GOOGLE_API_USE_CLIENT_CERTIFICATE = originalMtls;
  }
  const steps = recorder.rows.filter(row => row.phase === 'observation');
  const cleanupSteps = recorder.rows.filter(row => row.phase === 'documentCleanup');
  const unknown = recorder.rows.filter(row => !row.result || row.outcomeClass === 'UNKNOWN');
  const tokens = {};
  for (const row of recorder.rows) {
    for (const frame of row.frames ?? row.result?.response?.responses ?? []) {
      if (frame?.transaction) tokens[`${row.caseId}-${row.client}-${row.attempt}`] = { value: frame.transaction, transport: 'grpc', state: 'open', start: row.timing };
    }
    const token = Object.values(tokens).find(token => token.value === row.request.transaction);
    if (token && row.rpc === 'Commit' && row.result?.code === 0) token.state = 'committed';
    if (token && row.rpc === 'Rollback' && row.result && row.outcomeClass !== 'UNKNOWN') token.state = row.result.code === 0 ? 'rolled-back' : 'released-refused';
  }
  const openTokens = Object.keys(tokens).filter(role => tokens[role].state === 'open');
  const unrecovered = recorder.journalFailure || !absent || unknown.length > 0 || openTokens.length > 0 || failureType !== null;
  const receipt = {
    kind: 'txn-program-recording-v1', complete: graphComplete && !unrecovered, graphComplete,
    program: 'FS-TRANSACTION-P17-ADMIN-SDK-RETRY', packetName: 'p17-admin-sdk-retry',
    sourceDigest: createHash('sha256').update(readFileSync(new URL('./admin_sdk_retry.mjs', import.meta.url))).update(readFileSync(new URL('../fs-listen-resume/listen_sdk_adapter.mjs', import.meta.url))).digest('hex'),
    corpusDigest: createHash('sha256').update(JSON.stringify(CASES)).digest('hex'), nonce, ownerId,
    observations: steps.filter(row => row.client === 'transaction' && row.rpc === 'Commit'), steps, cleanupSteps, attempts,
    tokens, documents, unknownStarts: unknown.filter(row => row.rpc === 'BatchGetDocuments' && row.request.newTransaction).map(row => row.sequence),
    unknownRollbacks: unknown.filter(row => row.rpc === 'Rollback').map(row => row.sequence), unknownCommits: unknown.filter(row => row.rpc === 'Commit').map(row => row.sequence), unknownWrites: unknown.filter(row => row.rpc === 'DeleteDocument' || row.rpc === 'Commit' && row.request.writes?.length).map(row => row.sequence),
    timingMode: 'wall-clock', timingSource: 'grpc-js-client-interceptor', openTokens, journalFailure: recorder.journalFailure,
    deadlineAccounting: { campaignWallCapSeconds: 600, recordingWallCapSeconds: 300, observationSeconds: 180, recoverySeconds: 120, perRpcDeadlineSeconds: 30, elapsedSeconds: (performance.now() - started) / 1000 },
    cleanup: { absent }, unrecovered, failureType, sandboxRequests: recorder.rows.length,
    phaseRequests: { observation: steps.length, tokenCleanup: 0, documentCleanup: cleanupSteps.length, management: 0, credential: 0 },
    runtime: { firebaseAdmin: '14.3.0', firestore: '8.7.1', grpcJs: '1.14.4', target: production ? 'production' : 'local', node: process.version, manifest: runtimeInfo(), nodeSha256: createHash('sha256').update(readFileSync(process.execPath)).digest('hex'), lockSha256: createHash('sha256').update(readFileSync(new URL('../../../conformance/pnpm-lock.yaml', import.meta.url))).digest('hex') },
  };
  const canonical = value => Array.isArray(value) ? value.map(canonical) : value && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])])) : value;
  receipt.receiptDigest = createHash('sha256').update(JSON.stringify(canonical(receipt))).digest('hex');
  return receipt;
}

/** Derive SDK attempts from native rows; timing is deliberately excluded. */
export function projectAdminReceipt(receipt) {
  if (receipt.kind !== 'txn-program-recording-v1' || receipt.program !== 'FS-TRANSACTION-P17-ADMIN-SDK-RETRY' || !receipt.complete || !receipt.graphComplete || receipt.unrecovered || receipt.journalFailure || receipt.failureType || !receipt.cleanup?.absent || ['openTokens', 'unknownStarts', 'unknownCommits', 'unknownRollbacks'].some(key => !Array.isArray(receipt[key]) || receipt[key].length)) throw new Error('SDK projection requires complete acquisition');
  const canonical = value => Array.isArray(value) ? value.map(canonical) : value && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])])) : value;
  const bound = { ...receipt }; delete bound.receiptDigest;
  if (receipt.receiptDigest !== createHash('sha256').update(JSON.stringify(canonical(bound))).digest('hex')) throw new Error('SDK receipt digest differs');
  if (receipt.runtime.node !== process.version || receipt.runtime.nodeSha256 !== createHash('sha256').update(readFileSync(process.execPath)).digest('hex') || receipt.runtime.lockSha256 !== createHash('sha256').update(readFileSync(new URL('../../../conformance/pnpm-lock.yaml', import.meta.url))).digest('hex') || JSON.stringify(canonical(receipt.runtime.manifest)) !== JSON.stringify(canonical(runtimeInfo()))) throw new Error('SDK runtime binding differs');
  const sourceDigest = createHash('sha256').update(readFileSync(new URL('./admin_sdk_retry.mjs', import.meta.url))).update(readFileSync(new URL('../fs-listen-resume/listen_sdk_adapter.mjs', import.meta.url))).digest('hex');
  if (receipt.sourceDigest !== sourceDigest || receipt.corpusDigest !== createHash('sha256').update(JSON.stringify(CASES)).digest('hex')) throw new Error('SDK source binding differs');
  if (Object.entries({ campaignWallCapSeconds: 600, recordingWallCapSeconds: 300, observationSeconds: 180, recoverySeconds: 120, perRpcDeadlineSeconds: 30 }).some(([key, value]) => receipt.deadlineAccounting?.[key] !== value)) throw new Error('SDK deadline accounting differs');
  const rows = [...receipt.steps, ...receipt.cleanupSteps].sort((a, b) => a.sequence - b.sequence);
  if (rows.some((row, i) => row.sequence !== i || !row.result?.complete || row.outcomeClass !== (row.result.code === 0 ? 'OK' : [3, 5, 9, 10].includes(row.result.code) ? 'REFUSED' : 'OTHER') || [1, 2, 4, 13, 14].includes(row.result.code) || !row.result.childReaped) || Object.values(receipt.phaseRequests).some(value => !Number.isInteger(value) || value < 0) || Object.values(receipt.phaseRequests).reduce((a, b) => a + b, 0) !== receipt.sandboxRequests || rows.length !== receipt.phaseRequests.observation + receipt.phaseRequests.documentCleanup || receipt.phaseRequests.observation !== receipt.steps.length || receipt.phaseRequests.documentCleanup !== receipt.cleanupSteps.length || receipt.phaseRequests.tokenCleanup !== 0) throw new Error('SDK RPC accounting differs');
  const owned = Object.entries(receipt.documents);
  if (owned.length !== 12 || owned.some(([, document]) => document.status !== 'confirmed-absent') || owned.some(([role]) => !receipt.cleanupSteps.some(row => row.site === `cleanup/${role}/verify` && row.result.code === 0 && row.result.response.responses.length === 1 && row.result.response.responses[0].missing === receipt.documents[role].name))) throw new Error('SDK cleanup evidence differs');
  const cases = [];
  for (const spec of CASES) {
    const entry = receipt.attempts.find(value => value.caseId === spec.caseId);
    if (!entry || entry.callbackCount !== entry.attempts.length || entry.callbackCount < 1 || entry.callbackCount > spec.maxAttempts) throw new Error('SDK callback accounting differs');
    const attempts = entry.attempts.map((attempt, index) => {
      const native = receipt.steps.filter(row => row.caseId === spec.caseId && row.client === 'transaction' && row.attempt === index + 1);
      const read = native.find(row => row.rpc === 'BatchGetDocuments');
      const commit = native.find(row => row.rpc === 'Commit');
      const frame = read?.result.response?.responses.find(frame => frame.found);
      if (!frame || ['role', 'owner', 'nonce', 'state'].some(key => frame.found.fields[key]?.stringValue !== attempt.readState?.[key])) throw new Error('SDK attempt read state differs');
      if (index > 0) {
        const previous = receipt.steps.find(row => row.caseId === spec.caseId && row.client === 'transaction' && row.attempt === index && row.rpc === 'BatchGetDocuments');
        if (read.request.newTransaction?.readWrite?.retryTransaction !== previous.result.response.responses.find(frame => frame.transaction)?.transaction) throw new Error('SDK retry lineage differs');
      }
      const sequence = native.map(row => ({ sequence: row.sequence, rpc: row.rpc, code: row.result.code }));
      if (!commit || attempt.callbackCount !== index + 1 || attempt.refusalCode !== commit.result.code || attempt.refusalMessage !== commit.result.details || JSON.stringify(sequence) !== JSON.stringify(attempt.rpcSequence)) throw new Error('SDK attempt refusal or RPC sequence differs');
      const witness = receipt.steps.find(row => row.sequence > commit.sequence && row.caseId === spec.caseId && row.client === 'witness' && row.site === `${spec.caseId}/post-state`);
      if (!witness || witness.result.code !== 0 || witness.result.response.responses.length !== 3) throw new Error('SDK witness evidence differs');
      const state = Object.fromEntries(['a', 'b', 'c'].map(role => {
        const value = attempt.finalState?.[role];
        if (!value || value.role !== role || value.owner !== receipt.ownerId || value.nonce !== receipt.nonce) throw new Error('SDK state ownership differs');
        const found = witness.result.response.responses.find(frame => frame.found?.name === receipt.documents[`${spec.caseId}-${role}`].name)?.found;
        if (!found || ['role', 'owner', 'nonce', 'state'].some(key => found.fields[key]?.stringValue !== value[key])) throw new Error('SDK final state contradicts native witness');
        return [role, value.state];
      }));
      return { callbackCount: attempt.callbackCount, refusalCode: attempt.refusalCode, refusalMessage: attempt.refusalMessage, finalState: state, rpcSequence: sequence.map(({ rpc, code }) => ({ rpc, code })) };
    });
    if (['a', 'b', 'c'].some(role => ['role', 'owner', 'nonce', 'state'].some(key => entry.finalState?.[role]?.[key] !== entry.attempts.at(-1).finalState?.[role]?.[key]))) throw new Error('SDK final state differs');
    const writerRows = receipt.steps.filter(row => row.caseId === spec.caseId && row.client === 'writer');
    const writerCommit = writerRows.find(row => row.rpc === 'Commit');
    const writerSequence = writerRows.map(row => ({ sequence: row.sequence, rpc: row.rpc, code: row.result.code, message: row.result.details }));
    if (!writerCommit || ![0, 10].includes(writerCommit.result.code) || entry.writer?.code !== writerCommit.result.code || entry.writer?.message !== writerCommit.result.details || JSON.stringify(entry.writer?.rpcSequence) !== JSON.stringify(writerSequence)) throw new Error('SDK writer outcome differs');
    cases.push({ writer: { code: entry.writer.code, message: entry.writer.message, rpcSequence: writerSequence.map(({ rpc, code, message }) => ({ rpc, code, message })) }, caseId: spec.caseId, callbackCount: entry.callbackCount, refusalCode: entry.refusalCode, refusalMessage: entry.refusalMessage, finalState: attempts.at(-1).finalState, attempts });
  }
  if (receipt.attempts.length !== cases.length) throw new Error('SDK case inventory differs');
  return { kind: 'txn-admin-sdk-projection-v1', sourceDigest: receipt.sourceDigest, corpusDigest: receipt.corpusDigest, cases, timing: Object.fromEntries(['deadlineSeconds', 'dispatchMonotonic', 'responseMonotonic', 'dispatchUtc', 'responseUtc', 'elapsedSeconds', 'writerDispatchMargin', 'sdkBackoff'].map(key => [key, 'NOT_COMPARABLE'])) };
}

export function compareAdminReceipts(production, local) {
  if (production.runtime?.target !== 'production' || local.runtime?.target !== 'local') throw new Error('SDK comparison requires production and local receipts');
  const left = projectAdminReceipt(production), right = projectAdminReceipt(local);
  if (production.runtime.nodeSha256 !== local.runtime.nodeSha256 || production.runtime.lockSha256 !== local.runtime.lockSha256 || JSON.stringify(Object.entries(production.runtime.manifest.dependencies).map(([name, row]) => [name, row.version, row.treeSha256]).sort()) !== JSON.stringify(Object.entries(local.runtime.manifest.dependencies).map(([name, row]) => [name, row.version, row.treeSha256]).sort())) throw new Error('SDK comparison runtime differs');
  if (left.sourceDigest !== right.sourceDigest || left.corpusDigest !== right.corpusDigest) throw new Error('SDK comparison source differs');
  const attempts = left.cases.flatMap((entry, i) => entry.attempts.map((attempt, j) => ({ caseId: entry.caseId, callbackCount: j + 1, production: { ...attempt, writer: entry.writer }, local: right.cases[i].attempts[j] ? { ...right.cases[i].attempts[j], writer: right.cases[i].writer } : null, match: JSON.stringify(attempt) === JSON.stringify(right.cases[i].attempts[j]) && JSON.stringify(entry.writer) === JSON.stringify(right.cases[i].writer) })));
  for (const [i, entry] of right.cases.entries()) for (let j = left.cases[i].attempts.length; j < entry.attempts.length; j++) attempts.push({ caseId: entry.caseId, callbackCount: j + 1, production: null, local: { ...entry.attempts[j], writer: entry.writer }, match: false });
  return { kind: 'txn-admin-sdk-comparison-v1', complete: true, attempts, mismatches: attempts.filter(row => !row.match).length, timing: left.timing };
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  try {
    const [mode, output, ...extra] = process.argv.slice(2);
    if (mode === 'production' && !output && !extra.length) {
      const exchange = value => {
        writeSync(1, JSON.stringify(value) + '\n');
        const bytes = [], one = Buffer.alloc(1);
        while (readSync(0, one, 0, 1, null)) { if (one[0] === 10) break; bytes.push(one[0]); if (bytes.length > 16384) throw new Error('SDK parent reply capacity exceeded'); }
        const reply = JSON.parse(Buffer.from(bytes).toString());
        if (reply.authorized !== true) throw new Error('SDK admitted parent refused');
        return reply;
      };
      const spec = exchange({ event: 'ready' });
      const receipt = await recordAdminRetries({ project: 'fireemu-oracle-txn', admission: { ...spec, journal: value => exchange(value), check: () => {} } });
      writeSync(1, JSON.stringify({ event: 'receipt', receipt }) + '\n');
    } else if (mode === 'project' && !output || mode === 'compare' && !output) {
      const input = JSON.parse(readFileSync(0, 'utf8'));
      process.stdout.write(JSON.stringify(mode === 'project' ? projectAdminReceipt(input) : compareAdminReceipts(input.production, input.local)) + '\n');
    } else {
    if (!admitMode(mode).ok || extra.length || !output) throw new Error('usage: admin_sdk_retry.mjs local target/codex-out/receipt.json');
    const root = realpathSync(new URL('../../../', import.meta.url));
    const target = resolve(root, 'target'), destination = resolve(output);
    if (!destination.startsWith(target + sep)) throw new Error('receipt must be under worktree target');
    let ancestor = dirname(destination);
    while (!existsSync(ancestor)) ancestor = dirname(ancestor);
    const actual = realpathSync(ancestor);
    if (actual !== root && actual !== target && !actual.startsWith(target + sep)) throw new Error('receipt target cannot escape through symlinks');
    if (lstatSync(destination, { throwIfNoEntry: false })?.isSymbolicLink()) throw new Error('receipt target cannot be a symlink');
    mkdirSync(dirname(destination), { recursive: true });
    const receipt = await recordAdminRetries({ host: process.env.FIRESTORE_EMULATOR_HOST, project: 'demo-admin-retry' });
    const raw = JSON.stringify(receipt, null, 2);
    if (/AIza|-----BEGIN .*PRIVATE KEY/.test(raw)) throw new Error('sensitive-looking value withheld');
    writeFileSync(destination, raw + '\n');
    console.log(`complete ${receipt.complete} requests ${receipt.sandboxRequests} receipt ${relative(root, destination)}`);
    if (!receipt.complete) process.exitCode = 1;
    }
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
