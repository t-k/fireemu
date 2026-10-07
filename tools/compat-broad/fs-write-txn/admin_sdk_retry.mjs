/** Offline P17 Admin SDK recorder. Run as a child of fireemu exec with a strict profile. */
import { createRequire } from 'node:module';
import { AsyncLocalStorage } from 'node:async_hooks';
import { createHash, randomBytes } from 'node:crypto';
import { readFileSync, writeFileSync, mkdirSync, realpathSync, existsSync, lstatSync } from 'node:fs';
import { dirname, resolve, relative, sep } from 'node:path';
import { pathToFileURL } from 'node:url';
import { performance } from 'node:perf_hooks';
import { admitMode } from '../fs-listen-resume/listen_sdk_adapter.mjs';

const require = createRequire(new URL('../../../conformance/package.json', import.meta.url));
const CASES = [{ caseId: 'conflict', maxAttempts: 1 }, { caseId: 'control', maxAttempts: 1 }, { caseId: 'retry', maxAttempts: 2 }];

export function localTarget(host, project) {
  const match = /^127\.0\.0\.1:([1-9][0-9]{0,4})$/.exec(host ?? '');
  if (!match || Number(match[1]) > 65535 || !/^demo-[a-z0-9-]{1,48}$/.test(project ?? '')) throw new Error('local loopback target and demo project required');
  return { host: '127.0.0.1', port: Number(match[1]) };
}

/** Record native calls rather than SDK promises: a callback can contain several RPCs. */
export function rpcRecorder(grpc) {
  const pending = new Set();
  const recorder = { rows: [], storage: new AsyncLocalStorage(), context: {}, onDispatch: null, onStatus: null };
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
    let row;
    return new grpc.InterceptingCall(nextCall(options), {
      sendMessage(message, next) {
        row = { sequence: recorder.rows.length, ...context, transport: 'grpc', rpc, request: json(message),
          timing: { dispatchMonotonic: performance.now() / 1000, dispatchUtc: new Date().toISOString() } };
        recorder.rows.push(row);
        next(message);
        recorder.onDispatch?.(row);
      },
      start(metadata, _listener, next) {
        next(metadata, {
          onReceiveMessage(message, forward) { frames.push(json(message)); forward(message); },
          onReceiveStatus(status, forward) {
            row.timing.responseMonotonic = performance.now() / 1000;
            row.timing.responseUtc = new Date().toISOString();
            row.result = { kind: 'txn-program-receipt-v1', transport: 'grpc', complete: true, code: status.code, details: status.details,
              response: status.code !== 0 ? null : rpc === 'BatchGetDocuments' ? { responses: frames } : (frames[0] ?? {}),
              http: null, dispatchedRequests: 1, childPid: null, childReaped: false, workerExitCode: null, ipcComplete: true };
            row.outcomeClass = status.code === 0 ? 'OK' : [1, 2, 4, 13, 14].includes(status.code) ? 'UNKNOWN' : [3, 5, 9, 10].includes(status.code) ? 'REFUSED' : 'OTHER';
            const work = Promise.resolve().then(() => recorder.onStatus?.(row)).finally(() => forward(status));
            pending.add(work);
            work.finally(() => pending.delete(work)).catch(() => {});
          },
        });
      },
    });
  };
  recorder.drain = async () => { while (pending.size) await Promise.all([...pending]); };
  return recorder;
}

export async function recordAdminRetries({ host, project }) {
  localTarget(host, project);
  for (const [module, version] of [['firebase-admin', '14.3.0'], ['@google-cloud/firestore', '8.7.1'], ['@grpc/grpc-js', '1.14.4']]) {
    if ((module === 'firebase-admin' ? require('firebase-admin').SDK_VERSION : require(`${module}/package.json`).version) !== version) throw new Error('SDK dependency pin differs');
  }
  // Default credential construction is lazy. Explicit offline auth below prevents credential discovery.
  const { initializeApp, deleteApp } = require('firebase-admin/app');
  const { getFirestore } = require('firebase-admin/firestore');
  const grpc = require('@grpc/grpc-js');
  const recorder = rpcRecorder(grpc);
  const nonce = randomBytes(16).toString('hex'), ownerId = randomBytes(16).toString('hex');
  const apps = [], clients = [], attempts = [], documents = {};
  const originalHost = process.env.FIRESTORE_EMULATOR_HOST;
  const originalMtls = process.env.GOOGLE_API_USE_CLIENT_CERTIFICATE;
  process.env.FIRESTORE_EMULATOR_HOST = host;
  process.env.GOOGLE_API_USE_CLIENT_CERTIFICATE = 'false';
  let failureType = null, absent = true, graphComplete = false;
  let releaseWriter = () => {}, writerPending = Promise.resolve();
  let writerDispatched = () => {};
  try {
    for (const name of ['transaction', 'writer', 'witness']) {
      const app = initializeApp({ projectId: project }, `p17-${nonce}-${name}`);
      apps.push(app);
      const db = getFirestore(app);
      db.settings({ host, ssl: false, preferRest: false,
        auth: { getUniverseDomain: async () => 'googleapis.com' },
        'grpc.enable_retries': 0,
        'grpc.callInvocationTransformer': properties => {
          properties.callOptions.interceptors = [recorder.interceptor];
          properties.callOptions.deadline = new Date(Math.min(Number(properties.callOptions.deadline ?? Infinity), Date.now() + 30_000));
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
          documents[`${caseId}-${role}`] = { name: witness.doc(path).formattedName, state: 'baseline' };
          await witness.doc(path).create(fields(role, 'baseline'));
        });
      }
      const entry = { caseId, callbackCount: 0, refusalCode: 0, attempts: [], finalState: null };
      attempts.push(entry);
      let writerError = null;
      recorder.onDispatch = row => {
        if (row.caseId === caseId && row.client === 'writer' && row.rpc === 'Commit') writerDispatched();
      };
      recorder.onStatus = async row => {
        if (row.caseId !== caseId || row.client !== 'transaction' || row.rpc !== 'Commit') return;
        const attempt = entry.attempts[row.attempt - 1];
        attempt.refusalCode = row.result.code;
        if (row.attempt === 1 && caseId !== 'control') await writerPending;
        attempt.finalState = await readState();
      };
      try {
        await recorder.storage.run(context('transaction', 'transaction'), () => db.runTransaction(async transaction => {
          entry.callbackCount += 1;
          const count = entry.callbackCount;
          recorder.storage.getStore().attempt = count;
          const snapshot = await transaction.get(db.doc(paths.a));
          entry.attempts.push({ callbackCount: count, readState: snapshot.data(), refusalCode: null, finalState: null, rpcSequence: [] });
          if (count === 1) {
            if (caseId === 'control') {
              await recorder.storage.run(context('writer', 'writer'), () => writer.doc(paths.c).set(fields('c', 'writer')));
            } else {
              let ready, failReady;
              const dispatched = new Promise(resolve => { writerDispatched = resolve; });
              const writerReady = new Promise((resolve, reject) => { ready = resolve; failReady = reject; });
              const canCommit = new Promise(resolve => { releaseWriter = resolve; });
              writerPending = recorder.storage.run(context('writer', 'writer'), () => writer.runTransaction(async concurrent => {
                await concurrent.get(writer.doc(paths.b));
                concurrent.set(writer.doc(paths.a), fields('a', 'writer'));
                ready();
                await canCommit;
              }, { maxAttempts: 1 })).catch(error => { writerError = error.code ?? 'writer-failure'; failReady(error); });
              await writerReady;
              releaseWriter();
              await dispatched;
              // The first waiting committer wins strict's deadlock resolution.
              await new Promise(resolve => setTimeout(resolve, 200));
            }
          }
          transaction.set(db.doc(paths.b), fields('b', `transaction-${snapshot.data().state}`));
        }, { maxAttempts: spec.maxAttempts }));
      } catch (error) { entry.refusalCode = error.code ?? 'sdk-failure'; }
      finally { releaseWriter(); await writerPending; await recorder.drain(); }
      if (writerError !== null) throw new Error('concurrent writer did not complete');
      entry.finalState = await readState();
      for (const attempt of entry.attempts) {
        attempt.rpcSequence = recorder.rows.filter(row => row.caseId === caseId && row.client === 'transaction' && row.attempt === attempt.callbackCount).map(row => ({ sequence: row.sequence, rpc: row.rpc, code: row.result.code }));
      }
      recorder.onDispatch = recorder.onStatus = null;
    }
    graphComplete = true;
  } catch (error) { failureType = error.constructor.name; }
  finally {
    releaseWriter();
    await writerPending;
    recorder.onDispatch = recorder.onStatus = null;
    const witness = clients[2];
    for (const [role, document] of Object.entries(documents)) {
      try {
        await recorder.storage.run({ client: 'witness', site: `cleanup/${role}`, caseId: null, attempt: 0, phase: 'documentCleanup' }, async () => {
          const ref = witness.doc(document.name.split('/documents/')[1]);
          const snapshot = await ref.get();
          if (snapshot.exists) {
            if (snapshot.data().owner !== ownerId || snapshot.data().nonce !== nonce) throw new Error('cleanup ownership differs');
            await ref.delete({ lastUpdateTime: snapshot.updateTime });
          }
          recorder.storage.getStore().site += '/verify';
          if ((await ref.get()).exists) throw new Error('cleanup readback differs');
          document.state = null;
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
    for (const frame of row.result?.response?.responses ?? []) {
      if (frame.transaction) tokens[`${row.caseId}-${row.client}-${row.attempt}`] = { value: frame.transaction, transport: 'grpc', state: 'open', start: row.timing };
    }
    const token = Object.values(tokens).find(token => token.value === row.request.transaction);
    if (token && row.rpc === 'Commit' && row.result?.code === 0) token.state = 'committed';
    if (token && row.rpc === 'Rollback' && [0, 10].includes(row.result?.code)) token.state = row.result.code === 0 ? 'rolled-back' : 'released-refused';
  }
  const openTokens = Object.keys(tokens).filter(role => tokens[role].state === 'open');
  const unrecovered = !absent || unknown.length > 0 || openTokens.length > 0 || failureType !== null;
  return {
    kind: 'txn-program-recording-v1', complete: graphComplete && !unrecovered, graphComplete,
    program: 'FS-TRANSACTION-P17-ADMIN-SDK-RETRY', packetName: 'p17-admin-sdk-retry',
    sourceDigest: createHash('sha256').update(readFileSync(new URL('./admin_sdk_retry.mjs', import.meta.url))).update(readFileSync(new URL('../fs-listen-resume/listen_sdk_adapter.mjs', import.meta.url))).digest('hex'),
    corpusDigest: createHash('sha256').update(JSON.stringify(CASES)).digest('hex'), nonce, ownerId,
    observations: steps.filter(row => row.client === 'transaction' && row.rpc === 'Commit'), steps, cleanupSteps, attempts,
    tokens, documents, unknownStarts: unknown.filter(row => row.rpc === 'BatchGetDocuments' && row.request.newTransaction).map(row => row.sequence),
    unknownRollbacks: unknown.filter(row => row.rpc === 'Rollback').map(row => row.sequence), unknownCommits: unknown.filter(row => row.rpc === 'Commit').map(row => row.sequence),
    timingMode: 'wall-clock', timingSource: 'grpc-js-client-interceptor', openTokens, journalFailure: false,
    cleanup: { absent }, unrecovered, failureType, sandboxRequests: recorder.rows.length,
    phaseRequests: { observation: steps.length, tokenCleanup: 0, documentCleanup: cleanupSteps.length, management: 0, credential: 0 },
    runtime: { firebaseAdmin: '14.3.0', firestore: '8.7.1', grpcJs: '1.14.4', target: 'local', node: process.version },
  };
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  try {
    const [mode, output, ...extra] = process.argv.slice(2);
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
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
