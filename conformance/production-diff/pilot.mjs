#!/usr/bin/env node
import { promises as fs } from 'node:fs';
import net from 'node:net';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { CASE, selectCase } from './registry.mjs';
import { compareRecords, resultEnvelope, gateExitCode, renderReport, sha256,
  digestJson, requireThat, equal, safeCode } from './core.mjs';
import { prepare, stageLegacy, sourceUnchanged } from './legacy.mjs';
import { cleanEnvironment, newPrivateDirectory, readSource, publishJson, publish,
  runProcess, snapshotBinary } from './io.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '../..');
const CONFIG = { schemaVersion: 1, profile: 'strict',
  firestore: { edition: 'standard', apiMode: 'native', rules: 'firestore.rules' },
  daemon: { clockStart: '2026-01-02T03:04:05Z' } };
const RULES = "rules_version = '2';\nservice cloud.firestore { match /databases/{d}/documents { match /{x=**} { allow read, write: if false; } } }\n";

export function parseArgs(argv) {
  const mode = argv[0] ?? 'help';
  requireThat(['help', 'list', 'plan', 'replay', 'compare'].includes(mode), 'unknown-mode');
  const values = { mode, repo: ROOT, case: CASE.id, timeout: 180 };
  const options = new Map([['--repo', 'repo'], ['--case', 'case'], ['--binary', 'binary'],
    ['--out', 'out'], ['--run-dir', 'runDir'], ['--timeout', 'timeout']]);
  const seen = new Set();
  for (let i = 1; i < argv.length; i += 2) {
    requireThat(options.has(argv[i]) && !seen.has(argv[i]) && argv[i + 1] &&
      !argv[i + 1].startsWith('--'), 'invalid-arguments');
    seen.add(argv[i]); values[options.get(argv[i])] = argv[i + 1];
  }
  selectCase(values.case);
  values.timeout = Number(values.timeout);
  requireThat(Number.isInteger(values.timeout) && values.timeout >= 10 && values.timeout <= 600,
    'invalid-timeout');
  if (mode === 'replay') requireThat(values.binary && values.out && !values.runDir, 'replay-arguments');
  if (mode === 'compare') requireThat(values.runDir && values.out && !values.binary, 'compare-arguments');
  if (['help', 'list', 'plan'].includes(mode)) requireThat(!values.binary && !values.out && !values.runDir,
    'unexpected-execution-arguments');
  return values;
}

export function buildExecArgs(binary, directory, sessionEntry, node = process.execPath) {
  return { command: binary, args: [
    'exec', '--config', join(directory, 'fireemu.json'), '--project', CASE.project,
    '--only', 'firestore', '--firestore-port', '0', '--http-port', '0', '--ui-port', '0',
    '--hub-port', '0', '--', node, sessionEntry,
  ] };
}
async function portIsClosed(endpoint) {
  if (!/^http:\/\/127\.0\.0\.1:[1-9][0-9]{0,4}$/.test(endpoint ?? '')) return false;
  const u = new URL(endpoint);
  return await new Promise(done => {
    const socket = net.connect({ host: '127.0.0.1', port: Number(u.port) });
    let settled = false;
    const finish = value => { if (!settled) { settled = true; socket.destroy(); done(value); } };
    socket.setTimeout(1000, () => finish(false));
    socket.once('connect', () => finish(false));
    socket.once('error', e => finish(e.code === 'ECONNREFUSED'));
  });
}

export function verifySession(session, prepared, localBytes) {
  requireThat(typeof session?.completed === 'boolean' &&
    (session.failure === null || typeof session.failure === 'string'), 'session-completion-shape');
  requireThat(!session.completed || session.failure === null, 'contradictory-session-completion');
  requireThat(session?.schema === 'fireemu-production-diff-session-v1' &&
    session.caseId === prepared.entry.id && session.programDigest === digestJson(prepared.program) &&
    session.localSha256 === sha256(localBytes), 'local-record-binding');
  requireThat(session.productionRequests === 0 && session.requestCount === 7 &&
    Array.isArray(session.requests) && session.requests.length === 7, 'local-request-count');
  requireThat(session.requests[0]?.phase === 'reset' && session.requests[0].status >= 200 &&
    session.requests[0].status < 300 && session.requests[1]?.phase === 'seed' &&
    session.requests[1].status >= 200 && session.requests[1].status < 300, 'local-setup-unconfirmed');
  requireThat(equal(session.requests.slice(2).map(row => row.phase), prepared.entry.stepIds),
    'local-operation-sequence');
  requireThat(session.cleanup?.state !== 'confirmed' ||
    (equal(session.cleanup.absent, prepared.entry.ownedDocuments) &&
      session.cleanup.requests === prepared.entry.ownedDocuments.length + 1), 'local-cleanup-binding');
}

async function replay(prepared, options, directory) {
  await stageLegacy(prepared, join(directory, 'legacy'));
  await publishJson(join(directory, 'program.json'), prepared.program);
  await publishJson(join(directory, 'programs.json'), [prepared.program]);
  await publishJson(join(directory, 'fireemu.json'), CONFIG);
  await publish(join(directory, 'firestore.rules'), RULES);
  const binaryPath = join(directory, 'fireemu');
  const artifact = await snapshotBinary(options.binary, binaryPath);
  const startedAt = new Date().toISOString();
  const { command, args } = buildExecArgs(binaryPath, directory, join(HERE, 'local-session.mjs'));
  const processResult = await runProcess(command, args, { cwd: directory,
    env: { ...cleanEnvironment(directory), PILOT_RUN_DIR: directory }, timeoutMs: options.timeout * 1000 });
  await publish(join(directory, 'process.log'), processResult.log);
  let session, localBytes;
  try {
    session = JSON.parse(await readSource(directory, 'session-result.json', 1024 * 1024));
    localBytes = await readSource(directory, 'local.json', 4 * 1024 * 1024);
    verifySession(session, prepared, localBytes);
  } catch { throw new Error('local-execution-incomplete'); }
  const portClosed = await portIsClosed(session.endpoint);
  const unchanged = await sourceUnchanged(options.repo, prepared.entry, prepared.state, prepared.provenance.implementation.adapterSha256);
  const execution = { origin: 'new-local-process', freshLocalExecution: true,
    state: processResult.code === 0 && !processResult.reason && session.completed && unchanged
      ? 'completed' : 'failed',
    startedAt, finishedAt: new Date().toISOString(),
    failure: processResult.reason ?? session.failure ?? (!unchanged ? 'source-changed' : null),
    process: { state: processResult.state === 'stopped' && portClosed ? 'stopped' : 'unconfirmed',
      exitCode: processResult.code, signal: processResult.signal, listenerClosed: portClosed },
    cleanup: session.cleanup, artifact, sourceUnchanged: unchanged,
    localSha256: sha256(localBytes), configSha256: digestJson(CONFIG),
    rulesSha256: sha256(RULES), requestCount: session.requestCount, cleanupRequests: session.cleanup.requests,
    networkScope: 'pinned-Node-recorder-with-owned-loopback-guard; not-an-OS-sandbox',
  };
  const record = { schema: 'fireemu-production-diff-recording-v1', caseId: prepared.entry.id,
    programDigest: digestJson(prepared.program), productionProjectionDigest: digestJson(prepared.production),
    execution, provenance: prepared.provenance,
    sessionSha256: sha256(await readSource(directory, 'session-result.json')) };
  await publishJson(join(directory, 'recording.json'), record);
  return { actual: JSON.parse(localBytes), execution, provenance: prepared.provenance };
}

async function loadRecording(prepared, runDir) {
  const recording = JSON.parse(await readSource(runDir, 'recording.json', 1024 * 1024));
  const bytes = await readSource(runDir, 'local.json', 4 * 1024 * 1024);
  const sessionBytes = await readSource(runDir, 'session-result.json', 1024 * 1024);
  verifySession(JSON.parse(sessionBytes), prepared, bytes);
  requireThat(recording.schema === 'fireemu-production-diff-recording-v1' &&
    recording.caseId === prepared.entry.id && recording.programDigest === digestJson(prepared.program) &&
    recording.productionProjectionDigest === digestJson(prepared.production) &&
    recording.execution?.localSha256 === sha256(bytes) && recording.sessionSha256 === sha256(sessionBytes) &&
    recording.execution.configSha256 === digestJson(CONFIG) && recording.execution.rulesSha256 === sha256(RULES) &&
    equal(recording.provenance?.implementation?.adapterSha256 ?? null, prepared.provenance.implementation.adapterSha256) &&
    recording.provenance?.implementation?.comparatorSliceSha256 === prepared.entry.comparatorSliceSha256 &&
    recording.provenance.implementation.sessionBlob === prepared.entry.sessionBlob &&
    recording.provenance.implementation.credentialsBlob === prepared.entry.credentialsBlob &&
    equal(recording.provenance?.oracle, prepared.provenance.oracle), 'recording-contract-mismatch');
  const session = JSON.parse(sessionBytes);
  requireThat(equal(recording.execution.cleanup, session.cleanup), 'recording-cleanup-contradiction');
  requireThat(recording.execution.state !== 'completed' || (session.completed === true &&
    session.failure === null && recording.execution.process?.exitCode === 0 &&
    recording.execution.process.signal === null && recording.execution.sourceUnchanged === true),
    'recording-execution-contradiction');
  return { actual: JSON.parse(bytes),
    execution: { ...recording.execution, origin: 'stored-local-process', freshLocalExecution: false },
    provenance: { ...recording.provenance, recomparisonRepository: prepared.state,
      recordingSha256: sha256(await readSource(runDir, 'recording.json')) } };
}

export async function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  if (options.mode === 'help') {
    console.log('pilot.mjs list | plan | replay --binary /absolute/fireemu --out /absolute/new-dir | compare --run-dir /absolute/prior-run --out /absolute/new-dir [--repo /repo] [--case ' + CASE.id + ']');
    return 0;
  }
  if (options.mode === 'list') {
    console.log(JSON.stringify({ cases: [CASE], productionExecuted: false }, null, 2)); return 0;
  }
  let directory;
  try {
    if (options.out) directory = await newPrivateDirectory(options.out, options.repo);
    const prepared = await prepare(options.repo);
    if (options.mode === 'plan') {
      console.log(JSON.stringify({ case: CASE.id, readyForLocalReplay: true,
        operations: prepared.program.steps.length, source: prepared.state,
        evidenceKind: 'saved-production-reference', productionRequests: 0,
        compared: CASE.compared, notEstablished: CASE.notEstablished,
        prerequisites: ['caller-built native fireemu; build provenance is a separate obligation'] }, null, 2));
      return 0;
    }
    const run = options.mode === 'replay' ? await replay(prepared, options, directory)
      : await loadRecording(prepared, options.runDir);
    const comparison = compareRecords({ ...prepared, actual: run.actual });
    const result = resultEnvelope({ entry: CASE, comparison, execution: run.execution, provenance: run.provenance });
    await publishJson(join(directory, 'result.json'), result);
    await publish(join(directory, 'report.md'), renderReport(result));
    console.log(JSON.stringify({ caseId: CASE.id, verdict: result.comparison.verdict,
      counts: result.comparison.counts, gatePassed: result.gatePassed,
      productionExecuted: false, freshLocalExecution: run.execution.freshLocalExecution }));
    return gateExitCode(result);
  } catch (error) {
    const failure = { schema: 'fireemu-production-diff-failure-v1', caseId: CASE.id,
      verdict: 'INDETERMINATE', code: safeCode(error), gatePassed: false,
      productionExecuted: false, nativeReplayAccepted: false };
    if (directory) await publishJson(join(directory, 'failure.json'), failure).catch(() => {});
    console.error(JSON.stringify(failure)); return 2;
  }
}
if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  main().then(code => { process.exitCode = code; }, () => {
    console.error('{"verdict":"INDETERMINATE","code":"invalid-invocation","gatePassed":false}');
    process.exitCode = 2;
  });
}
