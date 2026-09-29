import { open, lstat, mkdir } from "node:fs/promises";
import { createCaptureJournal } from "./capture-journal.mjs";
import { buildCorpus } from "./corpus.mjs";
import { createController } from "./controller.mjs";
import { createRunnerDelegates } from "./delegates.mjs";
import { createDispatchGate } from "./dispatch-gate.mjs";
import { buildFullRequestManifest } from "./full-manifest.mjs";
import { confirmCleanClose, leaseTransport, withLockedAdmission } from "./locked-run.mjs";
import { createPreflightJudge } from "./preflight-judge.mjs";
import { generateRunSecrets, loadPrivateInputs, readAdcFile } from "./private-inputs.mjs";
import { createRecordingUsage } from "./recording-usage.mjs";
import { createReservationJournal } from "./reservation-journal.mjs";
import { createResourceLedger } from "./resource-ledger.mjs";
import { createRunLedger } from "./run-ledger.mjs";
import { buildRefTables, createRuntimeRefStore } from "./runtime-refs.mjs";
import { buildRecoverySchedule, buildSchedule } from "./schedule.mjs";
import { createTargetBuilder } from "./target.mjs";
import { plain } from "./shape.mjs";

// The one entry point that wires a recording together: the private packet and the ADC file are loaded, the manifest is built
// for this run, the project locks and the live admission are taken (the lock set must be exactly the packet's), the two
// journals are opened in the caller's private run directory, and the controller, the gate, the delegates, the credential
// provider and the preflight judge are assembled. The only network capability is the `transport` the caller passes in; it
// reaches the wire only through the gate, inside a leased, counted, journalled attempt. Nothing here sends by itself: the
// caller decides to run, and to recover, inside `use`, and the locks are released only after a confirmed clean close.
const KEYS = ["inputsPath", "closure", "runId", "sourceCommit", "packet", "review", "readLedger", "locks", "usagePath", "directory", "transport", "clock"];
const bad = () => { throw new Error("invalid assembled run options"); };

export async function withAssembledRun(options, use, { randomBytes } = {}) {
  if (!plain(options) || Reflect.ownKeys(options).length !== KEYS.length || !KEYS.every((key) => Object.hasOwn(options, key)) || typeof use !== "function") bad();
  const { inputsPath, closure, runId, sourceCommit, packet, review, readLedger, locks, usagePath, directory, transport, clock } = options;
  if (
    typeof inputsPath !== "string" || !plain(closure) || typeof runId !== "string" || !/^[a-z0-9][a-z0-9-]{0,47}$/.test(runId) || typeof sourceCommit !== "string" || !/^[a-f0-9]{40}$/.test(sourceCommit) ||
    !plain(packet) || packet.sourceCommit !== sourceCommit || typeof readLedger !== "function" || !plain(locks) || typeof usagePath !== "string" || typeof directory !== "string" ||
    typeof transport?.send !== "function" || typeof transport?.validate !== "function" || !plain(clock) || typeof clock.nowSeconds !== "function" || typeof clock.waitUntilSeconds !== "function" || typeof clock.sleep !== "function"
  ) bad();

  // Everything that can refuse for a reason of its own happens before a lock is taken or a marker is written.
  const inputs = await loadPrivateInputs({ path: inputsPath });
  const adc = await readAdcFile({ path: inputs.adcPath });
  const secrets = generateRunSecrets(randomBytes === undefined ? undefined : { randomBytes });
  const binding = { bucket: inputs.bucket.name, prefix: `STORAGE-RULES/${runId}/`, uidA: `storage-rules-${runId}-user-a`, uidB: `storage-rules-${runId}-user-b` };
  const manifest = buildFullRequestManifest(buildCorpus(binding), closure, {
    runId, sourceCommit, queryProjectNumber: inputs.projects.query.projectNumber, idpProjectNumber: inputs.projects.idp.projectNumber,
    queryApiKeyId: inputs.projects.query.apiKeyId, idpApiKeyId: inputs.projects.idp.apiKeyId,
  });
  const usage = createRecordingUsage({ path: usagePath, packetSha256: packet.packetSha256 });

  return withLockedAdmission({ locks: { ...locks, projects: [...packet.projects], taskId: packet.taskId, packetId: packet.packetName, sourceCommit: packet.sourceCommit }, readLedger, packet, review, runId, usage }, async ({ admission, lease }) => {
    const requestIds = manifest.rows.map((row) => row.id);
    const reservations = await createReservationJournal({ directory, runId, sourceCommit, manifestDigest: manifest.sha256, requestIds, preflightIds: manifest.preflightIds, io: { open, lstat } });
    let capture;
    try {
      capture = await createCaptureJournal({ directory, runId, sourceCommit, manifestDigest: manifest.sha256, digestSalt: secrets.digestSalt, requestIds, io: { open, lstat, mkdir } });
    } catch (error) { await reservations.close().catch(() => {}); throw error; }
    const closeJournals = async () => { await capture.close().catch(() => {}); await reservations.close().catch(() => {}); };
    try {
      const targets = createTargetBuilder({ manifest, digestSalt: secrets.digestSalt });
      const tables = buildRefTables(manifest);
      const refs = createRuntimeRefStore({ tables, runId, digestSalt: secrets.digestSalt, writeProof: (proof) => capture.writeProof(proof) });
      const objects = createResourceLedger({ manifest });
      const runLedger = createRunLedger({ manifest, objects });
      let assembled;
      const gate = createDispatchGate({
        reservations: { onStarted: reservations.onStarted, onReserve: reservations.onReserve, onTerminal: reservations.onTerminal },
        capture, transport: leaseTransport(lease, transport), targets,
        credentials: { headersFor: (credential, context) => assembled.credentials.headersFor(credential, context) },
        preflightIds: manifest.preflightIds, admission,
      });
      assembled = createRunnerDelegates({
        gate, adc, apiKeys: { "fireemu-oracle-query": inputs.secrets.apiKeys.query, "fireemu-oracle-idp": inputs.secrets.apiKeys.idp }, passwords: secrets.passwords, digestSalt: secrets.digestSalt,
        runId, nowSeconds: clock.nowSeconds, waitUntilSeconds: clock.waitUntilSeconds, evidence: capture, malformed: secrets.malformed,
      });
      const judge = createPreflightJudge({ inputs });
      const controller = createController({
        manifest, schedule: buildSchedule(manifest), recoverySchedule: buildRecoverySchedule(manifest), gate, targets, refs, tables, objects, run: runLedger, capture,
        delegates: assembled.delegates, wait: clock.sleep, credentials: assembled.credentials, judgePreflight: judge,
      });
      const recording = Object.freeze({
        runId, manifest, controller, gate, admission,
        run: () => controller.run(),
        recover: () => controller.recover(),
        confirmCleanClose: (result) => confirmCleanClose(lease, result),
      });
      return await use(recording);
    } finally { await closeJournals(); }
  });
}
