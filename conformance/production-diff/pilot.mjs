#!/usr/bin/env node
import { statSync, writeFileSync } from "node:fs";
import net from "node:net";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { CASE, CASES, selectCase } from "./registry.mjs";
import {
  compareRecords,
  resultEnvelope,
  gateExitCode,
  renderReport,
  sha256,
  digestJson,
  requireThat,
  equal,
  safeCode,
  expectedCleanupDocuments,
} from "./core.mjs";
import { prepare, stageLegacy, sourceUnchanged } from "./legacy.mjs";
import {
  prepareCommitTransform,
  commitTransformSourceUnchanged,
  compareCommitTransform,
} from "./commit-transform.mjs";
import { prepareG0, compareG0, g0SourceUnchanged } from "./g0.mjs";
import {
  cleanEnvironment,
  newPrivateDirectory,
  readSource,
  publishJson,
  publish,
  runProcess,
  snapshotBinary,
} from "./io.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "../..");
const CONFIG = {
  schemaVersion: 1,
  profile: "strict",
  firestore: { edition: "standard", apiMode: "native", rules: "firestore.rules" },
  daemon: { clockStart: "2026-01-02T03:04:05Z" },
};
export function configForCase(entry = CASE) {
  const config = structuredClone(CONFIG);
  if (entry.indexFilePath) {
    requireThat(
      entry.indexFilePath === "conformance/firestore.indexes.json" &&
        entry.indexFileBlob === "7c1ef93940752d8981ae29cfea40c210f27560f8" &&
        entry.indexFileSha256 === "sha256-8a4d4bd7a72c3ce2bed4e0f8c4adc0cdb3a7c428477578295e44a11ae063d01c" &&
        entry.indexFilesDigest === "sha256-ad4a66f22bbfb41fd0a2e7585ed0cbd82f88e854a915049ee724e9f2afd4d01a" &&
        entry.indexFileBytes === 2484,
      "index-file-config-pin",
    );
    config.firestore.indexFile = "firestore.indexes.json";
  }
  return config;
}
const RULES =
  "rules_version = '2';\nservice cloud.firestore { match /databases/{d}/documents { match /{x=**} { allow read, write: if false; } } }\n";

export function parseArgs(argv) {
  const mode = argv[0] ?? "help";
  requireThat(["help", "list", "plan", "replay", "compare"].includes(mode), "unknown-mode");
  const values = { mode, repo: ROOT, case: CASE.id, timeout: 180 };
  const options = new Map([
    ["--repo", "repo"],
    ["--case", "case"],
    ["--binary", "binary"],
    ["--out", "out"],
    ["--run-dir", "runDir"],
    ["--timeout", "timeout"],
  ]);
  const seen = new Set();
  for (let i = 1; i < argv.length; i += 2) {
    requireThat(
      options.has(argv[i]) && !seen.has(argv[i]) && argv[i + 1] && !argv[i + 1].startsWith("--"),
      "invalid-arguments",
    );
    seen.add(argv[i]);
    values[options.get(argv[i])] = argv[i + 1];
  }
  selectCase(values.case);
  values.timeout = Number(values.timeout);
  requireThat(
    Number.isInteger(values.timeout) && values.timeout >= 10 && values.timeout <= 600,
    "invalid-timeout",
  );
  if (mode === "replay")
    requireThat(values.binary && values.out && !values.runDir, "replay-arguments");
  if (mode === "compare")
    requireThat(values.runDir && values.out && !values.binary, "compare-arguments");
  if (["help", "list", "plan"].includes(mode))
    requireThat(!values.binary && !values.out && !values.runDir, "unexpected-execution-arguments");
  return values;
}

export function buildExecArgs(
  binary,
  directory,
  sessionEntry,
  node = process.execPath,
  project = CASE.project,
  services = "firestore",
) {
  return {
    command: binary,
    args: [
      "exec",
      "--config",
      join(directory, "fireemu.json"),
      "--project",
      project,
      "--only",
      services,
      "--firestore-port",
      "0",
      "--http-port",
      "0",
      "--ui-port",
      "0",
      "--hub-port",
      "0",
      "--logging-port",
      "0",
      "--",
      node,
      sessionEntry,
    ],
  };
}
async function portIsClosed(endpoint) {
  if (!/^http:\/\/127\.0\.0\.1:[1-9][0-9]{0,4}$/.test(endpoint ?? "")) return false;
  const u = new URL(endpoint);
  return await new Promise((done) => {
    const socket = net.connect({ host: "127.0.0.1", port: Number(u.port) });
    let settled = false;
    const finish = (value) => {
      if (!settled) {
        settled = true;
        socket.destroy();
        done(value);
      }
    };
    socket.setTimeout(1000, () => finish(false));
    socket.once("connect", () => finish(false));
    socket.once("error", (e) => finish(e.code === "ECONNREFUSED"));
  });
}

export function verifyG0ProgramDigest(sessionDigest, preparedProgram) {
  requireThat(sessionDigest === digestJson(preparedProgram), "local-record-binding");
}

export function verifySession(session, prepared, localBytes) {
  const entry = prepared.entry;
  // The setup prefix (e.g. batch-write's reset+seed) is case-specific; a case with no separate
  // setup phase (e.g. commit-transform, whose plan's own steps are the setup) declares [].
  const setupPhases = entry.sessionSetupPhases ?? ["reset", "seed"];
  const cleanupResetRequests = entry.cleanupResetRequests ?? 1;
  requireThat(
    typeof session?.completed === "boolean" &&
      (session.failure === null || typeof session.failure === "string"),
    "session-completion-shape",
  );
  requireThat(!session.completed || session.failure === null, "contradictory-session-completion");
  requireThat(
    session?.schema === "fireemu-production-diff-session-v1" &&
      session.caseId === entry.id &&
      session.localSha256 === sha256(localBytes),
    "local-record-binding",
  );
  verifyG0ProgramDigest(session.programDigest, prepared.program);
  const expectedCount = setupPhases.length + entry.stepIds.length;
  requireThat(
    session.productionRequests === 0 &&
      session.requestCount === expectedCount &&
      Array.isArray(session.requests) &&
      session.requests.length === expectedCount,
    "local-request-count",
  );
  for (let i = 0; i < setupPhases.length; i++)
    requireThat(
      session.requests[i]?.phase === setupPhases[i] &&
        session.requests[i].status >= 200 &&
        session.requests[i].status < 300,
      "local-setup-unconfirmed",
    );
  requireThat(
    equal(
      session.requests.slice(setupPhases.length).map((row) => row.phase),
      entry.stepIds,
    ),
    "local-operation-sequence",
  );
  const cleanupDocuments = expectedCleanupDocuments(entry, session.requests);
  requireThat(
    session.cleanup?.state !== "confirmed" ||
      (equal(session.cleanup.absent, cleanupDocuments) &&
        session.cleanup.requests === cleanupDocuments.length + cleanupResetRequests),
    "local-cleanup-binding",
  );
}

async function replay(prepared, options, directory) {
  const entry = prepared.entry;
  const build = prepared.provenance.implementation.build;
  if (entry.adapter === "g0")
    requireThat(
      build &&
        typeof build.retainedManifestSha256 === "string" &&
        typeof build.artifactProfile === "string" &&
        typeof build.runtimeSourceCommit === "string" &&
        typeof build.sourceInputsDigest === "string",
      "g0-build-provenance-unavailable",
    );
  if (entry.adapter === "batch-write") await stageLegacy(prepared, join(directory, "legacy"));
  await publishJson(join(directory, "program.json"), prepared.program);
  await publishJson(join(directory, "programs.json"), [prepared.program]);
  const config = configForCase(entry);
  await publishJson(join(directory, "fireemu.json"), config);
  await publish(join(directory, "firestore.rules"), RULES);
  const binaryPath = join(directory, "fireemu");
  const artifact = await snapshotBinary(options.binary, binaryPath);
  if (entry.adapter === "g0")
    requireThat(
      prepared.provenance.implementation.build?.artifactSha256 === artifact.sha256,
      "g0-artifact-snapshot-mismatch",
    );
  const startedAt = new Date().toISOString();
  const { command, args } = buildExecArgs(
    binaryPath,
    directory,
    join(HERE, entry.sessionScript ?? "local-session.mjs"),
    process.execPath,
    entry.project,
    entry.adapter === "g0" ? "auth,firestore" : "firestore",
  );
  const cleanEnv = cleanEnvironment(directory);
  const processResult = await runProcess(command, args, {
    cwd: directory,
    env: {
      ...cleanEnv,
      PILOT_RUN_DIR: directory,
      PILOT_CASE_ID: entry.id,
      PILOT_REPO: options.repo,
      ...(entry.adapter === "g0"
        ? {
            PILOT_PROGRAM_DIGEST: digestJson(prepared.program),
            G0_RETAINED_MANIFEST_SHA256: build.retainedManifestSha256,
            G0_ARTIFACT_PROFILE: build.artifactProfile,
            G0_RUNTIME_SOURCE_COMMIT: build.runtimeSourceCommit,
            G0_SOURCE_INPUTS_DIGEST: build.sourceInputsDigest,
          }
        : {}),
    },
    timeoutMs: options.timeout * 1000,
    onSpawn:
      entry.adapter === "g0"
        ? ({ pid }) => {
            requireThat(Number.isInteger(pid) && pid > 0, "g0-spawn-pid-unavailable");
            const info = statSync(directory);
            const receipt = {
              schema: "fireemu-g0-launch-v1",
              pid,
              command,
              args: [...args],
              binarySha256: artifact.sha256,
              sourceCommit: prepared.state.head,
              configSha256: sha256(Buffer.from(JSON.stringify(config, null, 2) + "\n")),
              rulesSha256: sha256(RULES),
              environmentSha256: digestJson(cleanEnv),
              retainedManifestSha256: build?.retainedManifestSha256,
              artifactProfile: build?.artifactProfile,
              runtimeSourceCommit: build?.runtimeSourceCommit,
              sourceInputsDigest: build?.sourceInputsDigest,
              runDirectory: { path: directory, dev: info.dev, ino: info.ino, mode: info.mode & 0o777 },
              import: null,
              exportOnExit: null,
            };
            const bytes = Buffer.from(JSON.stringify(receipt) + "\n");
            writeFileSync(join(directory, "launch-receipt.json"), bytes, { flag: "wx", mode: 0o600 });
          }
        : null,
  });
  await publish(join(directory, "process.log"), processResult.log);
  let session, localBytes;
  try {
    session = JSON.parse(await readSource(directory, "session-result.json", 1024 * 1024));
    localBytes = await readSource(directory, "local.json", 4 * 1024 * 1024);
    verifySession(session, prepared, localBytes);
  } catch {
    throw new Error("local-execution-incomplete");
  }
  const portClosed = await portIsClosed(session.endpoint);
  const unchanged =
    entry.adapter === "batch-write"
      ? await sourceUnchanged(
          options.repo,
          prepared.entry,
          prepared.state,
          prepared.provenance.implementation.adapterSha256,
        )
      : entry.adapter === "commit-transform"
        ? await commitTransformSourceUnchanged(
          options.repo,
          prepared.entry,
          prepared.state,
          prepared.provenance.implementation.adapterSha256,
        )
        : await g0SourceUnchanged(
            options.repo,
            prepared.state,
            prepared.provenance.implementation.adapterSha256,
          );
  const execution = {
    origin: "new-local-process",
    freshLocalExecution: true,
    state:
      processResult.code === 0 && !processResult.reason && session.completed && unchanged
        ? "completed"
        : "failed",
    startedAt,
    finishedAt: new Date().toISOString(),
    failure: processResult.reason ?? session.failure ?? (!unchanged ? "source-changed" : null),
    process: {
      state: processResult.state === "stopped" && portClosed ? "stopped" : "unconfirmed",
      exitCode: processResult.code,
      signal: processResult.signal,
      listenerClosed: portClosed,
    },
    ...(entry.adapter === "g0"
      ? { launchReceiptSha256: sha256(await readSource(directory, "launch-receipt.json", 128 * 1024)) }
      : {}),
    cleanup: session.cleanup,
    artifact,
    sourceUnchanged: unchanged,
    localSha256: sha256(localBytes),
    configSha256: digestJson(config),
    rulesSha256: sha256(RULES),
    requestCount: session.requestCount,
    cleanupRequests: session.cleanup.requests,
    networkScope: "pinned-Node-recorder-with-owned-loopback-guard; not-an-OS-sandbox",
  };
  const record = {
    schema: "fireemu-production-diff-recording-v1",
    caseId: prepared.entry.id,
    programDigest: digestJson(prepared.program),
    productionProjectionDigest: digestJson(prepared.production),
    execution,
    provenance: prepared.provenance,
    sessionSha256: sha256(await readSource(directory, "session-result.json")),
  };
  await publishJson(join(directory, "recording.json"), record);
  return { actual: JSON.parse(localBytes), execution, provenance: prepared.provenance };
}

async function loadRecording(prepared, runDir) {
  const recording = JSON.parse(await readSource(runDir, "recording.json", 1024 * 1024));
  const bytes = await readSource(runDir, "local.json", 4 * 1024 * 1024);
  const sessionBytes = await readSource(runDir, "session-result.json", 1024 * 1024);
  verifySession(JSON.parse(sessionBytes), prepared, bytes);
  requireThat(
    recording.schema === "fireemu-production-diff-recording-v1" &&
      recording.caseId === prepared.entry.id &&
      recording.programDigest === digestJson(prepared.program) &&
      recording.productionProjectionDigest === digestJson(prepared.production) &&
      recording.execution?.localSha256 === sha256(bytes) &&
      recording.sessionSha256 === sha256(sessionBytes) &&
      recording.execution.configSha256 === digestJson(configForCase(prepared.entry)) &&
      recording.execution.rulesSha256 === sha256(RULES) &&
      equal(
        recording.provenance?.implementation?.adapterSha256 ?? null,
        prepared.provenance.implementation.adapterSha256,
      ) &&
      recording.provenance?.implementation?.comparatorSliceSha256 ===
        prepared.entry.comparatorSliceSha256 &&
      recording.provenance.implementation.sessionBlob === prepared.entry.sessionBlob &&
      recording.provenance.implementation.credentialsBlob === prepared.entry.credentialsBlob &&
      equal(
        recording.provenance.implementation.indexFile ?? null,
        prepared.provenance.implementation.indexFile ?? null,
      ) &&
      equal(recording.provenance?.oracle, prepared.provenance.oracle),
    "recording-contract-mismatch",
  );
  const session = JSON.parse(sessionBytes);
  requireThat(
    equal(recording.execution.cleanup, session.cleanup),
    "recording-cleanup-contradiction",
  );
  requireThat(
    recording.execution.state !== "completed" ||
      (session.completed === true &&
        session.failure === null &&
        recording.execution.process?.exitCode === 0 &&
        recording.execution.process.signal === null &&
        recording.execution.sourceUnchanged === true),
    "recording-execution-contradiction",
  );
  return {
    actual: JSON.parse(bytes),
    execution: {
      ...recording.execution,
      origin: "stored-local-process",
      freshLocalExecution: false,
    },
    provenance: {
      ...recording.provenance,
      recomparisonRepository: prepared.state,
      recordingSha256: sha256(await readSource(runDir, "recording.json")),
    },
  };
}

export async function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  if (options.mode === "help") {
    console.log(
      "pilot.mjs list | plan | replay --binary /absolute/fireemu --out /absolute/new-dir | compare --run-dir /absolute/prior-run --out /absolute/new-dir [--repo /repo] [--case <id>], one of " +
        CASES.map((c) => c.id).join(" | "),
    );
    return 0;
  }
  if (options.mode === "list") {
    console.log(JSON.stringify({ cases: CASES, productionExecuted: false }, null, 2));
    return 0;
  }
  let directory;
  let entry;
  try {
    entry = selectCase(options.case);
    if (options.out) directory = await newPrivateDirectory(options.out, options.repo);
    const prepared =
      entry.adapter === "batch-write"
        ? await prepare(options.repo, entry)
        : entry.adapter === "commit-transform"
          ? await prepareCommitTransform(options.repo, entry)
          : await prepareG0(
              options.repo,
              entry,
              options.binary ?? null,
              options.mode === "replay" || options.mode === "compare",
            );
    if (options.mode === "plan") {
      console.log(
        JSON.stringify(
          {
            case: entry.id,
            readyForLocalReplay: true,
            operations:
              entry.adapter === "batch-write"
                ? prepared.program.steps.length
                : entry.adapter === "commit-transform"
                  ? prepared.program.observation.length + prepared.program.recovery.length
                  : Object.values(prepared.program.jobs).reduce(
                      (total, job) => total + job.observation.length,
                      0,
                    ),
            source: prepared.state,
            evidenceKind: entry.evidenceKind,
            oracleKind: entry.oracleKind,
            productionRequests: 0,
            compared: entry.compared,
            notEstablished: entry.notEstablished,
            prerequisites: [
              "caller-built native fireemu; build provenance is a separate obligation",
            ],
          },
          null,
          2,
        ),
      );
      return 0;
    }
    const run =
      options.mode === "replay"
        ? await replay(prepared, options, directory)
        : await loadRecording(prepared, options.runDir);
    const comparison =
      entry.adapter === "batch-write"
        ? compareRecords({ ...prepared, actual: run.actual })
        : entry.adapter === "commit-transform"
          ? compareCommitTransform({ ...prepared, actual: run.actual })
          : compareG0({
              ...prepared,
              actual: run.actual,
              repo: options.repo,
              execution: run.execution,
              build: prepared.provenance.implementation.build,
            });
    const result = resultEnvelope({
      entry,
      comparison,
      execution: run.execution,
      provenance: run.provenance,
    });
    await publishJson(join(directory, "result.json"), result);
    await publish(join(directory, "report.md"), renderReport(result));
    console.log(
      JSON.stringify({
        caseId: entry.id,
        verdict: result.comparison.verdict,
        counts: result.comparison.counts,
        gatePassed: result.gatePassed,
        productionExecuted: false,
        freshLocalExecution: run.execution.freshLocalExecution,
      }),
    );
    return gateExitCode(result);
  } catch (error) {
    const failure = {
      schema: "fireemu-production-diff-failure-v1",
      caseId: entry?.id ?? options.case,
      verdict: "INDETERMINATE",
      code: safeCode(error),
      gatePassed: false,
      productionExecuted: false,
      nativeReplayAccepted: false,
    };
    if (directory) await publishJson(join(directory, "failure.json"), failure).catch(() => {});
    console.error(JSON.stringify(failure));
    return 2;
  }
}
if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  main().then(
    (code) => {
      process.exitCode = code;
    },
    () => {
      console.error('{"verdict":"INDETERMINATE","code":"invalid-invocation","gatePassed":false}');
      process.exitCode = 2;
    },
  );
}
