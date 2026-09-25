import { execFile } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import {
  appendFile,
  open,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  rmdir,
  stat,
  writeFile,
} from "node:fs/promises";
import { createRequire } from "node:module";
import { promisify } from "node:util";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { CONFORMANCE_DIR, RUNS_DIR } from "./config.mjs";
import {
  compareSandboxArtifact,
  freezeSandboxFixture,
  validateSandboxCorpus,
} from "./fs-data-write-sandbox.mjs";
import { validateStreamRecipes } from "./firestore-probe/stream-session.mjs";
import {
  legacyManagedClearNames,
  managedClearScope,
  managedShrinkScope,
} from "./firestore-probe/sandbox-session.mjs";

const execFileAsync = promisify(execFile);
const require = createRequire(import.meta.url);
const ROOT = resolve(CONFORMANCE_DIR, "..");
const TASK_ID = "FS-DATA-WRITE-SANDBOX";
// Owner-approved exception for the stable FS-DATA-WRITE-SANDBOX task (addendum 4).
const TASK_LIMIT_USD = 30;
const SANDBOX_PROJECT = "fireemu-oracle-sbx";
const RECORDED_PROJECT = "demo-firestore-probe";
// The declared REST observation steps need pre/final clears; the 100-level document chain adds
// about 200 recursive public-API reads, while the other bounded programs add smaller clears.
// Leave headroom, but reject attempt 1001 before the network send.
const REST_CAP = 1000;
const ATTEMPT_ESTIMATE_USD = 0.5;
const HISTORICAL_UNKNOWN_HOLD_USD = 9.24;
const HISTORICAL_UNKNOWN_HOLD_ID = "FS-DATA-WRITE-SANDBOX-2026-09-24-HISTORICAL-UNKNOWN";
const V3_MANAGED_CLEAR_CAP = 400;
const DELTA_V3_HTTP_CAP = 430;
const DELTA_DELETE_ROUTES = ["rest", "commit", "batch-write"];
const DELTA_DELETE_COUNTS = [12112, 12113];
const DELTA_STREAM_ID = "writes/write-stream-terminal/response-before-half-close";
export const MAX_STREAM_FRAMES = 9;
const sha256 = (value) => createHash("sha256").update(value).digest("hex");

export function assertMatchingSandboxCorpus(fixture, currentCorpus, localCorpus) {
  const currentDigest = sha256(JSON.stringify(currentCorpus));
  if (fixture?.evidence?.corpusSha256 !== currentDigest) {
    throw new Error("fixture corpus differs from the current recipe");
  }
  if (sha256(JSON.stringify(localCorpus)) !== currentDigest) {
    throw new Error("local corpus differs from the current recipe");
  }
  return currentDigest;
}

/** Compare an older recording only where the serialized program recipe is unchanged. */
export function selectComparableSandboxRecipes(fixture, manifest, currentCorpus, localCorpus) {
  const currentDigest = sha256(JSON.stringify(currentCorpus));
  if (sha256(JSON.stringify(localCorpus)) !== currentDigest) {
    throw new Error("local corpus differs from the current recipe");
  }
  if (manifest?.schemaVersion !== 1 || manifest.corpusSha256 !== fixture?.evidence?.corpusSha256) {
    throw new Error("manifest corpus differs from the production fixture");
  }
  if (manifest.sourceCommit !== fixture.evidence.harnessRevision) {
    throw new Error("manifest source differs from the production fixture");
  }
  const recordedIds = Object.keys(fixture.programs ?? {}).toSorted();
  if (
    JSON.stringify(recordedIds) !== JSON.stringify(Object.keys(manifest.programs ?? {}).toSorted())
  ) {
    throw new Error("manifest programs differ from the production fixture");
  }
  if (Object.keys(fixture.streams ?? {}).some((id) => !manifest.streams?.[id])) {
    throw new Error("manifest streams differ from the production fixture");
  }
  const selectedPrograms = (currentCorpus.restPrograms ?? []).filter(
    (program) => manifest.programs[program.id] === sha256(JSON.stringify(program)),
  );
  const matchedRestIds = selectedPrograms.map((program) => program.id).toSorted();
  const pendingRestIds = [
    ...new Set([
      ...recordedIds,
      ...(currentCorpus.restPrograms ?? []).map((program) => program.id),
    ]),
  ]
    .filter((id) => !matchedRestIds.includes(id))
    .toSorted();
  const currentStreams = (currentCorpus.streamRecipes ?? []).filter(
    (recipe) => recipe.transport === "grpc",
  );
  const selectedStreams = currentStreams.filter(
    (recipe) => manifest.streams?.[recipe.id] === sha256(JSON.stringify(recipe)),
  );
  const matchedStreamIds = selectedStreams.map((recipe) => recipe.id).toSorted();
  const pendingStreamIds = [
    ...new Set([
      ...Object.keys(fixture.streams ?? {}),
      ...currentStreams.map((recipe) => recipe.id),
    ]),
  ]
    .filter((id) => !matchedStreamIds.includes(id))
    .toSorted();
  const keep = (entries, ids) => Object.fromEntries(ids.map((id) => [id, entries[id]]));
  return {
    fixture: {
      ...fixture,
      programs: keep(fixture.programs, matchedRestIds),
      streams: keep(fixture.streams ?? {}, matchedStreamIds),
    },
    corpus: {
      ...currentCorpus,
      restPrograms: selectedPrograms,
      streamRecipes: selectedStreams,
      restRequestCount: selectedPrograms.reduce(
        (total, program) => total + program.steps.length,
        0,
      ),
    },
    matchedRestIds,
    pendingRestIds,
    matchedStreamIds,
    pendingStreamIds,
  };
}

export function selectDeltaV3Recipes(currentCorpus, fixture, manifest) {
  validateSandboxCorpus(currentCorpus);
  const currentDigest = sha256(JSON.stringify(currentCorpus));
  if (
    manifest?.schemaVersion !== 1 ||
    manifest.corpusSha256 !== fixture?.evidence?.corpusSha256 ||
    manifest.sourceCommit !== fixture?.evidence?.harnessRevision
  ) {
    throw new Error("delta-v3 saved references are not bound to the production fixture");
  }
  const expectedRestIds = DELTA_DELETE_ROUTES.flatMap((route) =>
    DELTA_DELETE_COUNTS.map((count) => `writes/limits/near-limit-delete-refusal/${route}/${count}`),
  ).toSorted();
  const deltaPrograms = currentCorpus.restPrograms.filter((program) =>
    expectedRestIds.includes(program.id),
  );
  if (
    JSON.stringify(deltaPrograms.map((program) => program.id).toSorted()) !==
    JSON.stringify(expectedRestIds)
  ) {
    throw new Error("delta-v3 source corpus does not contain the exact six DELETE recipes");
  }
  const deltaStreams = currentCorpus.streamRecipes.filter(
    (recipe) => recipe.transport === "grpc" && recipe.id === DELTA_STREAM_ID,
  );
  if (deltaStreams.length !== 1 || deltaStreams[0].maxFrames !== 2) {
    throw new Error(
      "delta-v3 source corpus does not contain the bounded response-before-half-close recipe",
    );
  }
  const recordedRestIds = Object.keys(fixture.programs ?? {}).toSorted();
  if (
    JSON.stringify(recordedRestIds) !==
    JSON.stringify(Object.keys(manifest.programs ?? {}).toSorted())
  ) {
    throw new Error("delta-v3 manifest programs differ from the saved production fixture");
  }
  if (
    JSON.stringify(Object.keys(fixture.streams ?? {}).toSorted()) !==
    JSON.stringify(Object.keys(manifest.streams ?? {}).toSorted())
  ) {
    throw new Error("delta-v3 manifest streams differ from the saved production fixture");
  }
  const retainedRestIds = currentCorpus.restPrograms
    .filter((program) => manifest.programs[program.id] === sha256(JSON.stringify(program)))
    .map((program) => program.id)
    .filter((id) => !expectedRestIds.includes(id))
    .toSorted();
  const retainedStreamIds = currentCorpus.streamRecipes
    .filter(
      (recipe) =>
        recipe.transport === "grpc" &&
        manifest.streams?.[recipe.id] === sha256(JSON.stringify(recipe)) &&
        recipe.id !== DELTA_STREAM_ID,
    )
    .map((recipe) => recipe.id)
    .toSorted();
  const pendingRestIds = [
    ...new Set([...recordedRestIds, ...currentCorpus.restPrograms.map((program) => program.id)]),
  ]
    .filter((id) => !expectedRestIds.includes(id) && !retainedRestIds.includes(id))
    .toSorted();
  const currentGrpcIds = currentCorpus.streamRecipes
    .filter((recipe) => recipe.transport === "grpc")
    .map((recipe) => recipe.id);
  const pendingStreamIds = [...new Set([...Object.keys(fixture.streams ?? {}), ...currentGrpcIds])]
    .filter((id) => id !== DELTA_STREAM_ID && !retainedStreamIds.includes(id))
    .toSorted();
  const restIds = [...expectedRestIds, ...retainedRestIds, ...pendingRestIds].toSorted();
  const streamIds = [DELTA_STREAM_ID, ...retainedStreamIds, ...pendingStreamIds].toSorted();
  if (
    JSON.stringify(restIds) !==
      JSON.stringify(currentCorpus.restPrograms.map((p) => p.id).toSorted()) ||
    JSON.stringify(streamIds) !== JSON.stringify(currentGrpcIds.toSorted())
  ) {
    throw new Error("delta-v3 selection does not conserve the current recipe denominator");
  }
  const requestCount = deltaPrograms.reduce((total, program) => total + program.steps.length, 0);
  if (requestCount !== 30) throw new Error("delta-v3 REST request denominator must be 30");
  return {
    sourceCorpusDigest: currentDigest,
    deltaRestIds: expectedRestIds,
    deltaStreamIds: [DELTA_STREAM_ID],
    retainedRestIds,
    retainedStreamIds,
    pendingRestIds,
    pendingStreamIds,
    recordingCorpus: {
      ...currentCorpus,
      restPrograms: deltaPrograms,
      streamRecipes: deltaStreams,
      restRequestCount: requestCount,
    },
  };
}

export function classifyDeltaV3DeletePair(route, smaller, larger) {
  if (!DELTA_DELETE_ROUTES.includes(route)) throw new Error("unknown DELETE route");
  const proves = (record, count) =>
    record?.documentCount === count &&
    record.deleteTargetExists === true &&
    record.deleteOutcomeProven === true &&
    ((record.outcome === "accepted" &&
      record.postDeleteAbsent === true &&
      record.groupEmpty === true) ||
      (record.outcome === "refused" &&
        record.postDeletePresent === true &&
        record.groupContainsTarget === true));
  if (!proves(smaller, 12112) || !proves(larger, 12113)) {
    return { status: "pending-indeterminate", route };
  }
  if (smaller.outcome === "accepted" && larger.outcome === "refused") {
    return { status: "adjacent-boundary", route };
  }
  return { status: "route-specific-exploration-required", route };
}

export function deltaV3RequestBound(recordingCorpus) {
  validateSandboxCorpus(recordingCorpus);
  const ids = (recordingCorpus.restPrograms ?? []).map((program) => program.id).toSorted();
  const expected = DELTA_DELETE_ROUTES.flatMap((route) =>
    DELTA_DELETE_COUNTS.map((count) => `writes/limits/near-limit-delete-refusal/${route}/${count}`),
  ).toSorted();
  const stream = (recordingCorpus.streamRecipes ?? []).filter(
    (recipe) => recipe.id === DELTA_STREAM_ID && recipe.transport === "grpc",
  );
  const declaredHttp = (recordingCorpus.restPrograms ?? []).reduce(
    (total, program) => total + program.steps.length,
    0,
  );
  if (
    JSON.stringify(ids) !== JSON.stringify(expected) ||
    declaredHttp !== 30 ||
    stream.length !== 1 ||
    stream[0].maxFrames !== 2
  ) {
    throw new Error(
      "delta-v3 request bound requires the exact six REST recipes and two-frame stream",
    );
  }
  return {
    declaredHttp,
    managedHttpCap: V3_MANAGED_CLEAR_CAP,
    maxHttpRequests: declaredHttp + V3_MANAGED_CLEAR_CAP,
    maxStreamFrames: 2,
    maxCombinedOperations: declaredHttp + V3_MANAGED_CLEAR_CAP + 2,
  };
}

export function comparisonExitCode(differences, pendingRestIds, pendingStreamIds) {
  if (differences.length > 0) return 1;
  if (pendingRestIds.length > 0 || pendingStreamIds.length > 0) return 2;
  return 0;
}

export async function prepareSandboxCorpus() {
  const { stdout } = await execFileAsync(
    "uv",
    ["run", "python", join(CONFORMANCE_DIR, "src/firestore-probe/closure_export.py")],
    { cwd: ROOT, maxBuffer: 240 * 1024 * 1024 },
  );
  const corpus = JSON.parse(stdout);
  const { requestCount } = validateSandboxCorpus(corpus);
  const { live, saved } = validateStreamRecipes(corpus.streamRecipes);
  if (!(await stat(join(ROOT, saved.source))).isFile()) {
    throw new Error("saved stream production reference is missing");
  }
  return { corpus, restRequestCount: requestCount, liveStreamCount: live.length };
}

export function remainingSandboxBudget(rows, nextEstimateUsd = 0) {
  if (!Array.isArray(rows) || !Number.isFinite(nextEstimateUsd) || nextEstimateUsd < 0) {
    throw new Error("invalid sandbox budget input");
  }
  let unlinkedSpent = 0;
  const attempts = new Map();
  for (const row of rows) {
    if (row.taskId !== TASK_ID) continue;
    if (!Number.isFinite(row.estimatedUsd) || row.estimatedUsd < 0) {
      throw new Error("invalid sandbox ledger cost");
    }
    if (typeof row.attemptId === "string" && row.attemptId.length > 0)
      attempts.set(row.attemptId, row);
    else unlinkedSpent += row.estimatedUsd;
  }
  const spent =
    unlinkedSpent + [...attempts.values()].reduce((total, row) => total + row.estimatedUsd, 0);
  if (spent + nextEstimateUsd > TASK_LIMIT_USD + Number.EPSILON) {
    throw new Error("sandbox observation task budget exceeded");
  }
  return TASK_LIMIT_USD - spent;
}

export function requireHistoricalUnknownHold(rows) {
  const holds = rows.filter(
    (row) => row.taskId === TASK_ID && row.outcome === "historical-unknown-hold",
  );
  if (
    holds.length !== 1 ||
    holds[0].project !== SANDBOX_PROJECT ||
    holds[0].database !== "(default)" ||
    holds[0].estimatedUsd !== HISTORICAL_UNKNOWN_HOLD_USD ||
    holds[0].requests !== null ||
    holds[0].holdId !== HISTORICAL_UNKNOWN_HOLD_ID ||
    !Number.isFinite(Date.parse(holds[0].ts ?? "")) ||
    holds[0].runDir !== undefined ||
    holds[0].attemptId !== undefined
  ) {
    throw new Error("the distinct $9.24 historical unknown hold must be present before admission");
  }
  return holds[0];
}

export function sandboxLedgerEntry({
  gitSha,
  corpusDigest,
  requests,
  outcome,
  runDir,
  estimatedUsd = ATTEMPT_ESTIMATE_USD,
  attemptId,
  streamFrames,
}) {
  const requestCap =
    streamFrames === undefined || streamFrames === null ? REST_CAP : DELTA_V3_HTTP_CAP;
  if (requests !== null && (!Number.isInteger(requests) || requests < 0 || requests > requestCap)) {
    throw new Error("invalid sandbox ledger request count");
  }
  if (
    streamFrames !== undefined &&
    streamFrames !== null &&
    (!Number.isInteger(streamFrames) || streamFrames < 0 || streamFrames > MAX_STREAM_FRAMES)
  ) {
    throw new Error("invalid sandbox ledger stream-frame count");
  }
  return {
    ts: new Date().toISOString(),
    project: SANDBOX_PROJECT,
    database: "(default)",
    gitSha,
    corpusDigest,
    requests,
    estimatedUsd,
    outcome,
    taskId: TASK_ID,
    runDir,
    ...(attemptId === undefined ? {} : { attemptId }),
    ...(streamFrames === undefined ? {} : { streamFrames }),
  };
}

export async function reserveProductionAttempt({ ledgerPath, rows, gitSha, corpusDigest, runDir }) {
  requireHistoricalUnknownHold(rows);
  remainingSandboxBudget(rows, ATTEMPT_ESTIMATE_USD);
  const attemptId = randomUUID().replaceAll("-", "");
  const reservation = sandboxLedgerEntry({
    gitSha,
    corpusDigest,
    requests: null,
    outcome: "reserved",
    runDir,
    estimatedUsd: ATTEMPT_ESTIMATE_USD,
    attemptId,
  });
  const handle = await open(ledgerPath, "a", 0o600);
  try {
    await handle.writeFile(`${JSON.stringify(reservation)}\n`);
    await handle.sync();
  } finally {
    await handle.close();
  }
  rows.push(reservation);
  return reservation;
}

export async function reserveProductionAttemptWithToken({
  ledgerPath,
  rows,
  gitSha,
  corpusDigest,
  runDir,
  acquireToken,
}) {
  if (typeof acquireToken !== "function") {
    throw new Error("production credential provider is required");
  }
  const reservation = await reserveProductionAttempt({
    ledgerPath,
    rows,
    gitSha,
    corpusDigest,
    runDir,
  });
  const token = await acquireToken();
  if (typeof token !== "string" || !token.trim()) {
    throw new Error("production OAuth bearer is missing");
  }
  return { reservation, token: token.trim() };
}

export function legacyRecoveryEnvironment({
  token,
  meta,
  journal,
  names = legacyManagedClearNames(),
}) {
  const frozenNames = legacyManagedClearNames();
  if (
    typeof token !== "string" ||
    token.length === 0 ||
    typeof meta !== "string" ||
    meta.length === 0 ||
    typeof journal !== "string" ||
    journal.length === 0 ||
    JSON.stringify(names) !== JSON.stringify(frozenNames)
  ) {
    throw new Error("legacy recovery requires the exact private sandbox scope");
  }
  managedClearScope(names, SANDBOX_PROJECT, "(default)");
  return {
    FIRESTORE_PROBE_TARGET: "production",
    FIRESTORE_PROBE_RECOVERY_MODE: "recover-legacy",
    FIRESTORE_PROBE_SCHEME: "https",
    FIRESTORE_PROBE_HOST: "firestore.googleapis.com",
    FIRESTORE_PROBE_TOKEN: token,
    FIRESTORE_PROBE_PROJECT: SANDBOX_PROJECT,
    FIRESTORE_PROBE_RECORD_PROJECT: RECORDED_PROJECT,
    FIRESTORE_PROBE_META_OUT: meta,
    FIRESTORE_PROBE_MAX_REQUESTS: String(REST_CAP),
    FIRESTORE_PROBE_TIMEOUT_MS: "180000",
    FIRESTORE_PROBE_MANAGED_CLEAR_NAMES: JSON.stringify(names),
    FIRESTORE_PROBE_MANAGED_CLEAR_JOURNAL: journal,
  };
}

export function v3RecoveryEnvironment({
  token,
  meta,
  journal,
  names,
  runId,
  corpusDigest,
  sourceGitSha,
}) {
  if (
    typeof token !== "string" ||
    !token ||
    typeof meta !== "string" ||
    !meta ||
    typeof journal !== "string" ||
    !journal ||
    !Array.isArray(names) ||
    names.length !== 12 ||
    !/^[a-f0-9]{32}$/.test(runId ?? "") ||
    !/^[a-f0-9]{64}$/.test(corpusDigest ?? "") ||
    !/^[a-f0-9]{40}$/.test(sourceGitSha ?? "")
  )
    throw new Error("corpus-v3 recovery requires exact private provenance");
  managedClearScope(
    names.map((name) => name.replaceAll("DELETE_RUN_ID", runId)),
    SANDBOX_PROJECT,
    "(default)",
  );
  return {
    FIRESTORE_PROBE_TARGET: "production",
    FIRESTORE_PROBE_RECOVERY_MODE: "recover-v3",
    FIRESTORE_PROBE_SCHEME: "https",
    FIRESTORE_PROBE_HOST: "firestore.googleapis.com",
    FIRESTORE_PROBE_TOKEN: token,
    FIRESTORE_PROBE_PROJECT: SANDBOX_PROJECT,
    FIRESTORE_PROBE_RECORD_PROJECT: RECORDED_PROJECT,
    FIRESTORE_PROBE_META_OUT: meta,
    FIRESTORE_PROBE_MAX_REQUESTS: String(REST_CAP),
    FIRESTORE_PROBE_TIMEOUT_MS: "180000",
    FIRESTORE_PROBE_MANAGED_CLEAR_NAMES: JSON.stringify(names),
    FIRESTORE_PROBE_MANAGED_CLEAR_JOURNAL: journal,
    FIRESTORE_PROBE_DELETE_RUN_ID: runId,
    FIRESTORE_PROBE_CORPUS_DIGEST: corpusDigest,
    FIRESTORE_PROBE_SOURCE_GIT_SHA: sourceGitSha,
  };
}

export function deltaV3RecoveryEnvironment({
  token,
  meta,
  journal,
  names,
  runId,
  corpusDigest,
  sourceGitSha,
  remainingHttp,
}) {
  if (
    typeof token !== "string" ||
    !token ||
    typeof meta !== "string" ||
    !meta ||
    typeof journal !== "string" ||
    !journal ||
    !Array.isArray(names) ||
    names.length !== 6 ||
    !/^[a-f0-9]{32}$/.test(runId ?? "") ||
    !/^[a-f0-9]{64}$/.test(corpusDigest ?? "") ||
    !/^[a-f0-9]{40}$/.test(sourceGitSha ?? "") ||
    !Number.isSafeInteger(remainingHttp) ||
    remainingHttp < 1 ||
    remainingHttp > DELTA_V3_HTTP_CAP
  )
    throw new Error(
      "delta-v3 recovery requires exact private provenance and remaining request cap",
    );
  if (
    managedShrinkScope(
      names.map((name) => name.replaceAll(runId, "DELETE_RUN_ID")),
      SANDBOX_PROJECT,
      "(default)",
    ) !== "delta-v3"
  ) {
    throw new Error("delta-v3 recovery escaped the exact six-name scope");
  }
  return {
    FIRESTORE_PROBE_TARGET: "production",
    FIRESTORE_PROBE_RECOVERY_MODE: "recover-delta-v3",
    FIRESTORE_PROBE_SCHEME: "https",
    FIRESTORE_PROBE_HOST: "firestore.googleapis.com",
    FIRESTORE_PROBE_TOKEN: token,
    FIRESTORE_PROBE_PROJECT: SANDBOX_PROJECT,
    FIRESTORE_PROBE_RECORD_PROJECT: RECORDED_PROJECT,
    FIRESTORE_PROBE_META_OUT: meta,
    FIRESTORE_PROBE_MAX_REQUESTS: String(remainingHttp),
    FIRESTORE_PROBE_TIMEOUT_MS: "180000",
    FIRESTORE_PROBE_MANAGED_CLEAR_NAMES: JSON.stringify(names),
    FIRESTORE_PROBE_DELTA_V3: "1",
    FIRESTORE_PROBE_DELTA_LOCK_HELD: "1",
    FIRESTORE_PROBE_DELTA_JOURNAL: journal,
    FIRESTORE_PROBE_DELETE_RUN_ID: runId,
    FIRESTORE_PROBE_CORPUS_DIGEST: corpusDigest,
    FIRESTORE_PROBE_SOURCE_GIT_SHA: sourceGitSha,
  };
}

export async function findV3RecoveryResume(privateDir, expectedNames) {
  if (
    typeof privateDir !== "string" ||
    !privateDir.startsWith("/") ||
    !Array.isArray(expectedNames) ||
    expectedNames.length !== 12
  ) {
    throw new Error("corpus-v3 recovery requires its exact private scope");
  }
  managedClearScope(
    expectedNames.map((name) => name.replaceAll("DELETE_RUN_ID", "a".repeat(32))),
    SANDBOX_PROJECT,
    "(default)",
  );
  const privateRoot = resolve(privateDir);
  const prefix = join(privateRoot, "fs-data-write-production-");
  const rows = await readLedger(join(privateRoot, "sandbox-ledger.jsonl"));
  const runDirs = new Set(
    rows
      .filter(
        (row) =>
          row.taskId === TASK_ID &&
          row.outcome === "reserved" &&
          typeof row.runDir === "string" &&
          row.runDir.startsWith(prefix),
      )
      .map((row) => row.runDir),
  );
  const candidates = [];
  for (const runDir of runDirs) {
    if (
      typeof runDir !== "string" ||
      resolve(runDir) !== runDir ||
      dirname(runDir) !== privateRoot ||
      !runDir.startsWith(prefix)
    ) {
      throw new Error("corpus-v3 recovery ledger path escaped its private directory");
    }
    const directory = await lstat(runDir);
    if (!directory.isDirectory() || directory.isSymbolicLink() || (directory.mode & 0o077) !== 0) {
      throw new Error("corpus-v3 recovery run directory is not private");
    }
    const journalPath = join(runDir, "managed-clear.json");
    let journalInfo;
    try {
      journalInfo = await lstat(journalPath);
    } catch (error) {
      if (error?.code === "ENOENT") continue;
      throw error;
    }
    if (!journalInfo.isFile() || journalInfo.isSymbolicLink() || (journalInfo.mode & 0o077) !== 0) {
      throw new Error("corpus-v3 recovery journal is not a private regular file");
    }
    let journal;
    try {
      journal = JSON.parse(await readFile(journalPath, "utf8"));
    } catch (error) {
      throw new Error("corpus-v3 recovery journal is malformed", { cause: error });
    }
    const reservation = rows.find(
      (row) => row.taskId === TASK_ID && row.outcome === "reserved" && row.runDir === runDir,
    );
    if (
      !reservation ||
      !/^[a-f0-9]{40}$/.test(reservation.gitSha ?? "") ||
      !/^[a-f0-9]{64}$/.test(reservation.corpusDigest ?? "") ||
      journal?.schemaVersion !== 1 ||
      journal.mode !== "cleanup-corpus-v3" ||
      journal.project !== SANDBOX_PROJECT ||
      journal.database !== "(default)" ||
      journal.sourceGitSha !== reservation.gitSha ||
      journal.corpusDigest !== reservation.corpusDigest ||
      !/^[a-f0-9]{32}$/.test(journal.runId ?? "") ||
      JSON.stringify(journal.names) !==
        JSON.stringify(expectedNames.map((name) => name.replaceAll("DELETE_RUN_ID", journal.runId)))
    ) {
      throw new Error("corpus-v3 recovery journal does not match its reserved frozen scope");
    }
    if (journal.status !== "complete")
      candidates.push({ runDir, journalPath, journal, sourceGitSha: reservation.gitSha });
  }
  if (candidates.length > 1)
    throw new Error("multiple incomplete corpus-v3 journals require operator resolution");
  return candidates[0] ?? null;
}

export async function findDeltaV3RecoveryResume(privateDir, expectedNames, expectedCorpusDigest) {
  if (
    typeof privateDir !== "string" ||
    !privateDir.startsWith("/") ||
    !Array.isArray(expectedNames) ||
    expectedNames.length !== 6 ||
    managedShrinkScope(expectedNames, SANDBOX_PROJECT, "(default)") !== "delta-v3" ||
    !/^[a-f0-9]{64}$/.test(expectedCorpusDigest ?? "")
  ) {
    throw new Error("delta-v3 recovery requires its exact private six-name scope");
  }
  const privateRoot = resolve(privateDir);
  const prefix = join(privateRoot, "fs-data-write-production-");
  const rows = await readLedger(join(privateRoot, "sandbox-ledger.jsonl"));
  const runDirs = new Set(
    rows
      .filter(
        (row) =>
          row.taskId === TASK_ID &&
          row.outcome === "reserved" &&
          typeof row.runDir === "string" &&
          row.runDir.startsWith(prefix),
      )
      .map((row) => row.runDir),
  );
  const candidates = [];
  for (const runDir of runDirs) {
    if (
      resolve(runDir) !== runDir ||
      dirname(runDir) !== privateRoot ||
      !runDir.startsWith(prefix)
    ) {
      throw new Error("delta-v3 recovery ledger path escaped its private directory");
    }
    const dirInfo = await lstat(runDir);
    if (!dirInfo.isDirectory() || dirInfo.isSymbolicLink() || (dirInfo.mode & 0o077) !== 0) {
      throw new Error("delta-v3 recovery run directory is not private");
    }
    const journalPath = join(runDir, "delta-cleanup.json");
    let info;
    try {
      info = await lstat(journalPath);
    } catch (error) {
      if (error?.code === "ENOENT") continue;
      throw error;
    }
    if (!info.isFile() || info.isSymbolicLink() || (info.mode & 0o077) !== 0) {
      throw new Error("delta-v3 recovery journal is not a private regular file");
    }
    const journal = JSON.parse(await readFile(journalPath, "utf8"));
    const reservation = rows.find(
      (row) => row.taskId === TASK_ID && row.outcome === "reserved" && row.runDir === runDir,
    );
    if (
      !reservation ||
      !/^[a-f0-9]{40}$/.test(reservation.gitSha ?? "") ||
      !/^[a-f0-9]{64}$/.test(reservation.corpusDigest ?? "") ||
      journal?.schemaVersion !== 1 ||
      journal.mode !== "cleanup-delta-v3" ||
      journal.project !== SANDBOX_PROJECT ||
      journal.database !== "(default)" ||
      journal.sourceGitSha !== reservation.gitSha ||
      journal.corpusDigest !== reservation.corpusDigest ||
      journal.corpusDigest !== expectedCorpusDigest ||
      !/^[a-f0-9]{32}$/.test(journal.runId ?? "") ||
      journal.writerExclusivity !==
        "task-lock-held; run-specific six collection groups have no external writer" ||
      !Number.isSafeInteger(journal.httpRequestCount) ||
      journal.httpRequestCount < 0 ||
      journal.httpRequestCount >= DELTA_V3_HTTP_CAP ||
      !Number.isSafeInteger(journal.managedRequestCount) ||
      journal.managedRequestCount < 0 ||
      journal.managedRequestCount > V3_MANAGED_CLEAR_CAP ||
      JSON.stringify(journal.names) !==
        JSON.stringify(expectedNames.map((name) => name.replaceAll("DELETE_RUN_ID", journal.runId)))
    ) {
      throw new Error("delta-v3 recovery journal does not match its reserved frozen scope");
    }
    if (journal.status !== "complete")
      candidates.push({ runDir, journalPath, journal, sourceGitSha: reservation.gitSha });
  }
  if (candidates.length > 1)
    throw new Error("multiple incomplete delta-v3 journals require operator resolution");
  return candidates[0] ?? null;
}

async function recoverV3() {
  const gitCommonDir = (
    await execFileAsync("git", ["rev-parse", "--path-format=absolute", "--git-common-dir"], {
      cwd: ROOT,
    })
  ).stdout.trim();
  const ledgerPath = sandboxLedgerPath(gitCommonDir);
  const privateDir = dirname(ledgerPath);
  await mkdir(privateDir, { recursive: true, mode: 0o700 });
  const { corpus } = await prepareSandboxCorpus();
  const names = sandboxManagedClearNames(corpus);
  const currentGitSha = (
    await execFileAsync("git", ["rev-parse", "HEAD"], { cwd: ROOT })
  ).stdout.trim();
  const result = await withSandboxExclusiveLock(privateDir, async (rows) => {
    const resume = await findV3RecoveryResume(privateDir, names);
    if (!resume) throw new Error("no incomplete exact-scope corpus-v3 cleanup journal exists");
    const reservation = await reserveProductionAttempt({
      ledgerPath,
      rows,
      gitSha: resume.journal.sourceGitSha,
      corpusDigest: resume.journal.corpusDigest,
      runDir: resume.runDir,
    });
    const meta = join(resume.runDir, `recovery-${randomUUID()}.meta.json`);
    const token = (
      process.env.FIREEMU_PRODUCTION_TOKEN ??
      (
        await execFileAsync("gcloud", ["auth", "application-default", "print-access-token"], {
          maxBuffer: 4096,
        })
      ).stdout
    ).trim();
    if (!token) throw new Error("production OAuth bearer is missing");
    let requestCount = null;
    let outcome = "recovery-failed";
    try {
      await runNode(
        "corpus-v3 exact cleanup recovery",
        "firestore-probe/sandbox-session.mjs",
        v3RecoveryEnvironment({
          token,
          meta,
          journal: resume.journalPath,
          names,
          runId: resume.journal.runId,
          corpusDigest: resume.journal.corpusDigest,
          sourceGitSha: resume.journal.sourceGitSha,
        }),
        1_200_000,
      );
      const recovered = JSON.parse(await readFile(resume.journalPath, "utf8"));
      if (recovered.status !== "complete" || recovered.mode !== "cleanup-corpus-v3") {
        throw new Error("corpus-v3 recovery did not verify exact typed absence");
      }
      outcome = "recovered";
    } finally {
      try {
        requestCount = sessionRequestCount(JSON.parse(await readFile(meta, "utf8")));
      } catch {
        // The reservation remains charged if recovery stops before writing metadata.
      }
      const entry = sandboxLedgerEntry({
        gitSha: resume.journal.sourceGitSha,
        corpusDigest: resume.journal.corpusDigest,
        requests: requestCount,
        outcome,
        runDir: resume.runDir,
        estimatedUsd: ATTEMPT_ESTIMATE_USD,
        attemptId: reservation.attemptId,
      });
      const handle = await open(ledgerPath, "a", 0o600);
      try {
        await handle.writeFile(`${JSON.stringify(entry)}\n`);
        await handle.sync();
      } finally {
        await handle.close();
      }
      rows.push(entry);
    }
    return {
      outcome,
      requestCount,
      runDir: resume.runDir,
      journal: resume.journalPath,
      sourceGitSha: resume.sourceGitSha,
      recoveryStartedFrom: resume.journal.status,
    };
  });
  process.stdout.write(`${JSON.stringify({ ...result, invocationGitSha: currentGitSha })}\n`);
}

async function recoverDeltaV3() {
  const gitCommonDir = (
    await execFileAsync("git", ["rev-parse", "--path-format=absolute", "--git-common-dir"], {
      cwd: ROOT,
    })
  ).stdout.trim();
  const ledgerPath = sandboxLedgerPath(gitCommonDir);
  const privateDir = dirname(ledgerPath);
  await mkdir(privateDir, { recursive: true, mode: 0o700 });
  const { corpus } = await prepareSandboxCorpus();
  const fixture = JSON.parse(
    await readFile(join(CONFORMANCE_DIR, "fs-data-write-production-matrix.json"), "utf8"),
  );
  const manifest = JSON.parse(
    await readFile(join(CONFORMANCE_DIR, "fs-data-write-recipe-digests.json"), "utf8"),
  );
  const selection = selectDeltaV3Recipes(corpus, fixture, manifest);
  const packet = {
    schemaVersion: 1,
    sourceCorpusSha256: selection.sourceCorpusDigest,
    restPrograms: selection.recordingCorpus.restPrograms,
    streamRecipes: selection.recordingCorpus.streamRecipes,
    restRequestCount: selection.recordingCorpus.restRequestCount,
  };
  const names = deltaV3ManagedClearNames(packet);
  const result = await withSandboxExclusiveLock(privateDir, async (rows) => {
    const resume = await findDeltaV3RecoveryResume(privateDir, names, selection.sourceCorpusDigest);
    if (!resume) throw new Error("no incomplete exact-scope delta-v3 cleanup journal exists");
    const remainingHttp = DELTA_V3_HTTP_CAP - resume.journal.httpRequestCount;
    if (remainingHttp < 1 || resume.journal.managedRequestCount >= V3_MANAGED_CLEAR_CAP) {
      throw new Error(
        "delta-v3 recovery has no safe remaining request budget; preserve its durable blocker",
      );
    }
    const reservation = await reserveProductionAttempt({
      ledgerPath,
      rows,
      gitSha: resume.journal.sourceGitSha,
      corpusDigest: resume.journal.corpusDigest,
      runDir: resume.runDir,
    });
    const meta = join(resume.runDir, `recovery-${randomUUID()}.meta.json`);
    // Credentials are refreshed only after the shared lock and durable reservation.
    const token = (
      process.env.FIREEMU_PRODUCTION_TOKEN ??
      (
        await execFileAsync("gcloud", ["auth", "application-default", "print-access-token"], {
          maxBuffer: 4096,
        })
      ).stdout
    ).trim();
    if (!token) throw new Error("production OAuth bearer is missing");
    let requestCount = null;
    let outcome = "recovery-failed";
    let boundError = null;
    try {
      await runNode(
        "delta-v3 exact cleanup recovery",
        "firestore-probe/sandbox-session.mjs",
        deltaV3RecoveryEnvironment({
          token,
          meta,
          journal: resume.journalPath,
          names,
          runId: resume.journal.runId,
          corpusDigest: resume.journal.corpusDigest,
          sourceGitSha: resume.journal.sourceGitSha,
          remainingHttp,
        }),
        1_200_000,
      );
      const recovered = JSON.parse(await readFile(resume.journalPath, "utf8"));
      if (recovered.status !== "complete" || recovered.mode !== "cleanup-delta-v3") {
        throw new Error("delta-v3 recovery did not verify exact typed absence and group emptiness");
      }
      outcome = "recovered";
    } finally {
      try {
        const cumulativeCount = sessionRequestCount(JSON.parse(await readFile(meta, "utf8")));
        if (
          cumulativeCount > DELTA_V3_HTTP_CAP ||
          cumulativeCount - resume.journal.httpRequestCount > remainingHttp
        ) {
          boundError = new Error("delta-v3 recovery exceeded its journaled HTTP reservation");
          outcome = "recovery-failed";
        } else {
          requestCount = cumulativeCount - resume.journal.httpRequestCount;
        }
      } catch {
        // Keep the reservation charged when the child failed before writing metadata.
      }
      const entry = sandboxLedgerEntry({
        gitSha: resume.journal.sourceGitSha,
        corpusDigest: resume.journal.corpusDigest,
        requests: requestCount,
        outcome,
        runDir: resume.runDir,
        estimatedUsd: ATTEMPT_ESTIMATE_USD,
        attemptId: reservation.attemptId,
      });
      const handle = await open(ledgerPath, "a", 0o600);
      try {
        await handle.writeFile(`${JSON.stringify(entry)}\n`);
        await handle.sync();
      } finally {
        await handle.close();
      }
      rows.push(entry);
      if (boundError) process.exitCode = 1;
    }
    return {
      outcome,
      requestCount,
      runDir: resume.runDir,
      journal: resume.journalPath,
      sourceGitSha: resume.sourceGitSha,
      recoveryStartedFrom: resume.journal.status,
    };
  });
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

export async function findLegacyRecoveryResume(
  privateDir,
  corpusDigest,
  names = legacyManagedClearNames(),
) {
  const frozenNames = legacyManagedClearNames();
  const expectedDigest = sha256(JSON.stringify({ mode: "recover-legacy", names: frozenNames }));
  if (
    typeof privateDir !== "string" ||
    !privateDir.startsWith("/") ||
    corpusDigest !== expectedDigest ||
    JSON.stringify(names) !== JSON.stringify(frozenNames)
  ) {
    throw new Error("legacy recovery resume requires its exact private provenance");
  }
  managedClearScope(names, SANDBOX_PROJECT, "(default)");
  const privateRoot = resolve(privateDir);
  const recoveryPrefix = join(privateRoot, "fs-data-write-legacy-recovery-");
  const rows = await readLedger(join(privateRoot, "sandbox-ledger.jsonl"));
  const byRunDir = new Map();
  for (const row of rows) {
    if (row.taskId !== TASK_ID || row.corpusDigest !== corpusDigest) continue;
    if (row.outcome !== "reserved" || !/^[a-f0-9]{40}$/.test(row.gitSha ?? "")) {
      throw new Error("legacy recovery ledger provenance is invalid");
    }
    if (
      typeof row.runDir !== "string" ||
      resolve(row.runDir) !== row.runDir ||
      dirname(row.runDir) !== privateRoot ||
      !row.runDir.startsWith(recoveryPrefix)
    ) {
      throw new Error("legacy recovery ledger path escaped its private run directory");
    }
    const existing = byRunDir.get(row.runDir);
    if (!existing || rows.indexOf(existing.row) < rows.indexOf(row)) {
      byRunDir.set(row.runDir, { row });
    }
  }

  const candidates = [];
  for (const [runDir, { row }] of byRunDir) {
    let directory;
    try {
      directory = await lstat(runDir);
    } catch (error) {
      if (error?.code === "ENOENT") continue;
      throw error;
    }
    if (!directory.isDirectory() || directory.isSymbolicLink() || (directory.mode & 0o077) !== 0) {
      throw new Error("legacy recovery ledger run path is not a private directory");
    }
    const journalPath = join(runDir, "journal.json");
    let journalInfo;
    try {
      journalInfo = await lstat(journalPath);
    } catch (error) {
      if (error?.code === "ENOENT") continue;
      throw error;
    }
    if (!journalInfo.isFile() || journalInfo.isSymbolicLink() || (journalInfo.mode & 0o077) !== 0) {
      throw new Error("legacy recovery journal is not a private regular file");
    }
    let source;
    try {
      source = await readFile(journalPath, "utf8");
    } catch (error) {
      if (error?.code === "ENOENT") continue;
      throw new Error("legacy recovery journal cannot be inspected", { cause: error });
    }
    let journal;
    try {
      journal = JSON.parse(source);
    } catch (error) {
      throw new Error("legacy recovery journal is malformed", { cause: error });
    }
    const deletedNames = journal?.deletedNames ?? [];
    const intent = journal?.deleteIntent ?? null;
    if (
      journal?.schemaVersion !== 1 ||
      journal.mode !== "recover-legacy" ||
      journal.project !== SANDBOX_PROJECT ||
      journal.database !== "(default)" ||
      JSON.stringify(journal.names) !== JSON.stringify(frozenNames) ||
      !Array.isArray(deletedNames) ||
      deletedNames.some((name) => !frozenNames.includes(name)) ||
      new Set(deletedNames).size !== deletedNames.length ||
      !Array.isArray(journal?.verifiedAbsentNames ?? []) ||
      (journal?.verifiedAbsentNames ?? []).some((name) => !frozenNames.includes(name)) ||
      new Set(journal?.verifiedAbsentNames ?? []).size !==
        (journal?.verifiedAbsentNames ?? []).length ||
      (journal?.verifiedAbsentNames ?? []).some((name) => deletedNames.includes(name)) ||
      (intent !== null &&
        (intent.action !== "commit-delete" ||
          !frozenNames.includes(intent.name) ||
          typeof intent.updateTime !== "string" ||
          !intent.updateTime ||
          !Array.isArray(intent.priorDeletedNames) ||
          JSON.stringify(intent.priorDeletedNames) !== JSON.stringify(deletedNames)))
    ) {
      throw new Error("legacy recovery journal does not match its frozen private scope");
    }
    if (journal.status === "complete") continue;
    if (!["starting", "preflight-complete", "deleting"].includes(journal.status)) {
      throw new Error("legacy recovery journal has an unknown status");
    }
    candidates.push({ runDir, sourceGitSha: row.gitSha });
  }
  if (candidates.length > 1) {
    throw new Error("multiple incomplete legacy recovery journals require operator resolution");
  }
  return candidates[0] ?? null;
}

export async function prepareLegacyRecoveryRun(privateDir, corpusDigest, names) {
  const resume = await findLegacyRecoveryResume(privateDir, corpusDigest, names);
  const runDir =
    resume?.runDir ?? (await mkdtemp(join(privateDir, "fs-data-write-legacy-recovery-")));
  const attemptDir = await mkdtemp(join(runDir, "attempt-"));
  return {
    runDir,
    meta: join(attemptDir, "meta.json"),
    journal: join(runDir, "journal.json"),
    resume,
  };
}

export async function withLegacyRecoveryReservation(privateDir, reservation, work) {
  return withSandboxExclusiveLock(privateDir, async (lockedRows) => {
    requireHistoricalUnknownHold(lockedRows);
    remainingSandboxBudget(lockedRows, ATTEMPT_ESTIMATE_USD);
    const selected =
      typeof reservation === "function" ? await reservation(lockedRows) : reservation;
    const { gitSha, corpusDigest, runDir } = selected;
    const reserve = sandboxLedgerEntry({
      gitSha,
      corpusDigest,
      runDir,
      requests: null,
      outcome: "reserved",
      estimatedUsd: ATTEMPT_ESTIMATE_USD,
    });
    await appendFile(join(privateDir, "sandbox-ledger.jsonl"), `${JSON.stringify(reserve)}\n`);
    lockedRows.push(reserve);
    return work(selected);
  });
}

export function sandboxLedgerPath(gitCommonDir) {
  if (typeof gitCommonDir !== "string" || !gitCommonDir.startsWith("/")) {
    throw new Error("absolute git common directory is required");
  }
  return resolve(gitCommonDir, "../docs.local/runs/sandbox-ledger.jsonl");
}

export function sessionRequestCount(meta) {
  if (
    !Number.isInteger(meta?.requestCount) ||
    meta.requestCount < 0 ||
    meta.requestCount > REST_CAP
  ) {
    throw new Error("session network attempt count escaped the bounded corpus");
  }
  return meta.requestCount;
}

export function localTarget(value) {
  const [host, portText, ...extra] = String(value ?? "").split(":");
  const port = Number(portText);
  if (extra.length > 0 || !new Set(["127.0.0.1", "localhost"]).has(host)) {
    throw new Error("local child requires a loopback target");
  }
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error("local child port is invalid");
  }
  return { host, port };
}

export function sandboxManagedClearNames(corpus) {
  const program = corpus?.restPrograms?.at(-1);
  if (program?.id !== "writes/limits/index-entry-sum/adjacent") {
    throw new Error("the managed-clear boundary program must be last");
  }
  const writes = program.steps.filter((step) => step.id.startsWith("write-"));
  const boundaryNames = writes.map((step) => step.body?.writes?.[0]?.update?.name);
  const deletionNames = corpus.restPrograms
    .filter((candidate) => candidate.id.startsWith("writes/limits/near-limit-delete-refusal/"))
    .map(
      (candidate) =>
        candidate.steps.find((step) => step.id === "seed")?.body?.writes?.[0]?.update?.name,
    );
  const names = [...boundaryNames, ...deletionNames];
  if (
    writes.length !== 6 ||
    program.steps.length !== 12 ||
    deletionNames.length !== 6 ||
    deletionNames.some((name) => typeof name !== "string") ||
    new Set(names).size !== 12
  ) {
    throw new Error("six paired boundary observations are required");
  }
  managedClearScope(names, SANDBOX_PROJECT, "(default)");
  return names;
}

export function deltaV3ManagedClearNames(recordingCorpus) {
  const programs = recordingCorpus?.restPrograms ?? [];
  const expectedIds = DELTA_DELETE_ROUTES.flatMap((route) =>
    DELTA_DELETE_COUNTS.map((count) => `writes/limits/near-limit-delete-refusal/${route}/${count}`),
  ).toSorted();
  if (
    JSON.stringify(programs.map((program) => program.id).toSorted()) !== JSON.stringify(expectedIds)
  ) {
    throw new Error(
      "delta-v3 managed scope requires exactly the six route-specific DELETE recipes",
    );
  }
  const names = programs.map((program) => program.steps[0]?.body?.writes?.[0]?.update?.name);
  if (names.some((name) => typeof name !== "string") || new Set(names).size !== 6) {
    throw new Error("delta-v3 managed scope must contain six distinct seed targets");
  }
  if (managedShrinkScope(names, SANDBOX_PROJECT, "(default)") !== "delta-v3") {
    throw new Error("delta-v3 names differ from the frozen route-specific target set");
  }
  return names;
}

export function assertDeltaV3ProductionAdmission({ host, presendReviewed = false }) {
  if (host === "firestore.googleapis.com" || host === "firestore.googleapis.com:443") {
    if (!presendReviewed) {
      throw new Error(
        "delta-v3 production recording is blocked pending independent presend review",
      );
    }
  } else {
    localTarget(host);
  }
}

function ownedMutationNamesForPrograms(programs) {
  const prefix = `projects/${SANDBOX_PROJECT}/databases/(default)/documents/`;
  const names = new Set();
  const add = (name) => {
    if (typeof name !== "string") return;
    if (!name.startsWith(prefix)) {
      if (name.startsWith("projects/")) {
        throw new Error("corpus mutation escaped the fixed sandbox resource prefix");
      }
      return;
    }
    const parts = name.slice(prefix.length).split("/");
    if (
      parts.length < 2 ||
      parts.length % 2 !== 0 ||
      parts.some((part) => !part || part === "." || part === ".." || /%2f/i.test(part))
    ) {
      return;
    }
    names.add(name);
  };
  const collectWrites = (value) => {
    if (Array.isArray(value)) {
      for (const child of value) collectWrites(child);
      return;
    }
    if (!value || typeof value !== "object") return;
    for (const [key, child] of Object.entries(value)) {
      if (key === "update" && typeof child?.name === "string") add(child.name);
      else if (key === "delete" && typeof child === "string") add(child);
      else if (key === "transform" && typeof child?.document === "string") add(child.document);
      else collectWrites(child);
    }
  };
  for (const program of programs) {
    for (const step of program.steps) {
      const method = step.method.toUpperCase();
      if (method === "POST" && /:(commit|batchWrite)$/i.test(step.path)) {
        let body = step.body;
        if (typeof body === "string") {
          try {
            body = JSON.parse(body);
          } catch {
            body = null;
          }
        }
        if (body && typeof body === "object") collectWrites(body.writes ?? []);
      } else if (method === "POST" && step.path.includes("/documents/")) {
        const url = new URL(step.path, "https://firestore.googleapis.com");
        const marker = "/documents/";
        const markerIndex = url.pathname.indexOf(marker);
        if (markerIndex < 0 || /%2f/i.test(url.pathname)) continue;
        const documentId = url.searchParams.get("documentId");
        if (!documentId) throw new Error("corpus create must use an explicit documentId");
        add(`${prefix}${url.pathname.slice(markerIndex + marker.length)}/${documentId}`);
      } else if (method === "PATCH" || method === "DELETE") {
        const url = new URL(step.path, "https://firestore.googleapis.com");
        const marker = "/documents/";
        const markerIndex = url.pathname.indexOf(marker);
        if (markerIndex < 0 || /%2f/i.test(url.pathname)) continue;
        add(`${prefix}${url.pathname.slice(markerIndex + marker.length)}`);
      }
    }
  }
  return [...names].toSorted();
}

function exactInventoryRequestBound(names) {
  const prefix = `projects/${SANDBOX_PROJECT}/databases/(default)/documents/`;
  const collectionGroupIds = new Set();
  const targetNames = new Set(names);
  const unownedAncestorDocs = new Set();
  for (const name of names) {
    const parts = name.slice(prefix.length).split("/");
    collectionGroupIds.add(parts.at(-2));
    for (let length = 2; length < parts.length - 1; length += 2) {
      const ancestor = `${prefix}${parts.slice(0, length).join("/")}`;
      if (!targetNames.has(ancestor)) unownedAncestorDocs.add(ancestor);
    }
  }
  return 1 + collectionGroupIds.size + names.length + unownedAncestorDocs.size;
}

export function productionCleanupRequestBound(corpus) {
  const { requestCount } = validateSandboxCorpus(corpus);
  const programs = corpus.restPrograms;
  const names = ownedMutationNamesForPrograms(programs);
  const boundaryNames = sandboxManagedClearNames(corpus);
  if (!boundaryNames.every((name) => names.includes(name))) {
    throw new Error("exact cleanup request bound omitted a frozen boundary target");
  }
  const managedRequestBound = exactInventoryRequestBound(names);
  const perProgramCleanupRequestBound = programs.reduce((total, program) => {
    const targets = ownedMutationNamesForPrograms([program]);
    return total + (targets.length ? exactInventoryRequestBound(targets) : 1);
  }, 0);
  return {
    mutationNameCount: names.length,
    rootCollectionCount: new Set(
      names.map((name) => name.slice(name.indexOf("/documents/") + 11).split("/")[0]),
    ).size,
    nestedTargetCount: names.filter(
      (name) => name.slice(name.indexOf("/documents/") + 11).split("/").length > 2,
    ).length,
    managedRequestBound,
    perProgramCleanupRequestBound,
    totalRequestBound: requestCount + managedRequestBound + perProgramCleanupRequestBound,
  };
}

export function requireBoundedProductionCleanup(corpus) {
  const bound = productionCleanupRequestBound(corpus);
  if (bound.managedRequestBound > V3_MANAGED_CLEAR_CAP || bound.totalRequestBound > REST_CAP) {
    throw new Error(
      `production v3 cleanup is blocked: exact inventory needs ${bound.managedRequestBound} initial managed requests and ${bound.totalRequestBound} total requests before deletes; caps are ${V3_MANAGED_CLEAR_CAP} and ${REST_CAP}, and generic broad clear is disabled`,
    );
  }
  return bound;
}

export async function withBoundedProductionCleanup(corpus, work) {
  if (typeof work !== "function") throw new Error("bounded production work callback is required");
  const bound = requireBoundedProductionCleanup(corpus);
  return work(bound);
}

export async function withSandboxExclusiveLock(privateDir, work) {
  const lockPath = join(privateDir, "fs-data-write-exclusive.lock");
  try {
    await mkdir(lockPath, { mode: 0o700 });
  } catch (error) {
    if (error?.code === "EEXIST") {
      throw new Error(
        "sandbox lock remains: verify no recording or recovery process is active, preserve its journal and reservation, then remove only the exact lock directory before retrying recovery",
        { cause: error },
      );
    }
    throw error;
  }
  const rows = await readLedger(join(privateDir, "sandbox-ledger.jsonl"));
  const result = await work(rows);
  await rmdir(lockPath);
  return result;
}

export function productionRestEnvironment({
  input,
  output,
  meta,
  token,
  managedNames,
  journal,
  runId,
  corpusDigest,
  sourceGitSha,
  deltaV3 = false,
}) {
  if (
    ![input, output, meta, token, journal].every(
      (value) => typeof value === "string" && value.length > 0,
    )
  ) {
    throw new Error("production REST session inputs are required");
  }
  if (
    !/^[a-f0-9]{32}$/.test(runId ?? "") ||
    !/^[a-f0-9]{64}$/.test(corpusDigest ?? "") ||
    !/^[a-f0-9]{40}$/.test(sourceGitSha ?? "")
  ) {
    throw new Error("production REST cleanup provenance is required");
  }
  if (
    !Array.isArray(managedNames) ||
    (deltaV3
      ? managedNames.length !== 6 ||
        managedShrinkScope(managedNames, SANDBOX_PROJECT, "(default)") !== "delta-v3"
      : managedNames.length !== 12)
  ) {
    throw new Error("production managed-clear names do not match the selected exact scope");
  }
  managedClearScope(managedNames, SANDBOX_PROJECT, "(default)");
  return {
    FIRESTORE_PROBE_TARGET: "production",
    FIRESTORE_PROBE_SCHEME: "https",
    FIRESTORE_PROBE_HOST: "firestore.googleapis.com",
    FIRESTORE_PROBE_TOKEN: token,
    FIRESTORE_PROBE_PROJECT: SANDBOX_PROJECT,
    FIRESTORE_PROBE_RECORD_PROJECT: RECORDED_PROJECT,
    FIRESTORE_PROBE_IN: input,
    FIRESTORE_PROBE_OUT: output,
    FIRESTORE_PROBE_META_OUT: meta,
    FIRESTORE_PROBE_MAX_REQUESTS: String(deltaV3 ? 430 : REST_CAP),
    FIRESTORE_PROBE_TIMEOUT_MS: "180000",
    FIRESTORE_PROBE_MANAGED_CLEAR_NAMES: JSON.stringify(managedNames),
    FIRESTORE_PROBE_MANAGED_CLEAR_JOURNAL: deltaV3 ? undefined : journal,
    FIRESTORE_PROBE_DELTA_V3: deltaV3 ? "1" : undefined,
    FIRESTORE_PROBE_DELTA_LOCK_HELD: deltaV3 ? "1" : undefined,
    FIRESTORE_PROBE_DELTA_JOURNAL: deltaV3 ? journal : undefined,
    FIRESTORE_PROBE_DELETE_RUN_ID: runId,
    FIRESTORE_PROBE_CORPUS_DIGEST: corpusDigest,
    FIRESTORE_PROBE_SOURCE_GIT_SHA: sourceGitSha,
  };
}

async function runNode(name, script, env, timeout = 1_200_000) {
  try {
    const childEnv = { ...process.env, ...env };
    for (const [key, value] of Object.entries(childEnv)) {
      if (value === undefined) delete childEnv[key];
    }
    await execFileAsync("node", [join(CONFORMANCE_DIR, "src", script)], {
      cwd: CONFORMANCE_DIR,
      env: childEnv,
      timeout,
      maxBuffer: 1024 * 1024,
    });
  } catch (error) {
    throw new Error(`${name} failed: ${String(error.stderr ?? error.message).slice(0, 2000)}`, {
      cause: error,
    });
  }
}

async function readLedger(path) {
  try {
    const content = await readFile(path, "utf8");
    return content
      .split("\n")
      .filter(Boolean)
      .map((line) => JSON.parse(line));
  } catch (error) {
    if (error.code === "ENOENT") return [];
    throw error;
  }
}

async function productionRecording({
  corpusIn,
  restIn,
  privateDir,
  gitSha,
  corpusDigest,
  restRequestCount,
  liveStreamCount,
  rows,
  managedNames,
  deltaV3 = false,
  streamFrameLimit = MAX_STREAM_FRAMES,
}) {
  const runDir = await mkdtemp(join(privateDir, "fs-data-write-production-"));
  const runId = randomUUID().replaceAll("-", "");
  const journal = join(runDir, deltaV3 ? "delta-cleanup.json" : "managed-clear.json");
  const ledgerPath = join(privateDir, "sandbox-ledger.jsonl");
  const { reservation, token } = await reserveProductionAttemptWithToken({
    ledgerPath,
    rows,
    gitSha,
    corpusDigest,
    runDir,
    acquireToken: productionAccessToken,
  });
  const restOut = join(runDir, "rest-results.json");
  const metaOut = join(runDir, "rest-meta.json");
  const streamOut = join(runDir, "stream-results.json");
  const startedAt = new Date().toISOString();
  let requestCount = null;
  let outcome = "failed";
  try {
    await runNode(
      "production REST",
      "firestore-probe/sandbox-session.mjs",
      productionRestEnvironment({
        input: restIn,
        output: restOut,
        meta: metaOut,
        token,
        managedNames,
        journal,
        runId,
        corpusDigest,
        sourceGitSha: gitSha,
        deltaV3,
      }),
      25_200_000,
    );
    const meta = JSON.parse(await readFile(metaOut, "utf8"));
    requestCount = sessionRequestCount(meta);
    if (requestCount < restRequestCount) {
      throw new Error("production REST request count escaped the bounded corpus");
    }
    if (
      deltaV3 &&
      requestCount >
        deltaV3RequestBound(JSON.parse(await readFile(corpusIn, "utf8"))).maxHttpRequests
    ) {
      throw new Error("delta-v3 HTTP requests exceeded the 430-attempt recording bound");
    }
    await runNode("production gRPC", "firestore-probe/stream-session.mjs", {
      FIRESTORE_STREAM_CORPUS: corpusIn,
      FIRESTORE_STREAM_OUT: streamOut,
      FIRESTORE_STREAM_TARGET: "production",
      FIRESTORE_STREAM_HOST: undefined,
      FIRESTORE_STREAM_PORT: undefined,
      FIRESTORE_STREAM_TOKEN: token,
    });
    const rest = JSON.parse(await readFile(restOut, "utf8"));
    const stream = JSON.parse(await readFile(streamOut, "utf8"));
    if (Object.keys(stream).length !== liveStreamCount)
      throw new Error("incomplete production stream set");
    const streamFrames = Object.values(stream).reduce((total, result) => {
      if (!Number.isInteger(result.sentFrames) || result.sentFrames < 1) {
        throw new Error("invalid production stream frame count");
      }
      return total + result.sentFrames;
    }, 0);
    if (streamFrames !== streamFrameLimit) {
      throw new Error("production stream messages escaped the bounded corpus");
    }
    outcome = "recorded";
    return { rest, stream, startedAt, runDir, journal, runId, requestCount, streamFrames, token };
  } finally {
    if (requestCount === null) {
      try {
        requestCount = sessionRequestCount(JSON.parse(await readFile(metaOut, "utf8")));
      } catch {
        // An early transport failure may leave no metadata; the cost reservation still stands.
      }
    }
    const entry = sandboxLedgerEntry({
      gitSha,
      corpusDigest,
      requests: requestCount,
      ...(outcome === "recorded" ? { streamFrames: streamFrameLimit } : {}),
      outcome,
      runDir,
      estimatedUsd: ATTEMPT_ESTIMATE_USD,
      attemptId: reservation.attemptId,
    });
    const handle = await open(ledgerPath, "a", 0o600);
    try {
      await handle.writeFile(`${JSON.stringify(entry)}\n`);
      await handle.sync();
    } finally {
      await handle.close();
    }
    rows.push(entry);
  }
}

async function recordProduction() {
  const gitCommonDir = (
    await execFileAsync("git", ["rev-parse", "--path-format=absolute", "--git-common-dir"], {
      cwd: ROOT,
    })
  ).stdout.trim();
  const ledgerPath = sandboxLedgerPath(gitCommonDir);
  const privateDir = dirname(ledgerPath);
  const { corpus, restRequestCount, liveStreamCount } = await prepareSandboxCorpus();
  requireBoundedProductionCleanup(corpus);
  const managedNames = sandboxManagedClearNames(corpus);
  const corpusDigest = sha256(JSON.stringify(corpus));
  const gitSha = (await execFileAsync("git", ["rev-parse", "HEAD"], { cwd: ROOT })).stdout.trim();
  const rows = await readLedger(ledgerPath);
  requireHistoricalUnknownHold(rows);
  remainingSandboxBudget(rows, ATTEMPT_ESTIMATE_USD * 2);
  await mkdir(privateDir, { recursive: true });
  await mkdir(RUNS_DIR, { recursive: true });
  const generatedDir = await mkdtemp(join(RUNS_DIR, "fs-data-write-corpus-"));
  const corpusIn = join(generatedDir, "corpus.json");
  const restIn = join(generatedDir, "rest-programs.json");
  await writeFile(corpusIn, JSON.stringify(corpus));
  await writeFile(restIn, JSON.stringify(corpus.restPrograms));
  // The lock spans both recordings and any managed-delete LRO. Failed work retains it.
  await withSandboxExclusiveLock(privateDir, async (lockedRows) => {
    requireHistoricalUnknownHold(lockedRows);
    remainingSandboxBudget(lockedRows, ATTEMPT_ESTIMATE_USD * 2);
    const first = await productionRecording({
      corpusIn,
      restIn,
      privateDir,
      gitSha,
      corpusDigest,
      restRequestCount,
      liveStreamCount,
      rows: lockedRows,
      managedNames,
    });
    const second = await productionRecording({
      corpusIn,
      restIn,
      privateDir,
      gitSha,
      corpusDigest,
      restRequestCount,
      liveStreamCount,
      rows: lockedRows,
      managedNames,
    });
    for (const recording of [first, second]) {
      const state = JSON.parse(await readFile(recording.journal, "utf8"));
      if (state.status !== "complete" || state.mode !== "cleanup-corpus-v3") {
        throw new Error("managed clear operation is not verified complete");
      }
    }
    const sdkVersions = {
      firebase: require("firebase/package.json").version,
      firebaseAdmin: require("firebase-admin").SDK_VERSION,
      firestore: require("@google-cloud/firestore/package.json").version,
      grpc: require("@grpc/grpc-js/package.json").version,
    };
    const fixture = freezeSandboxFixture({
      corpus,
      first: first.rest,
      second: second.rest,
      firstStream: first.stream,
      secondStream: second.stream,
      recordedAt: [first.startedAt, second.startedAt],
      harnessRevision: gitSha,
      sdkVersions,
      credentialToken: first.token,
    });
    const output = join(CONFORMANCE_DIR, "fs-data-write-production-matrix.json");
    await writeFile(output, `${JSON.stringify(fixture, null, 2)}\n`);
    process.stdout.write(
      `${JSON.stringify({ output, firstRunDir: first.runDir, secondRunDir: second.runDir, requestCount: first.requestCount + second.requestCount, corpusDigest })}\n`,
    );
  });
}

function classifyRecordingDeletePairs(rest) {
  return Object.fromEntries(
    DELTA_DELETE_ROUTES.map((route) => {
      const proofFor = (count) =>
        rest[`writes/limits/near-limit-delete-refusal/${route}/${count}`]?.deleteProof;
      return [route, classifyDeltaV3DeletePair(route, proofFor(12112), proofFor(12113))];
    }),
  );
}

export async function recordDeltaV3Production() {
  assertDeltaV3ProductionAdmission({ host: "firestore.googleapis.com" });
  const gitCommonDir = (
    await execFileAsync("git", ["rev-parse", "--path-format=absolute", "--git-common-dir"], {
      cwd: ROOT,
    })
  ).stdout.trim();
  const ledgerPath = sandboxLedgerPath(gitCommonDir);
  const privateDir = dirname(ledgerPath);
  const { corpus } = await prepareSandboxCorpus();
  const fixture = JSON.parse(
    await readFile(join(CONFORMANCE_DIR, "fs-data-write-production-matrix.json"), "utf8"),
  );
  const manifest = JSON.parse(
    await readFile(join(CONFORMANCE_DIR, "fs-data-write-recipe-digests.json"), "utf8"),
  );
  const selection = selectDeltaV3Recipes(corpus, fixture, manifest);
  const recordingCorpus = {
    schemaVersion: 1,
    sourceCorpusSha256: selection.sourceCorpusDigest,
    restPrograms: selection.recordingCorpus.restPrograms,
    streamRecipes: selection.recordingCorpus.streamRecipes,
    restRequestCount: selection.recordingCorpus.restRequestCount,
  };
  const bound = deltaV3RequestBound(recordingCorpus);
  const managedNames = deltaV3ManagedClearNames(recordingCorpus);
  const corpusDigest = selection.sourceCorpusDigest;
  const gitSha = (await execFileAsync("git", ["rev-parse", "HEAD"], { cwd: ROOT })).stdout.trim();
  const rows = await readLedger(ledgerPath);
  requireHistoricalUnknownHold(rows);
  remainingSandboxBudget(rows, ATTEMPT_ESTIMATE_USD * 2);
  await mkdir(privateDir, { recursive: true });
  await mkdir(RUNS_DIR, { recursive: true });
  const generatedDir = await mkdtemp(join(RUNS_DIR, "fs-data-write-delta-v3-"));
  const corpusIn = join(generatedDir, "delta-corpus.json");
  await writeFile(corpusIn, JSON.stringify(recordingCorpus));
  await withSandboxExclusiveLock(privateDir, async (lockedRows) => {
    requireHistoricalUnknownHold(lockedRows);
    remainingSandboxBudget(lockedRows, ATTEMPT_ESTIMATE_USD * 2);
    const recordings = [];
    for (let index = 0; index < 2; index += 1) {
      recordings.push(
        await productionRecording({
          corpusIn,
          restIn: corpusIn,
          privateDir,
          gitSha,
          corpusDigest,
          restRequestCount: bound.declaredHttp,
          liveStreamCount: 1,
          rows: lockedRows,
          managedNames,
          deltaV3: true,
          streamFrameLimit: bound.maxStreamFrames,
        }),
      );
    }
    if (recordings[0].runId === recordings[1].runId) {
      throw new Error("delta-v3 recordings reused a run-specific collection group");
    }
    for (const recording of recordings) {
      const journal = JSON.parse(await readFile(recording.journal, "utf8"));
      if (journal.status !== "complete" || journal.mode !== "cleanup-delta-v3") {
        throw new Error("delta-v3 cleanup is unresolved; preserve the lock and journal");
      }
      if (recording.requestCount > bound.maxHttpRequests || recording.streamFrames !== 2) {
        throw new Error("delta-v3 recording exceeded its separate HTTP/frame request bounds");
      }
    }
    const routeEvidence = recordings.map((recording) =>
      classifyRecordingDeletePairs(recording.rest),
    );
    const routeTasks = Object.fromEntries(
      DELTA_DELETE_ROUTES.map((route) => [
        route,
        routeEvidence.some(
          (evidence) => evidence[route].status === "route-specific-exploration-required",
        )
          ? "requires-one-reviewed-route-specific-exploration"
          : routeEvidence.every((evidence) => evidence[route].status === "adjacent-boundary")
            ? "adjacent-boundary-observed-twice"
            : "pending-indeterminate",
      ]),
    );
    const summary = {
      status: "PENDING_INDEPENDENT_REVIEW",
      sourceCorpusDigest: corpusDigest,
      routeTasks,
      routeEvidence,
      deltaRestIds: selection.deltaRestIds,
      deltaStreamIds: selection.deltaStreamIds,
      retainedRestIds: selection.retainedRestIds,
      retainedStreamIds: selection.retainedStreamIds,
      pendingRestIds: selection.pendingRestIds,
      pendingStreamIds: selection.pendingStreamIds,
      recordings: recordings.map(
        ({ runId, runDir, startedAt, requestCount, streamFrames, rest, stream }) => ({
          runId,
          runDir,
          startedAt,
          httpRequests: requestCount,
          streamFrames,
          rest,
          stream,
        }),
      ),
      resultsIdentical:
        JSON.stringify(recordings[0].rest) === JSON.stringify(recordings[1].rest) &&
        JSON.stringify(recordings[0].stream) === JSON.stringify(recordings[1].stream),
    };
    const output = join(generatedDir, "delta-v3-recordings.json");
    await writeFile(output, `${JSON.stringify(summary, null, 2)}\n`, { mode: 0o600 });
    process.stdout.write(
      `${JSON.stringify({ output, routeTasks, resultsIdentical: summary.resultsIdentical, bounds: bound })}\n`,
    );
  });
}

async function productionAccessToken() {
  const token =
    process.env.FIREEMU_PRODUCTION_TOKEN ??
    (
      await execFileAsync("gcloud", ["auth", "application-default", "print-access-token"], {
        maxBuffer: 4096,
      })
    ).stdout;
  if (!token.trim()) throw new Error("production OAuth bearer is missing");
  return token.trim();
}

async function recoverLegacy() {
  const gitCommonDir = (
    await execFileAsync("git", ["rev-parse", "--path-format=absolute", "--git-common-dir"], {
      cwd: ROOT,
    })
  ).stdout.trim();
  const ledgerPath = sandboxLedgerPath(gitCommonDir);
  const privateDir = dirname(ledgerPath);
  await mkdir(privateDir, { recursive: true, mode: 0o700 });
  const names = legacyManagedClearNames();
  const corpusDigest = sha256(JSON.stringify({ mode: "recover-legacy", names }));
  const gitSha = (await execFileAsync("git", ["rev-parse", "HEAD"], { cwd: ROOT })).stdout.trim();
  const result = await withLegacyRecoveryReservation(
    privateDir,
    async () => ({
      gitSha,
      corpusDigest,
      ...(await prepareLegacyRecoveryRun(privateDir, corpusDigest, names)),
    }),
    async ({ meta, journal, resume }) => {
      const token = (
        process.env.FIREEMU_PRODUCTION_TOKEN ??
        (
          await execFileAsync("gcloud", ["auth", "application-default", "print-access-token"], {
            maxBuffer: 4096,
          })
        ).stdout
      ).trim();
      if (!token) throw new Error("production OAuth bearer is missing");
      let outcome = "recovery-failed";
      let requestCount = null;
      try {
        await runNode(
          "legacy array recovery",
          "firestore-probe/sandbox-session.mjs",
          legacyRecoveryEnvironment({ token, meta, journal, names }),
          1_200_000,
        );
        const state = JSON.parse(await readFile(journal, "utf8"));
        if (state.status !== "complete" || state.mode !== "recover-legacy") {
          throw new Error("legacy recovery did not verify exact typed absence");
        }
        outcome = "recovered";
      } finally {
        try {
          requestCount = sessionRequestCount(JSON.parse(await readFile(meta, "utf8")));
        } catch {
          // The reservation remains charged when a child fails before emitting metadata.
        }
      }
      return {
        outcome,
        requestCount,
        journal,
        meta,
        resumedFrom: resume ? { runDir: resume.runDir, sourceGitSha: resume.sourceGitSha } : null,
      };
    },
  );
  process.stdout.write(
    `${JSON.stringify({
      ...result,
      corpusDigest,
    })}\n`,
  );
}

async function localChild() {
  const { host, port } = localTarget(process.env.FIRESTORE_EMULATOR_HOST);
  const { corpus, restRequestCount } = await prepareSandboxCorpus();
  await mkdir(RUNS_DIR, { recursive: true });
  const runDir = await mkdtemp(join(RUNS_DIR, "fs-data-write-local-"));
  const restIn = join(runDir, "rest-programs.json");
  const corpusIn = join(runDir, "corpus.json");
  const restOut = join(runDir, "rest-results.json");
  const metaOut = join(runDir, "rest-meta.json");
  const streamOut = join(runDir, "stream-results.json");
  await writeFile(restIn, JSON.stringify(corpus.restPrograms));
  await writeFile(corpusIn, JSON.stringify(corpus));
  await runNode("local REST", "firestore-probe/sandbox-session.mjs", {
    FIRESTORE_PROBE_TARGET: "local",
    FIRESTORE_PROBE_HOST: `${host}:${port}`,
    FIRESTORE_PROBE_SCHEME: "http",
    FIRESTORE_PROBE_TOKEN: "owner",
    FIRESTORE_PROBE_PROJECT: SANDBOX_PROJECT,
    FIRESTORE_PROBE_RECORD_PROJECT: RECORDED_PROJECT,
    FIRESTORE_PROBE_IN: restIn,
    FIRESTORE_PROBE_OUT: restOut,
    FIRESTORE_PROBE_META_OUT: metaOut,
    FIRESTORE_PROBE_MAX_REQUESTS: String(REST_CAP),
  });
  const metadata = JSON.parse(await readFile(metaOut, "utf8"));
  if (metadata.requestCount < restRequestCount || metadata.requestCount > REST_CAP) {
    throw new Error("local REST request count escaped the bounded corpus");
  }
  await runNode("local gRPC", "firestore-probe/stream-session.mjs", {
    FIRESTORE_STREAM_CORPUS: corpusIn,
    FIRESTORE_STREAM_OUT: streamOut,
    FIRESTORE_STREAM_TARGET: "local",
    FIRESTORE_STREAM_HOST: host,
    FIRESTORE_STREAM_PORT: String(port),
    FIRESTORE_STREAM_TOKEN: "owner",
  });
  const rest = JSON.parse(await readFile(restOut, "utf8"));
  const stream = JSON.parse(await readFile(streamOut, "utf8"));
  process.stdout.write(
    `${JSON.stringify({ runDir, restPrograms: Object.keys(rest).length, restRequests: metadata.requestCount, streamRecipes: Object.keys(stream).length })}\n`,
  );
}

async function compareLocal(runDir) {
  if (typeof runDir !== "string" || !runDir) throw new Error("local run directory is required");
  const { corpus } = await prepareSandboxCorpus();
  const fixture = JSON.parse(
    await readFile(join(CONFORMANCE_DIR, "fs-data-write-production-matrix.json"), "utf8"),
  );
  const localCorpus = JSON.parse(await readFile(join(runDir, "corpus.json"), "utf8"));
  const corpusDigest = sha256(JSON.stringify(corpus));
  const rest = JSON.parse(await readFile(join(runDir, "rest-results.json"), "utf8"));
  const stream = JSON.parse(await readFile(join(runDir, "stream-results.json"), "utf8"));
  let comparison;
  if (fixture.evidence.corpusSha256 === corpusDigest) {
    assertMatchingSandboxCorpus(fixture, corpus, localCorpus);
    comparison = {
      fixture,
      corpus,
      matchedRestIds: corpus.restPrograms.map((program) => program.id),
      pendingRestIds: [],
      matchedStreamIds: corpus.streamRecipes
        .filter((recipe) => recipe.transport === "grpc")
        .map((recipe) => recipe.id),
      pendingStreamIds: [],
    };
  } else {
    const manifest = JSON.parse(
      await readFile(join(CONFORMANCE_DIR, "fs-data-write-recipe-digests.json"), "utf8"),
    );
    comparison = selectComparableSandboxRecipes(fixture, manifest, corpus, localCorpus);
  }
  const comparedRest = Object.fromEntries(comparison.matchedRestIds.map((id) => [id, rest[id]]));
  const comparedStreams = Object.fromEntries(
    comparison.matchedStreamIds.map((id) => [id, stream[id]]),
  );
  const differences = compareSandboxArtifact(
    comparison.fixture,
    comparedRest,
    comparedStreams,
    comparison.corpus,
  );
  process.stdout.write(
    `${JSON.stringify({ corpusDigest, recordedCorpusDigest: fixture.evidence.corpusSha256, comparedPrograms: comparison.matchedRestIds.length, comparedStreams: comparison.matchedStreamIds.length, pendingRestIds: comparison.pendingRestIds, pendingStreamIds: comparison.pendingStreamIds, mismatches: differences.length, differences })}\n`,
  );
  process.exitCode = comparisonExitCode(
    differences,
    comparison.pendingRestIds,
    comparison.pendingStreamIds,
  );
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  if (process.argv[2] === "local-child") {
    await localChild();
  } else if (process.argv[2] === "compare-local") {
    await compareLocal(process.argv[3]);
  } else if (process.argv[2] === "record-production") {
    await recordProduction();
  } else if (process.argv[2] === "recover-legacy") {
    await recoverLegacy();
  } else if (process.argv[2] === "recover-v3") {
    await recoverV3();
  } else if (process.argv[2] === "recover-delta-v3") {
    await recoverDeltaV3();
  } else if (process.argv[2] === "prepare") {
    const prepared = await prepareSandboxCorpus();
    process.stdout.write(
      `${JSON.stringify({ programs: prepared.corpus.restPrograms.length, restRequests: prepared.restRequestCount, liveStreamRecipes: prepared.liveStreamCount })}\n`,
    );
  } else {
    throw new Error(
      "expected prepare, local-child, compare-local, record-production, recover-legacy, recover-v3 or recover-delta-v3",
    );
  }
}
