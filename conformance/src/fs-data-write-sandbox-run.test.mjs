import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { legacyManagedClearNames } from "./firestore-probe/sandbox-session.mjs";

import {
  MAX_STREAM_FRAMES,
  assertMatchingSandboxCorpus,
  comparisonExitCode,
  findLegacyRecoveryResume,
  findV3RecoveryResume,
  findDeltaV3RecoveryResume,
  localTarget,
  prepareLegacyRecoveryRun,
  legacyRecoveryEnvironment,
  v3RecoveryEnvironment,
  deltaV3RecoveryEnvironment,
  deltaV3RecoveryOutcome,
  prepareSandboxCorpus,
  productionRestEnvironment,
  remainingSandboxBudget,
  selectComparableSandboxRecipes,
  selectDeltaV3Recipes,
  deltaV3RequestBound,
  deltaV3ManagedClearNames,
  sessionRequestCount,
  withSandboxExclusiveLock,
  withLegacyRecoveryReservation,
  sandboxLedgerEntry,
  reserveProductionAttempt,
  reserveProductionAttemptWithToken,
  requireHistoricalUnknownHold,
  sandboxLedgerPath,
  sandboxManagedClearNames,
  productionCleanupRequestBound,
  requireBoundedProductionCleanup,
  withBoundedProductionCleanup,
} from "./fs-data-write-sandbox-run.mjs";

const unknownHold = () => ({
  ts: "2026-09-24T00:00:00.000Z",
  project: "fireemu-oracle-sbx",
  database: "(default)",
  taskId: "FS-DATA-WRITE-SANDBOX",
  outcome: "historical-unknown-hold",
  requests: null,
  estimatedUsd: 9.24,
  holdId: "FS-DATA-WRITE-SANDBOX-2026-09-24-HISTORICAL-UNKNOWN",
});

test("local comparison refuses a fixture or run from a different corpus", () => {
  const corpus = { schemaVersion: 1, restPrograms: [], restRequestCount: 0 };
  const digest = "2a83e139b5c7a9b82d414b3b6fbbcac82fd1825a79932be9afdee320729542d2";
  assert.equal(
    assertMatchingSandboxCorpus({ evidence: { corpusSha256: digest } }, corpus, corpus),
    digest,
  );
  assert.throws(
    () =>
      assertMatchingSandboxCorpus({ evidence: { corpusSha256: "0".repeat(64) } }, corpus, corpus),
    /fixture corpus/,
  );
  assert.throws(
    () =>
      assertMatchingSandboxCorpus({ evidence: { corpusSha256: digest } }, corpus, {
        ...corpus,
        restRequestCount: 1,
      }),
    /local corpus/,
  );
});

test("a partial saved replay cannot pass as complete compatibility", () => {
  assert.equal(comparisonExitCode([], [], []), 0);
  assert.equal(comparisonExitCode([], ["changed"], []), 2);
  assert.equal(comparisonExitCode([], [], ["stream"]), 2);
  assert.equal(comparisonExitCode(["mismatch"], ["changed"], []), 1);
});

test("saved production comparison selects only identical program recipes and reports changed ones", () => {
  const digest = (value) => createHash("sha256").update(JSON.stringify(value)).digest("hex");
  const saved = {
    id: "saved",
    steps: [
      {
        id: "write",
        method: "POST",
        path: "/v1/projects/fireemu-oracle-sbx/databases/(default)/documents:commit",
      },
    ],
  };
  const changed = {
    id: "changed",
    steps: [
      {
        id: "write",
        method: "POST",
        path: "/v1/projects/fireemu-oracle-sbx/databases/(default)/documents:commit",
      },
    ],
  };
  const recordedCorpus = {
    schemaVersion: 1,
    restPrograms: [saved, changed],
    streamRecipes: [],
    restRequestCount: 2,
  };
  const currentCorpus = {
    ...recordedCorpus,
    restPrograms: [
      saved,
      {
        ...changed,
        steps: [
          ...changed.steps,
          {
            id: "readback",
            method: "GET",
            path: "/v1/projects/fireemu-oracle-sbx/databases/(default)/documents/c/x",
          },
        ],
      },
    ],
    restRequestCount: 3,
  };
  const manifest = {
    schemaVersion: 1,
    sourceCommit: "a".repeat(40),
    corpusSha256: digest(recordedCorpus),
    programs: { saved: digest(saved), changed: digest(changed) },
    streams: {},
  };
  const fixture = {
    evidence: { corpusSha256: digest(recordedCorpus), harnessRevision: "a".repeat(40) },
    programs: {
      saved: { steps: { write: { status: 200, code: "OK", body: {} } } },
      changed: { steps: { write: { status: 200, code: "OK", body: {} } } },
    },
    streams: {},
  };
  const selected = selectComparableSandboxRecipes(fixture, manifest, currentCorpus, currentCorpus);
  assert.deepEqual(selected.matchedRestIds, ["saved"]);
  assert.deepEqual(selected.pendingRestIds, ["changed"]);
  assert.deepEqual(Object.keys(selected.fixture.programs), ["saved"]);
  assert.deepEqual(
    selected.corpus.restPrograms.map((program) => program.id),
    ["saved"],
  );
  assert.throws(
    () =>
      selectComparableSandboxRecipes(
        fixture,
        { ...manifest, sourceCommit: "b".repeat(40) },
        currentCorpus,
        currentCorpus,
      ),
    /manifest source/,
  );
  assert.throws(
    () =>
      selectComparableSandboxRecipes(
        fixture,
        { ...manifest, corpusSha256: "0".repeat(64) },
        currentCorpus,
        currentCorpus,
      ),
    /manifest corpus/,
  );
  assert.throws(
    () => selectComparableSandboxRecipes(fixture, manifest, currentCorpus, recordedCorpus),
    /local corpus/,
  );
});

test("delta-v3 selection keeps only the six deletes and stream while partitioning every recipe", async () => {
  const { corpus } = await prepareSandboxCorpus();
  const digest = (value) => createHash("sha256").update(JSON.stringify(value)).digest("hex");
  const deltaIds = new Set(
    ["rest", "commit", "batch-write"].flatMap((route) =>
      [12112, 12113].map((count) => `writes/limits/near-limit-delete-refusal/${route}/${count}`),
    ),
  );
  const savedProgram = corpus.restPrograms.find((program) => !deltaIds.has(program.id));
  const changedProgram = corpus.restPrograms.find(
    (program) => program.id !== savedProgram.id && !deltaIds.has(program.id),
  );
  const savedStream = corpus.streamRecipes.find(
    (recipe) =>
      recipe.transport === "grpc" &&
      recipe.id !== "writes/write-stream-terminal/response-before-half-close",
  );
  const sourceCommit = "a".repeat(40);
  const oldDigest = "b".repeat(64);
  const fixture = {
    evidence: { corpusSha256: oldDigest, harnessRevision: sourceCommit },
    programs: {
      [savedProgram.id]: { steps: {} },
      [changedProgram.id]: { steps: {} },
    },
    streams: { [savedStream.id]: {} },
  };
  const manifest = {
    schemaVersion: 1,
    sourceCommit,
    corpusSha256: oldDigest,
    programs: {
      [savedProgram.id]: digest(savedProgram),
      [changedProgram.id]: "c".repeat(64),
    },
    streams: { [savedStream.id]: digest(savedStream) },
  };
  const selected = selectDeltaV3Recipes(corpus, fixture, manifest);
  assert.deepEqual(new Set(selected.deltaRestIds), deltaIds);
  assert.deepEqual(selected.deltaStreamIds, [
    "writes/write-stream-terminal/response-before-half-close",
  ]);
  assert.deepEqual(selected.retainedRestIds, [savedProgram.id]);
  assert.deepEqual(selected.retainedStreamIds, [savedStream.id]);
  assert.ok(selected.pendingRestIds.includes(changedProgram.id));
  assert.ok(!selected.pendingRestIds.includes(savedProgram.id));
  assert.ok(!selected.pendingRestIds.some((id) => deltaIds.has(id)));
  assert.deepEqual(
    new Set([...selected.deltaRestIds, ...selected.retainedRestIds, ...selected.pendingRestIds]),
    new Set(corpus.restPrograms.map((program) => program.id)),
  );
  assert.deepEqual(
    new Set([
      ...selected.deltaStreamIds,
      ...selected.retainedStreamIds,
      ...selected.pendingStreamIds,
    ]),
    new Set(
      corpus.streamRecipes
        .filter((recipe) => recipe.transport === "grpc")
        .map((recipe) => recipe.id),
    ),
  );
  assert.equal(selected.recordingCorpus.restRequestCount, 30);
  assert.equal(selected.recordingCorpus.streamRecipes.length, 1);
  const ownedNames = deltaV3ManagedClearNames(selected.recordingCorpus);
  assert.equal(ownedNames.length, 6);
  assert.equal(new Set(ownedNames).size, 6);
  assert.deepEqual(deltaV3RequestBound(selected.recordingCorpus), {
    declaredHttp: 30,
    managedHttpCap: 400,
    maxHttpRequests: 430,
    maxStreamFrames: 2,
    maxCombinedOperations: 432,
  });
});

test("delta-v3 production REST environment uses only the six names and strict HTTP cap", async () => {
  const { corpus } = await prepareSandboxCorpus();
  const programs = corpus.restPrograms.filter((program) =>
    program.id.startsWith("writes/limits/near-limit-delete-refusal/"),
  );
  const names = deltaV3ManagedClearNames({ restPrograms: programs });
  const env = productionRestEnvironment({
    input: "/private/delta-corpus.json",
    output: "/private/rest.json",
    meta: "/private/meta.json",
    token: "not-used",
    managedNames: names,
    journal: "/private/delta-cleanup.json",
    runId: "a".repeat(32),
    corpusDigest: "b".repeat(64),
    sourceGitSha: "c".repeat(40),
    deltaV3: true,
  });
  assert.equal(env.FIRESTORE_PROBE_MAX_REQUESTS, "430");
  assert.equal(env.FIRESTORE_PROBE_DELTA_V3, "1");
  assert.equal(env.FIRESTORE_PROBE_DELTA_LOCK_HELD, "1");
  assert.equal(env.FIRESTORE_PROBE_DELTA_JOURNAL, "/private/delta-cleanup.json");
  assert.equal("FIRESTORE_PROBE_MANAGED_CLEAR_JOURNAL" in env, true);
  assert.equal(env.FIRESTORE_PROBE_MANAGED_CLEAR_JOURNAL, undefined);
  assert.equal(JSON.parse(env.FIRESTORE_PROBE_MANAGED_CLEAR_NAMES).length, 6);
});

test("delete pair classification is route-local and requires typed target and outcome proofs", async () => {
  const { classifyDeltaV3DeletePair } = await import("./fs-data-write-sandbox-run.mjs");
  assert.equal(typeof classifyDeltaV3DeletePair, "function");
  const accepted = {
    documentCount: 12112,
    deleteTargetExists: true,
    deleteOutcomeProven: true,
    postDeleteAbsent: true,
    groupEmpty: true,
    outcome: "accepted",
  };
  const refused = {
    documentCount: 12113,
    deleteTargetExists: true,
    deleteOutcomeProven: true,
    postDeletePresent: true,
    groupContainsTarget: true,
    outcome: "refused",
  };
  assert.deepEqual(classifyDeltaV3DeletePair("rest", accepted, refused), {
    status: "adjacent-boundary",
    route: "rest",
  });
  assert.deepEqual(
    classifyDeltaV3DeletePair("commit", accepted, { ...accepted, documentCount: 12113 }),
    {
      status: "route-specific-exploration-required",
      route: "commit",
    },
  );
  assert.deepEqual(
    classifyDeltaV3DeletePair("batch-write", { ...accepted, deleteTargetExists: false }, refused),
    { status: "pending-indeterminate", route: "batch-write" },
  );
});

test("the runnable sandbox corpus combines bounded REST and live gRPC recipes", async () => {
  const { corpus, restRequestCount, liveStreamCount } = await prepareSandboxCorpus();
  assert.equal(corpus.restPrograms.length, 74);
  assert.equal(restRequestCount, 267);
  assert.equal(liveStreamCount, 7);
  assert.equal(MAX_STREAM_FRAMES, 9);
  assert.equal(
    corpus.streamRecipes
      .filter((recipe) => recipe.transport === "grpc")
      .reduce((total, recipe) => total + recipe.maxFrames, 0),
    9,
  );
});

test("all sandbox run directories share the canonical root ledger", () => {
  assert.equal(
    sandboxLedgerPath("/workspace/.git"),
    "/workspace/docs.local/runs/sandbox-ledger.jsonl",
  );
  assert.equal(
    sandboxLedgerPath("/workspace/.git", "/one/run"),
    sandboxLedgerPath("/workspace/.git", "/other/run"),
  );
});

test("production REST session fixes project, endpoint, managed scope and all-attempt cap", async () => {
  const { corpus } = await prepareSandboxCorpus();
  const managedNames = sandboxManagedClearNames(corpus);
  const env = productionRestEnvironment({
    input: "/tmp/input",
    output: "/tmp/output",
    meta: "/tmp/meta",
    token: "private",
    managedNames,
    journal: "/tmp/managed-clear.json",
    runId: "a".repeat(32),
    corpusDigest: "b".repeat(64),
    sourceGitSha: "c".repeat(40),
  });
  assert.equal(env.FIRESTORE_PROBE_PROJECT, "fireemu-oracle-sbx");
  assert.equal(env.FIRESTORE_PROBE_HOST, "firestore.googleapis.com");
  assert.equal(env.FIRESTORE_PROBE_MAX_REQUESTS, "1000");
  assert.equal(env.FIRESTORE_PROBE_RECORD_PROJECT, "demo-firestore-probe");
  assert.equal(env.FIRESTORE_PROBE_TOKEN, "private");
  assert.equal(env.FIRESTORE_PROBE_TIMEOUT_MS, "180000");
  assert.equal(env.FIRESTORE_PROBE_MANAGED_CLEAR_JOURNAL, "/tmp/managed-clear.json");
  assert.equal(env.FIRESTORE_PROBE_DELETE_RUN_ID, "a".repeat(32));
  assert.equal(env.FIRESTORE_PROBE_CORPUS_DIGEST, "b".repeat(64));
  assert.equal(env.FIRESTORE_PROBE_SOURCE_GIT_SHA, "c".repeat(40));
  assert.deepEqual(JSON.parse(env.FIRESTORE_PROBE_MANAGED_CLEAR_NAMES), managedNames);
  assert.equal(managedNames.length, 12);
  assert.throws(() => sandboxManagedClearNames({ ...corpus, restPrograms: [] }), /last/);
});

test("production cleanup is blocked before send when exact ownership exceeds fixed caps", async () => {
  const { corpus } = await prepareSandboxCorpus();
  assert.deepEqual(productionCleanupRequestBound(corpus), {
    mutationNameCount: 181,
    rootCollectionCount: 27,
    nestedTargetCount: 109,
    managedRequestBound: 462,
    perProgramCleanupRequestBound: 593,
    totalRequestBound: 1322,
  });
  assert.throws(
    () => requireBoundedProductionCleanup(corpus),
    /462 initial managed requests and 1322 total requests.*caps are 400 and 1000.*generic broad clear is disabled/,
  );
  let networkCalls = 0;
  await assert.rejects(
    withBoundedProductionCleanup(corpus, async () => {
      networkCalls += 1;
    }),
    /production v3 cleanup is blocked/,
  );
  assert.equal(networkCalls, 0);
});

test("corpus-v3 recovery locates only a private journal bound to its durable reservation", async () => {
  const directory = await mkdtemp(join(tmpdir(), "fireemu-v3-recovery-resume-"));
  const runDir = await mkdtemp(join(directory, "fs-data-write-production-"));
  const { corpus } = await prepareSandboxCorpus();
  const names = sandboxManagedClearNames(corpus);
  const runId = "e".repeat(32);
  const corpusDigest = "b".repeat(64);
  const gitSha = "a".repeat(40);
  const runtimeNames = names.map((name) => name.replaceAll("DELETE_RUN_ID", runId));
  const journal = join(runDir, "managed-clear.json");
  try {
    const reservation = sandboxLedgerEntry({
      gitSha,
      corpusDigest,
      requests: null,
      outcome: "reserved",
      runDir,
    });
    await writeFile(join(directory, "sandbox-ledger.jsonl"), `${JSON.stringify(reservation)}\n`, {
      mode: 0o600,
    });
    await writeFile(
      journal,
      JSON.stringify({
        schemaVersion: 1,
        mode: "cleanup-corpus-v3",
        status: "deleting",
        project: "fireemu-oracle-sbx",
        database: "(default)",
        runId,
        corpusDigest,
        sourceGitSha: gitSha,
        names: runtimeNames,
        deletedNames: [],
        deleteIntent: null,
      }),
      { mode: 0o600 },
    );
    const resume = await findV3RecoveryResume(directory, names);
    assert.equal(resume.journalPath, journal);
    assert.equal(resume.journal.runId, runId);
    assert.equal(resume.sourceGitSha, gitSha);
    assert.equal(
      v3RecoveryEnvironment({
        token: "private",
        meta: join(runDir, "meta.json"),
        journal,
        names,
        runId,
        corpusDigest,
        sourceGitSha: gitSha,
      }).FIRESTORE_PROBE_RECOVERY_MODE,
      "recover-v3",
    );

    await writeFile(journal, JSON.stringify({ ...resume.journal, names: runtimeNames.slice(1) }), {
      mode: 0o600,
    });
    await assert.rejects(findV3RecoveryResume(directory, names), /does not match/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("delta-v3 recovery resumes only its reserved six-name journal with the remaining HTTP window", async () => {
  const directory = await mkdtemp(join(tmpdir(), "fireemu-delta-recovery-"));
  const runDir = await mkdtemp(join(directory, "fs-data-write-production-"));
  const { corpus } = await prepareSandboxCorpus();
  const programs = corpus.restPrograms.filter((p) =>
    p.id.startsWith("writes/limits/near-limit-delete-refusal/"),
  );
  const names = deltaV3ManagedClearNames({ restPrograms: programs });
  const runId = "e".repeat(32);
  const corpusDigest = "b".repeat(64);
  const gitSha = "a".repeat(40);
  const runtimeNames = names.map((name) => name.replaceAll("DELETE_RUN_ID", runId));
  const journalPath = join(runDir, "delta-cleanup.json");
  try {
    const reservation = sandboxLedgerEntry({
      gitSha,
      corpusDigest,
      requests: null,
      outcome: "reserved",
      runDir,
    });
    await writeFile(join(directory, "sandbox-ledger.jsonl"), `${JSON.stringify(reservation)}\n`, {
      mode: 0o600,
    });
    await writeFile(
      journalPath,
      JSON.stringify({
        schemaVersion: 1,
        mode: "cleanup-delta-v3",
        status: "recovering",
        project: "fireemu-oracle-sbx",
        database: "(default)",
        runId,
        corpusDigest,
        sourceGitSha: gitSha,
        names: runtimeNames,
        writerExclusivity:
          "task-lock-held; run-specific six collection groups have no external writer",
        httpRequestCount: 30,
        managedRequestCount: 11,
        bulkDeleteIntent: true,
        bulkDeleteOperation: "projects/fireemu-oracle-sbx/databases/(default)/operations/op_1",
      }),
      { mode: 0o600 },
    );
    const resume = await findDeltaV3RecoveryResume(directory, names, corpusDigest);
    assert.equal(resume.journalPath, journalPath);
    const env = deltaV3RecoveryEnvironment({
      token: "private",
      meta: join(runDir, "recovery.json"),
      journal: journalPath,
      names: runtimeNames,
      runId,
      corpusDigest,
      sourceGitSha: gitSha,
      remainingHttp: 400,
    });
    assert.equal(env.FIRESTORE_PROBE_RECOVERY_MODE, "recover-delta-v3");
    assert.equal(env.FIRESTORE_PROBE_MAX_REQUESTS, "400");
    assert.equal(env.FIRESTORE_PROBE_DELTA_JOURNAL, journalPath);
    // Cancelling the journaled bulk delete is an explicit, per-use choice.
    assert.equal(env.FIRESTORE_PROBE_DELTA_V3_CANCEL_BULK_DELETE, undefined);
    const cancelling = deltaV3RecoveryEnvironment({
      token: "private",
      meta: join(runDir, "recovery.json"),
      journal: journalPath,
      names: runtimeNames,
      runId,
      corpusDigest,
      sourceGitSha: gitSha,
      remainingHttp: 400,
      cancelBulkDelete: true,
    });
    assert.equal(cancelling.FIRESTORE_PROBE_DELTA_V3_CANCEL_BULK_DELETE, "1");
    // A cancel run ends once the operation is terminal; only a plain run completes cleanup.
    assert.equal(deltaV3RecoveryOutcome("complete", false), "recovered");
    assert.equal(deltaV3RecoveryOutcome("bulk-delete-cancelled", true), "bulk-delete-cancelled");
    assert.equal(deltaV3RecoveryOutcome("bulk-delete-done", true), "bulk-delete-done");
    for (const [status, cancel] of [
      ["bulk-delete-cancelled", false],
      ["complete", true],
      ["bulk-delete-cancel-intent", true],
      ["request-reserved", false],
    ]) {
      assert.throws(() => deltaV3RecoveryOutcome(status, cancel), /did not/, `${status} ${cancel}`);
    }
    assert.throws(
      () =>
        deltaV3RecoveryEnvironment({
          token: "private",
          meta: "m",
          journal: journalPath,
          names: [...runtimeNames, "extra"],
          runId,
          corpusDigest,
          sourceGitSha: gitSha,
          remainingHttp: 400,
        }),
      /exact private/,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("a failed session still reports its bounded network attempts from metadata", () => {
  assert.equal(sessionRequestCount({ requestCount: 400 }), 400);
  assert.throws(() => sessionRequestCount({ requestCount: 1001 }), /bounded/);
});

test("the stable FS observation task carries attempts into its owner-approved thirty-dollar budget", () => {
  assert.equal(
    remainingSandboxBudget([{ taskId: "FS-DATA-WRITE-SANDBOX", estimatedUsd: 0.5 }]),
    29.5,
  );
  assert.equal(
    remainingSandboxBudget([{ taskId: "FS-DATA-WRITE-SANDBOX", estimatedUsd: 19.75 }], 0.5),
    10.25,
  );
  assert.throws(
    () => remainingSandboxBudget([{ taskId: "FS-DATA-WRITE-SANDBOX", estimatedUsd: 29.6 }], 0.5),
    /budget/,
  );
});

test("admission requires exactly one explicit historical unknown hold without request attribution", () => {
  const hold = {
    ts: "2026-09-24T00:00:00.000Z",
    project: "fireemu-oracle-sbx",
    database: "(default)",
    taskId: "FS-DATA-WRITE-SANDBOX",
    outcome: "historical-unknown-hold",
    requests: null,
    estimatedUsd: 9.24,
    holdId: "FS-DATA-WRITE-SANDBOX-2026-09-24-HISTORICAL-UNKNOWN",
  };
  assert.equal(requireHistoricalUnknownHold([hold]), hold);
  assert.throws(() => requireHistoricalUnknownHold([]), /historical unknown hold/);
  assert.throws(() => requireHistoricalUnknownHold([hold, hold]), /historical unknown hold/);
  assert.throws(
    () => requireHistoricalUnknownHold([{ ...hold, requests: 100 }]),
    /historical unknown hold/,
  );
});

test("a production attempt durably reserves budget before child work and refuses an exhausted ledger", async () => {
  const directory = await mkdtemp(join(tmpdir(), "fireemu-recording-reservation-"));
  const ledger = join(directory, "sandbox-ledger.jsonl");
  const rows = [];
  try {
    await assert.rejects(
      reserveProductionAttempt({
        ledgerPath: ledger,
        rows,
        gitSha: "a".repeat(40),
        corpusDigest: "b".repeat(64),
        runDir: join(directory, "no-hold"),
      }),
      /historical unknown hold/,
    );
    rows.push(unknownHold());
    const reservation = await reserveProductionAttempt({
      ledgerPath: ledger,
      rows,
      gitSha: "a".repeat(40),
      corpusDigest: "b".repeat(64),
      runDir: join(directory, "attempt"),
    });
    assert.equal(reservation.outcome, "reserved");
    assert.equal(reservation.requests, null);
    assert.equal(reservation.estimatedUsd, 0.5);
    assert.match(reservation.attemptId, /^[a-f0-9]{32}$/);
    assert.deepEqual(JSON.parse((await readFile(ledger, "utf8")).trim()), reservation);
    assert.ok(Math.abs(remainingSandboxBudget(rows, 0.5) - 20.26) < 1e-9);
    const secondReservation = await reserveProductionAttempt({
      ledgerPath: ledger,
      rows,
      gitSha: "a".repeat(40),
      corpusDigest: "b".repeat(64),
      runDir: join(directory, "attempt-2"),
    });
    assert.notEqual(secondReservation.attemptId, reservation.attemptId);
    assert.equal((await readFile(ledger, "utf8")).trim().split("\n").length, 2);
    rows.push(
      sandboxLedgerEntry({
        gitSha: reservation.gitSha,
        corpusDigest: reservation.corpusDigest,
        requests: 410,
        outcome: "recorded",
        runDir: reservation.runDir,
        attemptId: reservation.attemptId,
        estimatedUsd: 0.5,
      }),
    );
    assert.ok(Math.abs(remainingSandboxBudget(rows) - 19.76) < 1e-9);

    await assert.rejects(
      reserveProductionAttempt({
        ledgerPath: ledger,
        rows: [rows[0], { taskId: "FS-DATA-WRITE-SANDBOX", estimatedUsd: 30 }],
        gitSha: "c".repeat(40),
        corpusDigest: "d".repeat(64),
        runDir: join(directory, "denied"),
      }),
      /budget/,
    );
    assert.equal((await readFile(ledger, "utf8")).trim().split("\n").length, 2);
    assert.throws(
      () => remainingSandboxBudget([{ taskId: "FS-DATA-WRITE-SANDBOX", estimatedUsd: 29.6 }], 0.5),
      /budget/,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("production credentials are acquired under the lock only after the durable reservation", async () => {
  const directory = await mkdtemp(join(tmpdir(), "fireemu-token-reservation-order-"));
  const ledger = join(directory, "sandbox-ledger.jsonl");
  await writeFile(ledger, `${JSON.stringify(unknownHold())}\n`, { mode: 0o600 });
  try {
    const result = await withSandboxExclusiveLock(directory, async (rows) =>
      reserveProductionAttemptWithToken({
        ledgerPath: ledger,
        rows,
        gitSha: "a".repeat(40),
        corpusDigest: "b".repeat(64),
        runDir: join(directory, "attempt"),
        acquireToken: async () => {
          const lockExists = await stat(join(directory, "fs-data-write-exclusive.lock"))
            .then(() => true)
            .catch(() => false);
          assert.equal(lockExists, true);
          const saved = (await readFile(ledger, "utf8"))
            .trim()
            .split("\n")
            .map((line) => JSON.parse(line));
          assert.equal(saved.at(-1).outcome, "reserved");
          assert.equal(saved.at(-1).requests, null);
          return "test-token";
        },
      }),
    );
    assert.equal(result.token, "test-token");
    assert.equal(result.reservation.outcome, "reserved");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("private append-only ledger names project, database, bounded requests and cost", () => {
  const entry = sandboxLedgerEntry({
    gitSha: "a".repeat(40),
    corpusDigest: "b".repeat(64),
    requests: 237,
    outcome: "recorded",
    runDir: "/private/run",
  });
  assert.equal(entry.project, "fireemu-oracle-sbx");
  assert.equal(entry.database, "(default)");
  assert.equal(entry.requests, 237);
  assert.equal(entry.estimatedUsd, 0.5);
  assert.equal(entry.taskId, "FS-DATA-WRITE-SANDBOX");
  assert.ok(Number.isFinite(Date.parse(entry.ts)));
});

test("ledger keeps bounded HTTP attempts separate from stream frames", () => {
  const entry = sandboxLedgerEntry({
    gitSha: "a".repeat(40),
    corpusDigest: "b".repeat(64),
    requests: 430,
    streamFrames: 2,
    outcome: "recorded",
    runDir: "/private/delta-run",
  });
  assert.equal(entry.requests, 430);
  assert.equal(entry.streamFrames, 2);
  assert.throws(
    () =>
      sandboxLedgerEntry({
        gitSha: "a".repeat(40),
        corpusDigest: "b".repeat(64),
        requests: 432,
        streamFrames: 0,
        outcome: "recorded",
        runDir: "/private/delta-run",
      }),
    /request count/,
  );
});

test("exclusive sandbox lock rejects competitors and remains after failed work", async () => {
  const directory = await mkdtemp(join(tmpdir(), "fireemu-sandbox-lock-"));
  const lock = join(directory, "fs-data-write-exclusive.lock");
  try {
    await assert.rejects(
      withSandboxExclusiveLock(directory, async () => {
        assert.ok((await stat(lock)).isDirectory());
        await assert.rejects(
          withSandboxExclusiveLock(directory, async () => {}),
          /preserve its journal and reservation/,
        );
        throw new Error("recording failed");
      }),
      /recording failed/,
    );
    assert.ok((await stat(lock)).isDirectory());
    await assert.rejects(
      withSandboxExclusiveLock(directory, async () => {}),
      /preserve its journal and reservation/,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("exclusive sandbox lock is released after successful work", async () => {
  const directory = await mkdtemp(join(tmpdir(), "fireemu-sandbox-lock-"));
  try {
    assert.equal(await withSandboxExclusiveLock(directory, async () => "recorded"), "recorded");
    await assert.rejects(stat(join(directory, "fs-data-write-exclusive.lock")), /ENOENT/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("sandbox lock re-reads the task ledger before admitting a recording", async () => {
  const directory = await mkdtemp(join(tmpdir(), "fireemu-sandbox-budget-lock-"));
  const ledger = join(directory, "sandbox-ledger.jsonl");
  const row = (estimatedUsd) =>
    JSON.stringify({ taskId: "FS-DATA-WRITE-SANDBOX", estimatedUsd }) + "\n";
  try {
    const staleRows = [JSON.parse(row(28.5))];
    assert.equal(remainingSandboxBudget(staleRows, 1), 1.5);
    await writeFile(ledger, row(29.6));
    await assert.rejects(
      withSandboxExclusiveLock(directory, async (lockedRows) => {
        assert.equal(lockedRows?.[0]?.estimatedUsd, 29.6);
        remainingSandboxBudget(lockedRows, 0.5);
      }),
      /budget exceeded/,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("legacy recovery environment is fixed to the exact sandbox names and 1000-request cap", () => {
  const env = legacyRecoveryEnvironment({
    token: "private",
    meta: "/private/meta.json",
    journal: "/private/journal.json",
  });
  assert.equal(env.FIRESTORE_PROBE_RECOVERY_MODE, "recover-legacy");
  assert.equal(env.FIRESTORE_PROBE_TARGET, "production");
  assert.equal(env.FIRESTORE_PROBE_SCHEME, "https");
  assert.equal(env.FIRESTORE_PROBE_HOST, "firestore.googleapis.com");
  assert.equal(env.FIRESTORE_PROBE_PROJECT, "fireemu-oracle-sbx");
  assert.equal(env.FIRESTORE_PROBE_MAX_REQUESTS, "1000");
  assert.equal(JSON.parse(env.FIRESTORE_PROBE_MANAGED_CLEAR_NAMES).length, 6);
  assert.equal(env.FIRESTORE_PROBE_TOKEN, "private");
  assert.throws(
    () =>
      legacyRecoveryEnvironment({
        token: "private",
        meta: "/private/meta.json",
        journal: "/private/journal.json",
        names: ["projects/fireemu-oracle-sbx/databases/(default)/documents/other/doc"],
      }),
    /exact private sandbox scope/,
  );
});

test("legacy recovery reserves its same-task budget inside the lock before invoking network work", async () => {
  const directory = await mkdtemp(join(tmpdir(), "fireemu-recovery-reservation-"));
  const ledger = join(directory, "sandbox-ledger.jsonl");
  const reservation = {
    gitSha: "a".repeat(40),
    corpusDigest: "b".repeat(64),
    runDir: "/private/recovery",
  };
  try {
    await writeFile(
      ledger,
      `${JSON.stringify(unknownHold())}\n${JSON.stringify({ taskId: "FS-DATA-WRITE-SANDBOX", estimatedUsd: 19.5 })}\n`,
    );
    const result = await withLegacyRecoveryReservation(directory, reservation, async () => {
      const rows = (await readFile(ledger, "utf8"))
        .trim()
        .split("\n")
        .map((line) => JSON.parse(line));
      assert.equal(rows[2].outcome, "reserved");
      assert.equal(rows[2].estimatedUsd, 0.5);
      assert.equal(rows[2].requests, null);
      return { outcome: "recovered", requestCount: 180 };
    });
    assert.equal(result.outcome, "recovered");
    const rows = (await readFile(ledger, "utf8"))
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line));
    assert.equal(rows.length, 3);
    assert.equal(rows[2].outcome, "reserved");
    assert.equal(rows[2].requests, null);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }

  const blocked = await mkdtemp(join(tmpdir(), "fireemu-recovery-budget-blocked-"));
  try {
    await writeFile(
      join(blocked, "sandbox-ledger.jsonl"),
      `${JSON.stringify(unknownHold())}\n${JSON.stringify({ taskId: "FS-DATA-WRITE-SANDBOX", estimatedUsd: 20.3 })}\n`,
    );
    let sent = false;
    await assert.rejects(
      withLegacyRecoveryReservation(blocked, reservation, async () => {
        sent = true;
      }),
      /budget exceeded/,
    );
    assert.equal(sent, false);
    assert.equal(
      (await readFile(join(blocked, "sandbox-ledger.jsonl"), "utf8")).trim().split("\n").length,
      2,
    );
  } finally {
    await rm(blocked, { recursive: true, force: true });
  }
});

test("failed legacy recovery keeps its single cost reservation and exclusive lock", async () => {
  const directory = await mkdtemp(join(tmpdir(), "fireemu-recovery-failure-reservation-"));
  try {
    await writeFile(join(directory, "sandbox-ledger.jsonl"), `${JSON.stringify(unknownHold())}\n`);
    await assert.rejects(
      withLegacyRecoveryReservation(
        directory,
        {
          gitSha: "a".repeat(40),
          corpusDigest: "b".repeat(64),
          runDir: "/private/recovery",
        },
        async () => {
          throw new Error("synthetic transport failure");
        },
      ),
      /synthetic transport failure/,
    );
    const rows = (await readFile(join(directory, "sandbox-ledger.jsonl"), "utf8"))
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line));
    assert.equal(rows.length, 2);
    assert.equal(rows[1].estimatedUsd, 0.5);
    assert.equal(rows[1].outcome, "reserved");
    assert.ok((await stat(join(directory, "fs-data-write-exclusive.lock"))).isDirectory());
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("legacy recovery selects one incomplete exact-scope journal from its ledger provenance", async () => {
  const privateDir = await mkdtemp(join(tmpdir(), "fireemu-recovery-resume-"));
  const runDir = await mkdtemp(join(privateDir, "fs-data-write-legacy-recovery-"));
  const names = legacyManagedClearNames();
  const corpusDigest = createHash("sha256")
    .update(JSON.stringify({ mode: "recover-legacy", names }))
    .digest("hex");
  try {
    await writeFile(
      join(privateDir, "sandbox-ledger.jsonl"),
      `${[
        {
          taskId: "FS-DATA-WRITE-SANDBOX",
          outcome: "reserved",
          gitSha: "a".repeat(40),
          corpusDigest,
          runDir,
        },
        {
          taskId: "FS-DATA-WRITE-SANDBOX",
          outcome: "reserved",
          gitSha: "b".repeat(40),
          corpusDigest,
          runDir,
        },
      ]
        .map((row) => JSON.stringify(row))
        .join("\n")}\n`,
    );
    await writeFile(
      join(runDir, "journal.json"),
      JSON.stringify({
        schemaVersion: 1,
        mode: "recover-legacy",
        status: "deleting",
        project: "fireemu-oracle-sbx",
        database: "(default)",
        names,
        deletedNames: [names[0]],
        deleteIntent: {
          action: "commit-delete",
          name: names[1],
          priorDeletedNames: [names[0]],
          updateTime: "test-cas-version",
        },
      }),
      { mode: 0o600 },
    );

    await writeFile(join(runDir, "meta.json"), "prior receipt marker");
    const prepared = await prepareLegacyRecoveryRun(privateDir, corpusDigest, names);
    assert.equal(prepared.runDir, runDir);
    assert.equal(prepared.journal, join(runDir, "journal.json"));
    assert.notEqual(prepared.meta, join(runDir, "meta.json"));
    assert.deepEqual(prepared.resume, { runDir, sourceGitSha: "b".repeat(40) });
    assert.equal(await readFile(join(runDir, "meta.json"), "utf8"), "prior receipt marker");
  } finally {
    await rm(privateDir, { recursive: true, force: true });
  }
});

test("legacy recovery rejects a provenance-matched journal for the wrong frozen names", async () => {
  const privateDir = await mkdtemp(join(tmpdir(), "fireemu-recovery-resume-invalid-"));
  const runDir = await mkdtemp(join(privateDir, "fs-data-write-legacy-recovery-"));
  const names = legacyManagedClearNames();
  const corpusDigest = createHash("sha256")
    .update(JSON.stringify({ mode: "recover-legacy", names }))
    .digest("hex");
  try {
    await writeFile(
      join(privateDir, "sandbox-ledger.jsonl"),
      `${JSON.stringify({
        taskId: "FS-DATA-WRITE-SANDBOX",
        outcome: "reserved",
        gitSha: "a".repeat(40),
        corpusDigest,
        runDir,
      })}\n`,
    );
    await writeFile(
      join(runDir, "journal.json"),
      JSON.stringify({
        schemaVersion: 1,
        mode: "recover-legacy",
        status: "deleting",
        project: "fireemu-oracle-sbx",
        database: "(default)",
        names: names.slice(1),
        deletedNames: [],
      }),
      { mode: 0o600 },
    );

    await assert.rejects(
      findLegacyRecoveryResume(privateDir, corpusDigest, names),
      /does not match its frozen private scope/,
    );
  } finally {
    await rm(privateDir, { recursive: true, force: true });
  }
});

test("legacy recovery selects and allocates its run only while holding the exclusive lock", async () => {
  const privateDir = await mkdtemp(join(tmpdir(), "fireemu-recovery-lock-selection-"));
  const lockPath = join(privateDir, "fs-data-write-exclusive.lock");
  const names = legacyManagedClearNames();
  const corpusDigest = createHash("sha256")
    .update(JSON.stringify({ mode: "recover-legacy", names }))
    .digest("hex");
  const reservation = {
    gitSha: "a".repeat(40),
    corpusDigest,
    runDir: join(privateDir, "fs-data-write-legacy-recovery-placeholder"),
  };
  try {
    await writeFile(join(privateDir, "sandbox-ledger.jsonl"), `${JSON.stringify(unknownHold())}\n`);
    await mkdir(lockPath, { mode: 0o700 });
    let selected = false;
    await assert.rejects(
      withLegacyRecoveryReservation(
        privateDir,
        async () => {
          selected = true;
          return reservation;
        },
        async () => undefined,
      ),
    );
    assert.equal(selected, false);
    await rm(lockPath, { recursive: true });

    let prepared;
    await withLegacyRecoveryReservation(
      privateDir,
      async () => {
        assert.ok((await stat(lockPath)).isDirectory());
        prepared = await prepareLegacyRecoveryRun(privateDir, corpusDigest, names);
        return { ...reservation, runDir: prepared.runDir };
      },
      async (selectedReservation) => {
        assert.ok((await stat(lockPath)).isDirectory());
        assert.equal(selectedReservation.runDir, prepared.runDir);
        const rows = (await readFile(join(privateDir, "sandbox-ledger.jsonl"), "utf8"))
          .trim()
          .split("\n")
          .map((line) => JSON.parse(line));
        assert.equal(rows.at(-1).runDir, prepared.runDir);
      },
    );
    await assert.rejects(stat(lockPath), /ENOENT/);
  } finally {
    await rm(privateDir, { recursive: true, force: true });
  }
});

test("legacy recovery ignores completed and mismatched journals before selecting one pending path", async () => {
  const privateDir = await mkdtemp(join(tmpdir(), "fireemu-recovery-resume-"));
  const names = legacyManagedClearNames();
  const corpusDigest = createHash("sha256")
    .update(JSON.stringify({ mode: "recover-legacy", names }))
    .digest("hex");
  const makeRun = async (status) => {
    const runDir = await mkdtemp(join(privateDir, "fs-data-write-legacy-recovery-"));
    await writeFile(
      join(runDir, "journal.json"),
      JSON.stringify({
        schemaVersion: 1,
        mode: "recover-legacy",
        status,
        project: "fireemu-oracle-sbx",
        database: "(default)",
        names,
        deletedNames: [],
      }),
      { mode: 0o600 },
    );
    return runDir;
  };
  try {
    const completeDir = await makeRun("complete");
    const mismatchedDir = await makeRun("deleting");
    const pendingDir = await makeRun("preflight-complete");
    const rows = [
      {
        taskId: "FS-DATA-WRITE-SANDBOX",
        outcome: "reserved",
        gitSha: "a".repeat(40),
        corpusDigest,
        runDir: completeDir,
      },
      {
        taskId: "FS-DATA-WRITE-SANDBOX",
        outcome: "reserved",
        gitSha: "b".repeat(40),
        corpusDigest: "f".repeat(64),
        runDir: mismatchedDir,
      },
      {
        taskId: "FS-DATA-WRITE-SANDBOX",
        outcome: "reserved",
        gitSha: "c".repeat(40),
        corpusDigest,
        runDir: pendingDir,
      },
      {
        taskId: "OTHER",
        outcome: "reserved",
        gitSha: "d".repeat(40),
        corpusDigest,
        runDir: await makeRun("deleting"),
      },
    ];
    await writeFile(
      join(privateDir, "sandbox-ledger.jsonl"),
      `${rows.map((row) => JSON.stringify(row)).join("\n")}\n`,
    );

    assert.deepEqual(await findLegacyRecoveryResume(privateDir, corpusDigest, names), {
      runDir: pendingDir,
      sourceGitSha: "c".repeat(40),
    });

    const ambiguousDir = await makeRun("deleting");
    await writeFile(
      join(privateDir, "sandbox-ledger.jsonl"),
      `${rows.map((row) => JSON.stringify(row)).join("\n")}\n${JSON.stringify({
        taskId: "FS-DATA-WRITE-SANDBOX",
        outcome: "reserved",
        gitSha: "e".repeat(40),
        corpusDigest,
        runDir: ambiguousDir,
      })}\n`,
    );
    await assert.rejects(
      findLegacyRecoveryResume(privateDir, corpusDigest, names),
      /multiple incomplete legacy recovery journals/,
    );
  } finally {
    await rm(privateDir, { recursive: true, force: true });
  }
});

test("local child cannot target a remote host", () => {
  assert.deepEqual(localTarget("127.0.0.1:16000"), { host: "127.0.0.1", port: 16000 });
  assert.throws(() => localTarget("firestore.googleapis.com:443"), /loopback/);
});
