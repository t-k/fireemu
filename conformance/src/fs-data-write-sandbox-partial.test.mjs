import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { promisify } from "node:util";

import { managedShrinkScope } from "./firestore-probe/sandbox-session.mjs";
import {
  partialManagedClearNames,
  partialRequestBound,
  prepareSandboxCorpus,
  productionAdmissionPlan,
  productionRestEnvironment,
  reserveProductionAttempt,
  selectPartialRecipes,
} from "./fs-data-write-sandbox-run.mjs";

const run = promisify(execFile);
const DELTA_IDS = ["rest", "commit", "batch-write"].flatMap((route) =>
  [12112, 12113].map((count) => `writes/limits/near-limit-delete-refusal/${route}/${count}`),
);
const DELTA_STREAM_ID = "writes/write-stream-terminal/response-before-half-close";

async function savedInputs() {
  const { corpus } = await prepareSandboxCorpus();
  const fixture = JSON.parse(
    await readFile(new URL("../fs-data-write-production-matrix.json", import.meta.url), "utf8"),
  );
  const manifest = JSON.parse(
    await readFile(new URL("../fs-data-write-recipe-digests.json", import.meta.url), "utf8"),
  );
  return { corpus, fixture, manifest };
}

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

test("the partial corpus records every unrecorded recipe outside delta-v3, boundary last", async () => {
  const { corpus, fixture, manifest } = await savedInputs();
  const selected = selectPartialRecipes(corpus, fixture, manifest);
  const restIds = selected.recordingCorpus.restPrograms.map((program) => program.id);
  const streamIds = selected.recordingCorpus.streamRecipes.map((recipe) => recipe.id);
  assert.equal(restIds.at(-1), "writes/limits/index-entry-sum/adjacent");
  assert.ok(restIds.every((id) => !DELTA_IDS.includes(id)));
  assert.ok(!streamIds.includes(DELTA_STREAM_ID));
  assert.deepEqual(streamIds.toSorted(), [
    "writes/limits/grpc-stream-request-bytes/10485760",
    "writes/limits/grpc-stream-request-bytes/10485761",
    "writes/limits/grpc-unary-request-bytes/10485760",
    "writes/limits/grpc-unary-request-bytes/10485761",
  ]);
  for (const id of [
    "writes/batch-write-malformed/two-fields-bad-integer",
    "writes/map-key-validation/type-tag/query",
    "writes/limits/webchannel-request-bytes/10485761",
    "writes/limits/non-commit-rest-request-bytes/run-query/10485761",
  ]) {
    assert.ok(restIds.includes(id), id);
  }
  // Every current recipe is either saved and unchanged, in delta-v3, or recorded here.
  const currentIds = corpus.restPrograms.map((program) => program.id);
  assert.deepEqual(
    new Set([...selected.retainedRestIds, ...DELTA_IDS, ...restIds]),
    new Set(currentIds),
  );
  assert.equal(new Set(restIds).size, restIds.length);
  assert.ok(selected.retainedRestIds.every((id) => !restIds.includes(id)));
  // Saved rows whose recipe left the corpus are reported, never recorded.
  assert.ok(selected.retiredRestIds.every((id) => !currentIds.includes(id)));
  assert.equal(
    selected.recordingCorpus.restRequestCount,
    selected.recordingCorpus.restPrograms.reduce(
      (total, program) => total + program.steps.length,
      0,
    ),
  );
});

test("the partial corpus clears only the six adjacent boundary documents within fixed caps", async () => {
  const { corpus, fixture, manifest } = await savedInputs();
  const { recordingCorpus } = selectPartialRecipes(corpus, fixture, manifest);
  const names = partialManagedClearNames(recordingCorpus);
  assert.equal(names.length, 6);
  assert.equal(managedShrinkScope(names, "fireemu-oracle-sbx", "(default)"), "v3");
  const bound = partialRequestBound(recordingCorpus);
  assert.ok(bound.managedRequestBound <= 400);
  assert.equal(bound.maxHttpRequests, bound.totalRequestBound + 400);
  assert.ok(bound.maxHttpRequests <= 1000);
  assert.equal(bound.maxStreamFrames, 4);
  assert.throws(
    () =>
      partialManagedClearNames({
        ...recordingCorpus,
        restPrograms: recordingCorpus.restPrograms.slice(0, -1),
      }),
    /boundary program must be last/,
  );
  assert.throws(
    () =>
      partialManagedClearNames({
        ...recordingCorpus,
        restPrograms: [
          corpus.restPrograms.find((program) => program.id === DELTA_IDS[0]),
          ...recordingCorpus.restPrograms,
        ],
      }),
    /delete/,
  );
});

test("the partial production environment carries its scope, cap and admission to the child", async () => {
  const { corpus, fixture, manifest } = await savedInputs();
  const { recordingCorpus } = selectPartialRecipes(corpus, fixture, manifest);
  const bound = partialRequestBound(recordingCorpus);
  const admission = {
    mode: "partial",
    nonce: "0123456789abcdef",
    reviewSha256: "d".repeat(64),
    planSha256: "e".repeat(64),
    sourceCommit: "c".repeat(40),
    reviewPath: "/private/review.md",
  };
  const env = productionRestEnvironment({
    input: "/private/partial-corpus.json",
    output: "/private/rest.json",
    meta: "/private/meta.json",
    token: "not-used",
    managedNames: partialManagedClearNames(recordingCorpus),
    journal: "/private/managed-clear.json",
    runId: "a".repeat(32),
    corpusDigest: "b".repeat(64),
    sourceGitSha: "c".repeat(40),
    partial: { maxHttpRequests: bound.maxHttpRequests },
    admission,
  });
  assert.equal(env.FIRESTORE_PROBE_PARTIAL, "1");
  assert.equal(env.FIRESTORE_PROBE_PARTIAL_LOCK_HELD, "1");
  assert.equal(env.FIRESTORE_PROBE_MAX_REQUESTS, String(bound.maxHttpRequests));
  assert.equal(env.FIRESTORE_PROBE_MANAGED_CLEAR_JOURNAL, "/private/managed-clear.json");
  assert.equal(env.FIRESTORE_PROBE_DELTA_V3, undefined);
  assert.deepEqual(JSON.parse(env.FIRESTORE_PROBE_ADMISSION), admission);
  assert.throws(
    () =>
      productionRestEnvironment({
        input: "/private/partial-corpus.json",
        output: "/private/rest.json",
        meta: "/private/meta.json",
        token: "not-used",
        managedNames: partialManagedClearNames(recordingCorpus),
        journal: "/private/managed-clear.json",
        runId: "a".repeat(32),
        corpusDigest: "b".repeat(64),
        sourceGitSha: "c".repeat(40),
        partial: { maxHttpRequests: 1001 },
        admission,
      }),
    /partial HTTP cap/,
  );
});

test("an attempt reservation names its admission packet and the run ID the child checks", async () => {
  const directory = await mkdtemp(join(tmpdir(), "fireemu-partial-reservation-"));
  try {
    const rows = [unknownHold()];
    const reservation = await reserveProductionAttempt({
      ledgerPath: join(directory, "sandbox-ledger.jsonl"),
      rows,
      gitSha: "a".repeat(40),
      corpusDigest: "b".repeat(64),
      runDir: join(directory, "attempt"),
      packetId: "fs-data-write-partial-0123456789abcdef",
      runId: "c".repeat(32),
    });
    assert.equal(reservation.packetId, "fs-data-write-partial-0123456789abcdef");
    assert.equal(reservation.runId, "c".repeat(32));
    assert.equal(reservation.outcome, "reserved");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("the admission plan pins mode, source corpus, recipes, names and bounds", async () => {
  const { corpus, fixture, manifest } = await savedInputs();
  const selected = selectPartialRecipes(corpus, fixture, manifest);
  const plan = productionAdmissionPlan("partial", selected);
  assert.equal(plan.mode, "partial");
  assert.equal(plan.sourceCorpusSha256, selected.sourceCorpusDigest);
  assert.deepEqual(
    plan.restIds,
    selected.recordingCorpus.restPrograms.map((program) => program.id),
  );
  assert.equal(plan.managedNames.length, 6);
  assert.equal(
    plan.bounds.maxHttpRequests,
    partialRequestBound(selected.recordingCorpus).maxHttpRequests,
  );
  assert.match(plan.recordingCorpusSha256, /^[0-9a-f]{64}$/);
});

test("the recording commands refuse to start without an admission before any preparation", async () => {
  const runner = new URL("./fs-data-write-sandbox-run.mjs", import.meta.url).pathname;
  for (const command of ["record-partial", "record-delta-v3"]) {
    await assert.rejects(
      run("node", [runner, command], { cwd: new URL("..", import.meta.url).pathname }),
      (error) => /--nonce, --review and --review-sha256/.test(error.stderr),
      command,
    );
  }
});
