import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { promisify } from "node:util";

import {
  managedShrinkScope,
  productionScopeFromEnvironment,
} from "./firestore-probe/sandbox-session.mjs";
import {
  deltaV3ManagedClearNames,
  deltaV3RecordingCorpus,
  partialManagedClearNames,
  partialRequestBound,
  prepareSandboxCorpus,
  productionAdmissionPlan,
  productionRestEnvironment,
  reserveProductionAttempt,
  selectDeltaV3Recipes,
  selectPartialRecipes,
  selectSupplementComparisons,
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

test("delta-v3 and partial selections both accept the real saved fixture and split the pending set", async () => {
  const { corpus, fixture, manifest } = await savedInputs();
  const delta = selectDeltaV3Recipes(corpus, fixture, manifest);
  const partial = selectPartialRecipes(corpus, fixture, manifest);
  const deltaRest = delta.recordingCorpus.restPrograms.map((program) => program.id);
  const partialRest = partial.recordingCorpus.restPrograms.map((program) => program.id);
  assert.deepEqual(deltaRest.toSorted(), DELTA_IDS.toSorted());
  assert.ok(partialRest.every((id) => !deltaRest.includes(id)));
  assert.deepEqual(
    new Set(delta.pendingRestIds.filter((id) => corpus.restPrograms.some((p) => p.id === id))),
    new Set(partialRest),
  );
});

test("supplement fixtures cover only pending recipes whose recipe digest is unchanged", () => {
  const digest = (value) => createHash("sha256").update(JSON.stringify(value)).digest("hex");
  const a = { id: "writes/a", steps: [{ id: "s", method: "GET", path: "/v1/a" }] };
  const b = { id: "writes/b", steps: [{ id: "s", method: "GET", path: "/v1/b" }] };
  const grpc = { id: "writes/g", transport: "grpc", action: "x", maxFrames: 1 };
  const corpus = {
    schemaVersion: 1,
    restPrograms: [a, b],
    streamRecipes: [grpc],
    restRequestCount: 2,
  };
  const supplement = (programs, streams = {}) => ({
    name: "partial-0123456789abcdef.json",
    fixture: {
      schemaVersion: 1,
      evidence: { corpusSha256: "e".repeat(64) },
      programs: Object.fromEntries(programs.map((program) => [program.id, { steps: { s: {} } }])),
      streams: Object.fromEntries(Object.keys(streams).map((id) => [id, {}])),
      recipeDigests: {
        programs: Object.fromEntries(programs.map((program) => [program.id, digest(program)])),
        streams,
      },
    },
  });
  const selected = selectSupplementComparisons(
    [supplement([b], { [grpc.id]: digest(grpc) })],
    corpus,
    [b.id],
    [grpc.id],
  );
  assert.equal(selected.comparisons.length, 1);
  assert.deepEqual(selected.comparisons[0].matchedRestIds, [b.id]);
  assert.deepEqual(selected.comparisons[0].matchedStreamIds, [grpc.id]);
  assert.deepEqual(Object.keys(selected.comparisons[0].fixture.programs), [b.id]);
  assert.deepEqual(selected.comparisons[0].corpus.restPrograms, [b]);
  assert.deepEqual(selected.pendingRestIds, []);
  assert.deepEqual(selected.pendingStreamIds, []);

  // A changed recipe stays pending; a recipe the base fixture already covers is not re-compared.
  const changed = supplement([{ ...b, steps: [] }]);
  changed.fixture.programs = { [b.id]: { steps: {} } };
  const stale = selectSupplementComparisons([changed], corpus, [b.id], []);
  assert.deepEqual(stale.pendingRestIds, [b.id]);
  assert.deepEqual(stale.comparisons, []);
  const covered = selectSupplementComparisons([supplement([a])], corpus, [b.id], []);
  assert.deepEqual(covered.comparisons, []);
  assert.deepEqual(covered.pendingRestIds, [b.id]);

  assert.throws(
    () =>
      selectSupplementComparisons(
        [supplement([b]), { ...supplement([b]), name: "delta-v3-x.json" }],
        corpus,
        [b.id],
        [],
      ),
    /more than one supplement/,
  );
  const unbound = supplement([b]);
  unbound.fixture.recipeDigests.programs = {};
  assert.throws(() => selectSupplementComparisons([unbound], corpus, [b.id], []), /recipe digests/);
});

test("the child admits the exact production scope the parent actually sends for each mode", async () => {
  const { corpus, fixture, manifest } = await savedInputs();
  const common = {
    input: "/private/corpus.json",
    output: "/private/rest.json",
    meta: "/private/meta.json",
    token: "not-used",
    journal: "/private/journal.json",
    runId: "a".repeat(32),
    corpusDigest: "b".repeat(64),
    sourceGitSha: "c".repeat(40),
  };
  const delta = deltaV3RecordingCorpus(selectDeltaV3Recipes(corpus, fixture, manifest));
  const deltaEnv = productionRestEnvironment({
    ...common,
    managedNames: deltaV3ManagedClearNames(delta),
    deltaV3: true,
  });
  assert.deepEqual(productionScopeFromEnvironment(deltaEnv), { delta: true, partial: false });
  const { recordingCorpus } = selectPartialRecipes(corpus, fixture, manifest);
  const partialEnv = productionRestEnvironment({
    ...common,
    managedNames: partialManagedClearNames(recordingCorpus),
    partial: { maxHttpRequests: partialRequestBound(recordingCorpus).maxHttpRequests },
  });
  assert.deepEqual(productionScopeFromEnvironment(partialEnv), { delta: false, partial: true });
  // Without the run ID the marker names cannot match a run-specific scope.
  assert.deepEqual(
    productionScopeFromEnvironment({ ...deltaEnv, FIRESTORE_PROBE_DELETE_RUN_ID: undefined }),
    { delta: false, partial: false },
  );
  assert.deepEqual(
    productionScopeFromEnvironment({ ...deltaEnv, FIRESTORE_PROBE_HOST: "attacker.example" }),
    { delta: false, partial: false },
  );
});
