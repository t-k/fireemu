import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";

import {
  MAX_STREAM_FRAMES,
  assertMatchingSandboxCorpus,
  comparisonExitCode,
  localTarget,
  prepareSandboxCorpus,
  productionRestEnvironment,
  remainingSandboxBudget,
  selectComparableSandboxRecipes,
  sessionRequestCount,
  sandboxLedgerEntry,
  sandboxLedgerPath,
} from "./fs-data-write-sandbox-run.mjs";

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

test("the runnable sandbox corpus combines bounded REST and live gRPC recipes", async () => {
  const { corpus, restRequestCount, liveStreamCount } = await prepareSandboxCorpus();
  assert.equal(corpus.restPrograms.length, 73);
  assert.equal(restRequestCount, 237);
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

test("production REST session fixes project, endpoint and all-attempt cap", () => {
  const env = productionRestEnvironment({
    input: "/tmp/input",
    output: "/tmp/output",
    meta: "/tmp/meta",
    token: "private",
  });
  assert.equal(env.FIRESTORE_PROBE_PROJECT, "fireemu-oracle-sbx");
  assert.equal(env.FIRESTORE_PROBE_HOST, "firestore.googleapis.com");
  assert.equal(env.FIRESTORE_PROBE_MAX_REQUESTS, "1000");
  assert.equal(env.FIRESTORE_PROBE_RECORD_PROJECT, "demo-firestore-probe");
  assert.equal(env.FIRESTORE_PROBE_TOKEN, "private");
  assert.equal(env.FIRESTORE_PROBE_TIMEOUT_MS, "180000");
});

test("a failed session still reports its bounded network attempts from metadata", () => {
  assert.equal(sessionRequestCount({ requestCount: 400 }), 400);
  assert.throws(() => sessionRequestCount({ requestCount: 1001 }), /bounded/);
});

test("the stable FS observation task carries retries into its ten-dollar budget", () => {
  assert.equal(
    remainingSandboxBudget([{ taskId: "FS-DATA-WRITE-SANDBOX", estimatedUsd: 0.5 }]),
    9.5,
  );
  assert.throws(
    () => remainingSandboxBudget([{ taskId: "FS-DATA-WRITE-SANDBOX", estimatedUsd: 9.75 }], 0.5),
    /budget/,
  );
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

test("local child cannot target a remote host", () => {
  assert.deepEqual(localTarget("127.0.0.1:16000"), { host: "127.0.0.1", port: 16000 });
  assert.throws(() => localTarget("firestore.googleapis.com:443"), /loopback/);
});
