import assert from "node:assert/strict";
import { test } from "node:test";

import {
  localTarget,
  prepareSandboxCorpus,
  productionRestEnvironment,
  remainingSandboxBudget,
  sessionRequestCount,
  sandboxLedgerEntry,
  sandboxLedgerPath,
} from "./fs-data-write-sandbox-run.mjs";

test("the runnable sandbox corpus combines bounded REST and live gRPC recipes", async () => {
  const { corpus, restRequestCount, liveStreamCount } = await prepareSandboxCorpus();
  assert.equal(corpus.restPrograms.length, 46);
  assert.equal(restRequestCount, 187);
  assert.equal(liveStreamCount, 2);
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
