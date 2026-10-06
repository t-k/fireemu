import assert from "node:assert/strict";
import test from "node:test";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { EventEmitter } from "node:events";
import { parseArgs } from "./pubsub-production/record.mjs";
import { selectCases } from "./pubsub-production/runner.mjs";
import { StopClean } from "./pubsub-production/cases/support.mjs";

const args = [
  "--target",
  "production",
  "--project",
  "demo-v2",
  "--out",
  "unused",
  "--suite",
  "stream-dlq-v2",
  "--run-id",
  "0123456789ab",
];
const principal = "serviceAccount:service-123456789012@gcp-sa-pubsub.iam.gserviceaccount.com";

test("v2 starts with its own deleted cursor before any stream topics exist", () => {
  const cases = selectCases(undefined, "stream-dlq-v2");
  assert.equal(cases[0].id, "deleted-cursor");
  assert.equal(new Set(cases.map((item) => item.id)).size, 8);
});

test("service-agent project number comes from environment and is refused on argv", () => {
  assert.throws(
    () => parseArgs([...args, "--service-agent-project-number", "123456789012"]),
    /environment|argv|unknown option/,
  );
  assert.equal(
    parseArgs(args, { PUBSUB_SERVICE_AGENT_PROJECT_NUMBER: "123456789012" }).serviceAgent,
    principal,
  );
  for (const number of ["", "12a", "1".repeat(21)]) {
    assert.throws(() => parseArgs(args, { PUBSUB_SERVICE_AGENT_PROJECT_NUMBER: number }), /digits/);
  }
});

test("A2 can take over a same-source dead original lock but refuses any live foreign pid", async () => {
  const { verifyLiveLock } = await import("./pubsub-production/admission.mjs");
  const out = mkdtempSync(join(tmpdir(), "v2-a2-lock-"));
  const path = join(out, "demo-v2.lock");
  const binding = { envelopeId: "PUBSUB-STREAM-DLQ-V2", sourceCommit: "a".repeat(40) };
  const lock = { pid: process.pid + 1, ...binding, acquiredAt: "1970-01-01T00:00:00Z" };
  writeFileSync(path, JSON.stringify(lock), { flag: "wx" });
  try {
    assert.doesNotThrow(() =>
      verifyLiveLock(
        { path, expectedPath: path, cleanupOnly: true, pidAlive: () => false },
        binding,
      ),
    );
    assert.throws(
      () =>
        verifyLiveLock(
          { path, expectedPath: path, cleanupOnly: true, pidAlive: () => true },
          binding,
        ),
      /lock/,
    );
    assert.throws(
      () => verifyLiveLock({ path, expectedPath: path, pidAlive: () => false }, binding),
      /lock/,
    );
    for (const changes of [
      { envelopeId: "OTHER" },
      { sourceCommit: "b".repeat(40) },
      { pid: 0 },
      { pid: 1.2 },
    ]) {
      writeFileSync(path, JSON.stringify({ ...lock, ...changes }));
      assert.throws(
        () =>
          verifyLiveLock(
            { path, expectedPath: path, cleanupOnly: true, pidAlive: () => false },
            binding,
          ),
        /lock/,
      );
    }
  } finally {
    rmSync(out, { recursive: true });
  }
});

test("E/V exports bind a canonical ledger line hash and the complete approved scope", async () => {
  const { verifyLedgerProof, proofScopeDigest, sha256 } =
    await import("./pubsub-production/admission.mjs");
  assert.equal(typeof verifyLedgerProof, "function");
  assert.equal(typeof proofScopeDigest, "function");
  const out = mkdtempSync(join(tmpdir(), "v2-proof-ledger-"));
  const path = join(out, "test-ledger.md");
  try {
    for (const kind of ["E", "V"]) {
      const row = {
        kind,
        state: "APPROVED",
        taskId: "PUBSUB-STREAM-DLQ",
        envelopeId: "PUBSUB-STREAM-DLQ-V2",
        sourceHead: "a".repeat(40),
        descriptorSha256: "b".repeat(64),
        packetSha256: "c".repeat(64),
        project: "demo-v2",
        runIds: ["0123456789ab", "0123456789ac"],
        runOutputs: { "0123456789ab": "/example/one", "0123456789ac": "/example/two" },
        expiresAt: "2099-01-01T00:00:00Z",
        maxRequestsPerAttempt: 228,
        cleanupRequests: 600,
        a2Requests: 600,
        bInheritedGrants: "UNAUDITED",
      };
      const line = `- 2026-10-06 | PUBSUB-STREAM-DLQ ${kind} | decision=APPROVE; envelopeId=${row.envelopeId}; scopeSha256=${proofScopeDigest(row)} | Coordinator | test`;
      writeFileSync(path, `# Test-only ledger\n${line}\n`);
      row.ledgerLine = 2;
      row.ledgerLineSha256 = sha256(line);
      assert.doesNotThrow(() => verifyLedgerProof(row, path));
      for (const changes of [
        { ledgerLine: 1 },
        { ledgerLine: 3 },
        { ledgerLine: 1.2 },
        { ledgerLine: 0 },
        { ledgerLineSha256: "d".repeat(64) },
        { sourceHead: "d".repeat(40) },
        { packetSha256: "d".repeat(64) },
        { maxRequestsPerAttempt: 229 },
        { bInheritedGrants: "AUDITED" },
      ]) {
        assert.throws(() => verifyLedgerProof({ ...row, ...changes }, path), /ledger/);
      }
      for (const changed of [
        line.replace("APPROVE", "REJECT"),
        line.replace(` ${kind} |`, " X |"),
        line.replace(row.envelopeId, "OTHER"),
        line.replace(proofScopeDigest(row), "d".repeat(64)),
      ]) {
        writeFileSync(path, `# Test-only ledger\n${changed}\n`);
        assert.throws(
          () => verifyLedgerProof({ ...row, ledgerLineSha256: sha256(changed) }, path),
          /ledger/,
        );
      }
    }
  } finally {
    rmSync(out, { recursive: true });
  }
});

test("signal interrupts a900second sleep promptly and removes handlers", async (t) => {
  const { createSignalSleep } = await import("./pubsub-production/record.mjs");
  assert.equal(typeof createSignalSleep, "function");
  for (const signal of ["SIGINT", "SIGTERM"]) {
    const signals = new EventEmitter();
    const stopped = createSignalSleep({ signals });
    t.after(() => stopped.close());
    const wait = stopped.sleep(900_000);
    signals.emit(signal);
    const { setTimeout } = await import("node:timers/promises");
    const result = await Promise.race([
      wait.then(
        () => null,
        (error) => error,
      ),
      setTimeout(100).then(() => "not-interrupted"),
    ]);
    assert.ok(result instanceof StopClean, "signal must interrupt without waiting900seconds");
    assert.equal(stopped.isStopping(), true);
    await assert.rejects(stopped.sleep(1), StopClean);
    stopped.close();
    assert.equal(signals.listenerCount("SIGINT"), 0);
    assert.equal(signals.listenerCount("SIGTERM"), 0);
  }
});

test("closing signal sleep aborts pending waits and releases their timer", async () => {
  const { createSignalSleep } = await import("./pubsub-production/record.mjs");
  const signals = new EventEmitter();
  let signal;
  const stopped = createSignalSleep({
    signals,
    wait: (_, received) => {
      signal = received;
      return Promise.resolve();
    },
  });
  const promise = stopped.sleep(900_000).catch((error) => error);
  stopped.close();
  assert.equal(signal.aborted, true);
  assert.ok((await promise) instanceof StopClean);
});
