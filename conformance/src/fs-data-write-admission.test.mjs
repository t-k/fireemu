import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";

import {
  admissionPacketId,
  admissionPacketRow,
  admissionPlanDigest,
  parseAdmissionEnvironment,
  requireChildProductionAdmission,
  verifyProductionAdmission,
} from "./fs-data-write-admission.mjs";

const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const sourceCommit = "a".repeat(40);
const planSha256 = "b".repeat(64);
const nonce = "0123456789abcdef";
const reviewText = [
  "# Pre-send review",
  `mode: partial`,
  `nonce: ${nonce}`,
  `sourceCommit: ${sourceCommit}`,
  `planSha256: ${planSha256}`,
  "verdict: APPROVE",
  "",
].join("\n");
const reviewBytes = Buffer.from(reviewText);
const admission = {
  mode: "partial",
  nonce,
  reviewSha256: sha256(reviewBytes),
  planSha256,
  sourceCommit,
};
const packetRow = () => admissionPacketRow({ ...admission, ts: "2026-09-25T00:00:00.000Z" });
const attemptRow = (runId) => ({
  taskId: "FS-DATA-WRITE-SANDBOX",
  outcome: "reserved",
  packetId: admissionPacketId("partial", nonce),
  runId,
  estimatedUsd: 0.5,
});
const accepted = (overrides = {}) => ({
  admission,
  reviewBytes,
  gitHead: sourceCommit,
  gitStatus: "",
  rows: [packetRow()],
  ...overrides,
});

test("admission accepts the reviewed plan, commit, nonce and single ledger packet", () => {
  const result = verifyProductionAdmission(accepted());
  assert.equal(result.packetId, "fs-data-write-partial-0123456789abcdef");
  assert.equal(result.packet.reviewSha256, admission.reviewSha256);
  assert.equal(packetRow().estimatedUsd, 0);
  assert.equal(packetRow().outcome, "reserved-presend-admission");
});

test("admission refuses review bytes that differ from the pinned SHA-256", () => {
  assert.throws(
    () => verifyProductionAdmission(accepted({ reviewBytes: Buffer.from(`${reviewText} `) })),
    /review SHA-256/,
  );
});

test("admission refuses a review that does not pin every plan input or approve", () => {
  for (const line of [
    "mode: partial",
    `nonce: ${nonce}`,
    `sourceCommit: ${sourceCommit}`,
    `planSha256: ${planSha256}`,
    "verdict: APPROVE",
  ]) {
    const bytes = Buffer.from(reviewText.replace(`${line}\n`, ""));
    assert.throws(
      () =>
        verifyProductionAdmission(
          accepted({
            reviewBytes: bytes,
            admission: { ...admission, reviewSha256: sha256(bytes) },
            rows: [
              admissionPacketRow({
                ...admission,
                reviewSha256: sha256(bytes),
                ts: "2026-09-25T00:00:00.000Z",
              }),
            ],
          }),
        ),
      /review does not/,
      line,
    );
  }
});

test("admission refuses a drifted or dirty source checkout", () => {
  assert.throws(() => verifyProductionAdmission(accepted({ gitHead: "c".repeat(40) })), /commit/);
  assert.throws(
    () => verifyProductionAdmission(accepted({ gitStatus: " M conformance/src/x.mjs" })),
    /dirty/,
  );
});

test("admission requires exactly one matching ledger packet reservation", () => {
  assert.throws(() => verifyProductionAdmission(accepted({ rows: [] })), /one ledger packet/);
  assert.throws(
    () => verifyProductionAdmission(accepted({ rows: [packetRow(), packetRow()] })),
    /one ledger packet/,
  );
  for (const field of ["sourceCommit", "planSha256", "reviewSha256"]) {
    const row = { ...packetRow(), [field]: "f".repeat(field === "sourceCommit" ? 40 : 64) };
    assert.throws(() => verifyProductionAdmission(accepted({ rows: [row] })), /packet/, field);
  }
});

test("admission rejects malformed modes, nonces and digests before reading anything else", () => {
  for (const bad of [
    { mode: "full" },
    { nonce: "short" },
    { nonce: "Z".repeat(16) },
    { planSha256: "x" },
    { sourceCommit: "a".repeat(39) },
  ]) {
    assert.throws(
      () => verifyProductionAdmission(accepted({ admission: { ...admission, ...bad } })),
      /admission/,
      JSON.stringify(bad),
    );
  }
});

test("a child launch also needs its own attempt reservation carrying its run ID", () => {
  const runId = "c".repeat(32);
  assert.throws(() => verifyProductionAdmission(accepted({ runId })), /attempt reservation/);
  assert.throws(
    () =>
      verifyProductionAdmission(
        accepted({ runId, rows: [packetRow(), attemptRow("d".repeat(32))] }),
      ),
    /attempt reservation/,
  );
  const result = verifyProductionAdmission(
    accepted({ runId, rows: [packetRow(), attemptRow(runId)] }),
  );
  assert.equal(result.attempt.runId, runId);
});

test("the plan digest is stable over key order and changes with any value", () => {
  const plan = { mode: "partial", bounds: { maxHttpRequests: 302 }, recipeIds: ["a", "b"] };
  assert.equal(
    admissionPlanDigest(plan),
    admissionPlanDigest({
      recipeIds: ["a", "b"],
      bounds: { maxHttpRequests: 302 },
      mode: "partial",
    }),
  );
  assert.notEqual(
    admissionPlanDigest(plan),
    admissionPlanDigest({ ...plan, bounds: { maxHttpRequests: 303 } }),
  );
});

test("the child reads admission only from one JSON environment value", () => {
  assert.equal(parseAdmissionEnvironment({}), null);
  const parsed = parseAdmissionEnvironment({
    FIRESTORE_PROBE_ADMISSION: JSON.stringify({ ...admission, reviewPath: "/r.md" }),
  });
  assert.equal(parsed.reviewPath, "/r.md");
  assert.throws(
    () => parseAdmissionEnvironment({ FIRESTORE_PROBE_ADMISSION: "{" }),
    /admission environment/,
  );
});

test("a directly launched production child without the runner's admission never sends", () => {
  const calls = [];
  const verify = (input) => {
    calls.push(input);
    return { ok: true };
  };
  assert.equal(requireChildProductionAdmission({ production: false, env: {}, verify }), null);
  assert.throws(
    () =>
      requireChildProductionAdmission({ production: true, env: {}, runId: "c".repeat(32), verify }),
    /runner's admission/,
  );
  assert.equal(calls.length, 0);
  const env = { FIRESTORE_PROBE_ADMISSION: JSON.stringify({ ...admission, reviewPath: "/r.md" }) };
  assert.deepEqual(
    requireChildProductionAdmission({ production: true, env, runId: "c".repeat(32), verify }),
    { ok: true },
  );
  assert.equal(calls[0].runId, "c".repeat(32));
  assert.equal(calls[0].admission.reviewPath, "/r.md");
  assert.throws(
    () => requireChildProductionAdmission({ production: true, env, runId: undefined, verify }),
    /run ID/,
  );
});

test("hand-launched REST and stream children with production variables stop at admission", async () => {
  const { execFile } = await import("node:child_process");
  const { promisify } = await import("node:util");
  const { mkdtemp, rm, writeFile } = await import("node:fs/promises");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const run = promisify(execFile);
  const directory = await mkdtemp(join(tmpdir(), "fireemu-admission-child-"));
  try {
    const corpus = join(directory, "corpus.json");
    await writeFile(corpus, "{}");
    const clean = { ...process.env };
    delete clean.FIRESTORE_PROBE_ADMISSION;
    await assert.rejects(
      run("node", [new URL("./firestore-probe/sandbox-session.mjs", import.meta.url).pathname], {
        env: {
          ...clean,
          FIRESTORE_PROBE_TARGET: "production",
          FIRESTORE_PROBE_SCHEME: "https",
          // TEST-NET-1: unroutable, so a missing gate would time out instead of reaching a service.
          FIRESTORE_PROBE_HOST: "192.0.2.1:443",
          FIRESTORE_PROBE_PROJECT: "fireemu-oracle-sbx",
          FIRESTORE_PROBE_IN: corpus,
          FIRESTORE_PROBE_OUT: join(directory, "out.json"),
          FIRESTORE_PROBE_TOKEN: "test-only",
          FIRESTORE_PROBE_TIMEOUT_MS: "500",
          FIRESTORE_PROBE_DELETE_RUN_ID: "c".repeat(32),
        },
      }),
      (error) => /runner's admission/.test(error.stderr),
    );
    // Leaving out the production target must not skip the gate for a remote host.
    await assert.rejects(
      run("node", [new URL("./firestore-probe/sandbox-session.mjs", import.meta.url).pathname], {
        env: {
          ...clean,
          FIRESTORE_PROBE_TARGET: "",
          FIRESTORE_PROBE_SCHEME: "https",
          FIRESTORE_PROBE_HOST: "192.0.2.1:443",
          FIRESTORE_PROBE_PROJECT: "fireemu-oracle-sbx",
          FIRESTORE_PROBE_IN: corpus,
          FIRESTORE_PROBE_OUT: join(directory, "out-untargeted.json"),
          FIRESTORE_PROBE_TOKEN: "test-only",
          FIRESTORE_PROBE_TIMEOUT_MS: "500",
          FIRESTORE_PROBE_DELETE_RUN_ID: "c".repeat(32),
        },
      }),
      (error) => /runner's admission/.test(error.stderr),
    );
    await assert.rejects(
      run("node", [new URL("./firestore-probe/stream-session.mjs", import.meta.url).pathname], {
        env: {
          ...clean,
          FIRESTORE_STREAM_CORPUS: corpus,
          FIRESTORE_STREAM_OUT: join(directory, "stream.json"),
          FIRESTORE_STREAM_TARGET: "production",
          FIRESTORE_STREAM_TOKEN: "test-only",
          FIRESTORE_STREAM_RUN_ID: "c".repeat(32),
        },
      }),
      (error) => /runner's admission/.test(error.stderr),
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("recovery children skip the generic cleanup gate and stop at their own journal checks", async () => {
  const { execFile } = await import("node:child_process");
  const { promisify } = await import("node:util");
  const { mkdtemp, rm } = await import("node:fs/promises");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const run = promisify(execFile);
  const directory = await mkdtemp(join(tmpdir(), "fireemu-recovery-gate-"));
  try {
    for (const mode of ["recover-v3", "recover-legacy"]) {
      await assert.rejects(
        run("node", [new URL("./firestore-probe/sandbox-session.mjs", import.meta.url).pathname], {
          env: {
            ...process.env,
            FIRESTORE_PROBE_TARGET: "production",
            FIRESTORE_PROBE_RECOVERY_MODE: mode,
            FIRESTORE_PROBE_SCHEME: "https",
            // TEST-NET-1: a missing journal must stop the child before any request.
            FIRESTORE_PROBE_HOST: "192.0.2.1:443",
            FIRESTORE_PROBE_PROJECT: "fireemu-oracle-sbx",
            FIRESTORE_PROBE_TOKEN: "test-only",
            FIRESTORE_PROBE_TIMEOUT_MS: "500",
            FIRESTORE_PROBE_MAX_REQUESTS: "1000",
            FIRESTORE_PROBE_META_OUT: join(directory, `${mode}.meta.json`),
            FIRESTORE_PROBE_MANAGED_CLEAR_JOURNAL: join(directory, `${mode}-missing.json`),
            FIRESTORE_PROBE_MANAGED_CLEAR_NAMES: "[]",
          },
        }),
        (error) =>
          !/v3 production cleanup is blocked/.test(error.stderr) &&
          /journal|recovery/i.test(error.stderr),
        mode,
      );
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
