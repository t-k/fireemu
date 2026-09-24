// Pre-send admission for FS-DATA-WRITE sandbox recordings.
//
// The same check runs in the parent runner before it acquires a credential and in
// each child session before its first production request. It pins the reviewed
// source commit, the review document bytes, the nonce and the deterministic plan,
// and requires the operator's ledger packet reservation. This is a procedural
// boundary against accidental launches; it does not defend against a deliberate
// forgery by the same OS user.
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { lstatSync, readFileSync } from "node:fs";
import { dirname, isAbsolute, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const TASK_ID = "FS-DATA-WRITE-SANDBOX";
const MODES = ["delta-v3", "partial"];
const PACKET_OUTCOME = "reserved-presend-admission";
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");

const sha256 = (value) => createHash("sha256").update(value).digest("hex");

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .toSorted()
        .map((key) => [key, canonical(value[key])]),
    );
  }
  return value;
}

export function admissionPlanDigest(plan) {
  return sha256(JSON.stringify(canonical(plan)));
}

export function admissionPacketId(mode, nonce) {
  return `fs-data-write-${mode}-${nonce}`;
}

function validateAdmission(admission) {
  if (
    !admission ||
    !MODES.includes(admission.mode) ||
    !/^[0-9a-f]{16,32}$/.test(admission.nonce ?? "") ||
    !/^[0-9a-f]{64}$/.test(admission.reviewSha256 ?? "") ||
    !/^[0-9a-f]{64}$/.test(admission.planSha256 ?? "") ||
    !/^[0-9a-f]{40}$/.test(admission.sourceCommit ?? "")
  ) {
    throw new Error("production admission requires mode, nonce, review, plan and commit pins");
  }
}

export function admissionPacketRow({ mode, nonce, sourceCommit, planSha256, reviewSha256, ts }) {
  validateAdmission({ mode, nonce, sourceCommit, planSha256, reviewSha256 });
  return {
    ts: ts ?? new Date().toISOString(),
    project: "fireemu-oracle-sbx",
    database: "(default)",
    taskId: TASK_ID,
    packetId: admissionPacketId(mode, nonce),
    mode,
    nonce,
    sourceCommit,
    planSha256,
    reviewSha256,
    requests: null,
    // Cost is reserved per attempt by the runner; the packet row carries none.
    estimatedUsd: 0,
    outcome: PACKET_OUTCOME,
  };
}

export function verifyProductionAdmission({
  admission,
  reviewBytes,
  gitHead,
  gitStatus,
  rows,
  runId,
}) {
  validateAdmission(admission);
  const { mode, nonce, reviewSha256, planSha256, sourceCommit } = admission;
  if (gitHead !== sourceCommit) throw new Error("admission source commit drift");
  if (gitStatus !== "") throw new Error("admission source checkout is dirty");
  if (!Buffer.isBuffer(reviewBytes) || sha256(reviewBytes) !== reviewSha256) {
    throw new Error("admission review SHA-256 mismatch");
  }
  const lines = new Set(reviewBytes.toString("utf8").split("\n").map((line) => line.trim()));
  for (const [label, line] of [
    ["mode", `mode: ${mode}`],
    ["nonce", `nonce: ${nonce}`],
    ["source commit", `sourceCommit: ${sourceCommit}`],
    ["plan", `planSha256: ${planSha256}`],
    ["verdict", "verdict: APPROVE"],
  ]) {
    if (!lines.has(line)) throw new Error(`admission review does not pin the ${label}`);
  }
  const packetId = admissionPacketId(mode, nonce);
  const packets = (rows ?? []).filter(
    (row) => row?.taskId === TASK_ID && row.packetId === packetId && row.outcome === PACKET_OUTCOME,
  );
  if (packets.length !== 1) throw new Error("admission requires one ledger packet reservation");
  const [packet] = packets;
  if (
    packet.sourceCommit !== sourceCommit ||
    packet.planSha256 !== planSha256 ||
    packet.reviewSha256 !== reviewSha256 ||
    packet.mode !== mode ||
    packet.nonce !== nonce
  ) {
    throw new Error("admission ledger packet does not match the reviewed pins");
  }
  if (runId === undefined) return { packetId, packet };
  const attempts = rows.filter(
    (row) =>
      row?.taskId === TASK_ID &&
      row.outcome === "reserved" &&
      row.packetId === packetId &&
      row.runId === runId,
  );
  if (!/^[a-f0-9]{32}$/.test(runId ?? "") || attempts.length !== 1) {
    throw new Error("admission requires this run's attempt reservation in the ledger");
  }
  return { packetId, packet, attempt: attempts[0] };
}

export function parseAdmissionEnvironment(env) {
  const raw = env.FIRESTORE_PROBE_ADMISSION;
  if (raw === undefined) return null;
  try {
    return JSON.parse(raw);
  } catch (error) {
    throw new Error("invalid production admission environment", { cause: error });
  }
}

function git(args) {
  return execFileSync("git", args, { cwd: ROOT, encoding: "utf8" });
}

export function admissionLedgerPath() {
  const gitCommonDir = git(["rev-parse", "--path-format=absolute", "--git-common-dir"]).trim();
  return resolve(gitCommonDir, "../docs.local/runs/sandbox-ledger.jsonl");
}

export function admissionReviewDirectory() {
  return resolve(dirname(admissionLedgerPath()), "../reviews");
}

/** Read the checkout, the review file and the ledger, then run the pure check. */
export function verifyProductionAdmissionOnDisk({ admission, runId }) {
  const reviewPath = admission?.reviewPath;
  const reviews = admissionReviewDirectory();
  if (
    typeof reviewPath !== "string" ||
    !isAbsolute(reviewPath) ||
    relative(reviews, reviewPath).startsWith("..") ||
    !lstatSync(reviewPath).isFile()
  ) {
    throw new Error("admission review must be a regular file under docs.local/reviews");
  }
  let rows = [];
  try {
    rows = readFileSync(admissionLedgerPath(), "utf8")
      .split("\n")
      .filter(Boolean)
      .map((line) => JSON.parse(line));
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  return verifyProductionAdmission({
    admission,
    reviewBytes: readFileSync(reviewPath),
    gitHead: git(["rev-parse", "HEAD"]).trim(),
    gitStatus: git(["status", "--porcelain"]).trim(),
    rows,
    runId,
  });
}

/** Child sessions call this before their first production request. */
export function requireChildProductionAdmission({
  production,
  env,
  runId,
  verify = verifyProductionAdmissionOnDisk,
}) {
  if (!production) return null;
  const admission = parseAdmissionEnvironment(env);
  if (admission === null) {
    throw new Error("a production child requires the runner's admission; launch through the runner");
  }
  if (!/^[a-f0-9]{32}$/.test(runId ?? "")) {
    throw new Error("a production child requires the runner's 32-hex run ID");
  }
  return verify({ admission, runId });
}
