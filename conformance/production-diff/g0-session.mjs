// Invoked only as the child of pilot-owned current fireemu execution.
import { promises as fs } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { publish, publishJson } from "./io.mjs";
import { requireThat, digestJson, safeCode } from "./core.mjs";
import { canonicalG0Origins, g0SessionPythonSource, readOwnedProcessArgv, resolveLockedUvCommand } from "./g0.mjs";

const directory = process.env.PILOT_RUN_DIR;
requireThat(typeof directory === "string", "missing-run-directory");
const root = resolve(process.env.PILOT_REPO ?? resolve(dirname(fileURLToPath(import.meta.url)), "../.."));
const inventoryProject = resolve(root, "tools/compat-inventory");
const plan = JSON.parse(await fs.readFile(join(directory, "program.json"), "utf8"));
const canonicalProgramDigest = process.env.PILOT_PROGRAM_DIGEST;
requireThat(canonicalProgramDigest === digestJson(plan), "g0-program-digest-binding");
const receiptPath = join(directory, "launch-receipt.json");
const receiptInfo = await fs.lstat(receiptPath);
requireThat(receiptInfo.isFile() && !receiptInfo.isSymbolicLink(), "g0-launch-receipt-type");
const receiptBytes = await fs.readFile(receiptPath);
const receipt = JSON.parse(receiptBytes);
const runInfo = await fs.stat(directory);
const binaryHash = createHash("sha256").update(await fs.readFile(join(directory, "fireemu"))).digest("hex");
const configHash = createHash("sha256").update(await fs.readFile(join(directory, "fireemu.json"))).digest("hex");
const rulesHash = createHash("sha256").update(await fs.readFile(join(directory, "firestore.rules"))).digest("hex");
function observedArgv(pid) {
  return readOwnedProcessArgv(pid);
}
const launcherArgv = observedArgv(process.ppid);
requireThat(
  receipt.schema === "fireemu-g0-launch-v1" &&
    receipt.pid === process.ppid &&
    receipt.command === join(directory, "fireemu") &&
    Array.isArray(receipt.args) &&
    !receipt.args.includes("--import") &&
    !receipt.args.includes("--export-on-exit") &&
    receipt.binarySha256 === binaryHash &&
    receipt.configSha256 === configHash &&
    receipt.rulesSha256 === rulesHash &&
    receipt.runDirectory?.path === directory &&
    receipt.runDirectory?.dev === runInfo.dev &&
    receipt.runDirectory?.ino === runInfo.ino &&
    receipt.runDirectory?.mode === (runInfo.mode & 0o777) &&
    receipt.import === null &&
    receipt.exportOnExit === null,
  "g0-launch-receipt-invalid",
);
requireThat(
  Array.isArray(launcherArgv) && JSON.stringify(launcherArgv) === JSON.stringify([receipt.command, ...receipt.args]),
  "g0-launch-argv-invalid",
);
const expectedProvenance = {
  retainedManifestSha256: process.env.G0_RETAINED_MANIFEST_SHA256,
  artifactProfile: process.env.G0_ARTIFACT_PROFILE,
  runtimeSourceCommit: process.env.G0_RUNTIME_SOURCE_COMMIT,
  sourceInputsDigest: process.env.G0_SOURCE_INPUTS_DIGEST,
};
requireThat(
  Object.values(expectedProvenance).every((value) => typeof value === "string" && value.length > 0) &&
    Object.entries(expectedProvenance).every(([key, value]) => receipt[key] === value),
  "g0-build-provenance-invalid",
);
const canonicalOrigins = canonicalG0Origins(process.env);
const pythonCommand = resolveLockedUvCommand();
const python = g0SessionPythonSource();
const pythonArgs = ["run", "--project", inventoryProject, "--locked", "--python", "3.12", "python", "-c", python, root, directory];
const freshness = {
  schema: "fireemu-g0-freshness-v1",
  parentPid: receipt.pid,
  childPid: process.pid,
  receiptSha256: createHash("sha256").update(receiptBytes).digest("hex"),
  binarySha256: receipt.binarySha256,
  sourceCommit: receipt.sourceCommit,
  argv: [receipt.command, ...receipt.args],
  configSha256: receipt.configSha256,
  rulesSha256: receipt.rulesSha256,
  environmentSha256: receipt.environmentSha256,
  runDirectory: receipt.runDirectory,
  import: null,
  exportOnExit: null,
  origins: canonicalOrigins,
  programDigest: canonicalProgramDigest,
  ...expectedProvenance,
  pythonArgv: [pythonCommand, ...pythonArgs],
};
await publishJson(join(directory, "freshness-handshake.json"), freshness);
const result = await new Promise((done) => {
  const child = spawn(
    pythonCommand,
    pythonArgs,
    {
      cwd: root,
      env: { ...process.env, PYTHONUNBUFFERED: "1" },
      stdio: ["ignore", "ignore", "pipe"],
    },
  );
  let stderrBytes = 0;
  let stderrTruncated = false;
  const stderrChunks = [];
  let stderrCaptured = 0;
  let settled = false;
  child.stderr.on("data", (chunk) => {
    stderrBytes += chunk.length;
    if (stderrCaptured < 64 * 1024) {
      const remaining = 64 * 1024 - stderrCaptured;
      const bounded = chunk.subarray(0, remaining);
      stderrChunks.push(bounded);
      stderrCaptured += bounded.length;
    }
    if (stderrBytes > 64 * 1024) stderrTruncated = true;
  });
  const complete = async (code, error, stage) => {
    if (settled) return;
    settled = true;
    const stderr = Buffer.concat(stderrChunks);
    let stderrArtifact = null;
    try {
      await publish(join(directory, "python-stderr.log"), stderr);
      stderrArtifact = {
        path: "python-stderr.log",
        bytes: stderr.length,
        sha256: createHash("sha256").update(stderr).digest("hex"),
        truncated: stderrTruncated,
      };
    } catch {
      stderrArtifact = { path: "python-stderr.log", bytes: 0, sha256: null, truncated: stderrTruncated };
    }
    done({ code, error, stage, stderrBytes, stderrTruncated, stderrArtifact });
  };
  child.once("error", () => complete(null, "python-start-failed", "python-start"));
  child.once("close", (code) => complete(code, code === 0 ? null : "shared-g0-execution-failed", "python-g0-execute"));
});
if (result.code !== 0) {
  await publishJson(join(directory, "session-result.json"), {
    schema: "fireemu-production-diff-session-v1",
    caseId: process.env.PILOT_CASE_ID,
    programDigest: canonicalProgramDigest,
    localSha256: null,
    completed: false,
    failure: result.error,
    failureStage: result.stage ?? "python-start",
    failureCode: result.code === null ? "spawn-failed" : `exit-${result.code}`,
    stderrBytes: result.stderrBytes ?? 0,
    stderrTruncated: result.stderrTruncated === true,
    stderrArtifact: result.stderrArtifact,
    cleanup: { state: "unconfirmed", absent: [], requests: 0 },
    requests: [],
    requestCount: 0,
    authRequests: 0,
    productionRequests: 0,
    endpoint: canonicalOrigins.firestore,
  });
  process.exitCode = 2;
  process.exit();
}
const batch = JSON.parse(await fs.readFile(join(directory, "batch", "result.json"), "utf8"));
const binary = await fs.readFile(join(directory, "fireemu"));
const local = {
  batch,
  executionCommit: (await new Promise((done) => {
    const child = spawn("git", ["-C", root, "rev-parse", "HEAD"], { stdio: ["ignore", "pipe", "ignore"] });
    const chunks = [];
    child.stdout.on("data", (chunk) => chunks.push(chunk));
    child.once("close", (code) => done(code === 0 ? Buffer.concat(chunks).toString().trim() : null));
  })) ?? "",
  runtimeArtifactSha256: createHash("sha256").update(binary).digest("hex"),
};
await publishJson(join(directory, "local.json"), local);
const cleanup = { state: batch.completed ? "confirmed" : "unconfirmed", absent: [], requests: 0 };
await publishJson(join(directory, "session-result.json"), {
  schema: "fireemu-production-diff-session-v1",
  caseId: process.env.PILOT_CASE_ID,
  programDigest: canonicalProgramDigest,
  localSha256: createHash("sha256").update(JSON.stringify(local, null, 2) + "\n").digest("hex"),
  completed: result.code === 0 && batch.completed,
  failure: result.error,
  cleanup,
  requests: [],
  requestCount: 0,
  authRequests: 0,
  productionRequests: 0,
  endpoint: canonicalOrigins.firestore,
});
if (result.code !== 0 || !batch.completed) process.exitCode = 2;
