// Invoked only as the child of pilot-owned current fireemu execution.
import { promises as fs } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { publishJson } from "./io.mjs";
import { requireThat, digestJson, safeCode } from "./core.mjs";
import { g0SessionPythonSource, validateG0Origins } from "./g0.mjs";

const directory = process.env.PILOT_RUN_DIR;
requireThat(typeof directory === "string", "missing-run-directory");
const root = resolve(process.env.PILOT_REPO ?? resolve(dirname(fileURLToPath(import.meta.url)), "../.."));
const inventoryProject = resolve(root, "tools/compat-inventory");
const plan = JSON.parse(await fs.readFile(join(directory, "program.json"), "utf8"));
const receiptPath = join(directory, "launch-receipt.json");
const receiptInfo = await fs.lstat(receiptPath);
requireThat(receiptInfo.isFile() && !receiptInfo.isSymbolicLink(), "g0-launch-receipt-type");
const receiptBytes = await fs.readFile(receiptPath);
const receipt = JSON.parse(receiptBytes);
const runInfo = await fs.stat(directory);
const binaryHash = createHash("sha256").update(await fs.readFile(join(directory, "fireemu"))).digest("hex");
const configHash = createHash("sha256").update(await fs.readFile(join(directory, "fireemu.json"))).digest("hex");
const rulesHash = createHash("sha256").update(await fs.readFile(join(directory, "firestore.rules"))).digest("hex");
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
const origins = validateG0Origins(process.env);
const freshness = {
  schema: "fireemu-g0-freshness-v1",
  parentPid: receipt.pid,
  childPid: process.pid,
  receiptSha256: createHash("sha256").update(receiptBytes).digest("hex"),
  binarySha256: receipt.binarySha256,
  sourceCommit: receipt.sourceCommit,
  configSha256: receipt.configSha256,
  rulesSha256: receipt.rulesSha256,
  environmentSha256: receipt.environmentSha256,
  runDirectory: receipt.runDirectory,
  import: null,
  exportOnExit: null,
  origins,
};
await publishJson(join(directory, "freshness-handshake.json"), freshness);
const python = g0SessionPythonSource();
const result = await new Promise((done) => {
  const child = spawn(
    "uv",
    ["run", "--project", inventoryProject, "--locked", "--python", "3.12", "python", "-c", python, root, directory],
    {
      cwd: root,
      env: { ...process.env, PYTHONUNBUFFERED: "1" },
      stdio: ["ignore", "ignore", "pipe"],
    },
  );
  child.once("error", () => done({ code: null, error: "python-start-failed" }));
  child.once("close", (code) =>
    done({
      code,
      stage: "python-g0-execute",
      error: code === 0 ? null : "shared-g0-execution-failed",
    }),
  );
});
if (result.code !== 0) {
  await publishJson(join(directory, "session-result.json"), {
    schema: "fireemu-production-diff-session-v1",
    caseId: process.env.PILOT_CASE_ID,
    programDigest: digestJson(plan),
    localSha256: null,
    completed: false,
    failure: result.error,
    failureStage: result.stage ?? "python-start",
    cleanup: { state: "unconfirmed", absent: [], requests: 0 },
    requests: [],
    requestCount: 0,
    authRequests: 0,
    productionRequests: 0,
    endpoint: null,
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
  programDigest: digestJson(plan),
  localSha256: createHash("sha256").update(JSON.stringify(local, null, 2) + "\n").digest("hex"),
  completed: result.code === 0 && batch.completed,
  failure: result.error,
  cleanup,
  requests: [],
  requestCount: 0,
  authRequests: 0,
  productionRequests: 0,
  endpoint: null,
});
if (result.code !== 0 || !batch.completed) process.exitCode = 2;
