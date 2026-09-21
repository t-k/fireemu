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
validateG0Origins(process.env);
const plan = JSON.parse(await fs.readFile(join(directory, "program.json"), "utf8"));
const python = g0SessionPythonSource();
const result = await new Promise((done) => {
  const child = spawn("uv", ["run", "python", "-c", python, root, directory], {
    cwd: root,
    env: { ...process.env, PYTHONUNBUFFERED: "1" },
    stdio: ["ignore", "ignore", "pipe"],
  });
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
