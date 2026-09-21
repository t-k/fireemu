// Invoked only as the child of pilot-owned current fireemu execution.
import { promises as fs } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { publishJson } from "./io.mjs";
import { requireThat, digestJson, safeCode } from "./core.mjs";

const directory = process.env.PILOT_RUN_DIR;
requireThat(typeof directory === "string", "missing-run-directory");
const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const plan = JSON.parse(await fs.readFile(join(directory, "program.json"), "utf8"));
const python = [
  "import json, os, pathlib, subprocess, sys",
  "root=pathlib.Path(sys.argv[1]); out=pathlib.Path(sys.argv[2])",
  "sys.path.insert(0, str(root/'tools/compat-broad'))",
  "from broad_contract import local_origin",
  "from batch_adapter import observer_digest",
  "from shared_cases import execute",
  "from shared_gate import create",
  "plan=json.loads((out/'program.json').read_bytes()); plan['observerSha256']=observer_digest()",
  "create(out/'gate', plan)",
  "origins={'firestore': local_origin('http://' + os.environ['FIRESTORE_EMULATOR_HOST'])}",
  "if not execute(out, origins): raise SystemExit(3)",
].join("; ");
const result = await new Promise((done) => {
  const child = spawn("uv", ["run", "python", "-c", python, root, directory], {
    cwd: root,
    env: { ...process.env, PYTHONUNBUFFERED: "1" },
    stdio: ["ignore", "ignore", "pipe"],
  });
  const errors = [];
  child.stderr.on("data", (chunk) => errors.push(chunk));
  child.once("error", () => done({ code: null, error: "python-start-failed" }));
  child.once("close", (code) => done({ code, error: code === 0 ? null : "shared-g0-execution-failed" }));
});
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
  productionRequests: 0,
  endpoint: null,
});
if (result.code !== 0 || !batch.completed) process.exitCode = 2;
