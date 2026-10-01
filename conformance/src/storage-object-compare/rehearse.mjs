// Runs the recorder's local rehearsal (the same 26 recipes, through the lean wire, against a local
// fireemu in the strict profile) and writes a receipt that binds the comparison to the fireemu
// commit and binary digest, the recorder commit and the journal. The recorder is a checkout of the
// recorder branch; this tool does not change it.

import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const STANDIN = join(dirname(fileURLToPath(import.meta.url)), "rehearsal-standin.mjs");
const sha256File = (path) => createHash("sha256").update(readFileSync(path)).digest("hex");

const git = (directory, ...args) =>
  spawnSync("git", ["-C", directory, ...args], { encoding: "utf8" }).stdout.trim();

/** The sandbox profile that allows loopback and nothing else outbound (macOS). */
export const LOOPBACK_PROFILE =
  '(version 1)\n(allow default)\n(deny network-outbound (remote ip))\n(allow network-outbound (remote ip "localhost:*"))\n';

export function rehearsalPlan({
  fireemuBinary,
  recorderDir,
  rulesFile,
  fixtureDir,
  outDir,
  sandbox,
}) {
  const conformance = join(recorderDir, "conformance");
  const config = join(outDir, "fireemu.config.json");
  const firebaseJson = join(outDir, "firebase.json");
  const profile = join(outDir, "loopback.sb");
  const inner = `STANDIN_STORAGE_ORIGIN="http://$FIREBASE_STORAGE_EMULATOR_HOST" exec node --import ${STANDIN} src/storage-object/local-aggregate.mjs`;
  const exec = [
    fireemuBinary,
    "exec",
    "--project",
    "example-project",
    "--config",
    config,
    "--firebase-json",
    firebaseJson,
    "--only",
    "storage,auth",
    "--",
    "sh",
    "-c",
    inner,
  ];
  return {
    cwd: conformance,
    files: {
      [config]: `${JSON.stringify({ schemaVersion: 1, profile: "strict", auth: { idTokenSigning: "session-rsa" } })}\n`,
      [firebaseJson]: `${JSON.stringify({ storage: { rules: rulesFile } })}\n`,
      ...(sandbox ? { [profile]: LOOPBACK_PROFILE } : {}),
    },
    command: sandbox ? ["sandbox-exec", "-f", profile, ...exec] : exec,
    env: {
      STORAGE_OBJECT_RULES_SOURCE: rulesFile,
      STORAGE_OBJECT_LOCAL_WIRE: "lean",
      STORAGE_OBJECT_LOCAL_RECORDINGS: "1",
      STANDIN_FIXTURE: fixtureDir,
    },
  };
}

function run(command, { cwd, env, timeoutMs }) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(command[0], command.slice(1), {
      cwd,
      env: { ...process.env, ...env },
      stdio: ["ignore", "pipe", "pipe"],
      detached: true,
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => (stdout += chunk));
    child.stderr.on("data", (chunk) => (stderr += chunk));
    const timer = setTimeout(() => {
      try {
        process.kill(-child.pid, "SIGTERM");
      } catch {
        // already gone
      }
      reject(new Error("the rehearsal timed out"));
    }, timeoutMs);
    child.on("close", (code) => {
      clearTimeout(timer);
      resolvePromise({ code, stdout, stderr });
    });
    child.on("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
  });
}

/** Run the rehearsal and return the receipt (also written to `<outDir>/receipt.json`). */
export async function rehearse({
  fireemuBinary,
  fireemuCommit,
  recorderDir,
  rulesFile,
  fixtureDir,
  outDir,
  sandbox = process.platform === "darwin",
  timeoutMs = 1_800_000,
}) {
  if (!/^[0-9a-f]{40}$/.test(fireemuCommit ?? ""))
    throw new Error("--fireemu-commit must be a full commit SHA");
  for (const [name, path] of Object.entries({ fireemuBinary, recorderDir, rulesFile, fixtureDir }))
    if (!path || !existsSync(path)) throw new Error(`${name} does not exist`);
  const recorderCommit = git(recorderDir, "rev-parse", "HEAD");
  if (git(recorderDir, "status", "--porcelain") !== "")
    throw new Error("the recorder checkout is not clean");
  mkdirSync(outDir, { recursive: true });
  const plan = rehearsalPlan({
    fireemuBinary: resolve(fireemuBinary),
    recorderDir: resolve(recorderDir),
    rulesFile: resolve(rulesFile),
    fixtureDir: resolve(fixtureDir),
    outDir: resolve(outDir),
    sandbox,
  });
  for (const [path, text] of Object.entries(plan.files)) writeFileSync(path, text);
  const result = await run(plan.command, { cwd: plan.cwd, env: plan.env, timeoutMs });
  const summary = result.stdout
    .trim()
    .split("\n")
    .findLast((line) => line.startsWith("{"));
  const parsed = summary ? JSON.parse(summary) : null;
  if (!parsed?.eventDirectory)
    throw new Error(`the rehearsal did not report its journal (exit ${result.code})`);
  const journal = join(resolve(outDir), "journal.jsonl");
  copyFileSync(join(parsed.eventDirectory, "aggregate-events.jsonl"), journal);
  const receipt = {
    fireemu: {
      binarySha256: sha256File(fireemuBinary),
      version: spawnSync(fireemuBinary, ["--version"], { encoding: "utf8" }).stdout.trim(),
      commit: fireemuCommit,
    },
    recorder: { commit: recorderCommit, clean: true },
    standinSha256: sha256File(STANDIN),
    journalSha256: sha256File(journal),
    result: {
      status: parsed.status,
      completedRecipes: parsed.completedRecipes,
      requests: parsed.requests,
      exitCode: result.code,
    },
  };
  writeFileSync(join(resolve(outDir), "receipt.json"), `${JSON.stringify(receipt, null, 2)}\n`);
  return receipt;
}
