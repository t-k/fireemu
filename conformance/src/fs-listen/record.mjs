// Records the native Listen programs (packet L1) against production or against fireemu. Plain on
// purpose: credentials come from `gcloud auth application-default print-access-token`, every
// resource is named with the run id and deleted by that prefix with a read-back, and the program
// only records rows. Whether a row is right is decided offline (compare.mjs).
//
//   node src/fs-listen/record.mjs native --target production --project fireemu-oracle-txn --out F
//   node src/fs-listen/record.mjs native --target local [--profile strict|emulator] --out F
//
// `--target local` starts fireemu itself (`fireemu exec`) and runs the same programs inside it.

import { execFile, spawn } from "node:child_process";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { resolveFireemuBinary } from "../evidence.mjs";
import { createNativeClient } from "./native-client.mjs";
import { NATIVE_PROGRAMS, SWEEP, programProblems } from "./native-programs.mjs";
import { cleanupNative, runNative } from "./native-run.mjs";

const execFileAsync = promisify(execFile);
const HERE = fileURLToPath(import.meta.url);

/** The only projects a recording may address: the disposable sandboxes that own this lane. */
export const ALLOWED_PROJECTS = {
  native: ["fireemu-oracle-txn"],
  sdk: ["fireemu-oracle-query"],
};

export function checkProject(kind, project) {
  if (!ALLOWED_PROJECTS[kind]?.includes(project))
    throw new Error(`${kind} recordings may address only ${ALLOWED_PROJECTS[kind]?.join(", ")}`);
}

export function parseArgs(argv) {
  const [command, ...rest] = argv;
  const options = { command };
  for (let i = 0; i < rest.length; i += 2) {
    if (!rest[i].startsWith("--")) throw new Error(`unexpected argument ${rest[i]}`);
    options[rest[i].slice(2)] = rest[i + 1];
  }
  return options;
}

async function accessToken() {
  const { stdout } = await execFileAsync("gcloud", [
    "auth",
    "application-default",
    "print-access-token",
  ]);
  return stdout.trim();
}

/** The run id: lower-case letters and digits, valid in a document id. */
export const newRunId = (now = Date.now()) => `n${now.toString(36)}`;

/** Records the native programs once with `client`, then cleans up; returns the recording. */
export async function recordNative({ client, project, run, log = () => {} }) {
  const startedAt = new Date().toISOString();
  const root = `projects/${project}/databases/(default)/documents`;
  let cleanup = { complete: false, error: "cleanup did not run" };
  let outcome = { rows: {}, errors: {}, requests: 0 };
  try {
    outcome = await runNative(NATIVE_PROGRAMS, { client, project, run, log });
  } finally {
    try {
      const report = await cleanupNative(NATIVE_PROGRAMS, {
        client,
        project,
        run,
        sweep: SWEEP(root),
      });
      cleanup = { ...report, deleted: report.deleted.length };
    } catch (error) {
      cleanup = { complete: false, error: String(error?.message ?? error) };
    }
  }
  return {
    version: 1,
    kind: "native",
    startedAt,
    node: process.version,
    requests: outcome.requests,
    errors: outcome.errors,
    cleanup,
    rows: outcome.rows,
  };
}

async function nativeProduction(options) {
  checkProject("native", options.project);
  const problems = programProblems(NATIVE_PROGRAMS);
  if (problems.length) throw new Error(`the programs are malformed:\n${problems.join("\n")}`);
  const client = createNativeClient({
    project: options.project,
    target: { kind: "production" },
    token: await accessToken(),
  });
  try {
    return await recordNative({
      client,
      project: options.project,
      run: newRunId(),
      log: (line) => console.error(line),
    });
  } finally {
    client.close();
  }
}

/** Inside `fireemu exec`: the emulator's Firestore address comes from the environment. */
async function nativeInsideFireemu(options) {
  const [host, port] = process.env.FIRESTORE_EMULATOR_HOST.split(":");
  const project = options.project ?? "demo-fs-listen";
  const client = createNativeClient({
    project,
    target: { kind: "local", host, port: Number(port) },
  });
  try {
    return await recordNative({ client, project, run: newRunId() });
  } finally {
    client.close();
  }
}

/** Starts fireemu with `profile` and runs `args` (a node script) inside it. */
export async function withFireemu({ profile, script, args, env }) {
  const dir = await mkdtemp(join(tmpdir(), "fs-listen-"));
  const config = join(dir, "fireemu.json");
  const firebase = join(dir, "firebase.json");
  await writeFile(
    config,
    JSON.stringify({
      schemaVersion: 1,
      profile,
      auth: { idTokenSigning: "session-rsa", apiKeys: ["fake-api-key"] },
    }),
  );
  await writeFile(firebase, JSON.stringify({ firestore: [{ database: "(default)" }] }));
  const ports = [
    "--http-port",
    "--firestore-port",
    "--storage-port",
    "--ui-port",
    "--hub-port",
    "--logging-port",
  ].flatMap((flag) => [flag, "0"]);
  const child = spawn(
    resolveFireemuBinary(),
    [
      "exec",
      "--config",
      config,
      "--firebase-json",
      firebase,
      "--project",
      "demo-fs-listen",
      "--only",
      "auth,firestore",
      ...ports,
      "--",
      process.execPath,
      script,
      ...args,
    ],
    { cwd: dir, stdio: ["ignore", "inherit", "inherit"], env: { ...process.env, ...env } },
  );
  const code = await new Promise((resolve) => child.once("exit", resolve));
  if (code !== 0) throw new Error(`fireemu session exited ${code}`);
}

async function main(argv) {
  const options = parseArgs(argv);
  if (!options.out) throw new Error("--out <file> is required");
  let recording;
  if (options.command === "native" && options.target === "production") {
    recording = await nativeProduction(options);
  } else if (options.command === "native" && options.target === "local") {
    const tmp = join(await mkdtemp(join(tmpdir(), "fs-listen-out-")), "recording.json");
    await withFireemu({
      profile: options.profile ?? "strict",
      script: HERE,
      args: ["native-in-fireemu", "--out", tmp],
    });
    recording = JSON.parse(await readFile(tmp, "utf8"));
  } else if (options.command === "native-in-fireemu") {
    recording = await nativeInsideFireemu(options);
  } else {
    throw new Error("usage: record.mjs native --target production|local --out FILE");
  }
  await mkdir(dirname(options.out), { recursive: true });
  await writeFile(options.out, `${JSON.stringify(recording, null, 2)}\n`);
  const bad = Object.keys(recording.errors ?? {}).length > 0 || !recording.cleanup.complete;
  console.error(
    `${options.command}: ${Object.keys(recording.rows).length} rows, ${recording.requests} requests, cleanup ${recording.cleanup.complete ? "complete" : "INCOMPLETE"}, ${Object.keys(recording.errors ?? {}).length} program errors`,
  );
  if (bad) process.exitCode = 2;
}

if (process.argv[1] === HERE) {
  main(process.argv.slice(2)).catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}
