// Records the native Listen programs (packet L1) against production or against fireemu. Plain on
// purpose: credentials come from `gcloud auth application-default print-access-token`, every
// resource is named with the run id and deleted by that prefix with a read-back, and the program
// only records rows. Whether a row is right is decided offline (compare.mjs).
//
//   node src/fs-listen/record.mjs native --target production --project fireemu-oracle-txn --out F
//   node src/fs-listen/record.mjs native --target local [--profile strict|emulator] --out F
//   node src/fs-listen/record.mjs sdk --target production --project fireemu-oracle-query \
//        --api-key-file KEY --out F     (KEY: a 0600 file holding only the web app's API key;
//                                         the key is bound to the project before anything is made)
//   node src/fs-listen/record.mjs sdk --target local [--profile strict|emulator] --out F
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
import { loadApiKey, recordSdk } from "./sdk-record.mjs";

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
export async function recordNative({ client, project, run, log = () => {}, clock = {} }) {
  const startedAt = new Date().toISOString();
  const root = `projects/${project}/databases/(default)/documents`;
  let cleanup;
  let outcome;
  try {
    outcome = await runNative(NATIVE_PROGRAMS, { client, project, run, log, ...clock });
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
export async function withFireemu({ profile, script, args, env, rules }) {
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
  await writeFile(
    firebase,
    JSON.stringify({ firestore: [{ database: "(default)", ...(rules ? { rules } : {}) }] }),
  );
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
  // The recording is written to its own file even when it ends not clean (exit 2): the caller
  // reads it and reports; only a session that never wrote one is an error.
  return new Promise((resolve) => child.once("exit", resolve));
}

async function sdkProduction(options) {
  checkProject("sdk", options.project);
  if (!options["api-key-file"]) throw new Error("--api-key-file <file> is required");
  const apiKey = await loadApiKey(options["api-key-file"]);
  const token = await accessToken();
  return recordSdk({
    target: {
      kind: "production",
      project: options.project,
      token,
      web: { apiKey, authDomain: `${options.project}.firebaseapp.com`, projectId: options.project },
    },
    run: newRunId(),
    log: (line) => console.error(line),
  });
}

/** Inside `fireemu exec`: the emulator's Firestore and Auth addresses come from the environment. */
async function sdkInsideFireemu() {
  const [host, port] = process.env.FIRESTORE_EMULATOR_HOST.split(":");
  return recordSdk({
    target: {
      kind: "local",
      project: "demo-fs-listen",
      firestore: { host, port: Number(port) },
      auth: `http://${process.env.FIREBASE_AUTH_EMULATOR_HOST}`,
    },
    run: newRunId(),
  });
}

/**
 * Runs `args` (a node script) inside the official Firestore emulator (firebase-tools, the
 * oracle of the emulator profile) and resolves with the script's exit code.
 */
export async function withOfficialEmulator({ script, args, rules, auth = false }) {
  const dir = await mkdtemp(join(tmpdir(), "fs-listen-official-"));
  await writeFile(
    join(dir, "firebase.json"),
    JSON.stringify({
      ...(rules ? { firestore: { rules } } : {}),
      emulators: {
        firestore: { host: "127.0.0.1", port: 0 },
        ...(auth ? { auth: { host: "127.0.0.1", port: 0 } } : {}),
        ui: { enabled: false },
      },
    }),
  );
  const command = [process.execPath, script, ...args].map((part) => JSON.stringify(part)).join(" ");
  const child = spawn(
    join(dirname(HERE), "../../node_modules/.bin/firebase"),
    [
      "emulators:exec",
      "--only",
      auth ? "auth,firestore" : "firestore",
      "--project",
      "demo-fs-listen",
      "--config",
      join(dir, "firebase.json"),
      command,
    ],
    { cwd: dir, stdio: ["ignore", "inherit", "inherit"], env: process.env },
  );
  return new Promise((resolve) => child.once("exit", resolve));
}

/** Runs `command` of this file inside a fireemu session and returns the recording it wrote. */
async function inFireemu(options, command, { rules } = {}) {
  const tmp = join(await mkdtemp(join(tmpdir(), "fs-listen-out-")), "recording.json");
  const args = [command, "--out", tmp];
  const code =
    options.target === "official"
      ? await withOfficialEmulator({ script: HERE, args, rules, auth: command.startsWith("sdk") })
      : await withFireemu({ profile: options.profile ?? "strict", script: HERE, args, rules });
  let text;
  try {
    text = await readFile(tmp, "utf8");
  } catch {
    throw new Error(`fireemu session exited ${code} without a recording`);
  }
  return JSON.parse(text);
}

async function main(argv) {
  const options = parseArgs(argv);
  if (!options.out) throw new Error("--out <file> is required");
  let recording;
  if (options.command === "native" && options.target === "production") {
    recording = await nativeProduction(options);
  } else if (options.command === "native" && ["local", "official"].includes(options.target)) {
    recording = await inFireemu(options, "native-in-fireemu");
  } else if (options.command === "native-in-fireemu") {
    recording = await nativeInsideFireemu(options);
  } else if (options.command === "sdk" && options.target === "production") {
    recording = await sdkProduction(options);
  } else if (options.command === "sdk" && ["local", "official"].includes(options.target)) {
    recording = await inFireemu(options, "sdk-in-fireemu", {
      rules: join(dirname(HERE), "../../firestore.rules"),
    });
  } else if (options.command === "sdk-in-fireemu") {
    recording = await sdkInsideFireemu();
  } else {
    throw new Error("usage: record.mjs native|sdk --target production|local --out FILE");
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
