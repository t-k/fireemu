// Records the native Listen programs (packet L1) against production or against fireemu. Plain on
// purpose: credentials come from `gcloud auth application-default print-access-token`, every
// resource is named with the run id and deleted by that prefix with a read-back, and the program
// only records rows. Whether a row is right is decided offline (compare.mjs).
//
//   node src/fs-listen/record.mjs native --target production --project fireemu-oracle-txn --envelope E --ledger L --out F
//   node src/fs-listen/record.mjs native --target local [--profile strict|emulator] --out F
//   (L: the sandbox ledger; E: the envelope id. A production run is admitted only if the coordinator
//   holds the project's lock for E, no other run of the project is open, and the latest ledger row
//   of the project is 30 minutes old. Add `--include-long yes` to also record the expired-token
//   program: about 35 minutes of waiting. The run id is printed as `run <id>` and, with every name
//   the run issues, written to `<F>.journal.jsonl` (0600, fsynced) before the first request.)
//   node src/fs-listen/record.mjs sdk --target production --project fireemu-oracle-query \
//        --envelope E --ledger L --api-key-file KEY --out F     (KEY: a 0600 file holding only the
//                                         web app's API key; the key is bound to the project
//                                         before anything is made)
//   node src/fs-listen/record.mjs readback --journal J --project P --out F
//        (the coordinator's A2 read-back: reads every name and account the journal lists, read-only)
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
import { checkAdmission } from "./admission.mjs";
import { createAccountClient } from "./accounts.mjs";
import { NULL_JOURNAL, createJournal, issuedFromJournal, readbackJournal } from "./journal.mjs";
import { createLedger, settleNames } from "./native-ledger.mjs";
import { LONG_PROGRAMS, NATIVE_PROGRAMS, programProblems } from "./native-programs.mjs";
import { runNative } from "./native-run.mjs";
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

/** The token from the command's output; an empty or odd output is refused, and never printed. */
export function validToken(stdout) {
  const token = String(stdout ?? "").trim();
  if (token === "" || /\s/.test(token))
    throw new Error("the access token command gave an empty or malformed token");
  return token;
}

export async function accessToken(run = execFileAsync) {
  const { stdout } = await run("gcloud", ["auth", "application-default", "print-access-token"]);
  return validToken(stdout);
}

/** The run id: lower-case letters and digits, valid in a document id. */
export const newRunId = (now = Date.now()) => `n${now.toString(36)}`;

/** The programs a run records: the short ones, and the long ones too with `--include-long yes`. */
export const programsFor = (options) =>
  options["include-long"] === "yes" ? [...NATIVE_PROGRAMS, ...LONG_PROGRAMS] : NATIVE_PROGRAMS;

/** Records the native programs once with `client`, then settles every name issued; returns the recording. */
export async function recordNative({
  client,
  project,
  run,
  log = () => {},
  clock = {},
  programs = NATIVE_PROGRAMS,
  journal = NULL_JOURNAL,
}) {
  const startedAt = new Date().toISOString();
  const root = `projects/${project}/databases/(default)/documents`;
  // The ledger outlives a run that fails: cleanup works from the names issued, however it ended.
  const ledger = createLedger({ journal });
  let cleanup;
  let outcome;
  try {
    outcome = await runNative(programs, { client, project, run, log, ledger, ...clock });
  } finally {
    try {
      cleanup = await settleNames({ issued: ledger.entries(), client, root, run, journal });
    } catch (error) {
      cleanup = { complete: false, error: String(error?.message ?? error) };
    }
  }
  const productionRequests = client.requestCount?.() ?? null;
  journal.append({ type: "end", productionRequests });
  return {
    version: 1,
    kind: "native",
    run,
    startedAt,
    endedAt: new Date().toISOString(),
    node: process.version,
    requests: outcome.requests,
    productionRequests,
    issued: ledger.entries().map(([name]) => name),
    errors: outcome.errors,
    cleanup,
    rows: outcome.rows,
  };
}

/** The read-only admission of a production recording: this envelope's lock is held, no other run is open, the spacing has passed. */
export async function admit(options) {
  if (!options.ledger) throw new Error("--ledger <sandbox-ledger.jsonl> is required");
  if (!options.envelope) throw new Error("--envelope <envelope id> is required");
  const admitted = await checkAdmission({
    ledger: options.ledger,
    project: options.project,
    envelope: options.envelope,
    readFile,
  });
  console.error(`admitted: lock held by ${admitted.holder.taskId} for ${options.envelope}`);
}

/** The journal of a production run: created (0600) and headed with the run id before any request. */
function openJournal(options, kind, run) {
  const journal = createJournal(`${options.out}.journal.jsonl`);
  journal.append({
    type: "run",
    runId: run,
    kind,
    project: options.project,
    envelopeId: options.envelope,
    startedAt: new Date().toISOString(),
  });
  console.error(`run ${run}`);
  return journal;
}

const PRODUCTION_DEPS = {
  checkProject,
  admit,
  accessToken: () => accessToken(),
  newRunId: () => newRunId(),
  openJournal,
  createClient: createNativeClient,
  recordNative,
  loadApiKey,
  recordSdk,
};

/**
 * The order of a production recording is the safety property: project check, then admission, then
 * (for the SDK) the key file, then the token, then the run id and journal, and only then the first
 * request. `deps` replaces the effects in tests.
 */
export async function nativeProduction(options, deps = {}) {
  const d = { ...PRODUCTION_DEPS, ...deps };
  d.checkProject("native", options.project);
  await d.admit(options);
  const problems = programProblems([...NATIVE_PROGRAMS, ...LONG_PROGRAMS]);
  if (problems.length) throw new Error(`the programs are malformed:\n${problems.join("\n")}`);
  const token = await d.accessToken();
  const run = d.newRunId();
  const journal = d.openJournal(options, "native", run);
  const client = d.createClient({
    project: options.project,
    target: { kind: "production" },
    token,
    refreshToken: d.accessToken,
  });
  try {
    return await d.recordNative({
      client,
      project: options.project,
      run,
      log: (line) => console.error(line),
      programs: programsFor(options),
      journal,
    });
  } finally {
    client.close();
    journal.close();
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
    return await recordNative({
      client,
      project,
      run: newRunId(),
      programs: programsFor(options),
    });
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

export async function sdkProduction(options, deps = {}) {
  const d = { ...PRODUCTION_DEPS, ...deps };
  d.checkProject("sdk", options.project);
  await d.admit(options);
  if (!options["api-key-file"]) throw new Error("--api-key-file <file> is required");
  const apiKey = await d.loadApiKey(options["api-key-file"]);
  const token = await d.accessToken();
  const run = d.newRunId();
  const journal = d.openJournal(options, "sdk", run);
  try {
    return await d.recordSdk({
      target: {
        kind: "production",
        project: options.project,
        token,
        web: {
          apiKey,
          authDomain: `${options.project}.firebaseapp.com`,
          projectId: options.project,
        },
      },
      run,
      log: (line) => console.error(line),
      journal,
    });
  } finally {
    journal.close();
  }
}

/** The coordinator's A2 read-back of a journal: read-only, nothing is deleted. */
export async function readbackProduction(options, deps = {}) {
  const d = { ...PRODUCTION_DEPS, accessToken: () => accessToken(), ...deps };
  if (!options.journal) throw new Error("--journal <file> is required");
  const text = await readFile(options.journal, "utf8");
  const { run } = issuedFromJournal(text);
  d.checkProject(run.kind, options.project);
  if (run.project !== options.project)
    throw new Error("the journal is of another project than --project");
  const token = await d.accessToken();
  const client = d.createClient({
    project: options.project,
    target: { kind: "production" },
    token,
  });
  const accountClient =
    run.kind === "sdk"
      ? createAccountClient({
          base: "https://identitytoolkit.googleapis.com",
          project: options.project,
          headers: { authorization: `Bearer ${token}`, "x-goog-user-project": options.project },
        })
      : {
          lookup: async () => {
            throw new Error("a native journal lists no accounts");
          },
        };
  try {
    return await readbackJournal({ text, client, accountClient });
  } finally {
    client.close();
  }
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
  const args = [
    command,
    "--out",
    tmp,
    ...(options["include-long"] ? ["--include-long", options["include-long"]] : []),
  ];
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
  if (options.command === "readback") {
    const report = await readbackProduction(options);
    await mkdir(dirname(options.out), { recursive: true });
    await writeFile(options.out, `${JSON.stringify(report, null, 2)}\n`);
    console.error(`readback ${report.run}: ${report.clean ? "clean" : "NOT CLEAN"}`);
    if (!report.clean) process.exitCode = 2;
    return;
  }
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
