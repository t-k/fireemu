// The command line of the lean recorder and its probe (`run.mjs pins`,
// `run.mjs record-production <1|2>` and `run.mjs probe-production`).
// It reads the packet and review files the approval check needs, builds the recorder's
// collaborators from the environment and prints one line of JSON. Exit codes: 0 recorded,
// 2 refused or failed before a run started, 3 stopped clean (nothing recorded), 4 needs
// recovery or a run that had started and then failed (its lock is kept). Nothing secret is printed.

import { execFile } from "node:child_process";
import { randomBytes } from "node:crypto";
import { constants, lstatSync } from "node:fs";
import { open, readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { admissionProblems } from "../auth-fs-cross/sandbox.mjs";
import { replayLocalAggregate } from "./aggregate-replay.mjs";
import {
  computePins,
  createLedgerFile,
  createPrivateRunFactory,
  readGitState,
} from "./record-io.mjs";
import { probeRun } from "./probe-run.mjs";
import { PROBE_MAX_REQUESTS, PROBE_RESERVE_USD } from "./probe.mjs";
import {
  createTokenProvider,
  PACKET_MAX_REQUESTS,
  PACKET_RESERVE_USD,
  RECORD_PROJECT,
  recordRun,
} from "./record.mjs";

const run = promisify(execFile);
const SOURCE_DIR = dirname(fileURLToPath(import.meta.url));
const PIN_KEYS = ["runnerSha256", "planSha256", "corpusSha256", "rulesSourceSha256"];
const PACKET_KEYS = ["packetName", "packetSha256", "sourceCommit", ...PIN_KEYS];
const PACKET_NAME = /^[a-z0-9][a-z0-9.-]{0,63}$/;
const API_KEY = /^[A-Za-z0-9_-]{20,}$/;
const EXIT = Object.freeze({ recorded: 0, "stopped-clean": 3, "needs-recovery": 4 });

export const requiredEnvironment = Object.freeze([
  "FIREEMU_STORAGE_OBJECT_PACKET",
  "FIREEMU_STORAGE_OBJECT_REVIEW",
  "FIREEMU_STORAGE_OBJECT_PRIVATE_DIR",
  "FIREEMU_STORAGE_OBJECT_AUTH_KEY_FILE",
]);

export const probeRequiredEnvironment = Object.freeze(
  requiredEnvironment.filter((name) => name !== "FIREEMU_STORAGE_OBJECT_AUTH_KEY_FILE"),
);

const MAX_OWNER_LEDGER_BYTES = 8 * 1024 * 1024;

/**
 * The main checkout above `start`: the nearest ancestor whose `.git` is a directory. A linked
 * worktree has a `.git` file, so the walk goes on to the checkout that owns it.
 */
export function mainRepositoryRoot(start) {
  let current = resolve(start);
  for (;;) {
    let stat = null;
    try {
      stat = lstatSync(join(current, ".git"));
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
    if (stat?.isDirectory()) return current;
    const parent = dirname(current);
    if (parent === current) throw new Error("main repository root not found");
    current = parent;
  }
}

/**
 * The shared ledger, the owner ledger and the locks live in the main checkout, at these paths and
 * nowhere else: another lane pins the same lock directory, so a run must not be able to move it.
 */
export function pinnedPaths(root) {
  const runs = join(root, "docs.local", "runs");
  return Object.freeze({
    ledger: join(runs, "sandbox-ledger.jsonl"),
    legacyLock: join(runs, "sandbox-ledger.jsonl.lock"),
    lockDir: join(runs, "sandbox-locks"),
    ownerLedger: join(root, "docs.local", "instructions", "owner-decisions.md"),
  });
}

/** The owner ledger: a regular file of this user that nobody else can write, read without following a link. */
async function readOwnerLedger(path) {
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  } catch {
    throw new Error("owner ledger refused");
  }
  try {
    const stat = await handle.stat();
    if (
      !stat.isFile() ||
      stat.uid !== process.getuid() ||
      (stat.mode & 0o022) !== 0 ||
      stat.size > MAX_OWNER_LEDGER_BYTES
    )
      throw new Error("owner ledger refused");
    return new TextDecoder("utf-8", { fatal: true }).decode(await handle.readFile());
  } catch {
    throw new Error("owner ledger refused");
  } finally {
    await handle.close();
  }
}

/** The collaborators that touch the machine; a test replaces them. */
export function realDeps() {
  return {
    stdout: (text) => process.stdout.write(text),
    stderr: (text) => process.stderr.write(text),
    nodeVersion: process.version,
    pins: () => computePins({ sourceDir: SOURCE_DIR }),
    git: () => readGitState(SOURCE_DIR),
    mainCheckout: () => mainRepositoryRoot(SOURCE_DIR),
    randomRunIds: () => {
      const runId = randomBytes(10).toString("hex");
      let otherRunId = randomBytes(10).toString("hex");
      while (otherRunId === runId) otherRunId = randomBytes(10).toString("hex");
      return { runId, otherRunId };
    },
    now: () => new Date(),
    gcloud: async () =>
      (await run("gcloud", ["auth", "application-default", "print-access-token"])).stdout,
    fetch: (...args) => globalThis.fetch(...args),
    recordRun,
    probeRun,
  };
}

async function readJson(path, label) {
  let value;
  try {
    value = JSON.parse(await readFile(path, "utf8"));
  } catch {
    throw new Error(`${label} is not readable JSON`);
  }
  return value;
}

async function readPacket(
  path,
  limits = { maxRequests: PACKET_MAX_REQUESTS, reserveUsd: PACKET_RESERVE_USD },
) {
  const file = await readJson(path, "packet file");
  const keys = file && typeof file === "object" && !Array.isArray(file) ? Object.keys(file) : [];
  if (
    keys.length !== PACKET_KEYS.length ||
    PACKET_KEYS.some((key) => !keys.includes(key)) ||
    !PACKET_NAME.test(file.packetName ?? "") ||
    Object.entries(file).some(([key, value]) => key !== "packetName" && typeof value !== "string")
  )
    throw new Error(
      "packet file must hold exactly the packet name, its SHA-256, the source commit and the four pins",
    );
  return {
    taskId: "STORAGE-OBJECT",
    packetName: file.packetName,
    projectId: RECORD_PROJECT,
    maxRequests: limits.maxRequests,
    reserveUsd: limits.reserveUsd,
    packetSha256: file.packetSha256,
    sourceCommit: file.sourceCommit,
    ...Object.fromEntries(PIN_KEYS.map((key) => [key, file[key]])),
  };
}

async function readApiKey(path) {
  const file = await readJson(path, "key file");
  if (typeof file?.keyString !== "string" || !API_KEY.test(file.keyString))
    throw new Error("key file has no usable key string");
  return file.keyString;
}

/** `run.mjs pins`: the digests a packet pins, for its author. Reads no credential. */
export async function pinsCommand(deps = realDeps()) {
  const [pins, tree] = await Promise.all([deps.pins(), deps.git()]);
  deps.stdout(
    `${JSON.stringify({
      sourceCommit: tree.commit,
      treeClean: tree.clean,
      ...Object.fromEntries(PIN_KEYS.map((key) => [key, pins[key]])),
      sourceFiles: pins.files.length,
    })}\n`,
  );
  return 0;
}

/** `run.mjs record-production <1|2>`. */
export async function recordCommand(argv, env, deps = realDeps()) {
  const fail = (message) => {
    deps.stderr(`${message}\n`);
    return 2;
  };
  if (argv.length !== 1 || !/^[12]$/.test(argv[0]))
    return fail("record-production needs the recording number (1 or 2)");
  const recording = Number(argv[0]);
  const missing = requiredEnvironment.filter((name) => !env[name]);
  if (missing.length > 0) return fail(`missing environment: ${missing.join(", ")}`);
  try {
    const packet = await readPacket(env.FIREEMU_STORAGE_OBJECT_PACKET);
    const review = await readJson(env.FIREEMU_STORAGE_OBJECT_REVIEW, "review file");
    const apiKey = await readApiKey(env.FIREEMU_STORAGE_OBJECT_AUTH_KEY_FILE);
    const paths = pinnedPaths(deps.mainCheckout());
    const ownerDecisionsText = await readOwnerLedger(paths.ownerLedger);
    const pins = await deps.pins();
    const ids = deps.randomRunIds();
    const options = {
      ids,
      recording,
      packet,
      review,
      ownerDecisionsText,
      actualPins: Object.fromEntries(PIN_KEYS.map((key) => [key, pins[key]])),
      env,
      nodeVersion: deps.nodeVersion,
      ledger: createLedgerFile(paths.ledger),
      git: () => deps.git(),
      admission: admissionProblems,
      locks: { lockDir: paths.lockDir, legacyLockPath: paths.legacyLock, pid: process.pid },
      privateRun: createPrivateRunFactory({ root: env.FIREEMU_STORAGE_OBJECT_PRIVATE_DIR }),
      getToken: createTokenProvider({ run: deps.gcloud, now: () => deps.now().getTime() }),
      apiKey,
      fetch: deps.fetch,
      replay: replayLocalAggregate,
      now: deps.now,
    };
    const result = await deps.recordRun(options);
    deps.stdout(
      `${JSON.stringify({
        outcome: result.outcome,
        requests: result.requests,
        recording,
        runId: ids.runId,
      })}\n`,
    );
    return EXIT[result.outcome] ?? 4;
  } catch (error) {
    // A run that had started keeps its lock and may have left objects: that is not a refusal.
    if (error?.afterStart === true) {
      deps.stderr(`${String(error.message)}\n`);
      return 4;
    }
    return fail(String(error?.message ?? error));
  }
}

/** `run.mjs probe-production`: the probe, once per packet. It holds no Web API key. */
export async function probeCommand(argv, env, deps = realDeps()) {
  const fail = (message) => {
    deps.stderr(`${message}\n`);
    return 2;
  };
  if (argv.length !== 0) return fail("probe-production takes no argument");
  const missing = probeRequiredEnvironment.filter((name) => !env[name]);
  if (missing.length > 0) return fail(`missing environment: ${missing.join(", ")}`);
  try {
    const packet = await readPacket(env.FIREEMU_STORAGE_OBJECT_PACKET, {
      maxRequests: PROBE_MAX_REQUESTS,
      reserveUsd: PROBE_RESERVE_USD,
    });
    const review = await readJson(env.FIREEMU_STORAGE_OBJECT_REVIEW, "review file");
    const paths = pinnedPaths(deps.mainCheckout());
    const ownerDecisionsText = await readOwnerLedger(paths.ownerLedger);
    const pins = await deps.pins();
    const ids = deps.randomRunIds();
    const result = await deps.probeRun({
      ids,
      packet,
      review,
      ownerDecisionsText,
      actualPins: Object.fromEntries(PIN_KEYS.map((key) => [key, pins[key]])),
      env,
      nodeVersion: deps.nodeVersion,
      ledger: createLedgerFile(paths.ledger),
      git: () => deps.git(),
      admission: admissionProblems,
      locks: { lockDir: paths.lockDir, legacyLockPath: paths.legacyLock, pid: process.pid },
      privateRun: createPrivateRunFactory({ root: env.FIREEMU_STORAGE_OBJECT_PRIVATE_DIR }),
      getToken: createTokenProvider({ run: deps.gcloud, now: () => deps.now().getTime() }),
      fetch: deps.fetch,
      now: deps.now,
    });
    deps.stdout(
      `${JSON.stringify({
        outcome: result.outcome,
        requests: result.requests,
        runId: ids.runId,
        ...(result.answers ? { answers: result.answers } : {}),
      })}\n`,
    );
    return EXIT[result.outcome] ?? 4;
  } catch (error) {
    if (error?.afterStart === true) {
      deps.stderr(`${String(error.message)}\n`);
      return 4;
    }
    return fail(String(error?.message ?? error));
  }
}
