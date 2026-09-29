// The command line of the lean recorder (`run.mjs pins` and `run.mjs record-production <1|2>`).
// It reads the packet and review files the approval check needs, builds the recorder's
// collaborators from the environment and prints one line of JSON. Exit codes: 0 recorded,
// 2 refused or failed before a run could finish, 3 stopped clean (nothing recorded), 4 needs
// recovery. Nothing secret is printed.

import { execFile } from "node:child_process";
import { randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
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
import { createTokenProvider, RECORD_PROJECT, recordRun } from "./record.mjs";

const run = promisify(execFile);
const SOURCE_DIR = dirname(fileURLToPath(import.meta.url));
const PIN_KEYS = ["runnerSha256", "planSha256", "corpusSha256", "rulesSourceSha256"];
const PACKET_KEYS = ["packetName", "packetSha256", "sourceCommit", ...PIN_KEYS];
const PACKET_NAME = /^[a-z0-9][a-z0-9.-]{0,63}$/;
const API_KEY = /^[A-Za-z0-9_-]{20,}$/;
const EXIT = Object.freeze({ recorded: 0, "stopped-clean": 3, "needs-recovery": 4 });

export const requiredEnvironment = Object.freeze([
  "FIREEMU_SANDBOX_LEDGER",
  "FIREEMU_OWNER_DECISIONS",
  "FIREEMU_STORAGE_OBJECT_PACKET",
  "FIREEMU_STORAGE_OBJECT_REVIEW",
  "FIREEMU_STORAGE_OBJECT_PRIVATE_DIR",
  "FIREEMU_STORAGE_OBJECT_AUTH_KEY_FILE",
]);

/** The collaborators that touch the machine; a test replaces them. */
export function realDeps() {
  return {
    stdout: (text) => process.stdout.write(text),
    stderr: (text) => process.stderr.write(text),
    nodeVersion: process.version,
    pins: () => computePins({ sourceDir: SOURCE_DIR }),
    git: () => readGitState(SOURCE_DIR),
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

async function readPacket(path) {
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
    maxRequests: 6000,
    reserveUsd: 1,
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
    const ownerDecisionsText = await readFile(env.FIREEMU_OWNER_DECISIONS, "utf8");
    const ledgerPath = env.FIREEMU_SANDBOX_LEDGER;
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
      ledger: createLedgerFile(ledgerPath),
      git: () => deps.git(),
      admission: admissionProblems,
      locks: {
        lockDir: env.FIREEMU_STORAGE_OBJECT_LOCK_DIR ?? join(dirname(ledgerPath), "sandbox-locks"),
        legacyLockPath: `${ledgerPath}.lock`,
        pid: process.pid,
      },
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
    return fail(String(error?.message ?? error));
  }
}
