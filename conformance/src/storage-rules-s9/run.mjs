// Storage Rules observation for the 2026-11-08 sibling audit (S1-S4, S7-S10).
//
//   node run.mjs record-production --baseline <absent|projects/.../rulesets/ID> --out <new dir>
//                                                   coordinator only: ADC, project lock, sends
//   node run.mjs record-local [--origin http://127.0.0.1:PORT] --out <new dir> [--rows a,b] [--recordings N]
//                                                   against fireemu or the official Storage emulator
//   node run.mjs readback --run-dir <dir>           the A2 read-back (reads only)
//   node run.mjs table --run label=dir [--run label=dir ...]
//
// The recorder never writes a ledger row; it prints the run report for the coordinator.

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { appendFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { withProjectLocks } from "../storage-rules/project-locks.mjs";
import { createLocalDeps, createProductionDeps, fetchNet } from "./deps.mjs";
import { installEgressGuard } from "../storage-signed-put/egress.mjs";
import { renderLoads, renderTable } from "./judge.mjs";
import { observe, readback } from "./observe.mjs";
import {
  BUCKET,
  ESTIMATED_USD,
  LOCAL_BUCKET,
  PROJECT,
  RECORDINGS,
  ROWS,
  newRunId,
} from "./plan.mjs";
import { validateBaseline } from "./guard.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const MODULES = [
  "plan.mjs",
  "guard.mjs",
  "judge.mjs",
  "wire.mjs",
  "observe.mjs",
  "deps.mjs",
  "run.mjs",
];
const FORBIDDEN_ENV = [/^GOOGLE_APPLICATION_CREDENTIALS$/, /^FIREBASE_TOKEN$/, /^CLOUDSDK_/];
const PRODUCTION_HOSTS = [
  "storage.googleapis.com",
  "firebasestorage.googleapis.com",
  "firebaserules.googleapis.com",
];

export function argValue(name, argv = process.argv) {
  const index = argv.indexOf(`--${name}`);
  return index === -1 ? undefined : argv[index + 1];
}

function required(name, argv = process.argv) {
  const value = argValue(name, argv);
  if (!value) throw new Error(`--${name} is required`);
  return value;
}

/** The options of a production run from the command line; the lock paths only when they are named. */
export function productionOptions(argv) {
  return {
    baseline: required("baseline", argv),
    outPath: required("out", argv),
    ...(argValue("lock-dir", argv) ? { lockDir: argValue("lock-dir", argv) } : {}),
    ...(argValue("legacy-lock", argv) ? { legacyLock: argValue("legacy-lock", argv) } : {}),
  };
}

export function newOutDir(path) {
  mkdirSync(path, { recursive: false, mode: 0o700 });
  return {
    journal: (entry) =>
      appendFileSync(
        join(path, "journal.jsonl"),
        `${JSON.stringify({ ts: new Date().toISOString(), ...entry })}\n`,
        { mode: 0o600 },
      ),
    save: (name, data) =>
      writeFileSync(join(path, name), `${JSON.stringify(data, null, 2)}\n`, { mode: 0o600 }),
    path,
  };
}

export function gitState(exec = execFileSync) {
  try {
    return {
      gitSha: exec("git", ["-C", HERE, "rev-parse", "HEAD"], { encoding: "utf8" }).trim(),
      // The whole checkout: the lock library and the tests are inputs too.
      dirty: exec("git", ["-C", HERE, "status", "--porcelain"], { encoding: "utf8" }).trim() !== "",
    };
  } catch {
    return { gitSha: null, dirty: null };
  }
}

/** A production run is pinned to a commit of a clean worktree. */
export function requireCleanCheckout(pin) {
  if (pin.gitSha === null) throw new Error("the recorder's git state is unavailable");
  if (pin.dirty)
    throw new Error(
      "the recorder's checkout (the whole worktree) has uncommitted or untracked files",
    );
}

export function pins(exec = execFileSync) {
  const digest = (file) =>
    createHash("sha256")
      .update(readFileSync(join(HERE, file)))
      .digest("hex");
  return {
    ...gitState(exec),
    modules: Object.fromEntries(MODULES.map((file) => [file, digest(file)])),
    node: process.version,
  };
}

export function finish(out, report, extra, log = console) {
  const full = {
    ...report,
    ...extra,
    estimatedUsd: ESTIMATED_USD,
    finishedAt: new Date().toISOString(),
  };
  // The receipt goes to stdout first: a full disk must not lose it.
  log.log(JSON.stringify({ ...full, rows: undefined, loads: undefined }));
  try {
    out.save("run-report.json", full);
  } catch (error) {
    log.error(`run-report.json not saved: ${error.message}`);
  }
  return full;
}

export function adcToken(exec = execFileSync) {
  try {
    return exec("gcloud", ["auth", "application-default", "print-access-token"], {
      encoding: "utf8",
      timeout: 30_000,
      stdio: ["ignore", "pipe", "pipe"],
    }).trim();
  } catch {
    throw new Error("ADC token acquisition failed");
  }
}

/** The production run, with its collaborators passed in so a test can stand in for each. */
export async function recordProductionRun({
  baseline: requested,
  outPath,
  lockDir = "docs.local/runs/sandbox-locks",
  legacyLock = "docs.local/runs/sandbox-ledger.jsonl.lock",
  env = process.env,
  exec = execFileSync,
  locks = withProjectLocks,
  makeDeps = createProductionDeps,
  observer = observe,
  guardEgress = installEgressGuard,
  newId = newRunId,
  pid = process.pid,
  log = console,
}) {
  for (const name of Object.keys(env)) {
    if (FORBIDDEN_ENV.some((pattern) => pattern.test(name)))
      throw new Error(`refusing to start with ${name} set`);
  }
  const baseline = validateBaseline(requested, PROJECT);
  const runId = newId();
  const pin = pins(exec);
  requireCleanCheckout(pin);
  const out = newOutDir(outPath);
  const startedAt = new Date().toISOString();
  guardEgress(PRODUCTION_HOSTS);
  const accessToken = adcToken(exec);
  const target = { name: "production", bucket: BUCKET, project: PROJECT };
  out.save("run-header.json", { runId, startedAt, baseline, ...pin, target });
  let final;
  await locks(
    {
      projects: [PROJECT],
      taskId: "STORAGE-RULES-S9",
      packetId: runId,
      sourceCommit: pin.gitSha,
      pid,
      acquiredAt: startedAt.replace(/\.\d{3}Z$/, "Z"),
      lockDir,
      legacyLockPath: legacyLock,
    },
    async (lease) => {
      const deps = makeDeps({ accessToken, lease });
      const { report } = await observer({ target, runId, baseline, deps, out });
      final = finish(out, report, { startedAt, ...pin }, log);
      if (report.closureReady) lease.confirmClosed();
    },
  );
  return final;
}

async function recordProduction() {
  return recordProductionRun(productionOptions(process.argv));
}

async function recordLocal() {
  const host = process.env.FIREBASE_STORAGE_EMULATOR_HOST;
  const origin = argValue("origin") ?? (host ? `http://${host}` : undefined);
  if (!origin)
    throw new Error("--origin is required (or run under `fireemu exec --only storage -- ...`)");
  const out = newOutDir(required("out"));
  const runId = newRunId();
  const pin = pins();
  const startedAt = new Date().toISOString();
  const rowIds = argValue("rows");
  const rowFilter = rowIds ? new Set(rowIds.split(",")) : null;
  if (rowFilter)
    for (const id of rowFilter)
      if (!ROWS.some((row) => row.id === id)) throw new Error(`unknown row ${id}`);
  const recordings = Number(argValue("recordings") ?? RECORDINGS);
  const target = { name: "local", bucket: LOCAL_BUCKET, origin };
  const { report } = await observe({
    target,
    runId,
    baseline: "local",
    deps: createLocalDeps(),
    out,
    recordings,
    rowFilter,
  });
  return finish(out, report, { startedAt, ...pin });
}

/** The A2 read-back of a finished run: the run's own header and entry list, fresh time-stamped files. */
export async function readbackRun({
  dir,
  exec = execFileSync,
  guardEgress = installEgressGuard,
  net = fetchNet,
  reader = readback,
  now = () => new Date(),
  log = console,
}) {
  const header = JSON.parse(readFileSync(join(dir, "run-header.json"), "utf8"));
  const entry = JSON.parse(readFileSync(join(dir, "entry.json"), "utf8")).entryRulesets;
  guardEgress(PRODUCTION_HOSTS);
  const accessToken = adcToken(exec);
  const stamp = now().toISOString().replace(/[:.]/g, "");
  const out = {
    journal: (entryLine) =>
      appendFileSync(
        join(dir, `readback-journal-${stamp}.jsonl`),
        `${JSON.stringify({ ts: new Date().toISOString(), ...entryLine })}\n`,
        { mode: 0o600 },
      ),
    save: (name, data) =>
      writeFileSync(
        join(dir, `${name.replace(/\.json$/, "")}-${stamp}.json`),
        `${JSON.stringify(data, null, 2)}\n`,
        { mode: 0o600, flag: "wx" },
      ),
  };
  const deps = {
    adminHeaders: () => ({
      authorization: `Bearer ${accessToken}`,
      "x-goog-user-project": PROJECT,
    }),
    net,
  };
  const report = await reader({
    target: { name: "production", bucket: BUCKET, project: PROJECT },
    runId: header.runId,
    baseline: header.baseline,
    entry,
    deps,
    out,
  });
  log.log(JSON.stringify(report));
  return report;
}

async function readbackCommand() {
  return readbackRun({ dir: required("run-dir") });
}

function tableCommand() {
  const runs = [];
  process.argv.forEach((arg, index) => {
    if (arg !== "--run") return;
    const [label, dir] = process.argv[index + 1].split("=");
    const results = JSON.parse(readFileSync(join(dir, "results.json"), "utf8"));
    runs.push({ label, rows: results.rows, loads: results.loads });
  });
  if (runs.length === 0) throw new Error("--run label=dir is required");
  const text = `${renderTable(runs)}\n\n${renderLoads(runs)}`;
  console.log(text);
  return text;
}

const commands = {
  "record-production": recordProduction,
  "record-local": recordLocal,
  readback: readbackCommand,
  table: tableCommand,
};
const command = process.argv[2];
if (import.meta.url === `file://${process.argv[1]}`) {
  if (!commands[command]) throw new Error(`usage: run.mjs ${Object.keys(commands).join(" | ")}`);
  await commands[command]();
}
