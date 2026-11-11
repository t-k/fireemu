// Storage Rules observation: the 2026-11-08 sibling audit (family s9: S1-S4, S7-S10) and the
// non-ASCII `lower()`/`upper()` observation (family case). Every command that sends names its family.
//
//   node run.mjs record-production --plan <s9|case> --baseline <absent|projects/.../rulesets/ID> --out <new dir>
//                                                   coordinator only: ADC, project lock, sends
//   node run.mjs record-local --plan <s9|case> [--origin http://127.0.0.1:PORT] --out <new dir> [--rows a,b] [--recordings N]
//                                                   against fireemu or the official Storage emulator
//   node run.mjs readback --run-dir <dir>           the A2 read-back (reads only; the family is the run's own)
//   node run.mjs recover --run-dir <dir>            coordinator only: finish a run that stopped (release back
//                                                   to the baseline, own rulesets and objects deleted)
//   node run.mjs table --plan <s9|case> --run label=dir [--run label=dir ...]
//
// The recorder never writes a ledger row; it prints the run report for the coordinator.

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { appendFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { withProjectLocks } from "../storage-rules/project-locks.mjs";
import { armSending, createLocalDeps, createProductionDeps, fetchNet, isArmed } from "./deps.mjs";
import { installEgressGuard } from "../storage-signed-put/egress.mjs";
import { renderLoads, renderTable } from "./judge.mjs";
import { observe, readback } from "./observe.mjs";
import { CASE_PLAN } from "./plan-case.mjs";
import { BUCKET, PROJECT, RECORDINGS, S9_PLAN, newRunId } from "./plan.mjs";
import { readCase, renderReading } from "./reading.mjs";
import { validateBaseline } from "./guard.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const MODULES = [
  "plan.mjs",
  "plan-case.mjs",
  "reading.mjs",
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

/** The families of the observation; a command names one with `--plan`. */
export const PLANS = Object.freeze({ s9: S9_PLAN, case: CASE_PLAN });

export function planFor(id) {
  if (typeof id !== "string" || !Object.hasOwn(PLANS, id)) throw new Error(`unknown plan ${id}`);
  return PLANS[id];
}

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
    plan: planFor(required("plan", argv)),
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

export function finish(out, report, extra, log = console, plan = S9_PLAN) {
  const full = {
    ...report,
    ...extra,
    estimatedUsd: plan.estimatedUsd,
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
  if (!isArmed()) throw new Error("the owner credential is read only after the launch flag");
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

/**
 * The owner's access token, minted when first asked for and again when it is older than forty
 * minutes (a token lives an hour, and a run with slow settles plus its cleanup can outlast one). A
 * failed re-mint keeps the old token, which may still be valid, and is tried again at the next use.
 */
export function tokenSource({ mint, now = Date.now, maxAgeMs = 40 * 60_000 }) {
  let current = null;
  let mintedAt = 0;
  return {
    get() {
      if (current === null) {
        current = mint();
        mintedAt = now();
      } else if (now() - mintedAt > maxAgeMs) {
        try {
          current = mint();
          mintedAt = now();
        } catch {
          // Keep the token we have; the next use tries again.
        }
      }
      return current;
    },
  };
}

/** What the case family adds to a report: the verdict of its rows against the candidates (no table). */
export function readingOf(plan, report) {
  if (plan.id !== "case") return {};
  const reading = readCase(report.rows ?? [], plan);
  return {
    reading: {
      verdict: reading.verdict,
      complete: reading.complete,
      controls: reading.controls,
      failedControls: reading.failedControls,
      unread: reading.unread,
      disagreeing: reading.disagreeing,
      mismatches: Object.fromEntries(
        Object.entries(reading.perCandidate).map(([name, { mismatches }]) => [name, mismatches]),
      ),
    },
  };
}

/** The production run, with its collaborators passed in so a test can stand in for each. */
export async function recordProductionRun({
  plan = S9_PLAN,
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
  clock = Date.now,
  log = console,
}) {
  for (const name of Object.keys(env)) {
    if (FORBIDDEN_ENV.some((pattern) => pattern.test(name)))
      throw new Error(`refusing to start with ${name} set`);
  }
  armSending(env, plan.id);
  const baseline = validateBaseline(requested, PROJECT);
  const runId = newId();
  const pin = pins(exec);
  requireCleanCheckout(pin);
  const out = newOutDir(outPath);
  const startedAt = new Date().toISOString();
  guardEgress(PRODUCTION_HOSTS);
  const tokens = tokenSource({ mint: () => adcToken(exec), now: clock });
  const accessToken = tokens.get();
  const target = { name: "production", bucket: BUCKET, project: PROJECT };
  out.save("run-header.json", { runId, plan: plan.id, startedAt, baseline, ...pin, target });
  let final;
  await locks(
    {
      projects: [PROJECT],
      taskId: plan.taskId,
      packetId: runId,
      sourceCommit: pin.gitSha,
      pid,
      acquiredAt: startedAt.replace(/\.\d{3}Z$/, "Z"),
      lockDir,
      legacyLockPath: legacyLock,
    },
    async (lease) => {
      const deps = makeDeps({ accessToken, token: tokens.get, lease });
      const { report } = await observer({ plan, target, runId, baseline, deps, out });
      final = finish(out, report, { startedAt, ...pin, ...readingOf(plan, report) }, log, plan);
      if (report.closureReady) lease.confirmClosed();
    },
  );
  return final;
}

/**
 * The names of the rulesets a run created, from its journal: the requests classified as a ruleset
 * create whose answer was a 200 with a name inside the project. A create whose answer is unknown
 * names nothing; the final ruleset list shows it.
 */
export function ownRulesetsOf(journalText, project) {
  const pattern = new RegExp(`^projects/${project}/rulesets/[A-Za-z0-9_-]{1,128}$`);
  const creates = new Set();
  const names = [];
  for (const line of journalText.split("\n")) {
    if (line.trim() === "") continue;
    let entry;
    try {
      entry = JSON.parse(line);
    } catch {
      continue;
    }
    if (entry.phase === "before" && entry.kind === "ruleset-create") creates.add(entry.n);
    if (entry.phase !== "after" || !creates.has(entry.n) || entry.status !== 200) continue;
    try {
      const name = JSON.parse(Buffer.from(entry.bodyBase64, "base64").toString("utf8"))?.name;
      if (typeof name === "string" && pattern.test(name) && !names.includes(name)) names.push(name);
    } catch {
      // An unreadable answer names nothing.
    }
  }
  return names;
}

/**
 * Finishes a run that stopped: puts the release back to the run's baseline (it reads first and
 * writes only toward the baseline), deletes the rulesets and objects the run made, and compares the
 * ruleset list with the one at entry. Coordinator only; it takes the project lock of the original
 * run's family, so a lock the stopped run kept must be released first.
 */
export async function recoverRun({
  dir,
  lockDir = "docs.local/runs/sandbox-locks",
  legacyLock = "docs.local/runs/sandbox-ledger.jsonl.lock",
  env = process.env,
  exec = execFileSync,
  locks = withProjectLocks,
  makeDeps = createProductionDeps,
  observer = observe,
  guardEgress = installEgressGuard,
  pid = process.pid,
  now = () => new Date(),
  clock = Date.now,
  log = console,
}) {
  for (const name of Object.keys(env)) {
    if (FORBIDDEN_ENV.some((pattern) => pattern.test(name)))
      throw new Error(`refusing to start with ${name} set`);
  }
  const header = JSON.parse(readFileSync(join(dir, "run-header.json"), "utf8"));
  const plan = planFor(header.plan ?? "s9");
  armSending(env, plan.id);
  const baseline = validateBaseline(header.baseline, PROJECT);
  let entryRulesets;
  try {
    entryRulesets = JSON.parse(readFileSync(join(dir, "entry.json"), "utf8")).entryRulesets;
  } catch {
    entryRulesets = null;
  }
  if (!Array.isArray(entryRulesets))
    throw new Error("the run has no readable entry.json; its ruleset list at entry is unknown");
  let journal = "";
  try {
    journal = readFileSync(join(dir, "journal.jsonl"), "utf8");
  } catch {
    // A run with no journal made no ruleset we can name.
  }
  const ownRulesets = ownRulesetsOf(journal, PROJECT);
  const pin = pins(exec);
  requireCleanCheckout(pin);
  const started = now();
  const out = newOutDir(join(dir, `recover-${started.toISOString().replace(/[:.]/g, "")}`));
  const startedAt = started.toISOString();
  guardEgress(PRODUCTION_HOSTS);
  const tokens = tokenSource({ mint: () => adcToken(exec), now: clock });
  const accessToken = tokens.get();
  const target = { name: "production", bucket: BUCKET, project: PROJECT };
  out.save("run-header.json", {
    runId: header.runId,
    recoverOf: header.runId,
    plan: plan.id,
    startedAt,
    baseline,
    ownRulesets,
    ...pin,
    target,
  });
  let final;
  await locks(
    {
      projects: [PROJECT],
      taskId: plan.taskId,
      packetId: `${header.runId}-recover`,
      sourceCommit: pin.gitSha,
      pid,
      acquiredAt: startedAt.replace(/\.\d{3}Z$/, "Z"),
      lockDir,
      legacyLockPath: legacyLock,
    },
    async (lease) => {
      const deps = makeDeps({ accessToken, token: tokens.get, lease });
      const { report } = await observer({
        plan,
        target,
        runId: header.runId,
        baseline,
        deps,
        out,
        recover: { entryRulesets, ownRulesets },
      });
      final = finish(out, report, { startedAt, ...pin }, log, plan);
      if (report.closureReady) lease.confirmClosed();
    },
  );
  return final;
}

async function recordProduction() {
  return recordProductionRun(productionOptions(process.argv));
}

async function recordLocal() {
  const plan = planFor(required("plan"));
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
      if (!plan.rows.some((row) => row.id === id)) throw new Error(`unknown row ${id}`);
  const recordings = Number(argValue("recordings") ?? RECORDINGS);
  const target = { name: "local", bucket: plan.localBucket, origin };
  const { report } = await observe({
    plan,
    target,
    runId,
    baseline: "local",
    deps: createLocalDeps(),
    out,
    recordings,
    rowFilter,
  });
  return finish(out, report, { startedAt, ...pin, ...readingOf(plan, report) }, console, plan);
}

/**
 * The A2 read-back of a finished run: the run's own header (its family: a header without one is the
 * first run's, family s9), entry list and report, fresh time-stamped files. A report that cannot be
 * read, or that has no list of unknown labels, is passed on as `null`: the read-back then stays open.
 */
export async function readbackRun({
  dir,
  env = process.env,
  exec = execFileSync,
  guardEgress = installEgressGuard,
  net = fetchNet,
  reader = readback,
  now = () => new Date(),
  log = console,
}) {
  const header = JSON.parse(readFileSync(join(dir, "run-header.json"), "utf8"));
  const entry = JSON.parse(readFileSync(join(dir, "entry.json"), "utf8")).entryRulesets;
  const plan = planFor(header.plan ?? "s9");
  armSending(env, plan.id);
  let unknowns = null;
  try {
    const list = JSON.parse(readFileSync(join(dir, "run-report.json"), "utf8")).unknowns;
    if (Array.isArray(list)) unknowns = list;
  } catch {
    // Missing or broken: the read-back cannot know what the run left open.
  }
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
    plan,
    unknowns,
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

/** The options of a recovery from the command line; the lock paths only when they are named. */
export function recoverOptions(argv) {
  return {
    dir: required("run-dir", argv),
    ...(argValue("lock-dir", argv) ? { lockDir: argValue("lock-dir", argv) } : {}),
    ...(argValue("legacy-lock", argv) ? { legacyLock: argValue("legacy-lock", argv) } : {}),
  };
}

async function recoverCommand() {
  return recoverRun(recoverOptions(process.argv));
}

function tableCommand() {
  const plan = planFor(required("plan"));
  const runs = [];
  process.argv.forEach((arg, index) => {
    if (arg !== "--run") return;
    const [label, dir] = process.argv[index + 1].split("=");
    const results = JSON.parse(readFileSync(join(dir, "results.json"), "utf8"));
    runs.push({ label, rows: results.rows, loads: results.loads });
  });
  if (runs.length === 0) throw new Error("--run label=dir is required");
  if (plan.id === "case") {
    const text = runs
      .map((run) => {
        const recordings = Math.max(1, ...run.rows.map((row) => row.recording));
        return `== ${run.label}\n${renderReading(readCase(run.rows, plan, { recordings }))}`;
      })
      .join("\n\n");
    console.log(text);
    return text;
  }
  const text = `${renderTable(runs)}\n\n${renderLoads(runs)}`;
  console.log(text);
  return text;
}

const commands = {
  "record-production": recordProduction,
  "record-local": recordLocal,
  readback: readbackCommand,
  recover: recoverCommand,
  table: tableCommand,
};
const command = process.argv[2];
if (import.meta.url === `file://${process.argv[1]}`) {
  if (!commands[command]) throw new Error(`usage: run.mjs ${Object.keys(commands).join(" | ")}`);
  await commands[command]();
}
