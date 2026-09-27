// AUTH-FS-CROSS sandbox runner (stage 1: the unary conditions).
//
//   node src/auth-fs-cross/run.mjs preflight            read-only production checks, plus a
//                                                       compile of the ruleset (created and
//                                                       deleted, never released)
//   node src/auth-fs-cross/run.mjs record-production    record the corpus twice against the
//                                                       sandbox and update
//                                                       auth-fs-cross-production.json
//   node src/auth-fs-cross/run.mjs rebuild-fixture <dir>
//   node src/auth-fs-cross/run.mjs check                run the corpus against fireemu and compare
//   node src/auth-fs-cross/run.mjs local                run the corpus against fireemu only
//   node src/auth-fs-cross/run.mjs export-comparison <out.json>
//
// Copied from conformance/src/fs-rules/run.mjs at commit
// fd6d3aac89443cfc866cec75819cdfef7e95a42b (file SHA-256
// a5985ed27f3b5e3448ab0340cc0cef7d38bf3b7f685ec96b478b183e37e4bf54) and changed only where this
// lane differs: its task, fixture, rulesets, principals and session, no custom-token signer, and
// the other project whose ID token the foreign-project program presents (X9).
//
// Production needs FIREEMU_AUTH_SANDBOX_WEB_CONFIG (the sandbox web app config JSON, kept outside
// the repository), FIREEMU_AUTH_FOREIGN_WEB_CONFIG (the same for fireemu-oracle-query, with its
// restricted key), owner ADC, FIREEMU_SANDBOX_LEDGER and FIREEMU_AUTH_FS_CROSS_PRIVATE_DIR.
// AFC_PROGRAMS selects programs by id prefix.

import { execFile, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { appendFile, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";

import { scanFixture } from "../auth-account/fixture-scan.mjs";
import { CONFORMANCE_DIR } from "../config.mjs";
import { resolveFireemuBinary } from "../evidence.mjs";
import {
  createContext,
  diffRecordings,
  isTransient,
  PRODUCTION,
  RECORDED_PROJECT,
  SANDBOX_PROJECT,
  sameRecording,
} from "../fs-rules/harness.mjs";
import { PRINCIPALS, PROGRAMS, validateCorpus } from "./corpus.mjs";
import { RULESET_IDS, rulesetSource } from "./rulesets.mjs";
import { runCorpus } from "./session.mjs";

const execFileAsync = promisify(execFile);
const FIXTURE = join(CONFORMANCE_DIR, "auth-fs-cross-production.json");
const RUN_DIR = join(CONFORMANCE_DIR, ".runs", "auth-fs-cross");
const TASK_ID = "AUTH-FS-CROSS-SANDBOX";
/** The project whose ID token the foreign-project program presents (X9). */
export const FOREIGN_PROJECT = "fireemu-oracle-query";
/** Its local stand-in: another project of the same fireemu daemon. */
export const LOCAL_FOREIGN_PROJECT = "demo-afc-foreign";
/** The synthetic project number fireemu is configured with. */
const LOCAL_PROJECT_NUMBER = "123456789012";
const LOCAL_FOREIGN_PROJECT_NUMBER = "123456789013";
const HARNESS_CEILING = 1_000;
const sha256 = (text) => createHash("sha256").update(text).digest("hex");

const RULESET_TEXT = RULESET_IDS.map((id) => rulesetSource(id)).join("\n");

/** A program's digest covers its JSON and every ruleset it could run under. */
export const programDigest = (program) => sha256(`${JSON.stringify(program)}\n${RULESET_TEXT}`);

/** Normalization and request semantics a saved row depends on; a change makes it stale. */
export async function harnessDigest() {
  const sources = await Promise.all(
    ["fs-rules/harness.mjs", "auth-fs-cross/session.mjs", "auth-credential/tokens.mjs"].map(
      (file) => readFile(join(CONFORMANCE_DIR, "src", file), "utf8"),
    ),
  );
  return sha256(`${sources.join("\n")}\n${JSON.stringify(PRINCIPALS)}`);
}

export function selectPrograms(programs = PROGRAMS, env = process.env) {
  const prefixes = (env.AFC_PROGRAMS ?? "").split(",").filter(Boolean);
  const selected = prefixes.length
    ? programs.filter((p) => prefixes.some((prefix) => p.id.startsWith(prefix)))
    : programs;
  if (selected.length === 0) throw new Error("no program matches AFC_PROGRAMS");
  return selected;
}

const ceilings = (programs) => ({
  maxRequests: programs.reduce((total, p) => total + p.steps.filter((s) => !s.action).length, 0),
  maxHarnessRequests: HARNESS_CEILING,
});

async function gitSha() {
  const { stdout } = await execFileAsync("git", ["rev-parse", "HEAD"], { cwd: CONFORMANCE_DIR });
  return stdout.trim();
}

async function assertCleanTree() {
  const { stdout } = await execFileAsync(
    "git",
    [
      "status",
      "--porcelain",
      "--",
      "src/auth-fs-cross",
      "src/fs-rules/harness.mjs",
      "src/auth-credential/tokens.mjs",
      "auth-fs-cross-production.json",
    ],
    { cwd: CONFORMANCE_DIR },
  );
  if (stdout.trim()) throw new Error(`record-production needs a clean tree:\n${stdout}`);
}

async function assertIgnored(path) {
  await mkdir(path, { recursive: true, mode: 0o700 });
  try {
    await execFileAsync("git", ["-C", path, "check-ignore", "-q", path]);
  } catch {
    throw new Error(`${path} is not ignored by git; private recordings must not be committable`);
  }
}

async function adminToken() {
  const { stdout } = await execFileAsync("gcloud", [
    "auth",
    "application-default",
    "print-access-token",
  ]);
  return stdout.trim();
}

async function webConfig(variable, project) {
  const configPath = process.env[variable];
  if (!configPath) throw new Error(`${variable} is required`);
  const web = JSON.parse(await readFile(configPath, "utf8"));
  if (web.projectId !== project) throw new Error(`${variable} is not ${project}`);
  if (!/^\d+$/.test(web.projectNumber ?? "") || web.projectNumber !== web.messagingSenderId)
    throw new Error(`${variable} has no consistent project number`);
  return web;
}

const sandboxWebConfig = () => webConfig("FIREEMU_AUTH_SANDBOX_WEB_CONFIG", SANDBOX_PROJECT);
const foreignWebConfig = () => webConfig("FIREEMU_AUTH_FOREIGN_WEB_CONFIG", FOREIGN_PROJECT);

async function productionTarget(web, foreignWeb) {
  let token = await adminToken();
  let fetchedAt = Date.now();
  const target = {
    kind: "production",
    apiKey: web.apiKey,
    adminToken: token,
    quotaProject: SANDBOX_PROJECT,
    projectNumber: web.projectNumber,
    foreign: { project: FOREIGN_PROJECT, apiKey: foreignWeb.apiKey },
    async refresh() {
      if (Date.now() - fetchedAt < 20 * 60_000) return;
      token = await adminToken();
      fetchedAt = Date.now();
      target.adminToken = token;
    },
  };
  return target;
}

async function assertClockSynchronized() {
  const { stdout } = await execFileAsync("sntp", ["-t", "2", "time.google.com"]);
  const offset = Number(/^([+-]\d+\.\d+)/m.exec(stdout)?.[1]);
  if (!Number.isFinite(offset) || Math.abs(offset) > 0.1)
    throw new Error(`clock offset to time.google.com is ${offset} s; synchronize before recording`);
  return offset;
}

/** Owner calls of the preflight; nothing here writes except a ruleset created and deleted. */
async function ownerFetch(target, method, url, body, quotaProject = SANDBOX_PROJECT) {
  const init = {
    method,
    headers: {
      authorization: `Bearer ${target.adminToken}`,
      "x-goog-user-project": quotaProject,
    },
  };
  if (body) {
    init.headers["content-type"] = "application/json";
    init.body = JSON.stringify(body);
  }
  const response = await fetch(url, init);
  return { status: response.status, json: await response.json().catch(() => null) };
}

/**
 * Read-only state of the sandbox plus a compile of every ruleset. Reports whether `(default)`
 * holds documents (the lane owns it and wipes it) and refuses to go on when a database other
 * than `(default)` or a release outside `cloud.firestore` exists, or a ruleset of the corpus
 * does not compile in production.
 */
export async function preflight(target, ledgerText = "", now = Date.now()) {
  const rules = `${PRODUCTION.rules}/v1/projects/${SANDBOX_PROJECT}`;
  const itk = `${PRODUCTION.itk}`;
  const reads = {
    releases: await ownerFetch(target, "GET", `${rules}/releases`),
    rulesets: await ownerFetch(target, "GET", `${rules}/rulesets`),
    databases: await ownerFetch(
      target,
      "GET",
      `${PRODUCTION.firestore}/v1/projects/${SANDBOX_PROJECT}/databases`,
    ),
    documents: await ownerFetch(
      target,
      "POST",
      `${PRODUCTION.firestore}/v1/projects/${SANDBOX_PROJECT}/databases/(default)/documents:runQuery`,
      { structuredQuery: { from: [{ allDescendants: true }], limit: 1 } },
    ),
    accounts: await ownerFetch(
      target,
      "POST",
      `${itk}/v1/projects/${SANDBOX_PROJECT}/accounts:query`,
      {
        returnUserInfo: false,
      },
    ),
    config: await ownerFetch(target, "GET", `${itk}/admin/v2/projects/${SANDBOX_PROJECT}/config`),
    tenants: await ownerFetch(
      target,
      "GET",
      `${itk}/v2/projects/${SANDBOX_PROJECT}/tenants?pageSize=100`,
    ),
    // X9: the foreign project must offer email/password sign-up (read only; billed to it).
    foreignConfig: await ownerFetch(
      target,
      "GET",
      `${itk}/admin/v2/projects/${FOREIGN_PROJECT}/config`,
      undefined,
      FOREIGN_PROJECT,
    ),
  };
  // Without multi-tenancy, listing tenants answers 400 INVALID_PROJECT_ID: there are none.
  const tenantsOff =
    reads.config.json?.multiTenant?.allowTenants !== true &&
    reads.tenants.status === 400 &&
    reads.tenants.json?.error?.message === "INVALID_PROJECT_ID";
  if (tenantsOff) reads.tenants = { status: 200, json: { tenants: [] } };
  const report = {
    failedReads: Object.entries(reads)
      .filter(([, { status }]) => status !== 200)
      .map(([name, { status }]) => `${name} (HTTP ${status})`),
    projectAccounts: Number(reads.accounts.json?.recordsCount ?? -1),
    foreignPasswordSignUp: reads.foreignConfig.json?.signIn?.email?.enabled === true,
    allowTenants: reads.config.json?.multiTenant?.allowTenants === true,
    tenants: (reads.tenants.json?.tenants ?? []).length,
    rulesets: (reads.rulesets.json?.rulesets ?? []).length,
    otherLanesRecently: otherLanesRecently(ledgerText, now),
    openRuns: openRuns(ledgerText, now),
    releases: (reads.releases.json?.releases ?? []).map(({ name }) => name.split("/releases/")[1]),
    databases: (reads.databases.json?.databases ?? []).map(({ name }) => name.split("/").at(-1)),
    defaultHasDocuments: (reads.documents.json ?? []).some((e) => e.document),
    compiled: {},
  };
  for (const id of RULESET_IDS) {
    const created = await ownerFetch(target, "POST", `${rules}/rulesets`, {
      source: { files: [{ name: "firestore.rules", content: rulesetSource(id) }] },
    });
    report.compiled[id] = created.status;
    if (created.status === 200) {
      const deleted = await ownerFetch(
        target,
        "DELETE",
        `${PRODUCTION.rules}/v1/${created.json.name}`,
      );
      if (deleted.status !== 200) report.failedReads.push(`delete of the ${id} compile probe`);
    }
  }
  return { report, problems: preflightProblems(report) };
}

/**
 * Why a recording may not start. The sandbox must be as the lanes leave it: no release, no
 * ruleset, no named database, no tenant and multi-tenancy off, no project-level account (the
 * AUTH lanes leave none when idle), no other lane active, the foreign project offering
 * email/password sign-up, the ruleset compiling, and every read answered.
 */
export function preflightProblems(report) {
  const foreign = report.databases.filter((db) => db !== "(default)");
  return [
    ...report.failedReads.map((read) => `preflight read failed: ${read}`),
    ...(foreign.length ? [`databases other than (default) exist: ${foreign.join(", ")}`] : []),
    ...(report.releases.length ? [`release(s) exist: ${report.releases.join(", ")}`] : []),
    ...(report.rulesets ? [`${report.rulesets} ruleset(s) exist`] : []),
    ...(report.allowTenants ? ["multiTenant.allowTenants is on"] : []),
    ...(report.tenants ? [`${report.tenants} tenant(s) exist`] : []),
    ...(report.projectAccounts !== 0
      ? [`${report.projectAccounts} project-level account(s) exist`]
      : []),
    ...(report.otherLanesRecently.length
      ? [`other lanes used the sandbox within 30 minutes: ${report.otherLanesRecently.join(", ")}`]
      : []),
    ...(report.openRuns.length ? [`runs still open: ${report.openRuns.join(", ")}`] : []),
    ...(report.foreignPasswordSignUp
      ? []
      : [`${FOREIGN_PROJECT} does not offer email/password sign-up`]),
    ...Object.entries(report.compiled)
      .filter(([, status]) => status !== 200)
      .map(([id, status]) => `ruleset ${id} does not compile (HTTP ${status})`),
  ];
}

/**
 * The AUTH lanes do not all write `started` lines, so the operator confirms that none is
 * recording on the sandbox: AFC_NO_AUTH_RECORDING=<ISO time of the check>, at most an hour
 * old. The value goes into the run's meta and its ledger `started` line.
 */
export function confirmedNoAuthRecording(env = process.env, now = Date.now()) {
  const at = Date.parse(env.AFC_NO_AUTH_RECORDING ?? "");
  if (!Number.isFinite(at) || now - at > 3_600_000 || at - now > 60_000) {
    throw new Error(
      "AFC_NO_AUTH_RECORDING must be the ISO time (within the last hour) at which the operator confirmed that no AUTH lane is recording on the sandbox",
    );
  }
  return new Date(at).toISOString();
}

/** Set by SIGINT or SIGTERM: the session stops before its next step and cleans up. */
let stopRequested = false;

async function recordOnce(programs, web, foreignWeb, signers) {
  const target = await productionTarget(web, foreignWeb);
  const ctx = createContext({ run: String(Date.now()), target });
  return runCorpus({ programs, principals: PRINCIPALS }, ctx, {
    ...ceilings(programs),
    signers,
    log: (line) => console.log(line),
    shouldStop: () => stopRequested,
  });
}

async function writeFixture({ programs, recordings, meta, secrets }) {
  const [first, second] = recordings;
  const fixture = existsSync(FIXTURE)
    ? JSON.parse(await readFile(FIXTURE, "utf8"))
    : { version: 1, recordedAgainst: {}, programs: {} };
  fixture.recordedAgainst = {
    target:
      "production Firestore REST v1 and gRPC, Identity Platform sandbox, end-user ID tokens, and one ID token of another Firebase project",
    project: RECORDED_PROJECT,
    note: "Two recordings per program. Principal uids, tenants, the run id, the project, its number, the other project and run-window times are placeholders. `second` holds the other recording of rows that differed.",
  };
  for (const program of programs) {
    const one = first.results[program.id];
    const two = second.results[program.id];
    if (!one || !two) continue;
    const differing = Object.fromEntries(
      Object.entries(two.steps).filter(([id, rec]) => !sameRecording(rec, one.steps[id])),
    );
    fixture.programs[program.id] = {
      corpusDigest: programDigest(program),
      harnessDigest: meta.harness,
      recordedAt: meta.startedAt,
      gitSha: meta.sha,
      steps: one.steps,
      ...(Object.keys(differing).length ? { second: differing } : {}),
    };
  }
  fixture.programs = Object.fromEntries(
    Object.entries(fixture.programs).toSorted(([a], [b]) => a.localeCompare(b)),
  );
  const text = `${JSON.stringify(fixture, null, 2)}\n`;
  scanFixture(text, secrets);
  await writeFile(FIXTURE, text);
  return diffRecordings(first.results, second.results);
}

/** Tasks other than this one with a ledger line for the sandbox in the last 30 minutes. */
export function otherLanesRecently(ledgerText, now = Date.now()) {
  const tasks = new Set();
  for (const line of ledgerText.split("\n")) {
    let entry;
    try {
      entry = JSON.parse(line);
    } catch {
      continue;
    }
    if (entry?.project !== SANDBOX_PROJECT || entry.taskId === TASK_ID) continue;
    if (now - Date.parse(entry.ts) < 30 * 60_000) tasks.add(entry.taskId ?? "unknown");
  }
  return [...tasks];
}

/**
 * Other tasks with a `started` line for the sandbox in the last 6 hours and no later line of
 * the same task: a run of theirs may still be going.
 */
export function openRuns(ledgerText, now = Date.now()) {
  const open = new Map();
  for (const line of ledgerText.split("\n")) {
    let entry;
    try {
      entry = JSON.parse(line);
    } catch {
      continue;
    }
    if (entry?.project !== SANDBOX_PROJECT || entry.taskId === TASK_ID || !entry.taskId) continue;
    if (entry.event === "started") open.set(entry.taskId, Date.parse(entry.ts));
    else open.delete(entry.taskId);
  }
  return [...open].filter(([, started]) => now - started < 6 * 3_600_000).map(([task]) => task);
}

/** Refuses a run within an hour of this task's last aborted run (per-IP account limits). */
export function recentAbort(ledgerText, now = Date.now()) {
  const entries = ledgerText
    .split("\n")
    .filter((line) => line.trim())
    .map((line) => {
      try {
        return JSON.parse(line);
      } catch {
        return undefined;
      }
    })
    .filter((entry) => entry?.taskId === TASK_ID && entry.outcome);
  const last = entries.at(-1);
  if (!last || !String(last.outcome).startsWith("aborted")) return undefined;
  return now - Date.parse(last.ts) < 3_600_000 ? last : undefined;
}

async function recordProduction() {
  const ledger = process.env.FIREEMU_SANDBOX_LEDGER;
  const privateRoot = process.env.FIREEMU_AUTH_FS_CROSS_PRIVATE_DIR;
  if (!ledger || !privateRoot)
    throw new Error("FIREEMU_SANDBOX_LEDGER and FIREEMU_AUTH_FS_CROSS_PRIVATE_DIR are required");
  await assertCleanTree();
  const aborted = existsSync(ledger) ? recentAbort(await readFile(ledger, "utf8")) : undefined;
  if (aborted)
    throw new Error(`the last run aborted at ${aborted.ts}; wait an hour before retrying`);
  const programs = selectPrograms();
  const corpusRequests = validateCorpus(programs);
  const operatorConfirmation = confirmedNoAuthRecording();
  const web = await sandboxWebConfig();
  const foreignWeb = await foreignWebConfig();
  const target = await productionTarget(web, foreignWeb);
  const { report, problems } = await preflight(
    target,
    await readFile(ledger, "utf8").catch(() => ""),
  );
  if (problems.length) throw new Error(`preflight: ${problems.join("; ")}`);
  const meta = {
    sha: await gitSha(),
    harness: await harnessDigest(),
    startedAt: new Date().toISOString(),
    programs: programs.map((p) => p.id),
    corpusDigests: Object.fromEntries(programs.map((p) => [p.id, programDigest(p)])),
    preflight: report,
    operatorConfirmation,
    clockOffsetSeconds: await assertClockSynchronized(),
  };
  await assertIgnored(privateRoot);
  const runDir = join(
    privateRoot,
    `auth-fs-cross-production-${meta.startedAt.replaceAll(":", "")}`,
  );
  await mkdir(runDir, { recursive: true, mode: 0o700 });
  await appendFile(
    ledger,
    `${JSON.stringify({ ts: meta.startedAt, event: "started", taskId: TASK_ID, project: SANDBOX_PROJECT, stage: 1, gitSha: meta.sha, programs: programs.length, operatorConfirmation })}\n`,
  );
  const signers = {};
  for (const signal of ["SIGINT", "SIGTERM"]) {
    process.on(signal, () => {
      if (stopRequested) {
        console.error(
          `${signal} again: cleanup is running and is not interrupted. A kill -9 now leaves releases, rulesets, accounts, the tenants and multiTenant.allowTenants for hand cleanup (see the private run directory).`,
        );
        return;
      }
      stopRequested = true;
      console.error(`${signal}: stopping at the next step or wait; cleanup follows`);
    });
  }
  const recordings = [];
  let outcome = "recorded";
  let error;
  try {
    for (const n of [1, 2]) {
      if (stopRequested) throw Object.assign(new Error("stopped by a signal"), { fatal: true });
      const recording = await recordOnce(programs, web, foreignWeb, signers);
      recordings.push(recording);
      await writeFile(join(runDir, `recording-${n}.json`), JSON.stringify(recording), {
        mode: 0o600,
      });
    }
  } catch (caught) {
    outcome = caught.fatal ? "aborted-fatal" : "aborted";
    error = String(caught.message ?? caught);
    if (caught.partial) {
      recordings.push(caught.partial);
      await writeFile(
        join(runDir, `recording-${recordings.length}-partial.json`),
        JSON.stringify(caught.partial),
        {
          mode: 0o600,
        },
      );
    }
  }
  await writeFile(join(runDir, "meta.json"), JSON.stringify({ ...meta, outcome, error }, null, 2), {
    mode: 0o600,
  });
  const requests = recordings.reduce((n, r) => n + r.requests + r.harnessRequests, 0);
  const failures = recordings.flatMap((r) => r.failures ?? []);
  // Something the run could not remove or restore is the first thing anyone must see.
  const cleanupErrors = recordings.flatMap((r) => r.cleanupErrors ?? []);
  if (cleanupErrors.length) {
    outcome = "aborted-cleanup-incomplete";
    console.error(`CLEANUP INCOMPLETE on ${SANDBOX_PROJECT}:\n  ${cleanupErrors.join("\n  ")}`);
  }
  try {
    if (!error) {
      const nondeterministic = await writeFixture({
        programs,
        recordings,
        meta,
        secrets: [
          web.apiKey,
          SANDBOX_PROJECT,
          web.projectNumber,
          foreignWeb.apiKey,
          FOREIGN_PROJECT,
          foreignWeb.projectNumber,
        ],
      });
      if (failures.length) outcome = "recorded-with-program-failures";
      console.log(
        JSON.stringify(
          { programs: programs.length, corpusRequests, requests, nondeterministic, failures },
          null,
          2,
        ),
      );
    }
  } catch (caught) {
    outcome = "not-written";
    error = `${String(caught.message ?? caught)} (recordings kept in ${runDir})`;
  } finally {
    await appendFile(
      ledger,
      `${JSON.stringify({
        ts: new Date().toISOString(),
        project: SANDBOX_PROJECT,
        database: "(default)",
        stage: 1,
        gitSha: meta.sha,
        corpusDigest: sha256(JSON.stringify(programs)),
        requests,
        // Firestore reads, writes and Rules evaluations at list price; Auth MAU for about 12 accounts.
        estimatedUsd: Number((requests * 0.0000006 + 0.1).toFixed(4)),
        outcome,
        taskId: TASK_ID,
        programs: meta.programs,
        configurationChanges: recordings.flatMap((r) => r.changes ?? []),
        ...(cleanupErrors.length ? { cleanupErrors } : {}),
        publications: recordings.flatMap((r) => r.publications ?? []).length,
        ...(error ? { error } : {}),
      })}\n`,
    );
  }
  if (error) throw new Error(error);
  if (failures.length) process.exitCode = 1;
}

async function rebuildFixture(runDir) {
  const meta = JSON.parse(await readFile(join(runDir, "meta.json"), "utf8"));
  if (meta.harness !== (await harnessDigest()))
    throw new Error("harness changed since the recording");
  const recordings = await Promise.all(
    [1, 2].map(async (n) =>
      JSON.parse(await readFile(join(runDir, `recording-${n}.json`), "utf8")),
    ),
  );
  const programs = PROGRAMS.filter((p) => meta.programs.includes(p.id));
  const changed = programs.filter((p) => meta.corpusDigests?.[p.id] !== programDigest(p));
  if (changed.length || programs.length !== meta.programs.length)
    throw new Error(`corpus changed since the recording: ${changed.map((p) => p.id).join(", ")}`);
  const web = await sandboxWebConfig();
  const foreignWeb = await foreignWebConfig();
  const nondeterministic = await writeFixture({
    programs,
    recordings,
    meta,
    secrets: [
      web.apiKey,
      SANDBOX_PROJECT,
      web.projectNumber,
      foreignWeb.apiKey,
      FOREIGN_PROJECT,
      foreignWeb.projectNumber,
    ],
  });
  console.log(JSON.stringify({ programs: programs.length, nondeterministic }, null, 2));
}

async function sessionLocal() {
  const programs = JSON.parse(await readFile(process.env.AFC_IN, "utf8"));
  const firestore = new URL(`http://${process.env.FIRESTORE_EMULATOR_HOST}`);
  const auth = new URL(`http://${process.env.FIREBASE_AUTH_EMULATOR_HOST}`);
  const ctx = createContext({
    run: process.env.AFC_RUN,
    target: {
      kind: "local",
      firestoreOrigin: firestore.origin,
      authOrigin: auth.origin,
      grpcHost: firestore.hostname,
      grpcPort: Number(firestore.port),
      projectNumber: LOCAL_PROJECT_NUMBER,
      foreign: localForeign(),
      control: {
        url: String(process.env.FIREEMU_CONTROL_URL).replace(/\/v1\/?$/, ""),
        token: process.env.FIREEMU_CONTROL_TOKEN,
      },
    },
  });
  const out = await runCorpus({ programs, principals: PRINCIPALS }, ctx, {
    ...ceilings(programs),
    log: process.env.AFC_VERBOSE ? (line) => console.error(line) : undefined,
  });
  await writeFile(process.env.AFC_OUT, JSON.stringify(out));
}

/** The local stand-in of the foreign project: see LOCAL_FOREIGN_PROJECT. */
function localForeign() {
  return { project: LOCAL_FOREIGN_PROJECT, apiKey: "fake-foreign-api-key" };
}

export async function runLocal(programs, { profile = "strict" } = {}) {
  await rm(RUN_DIR, { recursive: true, force: true });
  await mkdir(RUN_DIR, { recursive: true, mode: 0o700 });
  const run = String(Date.now());
  const paths = {
    in: join(RUN_DIR, "programs.json"),
    out: join(RUN_DIR, "fireemu.json"),
    config: join(RUN_DIR, "fireemu.config.json"),
    firebase: join(RUN_DIR, "firebase.json"),
  };
  await writeFile(paths.firebase, JSON.stringify({ firestore: [{ database: "(default)" }] }));
  await writeFile(paths.config, JSON.stringify(localConfig(profile)));
  await writeFile(paths.in, JSON.stringify(programs));
  const binary = resolveFireemuBinary();
  const ports = [
    "--http-port",
    "0",
    "--firestore-port",
    "0",
    "--storage-port",
    "0",
    "--ui-port",
    "0",
    "--hub-port",
    "0",
    "--logging-port",
    "0",
  ];
  const child = spawn(
    binary,
    [
      "exec",
      "--config",
      paths.config,
      "--firebase-json",
      paths.firebase,
      "--project",
      SANDBOX_PROJECT,
      "--only",
      "auth,firestore",
      ...ports,
      "--",
      process.execPath,
      join(CONFORMANCE_DIR, "src/auth-fs-cross/run.mjs"),
      "session-local",
    ],
    {
      cwd: RUN_DIR,
      stdio: ["ignore", "inherit", "inherit"],
      env: { ...process.env, AFC_IN: paths.in, AFC_OUT: paths.out, AFC_RUN: run },
    },
  );
  const code = await new Promise((resolve) => child.once("exit", resolve));
  if (code !== 0) throw new Error(`fireemu session exited ${code}`);
  return { binary, ...JSON.parse(await readFile(paths.out, "utf8")) };
}

/** fireemu's configuration for a local run (see localForeign for the other project). */
export function localConfig(profile) {
  return {
    schemaVersion: 1,
    profile,
    daemon: {
      authProjectNumbers: {
        [SANDBOX_PROJECT]: LOCAL_PROJECT_NUMBER,
        [LOCAL_FOREIGN_PROJECT]: LOCAL_FOREIGN_PROJECT_NUMBER,
      },
    },
    auth: { idTokenSigning: "session-rsa", apiKeys: ["fake-api-key"] },
  };
}

/**
 * Rows whose two production recordings may differ, with the reason. A differing row outside
 * this list is INDETERMINATE: it may be a propagation artefact, not behavior.
 */
export const NONDETERMINISTIC_ROWS = {};

export function classify({ row, stale, production, alternative, fireemu }) {
  if (stale) return "STALE_FIXTURE";
  if (production === undefined) return "MISSING_FIXTURE";
  if (fireemu === undefined) return "MISSING";
  if ([production, alternative, fireemu].some(isTransient)) return "INDETERMINATE";
  if (alternative && !Object.hasOwn(NONDETERMINISTIC_ROWS, row)) return "INDETERMINATE";
  // A step whose dependency was refused on both sides never ran: it confirms that refusal only,
  // and only when both sides name the same unresolved dependency (step and path).
  if (production.unresolved !== undefined || fireemu.unresolved !== undefined) {
    const same = production.unresolved === fireemu.unresolved;
    return same && !alternative ? "DEPENDENCY_REFUSED" : "MISMATCH";
  }
  if (sameRecording(production, fireemu)) return alternative ? "MATCH_NONDETERMINISTIC" : "MATCH";
  if (alternative && sameRecording(alternative, fireemu)) return "MATCH_NONDETERMINISTIC";
  return "MISMATCH";
}

async function check() {
  const fixture = existsSync(FIXTURE)
    ? JSON.parse(await readFile(FIXTURE, "utf8"))
    : { programs: {} };
  const selected = selectPrograms();
  validateCorpus(selected);
  const harness = await harnessDigest();
  const local = await runLocal(selected);
  const rows = [];
  for (const program of selected) {
    const saved = fixture.programs[program.id];
    const stale =
      saved !== undefined &&
      (saved.corpusDigest !== programDigest(program) || saved.harnessDigest !== harness);
    for (const step of program.steps.filter((s) => !s.action)) {
      const production = saved?.steps?.[step.id];
      const alternative = saved?.second?.[step.id];
      const fireemu = local.results[program.id]?.steps?.[step.id];
      const row = `${program.id}#${step.id}`;
      rows.push({
        row,
        status: classify({ row, stale, production, alternative, fireemu }),
        production,
        ...(alternative ? { alternative } : {}),
        fireemu,
      });
    }
  }
  const known = new Set(PROGRAMS.map((p) => p.id));
  const orphans = Object.keys(fixture.programs).filter((id) => !known.has(id));
  const summary = {};
  for (const { status } of rows) summary[status] = (summary[status] ?? 0) + 1;
  const artifactSha256 = sha256(await readFile(local.binary));
  await writeFile(
    join(RUN_DIR, "comparison.json"),
    `${JSON.stringify({ artifact: local.binary, artifactSha256, summary, orphans, failures: local.failures, rows }, null, 2)}\n`,
  );
  const passing = new Set(["MATCH", "MATCH_NONDETERMINISTIC", "DEPENDENCY_REFUSED"]);
  for (const row of rows.filter((r) => !passing.has(r.status))) {
    console.log(`\n${row.status} ${row.row}`);
    console.log(`  production ${String(JSON.stringify(row.production)).slice(0, 400)}`);
    console.log(`  fireemu    ${String(JSON.stringify(row.fireemu)).slice(0, 400)}`);
  }
  console.log(JSON.stringify({ summary, orphans, failures: local.failures }, null, 2));
  if (!rows.every((r) => passing.has(r.status)) || orphans.length || local.failures.length)
    process.exitCode = 1;
}

async function exportComparison(out) {
  if (!out) throw new Error("usage: export-comparison <output.json>");
  const comparison = JSON.parse(await readFile(join(RUN_DIR, "comparison.json"), "utf8"));
  const fixtureSha256 = sha256(await readFile(FIXTURE, "utf8"));
  const evidence = {
    kind: "auth-fs-cross-comparison-v1",
    artifactSha256: comparison.artifactSha256,
    fixtureSha256,
    summary: comparison.summary,
    rows: comparison.rows.map(({ row, status }) => ({ row, status })),
  };
  await writeFile(out, `${JSON.stringify(evidence, null, 2)}\n`);
  console.log(JSON.stringify({ out, summary: evidence.summary, fixtureSha256 }, null, 2));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const mode = process.argv[2];
  if (mode === "preflight") {
    const target = await productionTarget(await sandboxWebConfig(), await foreignWebConfig());
    console.log(JSON.stringify(await preflight(target), null, 2));
  } else if (mode === "record-production") await recordProduction();
  else if (mode === "rebuild-fixture") await rebuildFixture(process.argv[3]);
  else if (mode === "check") await check();
  else if (mode === "export-comparison") await exportComparison(process.argv[3]);
  else if (mode === "session-local") await sessionLocal();
  else if (mode === "local") {
    const local = await runLocal(selectPrograms(), {
      profile: process.env.AFC_PROFILE ?? "strict",
    });
    await writeFile(join(RUN_DIR, "fireemu-results.json"), `${JSON.stringify(local, null, 2)}\n`);
    console.log(
      JSON.stringify(
        { requests: local.requests, failures: local.failures, cleanupErrors: local.cleanupErrors },
        null,
        2,
      ),
    );
  } else {
    console.error(
      "usage: run.mjs preflight|record-production|rebuild-fixture|check|export-comparison|local",
    );
    process.exitCode = 2;
  }
}
