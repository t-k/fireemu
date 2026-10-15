// FS-3 (rules v1 and collection-group queries) sandbox runner.
//
//   node src/fs-rules-v1/run.mjs preflight          read-only production checks
//   node src/fs-rules-v1/run.mjs record-production  record the corpus twice against the sandbox
//                                                   and write fs-rules-v1-observation.json
//   node src/fs-rules-v1/run.mjs check              the corpus against fireemu (strict, or
//                                                   FS3_PROFILE=emulator) and the saved rows
//   node src/fs-rules-v1/run.mjs local              the corpus against fireemu only
//   node src/fs-rules-v1/run.mjs official           the corpus against the pinned official
//                                                   Firestore emulator (firebase-tools 15.28.2)
//   node src/fs-rules-v1/run.mjs export-comparison <out.json>
//
// FS3_CORPUS picks the corpus: `v1` (FS-3, the default) or `bad-path` (FS-8, Rules get()/exists()
// on a path that is not a document of this database). One run never mixes the two.
//
// Production needs FIREEMU_AUTH_SANDBOX_WEB_CONFIG (the sandbox web app config JSON, kept outside
// the repository), owner ADC, FIREEMU_SANDBOX_LEDGER, FIREEMU_FS3_PRIVATE_DIR and
// FS3_NO_AUTH_RECORDING (the ISO time at which the operator confirmed that no AUTH lane is
// recording on the sandbox). It only ever addresses `fireemu-oracle-idp`, `(default)`.
//
// This file is the orchestration (processes, files, the real effects); the decisions are in
// judge.mjs, the production sequence in record.mjs, the requests in session.mjs.

import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { appendFile, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";

import { scanFixture } from "../auth-account/fixture-scan.mjs";
import { CONFORMANCE_DIR } from "../config.mjs";
import { resolveFireemuBinary } from "../evidence.mjs";
import { createContext, SANDBOX_PROJECT } from "../fs-rules/harness.mjs";
import { BAD_PATH_PROGRAMS, PRINCIPALS, PROGRAMS, validateCorpus } from "./corpus.mjs";
import { createGrpcAdapter } from "./grpc.mjs";
import {
  brief,
  ceilings,
  compareRows,
  fireemuConfig,
  harnessDigest,
  LOCAL_PROJECT_NUMBER,
  mockToken,
  OFFICIAL_PROJECT,
  PASSING,
  selectPrograms,
  sha256,
  taskIdFor,
} from "./judge.mjs";
import { preflight } from "./preflight.mjs";
import { recordProduction } from "./record.mjs";
import { runCorpus } from "./session.mjs";
import { runSupervised } from "./supervise.mjs";

const execFileAsync = promisify(execFile);
export const FIXTURE = join(CONFORMANCE_DIR, "fs-rules-v1-observation.json");
const RUN_DIR = join(CONFORMANCE_DIR, ".runs", "fs-rules-v1");
const SESSION_SCRIPT = join(CONFORMANCE_DIR, "src/fs-rules-v1/run.mjs");

// ---- production -----------------------------------------------------------------------------

async function adminToken() {
  const { stdout } = await execFileAsync("gcloud", [
    "auth",
    "application-default",
    "print-access-token",
  ]);
  return stdout.trim();
}

async function sandboxWebConfig() {
  const configPath = process.env.FIREEMU_AUTH_SANDBOX_WEB_CONFIG;
  if (!configPath) throw new Error("FIREEMU_AUTH_SANDBOX_WEB_CONFIG is required");
  const web = JSON.parse(await readFile(configPath, "utf8"));
  if (web.projectId !== SANDBOX_PROJECT) throw new Error("web config is not the sandbox project");
  if (!/^\d+$/.test(web.projectNumber ?? "") || web.projectNumber !== web.messagingSenderId)
    throw new Error("web config has no consistent project number");
  return web;
}

async function productionTarget(web) {
  let token = await adminToken();
  let fetchedAt = Date.now();
  const target = {
    kind: "production",
    apiKey: web.apiKey,
    adminToken: token,
    quotaProject: SANDBOX_PROJECT,
    projectNumber: web.projectNumber,
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

/**
 * Refuses a recording from a worktree with any change, tracked or not: the recorder depends on
 * more files than its own (the shared harness, the Listen helper, the fixture scan, the config),
 * and a change in any of them is a change in what the rows mean.
 */
export async function assertCleanTree(cwd = CONFORMANCE_DIR) {
  const { stdout } = await execFileAsync("git", ["status", "--porcelain"], { cwd });
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

const realGrpc = (ctx) => ({ grpc: createGrpcAdapter(ctx) });

/** The real effects of a production recording. */
export function productionDeps() {
  return {
    now: () => Date.now(),
    readLedger: async (path) => (existsSync(path) ? readFile(path, "utf8") : ""),
    appendLedger: (path, text) => appendFile(path, text),
    assertCleanTree,
    gitSha: async () =>
      (await execFileAsync("git", ["rev-parse", "HEAD"], { cwd: CONFORMANCE_DIR })).stdout.trim(),
    harnessDigest,
    assertIgnored,
    makeRunDir: (dir) => mkdir(dir, { recursive: true, mode: 0o700 }),
    writeRunFile: (dir, name, text) => writeFile(join(dir, name), text, { mode: 0o600 }),
    clockOffset: assertClockSynchronized,
    sandboxWebConfig,
    productionTarget,
    preflight: (target, ledgerText, taskId) => preflight(target, ledgerText, { taskId }),
    async recordOnce(programs, web, { shouldStop }) {
      const target = await productionTarget(web);
      const ctx = createContext({ run: String(Date.now()), target });
      return runCorpus({ programs, principals: PRINCIPALS }, ctx, realGrpc(ctx), {
        ...ceilings(programs),
        log: (line) => console.log(line),
        shouldStop,
      });
    },
    readFixture: async () => (existsSync(FIXTURE) ? readFile(FIXTURE, "utf8") : undefined),
    writeFixture: (text) => writeFile(FIXTURE, text),
    scanFixture,
    installSignals(handler) {
      for (const signal of RECORDING_SIGNALS) process.on(signal, () => handler(signal));
    },
    log: (text) => console.log(text),
    warn: (text) => console.error(text),
  };
}

// ---- the local side -------------------------------------------------------------------------

function localContext(target, project = SANDBOX_PROJECT) {
  return { ...createContext({ run: process.env.FS3_RUN ?? String(Date.now()), target }), project };
}

/** Inside `fireemu exec`: runs the programs against the ports it set in the environment. */
async function sessionLocal() {
  const programs = JSON.parse(await readFile(process.env.FS3_IN, "utf8"));
  const firestore = new URL(`http://${process.env.FIRESTORE_EMULATOR_HOST}`);
  const ctx = localContext({
    kind: "local",
    firestoreOrigin: firestore.origin,
    authOrigin: new URL(`http://${process.env.FIREBASE_AUTH_EMULATOR_HOST}`).origin,
    grpcHost: firestore.hostname,
    grpcPort: Number(firestore.port),
    projectNumber: LOCAL_PROJECT_NUMBER,
  });
  const value = await runCorpus({ programs, principals: PRINCIPALS }, ctx, realGrpc(ctx), {
    ...ceilings(programs),
    log: process.env.FS3_VERBOSE ? (line) => console.error(line) : undefined,
  });
  await writeFile(process.env.FS3_OUT, JSON.stringify(value));
}

/** Inside `firebase emulators:exec`: runs the programs against the official Firestore emulator. */
async function sessionOfficial() {
  const programs = JSON.parse(await readFile(process.env.FS3_IN, "utf8"));
  const firestore = new URL(`http://${process.env.FIRESTORE_EMULATOR_HOST}`);
  const ctx = localContext(
    {
      kind: "local",
      firestoreOrigin: firestore.origin,
      authOrigin: "http://127.0.0.1:1",
      grpcHost: firestore.hostname,
      grpcPort: Number(firestore.port),
      mockToken: (uid) => mockToken(uid),
    },
    OFFICIAL_PROJECT,
  );
  const value = await runCorpus({ programs, principals: PRINCIPALS }, ctx, realGrpc(ctx), {
    ...ceilings(programs),
    log: process.env.FS3_VERBOSE ? (line) => console.error(line) : undefined,
  });
  await writeFile(process.env.FS3_OUT, JSON.stringify(value));
}

async function prepareRunDir(programs) {
  await rm(RUN_DIR, { recursive: true, force: true });
  await mkdir(RUN_DIR, { recursive: true, mode: 0o700 });
  const paths = {
    in: join(RUN_DIR, "programs.json"),
    out: join(RUN_DIR, "result.json"),
    config: join(RUN_DIR, "fireemu.config.json"),
    firebase: join(RUN_DIR, "firebase.json"),
  };
  await writeFile(paths.in, JSON.stringify(programs));
  return paths;
}

/** What stops a recording at its next step, with cleanup: an interrupt, a terminate, a closed terminal. */
export const RECORDING_SIGNALS = ["SIGINT", "SIGTERM", "SIGHUP"];

const SESSION_TIMEOUT_MS = 30 * 60_000;

export async function runLocal(
  programs,
  { profile = "strict", binary = resolveFireemuBinary() } = {},
) {
  const paths = await prepareRunDir(programs);
  await writeFile(paths.firebase, JSON.stringify({ firestore: [{ database: "(default)" }] }));
  await writeFile(paths.config, JSON.stringify(fireemuConfig(profile)));
  const ports = ["http", "firestore", "storage", "ui", "hub", "logging"].flatMap((name) => [
    `--${name}-port`,
    "0",
  ]);
  const { exitCode, timedOut } = await runSupervised({
    command: binary,
    args: [
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
      SESSION_SCRIPT,
      "session-local",
    ],
    cwd: RUN_DIR,
    env: { ...process.env, FS3_IN: paths.in, FS3_OUT: paths.out, FS3_RUN: String(Date.now()) },
    timeoutMs: SESSION_TIMEOUT_MS,
  });
  if (timedOut || exitCode !== 0)
    throw new Error(`fireemu session ended ${timedOut ? "on its timeout" : exitCode}`);
  return { binary, ...JSON.parse(await readFile(paths.out, "utf8")) };
}

export async function runOfficial(programs) {
  const paths = await prepareRunDir(programs);
  await writeFile(
    paths.firebase,
    JSON.stringify({
      emulators: { firestore: { host: "127.0.0.1", port: 32082 }, ui: { enabled: false } },
    }),
  );
  const inner = `'${process.execPath}' '${SESSION_SCRIPT}' session-official`;
  const { exitCode, timedOut } = await runSupervised({
    command: join(CONFORMANCE_DIR, "node_modules/.bin/firebase"),
    args: [
      "emulators:exec",
      "--only",
      "firestore",
      "--project",
      OFFICIAL_PROJECT,
      "--config",
      paths.firebase,
      inner,
    ],
    cwd: RUN_DIR,
    env: {
      ...process.env,
      FS3_IN: paths.in,
      FS3_OUT: paths.out,
      FS3_RUN: String(Date.now()),
      GOOGLE_APPLICATION_CREDENTIALS: "",
    },
    timeoutMs: SESSION_TIMEOUT_MS,
  });
  if (timedOut || exitCode !== 0)
    throw new Error(`official emulator session ended ${timedOut ? "on its timeout" : exitCode}`);
  return JSON.parse(await readFile(paths.out, "utf8"));
}

// ---- commands -------------------------------------------------------------------------------

function printRows(title, programs, results) {
  console.log(`\n${title}`);
  for (const program of programs) {
    console.log(`  ${program.id}`);
    for (const step of program.steps)
      console.log(`    ${step.id.padEnd(28)} ${brief(results[program.id]?.steps?.[step.id])}`);
  }
}

async function check() {
  const fixture = existsSync(FIXTURE)
    ? JSON.parse(await readFile(FIXTURE, "utf8"))
    : { programs: {} };
  const programs = selectPrograms();
  validateCorpus(programs);
  const profile = process.env.FS3_PROFILE ?? "strict";
  const local = await runLocal(programs, { profile });
  const rows = compareRows({ fixture, programs, local });
  const known = new Set([...PROGRAMS, ...BAD_PATH_PROGRAMS].map((p) => p.id));
  const orphans = Object.keys(fixture.programs ?? {}).filter((id) => !known.has(id));
  const summary = {};
  for (const { status } of rows) summary[status] = (summary[status] ?? 0) + 1;
  await writeFile(
    join(RUN_DIR, "comparison.json"),
    `${JSON.stringify({ profile, artifact: local.binary, artifactSha256: sha256(await readFile(local.binary)), summary, orphans, failures: local.failures, rows }, null, 2)}\n`,
  );
  for (const row of rows.filter((r) => !PASSING.has(r.status)))
    console.log(
      `${row.status.padEnd(16)} ${row.row}\n  production ${brief(row.production)}\n  fireemu    ${brief(row.fireemu)}`,
    );
  console.log(JSON.stringify({ profile, summary, orphans, failures: local.failures }, null, 2));
  if (!rows.every((r) => PASSING.has(r.status)) || orphans.length || local.failures.length)
    process.exitCode = 1;
}

async function exportComparison(out) {
  if (!out) throw new Error("usage: export-comparison <output.json>");
  const comparison = JSON.parse(await readFile(join(RUN_DIR, "comparison.json"), "utf8"));
  const evidence = {
    kind: "fs-rules-v1-comparison-v1",
    profile: comparison.profile,
    artifactSha256: comparison.artifactSha256,
    fixtureSha256: sha256(await readFile(FIXTURE, "utf8")),
    summary: comparison.summary,
    rows: comparison.rows.map(({ row, status }) => ({ row, status })),
  };
  await writeFile(out, `${JSON.stringify(evidence, null, 2)}\n`);
  console.log(
    JSON.stringify(
      { out, summary: evidence.summary, fixtureSha256: evidence.fixtureSha256 },
      null,
      2,
    ),
  );
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const mode = process.argv[2];
  if (mode === "preflight") {
    const ledger = process.env.FIREEMU_SANDBOX_LEDGER;
    const ledgerText = ledger && existsSync(ledger) ? await readFile(ledger, "utf8") : "";
    const taskId = taskIdFor(selectPrograms());
    const target = await productionTarget(await sandboxWebConfig());
    console.log(JSON.stringify(await preflight(target, ledgerText, { taskId }), null, 2));
  } else if (mode === "record-production") {
    const result = await recordProduction(process.env, productionDeps());
    if (result.error) console.error(result.error);
    process.exitCode = result.exitCode;
  } else if (mode === "check") await check();
  else if (mode === "export-comparison") await exportComparison(process.argv[3]);
  else if (mode === "session-local") await sessionLocal();
  else if (mode === "session-official") await sessionOfficial();
  else if (mode === "local" || mode === "official") {
    const programs = selectPrograms();
    const profile = process.env.FS3_PROFILE ?? "strict";
    const result =
      mode === "local" ? await runLocal(programs, { profile }) : await runOfficial(programs);
    await writeFile(join(RUN_DIR, `${mode}-results.json`), `${JSON.stringify(result, null, 2)}\n`);
    printRows(`${mode}${mode === "local" ? ` (${profile})` : ""}`, programs, result.results);
    console.log(
      JSON.stringify(
        {
          requests: result.requests,
          failures: result.failures,
          cleanupErrors: result.cleanupErrors,
        },
        null,
        2,
      ),
    );
  } else {
    console.error(
      "usage: run.mjs preflight|record-production|check|local|official|export-comparison",
    );
    process.exitCode = 2;
  }
}
