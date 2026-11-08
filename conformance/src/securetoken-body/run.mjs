// Secure Token request-body sandbox runner.
//
//   node src/securetoken-body/run.mjs preflight          read-only production checks
//   node src/securetoken-body/run.mjs record-production record the corpus twice against the
//                                                        sandbox and write
//                                                        securetoken-body-production.json
//   node src/securetoken-body/run.mjs local              the corpus against fireemu only
//                                                        (SECURETOKEN_PROFILE=strict|emulator)
//   node src/securetoken-body/run.mjs report             production rows (when recorded) against
//                                                        the last local result
//
// Production needs FIREEMU_AUTH_SANDBOX_WEB_CONFIG (the sandbox web app config JSON, kept outside
// the repository), owner ADC, FIREEMU_SANDBOX_LEDGER and FIREEMU_SECURETOKEN_PRIVATE_DIR. It only
// ever addresses the Identity Platform sandbox project. The decisions are in judge.mjs, the
// production sequence in record.mjs, the requests in harness.mjs and session.mjs.

import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { appendFile, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";

import { SANDBOX_PROJECT, createContext } from "../auth-account/harness.mjs";
import { scanFixture } from "../auth-account/fixture-scan.mjs";
import { CONFORMANCE_DIR } from "../config.mjs";
import { resolveFireemuBinary } from "../evidence.mjs";
import { validateCorpus } from "./corpus.mjs";
import { buildReport, estimatedUsd, harnessDigest } from "./judge.mjs";
import { preflight } from "./preflight.mjs";
import { fixtureText, recordProduction } from "./record.mjs";
import { nextRun, recordWith } from "./recording.mjs";
import { runSupervised } from "../fs-rules-v1/supervise.mjs";

const execFileAsync = promisify(execFile);
export const FIXTURE = join(CONFORMANCE_DIR, "securetoken-body-production.json");
const RUN_DIR = join(CONFORMANCE_DIR, ".runs", "securetoken-body");
const SESSION_SCRIPT = join(CONFORMANCE_DIR, "src/securetoken-body/run.mjs");
const LOCAL_PROJECT_NUMBER = "123456789012";
export const RECORDING_SIGNALS = ["SIGINT", "SIGTERM", "SIGHUP"];

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

/** Refuses a recording from a worktree with any change, tracked or not. */
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
    preflight: async (target, ledgerText) => {
      const ctx = createContext({ run: nextRun(), project: SANDBOX_PROJECT, target });
      return preflight(ctx, ledgerText);
    },
    async recordOnce(n, web, { runDir, shouldStop }) {
      const target = await productionTarget(web);
      return recordWith(target, runDir, n, {
        shouldStop,
        log: (line) => console.log(line),
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

export const fireemuConfig = (profile) => ({
  schemaVersion: 1,
  profile,
  daemon: { authProjectNumbers: { [SANDBOX_PROJECT]: LOCAL_PROJECT_NUMBER } },
  auth: { idTokenSigning: "session-rsa", apiKeys: ["fake-api-key"] },
});

/** Inside `fireemu exec`: records the corpus once against the port it set in the environment. */
async function sessionLocal() {
  const origin = process.env.SECURETOKEN_ORIGIN;
  const dir = process.env.SECURETOKEN_DIR;
  const target = { kind: "local", origin, projectNumber: LOCAL_PROJECT_NUMBER };
  const recording = await recordWith(target, dir, Number(process.env.SECURETOKEN_N ?? 1), {
    pollMs: 20,
    log: process.env.SECURETOKEN_VERBOSE ? (line) => console.error(line) : undefined,
  });
  const { secrets: _secrets, ...publicPart } = recording;
  await writeFile(process.env.SECURETOKEN_OUT, JSON.stringify(publicPart));
}

export async function runLocal({
  profile = "strict",
  binary = resolveFireemuBinary(),
  n = 1,
} = {}) {
  await rm(RUN_DIR, { recursive: true, force: true });
  await mkdir(RUN_DIR, { recursive: true, mode: 0o700 });
  const configPath = join(RUN_DIR, "fireemu.config.json");
  const out = join(RUN_DIR, `local-${profile}-${n}.json`);
  await writeFile(configPath, JSON.stringify(fireemuConfig(profile)));
  const port = 32299;
  const { exitCode, timedOut } = await runSupervised({
    command: binary,
    args: [
      "exec",
      "--config",
      configPath,
      "--project",
      SANDBOX_PROJECT,
      "--only",
      "auth",
      "--http-port",
      String(port),
      "--firestore-port",
      "0",
      "--ui-port",
      "0",
      "--hub-port",
      "0",
      "--logging-port",
      "0",
      "--",
      process.execPath,
      SESSION_SCRIPT,
      "session-local",
    ],
    cwd: RUN_DIR,
    env: {
      ...process.env,
      SECURETOKEN_ORIGIN: `http://127.0.0.1:${port}`,
      SECURETOKEN_DIR: RUN_DIR,
      SECURETOKEN_N: String(n),
      SECURETOKEN_OUT: out,
    },
    timeoutMs: 10 * 60_000,
  });
  if (timedOut || exitCode !== 0)
    throw new Error(`fireemu session ended ${timedOut ? "on its timeout" : exitCode}`);
  return { binary, profile, ...JSON.parse(await readFile(out, "utf8")) };
}

// ---- commands -------------------------------------------------------------------------------

function printReport(rows) {
  for (const r of rows)
    console.log(
      `${r.status.padEnd(9)} ${r.row.padEnd(38)} production: ${r.production ?? "-"} | fireemu: ${r.fireemu ?? "-"}`,
    );
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const mode = process.argv[2];
  if (mode === "preflight") {
    const ledger = process.env.FIREEMU_SANDBOX_LEDGER;
    const ledgerText = ledger && existsSync(ledger) ? await readFile(ledger, "utf8") : "";
    const target = await productionTarget(await sandboxWebConfig());
    const ctx = createContext({ run: nextRun(), project: SANDBOX_PROJECT, target });
    console.log(JSON.stringify(await preflight(ctx, ledgerText), null, 2));
  } else if (mode === "record-production") {
    const result = await recordProduction(process.env, productionDeps());
    if (result.error) console.error(result.error);
    process.exitCode = result.exitCode;
  } else if (mode === "session-local") await sessionLocal();
  else if (mode === "local") {
    validateCorpus();
    const profile = process.env.SECURETOKEN_PROFILE ?? "strict";
    const result = await runLocal({ profile });
    const rows = buildReport({ localRecordings: [result] });
    printReport(rows);
    console.log(
      JSON.stringify(
        {
          profile,
          requests: result.requests,
          harnessRequests: result.harnessRequests,
          closureReady: result.closureReady,
          cleanupErrors: result.cleanupErrors,
          failure: result.failure,
          estimatedUsd: estimatedUsd(result.requests + result.harnessRequests),
        },
        null,
        2,
      ),
    );
    if (!result.closureReady || result.failure) process.exitCode = 1;
  } else if (mode === "report") {
    const fixture = existsSync(FIXTURE) ? JSON.parse(await readFile(FIXTURE, "utf8")) : undefined;
    const profile = process.env.SECURETOKEN_PROFILE ?? "strict";
    const local = JSON.parse(await readFile(join(RUN_DIR, `local-${profile}-1.json`), "utf8"));
    printReport(
      buildReport({
        productionRecordings: fixture?.recordings,
        localRecordings: [local],
      }),
    );
  } else {
    console.error("usage: run.mjs preflight|record-production|local|report");
    process.exitCode = 2;
  }
}

export { fixtureText };
