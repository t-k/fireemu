// The production side of the AUTH-FS-CROSS stage-2 runner: local admission (no request), and
// one recording of the window against the idp sandbox under the packet's approval.
//
// Production needs FIREEMU_AUTH_SANDBOX_WEB_CONFIG (the sandbox web app config JSON, kept outside
// the repository), owner ADC, FIREEMU_SANDBOX_LEDGER (the shared ledger),
// FIREEMU_AUTH_FS_CROSS_PRIVATE_DIR (under the shared docs.local), AFC_PACKET_FILE (the packet,
// under the shared docs.local), AFC_PACKET_SOURCE_COMMIT (HEAD) and AFC_NO_AUTH_RECORDING (the
// operator's check that no AUTH lane is recording).

import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readFile, realpath } from "node:fs/promises";
import { join, resolve as resolvePath } from "node:path";
import { promisify } from "node:util";

import { CONFORMANCE_DIR } from "../config.mjs";
import { createContext } from "../fs-rules/harness.mjs";
import { STAGE2_PRINCIPALS, STAGE2_PROGRAM } from "./programs-stage2.mjs";
import { DRIVERS, spawnSdk } from "./sdk-client.mjs";
import { confirmedNoAuthRecording, recentAbort, sharedRoot } from "./run.mjs";
import { admissionProblems } from "./sandbox.mjs";
import { closureTransports, validateStage2 } from "./stage2-corpus.mjs";
import { runStage2Window } from "./stage2-orchestrator.mjs";
import { compileProbe, runStage2Production } from "./stage2-production.mjs";
import { rulesetSource, RULESET_IDS } from "./stage2-rulesets.mjs";
import {
  DECLARED_PROJECTS,
  RECORDINGS,
  destinationProblem,
  packetApproval,
  recordingProblems,
  SANDBOX_PROJECT,
} from "./stage2-sandbox.mjs";

const execFileAsync = promisify(execFile);
const sha256 = (text) => createHash("sha256").update(text).digest("hex");

/** Harness calls one recording may make (setup, probes, publication settling, cleanup). */
export const HARNESS_CEILING = 700;
/** The requests the browser key probe's client may make. */
const KEY_PROBE_CAP = 5;
/** Baseline reads at the start (with the API keys read) and the end, the key probe, the compile probe. */
const FIXED_REQUESTS = 8 + 1 + KEY_PROBE_CAP + 3 + 8;
/** The Firestore and Auth spend one recording reserves in the ledger. */
export const RESERVE_USD = 1;

/** The runner's own limits, which an envelope must cover. */
export function runnerLimits(cost) {
  return {
    project: SANDBOX_PROJECT,
    maxRequests: HARNESS_CEILING + cost.maxWire + FIXED_REQUESTS,
    reserveUsd: RESERVE_USD,
  };
}

/** The files whose semantics a recorded row depends on; a change makes the rows stale. */
const HARNESS_FILES = [
  "fs-rules/harness.mjs",
  "auth-credential/tokens.mjs",
  "auth-fs-cross/stage2-session.mjs",
  "auth-fs-cross/stage2-orchestrator.mjs",
  "auth-fs-cross/listen-grpc.mjs",
  "auth-fs-cross/sdk-client.mjs",
  "auth-fs-cross/sdk-driver.mjs",
  "auth-fs-cross/sdk-driver-wire.mjs",
  "auth-fs-cross/sdk-wire.mjs",
  "auth-fs-cross/sdk-operations.mjs",
  "auth-fs-cross/browser-driver.mjs",
  "auth-fs-cross/browser-page.mjs",
];

export async function stage2HarnessDigest() {
  const sources = await Promise.all(
    HARNESS_FILES.map((file) => readFile(join(CONFORMANCE_DIR, "src", file), "utf8")),
  );
  return sha256(`${sources.join("\n")}\n${JSON.stringify(STAGE2_PRINCIPALS)}`);
}

/** The program's digest covers its JSON and the rules it runs under. */
export const stage2ProgramDigest = (program = STAGE2_PROGRAM) =>
  sha256(`${JSON.stringify(program)}\n${RULESET_IDS.map((id) => rulesetSource(id)).join("\n")}`);

async function gitSha() {
  const { stdout } = await execFileAsync("git", ["rev-parse", "HEAD"], { cwd: CONFORMANCE_DIR });
  return stdout.trim();
}

async function assertCleanTree() {
  const { stdout } = await execFileAsync("git", ["status", "--porcelain", "--", "src"], {
    cwd: CONFORMANCE_DIR,
  });
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

async function sandboxWebConfig(env = process.env) {
  const path = env.FIREEMU_AUTH_SANDBOX_WEB_CONFIG;
  if (!path) throw new Error("FIREEMU_AUTH_SANDBOX_WEB_CONFIG is required");
  const web = JSON.parse(await readFile(path, "utf8"));
  if (web.projectId !== SANDBOX_PROJECT)
    throw new Error(`the web config is not ${SANDBOX_PROJECT}`);
  if (!/^\d+$/.test(web.projectNumber ?? "") || web.projectNumber !== web.messagingSenderId)
    throw new Error("the web config has no consistent project number");
  return web;
}

async function adminToken() {
  const { stdout } = await execFileAsync("gcloud", [
    "auth",
    "application-default",
    "print-access-token",
  ]);
  return stdout.trim();
}

async function productionTarget(web) {
  let fetchedAt = Date.now();
  const target = {
    kind: "production",
    apiKey: web.apiKey,
    adminToken: await adminToken(),
    quotaProject: SANDBOX_PROJECT,
    projectNumber: web.projectNumber,
    async refresh() {
      if (Date.now() - fetchedAt < 20 * 60_000) return;
      target.adminToken = await adminToken();
      fetchedAt = Date.now();
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

/** An owner call of the baseline and the compile probe; the destination is checked first. */
async function ownerFetch(target, method, url, body, quotaProject = SANDBOX_PROJECT) {
  const refused = destinationProblem(url);
  if (refused) throw new Error(`${method}: ${refused}; not sent`);
  const init = {
    method,
    headers: { authorization: `Bearer ${target.adminToken}`, "x-goog-user-project": quotaProject },
  };
  if (body) {
    init.headers["content-type"] = "application/json";
    init.body = JSON.stringify(body);
  }
  const response = await fetch(url, init);
  return { status: response.status, json: await response.json().catch(() => null) };
}

/**
 * One browser client makes one read with the web key (the password policy) from the page's
 * origin, and is closed. `ok: false` with the SDK's code when the key refuses it.
 */
export async function browserKeyProbe(sdkConfig, { spawn = spawnSdk } = {}) {
  const sdk = spawn(
    { ...sdkConfig, wireCap: KEY_PROBE_CAP },
    { driver: DRIVERS.browser, timeoutMs: 60_000 },
  );
  try {
    await sdk.ready();
    const result = await sdk.send("probeKey", {});
    return {
      ok: result.ok,
      code: result.ok ? null : (result.code ?? "unknown"),
      requests: sdk.events.filter((e) => e.event === "wire").length,
    };
  } finally {
    await sdk.close();
  }
}

/** Everything checked before the lock and before any request. */
export async function stage2Admission(env = process.env, now = Date.now()) {
  const problems = [];
  const attempt = async (run) => {
    try {
      return await run();
    } catch (error) {
      problems.push(String(error.message ?? error));
      return undefined;
    }
  };
  const root = await sharedRoot();
  const sharedLedger = join(root, "docs.local", "runs", "sandbox-ledger.jsonl");
  const ledgerText = await attempt(async () => {
    if (!env.FIREEMU_SANDBOX_LEDGER) throw new Error("FIREEMU_SANDBOX_LEDGER is required");
    if ((await realpath(env.FIREEMU_SANDBOX_LEDGER)) !== sharedLedger)
      throw new Error(`FIREEMU_SANDBOX_LEDGER is not the shared ledger ${sharedLedger}`);
    return readFile(env.FIREEMU_SANDBOX_LEDGER, "utf8");
  });
  const underDocsLocal = (path) =>
    resolvePath(path ?? "").startsWith(`${join(root, "docs.local")}/`);
  if (!underDocsLocal(env.FIREEMU_AUTH_FS_CROSS_PRIVATE_DIR))
    problems.push("FIREEMU_AUTH_FS_CROSS_PRIVATE_DIR must be under the shared docs.local");
  const sha = await gitSha();
  if (sha !== (env.AFC_PACKET_SOURCE_COMMIT ?? ""))
    problems.push(`HEAD ${sha} is not the packet's source commit ${env.AFC_PACKET_SOURCE_COMMIT}`);
  const harness = await stage2HarnessDigest();
  const closure = closureTransports(
    JSON.parse(
      await readFile(
        join(CONFORMANCE_DIR, "..", "spec", "compatibility", "closure", "AUTH-FS-CROSS.json"),
        "utf8",
      ),
    ),
  );
  const cost = await attempt(async () => validateStage2(STAGE2_PROGRAM, { closure }));
  const packetSha256 = await attempt(async () => {
    if (!underDocsLocal(env.AFC_PACKET_FILE))
      throw new Error("AFC_PACKET_FILE must name the packet under the shared docs.local");
    return sha256(await readFile(env.AFC_PACKET_FILE, "utf8"));
  });
  const recording = Number(env.AFC2_RECORDING);
  if (!RECORDINGS.includes(recording)) problems.push("AFC2_RECORDING must be 1 or 2");
  if (packetSha256 && cost) {
    const owner = await attempt(() =>
      readFile(join(root, "docs.local", "instructions", "owner-decisions.md"), "utf8"),
    );
    if (owner !== undefined)
      problems.push(
        ...packetApproval(owner, {
          packetSha256,
          sourceCommit: sha,
          harnessDigest: harness,
          runner: runnerLimits(cost),
        }).problems,
      );
  }
  await attempt(assertCleanTree);
  await attempt(() => confirmedNoAuthRecording(env, now));
  await attempt(() => sandboxWebConfig(env));
  if (ledgerText !== undefined) {
    const aborted = recentAbort(ledgerText, now);
    if (aborted) problems.push(`this task's last run aborted at ${aborted.ts}; wait an hour`);
    for (const project of DECLARED_PROJECTS)
      problems.push(...admissionProblems(ledgerText, project, now));
    if (packetSha256) problems.push(...recordingProblems(ledgerText, packetSha256, recording));
  }
  return {
    sha,
    harness,
    packetSha256,
    recording,
    cost,
    programDigest: stage2ProgramDigest(),
    problems,
    root,
  };
}

/** Set by SIGINT or SIGTERM: the window stops at its next step and cleans up. */
let stopRequested = false;

export async function recordProduction(env = process.env) {
  const first = await stage2Admission(env);
  if (first.problems.length) throw new Error(`admission: ${first.problems.join("; ")}`);
  const web = await sandboxWebConfig(env);
  const privateRoot = env.FIREEMU_AUTH_FS_CROSS_PRIVATE_DIR;
  await assertIgnored(privateRoot);
  for (const signal of ["SIGINT", "SIGTERM"])
    process.on(signal, () => {
      if (stopRequested) {
        console.error(`${signal} again: cleanup is running and is not interrupted.`);
        return;
      }
      stopRequested = true;
      console.error(`${signal}: stopping at the next step or wait; cleanup follows`);
    });
  const locks = join(first.root, "docs.local", "runs", "sandbox-locks");
  const secrets = [
    [web.apiKey, "api-key"],
    [web.projectNumber, "project-number"],
  ];
  const sdkConfig = {
    mode: "production",
    web: { apiKey: web.apiKey, projectId: web.projectId, authDomain: web.authDomain },
  };
  return runStage2Production({
    ledger: env.FIREEMU_SANDBOX_LEDGER,
    lockDir: locks,
    legacyLock: `${env.FIREEMU_SANDBOX_LEDGER}.lock`,
    ownerDecisions: join(first.root, "docs.local", "instructions", "owner-decisions.md"),
    privateRoot,
    packetSha256: first.packetSha256,
    recording: first.recording,
    runner: runnerLimits(first.cost),
    secrets,
    // Checked again right before the lock: the ledger may have moved since.
    admission: () => stage2Admission(env),
    target: () => productionTarget(web),
    fetchJson: ownerFetch,
    clockOffset: assertClockSynchronized,
    browserKeyProbe: () => browserKeyProbe(sdkConfig),
    compileProbe,
    recordWindow: (target) =>
      runStage2Window(STAGE2_PROGRAM, createContext({ run: String(Date.now()), target }), {
        principals: STAGE2_PRINCIPALS,
        sdkConfig,
        sessionOptions: {
          maxHarnessRequests: HARNESS_CEILING,
          destinationProblem,
          shouldStop: () => stopRequested,
          log: (line) => console.log(line),
        },
        log: (line) => console.log(`${new Date().toISOString()} ${line}`),
      }),
    recentAbort: (text) => recentAbort(text),
    stopRequested: () => stopRequested,
    now: () => new Date(),
    log: (value) => console.log(JSON.stringify(value, null, 2)),
  });
}
