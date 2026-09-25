// AUTH-MFA sandbox runner.
//
//   node src/auth-mfa/run.mjs record-production   record the corpus twice against the Identity
//                                                 Platform sandbox and update
//                                                 auth-mfa-production.json
//   node src/auth-mfa/run.mjs rebuild-fixture <run dir>
//   node src/auth-mfa/run.mjs check               run the corpus against fireemu and compare
//                                                 with the saved production rows
//   node src/auth-mfa/run.mjs export-comparison <out.json>
//   node src/auth-mfa/run.mjs restore-sandbox     after a run that could not clean up (SIGKILL,
//                                                 a crash): MFA off, password required, read
//                                                 back, and a ledger line (no account deleted)
//
// `record-production` needs FIREEMU_AUTH_SANDBOX_WEB_CONFIG (the sandbox web app config JSON,
// kept outside the repository), owner ADC (`gcloud auth application-default`),
// FIREEMU_SANDBOX_LEDGER and FIREEMU_AUTH_MFA_PRIVATE_DIR. AUTH_MFA_PROGRAMS selects programs
// by id prefix (AUTH_MFA_PROGRAMS_EXACT=1: by exact id).
//
// Every program but the first switches the project's `mfa` config on for its own duration; the
// session restores it and reads it back, and the run requires MFA to be off before it starts
// and after it ends. Second factors are TOTP and SMS to configured test numbers only.

import { execFile, spawn } from "node:child_process";
import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import { existsSync } from "node:fs";
import { appendFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";

import { CONFORMANCE_DIR } from "../config.mjs";
import { resolveFireemuBinary } from "../evidence.mjs";
import { BASELINE_CONFIG, CONFIG_DEFAULTS } from "../auth-account/corpus.mjs";
import { scanFixture } from "../auth-account/fixture-scan.mjs";
import {
  RECORDED_PROJECT,
  SANDBOX_PROJECT,
  buildRequest,
  createContext,
  diffRecordings,
  isTransient,
  sameRecording,
} from "../auth-account/harness.mjs";
import { configMatches, createSession as createAccountSession } from "../auth-account/session.mjs";
import { SIGNER_ACCOUNTS, harnessRequest } from "../auth-credential/harness.mjs";
import { customTokenClaims } from "../auth-credential/tokens.mjs";
import { PROGRAMS } from "./corpus.mjs";
import { MFA_CONFIGS, guardMfaRequest, validateMfaCorpus } from "./guard.mjs";
import { AGE_MARGIN_SECONDS, ALIGN_WINDOW, createSession, runCorpus } from "./session.mjs";

const execFileAsync = promisify(execFile);
const FIXTURE = join(CONFORMANCE_DIR, "auth-mfa-production.json");
const RUN_DIR = join(CONFORMANCE_DIR, ".runs", "auth-mfa");
const LOCAL_PORT = 32297;
/** The synthetic project number fireemu is configured with. */
const LOCAL_PROJECT_NUMBER = "123456789012";
const TASK_ID = "AUTH-MFA-SANDBOX";
const sha256 = (text) => createHash("sha256").update(text).digest("hex");

function selectedPrograms() {
  const prefixes = (process.env.AUTH_MFA_PROGRAMS ?? "").split(",").filter(Boolean);
  const exact = process.env.AUTH_MFA_PROGRAMS_EXACT === "1";
  const programs = prefixes.length
    ? PROGRAMS.filter((p) =>
        prefixes.some((prefix) => (exact ? p.id === prefix : p.id.startsWith(prefix))),
      )
    : PROGRAMS;
  if (programs.length === 0) throw new Error("no program matches AUTH_MFA_PROGRAMS");
  return programs;
}

const programDigest = (program) => sha256(JSON.stringify(program));

/**
 * Normalization and request semantics a saved row depends on; a change makes it stale. The
 * guard and corpus rules (guard.mjs) only refuse requests and are not part of it.
 */
async function harnessDigest() {
  const sources = await Promise.all(
    [
      "auth-mfa/harness.mjs",
      "auth-mfa/session.mjs",
      "auth-credential/session.mjs",
      "auth-credential/tokens.mjs",
      "auth-account/harness.mjs",
      "auth-account/session.mjs",
    ].map((file) => readFile(join(CONFORMANCE_DIR, "src", file), "utf8")),
  );
  return sha256(
    `${sources.join("\n")}\n${JSON.stringify(BASELINE_CONFIG)}\n${JSON.stringify(AUTHORIZED_DOMAINS)}\n${JSON.stringify(ALIGN_WINDOW)}`,
  );
}

/**
 * Per recording: every step once; the harness gets its own budget for config, clock reads and
 * waits (locally a code, an alignment and an age each read the clock, and a wait advances it),
 * and wipes and config restores a separate reserve (two wipes of up to 41 requests and one
 * restore of up to 31 per program, and the final wipe).
 */
const ceilings = (programs) => ({
  maxRequests: programs.reduce((total, p) => total + p.steps.length, 0),
  maxHarnessRequests: programs.reduce(
    (total, p) => total + 4 + (p.config ? 32 : 0) + 4 * p.steps.length,
    20,
  ),
  maxCleanupRequests: programs.reduce((total, p) => total + 82 + (p.config ? 31 : 0), 41),
});

async function assertIgnored(path) {
  await mkdir(path, { recursive: true, mode: 0o700 });
  try {
    await execFileAsync("git", ["-C", path, "rev-parse", "--show-toplevel"]);
  } catch {
    return;
  }
  try {
    await execFileAsync("git", ["-C", path, "check-ignore", "-q", path]);
  } catch {
    throw new Error(`${path} is not ignored by git; private recordings must not be committable`);
  }
}

async function assertCleanTree() {
  const { stdout } = await execFileAsync(
    "git",
    [
      "status",
      "--porcelain",
      "--",
      "src/auth-mfa",
      "src/auth-credential",
      "src/auth-account",
      "auth-mfa-production.json",
    ],
    { cwd: CONFORMANCE_DIR },
  );
  if (stdout.trim()) throw new Error(`record-production needs a clean tree:\n${stdout}`);
}

async function gitSha() {
  const { stdout } = await execFileAsync("git", ["rev-parse", "HEAD"], { cwd: CONFORMANCE_DIR });
  return stdout.trim();
}

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
  if (!/^\d+$/.test(web.projectNumber ?? "") || web.projectNumber !== web.messagingSenderId) {
    throw new Error("web config has no consistent project number");
  }
  return web;
}

/**
 * The authorized domains the sandbox answers with (read 2026-09-24): its Firebase Hosting
 * domains, without `localhost`. Production is checked against them; fireemu is given them.
 */
export const AUTHORIZED_DOMAINS = ["{project}.firebaseapp.com", "{project}.web.app"];

/**
 * The sign-in baseline, the account-behaviour defaults and the authorized domains: read and
 * required in production, applied locally.
 */
async function prepareProject(ctx, { apply }) {
  const account = createAccountSession(ctx, { maxHarnessRequests: 80 });
  const domains = AUTHORIZED_DOMAINS.map((d) => d.replaceAll("{project}", ctx.project));
  const baseline = { ...BASELINE_CONFIG, authorizedDomains: domains };
  const baselineMask = Object.keys(baseline);
  if (apply) await account.writeConfig(baselineMask, baseline);
  else {
    const current = await account.readConfig(baselineMask);
    const drift = baselineMask.filter((path) => !configMatches(current[path], baseline[path]));
    if (drift.length) throw new Error(`sandbox baseline differs at ${drift.join(", ")}`);
  }
  const defaultsMask = Object.keys(CONFIG_DEFAULTS);
  const now = await account.readConfig(defaultsMask);
  const drift = defaultsMask.filter((path) => !configMatches(now[path], CONFIG_DEFAULTS[path]));
  if (drift.length && ctx.target.kind === "production")
    throw new Error(`sandbox config is not at its defaults: ${drift.join(", ")}`);
  // Every program starts from MFA switched off, exactly as the sandbox baseline has it.
  if (apply) await account.writeConfig(["mfa"], { mfa: MFA_CONFIGS.disabled });
  const { mfa } = await account.readConfig(["mfa"]);
  if (!sameRecording(mfa, MFA_CONFIGS.disabled)) {
    throw new Error(`sandbox MFA is not at its baseline: ${JSON.stringify(mfa)}`);
  }
  return account.counts().harnessRequests;
}

/**
 * Refuses to start while the sandbox holds any project-level account: every program wipes the
 * project, so an account here belongs to a lane that is still recording.
 */
async function assertNoAccounts(ctx) {
  const request = buildRequest(
    {
      id: "preflight",
      method: "GET",
      path: "v1/projects/{project}/accounts:batchGet",
      auth: "admin",
      query: { maxResults: 1 },
    },
    ctx,
    new Map(),
  );
  guardMfaRequest(request, ctx, { harness: true });
  const response = await fetch(request.url, { ...request.init, redirect: "error" });
  const body = await response.json().catch(() => null);
  if (response.status !== 200) throw new Error(`account preflight: HTTP ${response.status}`);
  if ((body?.users ?? []).length)
    throw new Error("the sandbox holds accounts: another lane may be recording");
}

/**
 * A production context whose owner token is renewed every half hour, or at once when forced
 * (a cleanup that met a 401); every token it ever held is collected for the fixture scan.
 */
async function productionContext(run, web, tokens) {
  let token = await adminToken();
  tokens.push(token);
  let fetchedAt = Date.now();
  const target = {
    kind: "production",
    apiKey: web.apiKey,
    adminToken: token,
    quotaProject: SANDBOX_PROJECT,
    projectNumber: web.projectNumber,
    async refresh({ force = false } = {}) {
      if (!force && Date.now() - fetchedAt < 30 * 60_000) return;
      token = await adminToken();
      tokens.push(token);
      fetchedAt = Date.now();
      target.adminToken = token;
    },
  };
  return createContext({ run, project: SANDBOX_PROJECT, target });
}

async function recordOnce(programs, run, web, { signal, tokens }) {
  const ctx = await productionContext(run, web, tokens);
  await assertNoAccounts(ctx);
  const preparation = await prepareProject(ctx, { apply: false });
  const out = await runCorpus(programs, ctx, {
    ...ceilings(programs),
    signers: { project: { serviceAccount: SIGNER_ACCOUNTS.project } },
    signal,
    log: (line) => console.log(line),
  });
  // MFA and the rest of the baseline must read back as they started.
  const after = await prepareProject(ctx, { apply: false });
  return { ...out, harnessRequests: out.harnessRequests + preparation + after };
}

/** The switches a run changes, read back after a run that stopped early (best effort). */
async function readSwitches(web, tokens) {
  try {
    const ctx = await productionContext(String(Date.now()), web, tokens);
    const session = createSession(ctx, { maxHarnessRequests: 4 });
    return await session.readConfig(["mfa", "signIn.email.passwordRequired"]);
  } catch (error) {
    return { unreadable: String(error?.message ?? error) };
  }
}

/**
 * Whether the project's own signer may mint a custom token (the time-limited signJwt binding
 * exists): checked before the run starts, so a missing binding does not stop it halfway.
 */
async function assertSignerReady(web, tokens) {
  const ctx = await productionContext(String(Date.now()), web, tokens);
  const now = Math.floor(Date.now() / 1000);
  const claims = customTokenClaims(
    { uid: "preflight" },
    SIGNER_ACCOUNTS.project,
    now,
    (text) => text,
  );
  const request = harnessRequest.signJwt(ctx, SIGNER_ACCOUNTS.project, claims);
  const response = await fetch(request.url, { ...request.init, redirect: "error" });
  if (response.status !== 200)
    throw new Error(
      `signJwt preflight: HTTP ${response.status} (create the signJwt binding first)`,
    );
}

async function writeFixture({ programs, recordings, meta, secrets }) {
  const [first, second] = recordings;
  const fixture = existsSync(FIXTURE)
    ? JSON.parse(await readFile(FIXTURE, "utf8"))
    : { version: 1, recordedAgainst: {}, programs: {} };
  fixture.recordedAgainst = {
    target:
      "production Identity Toolkit and Secure Token REST, Identity Platform sandbox, with the project mfa config switched on per program (owner decision M1); second factors are TOTP (codes computed from the enrollment secret, RFC 6238) and SMS to configured test numbers only (no SMS is sent, M3)",
    project: RECORDED_PROJECT,
    note: "Two recordings per program. TOTP secrets, session infos, pending credentials and refresh tokens are placeholders; codes are never recorded. Second factors are named per program by first appearance and shape (<enrollment:N:uuid>). Tokens are recorded as their decoded header shape and claims, with times relative to the token's own iat. Factor instants in the run window are recorded as their fraction precision; an enrollment deadline as its distance from the send time. Generated ids, run-window times, the project id, its number and the API key are placeholders. `second` holds the other recording of rows that differed.",
    baselineConfig: BASELINE_CONFIG,
    authorizedDomains: AUTHORIZED_DOMAINS,
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
  scanFixture(text, [...secrets, SIGNER_ACCOUNTS.project]);
  // A base32 run the length of a TOTP secret, or an otpauth URI, would be a secret.
  if (/otpauth:|"[A-Z2-7]{32}"/.test(text)) throw new Error("fixture holds a TOTP secret");
  await writeFile(FIXTURE, text);
  return diffRecordings(first.results, second.results);
}

/**
 * The per-IP account-creation limit is about 100 per hour, so a run is refused within an hour of
 * this task's last aborted run.
 */
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
    .filter((entry) => entry?.taskId === TASK_ID && entry.outcome !== undefined);
  const last = entries.at(-1);
  // Anything but a clean recording (an abort, program failures, a hand restore) counts.
  const clean = (outcome) => outcome === "recorded" || String(outcome).startsWith("exploration");
  if (!last || clean(last.outcome)) return undefined;
  const age = now - Date.parse(last.ts);
  return age < 3_600_000 ? last : undefined;
}

/**
 * Another lane recording on the Identity Platform sandbox: a task whose last line there is a
 * `started` event, or any other task's line there within the last 30 minutes (agreed with the
 * FS-RULES lane, 2026-09-25). Harness programs wipe every project-level account, so two
 * recordings must never overlap.
 */
export function otherLaneOnSandbox(ledgerText, now = Date.now()) {
  const lines = ledgerText
    .split("\n")
    .filter((line) => line.trim())
    .map((line) => {
      try {
        return JSON.parse(line);
      } catch {
        return undefined;
      }
    })
    .filter((entry) => entry?.project === SANDBOX_PROJECT && entry.taskId !== TASK_ID);
  const last = new Map();
  for (const entry of lines) last.set(entry.taskId, entry);
  const open = [...last.values()].find((entry) => entry.event === "started");
  if (open) return `${open.taskId} started at ${open.ts} and has not finished`;
  const recent = lines.find((entry) => now - Date.parse(entry.ts) < 30 * 60_000);
  return recent ? `${recent.taskId} wrote a line at ${recent.ts}` : undefined;
}

async function recordProduction() {
  const ledger = process.env.FIREEMU_SANDBOX_LEDGER;
  const privateRoot = process.env.FIREEMU_AUTH_MFA_PRIVATE_DIR;
  if (!ledger || !privateRoot) {
    throw new Error("FIREEMU_SANDBOX_LEDGER and FIREEMU_AUTH_MFA_PRIVATE_DIR are required");
  }
  await assertCleanTree();
  const aborted = existsSync(ledger) ? recentAbort(await readFile(ledger, "utf8")) : undefined;
  if (aborted)
    throw new Error(`the last run aborted at ${aborted.ts}; wait an hour before retrying`);
  const busy = existsSync(ledger) ? otherLaneOnSandbox(await readFile(ledger, "utf8")) : undefined;
  if (busy) throw new Error(`another lane is on the sandbox: ${busy}`);
  const programs = selectedPrograms();
  const corpusRequests = validateMfaCorpus(programs);
  const meta = {
    sha: await gitSha(),
    harness: await harnessDigest(),
    startedAt: new Date().toISOString(),
    programs: programs.map((p) => p.id),
    corpusDigests: Object.fromEntries(programs.map((p) => [p.id, programDigest(p)])),
  };
  const web = await sandboxWebConfig();
  const tokens = [];
  if (programs.some(({ tokens: minted }) => minted)) await assertSignerReady(web, tokens);
  await assertIgnored(privateRoot);
  const runDir = join(privateRoot, `auth-mfa-production-${meta.startedAt.replaceAll(":", "")}`);
  await mkdir(runDir, { recursive: true, mode: 0o700 });
  // A first SIGINT or SIGTERM stops at the next step (or ends a wait at once); the program
  // then wipes its accounts and restores the config as on any other stop. A later signal only
  // says so: the sandbox would otherwise keep MFA switched on (pre-send review MF-1).
  const controller = new AbortController();
  let signals = 0;
  const onSignal = (name) => {
    signals += 1;
    if (signals === 1) {
      console.error(
        `${name}: stopping; the current program wipes its accounts and restores the config`,
      );
      controller.abort();
    } else {
      console.error(`${name}: cleanup is running; wait for it (restore-sandbox restores by hand)`);
    }
  };
  // A closed terminal (SIGHUP) stops the run the same way; its later writes may fail, which must
  // not interrupt the cleanup.
  const signalNames = ["SIGINT", "SIGTERM", "SIGHUP"];
  for (const name of signalNames) process.on(name, onSignal);
  const ignoreWriteError = () => {};
  process.stdout.on("error", ignoreWriteError);
  process.stderr.on("error", ignoreWriteError);
  await appendFile(
    ledger,
    `${JSON.stringify({ ts: new Date().toISOString(), event: "started", taskId: TASK_ID, project: SANDBOX_PROJECT, gitSha: meta.sha, programs: meta.programs })}\n`,
  );
  const recordings = [];
  const secrets = [];
  let outcome = "recorded";
  let error;
  let switchesAfter;
  try {
    for (const offset of [0, 1]) {
      const { secrets: seen, ...recording } = await recordOnce(
        programs,
        String(Date.now() + offset),
        web,
        { signal: controller.signal, tokens },
      );
      secrets.push(...seen);
      recordings.push(recording);
      await writeFile(join(runDir, `recording-${offset + 1}.json`), JSON.stringify(recording), {
        mode: 0o600,
      });
    }
  } catch (caught) {
    outcome = controller.signal.aborted
      ? "aborted-signal"
      : caught.fatal
        ? "aborted-fatal"
        : "aborted";
    error = String(caught.message ?? caught);
    if (caught.partial) recordings.push(caught.partial);
    secrets.push(...(caught.secrets ?? []));
    switchesAfter = await readSwitches(web, tokens);
    console.error(`switches after the stop: ${JSON.stringify(switchesAfter)}`);
  }
  await writeFile(
    join(runDir, "meta.json"),
    JSON.stringify(
      {
        ...meta,
        outcome,
        error,
        switchesAfter,
        ageMarginSeconds: AGE_MARGIN_SECONDS,
        timings: recordings.map((r) => r.timings),
      },
      null,
      2,
    ),
    { mode: 0o600 },
  );
  const requests = recordings.reduce((n, r) => n + r.requests + r.harnessRequests, 0);
  const failures = recordings.flatMap((r) => r.failures);
  try {
    if (!error) {
      const nondeterministic = await writeFixture({
        programs,
        recordings,
        meta,
        secrets: [web.apiKey, ...tokens, ...secrets, SANDBOX_PROJECT, web.projectNumber],
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
        database: null,
        gitSha: meta.sha,
        corpusDigest: sha256(JSON.stringify(programs)),
        requests,
        estimatedUsd: 0,
        outcome,
        taskId: TASK_ID,
        programs: meta.programs,
        ...(error ? { error } : {}),
        ...(switchesAfter ? { switchesAfter } : {}),
      })}\n`,
    );
    // Only now: a signal before the terminal line is in must not end the process.
    for (const name of signalNames) process.off(name, onSignal);
  }
  if (error) throw new Error(error);
  if (failures.length) process.exitCode = 1;
}

/** Retries the fixture from a saved run directory; sends nothing to production. */
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
  if (changed.length || programs.length !== meta.programs.length) {
    throw new Error(`corpus changed since the recording: ${changed.map((p) => p.id).join(", ")}`);
  }
  const web = await sandboxWebConfig();
  const nondeterministic = await writeFixture({
    programs,
    recordings,
    meta,
    secrets: [web.apiKey, SANDBOX_PROJECT, web.projectNumber],
  });
  console.log(JSON.stringify({ programs: programs.length, nondeterministic }, null, 2));
}

/** A run-local RSA key standing in for the project's signer service account. */
function localSigner(serviceAccount) {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const kid = randomBytes(20).toString("hex");
  return {
    serviceAccount,
    kid,
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }),
    jwks: { keys: [{ ...publicKey.export({ format: "jwk" }), kid, alg: "RS256", use: "sig" }] },
  };
}

async function sessionLocal() {
  const programs = JSON.parse(await readFile(process.env.AUTH_MFA_IN, "utf8"));
  const signers = JSON.parse(await readFile(process.env.AUTH_MFA_SIGNERS, "utf8"));
  const ctx = createContext({
    run: process.env.AUTH_MFA_RUN,
    project: SANDBOX_PROJECT,
    target: {
      kind: "local",
      origin: process.env.AUTH_MFA_ORIGIN,
      projectNumber: LOCAL_PROJECT_NUMBER,
      control: { url: process.env.FIREEMU_CONTROL_URL, token: process.env.FIREEMU_CONTROL_TOKEN },
    },
  });
  const preparation = await prepareProject(ctx, { apply: true });
  const out = await runCorpus(programs, ctx, { ...ceilings(programs), signers });
  await writeFile(
    process.env.AUTH_MFA_OUT,
    JSON.stringify({ ...out, harnessRequests: out.harnessRequests + preparation }),
  );
}

/**
 * Runs each program in a fireemu session of its own. fireemu's virtual clock follows the wall
 * clock only forward, so after an alignment or an age moved it ahead it stands still until the
 * wall clock catches up; a later program's instants would then all share one whole-second or
 * aligned fraction that production never shows (its instants carry a millisecond or microsecond
 * fraction). A fresh session starts at the wall clock, as a production recording does.
 */
async function runLocal(programs) {
  const merged = { results: {}, failures: [], timings: [], secrets: [], requests: 0, harnessRequests: 0 };
  let binary;
  for (const program of programs) {
    const local = await runLocalSession([program]);
    binary = local.binary;
    Object.assign(merged.results, local.results);
    merged.failures.push(...local.failures);
    merged.timings.push(local.timings);
    merged.secrets.push(...(local.secrets ?? []));
    merged.requests += local.requests;
    merged.harnessRequests += local.harnessRequests;
  }
  return { binary, ...merged };
}

/**
 * The local session's clock starts pinned: fireemu's virtual clock then moves only when the
 * session advances it, so a check is reproducible. It starts at the current second (custom
 * tokens carry the real time) with a sub-second part whose microsecond digits are not zero, so
 * a microsecond instant never loses its trailing digits and a sign-in never straddles a second
 * boundary while it is processed (closure confirmation S1: `enrolledAt` fraction digits and the
 * `aged-token-start-r330` boundary had flaked 3 times in 27 runs).
 */
export function pinnedClockStart(now = Date.now()) {
  return new Date(Math.floor(now / 1000) * 1000).toISOString().replace(".000Z", ".123456789Z");
}

async function runLocalSession(programs) {
  await mkdir(RUN_DIR, { recursive: true, mode: 0o700 });
  const inPath = join(RUN_DIR, "programs.json");
  const outPath = join(RUN_DIR, "fireemu.json");
  const configPath = join(RUN_DIR, "fireemu.config.json");
  const signersPath = join(RUN_DIR, "signers.json");
  const project = localSigner(SIGNER_ACCOUNTS.project);
  await writeFile(signersPath, JSON.stringify({ project }), { mode: 0o600 });
  await writeFile(
    configPath,
    JSON.stringify({
      schemaVersion: 1,
      profile: "strict",
      daemon: {
        authProjectNumbers: { [SANDBOX_PROJECT]: LOCAL_PROJECT_NUMBER },
        clockStart: pinnedClockStart(),
      },
      auth: {
        idTokenSigning: "session-rsa",
        apiKeys: ["fake-api-key"],
        customTokenSigners: { [project.serviceAccount]: project.jwks },
      },
    }),
  );
  await writeFile(inPath, JSON.stringify(programs));
  const binary = resolveFireemuBinary();
  const child = spawn(
    binary,
    [
      "exec",
      "--config",
      configPath,
      "--project",
      SANDBOX_PROJECT,
      "--only",
      "auth",
      "--http-port",
      String(LOCAL_PORT),
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
      "src/auth-mfa/run.mjs",
      "session-local",
    ],
    {
      cwd: CONFORMANCE_DIR,
      stdio: ["ignore", "inherit", "inherit"],
      env: {
        ...process.env,
        AUTH_MFA_IN: inPath,
        AUTH_MFA_OUT: outPath,
        AUTH_MFA_SIGNERS: signersPath,
        AUTH_MFA_RUN: String(Date.now()),
        AUTH_MFA_ORIGIN: `http://127.0.0.1:${LOCAL_PORT}`,
      },
    },
  );
  const code = await new Promise((resolve) => child.once("exit", resolve));
  if (code !== 0) throw new Error(`fireemu session exited ${code}`);
  return { binary, ...JSON.parse(await readFile(outPath, "utf8")) };
}

/**
 * A phone control start (`auth-mfa/lifetime#control-start-s<age>`) asks with the token of the
 * sign-in just before the enrollment, and a phone enrollment moves `validSince` to its own
 * second. Whether that token is then `TOKEN_EXPIRED` or still valid (`SECOND_FACTOR_EXISTS`)
 * depends only on whether the sign-in and the enrollment fell in the same second: production
 * answered both ways for the same row across the two recordings (s600, s1800). Such a row
 * matches any answer production recorded for a phone control start of the program, and nothing
 * else. The fireemu rule itself is pinned by the adapter tests.
 */
export function timingAlternatives(programId, stepId, saved) {
  const phoneControlStart = /^control-start-s\d+$/;
  if (programId !== "auth-mfa/lifetime" || !phoneControlStart.test(stepId)) return [];
  const known = [];
  for (const recorded of [saved?.steps ?? {}, saved?.second ?? {}]) {
    for (const [id, answer] of Object.entries(recorded)) {
      if (!phoneControlStart.test(id) || isTransient(answer) || answer?.status === -1) continue;
      if (!known.some((seen) => sameRecording(seen, answer))) known.push(answer);
    }
  }
  return known;
}

/**
 * Rows production answered with its per-account TOTP attempt quota (QUOTA_EXCEEDED) and the
 * rows that repeat them below the quota (owner decision M10, auth-mfa/totp/quota-free).
 */
export const REOBSERVED = {
  "auth-mfa/totp/sign-in#replayed-enrollment-code":
    "auth-mfa/totp/quota-free#replayed-enrollment-code",
  "auth-mfa/totp/sign-in#older-unused-code": "auth-mfa/totp/quota-free#older-unused-code",
};

/**
 * An indeterminate row of [`REOBSERVED`] passes only when its re-observation matched and
 * fireemu's own answer on the row is the re-observed production answer (so fireemu's own
 * quota refusal, a server error or an acceptance never passes).
 */
export function reobservedStatus({ row, status, fireemu }, rowsByName) {
  const again = rowsByName.get(REOBSERVED[row]);
  if (status !== "INDETERMINATE" || again === undefined) return status;
  const same = again.status === "MATCH" && !isTransient(fireemu) && sameRecording(again.production, fireemu);
  return same ? "REOBSERVED_MATCH" : status;
}

export function classify({ stale, production, alternative, fireemu, timing = [] }) {
  if (stale) return "STALE_FIXTURE";
  if (production === undefined) return "MISSING_FIXTURE";
  if (fireemu === undefined) return "MISSING";
  const repeatedServerError = production.status >= 500 && alternative === undefined;
  const transient = (recorded) =>
    isTransient(recorded) && !(repeatedServerError && recorded?.status >= 500);
  if ([production, alternative, fireemu].some(transient)) return "INDETERMINATE";
  if (sameRecording(production, fireemu)) return alternative ? "MATCH_NONDETERMINISTIC" : "MATCH";
  if (alternative && sameRecording(alternative, fireemu)) return "MATCH_NONDETERMINISTIC";
  if (timing.some((answer) => sameRecording(answer, fireemu))) return "MATCH_TIMING_DEPENDENT";
  return "MISMATCH";
}

async function check() {
  const fixture = existsSync(FIXTURE)
    ? JSON.parse(await readFile(FIXTURE, "utf8"))
    : { programs: {} };
  const selected = selectedPrograms();
  validateMfaCorpus(selected);
  const harness = await harnessDigest();
  const local = await runLocal(selected);
  const rows = [];
  for (const program of selected) {
    const saved = fixture.programs[program.id];
    const stale =
      saved !== undefined &&
      (saved.corpusDigest !== programDigest(program) || saved.harnessDigest !== harness);
    for (const step of program.steps) {
      const production = saved?.steps?.[step.id];
      const alternative = saved?.second?.[step.id];
      const fireemu = local.results[program.id]?.steps?.[step.id];
      rows.push({
        row: `${program.id}#${step.id}`,
        status: classify({
          stale,
          production,
          alternative,
          fireemu,
          timing: timingAlternatives(program.id, step.id, saved),
        }),
        production,
        ...(alternative ? { alternative } : {}),
        fireemu,
      });
    }
  }
  const rowsByName = new Map(rows.map((r) => [r.row, { status: r.status, production: r.production }]));
  for (const row of rows) row.status = reobservedStatus(row, rowsByName);
  const known = new Set(PROGRAMS.map((p) => p.id));
  const orphans = Object.keys(fixture.programs).filter((id) => !known.has(id));
  const summary = {};
  for (const { status } of rows) summary[status] = (summary[status] ?? 0) + 1;
  const artifactSha256 = sha256(await readFile(local.binary));
  await writeFile(
    join(RUN_DIR, "comparison.json"),
    `${JSON.stringify({ artifact: local.binary, artifactSha256, summary, orphans, failures: local.failures, rows }, null, 2)}\n`,
  );
  const passing = new Set([
    "MATCH",
    "MATCH_NONDETERMINISTIC",
    "MATCH_TIMING_DEPENDENT",
    "REOBSERVED_MATCH",
  ]);
  for (const row of rows.filter((r) => !passing.has(r.status))) {
    console.log(`\n${row.status} ${row.row}`);
    console.log(`  production ${String(JSON.stringify(row.production)).slice(0, 600)}`);
    console.log(`  fireemu    ${String(JSON.stringify(row.fireemu)).slice(0, 600)}`);
  }
  console.log(JSON.stringify({ summary, orphans, failures: local.failures }, null, 2));
  if (!rows.every((r) => passing.has(r.status)) || orphans.length || local.failures.length) {
    process.exitCode = 1;
  }
}

function differenceSummary(production, fireemu) {
  const differences = [];
  const walk = (a, b, path) => {
    if (JSON.stringify(a) === JSON.stringify(b)) return;
    if (
      a &&
      b &&
      typeof a === "object" &&
      typeof b === "object" &&
      Array.isArray(a) === Array.isArray(b)
    ) {
      for (const key of new Set([...Object.keys(a), ...Object.keys(b)]))
        walk(a[key], b[key], `${path}.${key}`);
      return;
    }
    differences.push(path.slice(1));
  };
  walk(production, fireemu, "");
  const code = (recorded) => String(recorded?.body?.error?.message ?? "").split(" : ")[0];
  return {
    differences,
    sameErrorCode: code(production) !== "" && code(production) === code(fireemu),
  };
}

async function exportComparison(out) {
  if (!out) throw new Error("usage: export-comparison <output.json>");
  const comparison = JSON.parse(await readFile(join(RUN_DIR, "comparison.json"), "utf8"));
  const fixtureSha256 = sha256(await readFile(FIXTURE, "utf8"));
  const evidence = {
    kind: "auth-mfa-comparison-v1",
    artifactSha256: comparison.artifactSha256,
    fixtureSha256,
    summary: comparison.summary,
    rows: comparison.rows.map(({ row, status, production, fireemu }) =>
      status === "MISMATCH"
        ? Object.assign({ row, status }, differenceSummary(production, fireemu))
        : { row, status },
    ),
  };
  await writeFile(out, `${JSON.stringify(evidence, null, 2)}\n`);
  console.log(JSON.stringify({ out, summary: evidence.summary, fixtureSha256 }, null, 2));
}

/**
 * Whether a hand restore is due: this task's last ledger line is a `started` line without a
 * terminal line, or an outcome other than a clean recording.
 */
export function restoreDue(ledgerText) {
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
    .filter((entry) => entry?.taskId === TASK_ID && entry.project === SANDBOX_PROJECT);
  const last = entries.at(-1);
  if (!last) return false;
  if (last.event === "started") return true;
  return last.outcome !== "recorded" && !String(last.outcome).startsWith("exploration");
}

/** Whether a recording of this harness is running on this machine. */
async function recordingRunning() {
  try {
    const { stdout } = await execFileAsync("pgrep", ["-f", "auth-mfa/run.mjs record-production"]);
    return stdout.trim().length > 0;
  } catch {
    return false;
  }
}

/**
 * Restores the switches a run changes after a run that could not (SIGKILL, a crash): MFA off
 * exactly as the sandbox baseline has it and password sign-in required, read back. It deletes
 * no account: another lane's accounts cannot be told apart from ours, and every program wipes
 * the project before it starts anyway. Refused unless this task's ledger shows a run that did
 * not end cleanly, while a recording of this harness runs, or while another lane is on the
 * sandbox. A terminal ledger line is written whatever happens.
 */
async function restoreSandbox() {
  const ledger = process.env.FIREEMU_SANDBOX_LEDGER;
  if (!ledger) throw new Error("FIREEMU_SANDBOX_LEDGER is required");
  const text = existsSync(ledger) ? await readFile(ledger, "utf8") : "";
  if (!restoreDue(text)) throw new Error("the ledger shows no run of this task to restore after");
  if (await recordingRunning()) throw new Error("a recording of this harness is still running");
  const busy = otherLaneOnSandbox(text);
  if (busy) throw new Error(`another lane is on the sandbox: ${busy}`);
  const web = await sandboxWebConfig();
  const tokens = [];
  let outcome = "restore-failed";
  let before;
  let restored;
  let error;
  let requests = 0;
  try {
    const ctx = await productionContext(String(Date.now()), web, tokens);
    const session = createSession(ctx, {
      maxHarnessRequests: 40,
      maxCleanupRequests: 40,
      log: (line) => console.log(line),
    });
    before = await session.readConfig(["mfa", "signIn.email.passwordRequired"]);
    restored = await session.writeConfig(
      ["mfa", "signIn.email.passwordRequired"],
      { mfa: MFA_CONFIGS.disabled, "signIn.email.passwordRequired": true },
      { cleanup: true },
    );
    requests = session.counts().harnessRequests;
    await prepareProject(ctx, { apply: false });
    outcome = "restored-by-hand";
  } catch (caught) {
    error = String(caught?.message ?? caught);
  } finally {
    await appendFile(
      ledger,
      `${JSON.stringify({ ts: new Date().toISOString(), project: SANDBOX_PROJECT, database: null, taskId: TASK_ID, outcome, before, restored, requests, ...(error ? { error } : {}) })}\n`,
    );
  }
  if (error) throw new Error(error);
  console.log(JSON.stringify({ before, restored }, null, 2));
}

const mode = process.argv[2];
if (mode === "record-production") await recordProduction();
else if (mode === "rebuild-fixture") await rebuildFixture(process.argv[3]);
else if (mode === "check") await check();
else if (mode === "export-comparison") await exportComparison(process.argv[3]);
else if (mode === "session-local") await sessionLocal();
else if (mode === "restore-sandbox") await restoreSandbox();
else if (mode === "local") {
  const local = await runLocal(selectedPrograms());
  await writeFile(join(RUN_DIR, "fireemu-results.json"), `${JSON.stringify(local, null, 2)}\n`);
  console.log(JSON.stringify({ requests: local.requests, failures: local.failures }, null, 2));
} else if (mode !== undefined) {
  console.error(
    "usage: run.mjs record-production|restore-sandbox|rebuild-fixture|check|export-comparison|local",
  );
  process.exitCode = 2;
}
