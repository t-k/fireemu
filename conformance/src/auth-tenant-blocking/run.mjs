// AUTH-TENANT-BLOCKING sandbox runner (tenant half).
//
//   node src/auth-tenant-blocking/run.mjs record-production   record the corpus twice against the
//                                                             Identity Platform sandbox and
//                                                             update auth-tenant-blocking-production.json
//   node src/auth-tenant-blocking/run.mjs rebuild-fixture <run dir>
//   node src/auth-tenant-blocking/run.mjs check               run the corpus against fireemu and
//                                                             compare with the saved rows
//   node src/auth-tenant-blocking/run.mjs export-comparison <out.json>
//   node src/auth-tenant-blocking/run.mjs restore-sandbox     after a run that could not clean up:
//                                                             delete the harness's tenants, switch
//                                                             multi-tenancy off, restore the
//                                                             project settings, read back
//
// `record-production` needs FIREEMU_AUTH_SANDBOX_WEB_CONFIG (the sandbox web app config JSON,
// kept outside the repository), owner ADC (`gcloud auth application-default`),
// FIREEMU_SANDBOX_LEDGER and FIREEMU_AUTH_TENANT_PRIVATE_DIR. AUTH_TENANT_PROGRAMS selects
// programs by id prefix (AUTH_TENANT_PROGRAMS_EXACT=1: by exact id).
//
// Each program switches multi-tenancy on for its own duration and creates its own tenants; the
// session deletes them, reads the list back and switches multi-tenancy off (owner decision TB2).
// The run requires multi-tenancy off, no tenant, no project account and MFA off before it
// starts and after it ends.

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
import { MFA_CONFIGS } from "../auth-mfa/guard.mjs";
import { BLOCKING_PROGRAMS } from "./blocking-corpus.mjs";
import { PROGRAMS as TENANT_PROGRAMS } from "./corpus.mjs";
import { createDeployer } from "./deploy.mjs";
import { guardTenantRequest, isHarnessDisplayName, validateTenantCorpus } from "./guard.mjs";
import { assertNoOpaqueValue } from "./harness.mjs";
import { createSession, runCorpus, tenantIdOf } from "./session.mjs";

const execFileAsync = promisify(execFile);
const FIXTURE = join(CONFORMANCE_DIR, "auth-tenant-blocking-production.json");
const RUN_DIR = join(CONFORMANCE_DIR, ".runs", "auth-tenant-blocking");
const LOCAL_PORT = 32298;
/** The synthetic project number fireemu is configured with. */
const LOCAL_PROJECT_NUMBER = "123456789012";
/**
 * The suite a run records: the tenant programs (owner decision TB2) or the blocking programs,
 * which run while the blocking fixture is deployed (TB1). Each suite is its own observation
 * task with its own budget and ledger lines.
 */
export const SUITE = process.env.AUTH_TENANT_SUITE === "blocking" ? "blocking" : "tenant";
export const TASK_ID = SUITE === "blocking" ? "AUTH-BLOCKING-SANDBOX" : "AUTH-TENANT-SANDBOX";
const PROGRAMS = SUITE === "blocking" ? BLOCKING_PROGRAMS : TENANT_PROGRAMS;
/** Every program of both suites: one fixture holds them all. */
const ALL_PROGRAMS = [...TENANT_PROGRAMS, ...BLOCKING_PROGRAMS];
/** The blocking fixture's source, served locally by fireemu and deployed to production. */
const FIXTURE_SOURCE = join(CONFORMANCE_DIR, "src", "auth-tenant-blocking", "function");
/** How long the fixture's services may stay public in one recording (TB1: about an hour). */
const PUBLIC_MINUTES = 50;
const sha256 = (text) => createHash("sha256").update(text).digest("hex");

/**
 * The project settings a program may change (T7) and their sandbox baseline: restored by hand
 * after a run that could not clean up.
 */
export const PROJECT_SWITCH_BASELINE = {
  "multiTenant.allowTenants": false,
  "emailPrivacyConfig.enableImprovedEmailPrivacy": true,
  "client.permissions.disabledUserSignup": false,
  "client.permissions.disabledUserDeletion": false,
  "signIn.allowDuplicateEmails": false,
  mfa: MFA_CONFIGS.disabled,
};

function selectedPrograms() {
  const prefixes = (process.env.AUTH_TENANT_PROGRAMS ?? "").split(",").filter(Boolean);
  const exact = process.env.AUTH_TENANT_PROGRAMS_EXACT === "1";
  const programs = prefixes.length
    ? PROGRAMS.filter((p) =>
        prefixes.some((prefix) => (exact ? p.id === prefix : p.id.startsWith(prefix))),
      )
    : PROGRAMS;
  if (programs.length === 0) throw new Error("no program matches AUTH_TENANT_PROGRAMS");
  return programs;
}

const programDigest = (program) => sha256(JSON.stringify(program));

/**
 * Normalization and request semantics a saved row depends on; a change makes it stale. The
 * guard and corpus rules (guard.mjs) only refuse requests and are not part of it.
 */
async function harnessDigest({ blocking = false } = {}) {
  // A blocking program's rows also depend on the fixture the functions run (pre-send review
  // SF-6); the tenant programs' digest stays what their recordings were bound to.
  const fixture = blocking
    ? await Promise.all(
        ["index.js", "package.json", "package-lock.json", "firebase.json"].map((file) =>
          readFile(join(FIXTURE_SOURCE, file), "utf8"),
        ),
      )
    : [];
  const sources = await Promise.all(
    [
      "auth-tenant-blocking/harness.mjs",
      "auth-tenant-blocking/session.mjs",
      "auth-mfa/harness.mjs",
      "auth-mfa/session.mjs",
      "auth-credential/session.mjs",
      "auth-credential/tokens.mjs",
      "auth-account/harness.mjs",
      "auth-account/session.mjs",
    ].map((file) => readFile(join(CONFORMANCE_DIR, "src", file), "utf8")),
  );
  return sha256(
    `${sources.join("\n")}\n${JSON.stringify(BASELINE_CONFIG)}\n${JSON.stringify(AUTHORIZED_DOMAINS)}${fixture.length ? `\n${fixture.join("\n")}` : ""}`,
  );
}

/**
 * Per recording: every step once. The harness budget covers per program the multi-tenancy switch
 * (a write and up to 30 read-backs), the tenants it creates, a program config and a clock read
 * per step; the cleanup reserve covers per program two wipes of up to 41 requests, one delete per
 * tenant seen (the steps may create some), a tenant list, a config restore and the switch back.
 */
const ceilings = (programs) => ({
  maxRequests: programs.reduce((total, p) => total + p.steps.length, 0),
  maxHarnessRequests: programs.reduce(
    (total, p) =>
      total + 40 + Object.keys(p.tenants ?? {}).length + (p.config ? 32 : 0) + p.steps.length,
    20,
  ),
  maxCleanupRequests: programs.reduce(
    (total, p) =>
      total +
      82 +
      Object.keys(p.tenants ?? {}).length +
      p.steps.filter((s) => s.method === "POST" && s.path.endsWith("/tenants")).length +
      2 +
      (p.config ? 31 : 0) +
      31 +
      31,
    41,
  ),
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
      "src/auth-tenant-blocking",
      "src/auth-mfa",
      "src/auth-credential",
      "src/auth-account",
      "auth-tenant-blocking-production.json",
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

/** The authorized domains the sandbox answers with (read 2026-09-24). */
export const AUTHORIZED_DOMAINS = ["{project}.firebaseapp.com", "{project}.web.app"];

/**
 * Whether a tenant list answer shows no tenant. With multi-tenancy off production refuses the
 * list with 400 INVALID_PROJECT_ID (FS-RULES preflight, 2026-09-25), which also means none.
 */
export function listShowsNoTenant(status, body) {
  if (status === 400 && /INVALID_PROJECT_ID/.test(String(body?.error?.message ?? ""))) return true;
  return status === 200 && (body?.tenants ?? []).length === 0;
}

/**
 * The sign-in baseline, the account-behaviour defaults and the authorized domains, MFA off,
 * multi-tenancy off and no tenant: read and required in production, applied locally.
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
  const session = createSession(ctx, { maxHarnessRequests: 80 });
  const switches = Object.keys(PROJECT_SWITCH_BASELINE);
  if (apply) await session.writeConfig(switches, PROJECT_SWITCH_BASELINE);
  const current = await session.readConfig(switches);
  const off = switches.filter(
    (path) => !configMatches(current[path], PROJECT_SWITCH_BASELINE[path]),
  );
  if (off.length) throw new Error(`sandbox switches are not at their baseline: ${off.join(", ")}`);
  const { status, json } = await session.admin("GET", "v2/projects/{project}/tenants", {
    query: { pageSize: 100 },
    accept: [200, 400],
  });
  if (!listShowsNoTenant(status, json)) throw new Error("the sandbox holds tenants");
  return account.counts().harnessRequests + session.counts().harnessRequests;
}

/** Refuses to start while the sandbox holds any project-level account. */
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
  guardTenantRequest(request, ctx, { harness: true });
  const response = await fetch(request.url, { ...request.init, redirect: "error" });
  const body = await response.json().catch(() => null);
  if (response.status !== 200) throw new Error(`account preflight: HTTP ${response.status}`);
  if ((body?.users ?? []).length)
    throw new Error("the sandbox holds accounts: another lane may be recording");
}

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
  const after = await prepareProject(ctx, { apply: false });
  return { ...out, harnessRequests: out.harnessRequests + preparation + after };
}

/** The switches a run changes, read back after a run that stopped early (best effort). */
async function readSwitches(web, tokens) {
  try {
    const ctx = await productionContext(String(Date.now()), web, tokens);
    const session = createSession(ctx, { maxHarnessRequests: 4 });
    return await session.readConfig(Object.keys(PROJECT_SWITCH_BASELINE));
  } catch (error) {
    return { unreadable: String(error?.message ?? error) };
  }
}

/** Whether the project's own signer may mint a custom token (the signJwt binding exists). */
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
      "production Identity Toolkit (v1, v2 tenant management) and Secure Token REST, Identity Platform sandbox, with multi-tenancy switched on per program and the program's own tenants created and deleted (owner decision TB2); phones are configured test numbers only (no SMS is sent, M3) and addresses @example.com (E1); the blocking programs (atb/blocking/*) run while the blocking-function fixture is deployed and registered (TB1) and compare the decoded events it echoes (TB5)",
    project: RECORDED_PROJECT,
    note: "Two recordings per program. Tenants are named per program: <tenant:label:shape> for a tenant the harness created, <tenant:N:shape> for one a step created, where shape is the display-name prefix and the length of the random suffix, or `other`. TOTP secrets, session infos, pending credentials and refresh tokens are placeholders; codes are never recorded. Tokens are recorded as their decoded header shape and claims, with times relative to the token's own iat. Generated ids, run-window times, the project id, its number and the API key are placeholders. `second` holds the other recording of rows that differed.",
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
      ...(one.config ? { config: one.config } : {}),
      ...(Object.keys(differing).length ? { second: differing } : {}),
    };
  }
  fixture.programs = Object.fromEntries(
    Object.entries(fixture.programs).toSorted(([a], [b]) => a.localeCompare(b)),
  );
  const text = `${JSON.stringify(fixture, null, 2)}\n`;
  scanFixture(text, [...secrets, SIGNER_ACCOUNTS.project]);
  assertNoOpaqueValue(text);
  if (/otpauth:|"[A-Z2-7]{32}"/.test(text)) throw new Error("fixture holds a TOTP secret");
  await writeFile(FIXTURE, text);
  return diffRecordings(first.results, second.results);
}

function ledgerEntries(ledgerText) {
  return ledgerText
    .split("\n")
    .filter((line) => line.trim())
    .map((line) => {
      try {
        return JSON.parse(line);
      } catch {
        return undefined;
      }
    })
    .filter(Boolean);
}

/**
 * The per-IP account-creation limit is about 100 per hour, so a run is refused within an hour of
 * this task's last run that did not end cleanly.
 */
export function recentAbort(ledgerText, now = Date.now()) {
  const last = ledgerEntries(ledgerText).findLast(
    (entry) => entry.taskId === TASK_ID && entry.outcome !== undefined,
  );
  const clean = (outcome) => outcome === "recorded" || String(outcome).startsWith("exploration");
  if (!last || clean(last.outcome)) return undefined;
  return now - Date.parse(last.ts) < 3_600_000 ? last : undefined;
}

/**
 * Another lane on the Identity Platform sandbox: a task whose last line there is a `started`
 * event, or any other task's line there within the last 30 minutes (the rule the AUTH lanes and
 * FS-RULES agreed on, 2026-09-25).
 */
export function otherLaneOnSandbox(ledgerText, now = Date.now()) {
  const lines = ledgerEntries(ledgerText).filter(
    (entry) => entry.project === SANDBOX_PROJECT && entry.taskId !== TASK_ID,
  );
  const last = new Map();
  for (const entry of lines) last.set(entry.taskId, entry);
  const open = [...last.values()].find((entry) => entry.event === "started");
  if (open) return `${open.taskId} started at ${open.ts} and has not finished`;
  const recent = lines.find((entry) => now - Date.parse(entry.ts) < 30 * 60_000);
  return recent ? `${recent.taskId} wrote a line at ${recent.ts}` : undefined;
}

async function recordProduction() {
  const ledger = process.env.FIREEMU_SANDBOX_LEDGER;
  const privateRoot = process.env.FIREEMU_AUTH_TENANT_PRIVATE_DIR;
  if (!ledger || !privateRoot) {
    throw new Error("FIREEMU_SANDBOX_LEDGER and FIREEMU_AUTH_TENANT_PRIVATE_DIR are required");
  }
  await assertCleanTree();
  const ledgerText = existsSync(ledger) ? await readFile(ledger, "utf8") : "";
  const aborted = recentAbort(ledgerText);
  if (aborted)
    throw new Error(`the last run aborted at ${aborted.ts}; wait an hour before retrying`);
  const busy = otherLaneOnSandbox(ledgerText);
  if (busy) throw new Error(`another lane is on the sandbox: ${busy}`);
  const programs = selectedPrograms();
  const corpusRequests = validateTenantCorpus(programs);
  const meta = {
    sha: await gitSha(),
    harness: await harnessDigest({ blocking: SUITE === "blocking" }),
    startedAt: new Date().toISOString(),
    programs: programs.map((p) => p.id),
    corpusDigests: Object.fromEntries(programs.map((p) => [p.id, programDigest(p)])),
  };
  const web = await sandboxWebConfig();
  const tokens = [];
  if (programs.some(({ tokens: minted }) => minted)) await assertSignerReady(web, tokens);
  await assertIgnored(privateRoot);
  const runDir = join(
    privateRoot,
    `auth-tenant-blocking-production-${meta.startedAt.replaceAll(":", "")}`,
  );
  await mkdir(runDir, { recursive: true, mode: 0o700 });
  // A first SIGINT, SIGTERM or SIGHUP stops at the next step; the program then deletes its
  // tenants and restores the switches as on any other stop. A later signal only says so.
  const controller = new AbortController();
  let signals = 0;
  const onSignal = (name) => {
    signals += 1;
    if (signals === 1) {
      console.error(`${name}: stopping; the current program deletes its tenants and restores`);
      controller.abort();
    } else {
      console.error(`${name}: cleanup is running; wait for it (restore-sandbox restores by hand)`);
    }
  };
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
  let fixture;
  let deployer;
  let publicDeadline;
  try {
    if (SUITE === "blocking") {
      // The fixture is deployed once for both recordings and removed below whenever a
      // deployment started (TB1; pre-send review MF-1).
      deployer = createDeployer({
        project: SANDBOX_PROJECT,
        number: web.projectNumber,
        token: async () => {
          const token = await adminToken();
          tokens.push(token);
          return token;
        },
        log: (line) => console.log(line),
      });
      fixture = { deployed: false, cli: await deployer.cliVersion() };
      await deployer.preflight();
      await deployer.deploy(FIXTURE_SOURCE, join(runDir, "function-build"));
      fixture.deployed = true;
      // The services are public from here on: stop the recording in time to remove them
      // within the hour TB1 allows (pre-send review SF-2).
      publicDeadline = setTimeout(() => controller.abort(), PUBLIC_MINUTES * 60_000);
      if (controller.signal.aborted) throw new Error("stopped by a signal after the deployment");
      fixture.registered = await deployer.verifyRegistered();
      fixture.invokers = await deployer.invokers();
      console.log(`fixture registered: ${JSON.stringify(fixture)}`);
      if (!Object.values(fixture.invokers).every((admits) => admits === true))
        throw new Error("Identity Platform cannot call every fixture function; not recording");
    }
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
  if (deployer) {
    // Removal runs on every path once a deployment started, a signal and a failed deployment
    // included; before that it removes nothing.
    clearTimeout(publicDeadline);
    try {
      fixture.removed = await deployer.remove(join(runDir, "function-build"));
    } catch (caught) {
      fixture.removed = false;
      outcome = "aborted-fatal";
      error = `${error ? `${error}; ` : ""}fixture removal: ${caught.message ?? caught}`;
      console.error(`FIXTURE NOT REMOVED: ${caught.message ?? caught}`);
    }
    fixture.requests = deployer.requests();
  }
  await writeFile(
    join(runDir, "meta.json"),
    JSON.stringify({ ...meta, outcome, error, switchesAfter }, null, 2),
    { mode: 0o600 },
  );
  const requests = recordings.reduce((n, r) => n + r.requests + r.harnessRequests, 0);
  const tenantsCreated = recordings.reduce((n, r) => n + (r.tenantsCreated ?? 0), 0);
  const tenantsDeleted = recordings.reduce((n, r) => n + (r.tenantsDeleted ?? 0), 0);
  // Every project setting a recording switches and restores (sandbox-oracles.md: record every
  // change in the ledger line).
  const switched = [
    "multiTenant.allowTenants",
    ...new Set(programs.flatMap((program) => Object.keys(program.config ?? {}))),
  ];
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
        // The deployment's Cloud Build, storage and Cloud Run are well under a dollar (SF-7).
        estimatedUsd: SUITE === "blocking" ? 0.5 : 0,
        outcome,
        taskId: TASK_ID,
        programs: meta.programs,
        tenantsCreated,
        tenantsDeleted,
        switched,
        ...(fixture ? { fixture } : {}),
        ...(error ? { error } : {}),
        ...(switchesAfter ? { switchesAfter } : {}),
      })}\n`,
    );
    // A fixture that could not be removed keeps every other lane off the sandbox until it is
    // removed by hand and a terminal line follows (SF-1).
    if (fixture?.removed === false)
      await appendFile(
        ledger,
        `${JSON.stringify({ ts: new Date().toISOString(), event: "started", taskId: TASK_ID, project: SANDBOX_PROJECT, reason: "fixture not removed; restore-sandbox removes it" })}\n`,
      );
    for (const name of signalNames) process.off(name, onSignal);
  }
  if (error) throw new Error(error);
  if (failures.length) process.exitCode = 1;
}

/** Retries the fixture from a saved run directory; sends nothing to production. */
async function rebuildFixture(runDir) {
  const meta = JSON.parse(await readFile(join(runDir, "meta.json"), "utf8"));
  if (meta.harness !== (await harnessDigest({ blocking: SUITE === "blocking" })))
    throw new Error("harness changed since the recording");
  const recordings = await Promise.all(
    [1, 2].map(async (n) =>
      JSON.parse(await readFile(join(runDir, `recording-${n}.json`), "utf8")),
    ),
  );
  const programs = ALL_PROGRAMS.filter((p) => meta.programs.includes(p.id));
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
  const programs = JSON.parse(await readFile(process.env.AUTH_TENANT_IN, "utf8"));
  const signers = JSON.parse(await readFile(process.env.AUTH_TENANT_SIGNERS, "utf8"));
  const ctx = createContext({
    run: process.env.AUTH_TENANT_RUN,
    project: SANDBOX_PROJECT,
    target: {
      kind: "local",
      origin: process.env.AUTH_TENANT_ORIGIN,
      projectNumber: LOCAL_PROJECT_NUMBER,
      control: { url: process.env.FIREEMU_CONTROL_URL, token: process.env.FIREEMU_CONTROL_TOKEN },
    },
  });
  const preparation = await prepareProject(ctx, { apply: true });
  const out = await runCorpus(programs, ctx, { ...ceilings(programs), signers });
  await writeFile(
    process.env.AUTH_TENANT_OUT,
    JSON.stringify({ ...out, harnessRequests: out.harnessRequests + preparation }),
  );
}

/** The local session's clock starts pinned at the current second (see AUTH-MFA). */
export function pinnedClockStart(now = Date.now()) {
  return new Date(Math.floor(now / 1000) * 1000).toISOString().replace(".000Z", ".123456789Z");
}

/** Runs each program in a fireemu session of its own. */
async function runLocal(programs) {
  const merged = { results: {}, failures: [], secrets: [], requests: 0, harnessRequests: 0 };
  let binary;
  for (const program of programs) {
    const local = await runLocalSession([program]);
    binary = local.binary;
    Object.assign(merged.results, local.results);
    merged.failures.push(...local.failures);
    merged.secrets.push(...(local.secrets ?? []));
    merged.requests += local.requests;
    merged.harnessRequests += local.harnessRequests;
  }
  return { binary, ...merged };
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
  const functions = programs.some((program) => program.functions);
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
      functions ? "auth,functions" : "auth",
      ...(functions
        ? ["--functions", FIXTURE_SOURCE, "--functions-port", String(LOCAL_PORT + 1)]
        : []),
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
      "src/auth-tenant-blocking/run.mjs",
      "session-local",
    ],
    {
      cwd: CONFORMANCE_DIR,
      stdio: ["ignore", "inherit", "inherit"],
      env: {
        ...process.env,
        AUTH_TENANT_IN: inPath,
        AUTH_TENANT_OUT: outPath,
        AUTH_TENANT_SIGNERS: signersPath,
        AUTH_TENANT_RUN: String(Date.now()),
        AUTH_TENANT_ORIGIN: `http://127.0.0.1:${LOCAL_PORT}`,
      },
    },
  );
  const code = await new Promise((resolve) => child.once("exit", resolve));
  if (code !== 0) throw new Error(`fireemu session exited ${code}`);
  return { binary, ...JSON.parse(await readFile(outPath, "utf8")) };
}

export function classify({ stale, production, alternative, fireemu }) {
  if (stale) return "STALE_FIXTURE";
  if (production === undefined) return "MISSING_FIXTURE";
  if (fireemu === undefined) return "MISSING";
  const repeatedServerError = production.status >= 500 && alternative === undefined;
  const transient = (recorded) =>
    isTransient(recorded) && !(repeatedServerError && recorded?.status >= 500);
  if ([production, alternative, fireemu].some(transient)) return "INDETERMINATE";
  if (sameRecording(production, fireemu)) return alternative ? "MATCH_NONDETERMINISTIC" : "MATCH";
  if (alternative && sameRecording(alternative, fireemu)) return "MATCH_NONDETERMINISTIC";
  return "MISMATCH";
}

async function check() {
  const fixture = existsSync(FIXTURE)
    ? JSON.parse(await readFile(FIXTURE, "utf8"))
    : { programs: {} };
  const selected = selectedPrograms();
  validateTenantCorpus(selected);
  const harnesses = {
    tenant: await harnessDigest(),
    blocking: await harnessDigest({ blocking: true }),
  };
  const local = await runLocal(selected);
  const rows = [];
  for (const program of selected) {
    const saved = fixture.programs[program.id];
    const stale =
      saved !== undefined &&
      (saved.corpusDigest !== programDigest(program) ||
        saved.harnessDigest !== harnesses[program.functions ? "blocking" : "tenant"]);
    for (const step of program.steps) {
      const production = saved?.steps?.[step.id];
      const alternative = saved?.second?.[step.id];
      const fireemu = local.results[program.id]?.steps?.[step.id];
      rows.push({
        row: `${program.id}#${step.id}`,
        status: classify({ stale, production, alternative, fireemu }),
        production,
        ...(alternative ? { alternative } : {}),
        fireemu,
      });
    }
  }
  const known = new Set(ALL_PROGRAMS.map((p) => p.id));
  const orphans = Object.keys(fixture.programs).filter((id) => !known.has(id));
  const summary = {};
  for (const { status } of rows) summary[status] = (summary[status] ?? 0) + 1;
  const artifactSha256 = sha256(await readFile(local.binary));
  await writeFile(
    join(RUN_DIR, "comparison.json"),
    `${JSON.stringify({ artifact: local.binary, artifactSha256, summary, orphans, failures: local.failures, rows }, null, 2)}\n`,
  );
  const passing = new Set(["MATCH", "MATCH_NONDETERMINISTIC"]);
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
    kind: "auth-tenant-blocking-comparison-v1",
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

/** Whether a hand restore is due: this task's last line is `started`, or not a clean recording. */
export function restoreDue(ledgerText) {
  const last = ledgerEntries(ledgerText).findLast(
    (entry) => entry.taskId === TASK_ID && entry.project === SANDBOX_PROJECT,
  );
  if (!last) return false;
  if (last.event === "started") return true;
  return last.outcome !== "recorded" && !String(last.outcome).startsWith("exploration");
}

async function recordingRunning() {
  try {
    const { stdout } = await execFileAsync("pgrep", [
      "-f",
      "auth-tenant-blocking/run.mjs record-production",
    ]);
    return stdout.trim().length > 0;
  } catch {
    return false;
  }
}

/**
 * After a run that could not clean up (SIGKILL, a crash): switches multi-tenancy on, deletes
 * every tenant whose display name starts with the harness prefix, reads the list back, restores
 * the project switches to their baseline and reads them back. It deletes no account. Refused
 * unless this task's ledger shows a run that did not end cleanly, while a recording of this
 * harness runs, or while another lane is on the sandbox. A terminal ledger line is always
 * written.
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
  let deleted = 0;
  let nameless = 0;
  let fixtureRemoved;
  let error;
  let requests = 0;
  const switches = Object.keys(PROJECT_SWITCH_BASELINE);
  let session;
  try {
    const ctx = await productionContext(String(Date.now()), web, tokens);
    session = createSession(ctx, {
      maxHarnessRequests: 80,
      maxCleanupRequests: 200,
      log: (line) => console.log(line),
    });
    if (SUITE === "blocking") {
      // A blocking run that could not remove its fixture: remove it first (pre-send review SF-1).
      const deployer = createDeployer({
        project: SANDBOX_PROJECT,
        number: web.projectNumber,
        token: async () => {
          const token = await adminToken();
          tokens.push(token);
          return token;
        },
        log: (line) => console.log(line),
      });
      deployer.adoptLeftovers();
      fixtureRemoved = await deployer.remove(
        join(process.env.FIREEMU_AUTH_TENANT_PRIVATE_DIR ?? CONFORMANCE_DIR, "restore-build"),
      );
    }
    before = await session.readConfig(switches);
    await session.writeConfig(
      ["multiTenant.allowTenants"],
      { "multiTenant.allowTenants": true },
      { cleanup: true },
    );
    const listed = await session.listTenants({ cleanup: true });
    for (const { id } of listed.filter(({ displayName }) => isHarnessDisplayName(displayName))) {
      await session.deleteHarnessTenant(id);
      deleted += 1;
    }
    const after = await session.listTenants({ cleanup: true });
    const left = after.filter(({ displayName }) => isHarnessDisplayName(displayName));
    if (left.length) throw new Error(`${left.length} harness tenants remain`);
    // A tenant without a display name may be the management program's nameless create or
    // another lane's: it is reported, never deleted (pre-send review MF-4).
    nameless = after.filter(({ displayName }) => !displayName).length;
    // Stop before multi-tenancy goes off: once it is off a nameless tenant no longer lists
    // (confirmation SF-C). The switches stay for the hand check.
    if (nameless)
      throw new Error(
        `${nameless} tenants without a display name remain; multi-tenancy left on for a hand check`,
      );
    await session.writeConfig(switches, PROJECT_SWITCH_BASELINE, { cleanup: true });
    await prepareProject(ctx, { apply: false });
    outcome = "restored-by-hand";
  } catch (caught) {
    error = String(caught?.message ?? caught);
  } finally {
    requests = session?.counts().harnessRequests ?? 0;
    await appendFile(
      ledger,
      `${JSON.stringify({ ts: new Date().toISOString(), project: SANDBOX_PROJECT, database: null, taskId: TASK_ID, outcome, before, deletedTenants: deleted, namelessTenants: nameless, ...(fixtureRemoved ? { fixtureRemoved } : {}), requests, ...(error ? { error } : {}) })}\n`,
    );
  }
  if (error) throw new Error(error);
  console.log(JSON.stringify({ before, deletedTenants: deleted }, null, 2));
}

/** The tenant id a tenant resource name ends with (re-exported for the tests). */
export { tenantIdOf };

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
