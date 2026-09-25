// AUTH-CONFIG-SDK sandbox runner.
//
//   node src/auth-config-sdk/run.mjs record-production   record the corpus twice against the
//                                                        Identity Platform sandbox and update
//                                                        auth-config-sdk-production.json
//   node src/auth-config-sdk/run.mjs rebuild-fixture <run dir>
//   node src/auth-config-sdk/run.mjs check               run the corpus against fireemu and
//                                                        compare with the saved production rows
//   node src/auth-config-sdk/run.mjs export-comparison <out.json>
//   node src/auth-config-sdk/run.mjs restore-sandbox     write the sandbox baseline back after a
//                                                        run that could not (crash, SIGKILL)
//
// `record-production` needs FIREEMU_AUTH_SANDBOX_WEB_CONFIG (the sandbox web app config JSON,
// kept outside the repository), owner ADC (`gcloud auth application-default`),
// FIREEMU_SANDBOX_LEDGER and FIREEMU_AUTH_CONFIG_SDK_PRIVATE_DIR. AUTH_CONFIG_SDK_PROGRAMS
// selects programs by id prefix (AUTH_CONFIG_SDK_PROGRAMS_EXACT=1: by exact id).
//
// The sandbox is shared with other lanes: a run refuses to start while another task's ledger
// line on the project is an open `started` line or is less than 30 minutes old, writes its own
// `started` line first and a terminal line at the end, and checks the whole configuration
// baseline this corpus may change before and after each recording.

import { execFile, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { appendFile, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";

import { CONFORMANCE_DIR } from "../config.mjs";
import { resolveFireemuBinary } from "../evidence.mjs";
import { scanFixture } from "../auth-account/fixture-scan.mjs";
import {
  RECORDED_PROJECT,
  SANDBOX_PROJECT,
  TEST_PHONES,
  TEST_PHONE_CODE,
  createContext,
  diffRecordings,
  isTransient,
  sameRecording,
} from "../auth-account/harness.mjs";
import { PROGRAMS } from "./corpus.mjs";
import { SIGNER_ACCOUNT, guardHttp, validateConfigSdkCorpus } from "./guard.mjs";
import { SDK_OPERATIONS, harnessFetch } from "./sdk.mjs";
import { configDrift, configEquals, createSession, runCorpus } from "./session.mjs";

const execFileAsync = promisify(execFile);
const FIXTURE = join(CONFORMANCE_DIR, "auth-config-sdk-production.json");
const RUN_DIR = join(CONFORMANCE_DIR, ".runs", "auth-config-sdk");
/** One fireemu per projection (scope decision K5). */
const LOCAL = {
  strict: { port: 32320, profile: "strict", idTokenSigning: "session-rsa" },
  "strict-unsigned-emulator": {
    port: 32321,
    profile: "strict",
    idTokenSigning: "unsigned-emulator",
  },
  emulator: { port: 32322, profile: "emulator", idTokenSigning: "unsigned-emulator" },
};
/** The synthetic project number fireemu is configured with. */
const LOCAL_PROJECT_NUMBER = "123456789012";
const TASK_ID = "AUTH-CONFIG-SDK-SANDBOX";
const sha256 = (text) => createHash("sha256").update(text).digest("hex");

/**
 * Every config path this corpus may change, at the value the sandbox holds between runs (read
 * 2026-09-25). Production is required to hold it before and after each recording; fireemu is
 * given the sign-in part and the authorized domains, the rest being its own defaults.
 */
export const SANDBOX_BASELINE = {
  "signIn.email.enabled": true,
  "signIn.email.passwordRequired": true,
  "signIn.anonymous.enabled": true,
  "signIn.phoneNumber.enabled": true,
  "signIn.phoneNumber.testPhoneNumbers": Object.fromEntries(
    TEST_PHONES.map((p) => [p, TEST_PHONE_CODE]),
  ),
  authorizedDomains: ["{project}.firebaseapp.com", "{project}.web.app"],
  "signIn.allowDuplicateEmails": undefined,
  "emailPrivacyConfig.enableImprovedEmailPrivacy": true,
  passwordPolicyConfig: undefined,
  "client.permissions.disabledUserSignup": undefined,
  "client.permissions.disabledUserDeletion": undefined,
  // Once written, production keeps a reCAPTCHA config: clearing it leaves both providers
  // unspecified (sandbox, 2026-09-24 22:2xZ). It answers clients as an unset one does.
  recaptchaConfig: {
    emailPasswordEnforcementState: "RECAPTCHA_PROVIDER_ENFORCEMENT_STATE_UNSPECIFIED",
    phoneEnforcementState: "RECAPTCHA_PROVIDER_ENFORCEMENT_STATE_UNSPECIFIED",
    useSmsBotScore: false,
    useSmsTollFraudProtection: false,
  },
  "quota.signUpQuotaConfig": undefined,
  "mobileLinksConfig.domain": "HOSTING_DOMAIN",
  smsRegionConfig: { allowByDefault: {} },
  "notification.defaultLocale": "en",
  "notification.sendEmail.resetPasswordTemplate.subject": "Reset your password for %APP_NAME%",
  autodeleteAnonymousUsers: undefined,
  "monitoring.requestLogging.enabled": undefined,
};
/** What fireemu is given; the other baseline paths must already be its defaults. */
const APPLIED_LOCALLY = [
  "signIn.email.enabled",
  "signIn.email.passwordRequired",
  "signIn.anonymous.enabled",
  "signIn.phoneNumber.enabled",
  "signIn.phoneNumber.testPhoneNumbers",
  "authorizedDomains",
  // The sandbox allows SMS to every region; a new project allows none.
  "smsRegionConfig",
  // The sandbox keeps the reCAPTCHA config an earlier run wrote; a new project has none.
  "recaptchaConfig",
];

function selectedPrograms() {
  const prefixes = (process.env.AUTH_CONFIG_SDK_PROGRAMS ?? "").split(",").filter(Boolean);
  const exact = process.env.AUTH_CONFIG_SDK_PROGRAMS_EXACT === "1";
  const programs = prefixes.length
    ? PROGRAMS.filter((p) =>
        prefixes.some((prefix) => (exact ? p.id === prefix : p.id.startsWith(prefix))),
      )
    : PROGRAMS;
  if (programs.length === 0) throw new Error("no program matches AUTH_CONFIG_SDK_PROGRAMS");
  return programs;
}

const programDigest = (program) => sha256(JSON.stringify(program));

/**
 * Normalization, request semantics and SDK versions a saved row depends on; a change makes it
 * stale. The guard and corpus rules (guard.mjs) only refuse requests and are not part of it.
 */
async function harnessDigest() {
  const sources = await Promise.all(
    [
      "auth-config-sdk/harness.mjs",
      "auth-config-sdk/session.mjs",
      "auth-config-sdk/sdk.mjs",
      "auth-action/harness.mjs",
      "auth-credential/session.mjs",
      "auth-credential/tokens.mjs",
      "auth-account/harness.mjs",
    ].map((file) => readFile(join(CONFORMANCE_DIR, "src", file), "utf8")),
  );
  const versions = await sdkVersions();
  return sha256(
    `${sources.join("\n")}\n${JSON.stringify(SANDBOX_BASELINE)}\n${JSON.stringify(versions)}`,
  );
}

async function sdkVersions() {
  const version = async (name) =>
    JSON.parse(await readFile(join(CONFORMANCE_DIR, "node_modules", name, "package.json"), "utf8"))
      .version;
  return {
    "firebase-admin": await version("firebase-admin"),
    firebase: await version("firebase"),
    "@firebase/auth": await version("@firebase/auth"),
  };
}

/**
 * Per recording: every step once; the SDKs' own requests (at most 8 per SDK step); the harness
 * budget for snapshots and settles; wipes and restores from a separate reserve.
 */
const ceilings = (programs) => ({
  maxRequests: programs.reduce((total, p) => total + p.steps.filter((s) => !s.sdk).length, 0),
  maxSdkRequests: programs.reduce((total, p) => total + 8 * p.steps.filter((s) => s.sdk).length, 0),
  maxHarnessRequests: programs.reduce(
    (total, p) =>
      total +
      4 +
      (p.touches?.length ? 1 : 0) +
      31 * p.steps.filter((s) => s.settle || s.settleTo).length,
    60,
  ),
  maxCleanupRequests: programs.reduce((total, p) => total + 82 + (p.touches?.length ? 32 : 0), 41),
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
      "src/auth-config-sdk",
      "src/auth-action",
      "src/auth-credential",
      "src/auth-account",
      "auth-config-sdk-production.json",
      "package.json",
      "pnpm-lock.yaml",
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

const substituteProject = (value, project) =>
  JSON.parse(JSON.stringify(value ?? null).replaceAll("{project}", project)) ?? undefined;

/** Whether a project's `mfa` config enables no second factor. */
export function mfaDisabled(mfa) {
  if (mfa === undefined || mfa === null) return true;
  const enabled = (state) => state === "ENABLED" || state === "MANDATORY";
  return (
    !enabled(mfa.state) && !(mfa.providerConfigs ?? []).some((provider) => enabled(provider?.state))
  );
}

/**
 * The configuration baseline: every path this corpus may change is read and required in
 * production (and MFA off, which AUTH-MFA owns); locally the sign-in part and the authorized
 * domains are applied and the rest must already be fireemu's defaults.
 */
async function prepareProject(ctx, { apply }) {
  const session = createSession(ctx, { maxHarnessRequests: 10, maxCleanupRequests: 40 });
  const baseline = Object.fromEntries(
    Object.entries(SANDBOX_BASELINE).map(([path, value]) => [
      path,
      substituteProject(value, ctx.project),
    ]),
  );
  if (apply) {
    await session.restore(Object.fromEntries(APPLIED_LOCALLY.map((p) => [p, baseline[p]])));
  }
  const current = await session.readConfig([...Object.keys(baseline), "mfa"]);
  const drift = Object.keys(baseline).filter(
    (path) => !configEquals(current[path], baseline[path]),
  );
  if (drift.length && ctx.target.kind === "production")
    throw new Error(`sandbox configuration differs from its baseline at ${drift.join(", ")}`);
  if (drift.length)
    console.error(`fireemu defaults differ from the sandbox at ${drift.join(", ")}`);
  if (ctx.target.kind === "production" && !mfaDisabled(current.mfa))
    throw new Error(`sandbox MFA is not disabled: ${JSON.stringify(current.mfa)}`);
  return session.counts().harnessRequests;
}

function productionTarget(web) {
  let token;
  let fetchedAt = 0;
  const target = {
    kind: "production",
    apiKey: web.apiKey,
    adminToken: undefined,
    quotaProject: SANDBOX_PROJECT,
    projectNumber: web.projectNumber,
    async refresh() {
      if (token && Date.now() - fetchedAt < 30 * 60_000) return;
      token = await adminToken();
      fetchedAt = Date.now();
      target.adminToken = token;
    },
  };
  return target;
}

/**
 * Whether the owner may sign through the project's Admin SDK account (the time-limited
 * signBlob binding of owner decision K6 exists): checked before the run starts.
 */
async function assertSignerReady(web) {
  const target = productionTarget(web);
  await target.refresh();
  const ctx = createContext({ run: String(Date.now()), project: SANDBOX_PROJECT, target });
  const url = `https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/${SIGNER_ACCOUNT}:signBlob`;
  const init = {
    method: "POST",
    headers: {
      authorization: `Bearer ${target.adminToken}`,
      "x-goog-user-project": SANDBOX_PROJECT,
      "content-type": "application/json",
    },
    body: JSON.stringify({ payload: Buffer.from("preflight").toString("base64") }),
  };
  guardHttp({ url, ...init }, ctx, { role: "sdk-admin" });
  const response = await harnessFetch(url, { ...init, redirect: "error" });
  if (response.status !== 200)
    throw new Error(`signBlob preflight: HTTP ${response.status} (create the K6 binding first)`);
}

async function recordOnce(programs, run, web, { signal, log }) {
  const target = productionTarget(web);
  await target.refresh();
  const ctx = createContext({ run, project: SANDBOX_PROJECT, target });
  const preparation = await prepareProject(ctx, { apply: false });
  const out = await runCorpus(programs, ctx, { ...ceilings(programs), log, signal });
  const after = await prepareProject(ctx, { apply: false });
  return {
    ...out,
    harnessRequests: out.harnessRequests + preparation + after,
    secrets: [target.adminToken],
  };
}

async function writeFixture({ programs, recordings, meta, secrets }) {
  const [first, second] = recordings;
  const fixture = existsSync(FIXTURE)
    ? JSON.parse(await readFile(FIXTURE, "utf8"))
    : { version: 1, recordedAgainst: {}, programs: {} };
  fixture.recordedAgainst = {
    target:
      "production Identity Toolkit and Secure Token REST and the declared SDKs (firebase-admin for Node, the Web SDK in Node), Identity Platform sandbox; action codes from the Admin sendOobCode with returnOobLink (nothing is mailed)",
    project: RECORDED_PROJECT,
    sdkVersions: meta.sdkVersions,
    note: "Two recordings per program. A configuration is recorded without the members other lanes own (mfa, multiTenant, blockingFunctions; scope decisions K9 and K10) and with key material as placeholders (K12). SDK rows are `{sdk: ok, value}` or `{sdk: error, code, message}`. Tokens are recorded as their claims with times relative to iat; action links as their query parameters. `second` holds the other recording of rows that differed.",
    baseline: SANDBOX_BASELINE,
  };
  for (const program of programs) {
    const one = first.results[program.id];
    const two = second.results[program.id];
    if (!one || !two) continue;
    const differing = Object.fromEntries(
      Object.entries(two.steps).filter(([id, rec]) => !sameRecording(rec, one.steps[id])),
    );
    fixture.programs[program.id] = {
      projection: program.projection,
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
  if (/oobcode(=|%3d)|apikey(=|%3d)/i.test(text))
    throw new Error("fixture holds a raw action link");
  if (/"(signerKey|saltSeparator)":\s*"(?!<bytes>)/.test(text))
    throw new Error("fixture holds password-hash key material");
  await writeFile(FIXTURE, text);
  return diffRecordings(first.results, second.results);
}

/**
 * The ledger's lines. A line that does not parse is refused rather than skipped: a lane cannot
 * be sure the sandbox is free when it cannot read what another lane wrote.
 */
function ledgerEntries(ledgerText) {
  return ledgerText
    .split("\n")
    .filter((line) => line.trim())
    .map((line, index) => {
      try {
        return JSON.parse(line);
      } catch {
        throw new Error(`ledger line ${index + 1} does not parse; read it before starting`);
      }
    });
}

/** Older lines name their task as `task`. */
const taskOf = (entry) => entry.taskId ?? entry.task ?? "<unnamed>";

/** Outcomes after which this task left the sandbox at its baseline. */
const cleanOutcome = (entry) =>
  entry.sandboxAtBaseline === true ||
  entry.outcome === "recorded" ||
  String(entry.outcome).startsWith("exploration");

/**
 * The per-IP account-creation limit is about 100 per hour, so a recording is refused within an
 * hour of this task's last recording that did not end as a clean recording.
 */
export function recentAbort(ledgerText, now = Date.now()) {
  const last = ledgerEntries(ledgerText)
    .filter((entry) => taskOf(entry) === TASK_ID && entry.outcome !== undefined && entry.programs)
    .at(-1);
  if (!last || last.outcome === "recorded" || String(last.outcome).startsWith("exploration"))
    return undefined;
  const age = now - Date.parse(last.ts);
  return Number.isNaN(age) || age < 3_600_000 ? last : undefined;
}

/**
 * Another lane on the Identity Platform sandbox: a task whose last line there is `started`, or
 * any other task's line there within the last 30 minutes (the rule agreed with the FS-RULES and
 * AUTH-MFA lanes, 2026-09-25). A line whose time does not parse counts as recent. Programs wipe
 * every account and change the project config, so two recordings must never overlap.
 */
export function otherLaneOnSandbox(ledgerText, now = Date.now()) {
  const lines = ledgerEntries(ledgerText).filter(
    (entry) => entry.project === SANDBOX_PROJECT && taskOf(entry) !== TASK_ID,
  );
  const last = new Map();
  for (const entry of lines) last.set(taskOf(entry), entry);
  const open = [...last.values()].find((entry) => entry.event === "started");
  if (open) return `${taskOf(open)} started at ${open.ts} and has not finished`;
  const recent = lines.find((entry) => {
    const age = now - Date.parse(entry.ts);
    return Number.isNaN(age) || age < 30 * 60_000;
  });
  return recent ? `${taskOf(recent)} wrote a line at ${recent.ts}` : undefined;
}

/**
 * Lines another task wrote on the sandbox after the first `offset` characters of the ledger,
 * which is what this run read before it decided to start (a race with its `started` line).
 */
export function linesAfter(ledgerText, offset) {
  return ledgerEntries(ledgerText.slice(offset)).filter(
    (entry) => entry.project === SANDBOX_PROJECT && taskOf(entry) !== TASK_ID,
  );
}

const lockPath = (ledger) => `${ledger}.auth-config-sdk.lock`;

/** Whether the process named in the lock still runs. */
function lockHolderAlive(text) {
  const pid = Number(/"pid":(\d+)/.exec(text)?.[1]);
  if (!pid) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

/** Takes the lane's lock (created exclusively), or refuses while its holder runs. */
async function takeLock(ledger, what) {
  const path = lockPath(ledger);
  if (existsSync(path)) {
    const text = await readFile(path, "utf8");
    if (lockHolderAlive(text)) throw new Error(`${path} is held: ${text.trim()}`);
    throw new Error(`${path} is stale (${text.trim()}); remove it after checking no run is live`);
  }
  await writeFile(path, JSON.stringify({ pid: process.pid, what, at: new Date().toISOString() }), {
    flag: "wx",
    mode: 0o600,
  });
  return async () => rm(path, { force: true });
}

async function appendLedger(ledger, entry) {
  await appendFile(ledger, `${JSON.stringify({ ts: new Date().toISOString(), ...entry })}\n`);
}

/**
 * Whether the sandbox is back at its baseline after a run that did not end cleanly: every
 * baseline path reads back, MFA is off and no account is left. Never throws.
 */
async function verifyBaseline(web, startConfig) {
  try {
    const target = productionTarget(web);
    await target.refresh();
    const ctx = createContext({ run: String(Date.now()), project: SANDBOX_PROJECT, target });
    await prepareProject(ctx, { apply: false });
    const session = createSession(ctx, { maxHarnessRequests: 2, maxCleanupRequests: 2 });
    if ((await session.accountCount()) !== 0) return { atBaseline: false, reason: "accounts left" };
    // Also every member outside the baseline paths, against the run's first read.
    const drift = configDrift(startConfig, await session.fullConfig());
    return drift.length
      ? { atBaseline: false, reason: `configuration changed at ${drift.join(", ")}` }
      : { atBaseline: true };
  } catch (error) {
    return { atBaseline: false, reason: String(error.message ?? error) };
  }
}

/** Refuses a key that is not the sandbox's: `v1/projects` names the project by its number. */
async function assertSandboxKey(web) {
  const url = `https://identitytoolkit.googleapis.com/v1/projects?key=${encodeURIComponent(web.apiKey)}`;
  const target = productionTarget(web);
  const ctx = createContext({
    run: String(Date.now()),
    project: SANDBOX_PROJECT,
    target: { ...target, adminToken: "unused" },
  });
  guardHttp({ url, method: "GET" }, ctx, { role: "harness" });
  const response = await harnessFetch(url, { redirect: "error" });
  const body = await response.json().catch(() => ({}));
  if (response.status !== 200 || body.projectId !== web.projectNumber)
    throw new Error("the web config's API key does not answer as the sandbox project");
}

async function recordProduction() {
  const ledger = process.env.FIREEMU_SANDBOX_LEDGER;
  const privateRoot = process.env.FIREEMU_AUTH_CONFIG_SDK_PRIVATE_DIR;
  if (!ledger || !privateRoot) {
    throw new Error("FIREEMU_SANDBOX_LEDGER and FIREEMU_AUTH_CONFIG_SDK_PRIVATE_DIR are required");
  }
  if (process.env.GOOGLE_APPLICATION_CREDENTIALS)
    throw new Error(
      "GOOGLE_APPLICATION_CREDENTIALS is set; the sandbox track uses the owner's ADC",
    );
  await assertCleanTree();
  const programs = selectedPrograms();
  const corpusRequests = validateConfigSdkCorpus(programs, { sdkOperations: SDK_OPERATIONS });
  const web = await sandboxWebConfig();
  await assertIgnored(privateRoot);
  const release = await takeLock(ledger, "record-production");
  try {
    await recordLocked({ ledger, privateRoot, programs, corpusRequests, web });
  } finally {
    await release();
  }
}

async function recordLocked({ ledger, privateRoot, programs, corpusRequests, web }) {
  const ledgerText = existsSync(ledger) ? await readFile(ledger, "utf8") : "";
  if (restoreDue(ledgerText))
    throw new Error(
      "this task's last run did not leave the sandbox at its baseline; run restore-sandbox",
    );
  const aborted = recentAbort(ledgerText);
  if (aborted)
    throw new Error(`the last run ended ${aborted.outcome} at ${aborted.ts}; wait an hour`);
  const busy = otherLaneOnSandbox(ledgerText);
  if (busy) throw new Error(`another lane is on the sandbox: ${busy}`);
  const meta = {
    sha: await gitSha(),
    harness: await harnessDigest(),
    sdkVersions: await sdkVersions(),
    startedAt: new Date().toISOString(),
    programs: programs.map((p) => p.id),
    corpusDigests: Object.fromEntries(programs.map((p) => [p.id, programDigest(p)])),
  };
  await assertSandboxKey(web);
  let startConfig;
  if (programs.some((p) => p.steps.some((s) => s.sdk === "admin.createCustomToken")))
    await assertSignerReady(web);
  {
    // Another lane's leftover accounts are its own to inspect; this run starts on none.
    const target = productionTarget(web);
    await target.refresh();
    const ctx = createContext({ run: String(Date.now()), project: SANDBOX_PROJECT, target });
    const session = createSession(ctx, { maxHarnessRequests: 2, maxCleanupRequests: 2 });
    const count = await session.accountCount();
    if (count !== 0) throw new Error(`the sandbox holds ${count}+ accounts; it must start empty`);
    // A drifted baseline is reported before anything is written to the ledger.
    await prepareProject(ctx, { apply: false });
    startConfig = await session.fullConfig();
  }
  const runDir = join(
    privateRoot,
    `auth-config-sdk-production-${meta.startedAt.replaceAll(":", "")}`,
  );
  await mkdir(runDir, { recursive: true, mode: 0o700 });
  // A first signal stops at the next step; the program then wipes its accounts and restores
  // the config as on any other stop. Later signals only say so.
  const controller = new AbortController();
  let signals = 0;
  const onSignal = (name) => {
    signals += 1;
    if (signals === 1) {
      console.error(`${name}: stopping; the current program wipes and restores the config`);
      controller.abort();
    } else console.error(`${name}: cleanup is running (restore-sandbox restores by hand)`);
  };
  for (const name of ["SIGINT", "SIGTERM", "SIGHUP"]) process.on(name, onSignal);
  const ignoreWriteError = () => {};
  process.stdout.on("error", ignoreWriteError);
  process.stderr.on("error", ignoreWriteError);
  await appendLedger(ledger, {
    event: "started",
    taskId: TASK_ID,
    project: SANDBOX_PROJECT,
    gitSha: meta.sha,
    programs: meta.programs,
  });
  // Another lane may have checked the ledger at the same moment; the later one yields.
  const raced = linesAfter(await readFile(ledger, "utf8"), ledgerText.length);
  if (raced.length) {
    await appendLedger(ledger, {
      event: "finished",
      taskId: TASK_ID,
      project: SANDBOX_PROJECT,
      requests: 0,
      estimatedUsd: 0,
      outcome: "yielded",
      sandboxAtBaseline: true,
      note: `another lane wrote ${taskOf(raced[0])} at ${raced[0].ts}`,
    });
    throw new Error(
      `another lane started at the same time (${taskOf(raced[0])}); nothing was sent`,
    );
  }
  const recordings = [];
  const secrets = [];
  let outcome = "recorded";
  let error;
  let requests = 0;
  let baseline = { atBaseline: true };
  try {
    try {
      for (const offset of [0, 1]) {
        const { secrets: seen, ...recording } = await recordOnce(
          programs,
          String(Date.now() + offset),
          web,
          { signal: controller.signal, log: (line) => console.log(line) },
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
      if (caught.partial) {
        recordings.push(caught.partial);
        // Kept privately as design input; a partial recording is never a fixture.
        await writeFile(join(runDir, "recording-partial.json"), JSON.stringify(caught.partial), {
          mode: 0o600,
        }).catch(() => {});
      }
    }
    requests = recordings.reduce(
      (n, r) => n + r.requests + (r.sdkRequests ?? 0) + r.harnessRequests,
      0,
    );
    await writeFile(
      join(runDir, "meta.json"),
      JSON.stringify({ ...meta, outcome, error }, null, 2),
      {
        mode: 0o600,
      },
    );
    const failures = recordings.flatMap((r) => r.failures);
    if (!error) {
      try {
        const nondeterministic = await writeFixture({
          programs,
          recordings,
          meta,
          secrets: [web.apiKey, ...secrets, SANDBOX_PROJECT, web.projectNumber],
        });
        if (failures.length) outcome = "recorded-with-program-failures";
        console.log(
          JSON.stringify(
            { programs: programs.length, corpusRequests, requests, nondeterministic, failures },
            null,
            2,
          ),
        );
      } catch (caught) {
        outcome = "not-written";
        error = `${String(caught.message ?? caught)} (recordings kept in ${runDir})`;
      }
    }
    if (failures.length) process.exitCode = 1;
  } catch (caught) {
    outcome = "aborted";
    error = String(caught.message ?? caught);
  } finally {
    // After anything but a clean recording, read the sandbox back before handing it over.
    // Every run reads the sandbox back before handing it over, a clean one too.
    baseline = await verifyBaseline(web, startConfig);
    await appendLedger(ledger, {
      event: "finished",
      project: SANDBOX_PROJECT,
      database: null,
      gitSha: meta.sha,
      corpusDigest: sha256(JSON.stringify(programs)),
      requests,
      estimatedUsd: 0,
      outcome,
      sandboxAtBaseline: baseline.atBaseline,
      taskId: TASK_ID,
      programs: meta.programs,
      ...(error ? { error } : {}),
      ...(baseline.reason ? { baselineCheck: baseline.reason } : {}),
    });
    if (!baseline.atBaseline) {
      // Keeps every lane off the sandbox until restore-sandbox reads the baseline back.
      await appendLedger(ledger, {
        event: "started",
        taskId: TASK_ID,
        project: SANDBOX_PROJECT,
        note: "sandbox not at baseline after a failed run; run restore-sandbox",
      });
    }
  }
  if (error) throw new Error(error);
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

async function sessionLocal() {
  const programs = JSON.parse(await readFile(process.env.AUTH_CONFIG_SDK_IN, "utf8"));
  const ctx = createContext({
    run: process.env.AUTH_CONFIG_SDK_RUN,
    project: SANDBOX_PROJECT,
    target: {
      kind: "local",
      origin: process.env.AUTH_CONFIG_SDK_ORIGIN,
      projectNumber: LOCAL_PROJECT_NUMBER,
    },
  });
  const preparation = await prepareProject(ctx, { apply: true });
  const out = await runCorpus(programs, ctx, {
    ...ceilings(programs),
    settleDelayMs: 0,
    log: process.env.AUTH_CONFIG_SDK_VERBOSE === "1" ? (line) => console.error(line) : () => {},
  });
  await writeFile(
    process.env.AUTH_CONFIG_SDK_OUT,
    JSON.stringify({ ...out, harnessRequests: out.harnessRequests + preparation }),
  );
}

/** Runs the programs of one projection under a fireemu configured for it. */
async function runProjection(projection, programs) {
  const local = LOCAL[projection];
  const dir = join(RUN_DIR, projection);
  await mkdir(dir, { recursive: true, mode: 0o700 });
  const inPath = join(dir, "programs.json");
  const outPath = join(dir, "fireemu.json");
  const configPath = join(dir, "fireemu.config.json");
  await writeFile(
    configPath,
    JSON.stringify({
      schemaVersion: 1,
      profile: local.profile,
      daemon: { authProjectNumbers: { [SANDBOX_PROJECT]: LOCAL_PROJECT_NUMBER } },
      auth: { idTokenSigning: local.idTokenSigning, apiKeys: ["fake-api-key"] },
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
      String(local.port),
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
      "src/auth-config-sdk/run.mjs",
      "session-local",
    ],
    {
      cwd: CONFORMANCE_DIR,
      stdio: ["ignore", "inherit", "inherit"],
      env: {
        ...process.env,
        AUTH_CONFIG_SDK_IN: inPath,
        AUTH_CONFIG_SDK_OUT: outPath,
        AUTH_CONFIG_SDK_RUN: String(Date.now()),
        AUTH_CONFIG_SDK_ORIGIN: `http://127.0.0.1:${local.port}`,
      },
    },
  );
  const code = await new Promise((resolve) => child.once("exit", resolve));
  if (code !== 0) throw new Error(`fireemu session (${projection}) exited ${code}`);
  return { binary, ...JSON.parse(await readFile(outPath, "utf8")) };
}

async function runLocal(programs) {
  const results = {};
  const failures = [];
  let binary;
  let requests = 0;
  for (const projection of Object.keys(LOCAL)) {
    const selected = programs.filter((p) => p.projection === projection);
    if (!selected.length) continue;
    const out = await runProjection(projection, selected);
    binary = out.binary;
    Object.assign(results, out.results);
    failures.push(...out.failures);
    requests += out.requests + (out.sdkRequests ?? 0);
  }
  return { binary, results, failures, requests };
}

const SDK_TRANSIENT =
  /^(auth\/(network-request-failed|too-many-requests|quota-exceeded|internal-error)|app\/network-error)$/;

/** A row that says nothing about behaviour: transport failure, 5xx, rate limit (K4). */
export function transient(recorded) {
  if (recorded?.sdk) return recorded.sdk === "error" && SDK_TRANSIENT.test(String(recorded.code));
  return isTransient(recorded);
}

export function classify({ stale, production, alternative, fireemu }) {
  if (stale) return "STALE_FIXTURE";
  if (production === undefined) return "MISSING_FIXTURE";
  if (fireemu === undefined) return "MISSING";
  // A server error both recordings answered alike is the recorded behaviour, not noise; so is
  // an Admin SDK internal error (the SDK's name for an answer it cannot read, such as a link
  // request answered without a link).
  const internal = (recorded) =>
    recorded?.sdk === "error" && recorded.code === "auth/internal-error";
  const repeatedServerError = production.status >= 500 && alternative === undefined;
  const repeatedInternal = internal(production) && alternative === undefined;
  const indeterminate = (recorded) =>
    transient(recorded) &&
    !(repeatedServerError && recorded?.status >= 500) &&
    !(repeatedInternal && internal(recorded));
  if ([production, alternative, fireemu].some(indeterminate)) return "INDETERMINATE";
  if (sameRecording(production, fireemu)) return alternative ? "MATCH_NONDETERMINISTIC" : "MATCH";
  if (alternative && sameRecording(alternative, fireemu)) return "MATCH_NONDETERMINISTIC";
  return "MISMATCH";
}

async function check() {
  const fixture = existsSync(FIXTURE)
    ? JSON.parse(await readFile(FIXTURE, "utf8"))
    : { programs: {} };
  const selected = selectedPrograms();
  validateConfigSdkCorpus(selected, { sdkOperations: SDK_OPERATIONS });
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
        status: classify({ stale, production, alternative, fireemu }),
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
  await mkdir(RUN_DIR, { recursive: true, mode: 0o700 });
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
  const code = (recorded) =>
    recorded?.sdk
      ? String(recorded.code ?? "")
      : String(recorded?.body?.error?.message ?? "").split(" : ")[0];
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
    kind: "auth-config-sdk-comparison-v1",
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
  const last = ledgerEntries(ledgerText)
    .filter((entry) => taskOf(entry) === TASK_ID && entry.project === SANDBOX_PROJECT)
    .at(-1);
  if (!last) return false;
  if (last.event === "started") return true;
  return !cleanOutcome(last);
}

/**
 * Writes the whole configuration baseline back after a run that could not (SIGKILL, a crash)
 * and reads it back. It deletes no account. Refused unless this task's ledger shows a run that
 * did not end cleanly, while a recording of this harness runs, or while another lane is on the
 * sandbox. A terminal ledger line is written whatever happens.
 */
async function restoreSandbox() {
  const ledger = process.env.FIREEMU_SANDBOX_LEDGER;
  if (!ledger) throw new Error("FIREEMU_SANDBOX_LEDGER is required");
  const text = existsSync(ledger) ? await readFile(ledger, "utf8") : "";
  if (!restoreDue(text)) throw new Error("the ledger shows no run of this task to restore after");
  const busy = otherLaneOnSandbox(text);
  if (busy) throw new Error(`another lane is on the sandbox: ${busy}`);
  // The lock refuses while a recording of this harness runs.
  const release = await takeLock(ledger, "restore-sandbox");
  try {
    await restoreLocked(ledger);
  } finally {
    await release();
  }
}

async function restoreLocked(ledger) {
  const web = await sandboxWebConfig();
  const target = productionTarget(web);
  await target.refresh();
  const ctx = createContext({ run: String(Date.now()), project: SANDBOX_PROJECT, target });
  let outcome = "restored-by-operator";
  let error;
  try {
    const session = createSession(ctx, { maxHarnessRequests: 10, maxCleanupRequests: 120 });
    await session.restore(
      Object.fromEntries(
        Object.entries(SANDBOX_BASELINE).map(([p, v]) => [p, substituteProject(v, ctx.project)]),
      ),
    );
    await prepareProject(ctx, { apply: false });
  } catch (caught) {
    outcome = "restore-failed";
    error = String(caught.message ?? caught);
  } finally {
    await appendLedger(ledger, {
      event: "finished",
      taskId: TASK_ID,
      project: SANDBOX_PROJECT,
      estimatedUsd: 0,
      outcome,
      sandboxAtBaseline: !error,
      ...(error ? { error } : {}),
    });
    if (error) {
      await appendLedger(ledger, {
        event: "started",
        taskId: TASK_ID,
        project: SANDBOX_PROJECT,
        note: "restore-sandbox failed; the sandbox is not at its baseline",
      });
    }
  }
  if (error) throw new Error(error);
  console.log("sandbox baseline restored and read back");
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
  await mkdir(RUN_DIR, { recursive: true, mode: 0o700 });
  await writeFile(join(RUN_DIR, "fireemu-results.json"), `${JSON.stringify(local, null, 2)}\n`);
  console.log(JSON.stringify({ requests: local.requests, failures: local.failures }, null, 2));
} else if (mode !== undefined) {
  console.error("usage: run.mjs record-production|check|export-comparison|local|restore-sandbox");
  process.exitCode = 2;
}
