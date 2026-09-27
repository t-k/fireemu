// The production recording of AUTH-FEDERATION's OIDC programs (packet `record-oidc`, envelope
// `AUTH-FEDERATION-record-oidc-1`): the run's issuer is published on a preview channel of the
// sandbox's Hosting, the corpus is recorded twice through the same guard as the local mode,
// and everything the run created is deleted and read back. The rows are written to
// `conformance/auth-federation-production.json`.
//
//   node src/auth-federation/record.mjs digest
//   node src/auth-federation/record.mjs record-production
//   node src/auth-federation/record.mjs recover     # after a recording that needs recovery
//
// Gates: an approval of this digest in the owner ledger (the owner's line, or the owner's
// envelope with the coordinator's version line), sources equal to the commit, the owner's
// user ADC, the sandbox's web config, the project lock of fireemu-oracle-idp (never while the
// legacy shared lock exists) and a free sandbox in the ledger (30 minutes after another task,
// no open run, no pending recovery). Nothing is retried; a recording that cannot confirm its
// cleanup keeps the lock and writes needs-recovery.
//
// Environment: FIREEMU_SANDBOX_LEDGER, FIREEMU_OWNER_DECISIONS, FIREEMU_AUTH_SANDBOX_WEB_CONFIG.

import { execFile } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { appendFile, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { SANDBOX_PROJECT } from "../auth-account/harness.mjs";
import { packetApproval } from "./approval.mjs";
import { PROGRAMS } from "./corpus.mjs";
import { runProvider } from "./guard.mjs";
import {
  checkWebConfig,
  clients,
  deployIssuer,
  ledgerEntries,
  limitedFetch,
  removeIssuer,
  sandboxBusy,
  uncommitted,
} from "./hosting.mjs";
import { withProjectLocks } from "./project-locks.mjs";
import { makeCertificate, prepareKeys, resolveRun, runPrograms } from "./run.mjs";
import { changedKeys, configKeyDigests, precheckRefusal } from "./saml-smoke.mjs";

export const TASK_ID = "AUTH-FEDERATION-SANDBOX";
export const PARENT = "AUTH-FEDERATION";
export const PACKET = "record-oidc";
export const ACTION = "record-oidc";
/** The runner's constants an envelope must cover. */
export const RUNNER = { project: SANDBOX_PROJECT, maxRequests: 500, reserveUsd: 1 };
/** 500 external requests: the APIs and the issuer's host (2 read-backs, 10 after the delete). */
export const LIMITS = { api: 488, issuer: 12 };
const PASSES = 2;
const ITK = "https://identitytoolkit.googleapis.com";
const HOSTING = "https://firebasehosting.googleapis.com/v1beta1";
const USAGE = "https://serviceusage.googleapis.com/v1";
const MAU_USD = 0.015;
export const FIXTURE = fileURLToPath(
  new URL("../../auth-federation-production.json", import.meta.url),
);

/** The recording's modules by absolute path: the approval names the digest of their sources. */
export const SOURCES = [
  "record.mjs",
  "run.mjs",
  "corpus.mjs",
  "guard.mjs",
  "harness.mjs",
  "idp.mjs",
  "hosting.mjs",
  "approval.mjs",
  "project-locks.mjs",
  "saml-smoke.mjs",
  "saml.mjs",
  "../auth-account/harness.mjs",
].map((name) => fileURLToPath(new URL(name, import.meta.url)));

export async function scriptDigest(read = (path) => readFile(path)) {
  const hash = createHash("sha256");
  for (const path of SOURCES) hash.update(await read(path));
  return hash.digest("hex");
}

const sha256Hex = (text) => createHash("sha256").update(text).digest("hex");

/** The config paths programs may touch, and their values before the recording. */
const TOUCHED = [...new Set(PROGRAMS.flatMap((program) => program.touches ?? []))];
const DEFAULT_IDPS = [...new Set(PROGRAMS.flatMap((program) => program.defaultIdpWrites ?? []))];
const valueAt = (config, path) => path.split(".").reduce((value, key) => value?.[key], config);

/** A digest of each program as written in the corpus (before a run fills it in). */
export function programDigests() {
  return Object.fromEntries(
    PROGRAMS.map((program) => [program.id, sha256Hex(JSON.stringify(program))]),
  );
}

/** Whether two recorded rows are the same. */
const sameRow = (a, b) => JSON.stringify(a) === JSON.stringify(b);

/**
 * The fixture of a recording: the first pass's rows per program, and in `second` the rows the
 * second pass recorded differently. Programs a pass did not complete are left out.
 */
export function buildFixture(passes, meta) {
  const [first, second] = passes;
  const digests = programDigests();
  const programs = {};
  for (const id of Object.keys(first.results).toSorted()) {
    const one = first.results[id];
    const two = second?.results[id];
    if (!one || !two) continue;
    const differing = Object.fromEntries(
      Object.entries(two.steps).filter(([step, row]) => !sameRow(row, one.steps[step])),
    );
    programs[id] = {
      corpusDigest: digests[id],
      harnessDigest: meta.digest,
      recordedAt: meta.startedAt,
      gitSha: meta.gitSha,
      steps: one.steps,
      ...(Object.keys(differing).length ? { second: differing } : {}),
    };
  }
  return {
    version: 1,
    recordedAgainst: {
      target:
        "production Identity Toolkit, Secure Token and Admin v2 REST, Identity Platform sandbox; the OIDC issuer is the run's preview channel of the sandbox's Hosting, its ID tokens signed locally (owner decision O1)",
      project: "<project>",
      note: "Two recordings per program. The run's issuer host, run tag, project and project number are placeholders; tokens are recorded as their header and claims with times relative to iat; refresh, access and pending tokens, session IDs, local IDs and certificates are masked. `second` holds the other recording of rows that differed.",
    },
    programs,
  };
}

/**
 * Refuses a fixture that holds a secret: `forbidden` values (API key, project number, token),
 * an API key's shape or a raw JWT.
 */
export function scanFixture(text, forbidden) {
  for (const secret of forbidden) {
    if (secret && text.includes(String(secret)))
      throw new Error("the fixture holds a secret value");
  }
  if (/AIza[0-9A-Za-z_-]{20,}/.test(text)) throw new Error("the fixture holds an API key");
  if (/eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\./.test(text))
    throw new Error("the fixture holds a raw JWT");
  if (/PRIVATE KEY/.test(text)) throw new Error("the fixture holds private key material");
}

/**
 * The recording, with every effect injected: `api(url, init)` (counted), the run's `keys` and
 * SAML `certificatePem`, `meta` ({adminToken, apiKey, projectNumber, gitSha, digest,
 * envelopeId}), `appendLedger`, `writeFixture(fixture)` (called before the terminal line),
 * `stop`, `now()` in seconds and `sleep`. Returns the terminal ledger entry.
 */
export async function recordCampaign({
  api,
  run,
  keys,
  certificatePem,
  meta,
  appendLedger,
  writeFixture,
  stop,
  now,
  sleep,
}) {
  const { auth, get, send } = clients(api, meta.adminToken);
  const base = `${ITK}/admin/v2/projects/${SANDBOX_PROJECT}`;
  const accountsUrl = (max) =>
    `${ITK}/v1/projects/${SANDBOX_PROJECT}/accounts:batchGet?maxResults=${max}`;
  const readConfig = async () => {
    const response = await api(`${base}/config`, { headers: auth });
    const text = await response.text();
    if (response.status !== 200) throw new Error(`config read: HTTP ${response.status}`);
    return { text, body: JSON.parse(text), date: response.headers.get("date") };
  };

  // Prechecks (read only).
  const before = await readConfig();
  const refusal = precheckRefusal(before.body, before.date, now());
  if (refusal) throw new Error(`precheck: ${refusal}`);
  const usage = await get(
    `${USAGE}/projects/${SANDBOX_PROJECT}/services/firebasehosting.googleapis.com`,
    "hosting service",
  );
  if (usage.state !== "ENABLED") throw new Error(`precheck: firebasehosting is ${usage.state}`);
  await get(`${HOSTING}/projects/${SANDBOX_PROJECT}/sites/${SANDBOX_PROJECT}`, "default site");
  const channels = await get(
    `${HOSTING}/projects/${SANDBOX_PROJECT}/sites/${SANDBOX_PROJECT}/channels?pageSize=100`,
    "channels",
  );
  if ((channels.channels ?? []).some((c) => String(c.name).split("/").at(-1).startsWith("fed-"))) {
    throw new Error("precheck: a channel of an earlier run remains");
  }
  for (const collection of ["oauthIdpConfigs", "inboundSamlConfigs"]) {
    const listed = await get(`${base}/${collection}?pageSize=100`, collection);
    if ((listed[collection] ?? []).some((c) => /\/(oidc|saml)\.fireemu-/.test(String(c.name)))) {
      throw new Error(`precheck: ${collection} of an earlier run remain`);
    }
  }
  if ((await get(accountsUrl(1), "accounts")).users?.length) {
    throw new Error("precheck: the project holds accounts");
  }
  stop.check();

  const keysBefore = configKeyDigests(before.text);
  await appendLedger({
    event: "started",
    action: ACTION,
    run,
    envelopeId: meta.envelopeId,
    requestLimits: LIMITS,
    reserveUsd: RUNNER.reserveUsd,
    gitSha: meta.gitSha,
    scriptDigest: meta.digest,
    configDigestBefore: sha256Hex(before.text),
    configKeyDigestsBefore: keysBefore,
    // Values a recovery may restore (booleans, no secret).
    touchedBefore: Object.fromEntries(
      TOUCHED.map((path) => [path, valueAt(before.body, path) ?? false]),
    ),
  });

  const issuer = { channelAttempted: false, channelCreated: false };
  const passes = [];
  let failure;
  try {
    await deployIssuer({
      api,
      auth,
      send,
      run,
      jwks: [keys.run.jwk],
      forbidden: [meta.apiKey, meta.projectNumber],
      stop,
      result: issuer,
    });
    for (let pass = 1; pass <= PASSES; pass += 1) {
      stop.check();
      const { programs } = resolveRun({
        project: SANDBOX_PROJECT,
        run,
        issuerHost: issuer.issuerHost,
        keys,
        certificatePem,
        now: now(),
      });
      const ctx = {
        run,
        project: SANDBOX_PROJECT,
        projectNumber: meta.projectNumber,
        issuerHost: issuer.issuerHost,
        runKids: [keys.run.jwk.kid],
        apiKey: meta.apiKey,
        adminAuthorization: `Bearer ${meta.adminToken}`,
        adminHeaders: { "x-goog-user-project": SANDBOX_PROJECT },
        target: { kind: "production" },
        fetch: api,
      };
      passes.push(await runPrograms(programs, ctx));
    }
  } catch (error) {
    failure = error;
  }

  // Cleanup: the issuer (channel and version), then read everything back.
  const cleanup = { errors: [] };
  const step = async (name, work) => {
    try {
      await work();
    } catch (error) {
      cleanup.errors.push(`${name}: ${error.message}`);
    }
  };
  let issuerRemoved = false;
  await step("remove issuer", async () => {
    const { created, cleanup: removed } = await removeIssuer({
      get,
      send,
      api,
      sleep,
      run,
      result: issuer,
      deleteVersion: true,
    });
    Object.assign(cleanup, removed);
    issuerRemoved =
      removed.channelProbe === undefined &&
      (!created ||
        (removed.channelReadBack === "absent" &&
          removed.issuerGone !== false &&
          (!issuer.version || ["absent", "DELETED"].includes(removed.versionStatus))));
  });
  await step("list providers", async () => {
    cleanup.providersLeft = [];
    for (const collection of ["oauthIdpConfigs", "inboundSamlConfigs"]) {
      const listed = await get(`${base}/${collection}?pageSize=100`, collection);
      cleanup.providersLeft.push(
        ...(listed[collection] ?? [])
          .map((c) => String(c.name).split("/").at(-1))
          .filter((id) => runProvider(run).test(id)),
      );
    }
  });
  await step("read default IdPs", async () => {
    cleanup.defaultIdpsLeft = [];
    for (const idp of DEFAULT_IDPS) {
      const response = await api(`${base}/defaultSupportedIdpConfigs/${idp}`, { headers: auth });
      await response.text();
      if (response.status !== 404) cleanup.defaultIdpsLeft.push(`${idp} (${response.status})`);
    }
  });
  await step("list accounts", async () => {
    cleanup.accountsLeft = ((await get(accountsUrl(1), "accounts")).users ?? []).length;
  });
  await step("read config", async () => {
    const after = await readConfig();
    cleanup.configUnchanged = after.text === before.text;
    if (!cleanup.configUnchanged)
      cleanup.configChangedKeys = changedKeys(keysBefore, configKeyDigests(after.text));
  });
  const clean =
    issuerRemoved &&
    cleanup.providersLeft?.length === 0 &&
    cleanup.defaultIdpsLeft?.length === 0 &&
    cleanup.accountsLeft === 0 &&
    cleanup.configUnchanged === true;
  if (!cleanup.errors.length) delete cleanup.errors;

  const programFailures = passes.flatMap((out, index) =>
    out.failures.map((f) => `pass ${index + 1}: ${f}`),
  );
  const accountsCreated = passes.reduce((sum, out) => sum + out.accountsDeleted, 0);
  const complete = !failure && passes.length === PASSES;
  let fixtureWritten = false;
  let fixtureError;
  if (complete) {
    try {
      await writeFixture(buildFixture(passes, meta));
      fixtureWritten = true;
    } catch (error) {
      fixtureError = error.message;
    }
  }
  const entry = {
    action: ACTION,
    outcome: !clean
      ? "needs-recovery"
      : !complete
        ? "failed-cleaned"
        : fixtureWritten
          ? "recorded"
          : "recorded-unwritten",
    ...(failure ? { error: failure.message } : {}),
    run,
    envelopeId: meta.envelopeId,
    issuerHost: issuer.issuerHost,
    version: issuer.version,
    passes: passes.length,
    stepRequests: passes.map((out) => out.requests),
    programFailures,
    accountsCreated,
    ...cleanup,
    fixtureWritten,
    ...(fixtureError ? { fixtureError } : {}),
    // Every account an OIDC sign-in created is an MAU; priced as if none were free.
    estimatedUsd: Math.round(accountsCreated * MAU_USD * 100) / 100,
  };
  await appendLedger(entry);
  return entry;
}

/**
 * The recording this task left unfinished: its run, and from its started line the config
 * digests and the touched values before it, and the issuer its last line named.
 */
export function recordingToRecover(ledgerText) {
  const own = ledgerEntries(ledgerText).filter(
    (entry) => entry.project === SANDBOX_PROJECT && (entry.taskId ?? entry.task) === TASK_ID,
  );
  const last = own.at(-1);
  const open =
    last &&
    [ACTION, `${ACTION}-recover`].includes(last.action) &&
    (last.event === "started" || last.outcome === "needs-recovery");
  if (!open) return undefined;
  const started = own.findLast(
    (entry) => entry.event === "started" && entry.action === ACTION && entry.run === last.run,
  );
  if (!started?.configDigestBefore) throw new Error(`run ${last.run} has no started line`);
  const named = own.findLast((entry) => entry.run === last.run && entry.issuerHost);
  return {
    run: last.run,
    digest: started.scriptDigest,
    configDigestBefore: started.configDigestBefore,
    configKeyDigestsBefore: started.configKeyDigestsBefore ?? {},
    touchedBefore: started.touchedBefore ?? {},
    issuerHost: named?.issuerHost,
    version: named?.version,
  };
}

/**
 * Recovers a recording: removes the run's issuer (channel and version), the run's providers,
 * the declared default IdPs (none existed when it started), the accounts of the run (their
 * address or provider names it), restores the touched config paths to the values before it,
 * and reads it all back. It writes nothing else of the config.
 */
export async function recoverCampaign({ api, target, meta, appendLedger, sleep }) {
  const { run } = target;
  const { auth, get, send } = clients(api, meta.adminToken);
  const base = `${ITK}/admin/v2/projects/${SANDBOX_PROJECT}`;
  const own = runProvider(run);
  const cleanup = { errors: [] };
  const step = async (name, work) => {
    try {
      await work();
    } catch (error) {
      cleanup.errors.push(`${name}: ${error.message}`);
    }
  };
  const issuer = {
    channelAttempted: true,
    channelCreated: false,
    issuerHost: target.issuerHost,
    version: target.version,
  };
  await step("remove issuer", async () => {
    Object.assign(
      cleanup,
      (await removeIssuer({ get, send, api, sleep, run, result: issuer, deleteVersion: true }))
        .cleanup,
    );
  });
  await step("delete providers", async () => {
    cleanup.providersLeft = [];
    for (const collection of ["oauthIdpConfigs", "inboundSamlConfigs"]) {
      const listed = await get(`${base}/${collection}?pageSize=100`, collection);
      for (const id of (listed[collection] ?? [])
        .map((c) => String(c.name).split("/").at(-1))
        .filter((i) => own.test(i))) {
        await send("DELETE", `${base}/${collection}/${id}`, undefined, `delete ${id}`);
      }
      const again = await get(`${base}/${collection}?pageSize=100`, collection);
      cleanup.providersLeft.push(
        ...(again[collection] ?? [])
          .map((c) => String(c.name).split("/").at(-1))
          .filter((i) => own.test(i)),
      );
    }
  });
  await step("delete default IdPs", async () => {
    cleanup.defaultIdpsLeft = [];
    for (const idp of DEFAULT_IDPS) {
      const response = await api(`${base}/defaultSupportedIdpConfigs/${idp}`, { headers: auth });
      await response.text();
      if (response.status === 404) continue;
      await send("DELETE", `${base}/defaultSupportedIdpConfigs/${idp}`, undefined, `delete ${idp}`);
      const again = await api(`${base}/defaultSupportedIdpConfigs/${idp}`, { headers: auth });
      await again.text();
      if (again.status !== 404) cleanup.defaultIdpsLeft.push(idp);
    }
  });
  const theRuns = (user) =>
    String(user.email ?? "").startsWith(`fireemu-fed-${run}-`) ||
    (user.providerUserInfo ?? []).some((info) => own.test(String(info.providerId).toLowerCase()));
  await step("delete accounts", async () => {
    const listed = await get(
      `${ITK}/v1/projects/${SANDBOX_PROJECT}/accounts:batchGet?maxResults=100`,
      "accounts",
    );
    for (const user of (listed.users ?? []).filter(theRuns)) {
      await send(
        "POST",
        `${ITK}/v1/projects/${SANDBOX_PROJECT}/accounts:delete`,
        { localId: user.localId },
        "delete account",
      );
    }
    const again = await get(
      `${ITK}/v1/projects/${SANDBOX_PROJECT}/accounts:batchGet?maxResults=100`,
      "accounts",
    );
    cleanup.accountsLeft = (again.users ?? []).filter(theRuns).length;
  });
  await step("restore config", async () => {
    const current = await get(`${base}/config`, "config");
    for (const [path, value] of Object.entries(target.touchedBefore)) {
      if (!TOUCHED.includes(path) || typeof value !== "boolean") continue;
      if ((valueAt(current, path) ?? false) === value) continue;
      const body = {};
      path.split(".").reduce((node, key, index, keys) => {
        node[key] = index === keys.length - 1 ? value : {};
        return node[key];
      }, body);
      await send("PATCH", `${base}/config?updateMask=${path}`, body, `restore ${path}`);
    }
    const response = await api(`${base}/config`, { headers: auth });
    const text = await response.text();
    cleanup.configUnchanged =
      response.status === 200 && sha256Hex(text) === target.configDigestBefore;
    if (response.status === 200 && !cleanup.configUnchanged) {
      cleanup.configChangedKeys = changedKeys(
        target.configKeyDigestsBefore,
        configKeyDigests(text),
      );
    }
  });
  const clean =
    cleanup.errors.length === 0 &&
    cleanup.channelReadBack === "absent" &&
    cleanup.issuerGone !== false &&
    (!target.version || ["absent", "DELETED"].includes(cleanup.versionStatus)) &&
    cleanup.providersLeft?.length === 0 &&
    cleanup.defaultIdpsLeft?.length === 0 &&
    cleanup.accountsLeft === 0 &&
    cleanup.configUnchanged === true;
  if (!cleanup.errors.length) delete cleanup.errors;
  const entry = {
    action: `${ACTION}-recover`,
    outcome: clean ? "recovered" : "needs-recovery",
    run,
    ...cleanup,
    estimatedUsd: 0,
  };
  await appendLedger(entry);
  return entry;
}

async function sh(command, args) {
  const { stdout } = await promisify(execFile)(command, args);
  return stdout.trim();
}

/** The gates of every production send of this script; returns what they read. */
async function gate(needs) {
  const env = Object.fromEntries(needs.map((name) => [name, process.env[name]]));
  const missing = needs.filter((name) => !env[name]);
  if (missing.length) throw new Error(`${missing.join(", ")} required`);
  for (const name of ["FIREBASE_TOKEN", "GOOGLE_APPLICATION_CREDENTIALS"]) {
    if (process.env[name]) throw new Error(`${name} must be unset (the owner's user ADC is used)`);
  }
  if ((await uncommitted(SOURCES)) !== "")
    throw new Error("the recording's sources have uncommitted changes");
  const digest = await scriptDigest();
  const commit = await sh("git", ["-C", dirname(SOURCES[0]), "rev-parse", "HEAD"]);
  const approval = packetApproval(await readFile(env.FIREEMU_OWNER_DECISIONS, "utf8"), {
    parent: PARENT,
    packet: PACKET,
    digest,
    commit,
    runner: RUNNER,
  });
  if (!approval) throw new Error(`no owner-ledger approval of ${PACKET} ${digest} at ${commit}`);
  return { env, digest, commit, approval };
}

const appender = (ledger, used, state) => (line) => {
  // Set first: a started line half written still keeps the lock.
  if (line.event === "started") state.sent = true;
  return appendFile(
    ledger,
    `${JSON.stringify({ ts: new Date().toISOString(), project: SANDBOX_PROJECT, taskId: TASK_ID, ...line, requests: { ...used } })}\n`,
  );
};

const stopper = () => {
  let stopped;
  const onSignal = (signal) => {
    stopped = signal;
  };
  for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) process.on(signal, onSignal);
  return {
    check() {
      if (stopped) throw new Error(`stopped by ${stopped}`);
    },
    remove() {
      for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) process.off(signal, onSignal);
    },
  };
};

async function recordProduction() {
  const { env, digest, commit, approval } = await gate([
    "FIREEMU_SANDBOX_LEDGER",
    "FIREEMU_OWNER_DECISIONS",
    "FIREEMU_AUTH_SANDBOX_WEB_CONFIG",
  ]);
  const ledger = env.FIREEMU_SANDBOX_LEDGER;
  const web = JSON.parse(await readFile(env.FIREEMU_AUTH_SANDBOX_WEB_CONFIG, "utf8"));
  checkWebConfig(web);
  const run = randomBytes(3).toString("hex");
  const keys = prepareKeys();
  const secretDir = await mkdtemp(join(tmpdir(), "fireemu-record-"));
  let certificatePem;
  try {
    certificatePem = await makeCertificate(secretDir, "saml-a");
  } finally {
    await rm(secretDir, { recursive: true, force: true });
  }
  const holder = { taskId: TASK_ID, packetId: PACKET, run, sourceCommit: commit };
  return withProjectLocks(
    ledger,
    [SANDBOX_PROJECT],
    holder,
    async (state) => {
      const busy = sandboxBusy(await readFile(ledger, "utf8").catch(() => ""));
      if (busy) throw new Error(`the sandbox is not free: ${busy}`);
      const adminToken = await sh("gcloud", ["auth", "application-default", "print-access-token"]);
      const { call, used } = limitedFetch(fetch, { run, limits: LIMITS });
      const stop = stopper();
      try {
        const startedAt = new Date().toISOString();
        const entry = await recordCampaign({
          api: call,
          run,
          keys,
          certificatePem,
          meta: {
            adminToken,
            apiKey: web.apiKey,
            projectNumber: web.projectNumber,
            gitSha: commit,
            digest,
            envelopeId: approval.envelopeId,
            startedAt,
          },
          appendLedger: appender(ledger, used, state),
          writeFixture: async (fixture) => {
            const text = `${JSON.stringify(fixture, null, 2)}\n`;
            scanFixture(text, [web.apiKey, web.projectNumber, adminToken]);
            await writeFile(FIXTURE, text);
          },
          stop,
          now: () => Math.floor(Date.now() / 1000),
          sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
        });
        console.log(JSON.stringify(entry, null, 2));
        if (entry.outcome !== "recorded") process.exitCode = 1;
        return entry;
      } finally {
        stop.remove();
      }
    },
    { keep: (entry) => entry.outcome === "needs-recovery" },
  );
}

async function recoverProduction() {
  const { env, digest } = await gate(["FIREEMU_SANDBOX_LEDGER", "FIREEMU_OWNER_DECISIONS"]);
  const ledger = env.FIREEMU_SANDBOX_LEDGER;
  const target = recordingToRecover(await readFile(ledger, "utf8"));
  if (!target) throw new Error("the ledger shows no recording of this task to recover");
  if (target.digest !== digest)
    throw new Error(`run ${target.run} ran ${target.digest}, not ${digest}`);
  // The recording's lock stays after a failure; recovery takes it over only when it is this
  // run's and its process is gone, so a recording that still runs is never overlapped.
  const commit = await sh("git", ["-C", dirname(SOURCES[0]), "rev-parse", "HEAD"]);
  return withProjectLocks(
    ledger,
    [SANDBOX_PROJECT],
    { taskId: TASK_ID, packetId: `${PACKET}-recover`, run: target.run, sourceCommit: commit },
    async (state) => {
      state.sent = true;
      const adminToken = await sh("gcloud", ["auth", "application-default", "print-access-token"]);
      const { call, used } = limitedFetch(fetch, { run: target.run, limits: LIMITS });
      const entry = await recoverCampaign({
        api: call,
        target,
        meta: { adminToken },
        appendLedger: appender(ledger, used, state),
        sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
      });
      console.log(JSON.stringify(entry, null, 2));
      if (entry.outcome !== "recovered") process.exitCode = 1;
      return entry;
    },
    {
      keep: (entry) => entry.outcome !== "recovered",
      adopt: (body) => body.taskId === TASK_ID && body.run === target.run,
    },
  );
}

const mode = process.argv[1] === fileURLToPath(import.meta.url) ? process.argv[2] : undefined;
if (mode === "digest") console.log(await scriptDigest());
else if (mode === "record-production") await recordProduction();
else if (mode === "recover") await recoverProduction();
else if (mode !== undefined) throw new Error(`unknown mode ${mode}`);
