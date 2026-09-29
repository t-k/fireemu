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
import { appendFile, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { SANDBOX_PROJECT } from "../auth-account/harness.mjs";
import { packetApproval } from "./approval.mjs";
import { PROGRAMS } from "./corpus.mjs";
import { SAML_PROGRAMS } from "./corpus-saml.mjs";
import { FOLLOWUP_DISCOVERY_SCOPES, FOLLOWUP_PROGRAMS } from "./corpus-followup.mjs";
import { STRICT_SAFETY_PROGRAMS } from "./corpus-strict-safety.mjs";
import {
  checkWebConfig,
  clients,
  deployIssuer,
  endsRun,
  ledgerEntries,
  limitedFetch,
  removeIssuer,
  sandboxBusy,
  uncommitted,
  versionsOfRun,
} from "./hosting.mjs";
import { withProjectLocks } from "./project-locks.mjs";
import {
  makeCertificate,
  prepareKeys,
  prepareSamlSigners,
  resolveRun,
  runPrograms,
} from "./run.mjs";
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
/** Requests a pass may use; the rest of the API limit stays for publishing and cleaning up. */
export const PASS_LIMIT = 220;
const ITK = "https://identitytoolkit.googleapis.com";
const HOSTING = "https://firebasehosting.googleapis.com/v1beta1";
const SITE_VERSIONS = `sites/${SANDBOX_PROJECT}/versions`;
const CHANNEL = (run) =>
  `${HOSTING}/projects/${SANDBOX_PROJECT}/sites/${SANDBOX_PROJECT}/channels/fed-${run}`;
/** A provider the run made, whatever its prefix (a refused unprefixed ID may be accepted). */
const ownedProvider = (run) => (id) => String(id).toLowerCase().includes(`fireemu-${run}-`);
const USAGE = "https://serviceusage.googleapis.com/v1";
const MAU_USD = 0.015;
export const FIXTURE = fileURLToPath(
  new URL("../../auth-federation-production.json", import.meta.url),
);

/**
 * What differs between the recordings this runner makes: the packet an approval names, the
 * ledger action, the envelope's constants, the request limits (API and issuer host), each
 * pass's share, the accounts a pass may create (every one is an MAU), the corpus and the
 * fixture. record-oidc's values are the module's exports above.
 */
export const PROFILES = {
  "record-oidc": {
    packet: PACKET,
    action: ACTION,
    runner: RUNNER,
    limits: LIMITS,
    passLimit: PASS_LIMIT,
    accountLimit: undefined,
    programs: PROGRAMS,
    fixture: FIXTURE,
    target:
      "production Identity Toolkit, Secure Token and Admin v2 REST, Identity Platform sandbox; the OIDC issuer is the run's preview channel of the sandbox's Hosting, its ID tokens signed locally (owner decision O1)",
  },
  "record-saml": {
    packet: "record-saml",
    action: "record-saml",
    runner: { project: SANDBOX_PROJECT, maxRequests: 450, reserveUsd: 2 },
    limits: { api: 438, issuer: 12 },
    passLimit: 150,
    accountLimit: 25,
    programs: SAML_PROGRAMS,
    samlSigners: true,
    fixture: fileURLToPath(new URL("../../auth-federation-saml-production.json", import.meta.url)),
    target:
      "production Identity Toolkit, Secure Token and Admin v2 REST, Identity Platform sandbox; the SAML responses signed locally with the run's certificates at each step, the OIDC issuer the run's preview channel of the sandbox's Hosting (owner decisions O1, O5)",
  },
  "record-followup": {
    packet: "record-followup",
    action: "record-followup",
    // Two passes of at most 40 requests, and at most 50 for the prechecks, the issuer's deploy
    // and the cleanup (the rehearsal used 33 of those), counted against the API limit alone.
    runner: { project: SANDBOX_PROJECT, maxRequests: 142, reserveUsd: 1 },
    limits: { api: 130, issuer: 12 },
    passLimit: 40,
    accountLimit: 2,
    programs: FOLLOWUP_PROGRAMS,
    samlSigners: true,
    discoveryScopes: FOLLOWUP_DISCOVERY_SCOPES,
    fixture: fileURLToPath(
      new URL("../../auth-federation-followup-production.json", import.meta.url),
    ),
    target:
      "production Identity Toolkit, Secure Token and Admin v2 REST, Identity Platform sandbox; the OIDC issuer the run's preview channel of the sandbox's Hosting, its discovery document listing scopes_supported; the SAML responses made locally at each step, tampered or unsigned (owner decisions O1, O5; the coordinator's T12 (c), 2026-09-29)",
  },
  "record-strict-safety": {
    packet: "record-strict-safety",
    action: "record-strict-safety",
    // Two passes of at most 50 requests (the corpus has 33 steps, and a pass also deletes the
    // accounts and providers it made and reads the providers back), and at most 50 for the
    // prechecks, the issuer's deploy and the cleanup, counted against the API limit alone.
    runner: { project: SANDBOX_PROJECT, maxRequests: 162, reserveUsd: 1 },
    limits: { api: 150, issuer: 12 },
    passLimit: 50,
    accountLimit: 6,
    programs: STRICT_SAFETY_PROGRAMS,
    samlSigners: true,
    fixture: fileURLToPath(
      new URL("../../auth-federation-strict-safety-production.json", import.meta.url),
    ),
    target:
      "production Identity Toolkit, Secure Token and Admin v2 REST, Identity Platform sandbox; the OIDC issuer the run's preview channel of the sandbox's Hosting; the SAML responses made locally at each step, signed with SHA-1, without NotOnOrAfter or sent again (owner decisions O1, O5; the coordinator's N10 packet, 2026-09-29)",
  },
};

/** The profile a mode names (record-oidc when none). */
export function profileOf(name = "record-oidc") {
  const profile = PROFILES[name];
  if (!profile) throw new Error(`no recording ${name}`);
  return profile;
}

/** The recording's modules by absolute path: the approval names the digest of their sources. */
export const SOURCES = [
  "record.mjs",
  "run.mjs",
  "corpus.mjs",
  "corpus-saml.mjs",
  "corpus-followup.mjs",
  "corpus-strict-safety.mjs",
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

/** Modules run.mjs imports for its local mode only: checked committed, not digested. */
const LOCAL_ONLY = ["../config.mjs", "../evidence.mjs"].map((name) =>
  fileURLToPath(new URL(name, import.meta.url)),
);

export async function scriptDigest(read = (path) => readFile(path)) {
  const hash = createHash("sha256");
  for (const path of SOURCES) hash.update(await read(path));
  return hash.digest("hex");
}

const sha256Hex = (text) => createHash("sha256").update(text).digest("hex");

/** The config paths a corpus's programs may touch. */
const touchedOf = (programs) => [...new Set(programs.flatMap((program) => program.touches ?? []))];
const PROVIDER_COLLECTIONS = [
  "oauthIdpConfigs",
  "inboundSamlConfigs",
  "defaultSupportedIdpConfigs",
];
/** The default IdPs a corpus's programs write. */
const defaultIdpsOf = (programs) => [
  ...new Set(programs.flatMap((program) => program.defaultIdpWrites ?? [])),
];
const valueAt = (config, path) => path.split(".").reduce((value, key) => value?.[key], config);

/** A digest of each program as written in the corpus (before a run fills it in). */
export function programDigests(programs = PROGRAMS) {
  return Object.fromEntries(
    programs.map((program) => [program.id, sha256Hex(JSON.stringify(program))]),
  );
}

/** Whether two recorded rows are the same. */
const sameRow = (a, b) => JSON.stringify(a) === JSON.stringify(b);

/**
 * The fixture of a recording: the first pass's rows per program, and in `second` the rows the
 * second pass recorded differently. Programs a pass did not complete are left out.
 */
export function buildFixture(passes, meta, profile = PROFILES["record-oidc"]) {
  const [first, second] = passes;
  const digests = programDigests(profile.programs);
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
      target: profile.target,
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
  if (/"(signerKey|saltSeparator|salt)"\s*:\s*"(?!<bytes>")/.test(text))
    throw new Error("the fixture holds password-hash key material");
  if (/"passwordHash"\s*:\s*"(?!UkVEQUNURUQ="|<bytes>")/.test(text))
    throw new Error("the fixture holds a password hash");
  if (/"clientSecret"\s*:\s*"(?!fireemu-|<client-secret>")/.test(text))
    throw new Error("the fixture holds a client secret");
  if (/GOCSPX-|ya29\.|AMf-/.test(text)) throw new Error("the fixture holds a Google credential");
}

/** A fetch that refuses more than `limit` requests (a pass's share of the API limit). */
export function budget(api, limit, what) {
  let used = 0;
  return (url, init) => {
    if (used >= limit) return Promise.reject(new Error(`${what} used its ${limit} requests`));
    used += 1;
    return api(url, init);
  };
}

/**
 * Deletes the providers the run made that are still listed (whatever their prefix, in the
 * OIDC and SAML collections) and returns those still listed after it.
 */
async function removeOwnedProviders({ get, send, base, run }) {
  const owned = ownedProvider(run);
  const listed = async (collection) =>
    ((await get(`${base}/${collection}?pageSize=100`, collection))[collection] ?? [])
      .map((c) => String(c.name).split("/").at(-1))
      .filter(owned);
  const left = [];
  for (const collection of ["oauthIdpConfigs", "inboundSamlConfigs"]) {
    for (const id of await listed(collection)) {
      await send("DELETE", `${base}/${collection}/${id}`, undefined, `delete ${id}`);
    }
    left.push(...(await listed(collection)));
  }
  return left;
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
  signers,
  meta,
  appendLedger,
  writeFixture,
  stop,
  now,
  sleep,
  profile = PROFILES["record-oidc"],
}) {
  const { action } = profile;
  const touched = touchedOf(profile.programs);
  const defaultIdps = defaultIdpsOf(profile.programs);
  // record-saml signs responses with the run's SAML keys; record-oidc only configures one.
  const certificates = signers?.certificates ?? { "saml-a": certificatePem };
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
  // No provider configuration at all: nothing the run did not make can be recorded (a list
  // answers every provider) or removed by a recovery (the default IdPs the corpus writes).
  for (const collection of PROVIDER_COLLECTIONS) {
    const listed = await get(`${base}/${collection}?pageSize=100`, collection);
    if ((listed[collection] ?? []).length) {
      throw new Error(`precheck: the project has ${collection}`);
    }
  }
  if ((await get(accountsUrl(1), "accounts")).users?.length) {
    throw new Error("precheck: the project holds accounts");
  }
  stop.check();

  const keysBefore = configKeyDigests(before.text);
  await appendLedger({
    event: "started",
    action,
    run,
    envelopeId: meta.envelopeId,
    requestLimits: profile.limits,
    reserveUsd: profile.runner.reserveUsd,
    ...(profile.accountLimit === undefined ? {} : { accountLimit: profile.accountLimit * PASSES }),
    gitSha: meta.gitSha,
    scriptDigest: meta.digest,
    configDigestBefore: sha256Hex(before.text),
    configKeyDigestsBefore: keysBefore,
    // Values a recovery may restore (booleans, no secret).
    touchedBefore: Object.fromEntries(
      touched.map((path) => [path, valueAt(before.body, path) ?? false]),
    ),
    // Checked absent above: a recovery removes only these.
    defaultIdpsAbsentBefore: defaultIdps,
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
      scopes: profile.discoveryScopes,
      result: issuer,
      journal: (fields) => appendLedger({ event: "progress", action, run, ...fields }),
    });
    for (let pass = 1; pass <= PASSES; pass += 1) {
      stop.check();
      const { programs, passTag, nonceLabels } = resolveRun({
        project: SANDBOX_PROJECT,
        run,
        issuerHost: issuer.issuerHost,
        keys,
        certificates,
        now: now(),
        pass,
        programs: profile.programs,
      });
      const ctx = {
        run,
        project: SANDBOX_PROJECT,
        projectNumber: meta.projectNumber,
        issuerHost: issuer.issuerHost,
        runKids: [keys.run.jwk.kid],
        passTag,
        nonceLabels,
        apiKey: meta.apiKey,
        adminAuthorization: `Bearer ${meta.adminToken}`,
        adminHeaders: { "x-goog-user-project": SANDBOX_PROJECT },
        target: { kind: "production" },
        fetch: budget(api, profile.passLimit, `pass ${pass}`),
        accountLimit: profile.accountLimit,
        runCertificates: signers?.runCertificates,
        saml: signers ? { keys: signers.keys, now } : undefined,
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
  await step("find a version whose create answer was lost", async () => {
    if (issuer.versionAttempted && !issuer.version) {
      const [found, ...more] = await versionsOfRun(get, run);
      if (more.length) throw new Error(`several versions are labelled with run ${run}`);
      if (found) issuer.version = found;
    }
  });
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
    // A version create that was sent must end with its version found and removed.
    issuerRemoved =
      removed.channelProbe === undefined &&
      (!issuer.versionAttempted || Boolean(issuer.version)) &&
      (!issuer.version || ["absent", "DELETED"].includes(removed.versionStatus)) &&
      (!created || (removed.channelReadBack === "absent" && removed.issuerGone !== false));
  });
  await step("remove providers", async () => {
    cleanup.providersLeft = await removeOwnedProviders({ get, send, base, run });
  });
  await step("read default IdPs", async () => {
    cleanup.defaultIdpsLeft = [];
    for (const idp of defaultIdps) {
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
      await writeFixture(buildFixture(passes, meta, profile));
      fixtureWritten = true;
    } catch (error) {
      fixtureError = error.message;
    }
  }
  const entry = {
    action,
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
    // The version's ID only: its full name may hold the project number.
    versionId: issuer.version ? String(issuer.version).split("/").at(-1) : undefined,
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
 * The recording this task left unfinished, from the ledger: the last started line of this
 * action not followed by a line of its run that ends it cleanly (`endsRun`), with what a
 * recovery needs: the config digests and touched values before it, the default IdPs it saw
 * absent, and the issuer: its host, its version's ID (journalled after the create) and
 * whether a version create was sent at all.
 */
export function recordingToRecover(ledgerText, profile = PROFILES["record-oidc"]) {
  const own = ledgerEntries(ledgerText).filter(
    (entry) => entry.project === SANDBOX_PROJECT && (entry.taskId ?? entry.task) === TASK_ID,
  );
  const started = own.findLast(
    (entry) => entry.event === "started" && entry.action === profile.action,
  );
  if (!started) return undefined;
  const after = own
    .slice(own.lastIndexOf(started) + 1)
    .filter((entry) => entry.run === started.run);
  const last = after.at(-1);
  if (last && endsRun(last)) return undefined;
  if (!started.configDigestBefore) throw new Error(`run ${started.run} has no config digest`);
  const named = (key) => [started, ...after].findLast((entry) => entry[key] !== undefined)?.[key];
  return {
    run: started.run,
    digest: started.scriptDigest,
    configDigestBefore: started.configDigestBefore,
    configKeyDigestsBefore: started.configKeyDigestsBefore ?? {},
    touchedBefore: started.touchedBefore ?? {},
    defaultIdpsAbsentBefore: started.defaultIdpsAbsentBefore ?? [],
    issuerHost: named("issuerHost"),
    versionId: named("versionId"),
    versionSent: after.some((entry) => entry.step === "version-create-sent"),
  };
}

/**
 * Recovers a recording: removes the run's issuer (the channel if it is there, and the version
 * whether or not the channel is: from the journal, or from the channel's release), the run's
 * providers, the default IdPs it saw absent, the accounts of the run (their address or
 * provider names it), restores the touched config paths to the values before it, and reads it
 * all back. A version create that was sent without a journalled ID and cannot be found leaves
 * the run needing recovery. It writes nothing else of the config.
 */
export async function recoverCampaign({
  api,
  target,
  meta,
  appendLedger,
  sleep,
  profile = PROFILES["record-oidc"],
}) {
  const touched = touchedOf(profile.programs);
  const defaultIdps = defaultIdpsOf(profile.programs);
  const { run } = target;
  const { auth, get, send } = clients(api, meta.adminToken);
  const base = `${ITK}/admin/v2/projects/${SANDBOX_PROJECT}`;
  const owned = ownedProvider(run);
  const cleanup = { errors: [] };
  const step = async (name, work) => {
    try {
      await work();
    } catch (error) {
      cleanup.errors.push(`${name}: ${error.message}`);
    }
  };
  let versionId = target.versionId;
  let issuerHost = target.issuerHost;
  await step("remove channel", async () => {
    let channel;
    try {
      channel = await get(CHANNEL(run), "channel");
    } catch (error) {
      if (error.status !== 404) throw error;
    }
    if (!channel) {
      cleanup.channelReadBack = "absent";
    } else {
      versionId ??=
        String(channel.release?.version?.name ?? "")
          .split("/")
          .at(-1) || undefined;
      if (URL.canParse(channel.url ?? "")) issuerHost ??= new URL(channel.url).host;
      const removed = await removeIssuer({
        get,
        send,
        api,
        sleep,
        run,
        result: { channelAttempted: true, channelCreated: true, issuerHost },
      });
      Object.assign(cleanup, removed.cleanup);
    }
  });
  await step("remove version", async () => {
    if (!versionId && target.versionSent) {
      // The create's answer was lost: the run's label finds the version, if it exists.
      const [found, ...more] = await versionsOfRun(get, run);
      if (more.length) throw new Error(`several versions are labelled with run ${run}`);
      versionId = found ? found.split("/").at(-1) : undefined;
      if (!found) cleanup.versionSearch = "no version labelled with the run";
    }
    if (!versionId) {
      cleanup.versionStatus = target.versionSent ? "unknown" : "none";
      return;
    }
    const version = `${HOSTING}/${SITE_VERSIONS}/${versionId}`;
    try {
      await send("DELETE", version, undefined, "version delete");
    } catch (error) {
      if (error.status !== 404) throw error;
    }
    try {
      cleanup.versionStatus = (await get(version, "version")).status;
    } catch (error) {
      if (error.status !== 404) throw error;
      cleanup.versionStatus = "absent";
    }
  });
  await step("delete providers", async () => {
    cleanup.providersLeft = await removeOwnedProviders({ get, send, base, run });
  });
  await step("delete default IdPs", async () => {
    cleanup.defaultIdpsLeft = [];
    for (const idp of target.defaultIdpsAbsentBefore.filter((id) => defaultIdps.includes(id))) {
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
    (user.providerUserInfo ?? []).some((info) => owned(info.providerId));
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
      if (!touched.includes(path) || typeof value !== "boolean") continue;
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
    ["absent", "DELETED", "none"].includes(cleanup.versionStatus) &&
    cleanup.providersLeft?.length === 0 &&
    cleanup.defaultIdpsLeft?.length === 0 &&
    cleanup.accountsLeft === 0 &&
    cleanup.configUnchanged === true;
  if (!cleanup.errors.length) delete cleanup.errors;
  const entry = {
    action: `${profile.action}-recover`,
    outcome: clean ? "recovered" : "needs-recovery",
    run,
    ...(versionId ? { versionId } : {}),
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
async function gate(needs, profile = PROFILES["record-oidc"]) {
  const env = Object.fromEntries(needs.map((name) => [name, process.env[name]]));
  const missing = needs.filter((name) => !env[name]);
  if (missing.length) throw new Error(`${missing.join(", ")} required`);
  for (const name of ["FIREBASE_TOKEN", "GOOGLE_APPLICATION_CREDENTIALS"]) {
    if (process.env[name]) throw new Error(`${name} must be unset (the owner's user ADC is used)`);
  }
  // Also the two modules run.mjs imports for its local mode (not in the digest).
  if ((await uncommitted([...SOURCES, ...LOCAL_ONLY])) !== "")
    throw new Error("the recording's sources have uncommitted changes");
  const digest = await scriptDigest();
  const commit = await sh("git", ["-C", dirname(SOURCES[0]), "rev-parse", "HEAD"]);
  const approval = packetApproval(await readFile(env.FIREEMU_OWNER_DECISIONS, "utf8"), {
    parent: PARENT,
    packet: profile.packet,
    digest,
    commit,
    runner: profile.runner,
  });
  if (!approval) {
    throw new Error(`no owner-ledger approval of ${profile.packet} ${digest} at ${commit}`);
  }
  return { env, digest, commit, approval };
}

/**
 * Appends a ledger line: the lock is kept from a started line on, and the project number and
 * API key (an error may quote an answer) are replaced before it is written.
 */
export const appender = (ledger, used, state, web) => (line) => {
  // Set first: a started line half written still keeps the lock.
  if (line.event === "started") state.sent = true;
  let text = JSON.stringify({
    ts: new Date().toISOString(),
    project: SANDBOX_PROJECT,
    taskId: TASK_ID,
    ...line,
    requests: { ...used },
  });
  if (web.projectNumber) text = text.replaceAll(String(web.projectNumber), "<project-number>");
  if (web.apiKey) text = text.replaceAll(String(web.apiKey), "<api-key>");
  return appendFile(ledger, `${text}\n`);
};

/**
 * Writes the fixture: first privately (below the ledger's directory, mode 600), so a scan
 * that refuses it loses no row, then scanned, then over the committed fixture.
 */
export async function writeFixtureFiles(fixture, { privateDir, forbidden, target = FIXTURE }) {
  const text = `${JSON.stringify(fixture, null, 2)}\n`;
  await mkdir(privateDir, { recursive: true, mode: 0o700 });
  await writeFile(join(privateDir, "fixture.json"), text, { mode: 0o600 });
  scanFixture(text, forbidden);
  await writeFile(target, text);
}

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

async function recordProduction(profile) {
  const { env, digest, commit, approval } = await gate(
    ["FIREEMU_SANDBOX_LEDGER", "FIREEMU_OWNER_DECISIONS", "FIREEMU_AUTH_SANDBOX_WEB_CONFIG"],
    profile,
  );
  const ledger = env.FIREEMU_SANDBOX_LEDGER;
  const web = JSON.parse(await readFile(env.FIREEMU_AUTH_SANDBOX_WEB_CONFIG, "utf8"));
  checkWebConfig(web);
  const run = randomBytes(3).toString("hex");
  const keys = prepareKeys();
  const secretDir = await mkdtemp(join(tmpdir(), "fireemu-record-"));
  // The keys live in memory for the run only; nothing is left on disk.
  let certificatePem;
  let signers;
  try {
    if (profile.samlSigners) {
      signers = await prepareSamlSigners(secretDir);
      delete signers.keyPems;
    } else {
      certificatePem = await makeCertificate(secretDir, "saml-a");
    }
  } finally {
    await rm(secretDir, { recursive: true, force: true });
  }
  const holder = { taskId: TASK_ID, packetId: profile.packet, run, sourceCommit: commit };
  return withProjectLocks(
    ledger,
    [SANDBOX_PROJECT],
    holder,
    async (state) => {
      const busy = sandboxBusy(await readFile(ledger, "utf8").catch(() => ""));
      if (busy) throw new Error(`the sandbox is not free: ${busy}`);
      const adminToken = await sh("gcloud", ["auth", "application-default", "print-access-token"]);
      const { call, used } = limitedFetch(fetch, { run, limits: profile.limits });
      const stop = stopper();
      try {
        const startedAt = new Date().toISOString();
        const entry = await recordCampaign({
          api: call,
          run,
          keys,
          certificatePem,
          signers,
          profile,
          meta: {
            adminToken,
            apiKey: web.apiKey,
            projectNumber: web.projectNumber,
            gitSha: commit,
            digest,
            envelopeId: approval.envelopeId,
            startedAt,
          },
          appendLedger: appender(ledger, used, state, web),
          writeFixture: (fixture) =>
            writeFixtureFiles(fixture, {
              privateDir: join(dirname(ledger), `auth-federation-${profile.packet}-${run}`),
              forbidden: [web.apiKey, web.projectNumber, adminToken],
              target: profile.fixture,
            }),
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

async function recoverProduction(profile) {
  const { env, digest } = await gate(
    ["FIREEMU_SANDBOX_LEDGER", "FIREEMU_OWNER_DECISIONS", "FIREEMU_AUTH_SANDBOX_WEB_CONFIG"],
    profile,
  );
  const ledger = env.FIREEMU_SANDBOX_LEDGER;
  const web = JSON.parse(await readFile(env.FIREEMU_AUTH_SANDBOX_WEB_CONFIG, "utf8"));
  checkWebConfig(web);
  const target = recordingToRecover(await readFile(ledger, "utf8"), profile);
  if (!target) throw new Error("the ledger shows no recording of this task to recover");
  if (target.digest !== digest)
    throw new Error(`run ${target.run} ran ${target.digest}, not ${digest}`);
  // The recording's lock stays after a failure; recovery takes it over only when it is this
  // run's and its process is gone, so a recording that still runs is never overlapped.
  const commit = await sh("git", ["-C", dirname(SOURCES[0]), "rev-parse", "HEAD"]);
  return withProjectLocks(
    ledger,
    [SANDBOX_PROJECT],
    {
      taskId: TASK_ID,
      packetId: `${profile.packet}-recover`,
      run: target.run,
      sourceCommit: commit,
    },
    async (state) => {
      state.sent = true;
      const adminToken = await sh("gcloud", ["auth", "application-default", "print-access-token"]);
      const { call, used } = limitedFetch(fetch, { run: target.run, limits: profile.limits });
      const entry = await recoverCampaign({
        api: call,
        target,
        profile,
        meta: { adminToken },
        appendLedger: appender(ledger, used, state, web),
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
else if (mode === "record-production") await recordProduction(profileOf(process.argv[3]));
else if (mode === "recover") await recoverProduction(profileOf(process.argv[3]));
else if (mode !== undefined) throw new Error(`unknown mode ${mode}`);
