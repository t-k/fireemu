// Stage A of the AUTH-FEDERATION SAML feasibility plan (owner decisions O1 and O5, plan H1):
// does production Identity Platform accept a SAMLResponse this harness signs locally? One
// SAML provider of the run, the SP-initiated flow through REST (createAuthUri, then
// signInWithIdp with the signed response), a tampered response, and, when the signed one is
// accepted, the response-signed and both-signed variants. Everything the run created is
// deleted and read back, and the project config is compared before and after: nothing
// writes it.
//
//   node src/auth-federation/saml-smoke.mjs digest
//   node src/auth-federation/saml-smoke.mjs smoke --attempt <1|2>
//   node src/auth-federation/saml-smoke.mjs recover   # after an attempt that needs recovery
//
// A second attempt is a separate send: it is started by hand after the first one's result
// has been read, and only when the owner ledger approves `attempts 2` for the digest being
// run (a changed signer has another digest, so it needs its own line).
//
// Environment: FIREEMU_SANDBOX_LEDGER, FIREEMU_OWNER_DECISIONS, FIREEMU_AUTH_SANDBOX_WEB_CONFIG
// (the API key for client calls and the project number the recording hides). Credentials are
// the owner's user ADC; FIREBASE_TOKEN and GOOGLE_APPLICATION_CREDENTIALS must be unset.

import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { createHash, createPrivateKey, randomBytes } from "node:crypto";
import { appendFile, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { SANDBOX_PROJECT } from "../auth-account/harness.mjs";
import { checkRun, guardHttp, runProvider } from "./guard.mjs";
import { normalizeHttp } from "./harness.mjs";
import {
  TASK_ID,
  checkWebConfig,
  ledgerEntries,
  limitedFetch,
  ownerApproval,
  sandboxBusy,
  uncommitted,
  withSandboxLock,
} from "./hosting.mjs";
import { certificateBase64, readAuthnRequest, signedSamlResponse } from "./saml.mjs";

export const ACTION = "saml-smoke";
/**
 * API requests per attempt: prechecks 3 (config, SAML providers, accounts), provider create 1,
 * four rows of createAuthUri and signInWithIdp 8, account deletes at most 2, provider delete 1,
 * read-backs 4 (provider, SAML providers, accounts, config).
 */
export const LIMITS = { api: 19, issuer: 0 };
const ITK = "https://identitytoolkit.googleapis.com";
const CALLBACK = `https://${SANDBOX_PROJECT}.firebaseapp.com/__/auth/handler`;

/** The smoke's modules by absolute path, including the one that names the project. */
export const SOURCES = [
  "saml-smoke.mjs",
  "saml.mjs",
  "guard.mjs",
  "hosting.mjs",
  "idp.mjs",
  "harness.mjs",
  "../auth-account/harness.mjs",
].map((name) => fileURLToPath(new URL(name, import.meta.url)));

export async function scriptDigest(read = (path) => readFile(path)) {
  const hash = createHash("sha256");
  for (const path of SOURCES) hash.update(await read(path));
  return hash.digest("hex");
}

/**
 * How many attempts the owner ledger approves for this digest: the fixed-form owner line
 * `… saml-smoke APPROVED <digest> …` (see `ownerApproval`), 2 when it says `attempts 2`, 0
 * when none approves it.
 */
export function approvedAttempts(ownerDecisions, digest) {
  return ownerApproval(ownerDecisions, ACTION, digest)?.attempts ?? 0;
}

const sha256Hex = (text) => createHash("sha256").update(text).digest("hex");

/**
 * Why attempt `attempt` may not start, or undefined. Attempts are counted by their started
 * lines, so an attempt that ended in an exception (and was recovered) still counts. The first
 * needs none before it; the second needs exactly one, whose own terminal line says
 * `failed-cleaned`. There is never a third.
 */
export function attemptRefusal(ledgerText, attempt) {
  const own = ledgerEntries(ledgerText).filter(
    (entry) =>
      entry.project === SANDBOX_PROJECT &&
      (entry.taskId ?? entry.task) === TASK_ID &&
      entry.action === ACTION,
  );
  const started = own.filter((entry) => entry.event === "started");
  if (attempt === 1)
    return started.length ? `attempt ${started.length} already started` : undefined;
  if (attempt !== 2) return `attempt ${attempt} is not 1 or 2`;
  if (started.length !== 1)
    return `attempt 2 needs exactly one earlier attempt (${started.length})`;
  const ended = own.findLast(
    (entry) => entry.run === started[0].run && entry.outcome !== undefined,
  );
  if (ended?.outcome !== "failed-cleaned") {
    return `attempt 1 ended ${ended?.outcome ?? "without a terminal line"}, not failed-cleaned`;
  }
  return undefined;
}

/** The provider configuration of the run: its certificate, a sandbox-hosted entity ID. */
function providerBody(run, certificatePem) {
  return {
    displayName: `fireemu ${run}`,
    enabled: true,
    idpConfig: {
      idpEntityId: `https://${SANDBOX_PROJECT}.web.app/saml/${run}`,
      ssoUrl: `https://${SANDBOX_PROJECT}.web.app/saml/${run}/sso`,
      idpCertificates: [{ x509Certificate: certificatePem }],
      signRequest: false,
    },
    spConfig: { spEntityId: `fireemu-${run}-sp`, callbackUri: CALLBACK },
  };
}

/**
 * The guard for a sign-in carrying a SAMLResponse: the response must name only the run's
 * certificate, and the rest of the request passes the harness guard.
 */
export function guardSamlSignIn(url, body, ctx) {
  const form = new URLSearchParams(JSON.parse(body).postBody);
  const xml = Buffer.from(form.get("SAMLResponse") ?? "", "base64").toString("utf8");
  const certificates = [...xml.matchAll(/<ds:X509Certificate>([^<]*)<\/ds:X509Certificate>/g)].map(
    (match) => match[1],
  );
  if (!certificates.length || certificates.some((c) => !ctx.runCertificates.includes(c))) {
    throw new Error("the SAMLResponse carries a certificate this run did not make");
  }
  form.set("SAMLResponse", "fireemu-saml-response");
  guardHttp(
    {
      url,
      method: "POST",
      body: JSON.stringify({ ...JSON.parse(body), postBody: form.toString() }),
    },
    ctx,
    {
      role: "step",
    },
  );
}

/** Flips the first character of the first SignatureValue: the signature no longer verifies. */
export function tamper(xml) {
  return xml.replace(
    /<ds:SignatureValue>(.)/,
    (_, c) => `<ds:SignatureValue>${c === "A" ? "B" : "A"}`,
  );
}

/**
 * The configuration read before the attempt must allow it, or nothing is sent: the callback
 * host is an authorized domain, no blocking function runs on sign-in (another lane's), the
 * project is on Identity Platform, and the local clock is within 30 seconds of the server's
 * (the response is valid from a minute before its issue).
 */
export function precheckRefusal(config, serverDate, now) {
  const domains = config.authorizedDomains ?? [];
  if (!domains.includes(`${SANDBOX_PROJECT}.firebaseapp.com`)) {
    return `${SANDBOX_PROJECT}.firebaseapp.com is not an authorized domain`;
  }
  if (Object.keys(config.blockingFunctions?.triggers ?? {}).length) {
    return "a blocking function is configured";
  }
  if (config.subtype !== "IDENTITY_PLATFORM") return `the project subtype is ${config.subtype}`;
  const server = Date.parse(serverDate ?? "");
  if (Number.isNaN(server)) return "the server sent no Date";
  const skew = Math.abs(now * 1000 - server);
  if (skew > 30_000) return `the local clock is ${Math.round(skew / 1000)} s off the server's`;
  return undefined;
}

/** The sha256 of each top-level member of a config: what a mismatch names, never its value. */
export function configKeyDigests(text) {
  let config;
  try {
    config = JSON.parse(text);
  } catch {
    return { "<unparsable>": sha256Hex(text) };
  }
  return Object.fromEntries(
    Object.entries(config)
      .toSorted(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([key, value]) => [key, sha256Hex(JSON.stringify(value))]),
  );
}

/** The top-level members whose digests differ between two `configKeyDigests`. */
export function changedKeys(before, after) {
  return [...new Set([...Object.keys(before), ...Object.keys(after)])]
    .filter((key) => before[key] !== after[key])
    .toSorted();
}

/**
 * The smoke, with every effect injected. `api(url, init)` is counted; `adminToken` and
 * `apiKey` authenticate; `signer` is `{privateKey, certificatePem}`. `writeAnswers(recorded)`
 * runs before the terminal ledger line, which is always written once the started line was,
 * with the rows, whatever the cleanup met. Returns the terminal entry.
 */
export async function samlSmoke({
  api,
  run,
  signer,
  meta,
  appendLedger,
  writeAnswers = async () => {},
  stop,
  attempt,
  now,
}) {
  checkRun(run);
  const provider = `saml.fireemu-${run}-s`;
  if (!runProvider(run).test(provider)) throw new Error("provider is not the run's");
  const ctx = {
    project: SANDBOX_PROJECT,
    run,
    target: { kind: "production" },
    runKids: [],
    runCertificates: [certificateBase64(signer.certificatePem)],
    defaultIdpWrites: [],
  };
  const admin = {
    authorization: `Bearer ${meta.adminToken}`,
    "x-goog-user-project": SANDBOX_PROJECT,
  };
  const request = async (method, url, body, { role = "harness", headers = admin, guard } = {}) => {
    const text = body === undefined ? undefined : JSON.stringify(body);
    if (guard) guard(url, text, ctx);
    else guardHttp({ url, method, body: text }, ctx, { role });
    const response = await api(url, {
      method,
      headers: {
        ...headers,
        ...(text === undefined ? {} : { "content-type": "application/json" }),
      },
      ...(text === undefined ? {} : { body: text }),
    });
    const answer = await response.text();
    let parsed;
    try {
      parsed = answer ? JSON.parse(answer) : {};
    } catch {
      parsed = {};
    }
    return {
      status: response.status,
      text: answer,
      body: parsed,
      date: response.headers.get("date"),
    };
  };
  const base = `${ITK}/admin/v2/projects/${SANDBOX_PROJECT}`;
  const accountsUrl = `${ITK}/v1/projects/${SANDBOX_PROJECT}/accounts:batchGet?maxResults=1`;
  const client = (method) => `${ITK}/v1/accounts:${method}?key=${meta.apiKey}`;
  const spEntityId = `fireemu-${run}-sp`;

  // Prechecks (read only): the config before, no SAML provider of an earlier run, no account.
  const before = await request("GET", `${base}/config`);
  if (before.status !== 200) throw new Error(`config read: ${before.status}`);
  const refusal = precheckRefusal(before.body, before.date, now());
  if (refusal) throw new Error(`precheck: ${refusal}`);
  const providers = await request("GET", `${base}/inboundSamlConfigs?pageSize=100`);
  const left = (providers.body.inboundSamlConfigs ?? []).filter((c) =>
    String(c.name).split("/").at(-1).startsWith("saml.fireemu-"),
  );
  if (providers.status !== 200 || left.length) {
    throw new Error(
      `SAML providers of earlier runs remain or cannot be listed (${providers.status})`,
    );
  }
  const accounts = await request("GET", accountsUrl);
  if (accounts.status !== 200 || (accounts.body.users ?? []).length) {
    throw new Error(`the project holds accounts or they cannot be listed (${accounts.status})`);
  }
  stop.check();
  const keysBefore = configKeyDigests(before.text);
  await appendLedger({
    event: "started",
    action: ACTION,
    attempt,
    run,
    provider,
    requestLimits: LIMITS,
    estimatedUsd: 0,
    gitSha: meta.gitSha,
    scriptDigest: meta.digest,
    // The config holds keys, so the ledger keeps digests only.
    configDigestBefore: sha256Hex(before.text),
    configKeyDigestsBefore: keysBefore,
  });

  const rows = {};
  const localIds = new Set();
  // From the create on, the provider may exist even if the answer is lost: it is deleted.
  let providerAttempted = false;
  let failure;
  try {
    providerAttempted = true;
    const created = await request(
      "POST",
      `${base}/inboundSamlConfigs?inboundSamlConfigId=${provider}`,
      providerBody(run, signer.certificatePem),
    );
    rows["create-provider"] = created;
    if (created.status !== 200)
      throw new Error(`provider create: ${created.status} ${created.text}`);
    const signIn = async (name, { sign, tampered = false }) => {
      stop.check();
      const uri = await request(
        "POST",
        client("createAuthUri"),
        { providerId: provider, continueUri: CALLBACK },
        { role: "step", headers: {} },
      );
      rows[`${name}-auth-uri`] = uri;
      if (uri.status !== 200 || !uri.body.authUri) return undefined;
      const authn = readAuthnRequest(uri.body.authUri);
      uri.authn = { acs: authn.acs, issuer: authn.issuer };
      // A request for another ACS or audience would make the response wrong: no sign-in.
      if ((authn.acs && authn.acs !== CALLBACK) || (authn.issuer && authn.issuer !== spEntityId)) {
        uri.mismatch = true;
        return undefined;
      }
      const suffix = randomBytes(6).toString("hex");
      const { xml } = signedSamlResponse(
        {
          responseId: `_r${suffix}`,
          assertionId: `_a${suffix}`,
          issuer: providerBody(run, "").idpConfig.idpEntityId,
          audience: spEntityId,
          destination: CALLBACK,
          inResponseTo: authn.id,
          nameId: `fireemu-fed-${run}@example.com`,
          now: now(),
        },
        { ...signer, sign },
      );
      const form = new URLSearchParams({
        SAMLResponse: Buffer.from(tampered ? tamper(xml) : xml, "utf8").toString("base64"),
        ...(authn.relayState ? { RelayState: authn.relayState } : {}),
      });
      const answer = await request(
        "POST",
        client("signInWithIdp"),
        {
          requestUri: CALLBACK,
          sessionId: uri.body.sessionId,
          postBody: form.toString(),
          returnSecureToken: true,
          returnIdpCredential: true,
        },
        { headers: {}, guard: guardSamlSignIn },
      );
      rows[name] = answer;
      if (typeof answer.body.localId === "string") localIds.add(answer.body.localId);
      return answer;
    };
    await signIn("tampered", { sign: "assertion", tampered: true });
    const assertionSigned = await signIn("assertion-signed", { sign: "assertion" });
    // Sent whatever the assertion-signed row answered (the coordinator's decision): production
    // may require the response to be signed.
    const responseSigned = await signIn("response-signed", { sign: "response" });
    if (assertionSigned?.status === 200 || responseSigned?.status === 200) {
      await signIn("both-signed", { sign: "both" });
    }
  } catch (error) {
    failure = error;
  }

  // Cleanup: every step runs whatever an earlier one met; a step that cannot be confirmed
  // leaves the run to recovery. Then the answers, then the terminal line with the rows.
  const cleanup = { accountsDeleted: [], errors: [] };
  const step = async (name, work) => {
    try {
      await work();
    } catch (error) {
      cleanup.errors.push(`${name}: ${error.message}`);
    }
  };
  for (const localId of localIds) {
    await step(`delete account`, async () => {
      const deleted = await request(
        "POST",
        `${ITK}/v1/projects/${SANDBOX_PROJECT}/accounts:delete`,
        { localId },
      );
      cleanup.accountsDeleted.push(deleted.status);
    });
  }
  if (providerAttempted) {
    await step("delete provider", async () => {
      cleanup.providerDelete = (
        await request("DELETE", `${base}/inboundSamlConfigs/${provider}`)
      ).status;
    });
    await step("read provider", async () => {
      cleanup.providerReadBack = (
        await request("GET", `${base}/inboundSamlConfigs/${provider}`)
      ).status;
    });
  }
  await step("list providers", async () => {
    const listed = await request("GET", `${base}/inboundSamlConfigs?pageSize=100`);
    cleanup.providersListStatus = listed.status;
    cleanup.providersLeft = (listed.body.inboundSamlConfigs ?? [])
      .map((c) => String(c.name).split("/").at(-1))
      .filter((id) => runProvider(run).test(id));
  });
  await step("list accounts", async () => {
    const listed = await request("GET", accountsUrl);
    cleanup.accountsLeft = listed.status === 200 ? (listed.body.users ?? []).length : -1;
  });
  await step("read config", async () => {
    const after = await request("GET", `${base}/config`);
    cleanup.configUnchanged = after.status === 200 && after.text === before.text;
    if (after.status === 200 && !cleanup.configUnchanged) {
      cleanup.configChangedKeys = changedKeys(keysBefore, configKeyDigests(after.text));
    }
  });
  // The read-backs decide: a step whose answer was lost is clean when they confirm it.
  const clean =
    (!providerAttempted || cleanup.providerReadBack === 404) &&
    cleanup.providersListStatus === 200 &&
    cleanup.providersLeft?.length === 0 &&
    cleanup.accountsLeft === 0 &&
    cleanup.configUnchanged === true;
  if (!cleanup.errors.length) delete cleanup.errors;
  const accepted = (name) => rows[name]?.status === 200;
  const tamperedRejected = rows.tampered !== undefined && !accepted("tampered");
  // Feasible only if production also refused the tampered signature: otherwise an accepted
  // row says nothing about signatures.
  const feasible =
    tamperedRejected && (accepted("assertion-signed") || accepted("response-signed"));
  const summary = Object.fromEntries(
    Object.entries(rows).map(([name, row]) => [
      name,
      {
        status: row.status,
        ...(row.body.error ? { error: row.body.error.message } : {}),
        ...(row.authn ? { authnRequest: row.authn } : {}),
        ...(row.mismatch ? { stopped: "the AuthnRequest names another ACS or audience" } : {}),
      },
    ]),
  );
  const outcome = !clean
    ? "needs-recovery"
    : accepted("tampered")
      ? "smoke-unexpected"
      : feasible
        ? "smoke-passed"
        : "failed-cleaned";
  const recorded = Object.fromEntries(
    Object.entries(rows).map(([name, row]) => [
      name,
      normalizeHttp(row.status, row.text, {
        run,
        project: SANDBOX_PROJECT,
        projectNumber: meta.projectNumber,
      }),
    ]),
  );
  let answersWritten = true;
  try {
    await writeAnswers(recorded);
  } catch {
    answersWritten = false;
  }
  const entry = {
    action: ACTION,
    attempt,
    outcome,
    ...(failure ? { error: failure.message } : {}),
    run,
    provider,
    feasible,
    tamperedRejected,
    rows: summary,
    ...cleanup,
    answersWritten,
    estimatedUsd: 0,
  };
  await appendLedger(entry);
  return { entry, recorded };
}

async function sh(command, args) {
  const { stdout } = await promisify(execFile)(command, args);
  return stdout.trim();
}

/** A fresh RSA key and its self-signed certificate; the key never touches a lasting file. */
async function makeSigner(run) {
  const dir = await mkdtemp(join(tmpdir(), "fireemu-saml-"));
  try {
    const key = join(dir, "key.pem");
    const cert = join(dir, "cert.pem");
    await sh("openssl", [
      "req",
      "-x509",
      "-newkey",
      "rsa:2048",
      "-nodes",
      "-keyout",
      key,
      "-out",
      cert,
      "-days",
      "2",
      "-subj",
      `/CN=fireemu-saml-${run}`,
    ]);
    return {
      privateKey: createPrivateKey(await readFile(key, "utf8")),
      certificatePem: await readFile(cert, "utf8"),
    };
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

/**
 * The attempt this task left unfinished: its run, digest and config digest, from its started
 * line, when the task's last line is that attempt's started line or a needs-recovery outcome
 * of the smoke or its recovery.
 */
export function samlRunToRecover(ledgerText) {
  const own = ledgerEntries(ledgerText).filter(
    (entry) => entry.project === SANDBOX_PROJECT && (entry.taskId ?? entry.task) === TASK_ID,
  );
  const last = own.at(-1);
  const open =
    last &&
    [ACTION, "saml-recover"].includes(last.action) &&
    (last.event === "started" || last.outcome === "needs-recovery");
  if (!open) return undefined;
  const started = own.findLast(
    (entry) => entry.event === "started" && entry.action === ACTION && entry.run === last.run,
  );
  if (!started?.configDigestBefore) throw new Error(`run ${last.run} has no started line`);
  return {
    run: checkRun(last.run),
    digest: started.scriptDigest,
    configDigestBefore: started.configDigestBefore,
    configKeyDigestsBefore: started.configKeyDigestsBefore ?? {},
  };
}

/**
 * Recovers an attempt: deletes the run's provider and the accounts that sign in with it,
 * reads both back and compares the config with its digest before the attempt. It never
 * writes the config; a changed config stays `needs-recovery` for the owner.
 */
export async function samlRecover({
  api,
  run,
  meta,
  appendLedger,
  configDigestBefore,
  configKeyDigestsBefore = {},
}) {
  checkRun(run);
  const provider = `saml.fireemu-${run}-s`;
  const admin = {
    authorization: `Bearer ${meta.adminToken}`,
    "x-goog-user-project": SANDBOX_PROJECT,
  };
  const ctx = { project: SANDBOX_PROJECT, run, target: { kind: "production" } };
  const request = async (method, url, body) => {
    const text = body === undefined ? undefined : JSON.stringify(body);
    guardHttp({ url, method, body: text }, ctx, { role: "harness" });
    const response = await api(url, {
      method,
      headers: { ...admin, ...(text === undefined ? {} : { "content-type": "application/json" }) },
      ...(text === undefined ? {} : { body: text }),
    });
    const answer = await response.text();
    let parsed = {};
    try {
      parsed = answer ? JSON.parse(answer) : {};
    } catch {
      parsed = {};
    }
    return { status: response.status, text: answer, body: parsed };
  };
  const base = `${ITK}/admin/v2/projects/${SANDBOX_PROJECT}`;
  const listUsers = async () => {
    const listed = await request(
      "GET",
      `${ITK}/v1/projects/${SANDBOX_PROJECT}/accounts:batchGet?maxResults=100`,
    );
    if (listed.status !== 200) throw new Error(`accounts read: ${listed.status}`);
    return (listed.body.users ?? []).filter((user) =>
      (user.providerUserInfo ?? []).some((info) => info.providerId === provider),
    );
  };
  let entry;
  try {
    const cleanup = { accountsDeleted: [] };
    cleanup.providerDelete = (
      await request("DELETE", `${base}/inboundSamlConfigs/${provider}`)
    ).status;
    cleanup.providerReadBack = (
      await request("GET", `${base}/inboundSamlConfigs/${provider}`)
    ).status;
    for (const user of await listUsers()) {
      const deleted = await request(
        "POST",
        `${ITK}/v1/projects/${SANDBOX_PROJECT}/accounts:delete`,
        {
          localId: user.localId,
        },
      );
      cleanup.accountsDeleted.push(deleted.status);
    }
    cleanup.accountsLeft = (await listUsers()).length;
    const config = await request("GET", `${base}/config`);
    cleanup.configUnchanged =
      config.status === 200 && sha256Hex(config.text) === configDigestBefore;
    if (config.status === 200 && !cleanup.configUnchanged) {
      cleanup.configChangedKeys = changedKeys(
        configKeyDigestsBefore,
        configKeyDigests(config.text),
      );
    }
    const clean =
      cleanup.providerReadBack === 404 && cleanup.accountsLeft === 0 && cleanup.configUnchanged;
    entry = { outcome: clean ? "recovered" : "needs-recovery", ...cleanup };
  } catch (error) {
    entry = { outcome: "needs-recovery", error: error.message };
  }
  entry = { action: "saml-recover", run, provider, ...entry, estimatedUsd: 0 };
  await appendLedger(entry);
  return entry;
}

/** The gates of every production send: environment, the owner's ADC, approval, a clean tree. */
async function gate(needs) {
  const env = Object.fromEntries(needs.map((name) => [name, process.env[name]]));
  const missing = needs.filter((name) => !env[name]);
  if (missing.length) throw new Error(`${missing.join(", ")} required`);
  for (const name of ["FIREBASE_TOKEN", "GOOGLE_APPLICATION_CREDENTIALS"]) {
    if (process.env[name]) throw new Error(`${name} must be unset (the owner's user ADC is used)`);
  }
  const digest = await scriptDigest();
  const attempts = approvedAttempts(await readFile(env.FIREEMU_OWNER_DECISIONS, "utf8"), digest);
  if ((await uncommitted(SOURCES)) !== "")
    throw new Error("the smoke's sources have uncommitted changes");
  return { env, digest, attempts };
}

const appender = (ledger, used, state) => (line) => {
  // Set first: a started line half written still leaves the lock held.
  if (line.event === "started") state.started = true;
  return appendFile(
    ledger,
    `${JSON.stringify({ ts: new Date().toISOString(), project: SANDBOX_PROJECT, taskId: TASK_ID, ...line, requests: { ...used } })}\n`,
  );
};

async function smokeFromEnvironment(attempt) {
  const { env, digest, attempts } = await gate([
    "FIREEMU_SANDBOX_LEDGER",
    "FIREEMU_OWNER_DECISIONS",
    "FIREEMU_AUTH_SANDBOX_WEB_CONFIG",
  ]);
  if (attempts < attempt) {
    throw new Error(`the owner ledger approves ${attempts} attempt(s) of saml-smoke ${digest}`);
  }
  const ledger = env.FIREEMU_SANDBOX_LEDGER;
  const web = JSON.parse(await readFile(env.FIREEMU_AUTH_SANDBOX_WEB_CONFIG, "utf8"));
  checkWebConfig(web);
  const run = randomBytes(3).toString("hex");
  const signer = await makeSigner(run);
  return withSandboxLock(
    ledger,
    async (state) => {
      state.run = run;
      const text = await readFile(ledger, "utf8").catch(() => "");
      const busy = sandboxBusy(text);
      if (busy) throw new Error(`the sandbox is not free: ${busy}`);
      const refused = attemptRefusal(text, attempt);
      if (refused) throw new Error(refused);
      const adminToken = await sh("gcloud", ["auth", "application-default", "print-access-token"]);
      const gitSha = await sh("git", ["-C", dirname(SOURCES[0]), "rev-parse", "HEAD"]);
      const { call, used } = limitedFetch(fetch, { run, limits: LIMITS });
      let stopped;
      const onSignal = (signal) => {
        stopped = signal;
      };
      for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) process.on(signal, onSignal);
      try {
        const { entry } = await samlSmoke({
          api: call,
          run,
          signer,
          attempt,
          now: () => Math.floor(Date.now() / 1000),
          stop: {
            check() {
              if (stopped) throw new Error(`stopped by ${stopped}`);
            },
          },
          meta: {
            adminToken,
            apiKey: web.apiKey,
            projectNumber: web.projectNumber,
            gitSha,
            digest,
          },
          appendLedger: appender(ledger, used, state),
          // Written before the terminal line, so a failure here never outlives the ledger.
          writeAnswers: async (answers) => {
            const out = join(dirname(ledger), `auth-federation-saml-${run}`);
            await mkdir(out, { recursive: true, mode: 0o700 });
            await writeFile(join(out, "answers.json"), `${JSON.stringify(answers, null, 2)}\n`, {
              mode: 0o600,
            });
          },
        });
        console.log(JSON.stringify(entry, null, 2));
        if (entry.outcome !== "smoke-passed") process.exitCode = 1;
        return entry;
      } finally {
        for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) process.off(signal, onSignal);
      }
    },
    { keep: (entry) => entry.outcome === "needs-recovery" },
  );
}

async function recoverFromEnvironment() {
  const { env, digest, attempts } = await gate([
    "FIREEMU_SANDBOX_LEDGER",
    "FIREEMU_OWNER_DECISIONS",
  ]);
  if (attempts < 1) throw new Error(`the owner ledger does not approve saml-smoke ${digest}`);
  const ledger = env.FIREEMU_SANDBOX_LEDGER;
  const target = samlRunToRecover(await readFile(ledger, "utf8"));
  if (!target) throw new Error("the ledger shows no SAML attempt of this task to recover");
  if (target.digest !== digest) {
    throw new Error(`run ${target.run} ran digest ${target.digest}, not this script's ${digest}`);
  }
  return withSandboxLock(
    ledger,
    async (state) => {
      state.run = target.run;
      const adminToken = await sh("gcloud", ["auth", "application-default", "print-access-token"]);
      const { call, used } = limitedFetch(fetch, { run: target.run, limits: LIMITS });
      const entry = await samlRecover({
        api: call,
        run: target.run,
        configDigestBefore: target.configDigestBefore,
        configKeyDigestsBefore: target.configKeyDigestsBefore,
        meta: { adminToken },
        appendLedger: appender(ledger, used, state),
      });
      console.log(JSON.stringify(entry, null, 2));
      if (entry.outcome !== "recovered") process.exitCode = 1;
      return entry;
    },
    { keep: (entry) => entry.outcome !== "recovered", ours: existsSync(`${ledger}.lock`) },
  );
}

const invoked = process.argv[1] === fileURLToPath(import.meta.url);
const mode = invoked ? process.argv[2] : undefined;
if (mode === "digest") console.log(await scriptDigest());
else if (mode === "recover") await recoverFromEnvironment();
else if (mode === "smoke") {
  const index = process.argv.indexOf("--attempt");
  const attempt = Number(process.argv[index + 1]);
  if (index < 0 || ![1, 2].includes(attempt)) throw new Error("smoke needs --attempt 1 or 2");
  await smokeFromEnvironment(attempt);
} else if (mode !== undefined) throw new Error(`unknown mode ${mode}`);
