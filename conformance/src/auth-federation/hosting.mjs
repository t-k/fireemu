// The controlled OIDC issuer of AUTH-FEDERATION on the sandbox's Firebase Hosting (owner
// decision O1): a smoke that deploys the run's discovery document and public JWKS to a
// preview channel, reads them back, deletes the channel and reads that back, all under the
// shared sandbox lock and within fixed request limits. It creates no Auth provider.
//
//   node src/auth-federation/hosting.mjs digest   # the script digest an approval names
//   node src/auth-federation/hosting.mjs smoke    # needs the environment below
//   node src/auth-federation/hosting.mjs recover  # after a run that needs recovery
//
// It speaks the Hosting REST API directly, never the firebase CLI: the CLI's channel
// commands rewrite Identity Platform's authorizedDomains (firebase-tools 15.23.0
// `hosting:channel:deploy` without `--no-authorized-domains`, `hosting:channel:create` and
// `hosting:channel:delete` always), which O1 does not cover. Creating the channel first
// gives its URL, so the issuer is known before anything is published and one version is
// deployed. authorizedDomains is read before and after and must be unchanged.
//
// Environment: FIREEMU_SANDBOX_LEDGER (the shared ledger; its `.lock` is taken),
// FIREEMU_OWNER_DECISIONS (the owner ledger, which must approve this script's digest),
// FIREEMU_AUTH_SANDBOX_WEB_CONFIG (for the project number and API key the scan refuses).
// Credentials are the owner's user ADC; FIREBASE_TOKEN and GOOGLE_APPLICATION_CREDENTIALS
// must be unset.

import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname } from "node:path";
import { createHash, randomBytes } from "node:crypto";
import { appendFile, open, readFile, rm, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { gzipSync } from "node:zlib";

import { SANDBOX_PROJECT } from "../auth-account/harness.mjs";
import { checkRun, issuerChannelHost } from "./guard.mjs";
import { generateSigningKey, issuerSite } from "./idp.mjs";

// The digest covers the module that names the project; this checks the name it gives.
if (SANDBOX_PROJECT !== "fireemu-oracle-idp") {
  throw new Error(`the sandbox project is ${SANDBOX_PROJECT}, not fireemu-oracle-idp`);
}

export const TASK_ID = "AUTH-FEDERATION-SANDBOX";
export const SITE = SANDBOX_PROJECT;
const HOSTING = "https://firebasehosting.googleapis.com/v1beta1";
const ITK = "https://identitytoolkit.googleapis.com";
const USAGE = "https://serviceusage.googleapis.com/v1";

/**
 * The request limits the ledger names. API: 4 prechecks, 6 deploy requests (channel, version,
 * populateFiles, 2 uploads, finalize), 1 release, 1 delete, 3 read-backs after it (config,
 * channel, version). Issuer fetches: 2 read-backs and at most 5 rounds of 2 after the delete.
 */
export const LIMITS = { api: 15, issuer: 12 };
const GONE_ROUNDS = 5;
const GONE_INTERVAL_MS = 60_000;
const QUIET_MS = 30 * 60_000;

/**
 * The smoke's modules, by absolute path: the approval names the digest of their sources,
 * including the module that names the sandbox project.
 */
export const SOURCES = ["hosting.mjs", "idp.mjs", "guard.mjs", "../auth-account/harness.mjs"].map(
  (name) => fileURLToPath(new URL(name, import.meta.url)),
);

export async function scriptDigest(read = (path) => readFile(path), sources = SOURCES) {
  const hash = createHash("sha256");
  for (const path of sources) hash.update(await read(path));
  return hash.digest("hex");
}

const escapeRegExp = (text) => text.replaceAll(/[.*+?^${}()|[\]\\]/g, "\\$&");

/**
 * The owner-ledger line that approves `packet` at `digest`, or undefined. Only a line of the
 * form `- YYYY-MM-DD | AUTH-FEDERATION | … <packet> APPROVED <64-digit digest> … | オーナー… |`
 * approves: the full digest, the fixed word, the owner as the decider. A later line with
 * `<packet> REVOKED <digest>` withdraws it (a still later approval restores it). `attempts`
 * is 2 when the approving line says `attempts 2`.
 */
export function ownerApproval(ownerDecisions, packet, digest) {
  if (!/^[0-9a-f]{64}$/.test(digest)) throw new Error("a digest is 64 hex digits");
  const word = (verb) =>
    new RegExp(`(?:^|[^\\w-])${escapeRegExp(packet)} ${verb} ${digest}(?![0-9A-Za-z])`);
  let approval;
  for (const line of ownerDecisions.split("\n")) {
    if (word("REVOKED").test(line)) {
      approval = undefined;
      continue;
    }
    const columns = /^- \d{4}-\d{2}-\d{2} \| AUTH-FEDERATION \| /.test(line)
      ? line.slice(2).split(" | ")
      : [];
    if (columns.length < 4 || !word("APPROVED").test(columns[2])) continue;
    if (!columns[3].trim().startsWith("オーナー")) continue;
    approval = { line, attempts: /\battempts 2\b/.test(columns[2]) ? 2 : 1 };
  }
  return approval;
}

/** Whether the owner ledger approves the Hosting smoke at `digest`. */
export function approved(ownerDecisions, digest) {
  return ownerApproval(ownerDecisions, "hosting-smoke", digest) !== undefined;
}

/**
 * The web app config's project number and API key, which the scan refuses to publish, after
 * checking that the config is the sandbox's: a mismatch or a missing value stops the run.
 */
export function checkWebConfig(web) {
  if (web?.projectId !== SANDBOX_PROJECT) throw new Error("the web config is not the sandbox's");
  if (!/^\d+$/.test(web.projectNumber ?? "") || web.projectNumber !== web.messagingSenderId) {
    throw new Error("the web config has no consistent project number");
  }
  if (!/^[A-Za-z0-9_-]{20,}$/.test(web.apiKey ?? ""))
    throw new Error("the web config has no API key");
  return [web.apiKey, web.projectNumber];
}

/** The ledger's lines; a line that does not parse stops the run (it cannot tell who is on). */
export function ledgerEntries(text) {
  return text
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

const taskOf = (entry) => entry.taskId ?? entry.task ?? "<unnamed>";

/** Lanes write a pending recovery as an outcome or as an event. */
const needsRecovery = (entry) =>
  entry?.outcome === "needs-recovery" || entry?.event === "needs-recovery";

/**
 * Whether a line ends a run cleanly: a closing line (an outcome other than needs-recovery,
 * `finished` or `cleanup-verified`) that does not say the sandbox was left off its baseline.
 * Notes, changes, controls and progress lines end nothing (the rule of AUTH-FS-CROSS and
 * AUTH-TENANT-BLOCKING).
 */
export function endsRun(entry) {
  if (entry.event === "started" || needsRecovery(entry)) return false;
  const closing =
    entry.outcome !== undefined || entry.event === "finished" || entry.event === "cleanup-verified";
  return closing && entry.sandboxAtBaseline !== false;
}

/**
 * Why the sandbox is not free for this task, or undefined:
 * - a run (this task's or another's) opened by `started` or `needs-recovery` and not followed
 *   by a line of that task that ends it (`endsRun`), however old;
 * - another task's line within the last 30 minutes;
 * - a line whose time does not parse (no rule could judge it).
 */
export function sandboxBusy(text, now = Date.now()) {
  const lines = ledgerEntries(text).filter((entry) => entry.project === SANDBOX_PROJECT);
  const running = new Map();
  for (const entry of lines) {
    const task = taskOf(entry);
    if (Number.isNaN(Date.parse(entry.ts))) return `${task} wrote a line whose time does not parse`;
    if (entry.event === "started" || needsRecovery(entry)) running.set(task, entry);
    else if (endsRun(entry)) running.delete(task);
  }
  const own = running.get(TASK_ID);
  if (own)
    return `this task's run ${own.run ?? ""} at ${own.ts} was not finished; recover it first`;
  const unfinished = [...running.values()][0];
  if (unfinished) return `${taskOf(unfinished)} at ${unfinished.ts} has not finished or recovered`;
  const recent = lines.find(
    (entry) => taskOf(entry) !== TASK_ID && now - Date.parse(entry.ts) < QUIET_MS,
  );
  return recent ? `${taskOf(recent)} wrote a line at ${recent.ts}` : undefined;
}

/** Whether the process a lock names still runs. */
function holderAlive(holder) {
  const pid = Number(/\bpid (\d+)/.exec(holder)?.[1]);
  if (!pid) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error.code === "EPERM";
  }
}

/**
 * Runs `work(state)` holding `<ledger>.lock`, created exclusively, as every sandbox lane does.
 * The lock stays, rewritten to say `needs-recovery`, whenever the sandbox may not be at its
 * baseline, so no lane starts on it: when `keep(result)` holds, and when `work` throws after
 * `state.started` was set (the run wrote its started line) or while recovering (`ours`).
 * `ours` takes over a lock this task left, only when it says `needs-recovery` or its process
 * is gone, never a running smoke's.
 */
export async function withSandboxLock(ledger, work, { keep = () => false, ours = false } = {}) {
  const lock = `${ledger}.lock`;
  let handle;
  try {
    handle = await open(lock, ours ? "r+" : "wx", 0o600);
  } catch (error) {
    if (error.code !== "EEXIST") throw error;
    const holder = await readFile(lock, "utf8").catch(() => "unknown");
    throw new Error(`another run holds ${lock} (${holder.trim()})`, { cause: error });
  }
  if (ours) {
    const holder = await handle.readFile("utf8");
    const takeable =
      holder.startsWith(`${TASK_ID} `) && (/ needs-recovery /.test(holder) || !holderAlive(holder));
    if (!takeable) {
      await handle.close();
      throw new Error(`${lock} is not this task's to recover (${holder.trim()})`);
    }
    await handle.truncate(0);
  }
  const state = { started: false, run: undefined };
  let kept = false;
  const leave = async (run) => {
    kept = true;
    await writeFile(
      lock,
      `${TASK_ID} needs-recovery run ${run ?? "unknown"} since ${new Date().toISOString()}\n`,
    );
  };
  try {
    await handle.write(`${TASK_ID} pid ${process.pid} since ${new Date().toISOString()}\n`, 0);
    await handle.close();
    let result;
    try {
      result = await work(state);
    } catch (error) {
      if (ours || state.started) await leave(state.run);
      throw error;
    }
    if (keep(result)) await leave(result.run ?? state.run);
    return result;
  } finally {
    if (!kept) await rm(lock, { force: true });
  }
}

/**
 * Counts requests against the limits and refuses any URL outside the reviewed ones: the
 * Hosting, Identity Toolkit, Secure Token and Service Usage APIs, the upload URL
 * populateFiles names, and the run's channel host. (What each API may be asked is the
 * caller's guard; the smokes read the config only, the recording runs the corpus guard.)
 */
export function limitedFetch(fetchImpl, { run, limits = LIMITS }) {
  const used = { api: 0, issuer: 0 };
  const channel = issuerChannelHost(SANDBOX_PROJECT, run);
  const call = async (url, init = {}) => {
    const { protocol, host } = new URL(url);
    if (protocol !== "https:") throw new Error(`not https: ${url}`);
    const kind = channel.test(host)
      ? "issuer"
      : [
            "firebasehosting.googleapis.com",
            "upload-firebasehosting.googleapis.com",
            "identitytoolkit.googleapis.com",
            "securetoken.googleapis.com",
            "serviceusage.googleapis.com",
          ].includes(host)
        ? "api"
        : undefined;
    if (!kind) throw new Error(`host ${host} is not reviewed`);
    if (used[kind] >= limits[kind])
      throw new Error(`${kind} request limit ${limits[kind]} reached`);
    used[kind] += 1;
    // A redirect would leave the reviewed URL: it fails instead of being followed.
    return fetchImpl(url, { ...init, redirect: "error" });
  };
  return { call, used };
}

async function json(response, what) {
  const text = await response.text();
  let body;
  try {
    body = text ? JSON.parse(text) : {};
  } catch {
    body = { unparsed: text.slice(0, 200) };
  }
  if (!response.ok) {
    const error = new Error(
      `${what}: HTTP ${response.status} ${JSON.stringify(body).slice(0, 300)}`,
    );
    error.status = response.status;
    throw error;
  }
  return body;
}

/** Stops the smoke at the next step after SIGINT, SIGTERM or SIGHUP; cleanup still runs. */
function stopSignals() {
  const state = { stopped: undefined };
  const handler = (signal) => {
    if (state.stopped) console.error("cleanup is running; wait for it");
    state.stopped = signal;
  };
  for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) process.on(signal, handler);
  return {
    state,
    check() {
      if (state.stopped) throw new Error(`stopped by ${state.stopped}`);
    },
    remove() {
      for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) process.off(signal, handler);
    },
  };
}

/**
 * The smoke itself, with every effect injected: `api(url, init)` (counted), `token`,
 * `appendLedger(entry)`, `sleep(ms)` and `stop.check()`. Returns the terminal ledger entry.
 * The channel is deleted whenever it was created, and the deletion is read back.
 */
/** Authenticated JSON requests to the sandbox's APIs through the counted `api`. */
export function clients(api, token) {
  const auth = { authorization: `Bearer ${token}`, "x-goog-user-project": SANDBOX_PROJECT };
  const get = async (url, what) => json(await api(url, { headers: auth }), what);
  const send = async (method, url, body, what) =>
    json(
      await api(url, {
        method,
        headers: { ...auth, "content-type": "application/json" },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      }),
      what,
    );
  return { auth, get, send };
}

const channelPathOf = (run) =>
  `${HOSTING}/projects/${SANDBOX_PROJECT}/sites/${SITE}/channels/fed-${run}`;
const CONFIG_URL = `${ITK}/admin/v2/projects/${SANDBOX_PROJECT}/config`;

/**
 * Deletes the run's channel and reads the deletion back: the channel is absent, the version
 * status, and the issuer's files no longer served (at most five rounds a minute apart; a
 * cached copy holds public keys only). A channel already gone counts as deleted.
 */
async function removeChannel({ get, send, api, sleep, run, version, issuerHost, deleteVersion }) {
  const channelPath = channelPathOf(run);
  const cleanup = {};
  try {
    await send("DELETE", channelPath, undefined, "channel delete");
    cleanup.channelDeleted = true;
  } catch (error) {
    cleanup.channelDeleted = error.status === 404;
    if (error.status !== 404) cleanup.deleteError = error.message;
  }
  try {
    await get(channelPath, "channel read back");
    cleanup.channelReadBack = "present";
  } catch (error) {
    cleanup.channelReadBack = error.status === 404 ? "absent" : `error ${error.message}`;
  }
  if (version && deleteVersion) {
    // Only the version this run created; gone is 404 or DELETED.
    try {
      await send("DELETE", `${HOSTING}/${version}`, undefined, "version delete");
      cleanup.versionDeleted = true;
    } catch (error) {
      cleanup.versionDeleted = error.status === 404;
      if (error.status !== 404) cleanup.versionDeleteError = error.message;
    }
  }
  if (version) {
    try {
      cleanup.versionStatus = (await get(`${HOSTING}/${version}`, "version")).status;
    } catch (error) {
      cleanup.versionStatus = error.status === 404 ? "absent" : `error ${error.message}`;
    }
  }
  if (issuerHost) {
    cleanup.issuerGone = false;
    for (let round = 0; round < GONE_ROUNDS && !cleanup.issuerGone; round += 1) {
      if (round > 0) await sleep(GONE_INTERVAL_MS);
      const statuses = [];
      for (const path of [
        `/oidc/${run}/.well-known/openid-configuration`,
        `/oidc/${run}/jwks.json`,
      ]) {
        try {
          statuses.push((await api(`https://${issuerHost}${path}`, { headers: {} })).status);
        } catch {
          statuses.push(-1);
        }
      }
      cleanup.issuerStatuses = statuses;
      cleanup.issuerGone = statuses.every((status) => status !== 200);
    }
  }
  return cleanup;
}

/** Whether authorizedDomains still reads as `before` (or why it could not be read). */
async function domainsUnchanged(get, before) {
  try {
    const after = (await get(CONFIG_URL, "config after")).authorizedDomains ?? [];
    return JSON.stringify(after) === JSON.stringify(before);
  } catch (error) {
    return `error ${error.message}`;
  }
}

/** Whether the sandbox is back at its baseline after a cleanup. */
function cleanOf(cleanup, channelCreated) {
  // A channel still served after the last round holds public keys only, but is recovered.
  return (
    (!channelCreated ||
      (cleanup.channelDeleted === true &&
        cleanup.channelReadBack === "absent" &&
        cleanup.issuerGone !== false)) &&
    cleanup.authorizedDomainsUnchanged === true
  );
}

/**
 * Publishes the run's issuer: creates the preview channel `fed-<run>` (whose URL names the
 * issuer), one version holding the discovery document and the JWKS, releases it and reads
 * both files back. `result` records how far it got (`channelAttempted`, `channelCreated`,
 * `issuerHost`, `version`, `readback`), also when it throws.
 */
export async function deployIssuer({
  api,
  auth,
  send,
  run,
  jwks,
  forbidden,
  stop,
  result,
  journal = async () => {},
}) {
  const channelId = `fed-${run}`;
  // From here the channel may exist even if the answer is lost: the cleanup probes it.
  result.channelAttempted = true;
  const channel = await send(
    "POST",
    `${HOSTING}/projects/${SANDBOX_PROJECT}/sites/${SITE}/channels?channelId=${channelId}`,
    { ttl: "86400s" },
    "channel create",
  );
  result.channelCreated = true;
  const host = new URL(channel.url).host;
  if (!issuerChannelHost(SANDBOX_PROJECT, run).test(host)) {
    throw new Error(`channel host ${host} is not the run's preview channel`);
  }
  result.issuerHost = host;
  const issuer = `https://${host}/oidc/${run}`;
  const site = issuerSite({ issuer, run, jwks, forbidden });
  stop.check();

  // Journalled before and after, so a recovery knows whether a version may exist and which.
  result.versionAttempted = true;
  await journal({ step: "version-create-sent" });
  const version = await send(
    "POST",
    `${HOSTING}/projects/-/sites/${SITE}/versions`,
    {},
    "version create",
  );
  result.version = version.name;
  await journal({ versionId: String(version.name).split("/").at(-1) });
  const zipped = Object.fromEntries(
    Object.entries(site.files).map(([path, text]) => [path, gzipSync(text)]),
  );
  const hashes = Object.fromEntries(
    Object.entries(zipped).map(([path, gz]) => [
      path,
      createHash("sha256").update(gz).digest("hex"),
    ]),
  );
  const populated = await send(
    "POST",
    `${HOSTING}/${version.name}:populateFiles`,
    { files: hashes },
    "populateFiles",
  );
  const uploadUrl = new URL(populated.uploadUrl);
  if (uploadUrl.host !== "upload-firebasehosting.googleapis.com") {
    throw new Error(`upload URL ${uploadUrl.host} is not reviewed`);
  }
  for (const [path, hash] of Object.entries(hashes)) {
    if (!(populated.uploadRequiredHashes ?? []).includes(hash)) continue;
    const response = await api(`${populated.uploadUrl}/${hash}`, {
      method: "POST",
      headers: { ...auth, "content-type": "application/octet-stream" },
      body: zipped[path],
    });
    await json(response, `upload ${path}`);
  }
  await send(
    "PATCH",
    `${HOSTING}/${version.name}?updateMask=status,config`,
    { status: "FINALIZED", config: site.config },
    "finalize",
  );
  await send(
    "POST",
    `${HOSTING}/projects/-/sites/${SITE}/channels/${channelId}/releases?versionName=${encodeURIComponent(version.name)}`,
    {},
    "release",
  );
  stop.check();

  // Read back what an Identity Platform fetch would get.
  result.readback = {};
  for (const [path, text] of Object.entries(site.files)) {
    const response = await api(`https://${host}${path}`, { headers: {} });
    const body = await response.text();
    const type = response.headers.get("content-type") ?? "";
    const same = response.status === 200 && body === text;
    result.readback[path] = { status: response.status, contentType: type, same };
    if (!same || !type.startsWith("application/json")) {
      throw new Error(`read back of ${path}: ${response.status} ${type} same=${same}`);
    }
  }
}

/**
 * Removes what `deployIssuer` recorded in `result`: a create whose answer was lost is probed
 * first; the channel (and, with `deleteVersion`, the version) is deleted and read back.
 */
export async function removeIssuer({ get, send, api, sleep, run, result, deleteVersion = false }) {
  // A create whose answer was lost or refused is probed: a channel that exists is removed.
  let created = result.channelCreated;
  const probe = {};
  if (!created && result.channelAttempted) {
    try {
      await get(channelPathOf(run), "channel probe");
      created = true;
    } catch (error) {
      if (error.status !== 404) probe.channelProbe = `error ${error.message}`;
    }
  }
  const cleanup = created
    ? await removeChannel({
        get,
        send,
        api,
        sleep,
        run,
        version: result.version,
        issuerHost: result.issuerHost,
        deleteVersion,
      })
    : probe;
  return { created, cleanup };
}

export async function hostingSmoke({ api, run, jwks, forbidden, appendLedger, sleep, stop, meta }) {
  checkRun(run);
  const { auth, get, send } = clients(api, meta.token);
  const channelId = `fed-${run}`;
  const configUrl = CONFIG_URL;
  const result = { run, channelId, channelCreated: false, channelAttempted: false };

  // Prechecks (read only): Hosting is enabled, the default site exists, no channel of an
  // earlier run is left, and authorizedDomains before.
  const usage = await get(
    `${USAGE}/projects/${SANDBOX_PROJECT}/services/firebasehosting.googleapis.com`,
    "firebasehosting service",
  );
  if (usage.state !== "ENABLED") throw new Error(`firebasehosting is ${usage.state}; stop`);
  await get(`${HOSTING}/projects/${SANDBOX_PROJECT}/sites/${SITE}`, "default site");
  const channels = await get(
    `${HOSTING}/projects/${SANDBOX_PROJECT}/sites/${SITE}/channels?pageSize=100`,
    "channels",
  );
  const leftover = (channels.channels ?? []).filter((c) =>
    String(c.name).split("/").at(-1).startsWith("fed-"),
  );
  if (leftover.length)
    throw new Error(`channels of earlier runs remain: ${leftover.map((c) => c.name)}`);
  const before = (await get(configUrl, "config")).authorizedDomains ?? [];
  stop.check();

  await appendLedger({
    event: "started",
    action: "hosting-smoke",
    run,
    channelId,
    requestLimits: LIMITS,
    estimatedUsd: 0,
    gitSha: meta.gitSha,
    scriptDigest: meta.digest,
    authorizedDomainsBefore: before,
  });
  let failure;
  try {
    await deployIssuer({ api, auth, send, run, jwks, forbidden, stop, result });
  } catch (error) {
    failure = error;
  }

  const { created, cleanup } = await removeIssuer({ get, send, api, sleep, run, result });
  cleanup.authorizedDomainsUnchanged = await domainsUnchanged(get, before);
  const clean = cleanOf(cleanup, created) && cleanup.channelProbe === undefined;
  const entry = {
    outcome: failure
      ? clean
        ? "failed-cleaned"
        : "needs-recovery"
      : clean
        ? "smoke-passed"
        : "needs-recovery",
    ...(failure ? { error: failure.message } : {}),
    run,
    channelId,
    issuerHost: result.issuerHost,
    readback: result.readback,
    ...cleanup,
    estimatedUsd: 0,
  };
  await appendLedger(entry);
  return entry;
}

/**
 * Recovers a run that needs it: deletes the run's channel if it is there (reading its host
 * first), reads the deletion back and compares authorizedDomains with the value the run's
 * started line recorded. It never writes the Auth config: a changed authorizedDomains stays
 * `needs-recovery` for the owner to decide.
 */
export async function hostingRecover({
  api,
  run,
  before,
  issuerHost: recorded,
  appendLedger,
  sleep,
  meta,
}) {
  checkRun(run);
  const { get, send } = clients(api, meta.token);
  const channel = issuerChannelHost(SANDBOX_PROJECT, run);
  // The host the run recorded is fetched again even when the channel is gone (a cached copy).
  let issuerHost = channel.test(recorded ?? "") ? recorded : undefined;
  let entry;
  try {
    try {
      const found = await get(channelPathOf(run), "channel");
      const host = URL.canParse(found.url) ? new URL(found.url).host : "";
      if (channel.test(host)) issuerHost = host;
    } catch (error) {
      if (error.status !== 404) throw error;
    }
    const cleanup = await removeChannel({ get, send, api, sleep, run, issuerHost });
    cleanup.authorizedDomainsUnchanged = await domainsUnchanged(get, before);
    entry = {
      outcome: cleanOf(cleanup, true) ? "recovered" : "needs-recovery",
      issuerHost,
      ...cleanup,
    };
  } catch (error) {
    entry = { outcome: "needs-recovery", error: error.message, issuerHost };
  }
  entry = { action: "hosting-recover", run, channelId: `fed-${run}`, ...entry, estimatedUsd: 0 };
  await appendLedger(entry);
  return entry;
}

async function sh(command, args) {
  const { stdout } = await promisify(execFile)(command, args);
  return stdout.trim();
}

/** Whether any of `sources` differs from the commit, wherever the process was started. */
export async function uncommitted(sources = SOURCES) {
  const root = dirname(sources[0]);
  return sh("git", ["-C", root, "status", "--porcelain", "--", ...sources]);
}

/**
 * The gates every production send of this script passes (smoke and recover): the
 * environment, credentials that are the owner's user ADC, an owner approval of this exact
 * digest, and sources equal to the commit.
 */
export async function gate({ needs }) {
  const env = Object.fromEntries(needs.map((name) => [name, process.env[name]]));
  const missing = needs.filter((name) => !env[name]);
  if (missing.length) throw new Error(`${missing.join(", ")} required`);
  for (const name of ["FIREBASE_TOKEN", "GOOGLE_APPLICATION_CREDENTIALS"]) {
    if (process.env[name]) throw new Error(`${name} must be unset (the owner's user ADC is used)`);
  }
  const digest = await scriptDigest();
  if (!approved(await readFile(env.FIREEMU_OWNER_DECISIONS, "utf8"), digest)) {
    throw new Error(`no owner-ledger line approves hosting-smoke ${digest}`);
  }
  if ((await uncommitted()) !== "") throw new Error("the smoke's sources have uncommitted changes");
  return { env, digest };
}

async function smokeFromEnvironment() {
  const { env, digest } = await gate({
    needs: ["FIREEMU_SANDBOX_LEDGER", "FIREEMU_OWNER_DECISIONS", "FIREEMU_AUTH_SANDBOX_WEB_CONFIG"],
  });
  const ledger = env.FIREEMU_SANDBOX_LEDGER;
  const forbidden = checkWebConfig(
    JSON.parse(await readFile(env.FIREEMU_AUTH_SANDBOX_WEB_CONFIG, "utf8")),
  );
  const run = randomBytes(3).toString("hex");
  // Only the public half leaves the process; the smoke signs nothing.
  const { jwk } = generateSigningKey({ kid: `fireemu-smoke-${run}` });
  return withSandboxLock(
    ledger,
    async (state) => {
      state.run = run;
      const busy = sandboxBusy(await readFile(ledger, "utf8").catch(() => ""));
      if (busy) throw new Error(`the sandbox is not free: ${busy}`);
      const token = await sh("gcloud", ["auth", "application-default", "print-access-token"]);
      const gitSha = await sh("git", ["rev-parse", "HEAD"]);
      const { call, used } = limitedFetch(fetch, { run });
      const stop = stopSignals();
      try {
        const entry = await hostingSmoke({
          api: call,
          run,
          jwks: [jwk],
          forbidden,
          sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
          stop,
          meta: { token, gitSha, digest },
          appendLedger: (line) => {
            // Set first: a started line half written still leaves the lock held.
            if (line.event === "started") state.started = true;
            return appendFile(
              ledger,
              `${JSON.stringify({ ts: new Date().toISOString(), project: SANDBOX_PROJECT, taskId: TASK_ID, ...line, requests: { ...used } })}\n`,
            );
          },
        });
        console.log(JSON.stringify(entry, null, 2));
        if (entry.outcome !== "smoke-passed") process.exitCode = 1;
        return entry;
      } finally {
        stop.remove();
      }
    },
    { keep: (entry) => entry.outcome === "needs-recovery" },
  );
}

/**
 * The run this task left unfinished: its tag, the authorizedDomains and script digest its
 * started line recorded, and the issuer host its last line named.
 */
export function runToRecover(ledgerText) {
  const own = ledgerEntries(ledgerText).filter(
    (entry) => entry.project === SANDBOX_PROJECT && taskOf(entry) === TASK_ID,
  );
  const last = own.at(-1);
  if (!last || !(last.event === "started" || last.outcome === "needs-recovery")) return undefined;
  const started = own.findLast((entry) => entry.event === "started" && entry.run === last.run);
  if (!started || !Array.isArray(started.authorizedDomainsBefore)) {
    throw new Error(`run ${last.run} has no started line with authorizedDomainsBefore`);
  }
  const host = own.findLast((entry) => entry.run === last.run && entry.issuerHost)?.issuerHost;
  return {
    run: checkRun(last.run),
    before: started.authorizedDomainsBefore,
    digest: started.scriptDigest,
    issuerHost: host,
  };
}

async function recoverFromEnvironment() {
  const { env, digest } = await gate({
    needs: ["FIREEMU_SANDBOX_LEDGER", "FIREEMU_OWNER_DECISIONS"],
  });
  const ledger = env.FIREEMU_SANDBOX_LEDGER;
  const target = runToRecover(await readFile(ledger, "utf8"));
  if (!target) throw new Error("the ledger shows no run of this task to recover");
  if (target.digest !== digest) {
    throw new Error(`run ${target.run} ran digest ${target.digest}, not this script's ${digest}`);
  }
  const ours = existsSync(`${ledger}.lock`);
  return withSandboxLock(
    ledger,
    async (state) => {
      state.run = target.run;
      const token = await sh("gcloud", ["auth", "application-default", "print-access-token"]);
      const { call, used } = limitedFetch(fetch, { run: target.run });
      const entry = await hostingRecover({
        api: call,
        run: target.run,
        before: target.before,
        issuerHost: target.issuerHost,
        sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
        meta: { token },
        appendLedger: (line) =>
          appendFile(
            ledger,
            `${JSON.stringify({ ts: new Date().toISOString(), project: SANDBOX_PROJECT, taskId: TASK_ID, ...line, requests: { ...used } })}\n`,
          ),
      });
      console.log(JSON.stringify(entry, null, 2));
      if (entry.outcome !== "recovered") process.exitCode = 1;
      return entry;
    },
    { keep: (entry) => entry.outcome !== "recovered", ours },
  );
}

const mode = process.argv[1] === fileURLToPath(import.meta.url) ? process.argv[2] : undefined;
if (mode === "digest") console.log(await scriptDigest());
else if (mode === "smoke") await smokeFromEnvironment();
else if (mode === "recover") await recoverFromEnvironment();
else if (mode !== undefined) throw new Error(`unknown mode ${mode}`);
