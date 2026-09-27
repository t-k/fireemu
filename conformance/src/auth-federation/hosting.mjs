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
import { createHash, randomBytes } from "node:crypto";
import { appendFile, open, readFile, rm, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { gzipSync } from "node:zlib";

import { SANDBOX_PROJECT } from "../auth-account/harness.mjs";
import { checkRun, issuerChannelHost } from "./guard.mjs";
import { generateSigningKey, issuerSite } from "./idp.mjs";

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

/** The smoke's modules: the approval names the digest of their sources. */
const SOURCES = ["hosting.mjs", "idp.mjs", "guard.mjs"].map((name) =>
  fileURLToPath(new URL(name, import.meta.url)),
);

export async function scriptDigest(read = (path) => readFile(path)) {
  const hash = createHash("sha256");
  for (const path of SOURCES) hash.update(await read(path));
  return hash.digest("hex");
}

/**
 * Whether the owner ledger approves this script: a line naming AUTH-FEDERATION, the
 * `hosting-smoke` packet and the first 12 hex digits of the script digest.
 */
export function approved(ownerDecisions, digest) {
  return ownerDecisions
    .split("\n")
    .some(
      (line) =>
        line.includes("AUTH-FEDERATION") &&
        line.includes("hosting-smoke") &&
        line.includes(digest.slice(0, 12)),
    );
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

/**
 * Why the sandbox is not free for this task, or undefined: this task's own run left open
 * (recover it first), another task's open `started` line, or another task's line within the
 * last 30 minutes (a time that does not parse counts as recent).
 */
export function sandboxBusy(text, now = Date.now()) {
  const lines = ledgerEntries(text).filter((entry) => entry.project === SANDBOX_PROJECT);
  const last = new Map();
  for (const entry of lines) last.set(taskOf(entry), entry);
  const own = last.get(TASK_ID);
  if (own?.event === "started" || own?.outcome === "needs-recovery") {
    return `this task's run ${own.run ?? ""} at ${own.ts} was not finished; recover it first`;
  }
  const unfinished = [...last.values()].find(
    (entry) => taskOf(entry) !== TASK_ID && entry.event === "started",
  );
  if (unfinished) return `${taskOf(unfinished)} started at ${unfinished.ts} and has not finished`;
  const recent = lines.find((entry) => {
    if (taskOf(entry) === TASK_ID) return false;
    const age = now - Date.parse(entry.ts);
    return Number.isNaN(age) || age < QUIET_MS;
  });
  return recent ? `${taskOf(recent)} wrote a line at ${recent.ts}` : undefined;
}

/**
 * Runs `work` holding `<ledger>.lock`, created exclusively, as every sandbox lane does. When
 * `keep(result)` holds (a run that needs recovery), the lock stays and says so, so no lane
 * starts on a sandbox this run may have left changed; `recover` takes it over. `ours` lets
 * `recover` take a lock this task left.
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
    if (!holder.startsWith(`${TASK_ID} `)) {
      await handle.close();
      throw new Error(`${lock} is not this task's (${holder.trim()})`);
    }
    await handle.truncate(0);
  }
  let kept = false;
  try {
    await handle.write(`${TASK_ID} pid ${process.pid} since ${new Date().toISOString()}\n`, 0);
    await handle.close();
    const result = await work();
    kept = keep(result);
    if (kept) {
      await writeFile(
        lock,
        `${TASK_ID} needs-recovery run ${result.run} since ${new Date().toISOString()}\n`,
      );
    }
    return result;
  } finally {
    if (!kept) await rm(lock, { force: true });
  }
}

/**
 * Counts requests against the limits and refuses any URL outside the reviewed ones: the
 * Hosting, Identity Toolkit (config read) and Service Usage APIs of the sandbox, the upload
 * URL populateFiles names, and the run's channel host.
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
            "serviceusage.googleapis.com",
          ].includes(host)
        ? "api"
        : undefined;
    if (!kind) throw new Error(`host ${host} is not reviewed`);
    if (used[kind] >= limits[kind])
      throw new Error(`${kind} request limit ${limits[kind]} reached`);
    used[kind] += 1;
    return fetchImpl(url, init);
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
function clients(api, token) {
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
async function removeChannel({ get, send, api, sleep, run, version, issuerHost }) {
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
  if (version) {
    try {
      cleanup.versionStatus = (await get(`${HOSTING}/${version}`, "version")).status;
    } catch (error) {
      cleanup.versionStatus = `error ${error.message}`;
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

export async function hostingSmoke({ api, run, jwks, forbidden, appendLedger, sleep, stop, meta }) {
  checkRun(run);
  const { auth, get, send } = clients(api, meta.token);
  const channelId = `fed-${run}`;
  const configUrl = CONFIG_URL;
  const result = { run, channelId, channelCreated: false };

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

    const version = await send(
      "POST",
      `${HOSTING}/projects/-/sites/${SITE}/versions`,
      {},
      "version create",
    );
    result.version = version.name;
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
  } catch (error) {
    failure = error;
  }

  const cleanup = result.channelCreated
    ? await removeChannel({
        get,
        send,
        api,
        sleep,
        run,
        version: result.version,
        issuerHost: result.issuerHost,
      })
    : {};
  cleanup.authorizedDomainsUnchanged = await domainsUnchanged(get, before);
  const clean = cleanOf(cleanup, result.channelCreated);
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
export async function hostingRecover({ api, run, before, appendLedger, sleep, meta }) {
  checkRun(run);
  const { get, send } = clients(api, meta.token);
  let issuerHost;
  try {
    const channel = await get(channelPathOf(run), "channel");
    const host = URL.canParse(channel.url) ? new URL(channel.url).host : "";
    if (issuerChannelHost(SANDBOX_PROJECT, run).test(host)) issuerHost = host;
  } catch (error) {
    if (error.status !== 404) throw error;
  }
  const cleanup = await removeChannel({ get, send, api, sleep, run, issuerHost });
  cleanup.authorizedDomainsUnchanged = await domainsUnchanged(get, before);
  const entry = {
    action: "hosting-recover",
    outcome: cleanOf(cleanup, true) ? "recovered" : "needs-recovery",
    run,
    channelId: `fed-${run}`,
    issuerHost,
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

async function smokeFromEnvironment() {
  const ledger = process.env.FIREEMU_SANDBOX_LEDGER;
  const owner = process.env.FIREEMU_OWNER_DECISIONS;
  const webPath = process.env.FIREEMU_AUTH_SANDBOX_WEB_CONFIG;
  if (!ledger || !owner || !webPath) {
    throw new Error(
      "FIREEMU_SANDBOX_LEDGER, FIREEMU_OWNER_DECISIONS and FIREEMU_AUTH_SANDBOX_WEB_CONFIG are required",
    );
  }
  for (const name of ["FIREBASE_TOKEN", "GOOGLE_APPLICATION_CREDENTIALS"]) {
    if (process.env[name]) throw new Error(`${name} must be unset (the owner's user ADC is used)`);
  }
  const digest = await scriptDigest();
  if (!approved(await readFile(owner, "utf8"), digest)) {
    throw new Error(`no owner-ledger line approves hosting-smoke ${digest.slice(0, 12)}`);
  }
  if ((await sh("git", ["status", "--porcelain", "--", "src/auth-federation"])) !== "") {
    throw new Error("src/auth-federation has uncommitted changes");
  }
  const web = JSON.parse(await readFile(webPath, "utf8"));
  const forbidden = [web.apiKey, web.projectNumber].filter(Boolean);
  const run = randomBytes(3).toString("hex");
  // Only the public half leaves the process; the smoke signs nothing.
  const { jwk } = generateSigningKey({ kid: `fireemu-smoke-${run}` });
  return withSandboxLock(
    ledger,
    async () => {
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
          appendLedger: (line) =>
            appendFile(
              ledger,
              `${JSON.stringify({ ts: new Date().toISOString(), project: SANDBOX_PROJECT, taskId: TASK_ID, ...line, requests: { ...used } })}\n`,
            ),
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

/** The run this task left unfinished and the authorizedDomains its started line recorded. */
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
  return { run: checkRun(last.run), before: started.authorizedDomainsBefore };
}

async function recoverFromEnvironment() {
  const ledger = process.env.FIREEMU_SANDBOX_LEDGER;
  if (!ledger) throw new Error("FIREEMU_SANDBOX_LEDGER is required");
  for (const name of ["FIREBASE_TOKEN", "GOOGLE_APPLICATION_CREDENTIALS"]) {
    if (process.env[name]) throw new Error(`${name} must be unset (the owner's user ADC is used)`);
  }
  const target = runToRecover(await readFile(ledger, "utf8"));
  if (!target) throw new Error("the ledger shows no run of this task to recover");
  const ours = existsSync(`${ledger}.lock`);
  return withSandboxLock(
    ledger,
    async () => {
      const token = await sh("gcloud", ["auth", "application-default", "print-access-token"]);
      const { call, used } = limitedFetch(fetch, { run: target.run });
      const entry = await hostingRecover({
        api: call,
        run: target.run,
        before: target.before,
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
