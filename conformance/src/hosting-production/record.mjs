// The production recorder of the Hosting observation (HOSTING parent): deploys the ten corpus
// versions, one at a time, each to its own disposable preview channel of the default site of the
// Identity Platform sandbox through the Hosting REST API, sends the version's requests to the
// channel host, deletes the channel and the version, and reads the deletions back at the end.
//
//   node record.mjs check               offline: digests, counts and the budget
//   node record.mjs record-production   the coordinator launches this, after the E and V ledger lines
//   node record.mjs recover             deletes what a run that needs recovery left behind
//
// It never uses the firebase CLI (the CLI's channel commands rewrite authorizedDomains), never
// releases to the live channel, never follows a redirect and never retries a request. The project
// lock is taken by the coordinator's launch script; the ledger rows follow the other recorders.
import { execFile } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { appendFile, mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { gzipSync } from "node:zlib";

import { edgeRequest } from "./client.mjs";
import { servingConfig } from "./convert.mjs";
import { buildCorpus, corpusManifest } from "./corpus.mjs";
import { requestHeaders } from "./local.mjs";
import { CORPUS_SHA256 } from "./pins.mjs";
import { assertNoSecrets, maskSecrets, shapeRow } from "./rows.mjs";

export const TASK_ID = "HOSTING-PRODUCTION";
export const PROJECT = "fireemu-oracle-idp";
export const SITE = PROJECT;
/** The budget of one attempt. `cleanup` has its own reserve so deploys never starve it. */
export const CAPS = { token: 3, control: 90, cleanup: 45, upload: 20, edge: 330 };

const HOSTING = "https://firebasehosting.googleapis.com/v1beta1";
const UPLOAD_HOST = "upload-firebasehosting.googleapis.com";
const ALLOWED_HOSTS = new Set([
  "firebasehosting.googleapis.com",
  UPLOAD_HOST,
  "serviceusage.googleapis.com",
  "identitytoolkit.googleapis.com",
  "oauth2.googleapis.com",
]);
const MAX_ATTEMPTS = 3;
/** Ruling 13: the parent's reservation over all envelopes. */
const MAX_CUMULATIVE_USD = 6;
const RESERVED_USD_PER_ATTEMPT = 1;
const ESTIMATED_USD = 0.05;
const WAIT_MS = 30 * 60_000;
export const READINESS_ATTEMPTS = 12;
export const READINESS_GAP_MS = 10_000;
const REQUEST_GAP_MS = 150;
const MAX_RESPONSE_BYTES = 1 << 20;
const RUN_TAG = /^[0-9a-f]{6}$/;
const execFileAsync = promisify(execFile);

/** Thrown when a request would exceed its budget kind; the request is not sent. */
export class CapReached extends Error {
  constructor(kind) {
    super(`the ${kind} budget is exhausted`);
    this.kind = kind;
  }
}

export function createBudget(caps = CAPS) {
  const used = Object.fromEntries(Object.keys(caps).map((kind) => [kind, 0]));
  return {
    take(kind) {
      if (!(kind in caps)) throw new Error(`unknown budget kind ${kind}`);
      if (used[kind] >= caps[kind]) throw new CapReached(kind);
      used[kind] += 1;
    },
    left: (kind) => caps[kind] - used[kind],
    snapshot: () => ({ ...used }),
  };
}

// ---- admission ------------------------------------------------------------------------------------

const CLOSING_EVENTS = new Set(["cleanup-verified", "observation-complete-cleanup-verified"]);
const CLOSING_OUTCOMES = new Set(["recorded", "cleanup-verified", "recovered-no-observation"]);

/** Whether a ledger row closes the run before it (explicit forms only; anything else is open). */
function closes(line) {
  if (CLOSING_EVENTS.has(line.event)) return true;
  return (
    (line.event === undefined || line.event === "finished") && CLOSING_OUTCOMES.has(line.outcome)
  );
}

const rowTime = (line) => Date.parse(line.ts ?? line.recordedAt ?? "");

/**
 * Plain admission on the sandbox ledger text: the last row for the project closes its run and is at
 * least 30 minutes old (unless the coordinator, as the only sender on the project with the previous
 * run closed, sets FIREEMU_HOSTING_SOLE_SENDER=1: owner ledger 1299); every own `started` row has a
 * later own row; at most MAX_ATTEMPTS attempts per envelope (FIREEMU_HOSTING_ENVELOPE, required) and
 * US$6.00 reserved over all envelopes. Returns the attempt number of the envelope and the reserved sum.
 */
export function admit({ ledgerText, now, env }) {
  const envelope = env.FIREEMU_HOSTING_ENVELOPE;
  if (!/^HOSTING-PRODUCTION-[A-Z0-9-]{3,60}$/.test(envelope ?? "")) {
    throw new Error("FIREEMU_HOSTING_ENVELOPE must name the envelope (HOSTING-PRODUCTION-...)");
  }
  const lines = ledgerText
    .split("\n")
    .filter((text) => text.trim())
    .map((text) => JSON.parse(text))
    .filter((line) => line.project === PROJECT);
  if (!lines.length) throw new Error(`no ledger row for ${PROJECT}`);
  const last = lines.at(-1);
  if (!closes(last)) {
    throw new Error(
      `the last row for ${PROJECT} does not close its run (${last.event ?? "-"} / ${last.outcome ?? "-"}); the coordinator closes it first`,
    );
  }
  const at = rowTime(last);
  if (!Number.isFinite(at)) throw new Error("the last row for the project has no time");
  if (now - at < WAIT_MS && env.FIREEMU_HOSTING_SOLE_SENDER !== "1") {
    throw new Error("30 minutes have not passed since the last row for the project");
  }
  const own = lines.filter((line) => line.taskId === TASK_ID);
  own.forEach((line, index) => {
    if (line.event === "started" && !own[index + 1]) {
      throw new Error("an own started row has no terminal row: recover that attempt first");
    }
  });
  // The attempts are counted per envelope: the started rows of this envelope (the caller names it;
  // a row of an earlier envelope has another id or none). The money is counted over all own rows.
  const started = own.filter((line) => line.event === "started");
  const attempt = started.filter((line) => line.envelopeId === envelope).length + 1;
  if (attempt > MAX_ATTEMPTS) {
    throw new Error(
      `attempt ${attempt} exceeds ${MAX_ATTEMPTS} attempts of the envelope ${envelope}`,
    );
  }
  const cumulativeReservedUsd = (started.length + 1) * RESERVED_USD_PER_ATTEMPT;
  if (cumulativeReservedUsd > MAX_CUMULATIVE_USD) {
    throw new Error(
      `the cumulative reservation ${cumulativeReservedUsd} passes US$${MAX_CUMULATIVE_USD.toFixed(2)}`,
    );
  }
  return { attempt, cumulativeReservedUsd };
}

// ---- secrets -----------------------------------------------------------------------------------------

/** The strings of the private web app config that must never reach a row or a file. */
/** The sandbox's project number from the private web config (the caller keeps it secret). */
export const projectNumberOf = (config) =>
  String(config?.projectNumber ?? config?.messagingSenderId ?? "");

export function secretsFromWebConfig(config) {
  if (config?.projectId !== PROJECT) throw new Error("the web config is not the sandbox's");
  const number = config.projectNumber ?? config.messagingSenderId;
  if (
    !/^\d+$/.test(number ?? "") ||
    (config.messagingSenderId && config.messagingSenderId !== number)
  ) {
    throw new Error("the web config has no consistent project number");
  }
  if (!/^[A-Za-z0-9_-]{20,}$/.test(config.apiKey ?? "")) {
    throw new Error("the web config has no API key");
  }
  const secrets = [config.apiKey, number];
  if (config.appId) secrets.push(config.appId, String(config.appId).split(":")[3]);
  if (config.measurementId) secrets.push(config.measurementId);
  return [...new Set(secrets.filter(Boolean))];
}

// ---- the run ---------------------------------------------------------------------------------------------

const channelHost = (run) =>
  new RegExp(`^${PROJECT}--hst-${run}-v\\d\\d-[a-z0-9]{1,16}\\.web\\.app$`);
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const pathOf = (url) => {
  const u = new URL(url);
  return `${u.pathname}${u.search ? `?${[...u.searchParams.keys()].join("&")}` : ""}`;
};

/**
 * Classifies an API answer (lane-guide section 5): a 2xx with readable JSON is `ok`, a 4xx is a
 * definite `refused`, anything else (no answer, 1xx, 3xx, 5xx, an unreadable body) is `unknown`.
 */
export function classify(reply) {
  const status = reply?.status ?? 0;
  if (status >= 200 && status < 300) {
    try {
      return { kind: "ok", status, value: reply.text ? JSON.parse(reply.text) : {} };
    } catch {
      return { kind: "unknown", status, reason: "unreadable-body" };
    }
  }
  if (status >= 400 && status < 500) return { kind: "refused", status };
  return { kind: "unknown", status, reason: status === 0 ? "no-answer" : `http-${status}` };
}

/**
 * @param {object} env FIREEMU_HOSTING_SOLE_SENDER
 * @param {object} deps every effect: now, assertCleanTree, gitSha, readSources, readLedger,
 *   appendLedger, ownerAdc, webConfig, makeRunDir, writeRunFile, appendRunFile, runTag, token,
 *   http, edge, sleep, installSignals, caps (tests only), log, warn.
 */
export async function recordHosting(env, deps) {
  await deps.assertCleanTree();
  const { corpus } = await deps.readSources();
  const { attempt, cumulativeReservedUsd } = admit({
    ledgerText: await deps.readLedger(),
    now: deps.now(),
    env,
  });
  const adc = await deps.ownerAdc();
  const webConfig = await deps.webConfig();
  const secrets = secretsFromWebConfig(webConfig);
  const number = projectNumberOf(webConfig);
  const run = deps.runTag();
  if (!RUN_TAG.test(run)) throw new Error(`run tag ${run} is not six hex digits`);
  const gitSha = await deps.gitSha();
  const startedAt = deps.now();
  const runDir = await deps.makeRunDir(
    `hosting-production-${new Date(startedAt).toISOString().replaceAll(":", "")}`,
  );
  const budget = createBudget(deps.caps ?? CAPS);
  const api = makeApi({ deps, budget, adc, runDir, secrets });

  // Read-only prechecks. Nothing is written to production or to the ledger before they pass.
  const before = await precheck(api);

  const base = {
    project: PROJECT,
    database: null,
    taskId: TASK_ID,
    gitSha,
    corpusDigest: CORPUS_SHA256,
    runDir,
    attempt,
    run,
    reservedUsd: RESERVED_USD_PER_ATTEMPT,
    cumulativeReservedUsd,
    envelopeId: env.FIREEMU_HOSTING_ENVELOPE,
  };
  await deps.appendLedger(
    `${JSON.stringify({ ts: new Date(startedAt).toISOString(), ...base, event: "started", authorizedDomainsBefore: before })}\n`,
  );
  const state = {
    stop: false,
    halt: undefined,
    needsRecovery: [],
    openCreates: [],
    residual: [],
    review: false,
  };
  deps.installSignals(() => {
    state.stop = true;
  });

  const rows = [];
  const deployed = {};
  for (const version of corpus.versions) {
    if (state.stop || state.halt) {
      rows.push(...unknownRows(version, state.stop ? "stopped" : "not-run", secrets));
      continue;
    }
    const record = (deployed[version.id] = { channelId: `hst-${run}-${version.id}` });
    const sink = [];
    try {
      await deployAndServe({ version, record, run, api, deps, secrets, number, state, sink });
    } catch (error) {
      // The message may carry whatever an effect threw; it reaches the ledger, so it is masked.
      const message = maskSecrets(String(error.message), secrets);
      state.halt ??= error instanceof CapReached ? `cap: ${message}` : `exception: ${message}`;
      record.failure ??= state.halt;
    } finally {
      record.cleanup = await removeVersion({ record, api, state });
    }
    // Requests that did not get an answer are unknown rows with the reason that stopped them.
    const reason = state.stop ? "stopped" : (record.failure ?? "failed");
    rows.push(...sink, ...unknownRows(version, reason, secrets, sink.length));
  }
  const readback = await finalReadback({ run, api, state, before });

  const unknownCount = rows.filter((row) => row.outcome !== "answered").length;
  const closureReady =
    state.needsRecovery.length === 0 &&
    state.residual.length === 0 &&
    readback.clean &&
    readback.domainsUnchanged === true;
  const failed = Boolean(state.halt) || Object.values(deployed).some((d) => d.failure);
  let outcome;
  if (!closureReady) outcome = "needs-recovery";
  else if (failed) outcome = "failed-cleaned";
  else outcome = unknownCount === 0 && !state.review ? "recorded" : "observed-unknown";

  const requests = budget.snapshot();
  const result = {
    outcome,
    closureReady,
    run,
    halt: state.halt,
    unknownRows: unknownCount,
    needsReview: state.review,
    needsRecovery: state.needsRecovery,
    openUnknownCreates: state.openCreates,
    residual: state.residual,
    readback,
    requests,
    estimatedUsd: ESTIMATED_USD,
  };
  let writeError;
  try {
    const write = async (name, value) => {
      const text = typeof value === "string" ? value : `${JSON.stringify(value, null, 2)}\n`;
      if (secrets.some((secret) => secret.length >= 6 && text.includes(secret))) {
        throw new Error(`${name} would retain a private value`);
      }
      await deps.writeRunFile(runDir, name, text);
    };
    await write("rows.json", { schema: 1, run, corpusSha256: CORPUS_SHA256, rows });
    // A version name production returns under `projects/-` carries the project number: names are
    // masked before they reach a file (the guard above is a second layer).
    const masked = (value) => JSON.parse(maskSecrets(JSON.stringify(value), secrets));
    await write("deploy.json", masked({ schema: 1, run, versions: deployed }));
    await write("result.json", masked(result));
  } catch (error) {
    writeError = error.message;
  }
  const ok = closureReady && !writeError;
  await deps.appendLedger(
    `${JSON.stringify({
      ts: new Date(deps.now()).toISOString(),
      ...base,
      event: ok ? "finished" : "needs-recovery",
      outcome: writeError ? "needs-recovery" : outcome,
      closureReady: ok,
      requests,
      estimatedUsd: ESTIMATED_USD,
      unknownRows: unknownCount,
      residual: state.residual.length + state.needsRecovery.length,
      // What a later recovery carries forward: creates no own 2xx read has shown, and the deletes
      // that did not answer 2xx. Both stay open until the coordinator's own A2 read-back.
      openUnknownCreates: state.openCreates,
      residualEntries: state.residual,
      lockKept: !ok || outcome === "observed-unknown" || state.review,
      needsReview: state.review || !ok,
      ...(state.halt || writeError
        ? { reason: [state.halt, writeError].filter(Boolean).join("; ") }
        : {}),
    })}\n`,
  );
  return {
    outcome: writeError ? "needs-recovery" : outcome,
    closureReady: ok,
    runDir,
    exitCode: ok && outcome === "recorded" ? 0 : 1,
  };
}

function unknownRows(version, reason, secrets, from = 0) {
  return version.requests
    .slice(from)
    .map((spec) =>
      shapeRow(spec, { outcome: "unknown", reason }, { origin: "", secrets, version: version.id }),
    );
}

/** The counted, allow-listed, never-retrying REST client over `deps.http`. */
export function makeApi({ deps, budget, adc, runDir, secrets = [] }) {
  let token;
  const journal = (kind, method, url, status) =>
    deps.appendRunFile(
      runDir,
      "journal.jsonl",
      `${JSON.stringify({ t: new Date(deps.now()).toISOString(), kind, method, path: maskSecrets(pathOf(url), secrets), status })}\n`,
    );
  async function call(kind, method, url, body, { binary = false } = {}) {
    const { protocol, hostname } = new URL(url);
    if (protocol !== "https:" || !ALLOWED_HOSTS.has(hostname)) {
      throw new Error(`host ${hostname} is not reviewed`);
    }
    if (!token || deps.now() >= token.expiresAt) {
      budget.take("token");
      token = await deps.token(adc);
    }
    budget.take(kind);
    let reply;
    try {
      reply = await deps.http({
        method,
        url,
        headers: {
          authorization: `Bearer ${token.value}`,
          "x-goog-user-project": PROJECT,
          "content-type": binary ? "application/octet-stream" : "application/json",
        },
        body: body === undefined ? undefined : binary ? body : JSON.stringify(body),
      });
    } catch {
      reply = { status: 0, text: "" };
    }
    const answer = classify(reply);
    await journal(kind, method, url, answer.status);
    return answer;
  }
  return { call, budget };
}

async function precheck(api) {
  const read = async (url, what) => {
    const answer = await api.call("control", "GET", url);
    if (answer.kind !== "ok") throw new Error(`precheck ${what}: ${answer.status}`);
    return answer.value;
  };
  const usage = await read(
    `https://serviceusage.googleapis.com/v1/projects/${PROJECT}/services/firebasehosting.googleapis.com`,
    "service",
  );
  if (usage.state !== "ENABLED") throw new Error(`firebasehosting is ${usage.state}; stop`);
  await read(`${HOSTING}/projects/${PROJECT}/sites/${SITE}`, "site");
  const channels = await read(
    `${HOSTING}/projects/${PROJECT}/sites/${SITE}/channels?pageSize=100`,
    "channels",
  );
  // A second page would hide channels the precheck cannot read: stop rather than guess.
  if (channels.nextPageToken) throw new Error("the channel list is paged; read it by hand first");
  if ((channels.channels ?? []).some((c) => String(c.name).split("/").at(-1).startsWith("hst-"))) {
    throw new Error("channels of an earlier run remain");
  }
  // The final read-back reads at most 3 pages of versions, and each attempt adds 10 (deleted ones
  // stay listed). Stop before any write when the list already runs past 2 pages.
  let token = "";
  for (let page = 0; page < 2; page += 1) {
    const query = `pageSize=100${token ? `&pageToken=${encodeURIComponent(token)}` : ""}`;
    const versions = await read(`${HOSTING}/sites/${SITE}/versions?${query}`, "versions");
    token = versions.nextPageToken ?? "";
    if (!token) break;
    if (page === 1)
      throw new Error("the site's version list runs past 2 pages; clear it by hand first");
  }
  const config = await read(
    `https://identitytoolkit.googleapis.com/admin/v2/projects/${PROJECT}/config`,
    "config",
  );
  return config.authorizedDomains ?? [];
}

/** `sites/<site>/versions/<id>` of a version name that may carry a project in front. */
const shortVersionName = (name) => String(name ?? "").replace(/^projects\/[^/]+\//, "");

/** What a readiness probe that was not the expected answer showed (kept in the deploy record). */
function probeShape(answer) {
  const header = (name) => answer.headers?.find(([key]) => String(key).toLowerCase() === name)?.[1];
  const body = answer.body ?? Buffer.alloc(0);
  return {
    status: answer.status,
    contentType: header("content-type"),
    xCache: header("x-cache"),
    xServedBy: header("x-served-by"),
    bodyBytes: body.length,
    bodyHead: body.subarray(0, 200).toString("utf8"),
  };
}

/** Deploys one version and serves its requests; returns the rows. Failures are recorded, not thrown. */
async function deployAndServe({ version, record, run, api, deps, secrets, number, state, sink }) {
  const fail = (reason, { halt = true } = {}) => {
    record.failure = reason;
    if (halt) state.halt ??= `${version.id}: ${reason}`;
  };
  // The channel path names the project, as every recorded channel create did (the `-` wildcard is
  // recorded for version creates and releases only).
  const channelsUrl = `${HOSTING}/projects/${PROJECT}/sites/${SITE}/channels`;
  // a. the preview channel
  let created = await api.call("control", "POST", `${channelsUrl}?channelId=${record.channelId}`, {
    ttl: "86400s",
    labels: { "fireemu-run": run },
  });
  if (created.kind === "unknown") {
    record.channelCreate = "unknown";
    const probe = await api.call(
      "cleanup",
      "GET",
      `${HOSTING}/projects/${PROJECT}/sites/${SITE}/channels/${record.channelId}`,
    );
    if (probe.kind !== "ok") {
      state.needsRecovery.push(`${record.channelId}: channel create unknown`);
      state.openCreates.push(`channel:${record.channelId}`);
      fail("channel create unknown");
      return;
    }
    created = probe;
  }
  if (created.kind === "refused") {
    fail(`channel create refused (${created.status})`);
    return;
  }
  if (created.kind !== "ok") {
    fail("channel create failed");
    return;
  }
  record.channelCreated = true;
  let host;
  try {
    const url = new URL(created.value.url);
    host = url.protocol === "https:" && channelHost(run).test(url.host) ? url.host : undefined;
  } catch {
    host = undefined;
  }
  if (!host) {
    fail("channel host is not the run's preview channel");
    return;
  }
  record.host = host;

  // b. the version, labelled with the run so a lost answer can be found again
  const made = await api.call("control", "POST", `${HOSTING}/projects/-/sites/${SITE}/versions`, {
    labels: { "fireemu-run": run, "fireemu-version": version.id },
  });
  if (made.kind === "unknown") {
    state.needsRecovery.push(`${version.id}: version create unknown`);
    state.openCreates.push(`version:${version.id}`);
    fail("version create unknown");
    return;
  }
  if (made.kind !== "ok") {
    fail(`version create refused (${made.status})`);
    return;
  }
  const name = String(made.value.name ?? "");
  // The id is cleaned up by the run whatever the name looks like: a create that answered 2xx is a
  // confirmed create, and the delete goes to this site's own path with that id.
  const id = name.split("/").at(-1);
  if (/^[A-Za-z0-9]{8,64}$/.test(id)) record.versionId = id;
  // Production names the version `sites/<site>/versions/<id>` or, under the `projects/-` wildcard,
  // with the project in front (its id or its number). Only this site and this project are accepted.
  const accepted = [
    `sites/${SITE}/versions/${id}`,
    `projects/${PROJECT}/sites/${SITE}/versions/${id}`,
    ...(/^\d+$/.test(number) ? [`projects/${number}/sites/${SITE}/versions/${id}`] : []),
  ];
  if (!record.versionId || !accepted.includes(name)) {
    fail("version name is not the site's");
    return;
  }
  record.version = name;

  // c. the file manifest and the uploads the server asks for
  const gz = new Map();
  const manifest = {};
  for (const [path, bytes] of Object.entries(version.files)) {
    const zipped = gzipSync(bytes);
    const hash = sha256(zipped);
    gz.set(hash, zipped);
    manifest[`/${path}`] = hash;
  }
  const populated = await api.call("control", "POST", `${HOSTING}/${name}:populateFiles`, {
    files: manifest,
  });
  if (populated.kind !== "ok") {
    fail("populateFiles failed");
    return;
  }
  const uploadUrl = String(populated.value.uploadUrl ?? "");
  let uploadHost;
  try {
    uploadHost = new URL(uploadUrl);
  } catch {
    uploadHost = undefined;
  }
  if (uploadHost?.protocol !== "https:" || uploadHost.host !== UPLOAD_HOST) {
    fail("upload URL is not the reviewed host");
    return;
  }
  record.uploads = 0;
  for (const hash of populated.value.uploadRequiredHashes ?? []) {
    if (!gz.has(hash)) {
      fail("the server asked for a hash the version does not hold");
      return;
    }
    const sent = await api.call("upload", "POST", `${uploadUrl}/${hash}`, gz.get(hash), {
      binary: true,
    });
    if (sent.kind !== "ok") {
      fail(`upload failed (${sent.status})`);
      return;
    }
    record.uploads += 1;
  }

  // d. finalize with the serving config; an optional key the API rejects is dropped once
  let config = servingConfig(version.hosting);
  let finalized = await api.call(
    "control",
    "PATCH",
    `${HOSTING}/${name}?updateMask=status,config`,
    {
      status: "FINALIZED",
      config,
    },
  );
  if (finalized.kind === "refused" && finalized.status === 400) {
    const dropped = version.optionalConfig.filter((key) => key in config);
    if (dropped.length) {
      config = Object.fromEntries(Object.entries(config).filter(([key]) => !dropped.includes(key)));
      record.droppedConfig = dropped;
      finalized = await api.call(
        "control",
        "PATCH",
        `${HOSTING}/${name}?updateMask=status,config`,
        {
          status: "FINALIZED",
          config,
        },
      );
    }
  }
  if (finalized.kind !== "ok") {
    fail(`finalize failed (${finalized.status})`);
    return;
  }

  // e. what the API says about the version (fileCount is a string and counts reserved files)
  const read = await api.call("control", "GET", `${HOSTING}/${name}`);
  if (read.kind !== "ok") {
    fail("version read failed");
    return;
  }
  record.status = read.value.status;
  record.fileCount = read.value.fileCount;
  record.fileCountType = typeof read.value.fileCount;
  record.versionBytes = read.value.versionBytes;
  if (read.value.status !== "FINALIZED") {
    fail(`version is ${read.value.status}`);
    return;
  }
  if (version.id === "v01") {
    const listed = await api.call("control", "GET", `${HOSTING}/${name}/files?pageSize=100`);
    if (listed.kind === "ok") {
      const paths = (listed.value.files ?? []).map((f) => String(f.path));
      record.filesListed = paths.length;
      record.reservedFiles = paths.filter((p) => p.startsWith("/__/"));
      record.filesTruncated = Boolean(listed.value.nextPageToken);
    } else record.filesListError = listed.status;
  }

  // f. release to the run's own preview channel
  const released = await api.call(
    "control",
    "POST",
    `${HOSTING}/projects/-/sites/${SITE}/channels/${record.channelId}/releases?versionName=${encodeURIComponent(name)}`,
    {},
  );
  if (released.kind !== "ok") {
    fail(`release failed (${released.status})`);
    return;
  }

  // g. serving
  const origin = `https://${host}`;
  const edge = async (spec, headers) => {
    api.budget.take("edge");
    return deps.edge({
      host,
      secure: true,
      method: spec.method,
      target: spec.target,
      headers: { host, ...headers },
      body: spec.body,
    });
  };
  record.readiness = [];
  let ready = false;
  let last;
  for (let attempt = 0; attempt < READINESS_ATTEMPTS && !ready; attempt += 1) {
    if (state.stop) break;
    if (attempt > 0) await deps.sleep(READINESS_GAP_MS);
    const answer = await edge({ method: "GET", target: version.readiness.path }, {});
    record.readiness.push(answer.outcome === "answered" ? answer.status : answer.reason);
    ready = answer.outcome === "answered" && version.readiness.accept.includes(answer.status);
    last = answer;
  }
  if (!ready) {
    // Run bba4c0 gave up on four releases after 20 s with no body kept. Keep what the last probe
    // showed and whether the API still holds this version as the channel's release, so that a
    // release that never goes live differs from one that is only slow.
    if (last?.outcome === "answered") record.lastProbe = probeShape(last);
    fail(state.stop ? "stopped" : "not-ready", { halt: false });
    if (!state.stop) {
      const channel = await api.call("control", "GET", `${channelsUrl}/${record.channelId}`);
      record.releaseOnChannel =
        channel.kind !== "ok"
          ? "unread"
          : shortVersionName(channel.value?.release?.version?.name) === shortVersionName(name);
    }
    return;
  }
  const answers = new Map();
  for (const spec of version.requests) {
    if (state.stop) return;
    let answer;
    const headers = requestHeaders(spec, answers);
    if (headers === undefined) answer = { outcome: "unknown", reason: "dependency" };
    else {
      answer = await edge(spec, headers);
      await deps.sleep(REQUEST_GAP_MS);
    }
    answers.set(spec.id, answer);
    if (answer.outcome === "answered" && (answer.status === 429 || answer.status >= 500)) {
      answer = { outcome: "unknown", reason: `http-${answer.status}` };
    }
    const context = { origin, secrets, version: version.id };
    let row = shapeRow(spec, answer, context);
    try {
      assertNoSecrets(row, secrets);
    } catch {
      state.review = true;
      row = shapeRow(spec, { outcome: "unknown", reason: "private-value-withheld" }, context);
    }
    sink.push(row);
  }
}

/** Deletes what the version's record says this run created; an unknown delete is never re-sent. */
async function removeVersion({ record, api, state }) {
  const result = {};
  const attempt = async (what, url) => {
    try {
      const answer = await api.call("cleanup", "DELETE", url);
      // Only the run's own 2xx settles a delete. A 404 for a resource this run confirmed creating is not
      // settled in the run (read-after-write lag can hide a live resource): it is left for the A2 read.
      if (answer.kind === "ok") return "deleted";
      state.residual.push(`${record.channelId}: ${what} delete ${answer.kind} (${answer.status})`);
      return answer.kind;
    } catch (error) {
      state.residual.push(`${record.channelId}: ${what} delete not sent (${error.message})`);
      return "not-sent";
    }
  };
  if (record.channelCreated) {
    result.channel = await attempt(
      "channel",
      `${HOSTING}/projects/${PROJECT}/sites/${SITE}/channels/${record.channelId}`,
    );
  }
  if (record.versionId) {
    result.version = await attempt(
      "version",
      `${HOSTING}/sites/${SITE}/versions/${record.versionId}`,
    );
  }
  return result;
}

async function listVersions(api, run) {
  const found = [];
  const details = [];
  let token = "";
  for (let page = 0; page < 3; page += 1) {
    const query = `pageSize=100${token ? `&pageToken=${encodeURIComponent(token)}` : ""}`;
    const listed = await api.call("cleanup", "GET", `${HOSTING}/sites/${SITE}/versions?${query}`);
    if (listed.kind !== "ok") return { error: listed.status, found, details };
    for (const version of listed.value.versions ?? []) {
      if (version.labels?.["fireemu-run"] === run && version.status !== "DELETED") {
        found.push(String(version.name));
        details.push({
          name: String(version.name),
          versionId: version.labels?.["fireemu-version"],
        });
      }
    }
    token = listed.value.nextPageToken ?? "";
    if (!token) return { found, details };
  }
  return { found, details, truncated: true };
}

async function finalReadback({ run, api, state, before }) {
  const out = { clean: true };
  try {
    const channels = await api.call(
      "cleanup",
      "GET",
      `${HOSTING}/projects/${PROJECT}/sites/${SITE}/channels?pageSize=100`,
    );
    if (channels.kind !== "ok") {
      out.clean = false;
      out.channelsError = channels.status;
    } else {
      out.channelsLeft = (channels.value.channels ?? [])
        .map((c) => String(c.name).split("/").at(-1))
        .filter((id) => id.startsWith(`hst-${run}-`));
      if (out.channelsLeft.length) out.clean = false;
    }
    const versions = await listVersions(api, run);
    out.versionsLeft = versions.found;
    if (versions.error || versions.truncated || versions.found.length) out.clean = false;
    if (versions.error) out.versionsError = versions.error;
    if (versions.truncated) out.versionsTruncated = true;
    const config = await api.call(
      "cleanup",
      "GET",
      `https://identitytoolkit.googleapis.com/admin/v2/projects/${PROJECT}/config`,
    );
    out.domainsUnchanged =
      config.kind === "ok"
        ? JSON.stringify(config.value.authorizedDomains ?? []) === JSON.stringify(before)
        : `error ${config.status}`;
  } catch (error) {
    out.clean = false;
    out.error = error.message;
    state.needsRecovery.push(`read-back: ${error.message}`);
  }
  return out;
}

// ---- recovery -----------------------------------------------------------------------------------------------

/**
 * The recovery of a run that ended `needs-recovery` (or never wrote a terminal row): it deletes what
 * is listed under the run's prefix and label, records each own DELETE answer, reads everything back,
 * and writes ONE row that never closes the run (`recovery-read`; `admit` does not accept it). Only
 * the coordinator closes the run, after its own A2 read-back at least 10 minutes later. Rules
 * (checklist section 3): an unknown create settles only on an own 2xx read that shows the resource,
 * then deleted with a 2xx and read back absent; absence never settles it. A DELETE that did not
 * answer 2xx stays residual. Run it only under its own recovery packet, never under the recording
 * envelope.
 */
export async function recoverHosting(env, deps) {
  const lines = (await deps.readLedger())
    .split("\n")
    .filter((text) => text.trim())
    .map((text) => JSON.parse(text))
    .filter((line) => line.project === PROJECT && line.taskId === TASK_ID);
  const last = lines.at(-1);
  if (!last || !["started", "needs-recovery", "recovery-read"].includes(last.event)) {
    throw new Error("the ledger shows no run of this task to recover");
  }
  const run = last.run;
  if (!RUN_TAG.test(run ?? "")) throw new Error("the run to recover has no tag");
  const started = lines.findLast((line) => line.event === "started" && line.run === run);
  const before = started?.authorizedDomainsBefore;
  if (!Array.isArray(before))
    throw new Error(`run ${run} has no started row with authorizedDomainsBefore`);
  // What the run (or the recovery before this one) left open. A run with no terminal row may have
  // an unknown create nobody wrote down: it stays open for the coordinator.
  const carried = last.openUnknownCreates ?? ["run-ended-without-a-terminal-row"];
  const carriedResidual = last.residualEntries ?? last.carriedResidual ?? [];
  const adc = await deps.ownerAdc();
  const budget = createBudget({ token: 3, control: 0, cleanup: CAPS.cleanup, upload: 0, edge: 0 });
  const runDir = await deps.makeRunDir(`hosting-recover-${run}-${deps.now()}`);
  const api = makeApi({ deps, budget, adc, runDir });
  const state = { needsRecovery: [], residual: [] };
  const deleted = [];
  const answered = (what, answer) => {
    deleted.push({ what, kind: answer.kind, status: answer.status });
    if (answer.kind !== "ok")
      state.residual.push(`${what} delete ${answer.kind} (${answer.status})`);
    return answer.kind === "ok";
  };
  const channelsDeleted = new Set();
  const channels = await api.call(
    "cleanup",
    "GET",
    `${HOSTING}/projects/${PROJECT}/sites/${SITE}/channels?pageSize=100`,
  );
  const channelsSeen = new Set();
  if (channels.kind === "ok") {
    for (const channel of channels.value.channels ?? []) {
      const id = String(channel.name).split("/").at(-1);
      if (!id.startsWith(`hst-${run}-`)) continue;
      channelsSeen.add(id);
      const answer = await api.call(
        "cleanup",
        "DELETE",
        `${HOSTING}/projects/${PROJECT}/sites/${SITE}/channels/${id}`,
      );
      if (answered(`channel ${id}`, answer)) channelsDeleted.add(id);
    }
  } else state.needsRecovery.push("channels list failed");
  const versionsDeleted = new Set();
  const versions = await listVersions(api, run);
  for (const detail of versions.details) {
    const answer = await api.call("cleanup", "DELETE", `${HOSTING}/${detail.name}`);
    if (answered(`version ${detail.name}`, answer)) versionsDeleted.add(detail.versionId);
  }
  if (versions.error || versions.truncated) state.needsRecovery.push("versions list incomplete");
  const readback = await finalReadback({ run, api, state, before });
  const channelsLeft = new Set(readback.channelsLeft ?? []);
  const versionsLeft = readback.versionsLeft ?? [];
  // A create settles only when an own read showed the resource and the own delete read back absent.
  const open = carried.filter((entry) => {
    const [kind, id] = entry.split(":");
    if (kind === "channel")
      return !(channelsSeen.has(id) && channelsDeleted.has(id) && !channelsLeft.has(id));
    if (kind === "version") return !(versionsDeleted.has(id) && versionsLeft.length === 0);
    return true;
  });
  const clean =
    state.needsRecovery.length === 0 &&
    state.residual.length === 0 &&
    readback.clean &&
    readback.domainsUnchanged === true &&
    open.length === 0 &&
    carriedResidual.length === 0;
  const at = deps.now();
  await deps.appendLedger(
    `${JSON.stringify({
      ts: new Date(at).toISOString(),
      project: PROJECT,
      database: null,
      taskId: TASK_ID,
      run,
      runDir,
      // Never a closing event: the coordinator writes the close row after the A2 read-back.
      event: "recovery-read",
      outcome: clean ? "recovery-read-clean" : "needs-recovery",
      deleted,
      residual: state.residual,
      openUnknownCreates: open,
      carriedResidual,
      domainsUnchanged: readback.domainsUnchanged,
      readbackClean: readback.clean,
      a2ReadNotBefore: new Date(at + 10 * 60_000).toISOString(),
      requests: budget.snapshot(),
      estimatedUsd: 0,
    })}\n`,
  );
  return {
    outcome: clean ? "recovery-read-clean" : "needs-recovery",
    deleted,
    openUnknownCreates: open,
    readback,
    exitCode: clean ? 0 : 1,
  };
}

// ---- production effects -----------------------------------------------------------------------------------------

async function ownerAdc() {
  const path = resolve(
    process.env.FIREEMU_OWNER_ADC ||
      join(homedir(), ".config/gcloud/application_default_credentials.json"),
  );
  const file = JSON.parse(await readFile(path, "utf8"));
  if (
    file.type !== "authorized_user" ||
    !file.refresh_token ||
    !file.client_id ||
    !file.client_secret ||
    (file.token_uri && file.token_uri !== "https://oauth2.googleapis.com/token")
  ) {
    throw new Error("owner authorized_user ADC is required");
  }
  if (
    process.env.GOOGLE_IMPERSONATE_SERVICE_ACCOUNT ||
    process.env.CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT
  ) {
    throw new Error("service-account impersonation is outside this packet");
  }
  return { path, file };
}

async function boundedText(response) {
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > MAX_RESPONSE_BYTES) {
      await reader.cancel("response exceeded 1 MiB");
      throw new Error("response exceeded 1 MiB");
    }
    chunks.push(Buffer.from(value));
  }
  return Buffer.concat(chunks).toString("utf8");
}

async function acquireToken(adc) {
  const response = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: adc.file.refresh_token,
      client_id: adc.file.client_id,
      client_secret: adc.file.client_secret,
    }),
    redirect: "manual",
    signal: AbortSignal.timeout(30_000),
  });
  const text = await boundedText(response);
  if (response.status !== 200) throw new Error(`ADC refresh returned ${response.status}`);
  const value = JSON.parse(text);
  if (!value.access_token || !Number.isFinite(value.expires_in))
    throw new Error("ADC refresh had no token");
  return { value: value.access_token, expiresAt: Date.now() + value.expires_in * 1000 - 120_000 };
}

const CONFORMANCE = resolve(fileURLToPath(new URL("../..", import.meta.url)));

async function repositoryRoot() {
  const { stdout } = await execFileAsync(
    "git",
    ["rev-parse", "--path-format=absolute", "--git-common-dir"],
    {
      cwd: CONFORMANCE,
    },
  );
  return resolve(stdout.trim(), "..");
}

export async function productionDeps() {
  const root = await repositoryRoot();
  const git = (args) => execFileAsync("git", args, { cwd: CONFORMANCE });
  return {
    now: Date.now,
    async assertCleanTree() {
      if ((await git(["status", "--porcelain"])).stdout.trim())
        throw new Error("the worktree is not clean");
    },
    gitSha: async () => (await git(["rev-parse", "HEAD"])).stdout.trim(),
    async readSources() {
      const cli = JSON.parse(
        await readFile(join(CONFORMANCE, "node_modules/firebase-tools/package.json"), "utf8"),
      );
      if (cli.version !== "15.28.2") throw new Error("pinned firebase-tools 15.28.2 is required");
      const corpus = buildCorpus();
      if (corpusManifest(corpus).corpusSha256 !== CORPUS_SHA256)
        throw new Error("the corpus is not the pinned one");
      return { corpus };
    },
    readLedger: () => readFile(join(root, "docs.local/runs/sandbox-ledger.jsonl"), "utf8"),
    appendLedger: (text) => appendFile(join(root, "docs.local/runs/sandbox-ledger.jsonl"), text),
    ownerAdc,
    async webConfig() {
      const path = resolve(process.env.FIREEMU_HOSTING_WEB_CONFIG ?? "");
      if (
        !process.env.FIREEMU_HOSTING_WEB_CONFIG ||
        !path.startsWith(join(root, "docs.local/oracle-credentials") + sep)
      ) {
        throw new Error(
          "FIREEMU_HOSTING_WEB_CONFIG must name a file under docs.local/oracle-credentials",
        );
      }
      const metadata = await stat(path);
      if (metadata.size > 4096 || (metadata.mode & 0o077) !== 0)
        throw new Error("the web config is not bounded and owner-only");
      return JSON.parse(await readFile(path, "utf8"));
    },
    async makeRunDir(name) {
      const dir = join(root, "docs.local/runs", name);
      await mkdir(dir, { recursive: false, mode: 0o700 });
      return dir;
    },
    writeRunFile: (dir, name, text) =>
      writeFile(join(dir, name), text, { mode: 0o600, flag: "wx" }),
    appendRunFile: (dir, name, text) => appendFile(join(dir, name), text, { mode: 0o600 }),
    runTag: () => randomBytes(3).toString("hex"),
    token: acquireToken,
    async http({ method, url, headers, body }) {
      const { hostname } = new URL(url);
      if (!ALLOWED_HOSTS.has(hostname)) throw new Error(`host ${hostname} is not reviewed`);
      try {
        const response = await fetch(url, {
          method,
          headers,
          ...(body === undefined ? undefined : { body }),
          redirect: "manual",
          signal: AbortSignal.timeout(60_000),
        });
        return { status: response.status, text: await boundedText(response) };
      } catch {
        return { status: 0, text: "" };
      }
    },
    edge: edgeRequest,
    sleep: (ms) => new Promise((resolveSleep) => setTimeout(resolveSleep, ms)),
    installSignals(handler) {
      for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) process.on(signal, handler);
    },
    log: (text) => console.log(text),
    warn: (text) => console.error(text),
  };
}

/** The offline `check`: digests, counts and the worst-case request total. */
export function checkReport() {
  const manifest = corpusManifest();
  return {
    corpusSha256: manifest.corpusSha256,
    pinned: CORPUS_SHA256,
    versions: manifest.versions.length,
    requests: manifest.versions.reduce((n, v) => n + v.requests.length, 0),
    caps: CAPS,
    worstCaseTotal: Object.values(CAPS).reduce((a, b) => a + b, 0),
  };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const mode = process.argv[2];
  if (mode === "check") console.log(JSON.stringify(checkReport(), null, 2));
  else if (mode === "digest") console.log(CORPUS_SHA256);
  else if (mode === "record-production" || mode === "recover") {
    const deps = await productionDeps();
    const result = await (mode === "recover" ? recoverHosting : recordHosting)(process.env, deps);
    console.log(JSON.stringify(result));
    process.exitCode = result.exitCode;
  } else throw new Error("usage: record.mjs check|digest|record-production|recover");
}
