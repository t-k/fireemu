// Deployment and removal of the blocking-function fixture on the Identity Platform sandbox
// (owner decision TB1). Production only; fireemu serves ./function directly.
//
// A recording deploys the fixture once (the pinned firebase-tools, codebase `atb-blocking`),
// reads back that the four triggers are registered and that each service admits Identity
// Platform (allUsers invoker), records, and then always removes what it deployed: the four
// functions, the fixture's triggers (the blockingFunctions config is put back to what the
// preflight read), the fixture's images in the Cloud Functions Artifact Registry repository, its
// source objects and the upload objects this deployment created. Each is read back. Nothing
// here deletes another function, trigger, image or object: every deletion names the fixture's
// functions, or an upload object that did not exist before the deployment started.
//
// Every request counts toward the campaign's single request budget (budget.mjs): the REST
// requests through the budget's `fetch`, each CLI and npm call by its whole allowance before it
// runs, under the request meter (cli-meter.cjs) that stops it at that allowance.

import { execFile } from "node:child_process";
import { cp, mkdir, mkdtemp, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { CONFORMANCE_DIR } from "../config.mjs";
import {
  CLI_DELETE_ALLOWANCE,
  CLI_DEPLOY_ALLOWANCE,
  MAX_FIXTURE_OBJECTS,
  SETTLE_READS,
  chargeExternal,
} from "./budget.mjs";

const execFileAsync = promisify(execFile);

export const REGION = "us-central1";
export const CODEBASE = "atb-blocking";
/** The fixture's functions by the blocking event each is registered for. */
export const FIXTURE_FUNCTIONS = {
  beforeCreate: "atbBeforeCreate",
  beforeSignIn: "atbBeforeSignIn",
  beforeSendEmail: "atbBeforeSendEmail",
  beforeSendSms: "atbBeforeSendSms",
};
const NAMES = Object.values(FIXTURE_FUNCTIONS);
const encodePackagePart = (value) =>
  value
    .replaceAll("_", "__")
    .replaceAll("-", "--")
    .replace(/^[A-Z]/, (first) => `${first.toLowerCase()}-${first.toLowerCase()}`)
    .replace(/[A-Z]/g, (letter) => `_${letter.toLowerCase()}`);
const PACKAGE_IDS = new Set(
  NAMES.map(
    (name) =>
      `${encodePackagePart("fireemu-oracle-idp")}__${encodePackagePart(REGION)}__${encodePackagePart(name)}`,
  ),
);
/**
 * Every API firebase-tools ensures for a 2nd gen deployment (it enables a missing one without
 * asking, pre-send review MF-2); the fixture also declares identitytoolkit. A deployment is only
 * started when all of them are already on, so the CLI enables nothing.
 */
export const REQUIRED_APIS = [
  "cloudfunctions.googleapis.com",
  "cloudbuild.googleapis.com",
  "artifactregistry.googleapis.com",
  "run.googleapis.com",
  "eventarc.googleapis.com",
  "pubsub.googleapis.com",
  "storage.googleapis.com",
  "identitytoolkit.googleapis.com",
  // The pinned CLI prepares extensions for every functions deployment (firebase-functions
  // always declares `extensions: {}`) and enables this API without asking (review M1).
  "firebaseextensions.googleapis.com",
];
/** The pinned Firebase CLI (conformance/package.json), never the one on PATH. */
export const FIREBASE_CLI = join(CONFORMANCE_DIR, "node_modules", ".bin", "firebase");
/** The request meter every deployment subprocess loads (`--require`). */
export const CLI_METER = fileURLToPath(new URL("./cli-meter.cjs", import.meta.url));
/** Environment variables that would change the CLI's credentials, billing, logging or meter. */
const DROPPED_ENV = [
  "NODE_OPTIONS",
  "FIREEMU_CLI_METER_FILE",
  "FIREEMU_CLI_METER_LIMIT",
  "FIREEMU_CLI_METER_COUNT_LOOPBACK",
  "GOOGLE_APPLICATION_CREDENTIALS",
  "GOOGLE_CLOUD_QUOTA_PROJECT",
  "FIREBASE_TOKEN",
  "DEBUG",
  "FIREEMU_SANDBOX_LOCK_NONCE",
  "FIREEMU_SANDBOX_WRAPPER_PID",
  "FIREEMU_AUTH_CAMPAIGN_PID",
];
/** Deployment subprocesses must never inherit the runner's lock capability. */
export function deploymentCliEnv(source = process.env) {
  const env = { ...source };
  for (const name of DROPPED_ENV) delete env[name];
  return env;
}
/**
 * A deployment subprocess's environment: counted into `file`, stopped past `limit`, and billed to
 * `project` (the CLI sends `x-goog-user-project` from it, so a fallback to the ADC never bills
 * the ADC file's quota project, review S2).
 */
function meteredEnv(file, limit, project) {
  return {
    ...deploymentCliEnv(),
    GOOGLE_CLOUD_QUOTA_PROJECT: project,
    NODE_OPTIONS: `--require=${CLI_METER}`,
    FIREEMU_CLI_METER_FILE: file,
    FIREEMU_CLI_METER_LIMIT: String(limit),
    // The update check and the CLI's message-of-the-day fetch (firebase-public cli.json, skipped
    // under CI) would be requests of their own.
    NO_UPDATE_NOTIFIER: "1",
    CI: "1",
  };
}
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
/** The fixture's services are public for at most about this long from the deployment (TB1). */
export const PUBLIC_DEADLINE_MINUTES = 60;

/**
 * The cleanup policy firebase-tools expects on `gcf-artifacts` (functions/artifacts.js): with it
 * in place the CLI deploys without `--force` and changes no policy (owner decision C, 2026-09-25:
 * the repository and this policy are created once, through REST, before the first deployment).
 */
export const CLEANUP_POLICY = {
  id: "firebase-functions-cleanup",
  condition: { tagState: "ANY", olderThan: "86400s" },
  action: "DELETE",
};

/** Whether a repository carries the CLI's cleanup policy (the CLI's own comparison). */
export function hasCleanupPolicy(repository) {
  const policy = repository?.cleanupPolicies?.[CLEANUP_POLICY.id];
  return policy?.condition?.tagState === "ANY" && policy?.condition?.olderThan === "86400s";
}

/** Whether an Artifact Registry package or a source object belongs to the fixture. */
export function isFixtureArtifact(name) {
  const path = String(name);
  let packageName = path.includes("/packages/") ? path.split("/packages/").at(-1) : path;
  // Artifact Registry encodes the slash of a cache image's package (`…%2Fcache`, review S5).
  try {
    packageName = decodeURIComponent(packageName);
  } catch {
    return false;
  }
  const packageId = packageName.split("/")[0];
  const sourcePrefix = path.split("/")[0].toLowerCase();
  return PACKAGE_IDS.has(packageId) || NAMES.some((fn) => sourcePrefix === fn.toLowerCase());
}

/** Whether an event names this project's fixture function or its read-back Cloud Run service. */
export function isFixtureTrigger(event, trigger, deployedUri) {
  const name = FIXTURE_FUNCTIONS[event];
  if (!name) return false;
  let uri;
  try {
    uri = new URL(trigger?.functionUri);
  } catch {
    return false;
  }
  if (uri.protocol !== "https:" || uri.username || uri.password || uri.search || uri.hash)
    return false;
  if (uri.hostname.endsWith(".cloudfunctions.net"))
    return (
      uri.hostname === `${REGION}-fireemu-oracle-idp.cloudfunctions.net` &&
      uri.pathname === `/${name}`
    );
  if (!uri.hostname.endsWith(".run.app")) return false;
  try {
    return uri.href === new URL(deployedUri).href;
  } catch {
    return false;
  }
}

/** A failed CLI call without its output: the exit and at most one short line (SF-5). */
function cliFailure(what, error, project, number) {
  const last = String(error?.stderr ?? "")
    .trim()
    .split("\n")
    .at(-1)
    ?.slice(0, 200)
    .replaceAll(number, "<project-number>")
    .replaceAll(project, "<project>");
  return new Error(
    `${what} failed (exit ${error?.code ?? "?"}${error?.signal ? `, ${error.signal}` : ""}): ${last ?? ""}`,
  );
}

/**
 * The sandbox's REST access and the CLI calls. Every call names the sandbox project and uses the
 * owner's ADC; `project` and `number` come from the checked web config. `run` and `fetchImpl`
 * are injectable for the tests.
 */
export function createDeployer({
  project,
  number,
  token,
  log = () => {},
  fetchImpl = fetch,
  run = execFileAsync,
  retryMs = 5000,
  // The wait between listings while a fixture function is still deploying (review S6).
  settleMs = 30_000,
  // Every REST request is abandoned after this long, so no removal step can hang (review S4).
  requestTimeoutMs = 30_000,
  now = Date.now,
  // Charges a CLI call's allowance to the installed budget before it runs.
  charge = chargeExternal,
  // The owner token is renewed after this long (each read is a charged `gcloud` call).
  tokenMaxAgeMs = 40 * 60_000,
}) {
  if (project !== "fireemu-oracle-idp")
    throw new Error("the fixture is deployed only to the sandbox");
  let requests = 0;
  let baseline;
  let uploadsBefore;
  // A restore's: when the stopped recording started, and the upload objects it left alone.
  let adoptedSince;
  let uploadsLeftAlone = 0;
  let deployStarted;
  let adopted = false;
  let repositoryChange;
  let ownerToken;
  let ownerTokenAt;
  const cliCalls = [];
  let meterDir;

  /** The owner token, read once and renewed when older than `tokenMaxAgeMs`. */
  async function currentToken() {
    if (ownerToken === undefined || now() - ownerTokenAt >= tokenMaxAgeMs) {
      ownerToken = await token();
      ownerTokenAt = now();
    }
    return ownerToken;
  }

  async function call(method, url, body) {
    const authorization = `Bearer ${await currentToken()}`;
    requests += 1;
    const response = await fetchImpl(url, {
      method,
      redirect: "error",
      signal: AbortSignal.timeout(requestTimeoutMs),
      headers: {
        authorization,
        "x-goog-user-project": project,
        ...(body === undefined ? {} : { "content-type": "application/json" }),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    const text = await response.text();
    let json = null;
    try {
      json = JSON.parse(text);
    } catch {
      /* not JSON */
    }
    return { status: response.status, json };
  }

  /**
   * The CLI deletion gets the time left until the public deadline (TB1: about an hour from the
   * start of the deployment), at most 20 minutes (review S4). A late deletion, and a restore's,
   * still gets 10 minutes: stopping the CLI mid-deletion would only leave the functions public
   * for longer.
   */
  function deletionTimeoutMs() {
    const started = deployStarted?.getTime() ?? now();
    const left = started + PUBLIC_DEADLINE_MINUTES * 60_000 - now();
    return Math.min(20 * 60_000, Math.max(10 * 60_000, left));
  }

  /**
   * Runs a CLI or npm call in its own process group (a terminal signal does not kill it, SF-3),
   * charged its whole allowance first and counted by the meter, which stops it at the allowance.
   * A refused charge runs nothing.
   */
  async function metered(file, args, { cwd, timeout, allowance, charged = () => {} }) {
    charge(allowance);
    charged();
    meterDir ??= await mkdtemp(join(tmpdir(), "atb-cli-meter-"));
    const counter = join(meterDir, `${cliCalls.length}`);
    const entry = { call: args[0], allowance, used: 0, stopped: false };
    cliCalls.push(entry);
    try {
      return await run(file, args, {
        cwd,
        timeout,
        env: meteredEnv(counter, allowance, project),
        detached: true,
        maxBuffer: 16 * 1024 * 1024,
      });
    } finally {
      // The meter appends a byte per request, the refused one included.
      const counted = await stat(counter).then(
        ({ size }) => size,
        () => 0,
      );
      entry.used = Math.min(counted, allowance);
      entry.stopped = counted > allowance;
      await rm(counter, { force: true });
    }
  }

  /** The pinned CLI under the meter. */
  async function cli(args, options) {
    return await metered(FIREBASE_CLI, args, options);
  }

  const functionsUrl = `https://cloudfunctions.googleapis.com/v2/projects/${project}/locations/${REGION}/functions`;
  const configUrl = `https://identitytoolkit.googleapis.com/admin/v2/projects/${project}/config`;
  const repository = `https://artifactregistry.googleapis.com/v1/projects/${project}/locations/${REGION}/repositories/gcf-artifacts`;
  const sourcesBucket = `gcf-v2-sources-${number}-${REGION}`;
  const uploadsBucket = `gcf-v2-uploads-${number}-${REGION}`;

  async function missingApis() {
    const missing = [];
    for (const api of REQUIRED_APIS) {
      const { status, json } = await call(
        "GET",
        `https://serviceusage.googleapis.com/v1/projects/${number}/services/${api}`,
      );
      if (status !== 200 || json?.state !== "ENABLED") missing.push(api);
    }
    return missing;
  }

  async function listFunctionResources() {
    const { status, json } = await call("GET", `${functionsUrl}?pageSize=100`);
    if (status !== 200) throw new Error(`functions list: HTTP ${status}`);
    if (json?.nextPageToken) throw new Error("functions list: more than one page");
    return json?.functions ?? [];
  }

  async function listFunctions() {
    return (await listFunctionResources()).map((fn) => fn.name.split("/").at(-1));
  }

  async function blockingConfig() {
    const { status, json } = await call("GET", configUrl);
    if (status !== 200) throw new Error(`config read: HTTP ${status}`);
    return json?.blockingFunctions ?? {};
  }

  /** The objects (`name`, `timeCreated`) of a bucket, or undefined when it does not exist. */
  async function objects(bucket) {
    const { status, json } = await call(
      "GET",
      `https://storage.googleapis.com/storage/v1/b/${bucket}/o?maxResults=1000`,
    );
    if (status === 404) return undefined;
    if (status !== 200) throw new Error(`objects of ${bucket}: HTTP ${status}`);
    if (json?.nextPageToken) throw new Error(`objects of ${bucket}: more than one page`);
    return (json?.items ?? []).map((item) => ({ name: item.name, timeCreated: item.timeCreated }));
  }

  /**
   * Creates `us-central1/gcf-artifacts` with the CLI's cleanup policy when it does not exist, or
   * adds the policy when it is missing, and reads it back; returns what it changed (for the change
   * log). Called by the preflight, before anything is deployed.
   */
  async function prepareRepository() {
    const read = async () => call("GET", repository);
    let { status, json } = await read();
    if (status === 200 && hasCleanupPolicy(json)) return "unchanged";
    let change;
    if (status === 404) {
      const created = await call(
        "POST",
        `${repository.replace(/\/gcf-artifacts$/, "")}?repositoryId=gcf-artifacts`,
        { format: "DOCKER", cleanupPolicies: { [CLEANUP_POLICY.id]: CLEANUP_POLICY } },
      );
      if (created.status !== 200) throw new Error(`repository create: HTTP ${created.status}`);
      change = "created with the cleanup policy";
      repositoryChange = change;
    } else if (status === 200) {
      const patched = await call("PATCH", `${repository}?updateMask=cleanupPolicies`, {
        cleanupPolicies: { ...json.cleanupPolicies, [CLEANUP_POLICY.id]: CLEANUP_POLICY },
      });
      if (patched.status !== 200) throw new Error(`repository policy: HTTP ${patched.status}`);
      change = "cleanup policy added";
      repositoryChange = change;
    } else throw new Error(`repository read: HTTP ${status}`);
    // Creation is a long-running operation: read back until the repository carries the policy.
    for (let attempt = 0; attempt < 12; attempt += 1) {
      ({ status, json } = await read());
      if (status === 200 && hasCleanupPolicy(json)) return change;
      await sleep(retryMs);
    }
    throw new Error("gcf-artifacts did not read back with the cleanup policy");
  }

  /**
   * Refuses to deploy unless every API the CLI ensures is on, no function exists in the region,
   * and no blocking trigger is registered. Keeps the blockingFunctions value and the upload
   * objects it saw, for the removal.
   */
  async function preflight() {
    const missing = await missingApis();
    if (missing.length) throw new Error(`APIs not enabled: ${missing.join(", ")}`);
    const existing = await listFunctions();
    if (existing.length) throw new Error(`functions exist in ${REGION}: ${existing.length}`);
    const config = await blockingConfig();
    if (Object.keys(config.triggers ?? {}).length)
      throw new Error("blocking triggers are already registered");
    // The sandbox's baseline is an empty blockingFunctions: the removal and a restore both put
    // it back to that, so any other value stops the run before anything changes (review-2 S-A).
    if (JSON.stringify(config) !== "{}")
      throw new Error("blockingFunctions is not the sandbox's empty baseline");
    baseline = config;
    uploadsBefore = new Set(((await objects(uploadsBucket)) ?? []).map((item) => item.name));
    return { repository: await prepareRepository() };
  }

  /** Deploys a private copy of the fixture with the pinned CLI; the removal is due from here. */
  async function deploy(source, buildDir) {
    if (baseline === undefined) throw new Error("deploy before a passed preflight");
    await mkdir(buildDir, { recursive: true, mode: 0o700 });
    await cp(source, buildDir, {
      recursive: true,
      filter: (path) => !path.split("/").includes("node_modules"),
    });
    try {
      // From the npm cache only (filled before the campaign): the campaign sends nothing to
      // the registry, and a missing package fails here, before anything is deployed.
      await metered("npm", ["ci", "--offline", "--no-audit", "--no-fund", "--loglevel=error"], {
        cwd: buildDir,
        timeout: 600_000,
        allowance: 0,
      });
    } catch (error) {
      if (error.fatal) throw error;
      throw cliFailure("npm ci", error, project, number);
    }
    log("deploying the blocking fixture (pinned firebase-tools)");
    try {
      await cli(
        [
          "deploy",
          "--only",
          `functions:${CODEBASE}`,
          `--project=${project}`,
          // No --force: it would rewrite the cleanup policy and skip other confirmations.
          "--non-interactive",
        ],
        {
          cwd: buildDir,
          timeout: 1_800_000,
          allowance: CLI_DEPLOY_ALLOWANCE,
          // The removal is due from the moment the deployment may send anything.
          charged: () => {
            deployStarted = new Date(now());
          },
        },
      );
    } catch (error) {
      if (error.fatal) throw error;
      throw cliFailure("firebase deploy", error, project, number);
    }
  }

  /**
   * The four triggers name the fixture's functions and the four functions exist, nothing else.
   * Each function is woken once with an empty request (it only refuses it), so the first
   * recorded row does not meet a cold start (SF-11).
   */
  async function verifyRegistered() {
    const triggers = (await blockingConfig()).triggers ?? {};
    const resources = await listFunctionResources();
    const existing = resources.map((resource) => resource.name.split("/").at(-1));
    const missing = NAMES.filter((fn) => !existing.includes(fn));
    if (missing.length) throw new Error(`functions missing after deploy: ${missing.join(", ")}`);
    const extra = existing.filter((fn) => !NAMES.includes(fn));
    if (extra.length) throw new Error(`unexpected functions after deploy: ${extra.join(", ")}`);
    for (const [event, fn] of Object.entries(FIXTURE_FUNCTIONS)) {
      const deployedUri = resources.find((resource) => resource.name.endsWith(`/functions/${fn}`))
        ?.serviceConfig?.uri;
      if (!isFixtureTrigger(event, triggers[event], deployedUri))
        throw new Error(`trigger ${event} is not registered to ${fn}`);
    }
    for (const event of Object.keys(FIXTURE_FUNCTIONS)) {
      await fetchImpl(triggers[event].functionUri, {
        method: "POST",
        redirect: "error",
        signal: AbortSignal.timeout(requestTimeoutMs),
        headers: { "content-type": "application/json" },
        body: "{}",
      }).catch(() => undefined);
    }
    return { triggers: Object.keys(triggers).toSorted(), functions: existing.toSorted() };
  }

  /** Whether each fixture service admits unauthenticated callers (TB1: read back). */
  async function invokers() {
    const out = {};
    for (const fn of NAMES) {
      const { status, json } = await call(
        "GET",
        `https://run.googleapis.com/v2/projects/${project}/locations/${REGION}/services/${fn.toLowerCase()}:getIamPolicy`,
      );
      out[fn] =
        status === 200
          ? (json?.bindings ?? []).some(
              (b) => b.role === "roles/run.invoker" && (b.members ?? []).includes("allUsers"),
            )
          : `HTTP ${status}`;
    }
    return out;
  }

  async function fixturePackages() {
    const { status, json } = await call("GET", `${repository}/packages?pageSize=500`);
    if (status === 404) return [];
    if (status !== 200) throw new Error(`artifact packages: HTTP ${status}`);
    if (json?.nextPageToken) throw new Error("artifact packages: more than one page");
    return (json?.packages ?? []).map((p) => p.name).filter(isFixtureArtifact);
  }

  /**
   * The objects this deployment created: fixture sources, and uploads new since the preflight.
   * A restore, which has no preflight listing, takes the uploads created since the stopped
   * recording started, only while no other function exists; older ones are left and counted
   * (review-2 S-B).
   */
  async function deployedObjects() {
    if (adopted && (await listFunctions()).some((fn) => !NAMES.includes(fn)))
      throw new Error("another function exists; upload objects are left for a hand check");
    const sources = ((await objects(sourcesBucket)) ?? [])
      .map((item) => item.name)
      .filter(isFixtureArtifact);
    const listed = (await objects(uploadsBucket)) ?? [];
    const ours = (item) =>
      adopted
        ? adoptedSince !== undefined && Date.parse(item.timeCreated) >= adoptedSince.getTime()
        : !uploadsBefore.has(item.name);
    const uploads = listed.filter(ours).map((item) => item.name);
    uploadsLeftAlone = listed.length - uploads.length;
    return [
      ...sources.map((name) => [sourcesBucket, name]),
      ...uploads.map((name) => [uploadsBucket, name]),
    ];
  }

  /** Retries a read-back while a deletion settles (Artifact Registry deletes are LROs, SF-8). */
  async function settle(what, check, attempts = 6) {
    for (let attempt = 1; ; attempt += 1) {
      if (await check()) return;
      if (attempt >= attempts) throw new Error(`${what} remain`);
      await sleep(retryMs);
    }
  }

  /**
   * Removes what the deployment left, reading each back. Due only once a deployment started;
   * every step runs even when an earlier one failed, and the failures are thrown together.
   */
  async function remove(buildDir) {
    if (deployStarted === undefined) return { removed: "nothing deployed" };
    // The CLI runs in the build copy; a restore has none yet (confirmation SF-C1).
    await mkdir(buildDir, { recursive: true, mode: 0o700 });
    const problems = [];
    const step = async (name, action) => {
      try {
        return await action();
      } catch (error) {
        problems.push(`${name}: ${error?.message ?? error}`);
        return undefined;
      }
    };
    const functionUris = new Map();
    await step("function URI read", async () => {
      for (const resource of await listFunctionResources()) {
        const name = resource.name.split("/").at(-1);
        if (NAMES.includes(name) && typeof resource.serviceConfig?.uri === "string")
          functionUris.set(name, resource.serviceConfig.uri);
      }
    });
    await step("functions:delete", async () => {
      const fixture = (resources) =>
        resources.filter((resource) => NAMES.includes(resource.name.split("/").at(-1)));
      let resources = fixture(await listFunctionResources());
      // A deployment the CLI's timeout stopped goes on at the server, and deleting a function
      // that is still deploying fails: wait, within a bound, then delete anyway (review S6).
      for (
        let reads = 0;
        reads < SETTLE_READS && resources.some((resource) => resource.state === "DEPLOYING");
        reads += 1
      ) {
        await sleep(settleMs);
        resources = fixture(await listFunctionResources());
      }
      const present = resources.map((resource) => resource.name.split("/").at(-1));
      if (present.length === 0) return;
      try {
        await cli(
          [
            "functions:delete",
            ...present,
            `--region=${REGION}`,
            `--project=${project}`,
            "--non-interactive",
            // Here --force only answers the deletion prompt for the functions listed above
            // (a non-interactive run otherwise aborts); it changes no policy.
            "--force",
          ],
          { cwd: buildDir, timeout: deletionTimeoutMs(), allowance: CLI_DELETE_ALLOWANCE },
        );
      } catch (error) {
        if (error.fatal) throw error;
        throw cliFailure("firebase functions:delete", error, project, number);
      }
    });
    await step("functions read back", async () => {
      const left = (await listFunctions()).filter((fn) => NAMES.includes(fn));
      if (left.length) throw new Error(`functions remain: ${left.join(", ")}`);
    });
    await step("blocking config", async () => {
      const current = await blockingConfig();
      const foreign = Object.entries(current.triggers ?? {}).filter(
        ([event, trigger]) =>
          !isFixtureTrigger(event, trigger, functionUris.get(FIXTURE_FUNCTIONS[event])),
      );
      // Only the fixture's triggers are taken out; another trigger stops the run untouched.
      if (foreign.length)
        throw new Error(`triggers of another function: ${foreign.map(([e]) => e).join(", ")}`);
      if (JSON.stringify(current) === JSON.stringify(baseline)) return;
      const { status } = await call("PATCH", `${configUrl}?updateMask=blockingFunctions`, {
        blockingFunctions: baseline,
      });
      if (status !== 200) throw new Error(`config restore: HTTP ${status}`);
      const after = await blockingConfig();
      if (Object.keys(after.triggers ?? {}).length) throw new Error("blocking triggers remain");
      if (
        JSON.stringify(after.forwardInboundCredentials ?? {}) !==
        JSON.stringify(baseline.forwardInboundCredentials ?? {})
      )
        throw new Error("forwardInboundCredentials did not read back as before");
    });
    let images = 0;
    await step("images", async () => {
      for (const name of await fixturePackages()) {
        const answer = await call("DELETE", `https://artifactregistry.googleapis.com/v1/${name}`);
        if (![200, 404].includes(answer.status))
          throw new Error(`artifact delete: HTTP ${answer.status}`);
        images += 1;
      }
    });
    await step("images read back", () =>
      settle("fixture images", async () => (await fixturePackages()).length === 0),
    );
    let sources = 0;
    await step("sources", async () => {
      const found = await deployedObjects();
      for (const [bucket, name] of found.slice(0, MAX_FIXTURE_OBJECTS)) {
        const answer = await call(
          "DELETE",
          `https://storage.googleapis.com/storage/v1/b/${bucket}/o/${encodeURIComponent(name)}`,
        );
        if (![204, 404].includes(answer.status))
          throw new Error(`object delete: HTTP ${answer.status}`);
        sources += 1;
      }
      if (found.length > MAX_FIXTURE_OBJECTS)
        throw new Error(`more than ${MAX_FIXTURE_OBJECTS} fixture objects; the rest are left`);
    });
    await step("sources read back", () =>
      settle("fixture sources", async () => (await deployedObjects()).length === 0),
    );
    // The build copy may hold a CLI debug log with config bodies (SF-5).
    await step("build copy", () => rm(buildDir, { recursive: true, force: true }));
    if (problems.length) throw Object.assign(new Error(problems.join("; ")), { fatal: true });
    return {
      images,
      sources,
      ...(adopted ? { uploadsLeftAlone } : {}),
      deployStartedAt: deployStarted.toISOString(),
      removedAt: new Date().toISOString(),
    };
  }

  async function cliVersion() {
    try {
      const { stdout } = await cli(["--version"], {
        cwd: CONFORMANCE_DIR,
        timeout: 60_000,
        allowance: 0,
      });
      return String(stdout).trim();
    } catch {
      return "unknown";
    }
  }

  /**
   * For restore-sandbox after a run that could not remove its fixture: the sandbox baseline is an
   * empty blockingFunctions (the recording's preflight required it), and the upload objects
   * created at or after `since` (when the stopped recording started) are taken as this harness's
   * while the sandbox holds no other function. Without `since` no upload object is removed.
   */
  function adoptLeftovers(since) {
    if (since !== undefined && !(since instanceof Date && Number.isFinite(since.getTime())))
      throw new Error("adoptLeftovers needs the recording's start as a Date");
    baseline = {};
    uploadsBefore = new Set();
    adoptedSince = since;
    deployStarted = new Date(0);
    adopted = true;
  }

  return {
    preflight,
    adoptLeftovers,
    deploy,
    verifyRegistered,
    invokers,
    remove,
    cliVersion,
    deployStarted: () => deployStarted,
    deletionTimeoutMs,
    /** What the preflight changed on gcf-artifacts, also when it failed afterwards (SF-C3). */
    repositoryChange: () => repositoryChange,
    requests: () => requests,
    /** Each CLI and npm call: its allowance, the requests the meter counted, whether it stopped. */
    cliRequests: () => cliCalls.map((entry) => ({ ...entry })),
  };
}
