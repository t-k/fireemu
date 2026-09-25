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

import { execFile } from "node:child_process";
import { cp, mkdir, rm } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";

import { CONFORMANCE_DIR } from "../config.mjs";

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
];
/** The pinned Firebase CLI (conformance/package.json), never the one on PATH. */
export const FIREBASE_CLI = join(CONFORMANCE_DIR, "node_modules", ".bin", "firebase");
/** Environment variables that would change the CLI's credentials, billing or logging. */
const DROPPED_ENV = [
  "GOOGLE_APPLICATION_CREDENTIALS",
  "GOOGLE_CLOUD_QUOTA_PROJECT",
  "FIREBASE_TOKEN",
  "DEBUG",
];
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

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
  const flat = String(name)
    .toLowerCase()
    .replaceAll(/[^a-z0-9]/g, "");
  return NAMES.some((fn) => flat.includes(fn.toLowerCase()));
}

/** Whether a registered trigger's URI names a fixture function. */
export function isFixtureTrigger(trigger) {
  const uri = String(trigger?.functionUri ?? "").toLowerCase();
  return NAMES.some((fn) => uri.includes(fn.toLowerCase()));
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
}) {
  if (project !== "fireemu-oracle-idp")
    throw new Error("the fixture is deployed only to the sandbox");
  let requests = 0;
  let baseline;
  let uploadsBefore;
  let deployStarted;
  let adopted = false;
  let repositoryChange;

  async function call(method, url, body) {
    requests += 1;
    const response = await fetchImpl(url, {
      method,
      redirect: "error",
      headers: {
        authorization: `Bearer ${await token()}`,
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

  /** The CLI in its own process group (a terminal signal does not kill it, SF-3). */
  async function cli(args, { cwd, timeout }) {
    const env = { ...process.env };
    for (const name of DROPPED_ENV) delete env[name];
    return await run(FIREBASE_CLI, args, {
      cwd,
      timeout,
      env,
      detached: true,
      maxBuffer: 16 * 1024 * 1024,
    });
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

  async function listFunctions() {
    const { status, json } = await call("GET", `${functionsUrl}?pageSize=100`);
    if (status !== 200) throw new Error(`functions list: HTTP ${status}`);
    if (json?.nextPageToken) throw new Error("functions list: more than one page");
    return (json?.functions ?? []).map((fn) => fn.name.split("/").at(-1));
  }

  async function blockingConfig() {
    const { status, json } = await call("GET", configUrl);
    if (status !== 200) throw new Error(`config read: HTTP ${status}`);
    return json?.blockingFunctions ?? {};
  }

  /** The object names of a bucket, or undefined when it does not exist. */
  async function objects(bucket) {
    const { status, json } = await call(
      "GET",
      `https://storage.googleapis.com/storage/v1/b/${bucket}/o?maxResults=1000`,
    );
    if (status === 404) return undefined;
    if (status !== 200) throw new Error(`objects of ${bucket}: HTTP ${status}`);
    if (json?.nextPageToken) throw new Error(`objects of ${bucket}: more than one page`);
    return (json?.items ?? []).map((item) => item.name);
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
    baseline = config;
    uploadsBefore = new Set((await objects(uploadsBucket)) ?? []);
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
      await run("npm", ["ci", "--no-audit", "--no-fund", "--loglevel=error"], {
        cwd: buildDir,
        timeout: 600_000,
        detached: true,
      });
    } catch (error) {
      throw cliFailure("npm ci", error, project, number);
    }
    log("deploying the blocking fixture (pinned firebase-tools)");
    deployStarted = new Date();
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
        { cwd: buildDir, timeout: 1_800_000 },
      );
    } catch (error) {
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
    for (const [event, fn] of Object.entries(FIXTURE_FUNCTIONS)) {
      const uri = triggers[event]?.functionUri;
      if (typeof uri !== "string" || !uri.toLowerCase().includes(fn.toLowerCase()))
        throw new Error(`trigger ${event} is not registered to ${fn}`);
    }
    const existing = await listFunctions();
    const missing = NAMES.filter((fn) => !existing.includes(fn));
    if (missing.length) throw new Error(`functions missing after deploy: ${missing.join(", ")}`);
    const extra = existing.filter((fn) => !NAMES.includes(fn));
    if (extra.length) throw new Error(`unexpected functions after deploy: ${extra.join(", ")}`);
    for (const event of Object.keys(FIXTURE_FUNCTIONS)) {
      const host = new URL(triggers[event].functionUri).hostname;
      if (!host.endsWith(".run.app") && !host.endsWith(".cloudfunctions.net"))
        throw new Error(`trigger ${event} names an unexpected host`);
      await fetchImpl(triggers[event].functionUri, {
        method: "POST",
        redirect: "error",
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

  /** The objects this deployment created: fixture sources, and uploads new since the preflight. */
  async function deployedObjects() {
    // A restore takes every upload object as the harness's only while no other function exists.
    if (adopted && (await listFunctions()).some((fn) => !NAMES.includes(fn)))
      throw new Error("another function exists; upload objects are left for a hand check");
    const sources = ((await objects(sourcesBucket)) ?? []).filter(isFixtureArtifact);
    const uploads = ((await objects(uploadsBucket)) ?? []).filter(
      (name) => !uploadsBefore.has(name),
    );
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
    await step("functions:delete", async () => {
      const present = (await listFunctions()).filter((fn) => NAMES.includes(fn));
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
          { cwd: buildDir, timeout: 1_200_000 },
        );
      } catch (error) {
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
        ([, t]) => !isFixtureTrigger(t),
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
      for (const [bucket, name] of await deployedObjects()) {
        const answer = await call(
          "DELETE",
          `https://storage.googleapis.com/storage/v1/b/${bucket}/o/${encodeURIComponent(name)}`,
        );
        if (![204, 404].includes(answer.status))
          throw new Error(`object delete: HTTP ${answer.status}`);
        sources += 1;
      }
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
      deployStartedAt: deployStarted.toISOString(),
      removedAt: new Date().toISOString(),
    };
  }

  async function cliVersion() {
    try {
      const { stdout } = await cli(["--version"], { cwd: CONFORMANCE_DIR, timeout: 60_000 });
      return String(stdout).trim();
    } catch {
      return "unknown";
    }
  }

  /**
   * For restore-sandbox after a run that could not remove its fixture: the sandbox baseline has
   * no blocking config, and every upload object is taken as this harness's (the sandbox holds no
   * other functions, which the removal reads back first).
   */
  function adoptLeftovers() {
    baseline = {};
    uploadsBefore = new Set();
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
    /** What the preflight changed on gcf-artifacts, also when it failed afterwards (SF-C3). */
    repositoryChange: () => repositoryChange,
    requests: () => requests,
  };
}
