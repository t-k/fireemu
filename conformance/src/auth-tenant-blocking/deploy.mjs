// Deployment and removal of the blocking-function fixture on the Identity Platform sandbox
// (owner decision TB1). Production only; fireemu serves ./function directly.
//
// A recording deploys the fixture once (firebase-tools, codebase `atb-blocking`), reads back that
// the four triggers are registered, records, and then always removes it: the four functions are
// deleted, the project's blockingFunctions config is cleared, the fixture's images in the
// Cloud Functions Artifact Registry repository and its source objects are deleted, and each of
// these is read back. Nothing here touches another function, image, object or setting: every
// deletion names the fixture's own function names.

import { execFile } from "node:child_process";
import { cp, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";

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
/** The APIs the owner approved enabling (TB1); a deployment asking for another one stops. */
export const APPROVED_APIS = [
  "cloudfunctions.googleapis.com",
  "cloudbuild.googleapis.com",
  "artifactregistry.googleapis.com",
  "run.googleapis.com",
  "eventarc.googleapis.com",
];

/** Whether an Artifact Registry package or a storage object belongs to the fixture. */
export function isFixtureArtifact(name) {
  const flat = String(name)
    .toLowerCase()
    .replaceAll(/[^a-z0-9]/g, "");
  return NAMES.some((fn) => flat.includes(fn.toLowerCase()));
}

/**
 * The sandbox's REST access: every call names the sandbox project and uses the owner's ADC.
 * `project` and `number` come from the checked web config.
 */
export function createDeployer({ project, number, token, log = () => {}, fetchImpl = fetch }) {
  if (project !== "fireemu-oracle-idp")
    throw new Error("the fixture is deployed only to the sandbox");
  let requests = 0;

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

  const functionsUrl = `https://cloudfunctions.googleapis.com/v2/projects/${project}/locations/${REGION}/functions`;
  const configUrl = `https://identitytoolkit.googleapis.com/admin/v2/projects/${project}/config`;
  const repository = `https://artifactregistry.googleapis.com/v1/projects/${project}/locations/${REGION}/repositories/gcf-artifacts`;
  const buckets = [`gcf-v2-sources-${number}-${REGION}`, `gcf-v2-uploads-${number}-${REGION}`];

  /** The approved APIs that are not enabled (serviceusage). */
  async function missingApis() {
    const missing = [];
    for (const api of APPROVED_APIS) {
      const { status, json } = await call(
        "GET",
        `https://serviceusage.googleapis.com/v1/projects/${number}/services/${api}`,
      );
      if (status !== 200 || json?.state !== "ENABLED") missing.push(api);
    }
    return missing;
  }

  /** The functions of the region (every page). */
  async function listFunctions() {
    const names = [];
    let pageToken;
    for (let page = 0; page < 20; page += 1) {
      const url = `${functionsUrl}?pageSize=100${pageToken ? `&pageToken=${encodeURIComponent(pageToken)}` : ""}`;
      const { status, json } = await call("GET", url);
      if (status !== 200) throw new Error(`functions list: HTTP ${status}`);
      for (const fn of json?.functions ?? []) names.push(fn.name.split("/").at(-1));
      pageToken = json?.nextPageToken;
      if (!pageToken) return names;
    }
    throw new Error("functions list: more than 20 pages");
  }

  async function blockingConfig() {
    const { status, json } = await call("GET", configUrl);
    if (status !== 200) throw new Error(`config read: HTTP ${status}`);
    return json?.blockingFunctions ?? {};
  }

  /**
   * Refuses to deploy unless the approved APIs are on, no function exists in the region, and no
   * blocking trigger is registered (nothing of another lane can be overwritten).
   */
  async function preflight() {
    const missing = await missingApis();
    if (missing.length) throw new Error(`APIs not enabled: ${missing.join(", ")}`);
    const existing = await listFunctions();
    if (existing.length) throw new Error(`functions exist in ${REGION}: ${existing.length}`);
    const triggers = (await blockingConfig()).triggers ?? {};
    if (Object.keys(triggers).length) throw new Error("blocking triggers are already registered");
  }

  /** Deploys a private copy of the fixture with firebase-tools; any failure is thrown. */
  async function deploy(source, buildDir) {
    await mkdir(buildDir, { recursive: true, mode: 0o700 });
    await cp(source, buildDir, {
      recursive: true,
      filter: (path) => !path.split("/").includes("node_modules"),
    });
    await execFileAsync("npm", ["ci", "--no-audit", "--no-fund", "--loglevel=error"], {
      cwd: buildDir,
      timeout: 600_000,
    });
    log("deploying the blocking fixture (firebase-tools)");
    await execFileAsync(
      "firebase",
      [
        "deploy",
        "--only",
        `functions:${CODEBASE}`,
        `--project=${project}`,
        "--non-interactive",
        "--force",
      ],
      { cwd: buildDir, timeout: 1_800_000, maxBuffer: 16 * 1024 * 1024 },
    );
  }

  /**
   * The four triggers are registered to the fixture's functions, and the four functions exist.
   * Returns what was read back (no URL is kept: the run.app host carries a random part).
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
    return { triggers: Object.keys(triggers).toSorted(), functions: existing.toSorted() };
  }

  /** Whether each fixture service admits unauthenticated callers (recorded, TB1). */
  async function invokers() {
    const out = {};
    for (const fn of NAMES) {
      const service = fn.toLowerCase();
      const { status, json } = await call(
        "GET",
        `https://run.googleapis.com/v2/projects/${project}/locations/${REGION}/services/${service}:getIamPolicy`,
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

  async function deleteArtifacts() {
    let deleted = 0;
    const { status, json } = await call("GET", `${repository}/packages?pageSize=500`);
    if (status === 404) return deleted;
    if (status !== 200) throw new Error(`artifact packages: HTTP ${status}`);
    for (const pkg of (json?.packages ?? []).filter((p) => isFixtureArtifact(p.name))) {
      const answer = await call("DELETE", `https://artifactregistry.googleapis.com/v1/${pkg.name}`);
      if (![200, 404].includes(answer.status))
        throw new Error(`artifact delete: HTTP ${answer.status}`);
      deleted += 1;
    }
    return deleted;
  }

  async function fixtureArtifacts() {
    const { status, json } = await call("GET", `${repository}/packages?pageSize=500`);
    if (status === 404) return 0;
    if (status !== 200) throw new Error(`artifact packages: HTTP ${status}`);
    return (json?.packages ?? []).filter((p) => isFixtureArtifact(p.name)).length;
  }

  async function bucketObjects(bucket) {
    const { status, json } = await call(
      "GET",
      `https://storage.googleapis.com/storage/v1/b/${bucket}/o?maxResults=1000`,
    );
    if (status === 404) return [];
    if (status !== 200) throw new Error(`objects of ${bucket}: HTTP ${status}`);
    return (json?.items ?? []).map((item) => item.name).filter(isFixtureArtifact);
  }

  async function deleteSources() {
    let deleted = 0;
    for (const bucket of buckets) {
      for (const name of await bucketObjects(bucket)) {
        const answer = await call(
          "DELETE",
          `https://storage.googleapis.com/storage/v1/b/${bucket}/o/${encodeURIComponent(name)}`,
        );
        if (![204, 404].includes(answer.status))
          throw new Error(`object delete: HTTP ${answer.status}`);
        deleted += 1;
      }
    }
    return deleted;
  }

  /**
   * Removes everything the fixture left: the four functions (firebase-tools), the blocking
   * triggers, the images and the sources, and reads each back. Every step runs even when an
   * earlier one failed; the failures are thrown together at the end.
   */
  async function remove(buildDir) {
    const problems = [];
    const step = async (name, run) => {
      try {
        return await run();
      } catch (error) {
        problems.push(`${name}: ${error?.message ?? error}`);
        return undefined;
      }
    };
    await step("functions:delete", async () => {
      const present = (await listFunctions()).filter((fn) => NAMES.includes(fn));
      if (present.length === 0) return;
      await execFileAsync(
        "firebase",
        [
          "functions:delete",
          ...present,
          `--region=${REGION}`,
          `--project=${project}`,
          "--non-interactive",
          "--force",
        ],
        { cwd: buildDir, timeout: 1_200_000, maxBuffer: 16 * 1024 * 1024 },
      );
    });
    await step("functions read back", async () => {
      const left = (await listFunctions()).filter((fn) => NAMES.includes(fn));
      if (left.length) throw new Error(`functions remain: ${left.join(", ")}`);
    });
    await step("blocking config", async () => {
      const triggers = (await blockingConfig()).triggers ?? {};
      if (Object.keys(triggers).length === 0) return;
      const { status } = await call("PATCH", `${configUrl}?updateMask=blockingFunctions`, {
        blockingFunctions: {},
      });
      if (status !== 200) throw new Error(`config clear: HTTP ${status}`);
      const after = (await blockingConfig()).triggers ?? {};
      if (Object.keys(after).length) throw new Error("blocking triggers remain");
    });
    const images = await step("images", deleteArtifacts);
    await step("images read back", async () => {
      if ((await fixtureArtifacts()) > 0) throw new Error("fixture images remain");
    });
    const sources = await step("sources", deleteSources);
    await step("sources read back", async () => {
      for (const bucket of buckets)
        if ((await bucketObjects(bucket)).length) throw new Error(`sources remain in ${bucket}`);
    });
    if (problems.length) throw Object.assign(new Error(problems.join("; ")), { fatal: true });
    return { images: images ?? 0, sources: sources ?? 0 };
  }

  return {
    preflight,
    deploy,
    verifyRegistered,
    invokers,
    remove,
    requests: () => requests,
    buildDir: (root) => join(root, "function-build"),
  };
}
