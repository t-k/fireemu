// The read-only read-back of a finished (or interrupted) run: the function, its images, the lists, the account, the account
// count and the Identity Platform configuration, with the same allowlist as the recording and every mutation refused. It
// sends nothing but reads. It is the separate, later read (at least ten minutes after the run's last request) that an unknown
// answer needs before a close row. It judges only absence (a direct read that answers 404 NOT_FOUND, an account lookup with no
// user) and equality with the baseline the run recorded (the blocking section empty, the whole configuration's digest the
// same, the account count the same). It never settles an unknown CREATE: the command that runs it reads the run's own result
// for the unconfirmed creates and refuses to close while any exist.
import { AuthStop, createCapture, readable } from "../../scheduled-delivery/capture.mjs";
import { iamUnexpected, inventoryDifferences, isGone, summarize } from "./deploy.mjs";
import { createGuard, ownPackages } from "./guard.mjs";
import { CONFIG_URL, PROJECT, REGION, functionName, packageIds, sourceBuckets } from "./plan.mjs";
import { absent, configDigest, emptyBlocking, iamKeyChanges, iamKeys } from "./run.mjs";
import { countAccounts, lookupAccount } from "./script.mjs";

export const READBACK_MAX_REQUESTS = 60;
export const SETTLE_MS = 10 * 60 * 1000;

const GCF = "https://cloudfunctions.googleapis.com/v2/";
const REGISTRY = `https://artifactregistry.googleapis.com/v1/projects/${PROJECT}/locations/${REGION}/repositories/gcf-artifacts/packages`;

/** The read-back's allowlist: the recording's, narrowed to requests that are not mutations. */
export function readbackAllow(runId, projectNumber, localId = null, uploadObjects = []) {
  const guard = createGuard(runId, projectNumber);
  guard.adopt(localId);
  for (const item of uploadObjectEntries(uploadObjects)) guard.adoptObject(item.bucket, item.name);
  return { allow: (spec) => guard.allow(spec) && !guard.isMutation(spec), guard };
}

/** The source objects the run deleted, as `{ bucket, name }` entries from its result, kept only when they are well formed. */
export const uploadObjectEntries = (list) =>
  (Array.isArray(list) ? list : []).filter(
    (item) => typeof item?.bucket === "string" && typeof item?.name === "string",
  );

export async function readbackRun({
  runId,
  projectNumber,
  localId = null,
  uploadObjects = [],
  accountsBefore = null,
  configBeforeDigest = null,
  baseline = null,
  carried = [],
  accessToken,
  save,
  send,
  clock = Date.now,
}) {
  const { allow } = readbackAllow(runId, projectNumber, localId, uploadObjects);
  const { capture, counts, authStop } = createCapture({
    accessToken,
    save,
    send,
    clock,
    maxRequests: READBACK_MAX_REQUESTS,
    maxRequestCap: READBACK_MAX_REQUESTS,
    allow,
    quotaProject: PROJECT,
    timeoutFor: () => 15_000,
  });
  const out = {
    runId,
    names: {},
    lists: {},
    incompleteReads: [],
    authStop: null,
    config: null,
    accounts: { before: accountsBefore, after: null },
  };
  const list = async (id, url, key) => {
    const items = [];
    let token = "";
    for (let page = 0; page < 5; page++) {
      const answer = await capture({
        id: id + (page ? "-page-" + (page + 1) : ""),
        method: "GET",
        url:
          url +
          (token ? (url.includes("?") ? "&" : "?") + "pageToken=" + encodeURIComponent(token) : ""),
      });
      if (!(answer?.status === 200 && readable(answer))) {
        out.incompleteReads.push({ id, status: answer?.status ?? null });
        return null;
      }
      items.push(...(answer.json[key] ?? []));
      token = answer.json.nextPageToken ?? "";
      if (!token) return { [key]: items };
    }
    out.incompleteReads.push({ id, status: "more-than-five-pages" });
    return null;
  };
  try {
    for (const [label, url] of [
      ["function", GCF + functionName()],
      ...packageIds().map((id) => ["package-" + id, REGISTRY + "/" + id]),
      ...uploadObjectEntries(uploadObjects).map((item, index) => [
        "upload-object-" + (index + 1),
        `https://storage.googleapis.com/storage/v1/b/${item.bucket}/o/${encodeURIComponent(item.name)}`,
      ]),
    ]) {
      const answer = await capture({ id: "readback-" + label, method: "GET", url });
      out.names[label] = { status: answer?.status ?? null, absent: absent(answer) };
    }
    if (localId !== null) {
      const answer = await capture({ id: "readback-account", ...lookupAccount(localId) });
      out.names.account = {
        status: answer?.status ?? null,
        absent:
          answer?.status === 200 && readable(answer) && (answer.json.users ?? []).length === 0,
      };
    }
    const found = {
      v2: await list(
        "list-functions-v2",
        GCF + "projects/" + PROJECT + "/locations/-/functions",
        "functions",
      ),
      run: await list(
        "list-run-services",
        "https://run.googleapis.com/v2/projects/" + PROJECT + "/locations/-/services",
        "services",
      ),
    };
    out.lists.functionAndService = Boolean(found.v2 && found.run) && isGone(summarize(found));
    const packages = await list("list-packages", REGISTRY + "?pageSize=100", "packages");
    out.lists.packages = packages
      ? packages.packages
          .map((item) => String(item.name).split("/").at(-1))
          .filter((id) => ownPackages().includes(id))
      : null;
    // The inventory the run started from, compared by identity with a fresh one (the closure rule of the recording).
    const triggers = await list(
      "list-triggers",
      `https://eventarc.googleapis.com/v1/projects/${PROJECT}/locations/-/triggers`,
      "triggers",
    );
    const subs = await list(
      "list-subscriptions",
      `https://pubsub.googleapis.com/v1/projects/${PROJECT}/subscriptions?pageSize=1000`,
      "subscriptions",
    );
    const topics = await list(
      "list-topics",
      `https://pubsub.googleapis.com/v1/projects/${PROJECT}/topics?pageSize=1000`,
      "topics",
    );
    const services = await list(
      "list-services",
      `https://serviceusage.googleapis.com/v1/projects/${projectNumber}/services?filter=state:ENABLED&pageSize=200`,
      "services",
    );
    const iamNow = await capture({
      id: "read-iam",
      method: "POST",
      url: `https://cloudresourcemanager.googleapis.com/v1/projects/${PROJECT}:getIamPolicy`,
      json: {},
    });
    const bucketNames = {};
    for (const [index, name] of sourceBuckets(projectNumber).entries()) {
      const label = index === 0 ? "uploads" : "sources";
      const listed = await list(
        "list-" + label,
        `https://storage.googleapis.com/storage/v1/b/${name}/o?maxResults=1000`,
        "items",
      );
      bucketNames[label] = listed ? listed.items.map((item) => item.name).toSorted() : null;
    }
    const sorted = (listed, key) =>
      listed ? listed[key].map((item) => item.name).toSorted() : null;
    if (baseline) {
      const compared = inventoryDifferences({
        before: baseline,
        after: {
          triggers: sorted(triggers, "triggers"),
          subscriptions: sorted(subs, "subscriptions"),
          topics: sorted(topics, "topics"),
          packages: sorted(packages, "packages"),
          services: services ? services.services.map((svc) => svc.config?.name).toSorted() : null,
          sourceObjects: bucketNames,
        },
        kinds: ["triggers", "subscriptions", "topics", "packages"],
      });
      // Project IAM may only have gained service-account members since the preflight.
      const iam = iamUnexpected(iamKeyChanges(baseline.iam, iamKeys(iamNow)));
      out.inventory = {
        baseline: true,
        complete: compared.complete && iam.complete,
        missing: [...compared.missing, ...(iam.complete ? [] : ["iam"])],
        differences: [
          ...compared.differences,
          ...iam.unexpected.map((what) => ({ kind: "iam", what })),
        ],
      };
    } else
      out.inventory = { baseline: false, complete: false, missing: ["baseline"], differences: [] };
    out.carried = carried;
    const config = await capture({ id: "read-config", method: "GET", url: CONFIG_URL });
    if (config?.status === 200 && readable(config)) {
      out.config = {
        blockingEmpty: emptyBlocking(config.json),
        digestMatches:
          configBeforeDigest === null ? null : configDigest(config.json) === configBeforeDigest,
      };
    } else {
      out.config = null;
      out.incompleteReads.push({ id: "read-config", status: config?.status ?? null });
    }
    const count = await capture({ id: "read-accounts", ...countAccounts() });
    out.accounts = {
      before: accountsBefore,
      after: count?.status === 200 && readable(count) ? Number(count.json.recordsCount ?? 0) : null,
    };
  } catch (error) {
    if (!(error instanceof AuthStop)) throw error;
  }
  const stop = authStop();
  const known = counts();
  out.attempted = known.attempted;
  out.unknown = known.unknown;
  if (stop) out.authStop = stop;
  const expectedNames = 3 + (localId === null ? 0 : 1) + uploadObjectEntries(uploadObjects).length;
  const namesGone =
    Object.keys(out.names).length === expectedNames &&
    Object.values(out.names).every((n) => n.absent === true);
  const listsGone =
    out.lists.functionAndService === true &&
    Array.isArray(out.lists.packages) &&
    out.lists.packages.length === 0;
  const configSame = out.config?.blockingEmpty === true && out.config?.digestMatches === true;
  const accountsSame = out.accounts.before !== null && out.accounts.after === out.accounts.before;
  const inventoryClean =
    out.inventory?.baseline === true &&
    out.inventory.complete === true &&
    out.inventory.differences.length === 0;
  // Every obligation the run left open (an unconfirmed upload, an unexplained object, a difference or an unreadable part of
  // its inventory, a configuration it could not restore) is carried: a read-back that finds nothing there cannot settle it.
  const carriedClear = Array.isArray(carried) && carried.length === 0;
  out.allAbsent =
    carriedClear &&
    namesGone &&
    listsGone &&
    inventoryClean &&
    configSame &&
    accountsSame &&
    stop === null &&
    known.unknown === 0 &&
    out.incompleteReads.length === 0;
  return out;
}
