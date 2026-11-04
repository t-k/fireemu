// The read-only read-back of a finished (or interrupted) run: the function, its images, the lists, the account, the account
// count and the Identity Platform configuration, with the same allowlist as the recording and every mutation refused. It
// sends nothing but reads. It is the separate, later read (at least ten minutes after the run's last request) that an unknown
// answer needs before a close row. It judges only absence (a direct read that answers 404 NOT_FOUND, an account lookup with no
// user) and equality with the baseline the run recorded (the blocking section empty, the whole configuration's digest the
// same, the account count the same). It never settles an unknown CREATE: the command that runs it reads the run's own result
// for the unconfirmed creates and refuses to close while any exist.
import { AuthStop, createCapture, readable } from "../../scheduled-delivery/capture.mjs";
import { isGone, summarize } from "./deploy.mjs";
import { createGuard, ownPackages } from "./guard.mjs";
import { CONFIG_URL, PROJECT, REGION, functionName, packageIds } from "./plan.mjs";
import { configDigest, absent, emptyBlocking } from "./run.mjs";
import { countAccounts, lookupAccount } from "./script.mjs";

export const READBACK_MAX_REQUESTS = 40;
export const SETTLE_MS = 10 * 60 * 1000;

const GCF = "https://cloudfunctions.googleapis.com/v2/";
const REGISTRY = `https://artifactregistry.googleapis.com/v1/projects/${PROJECT}/locations/${REGION}/repositories/gcf-artifacts/packages`;

/** The read-back's allowlist: the recording's, narrowed to requests that are not mutations. */
export function readbackAllow(runId, projectNumber, localId = null) {
  const guard = createGuard(runId, projectNumber);
  guard.adopt(localId);
  return { allow: (spec) => guard.allow(spec) && !guard.isMutation(spec), guard };
}

export async function readbackRun({
  runId,
  projectNumber,
  localId = null,
  accountsBefore = null,
  configBeforeDigest = null,
  accessToken,
  save,
  send,
  clock = Date.now,
}) {
  const { allow } = readbackAllow(runId, projectNumber, localId);
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
  const expectedNames = 3 + (localId === null ? 0 : 1);
  const namesGone =
    Object.keys(out.names).length === expectedNames &&
    Object.values(out.names).every((n) => n.absent === true);
  const listsGone =
    out.lists.functionAndService === true &&
    Array.isArray(out.lists.packages) &&
    out.lists.packages.length === 0;
  const configSame = out.config?.blockingEmpty === true && out.config?.digestMatches === true;
  const accountsSame = out.accounts.before !== null && out.accounts.after === out.accounts.before;
  out.allAbsent =
    namesGone &&
    listsGone &&
    configSame &&
    accountsSame &&
    stop === null &&
    known.unknown === 0 &&
    out.incompleteReads.length === 0;
  return out;
}
