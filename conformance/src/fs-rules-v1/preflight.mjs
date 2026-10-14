// The read-only preflight of an FS-3 recording: what the sandbox holds before anything is created.
// Every call is a GET or a read-only query on the sandbox project; a refused preflight leaves
// nothing behind. The answers are read in the shapes the FS-RULES preflight already reads from
// production (release and ruleset names, database names, `recordsCount`, the Admin v2 config).

import { PRODUCTION, SANDBOX_PROJECT } from "../fs-rules/harness.mjs";
import { openRuns, otherLanesRecently, preflightProblems } from "./judge.mjs";

/** Owner calls of the preflight; nothing here writes. */
async function ownerFetch(fetchImpl, target, method, url, body) {
  const init = {
    method,
    headers: {
      authorization: `Bearer ${target.adminToken}`,
      "x-goog-user-project": SANDBOX_PROJECT,
    },
  };
  if (body) {
    init.headers["content-type"] = "application/json";
    init.body = JSON.stringify(body);
  }
  const response = await fetchImpl(url, init);
  return { status: response.status, json: await response.json().catch(() => null) };
}

export async function preflight(
  target,
  ledgerText = "",
  { now = Date.now(), fetchImpl = fetch } = {},
) {
  const rules = `${PRODUCTION.rules}/v1/projects/${SANDBOX_PROJECT}`;
  const itk = PRODUCTION.itk;
  const firestore = `${PRODUCTION.firestore}/v1/projects/${SANDBOX_PROJECT}`;
  const read = (method, url, body) => ownerFetch(fetchImpl, target, method, url, body);
  const reads = {
    releases: await read("GET", `${rules}/releases`),
    rulesets: await read("GET", `${rules}/rulesets`),
    databases: await read("GET", `${firestore}/databases`),
    documents: await read("POST", `${firestore}/databases/(default)/documents:runQuery`, {
      structuredQuery: { from: [{ allDescendants: true }], limit: 1 },
    }),
    accounts: await read("POST", `${itk}/v1/projects/${SANDBOX_PROJECT}/accounts:query`, {
      returnUserInfo: false,
    }),
    config: await read("GET", `${itk}/admin/v2/projects/${SANDBOX_PROJECT}/config`),
  };
  const report = {
    failedReads: Object.entries(reads)
      .filter(([, { status }]) => status !== 200)
      .map(([name, { status }]) => `${name} (HTTP ${status})`),
    projectAccounts: Number(reads.accounts.json?.recordsCount ?? -1),
    anonymousEnabled: reads.config.json?.signIn?.anonymous?.enabled === true,
    rulesets: (reads.rulesets.json?.rulesets ?? []).length,
    otherLanesRecently: otherLanesRecently(ledgerText, now),
    openRuns: openRuns(ledgerText, now),
    releases: (reads.releases.json?.releases ?? []).map(({ name }) => name.split("/releases/")[1]),
    databases: (reads.databases.json?.databases ?? []).map(({ name }) => name.split("/").at(-1)),
    defaultHasDocuments:
      Array.isArray(reads.documents.json) && reads.documents.json.some((e) => e.document),
  };
  return { report, problems: preflightProblems(report) };
}
