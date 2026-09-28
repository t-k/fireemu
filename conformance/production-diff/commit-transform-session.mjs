// Invoked only as the child of the owned `fireemu exec`, exactly like local-session.mjs, but for
// the fs.commit-transform-limits.saved-031c74bfe.v1 case. No caller-supplied endpoint option.
//
// Unlike local-session.mjs, this case has no upstream "legacy" Node recorder to wrap: the
// compiled plan (commit-transform-plan.mjs) already IS the exact, deterministic, credential-free
// request sequence, ported from transform_compiler.compile_plan(). This script executes that
// sequence directly against the owned local daemon, records the raw typed responses, and defers
// all judgement about whether those responses match the documented production outcome to
// compareCommitTransform() in commit-transform.mjs, run later by pilot.mjs.
import { promises as fs } from "node:fs";
import { join } from "node:path";
import { selectCase } from "./registry.mjs";
import { requireThat, sha256, digestJson, safeCode } from "./core.mjs";
import { compilePlan } from "./commit-transform-plan.mjs";
import { publishJson } from "./io.mjs";
import { localOrigin, assertUrl, installNetworkGuard, boundedText } from "./network.mjs";

const directory = process.env.PILOT_RUN_DIR;
requireThat(typeof directory === "string", "missing-run-directory");
const caseId = process.env.PILOT_CASE_ID;
requireThat(typeof caseId === "string", "missing-case-id");
const entry = selectCase(caseId);

const plan = JSON.parse(await fs.readFile(join(directory, "program.json")));
requireThat(
  plan.planDigest === entry.programDigest &&
    JSON.stringify(plan) ===
      JSON.stringify(compilePlan(entry.project, entry.database, entry.nonce)),
  "compiled-plan-drift",
);

const origin = localOrigin(process.env.FIRESTORE_EMULATOR_HOST);
requireThat(process.env.GOOGLE_CLOUD_PROJECT === entry.project, "wrong-child-project");

const guardedFetch = installNetworkGuard(origin);
// This is a local recorder limit, not a claim about production latency. One signal
// covers the connection, headers and entire body; the parent still bounds the whole run.
const REQUEST_TIMEOUT_MS = 10000;
async function requestText(url, init) {
  const signal = AbortSignal.timeout(REQUEST_TIMEOUT_MS);
  try {
    const response = await guardedFetch(url, { ...init, signal });
    const text = await boundedText(response, undefined, signal);
    return { response, text };
  } catch (error) {
    if (signal.aborted) throw new Error("request-timeout");
    throw error;
  }
}

const labelOf = (resource) => {
  for (const [label, doc] of Object.entries(plan.documents))
    if (doc.resource === resource) return label;
  return null;
};
const stepId = (op) => `${op.kind}:${labelOf(op.resource ?? op.resources?.[0])}`;
const ops = [...plan.observation, ...plan.recovery];
requireThat(
  JSON.stringify(ops.map(stepId)) === JSON.stringify(entry.stepIds),
  "step-id-sequence-drift",
);

const rows = [];
let totalBytes = 0;
async function execute(op, index, priorRow) {
  let path = op.path; // op.path is already fully qualified with the leading "/v1/...".
  if (op.kind === "cleanup-conditional-delete") {
    requireThat(
      priorRow?.status === 200 && typeof priorRow.body?.updateTime === "string",
      "delete-not-bound-to-ownership-read",
    );
    path = path + "?currentDocument.updateTime=" + encodeURIComponent(priorRow.body.updateTime);
  }
  const url = origin + path;
  assertUrl(url, origin);
  const init = {
    method: op.method,
    headers: { authorization: "Bearer owner", "content-type": "application/json" },
    redirect: "error",
  };
  if (op.body !== null && op.body !== undefined) init.body = JSON.stringify(op.body);
  const { response, text } = await requestText(url, init);
  totalBytes += Buffer.byteLength(text);
  requireThat(totalBytes <= 8 * 1024 * 1024, "response-budget");
  let body = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    throw new Error("non-json-response");
  }
  const row = {
    index,
    stepId: stepId(op),
    kind: op.kind,
    resource: op.resource ?? op.resources?.[0] ?? null,
    method: op.method,
    path,
    status: response.status,
    bodySha256: sha256(text),
    body,
  };
  rows.push(row);
  return row;
}

let failure = null;
let cleanup = { state: "unconfirmed", absent: [], requests: 0 };
try {
  for (let i = 0; i < ops.length; i++) await execute(ops[i], i, i > 0 ? rows[i - 1] : null);
  requireThat(rows.length === ops.length, "recorder-incomplete");
} catch (error) {
  failure = safeCode(error);
} finally {
  try {
    for (const resource of entry.ownedDocuments) {
      cleanup.requests++;
      const { response, text } = await requestText(origin + "/v1/" + resource, {
        headers: { authorization: "Bearer owner" },
      });
      const body = text ? JSON.parse(text) : null;
      requireThat(
        response.status === 404 && body?.error?.status === "NOT_FOUND",
        "cleanup-absence-unconfirmed",
      );
      cleanup.absent.push(resource);
    }
    cleanup.state = "confirmed";
  } catch (error) {
    cleanup.failure = safeCode(error);
  }
  const local = { schema: "fireemu-commit-transform-local-rows-v1", caseId: entry.id, rows };
  const localBytes = JSON.stringify(local);
  await fs.writeFile(join(directory, "local.json"), localBytes);
  await publishJson(join(directory, "session-result.json"), {
    schema: "fireemu-production-diff-session-v1",
    caseId: entry.id,
    programDigest: digestJson(plan),
    localSha256: sha256(localBytes),
    completed: !failure && rows.length === ops.length,
    failure,
    cleanup,
    requests: rows.map((r) => ({
      phase: r.stepId,
      method: r.method,
      path: r.path,
      status: r.status,
    })),
    requestCount: rows.length,
    totalResponseBytes: totalBytes,
    endpoint: origin,
    productionRequests: 0,
  });
}
if (failure || cleanup.state !== "confirmed") process.exitCode = 2;
