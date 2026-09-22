// Invoked only as the child of the owned `fireemu exec`. No caller-supplied endpoint option.
import { promises as fs } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { CASE, selectCase } from "./registry.mjs";
import {
  requireThat,
  equal,
  sha256,
  digestJson,
  blobSha,
  safeCode,
  validateProgram,
  resolveRecordedValue,
  resolveRecordedPath,
  expectedCleanupDocuments,
} from "./core.mjs";
import { publishJson, readSource } from "./io.mjs";
import { localOrigin, assertUrl, installNetworkGuard, boundedText } from "./network.mjs";

const directory = process.env.PILOT_RUN_DIR;
requireThat(typeof directory === "string", "missing-run-directory");
const entry = selectCase(process.env.PILOT_CASE_ID ?? CASE.id);
requireThat(
  entry.adapter === "batch-write" && entry.sessionScript === "local-session.mjs",
  "wrong-local-session-adapter",
);
const legacyDir = join(directory, "legacy");
const program = validateProgram(
  JSON.parse(await fs.readFile(join(directory, "program.json"))),
  entry,
);
const origin = localOrigin(process.env.FIRESTORE_EMULATOR_HOST);
requireThat(process.env.GOOGLE_CLOUD_PROJECT === entry.project, "wrong-child-project");
for (const [name, hash] of [
  ["session.mjs", entry.sessionBlob],
  ["credentials.mjs", entry.credentialsBlob],
])
  requireThat(blobSha(await readSource(legacyDir, name)) === hash, "staged-source-pin-mismatch");

// Overwrite *all* legacy selectors. Ambient production/proxy/ADC settings are not inherited.
for (const key of Object.keys(process.env))
  if (key.startsWith("FIRESTORE_PROBE_")) delete process.env[key];
Object.assign(process.env, {
  FIRESTORE_PROBE_HOST: new URL(origin).host,
  FIRESTORE_PROBE_SCHEME: "http",
  FIRESTORE_PROBE_TARGET: "local",
  FIRESTORE_PROBE_TOKEN: "owner",
  FIRESTORE_PROBE_PROJECT: entry.project,
  FIRESTORE_PROBE_RECORD_PROJECT: entry.project,
  FIRESTORE_PROBE_IN: join(directory, "programs.json"),
  FIRESTORE_PROBE_OUT: join(directory, "local.json"),
  FIRESTORE_PROBE_TIMEOUT_MS: "10000",
});
const guardedFetch = installNetworkGuard(origin);
const replace = (value) => JSON.parse(JSON.stringify(value).replaceAll("PROJECT", entry.project));
const clearPath = `/emulator/v1/projects/${entry.project}/databases/(default)/documents`;
const expected = [
  { phase: "reset", method: "DELETE", path: clearPath },
  ...program.seed.map((seed) => ({
    phase: "seed",
    method: "PATCH",
    path: seed.path.replaceAll("PROJECT", entry.project),
    body: { fields: replace(seed.fields) },
  })),
  ...program.steps.map((step) => ({
    phase: step.id,
    method: step.method,
    path: step.path.replaceAll("PROJECT", entry.project),
    ...(step.body === undefined ? {} : { body: replace(step.body) }),
  })),
];
const requests = [];
const rawReplies = new Map();
let index = 0,
  totalBytes = 0;
globalThis.fetch = async (url, init = {}) => {
  const parsed = assertUrl(url, origin);
  const op = expected[index];
  const resolvedPath = op ? resolveRecordedPath(op.path, rawReplies) : null;
  const expectedUrl = op ? assertUrl(origin + resolvedPath, origin) : null;
  const path = expectedUrl ? expectedUrl.pathname + expectedUrl.search : null;
  requireThat(
    op && op.method === (init.method ?? "GET") && path === parsed.pathname + parsed.search,
    "unexpected-recorder-operation",
  );
  const body = init.body === undefined ? undefined : JSON.parse(init.body);
  const expectedBody = resolveRecordedValue(op.body, rawReplies);
  requireThat(
    (expectedBody === undefined && body === undefined) ||
      (expectedBody !== undefined && body !== undefined && equal(expectedBody, body)),
    "recorder-input-drift",
  );
  const authorization = new Headers(init.headers).get("authorization");
  requireThat(
    authorization === (op.phase === "reset" ? null : "Bearer owner"),
    "recorder-principal-drift",
  );
  index++;
  const row = {
    phase: op.phase,
    method: op.method,
    path,
    bodySha256: init.body === undefined ? null : sha256(init.body),
    status: null,
  };
  requests.push(row);
  const response = await guardedFetch(url, { ...init, redirect: "error" });
  const text = await boundedText(response);
  totalBytes += Buffer.byteLength(text);
  requireThat(totalBytes <= 8 * 1024 * 1024, "response-budget");
  row.status = response.status;
  row.responseSha256 = sha256(text);
  // Preserve only the declared finite witness set, before <now> normalization.
  // No additional HTTP request is made and ordinary cases retain no new bodies.
  if (entry.rawTimestampResponseSteps?.includes(op.phase)) row.rawResponseText = text;
  if (op.phase === "reset" || op.phase === "seed") requireThat(response.ok, "setup-not-confirmed");
  // Store only fully read replies, before the recorder normalizes server times.
  if (op.phase !== "reset" && op.phase !== "seed") {
    let raw = null;
    try { raw = JSON.parse(text); } catch { /* The pinned recorder emits non-json. */ }
    rawReplies.set(op.phase, raw);
    if (Object.hasOwn(entry.generatedDocumentSteps ?? {}, op.phase) && response.ok) {
      row.generatedDocument = raw?.name;
      row.generatedResponseText = text;
      expectedCleanupDocuments(entry, requests); // Reject foreign/malformed names before using them.
    }
  }
  // The legacy recorder consumes the same response bytes and performs its own normalization.
  return new Response(response.status === 204 ? null : text, {
    status: response.status,
    headers: response.headers,
  });
};

let failure = null;
let cleanup = { state: "unconfirmed", absent: [], requests: 0 };
try {
  await import(pathToFileURL(join(legacyDir, "session.mjs")).href);
  requireThat(index === expected.length, "recorder-incomplete");
} catch (error) {
  failure = safeCode(error);
} finally {
  try {
    // Entire DB reset is safe here only because the parent owns this throwaway daemon.
    cleanup.requests++;
    const response = await guardedFetch(origin + clearPath, {
      method: "DELETE",
      signal: AbortSignal.timeout(10000),
    });
    await boundedText(response);
    requireThat(response.ok, "cleanup-reset-failed");
    for (const path of expectedCleanupDocuments(entry, requests)) {
      cleanup.requests++;
      const r = await guardedFetch(
        `${origin}/v1/projects/${entry.project}/databases/(default)/documents/${path}`,
        { headers: { authorization: "Bearer owner" }, signal: AbortSignal.timeout(10000) },
      );
      const body = JSON.parse(await boundedText(r));
      requireThat(
        r.status === 404 && body?.error?.status === "NOT_FOUND",
        "cleanup-absence-unconfirmed",
      );
      cleanup.absent.push(path);
    }
    cleanup.state = "confirmed";
  } catch (error) {
    cleanup.failure = safeCode(error);
  }
  const local = await fs.readFile(join(directory, "local.json")).catch(() => null);
  await publishJson(join(directory, "session-result.json"), {
    schema: "fireemu-production-diff-session-v1",
    caseId: entry.id,
    programDigest: digestJson(program),
    localSha256: local ? sha256(local) : null,
    completed: !failure && index === expected.length,
    failure,
    cleanup,
    requests,
    requestCount: index,
    totalResponseBytes: totalBytes,
    endpoint: origin,
    productionRequests: 0,
  });
}
if (failure || cleanup.state !== "confirmed") process.exitCode = 2;
