// Capture owned bootstrap shapes; production execution belongs only to the coordinator.
import { createHash } from "node:crypto";
import { readFileSync, existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { createCaptureDirectory, durableFile } from "./capture.mjs";
import { responseBytes } from "./preflight.mjs";
import { assertWriteAuthority } from "./authority-check.mjs";
const PROJECT = "fireemu-oracle-idp";
const ROOT = `https://pubsub.googleapis.com/v1/projects/${PROJECT}`;
export function shapeRequests(runId) {
  if (!/^[a-f0-9]{32}$/.test(runId)) throw new Error("fresh run id required");
  const prefix = `fireemu-lane7-${runId}`;
  const topic = `projects/${PROJECT}/topics/${prefix}-topic`;
  const subscription = `projects/${PROJECT}/subscriptions/${prefix}-sub`;
  const make = (id, method, resource, body) => ({
    id,
    method,
    url: resource.startsWith("https:") ? resource : `https://pubsub.googleapis.com/v1/${resource}`,
    ...(body ? { requestBody: JSON.stringify(body) } : {}),
  });
  return [
    make("topics-list-before", "GET", `${ROOT}/topics?pageSize=1000`),
    make("subscriptions-list-before", "GET", `${ROOT}/subscriptions?pageSize=1000`),
    make("topic-missing-get", "GET", `projects/${PROJECT}/topics/${prefix}-never-topic`),
    make(
      "subscription-missing-get",
      "GET",
      `projects/${PROJECT}/subscriptions/${prefix}-never-sub`,
    ),
    make("topic-before-get", "GET", topic),
    make("subscription-before-get", "GET", subscription),
    make("topic-create", "PUT", topic, {
      name: topic,
      labels: { fireemu_owner: "lane7", fireemu_run: runId },
    }),
    make("topic-get", "GET", topic),
    make("subscription-create", "PUT", subscription, {
      name: subscription,
      topic,
      ackDeadlineSeconds: 60,
    }),
    make("subscription-get", "GET", subscription),
    make("subscription-delete", "DELETE", subscription),
    make("subscription-after-get", "GET", subscription),
    make("topic-delete", "DELETE", topic),
    make("topic-after-get", "GET", topic),
    make("topics-list-after", "GET", `${ROOT}/topics?pageSize=1000`),
    make("subscriptions-list-after", "GET", `${ROOT}/subscriptions?pageSize=1000`),
  ];
}
const nameOf = (request) => new URL(request.url).pathname.slice("/v1/".length);
function canonicalBody(body, name) {
  const leaf = name.split("/").at(-1);
  function map(value) {
    if (typeof value === "string")
      return value.replaceAll(name, "<resource>").replaceAll(leaf, "<resource>");
    if (Array.isArray(value)) return value.map(map);
    if (value && typeof value === "object")
      return Object.fromEntries(
        Object.keys(value)
          .toSorted()
          .map((key) => [key, map(value[key])]),
      );
    return value;
  }
  return JSON.stringify(map(JSON.parse(body)));
}
function sameAbsence(row, request, missing, missingRequest) {
  return (
    row?.status === 404 &&
    missing?.status === 404 &&
    row.contentType === missing.contentType &&
    canonicalBody(row.body, nameOf(request)) === canonicalBody(missing.body, nameOf(missingRequest))
  );
}
function recordedEmpty(row, baseline) {
  return (
    row?.status === baseline.status &&
    row.status === 200 &&
    JSON.stringify(JSON.parse(row.body)) === JSON.stringify(JSON.parse(baseline.body)) &&
    JSON.stringify(JSON.parse(baseline.body)) === "{}"
  );
}
export async function captureShape({
  directory,
  runId,
  accessToken,
  baseline,
  send = (request) => fetch(request.url, request),
  clock = Date.now,
  guard = async () => {},
}) {
  if (typeof accessToken !== "string" || !accessToken || /[\r\n]/.test(accessToken))
    throw new Error("coordinator credential required");
  const requests = shapeRequests(runId),
    byId = new Map(requests.map((r) => [r.id, r])),
    responses = new Map(),
    intents = new Set();
  await createCaptureDirectory(directory);
  let attempted = 0,
    completed = 0,
    mutationAttempts = 0,
    incomplete = false,
    collision = false,
    baselineKnown = false;
  const start = clock();
  async function call(id) {
    await guard();
    const request = byId.get(id);
    if (attempted >= 16 || clock() - start >= 600000) throw new Error("shape bound exceeded");
    const mutation = request.method !== "GET";
    await durableFile(
      join(directory, "requests.jsonl"),
      {
        ...request,
        state: "before-send",
        recordedAt: new Date().toISOString(),
        ...(request.method === "PUT" ? { ownership: "fresh-absent-before-create" } : {}),
      },
      "a",
    );
    attempted++;
    if (mutation) mutationAttempts++;
    if (request.method === "PUT") intents.add(id.split("-")[0]);
    const response = await send({
      ...request,
      body: request.requestBody,
      headers: {
        authorization: `Bearer ${accessToken}`,
        "x-goog-user-project": PROJECT,
        ...(request.requestBody ? { "content-type": "application/json" } : {}),
      },
      redirect: "manual",
      signal: AbortSignal.timeout(30000),
    });
    if (request.method === "PUT" && response.status === 409) collision = true;
    await durableFile(
      join(directory, "requests.jsonl"),
      {
        id,
        state: "response-headers",
        status: response.status,
        contentType: response.headers.get("content-type"),
        recordedAt: new Date().toISOString(),
      },
      "a",
    );
    const bytes = await responseBytes(response);
    const row = {
      ...request,
      status: response.status,
      contentType: response.headers.get("content-type"),
      body: bytes.toString("utf8"),
      bodyBase64: bytes.toString("base64"),
      bodyBytes: bytes.length,
      bodySha256: createHash("sha256").update(bytes).digest("hex"),
      recordedAt: new Date().toISOString(),
    };
    await durableFile(join(directory, `${id}.json`), row);
    await durableFile(
      join(directory, "requests.jsonl"),
      { id, state: "response-persisted", status: row.status, recordedAt: row.recordedAt },
      "a",
    );
    completed++;
    responses.set(id, row);
    if (row.status >= 300 && row.status < 400) throw new Error("redirect refused");
    if (request.method === "PUT" && row.status === 409) {
      collision = true;
      throw new Error("run name collision");
    }
    return row;
  }
  try {
    for (const id of ["topics-list-before", "subscriptions-list-before"]) {
      const row = await call(id);
      const kind = id.split("-")[0];
      if (!recordedEmpty(row, baseline[kind])) throw new Error("recorded baseline differs");
    }
    baselineKnown = true;
    for (const kind of ["topic", "subscription"]) {
      const missing = await call(`${kind}-missing-get`);
      if (missing.status !== 404) throw new Error("missing resource did not establish absence");
    }
    for (const kind of ["topic", "subscription"]) {
      const row = await call(`${kind}-before-get`);
      if (
        !sameAbsence(
          row,
          byId.get(`${kind}-before-get`),
          responses.get(`${kind}-missing-get`),
          byId.get(`${kind}-missing-get`),
        )
      )
        throw new Error("fresh resource absence not proven");
    }
    for (const id of ["topic-create", "topic-get", "subscription-create", "subscription-get"]) {
      const row = await call(id);
      if (id.endsWith("-create") && (row.status < 200 || row.status >= 300))
        throw new Error("creation was not confirmed");
    }
  } catch {
    incomplete = true;
  }
  let clean = intents.size === 0 && !collision && baselineKnown;
  if (intents.size && !collision) {
    let proof = true;
    for (const kind of ["subscription", "topic"])
      if (intents.has(kind)) {
        try {
          await call(`${kind}-delete`);
        } catch {
          incomplete = true;
        }
        try {
          const row = await call(`${kind}-after-get`);
          if (
            !sameAbsence(
              row,
              byId.get(`${kind}-after-get`),
              responses.get(`${kind}-missing-get`),
              byId.get(`${kind}-missing-get`),
            )
          )
            proof = false;
        } catch {
          incomplete = true;
          proof = false;
        }
      }
    for (const kind of ["topics", "subscriptions"]) {
      try {
        if (!recordedEmpty(await call(`${kind}-list-after`), baseline[kind])) proof = false;
      } catch {
        incomplete = true;
        proof = false;
      }
    }
    clean = proof;
  }
  const summary = {
    outcome: !clean
      ? "needs-recovery"
      : incomplete
        ? "exploration-inconclusive"
        : "exploration-recorded",
    sandboxAtBaseline: clean,
    attempted,
    completed,
    unknown: attempted - completed,
    mutationAttempts,
    runId,
  };
  await durableFile(join(directory, "summary.json"), summary);
  return summary;
}
if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  try {
    const input = JSON.parse(readFileSync(0, "utf8"));
    const guard = async () => {
      if (existsSync(input.quietPath)) throw new Error("quiet window active");
      assertWriteAuthority({
        ...input.authority,
        ledgerText: readFileSync(input.ownerLedgerPath, "utf8"),
      });
    };
    const result = await captureShape({ ...input, directory: process.argv[2], guard });
    process.stdout.write(JSON.stringify(result) + "\n");
    if (result.outcome !== "exploration-recorded") process.exitCode = 1;
  } catch {
    process.stderr.write("Owned shape capture did not finish; inspect private WAL.\n");
    process.exitCode = 1;
  }
}
