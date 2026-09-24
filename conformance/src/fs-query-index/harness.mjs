// Pure building blocks of the FS-QUERY-INDEX sandbox harness: request construction for REST and
// gRPC steps, the request guard, the projection of gRPC messages to their REST JSON shape,
// response normalization and the comparison of two production recordings. Nothing here performs
// I/O.
//
// Production is only ever the disposable query sandbox (`SANDBOX_PROJECT`, database
// `(default)`); the local side is fireemu on a loopback port, started with the same project id.
// Recorded values never contain the sandbox project id, a token, a run-window time or an opaque
// server token.

import { isDeepStrictEqual } from "node:util";

export const SANDBOX_PROJECT = "fireemu-oracle-query";
export const DATABASE = "(default)";
export const RECORDED_PROJECT = "demo-fs-query-index";
export const REQUEST_CAP = 3000;
export const PRODUCTION_ORIGIN = "https://firestore.googleapis.com";
export const PRODUCTION_GRPC = { host: "firestore.googleapis.com", port: 443 };

const LOOPBACK = new Set(["127.0.0.1", "localhost", "[::1]"]);

/** The REST custom methods a recorded step may call, by transport. */
export const RPCS = {
  rest: new Set([
    "runQuery",
    "runAggregationQuery",
    "partitionQuery",
    "executePipeline",
    "commit",
    "get",
  ]),
  grpc: new Set(["runQuery", "runAggregationQuery", "partitionQuery", "executePipeline"]),
};

/** gRPC method paths and whether they stream their responses. */
export const GRPC_METHODS = {
  runQuery: { method: "RunQuery", stream: true },
  runAggregationQuery: { method: "RunAggregationQuery", stream: true },
  partitionQuery: { method: "PartitionQuery", stream: false },
  executePipeline: { method: "ExecutePipeline", stream: true },
};

/**
 * Binds a run id, the run start time and one target (production sandbox or local fireemu).
 * Times inside the run window are the only times normalization masks.
 */
export function createContext({ run, target, startedMs = Date.now() }) {
  if (!/^\d+$/.test(String(run))) throw new Error("run id must be numeric");
  if (!Number.isFinite(startedMs)) throw new Error("run start must be a time");
  if (target.kind === "production") {
    if (!target.token) throw new Error("production needs an access token");
    if (target.quotaProject !== SANDBOX_PROJECT) {
      throw new Error("quota project must be the sandbox project");
    }
  } else if (target.kind === "local") {
    const url = new URL(target.origin);
    if (url.protocol !== "http:" || !LOOPBACK.has(url.hostname)) {
      throw new Error("local target must be a loopback http origin");
    }
    if (!LOOPBACK.has(String(target.grpcHost)) || !Number.isInteger(target.grpcPort)) {
      throw new Error("local gRPC target must be a loopback host and port");
    }
  } else {
    throw new Error(`unknown target kind ${target.kind}`);
  }
  return {
    run: String(run),
    project: SANDBOX_PROJECT,
    target,
    window: { from: startedMs - 10 * 60_000, to: startedMs + 12 * 3_600_000 },
  };
}

export const databaseName = (ctx) => `projects/${ctx.project}/databases/${DATABASE}`;
export const documentsName = (ctx) => `${databaseName(ctx)}/documents`;

function substitute(text, ctx) {
  return text
    .replaceAll("{docs}", documentsName(ctx))
    .replaceAll("{db}", databaseName(ctx))
    .replaceAll("{project}", ctx.project);
}

function lookup(value, path) {
  let current = value;
  for (const segment of String(path).split(".")) {
    if (current === null || current === undefined) return undefined;
    current = current[segment];
  }
  return current;
}

/** Resolves placeholders and `$from` references (to earlier raw responses) in a request value. */
export function resolveValue(value, ctx, raw) {
  if (Array.isArray(value)) return value.map((v) => resolveValue(v, ctx, raw));
  if (value && typeof value === "object") {
    if (typeof value.$from === "string") {
      const found = lookup(raw.get(value.$from), value.path);
      if (found === undefined)
        throw new Error(`step ${value.$from} recorded nothing at ${value.path}`);
      return found;
    }
    if (value.$array !== undefined) {
      return Array.from({ length: value.$array.count }, (_, i) =>
        resolveValue(
          JSON.parse(JSON.stringify(value.$array.item).replaceAll("$i", String(i))),
          ctx,
          raw,
        ),
      );
    }
    return Object.fromEntries(
      Object.entries(value).map(([k, v]) => [k, resolveValue(v, ctx, raw)]),
    );
  }
  if (typeof value === "string") return substitute(value, ctx);
  return value;
}

/** The parent resource of a step: the documents root or a document below it. */
export function stepParent(step, ctx) {
  const parent = step.parent ?? "";
  return parent ? `${documentsName(ctx)}/${parent}` : documentsName(ctx);
}

/** The URL and fetch init for one REST step against the context's target. */
export function buildRestRequest(step, ctx, raw) {
  const origin = ctx.target.kind === "production" ? PRODUCTION_ORIGIN : ctx.target.origin;
  let path;
  if (step.path !== undefined) path = substitute(step.path, ctx);
  else if (step.rpc === "get") path = `v1/${stepParent(step, ctx)}`;
  else if (step.rpc === "executePipeline" || step.rpc === "commit")
    path = `v1/${databaseName(ctx)}/documents:${step.rpc}`;
  else path = `v1/${stepParent(step, ctx)}:${step.rpc}`;
  const headers = {
    authorization: `Bearer ${ctx.target.kind === "production" ? ctx.target.token : "owner"}`,
  };
  if (ctx.target.kind === "production") headers["x-goog-user-project"] = ctx.target.quotaProject;
  const init = { method: step.rpc === "get" ? "GET" : "POST", headers };
  if (step.rawBody !== undefined) {
    headers["content-type"] = "application/json";
    init.body = substitute(step.rawBody, ctx);
  } else if (step.body !== undefined) {
    headers["content-type"] = "application/json";
    init.body = JSON.stringify(resolveValue(step.body, ctx, raw));
  }
  return { url: `${origin}/${path}`, init };
}

/** The gRPC method and request message for one gRPC step. */
export function buildGrpcRequest(step, ctx, raw) {
  const spec = GRPC_METHODS[step.rpc];
  if (!spec) throw new Error(`${step.id}: no gRPC mapping for ${step.rpc}`);
  const body = resolveValue(step.body ?? {}, ctx, raw);
  const request =
    step.rpc === "executePipeline"
      ? { database: databaseName(ctx), ...body }
      : { parent: stepParent(step, ctx), ...body };
  return { ...spec, request: toGrpcMessage(request) };
}

/** Fields whose proto type is a wrapper message; REST JSON writes them as bare scalars. */
const WRAPPED = new Set(["limit", "upTo", "distanceThreshold"]);

/** REST JSON to the plain-object form the gRPC serializer accepts. */
export function toGrpcMessage(value, key = "") {
  if (Array.isArray(value)) return value.map((v) => toGrpcMessage(v, key));
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, toGrpcMessage(v, k)]));
  }
  if (WRAPPED.has(key) && (typeof value === "number" || typeof value === "string")) {
    return { value: key === "distanceThreshold" ? toGrpcMessage(value, "doubleValue") : value };
  }
  if (typeof value === "string" && (key === "timestampValue" || key.endsWith("Time"))) {
    const millis = Date.parse(value);
    if (Number.isFinite(millis)) {
      const nanos = /\.(\d+)Z$/.exec(value)?.[1] ?? "";
      return {
        seconds: String(Math.floor(millis / 1000)),
        nanos: Number(nanos.padEnd(9, "0").slice(0, 9)),
      };
    }
  }
  if (key === "doubleValue" && typeof value === "string") {
    return { NaN: Number.NaN, Infinity: Infinity, "-Infinity": -Infinity }[value] ?? Number(value);
  }
  if (key === "bytesValue" && typeof value === "string") return Buffer.from(value, "base64");
  return value;
}

/** A proto-loader oneof discriminator: a `*Type`/`*Selector`/`kind` key naming a sibling. */
const isDiscriminator = (key, value, object) =>
  (key === "kind" || key.endsWith("Type") || key.endsWith("Selector")) &&
  typeof value === "string" &&
  value !== key &&
  Object.hasOwn(object, value);
const MAP_FIELDS = new Set(["fields", "aggregateFields"]);

function isDefault(value) {
  return (
    value === null ||
    value === undefined ||
    value === 0 ||
    value === "0" ||
    value === "" ||
    value === false ||
    (Buffer.isBuffer(value) && value.length === 0) ||
    (value?.type === "Buffer" && Array.isArray(value.data) && value.data.length === 0)
  );
}

function timestampText({ seconds, nanos }) {
  const millis = Number(seconds) * 1000;
  const base = new Date(millis).toISOString().replace(/\.\d{3}Z$/, "");
  const fraction = String(nanos ?? 0)
    .padStart(9, "0")
    .replace(/0+$/, "");
  return `${base}${fraction ? `.${fraction}` : ""}Z`;
}

function durationText({ seconds, nanos }) {
  const fraction = String(nanos ?? 0)
    .padStart(9, "0")
    .replace(/0+$/, "");
  return `${Number(seconds ?? 0)}${fraction ? `.${fraction}` : ""}s`;
}

function structValue(value) {
  if (value.structValue) return structFields(value.structValue.fields ?? {});
  if (value.listValue) return (value.listValue.values ?? []).map(structValue);
  if ("stringValue" in value) return value.stringValue;
  if ("numberValue" in value) return value.numberValue;
  if ("boolValue" in value) return value.boolValue;
  return null;
}

function structFields(fields) {
  return Object.fromEntries(Object.entries(fields).map(([k, v]) => [k, structValue(v)]));
}

/**
 * A decoded gRPC message in the shape its REST JSON has: default scalars and absent messages
 * dropped (proto3 cannot tell them apart on the wire), oneof discriminators dropped, times and
 * durations as text, bytes as base64, Struct as plain JSON.
 */
export function projectGrpcMessage(value, key = "") {
  if (Array.isArray(value)) return value.map((v) => projectGrpcMessage(v, key));
  if (Buffer.isBuffer(value)) return value.toString("base64");
  if (value?.type === "Buffer" && Array.isArray(value.data))
    return Buffer.from(value.data).toString("base64");
  if (value && typeof value === "object") {
    if (key === "debugStats" && value.fields) return structFields(value.fields);
    if ((key.endsWith("Time") || key === "readTime") && "seconds" in value)
      return timestampText(value);
    if (key === "timestampValue" && "seconds" in value) return timestampText(value);
    if (key === "executionDuration" && "seconds" in value) return durationText(value);
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      if (k === "nullValue") {
        if (value.valueType === "nullValue") out[k] = null;
        continue;
      }
      if (isDiscriminator(k, v, value) || isDefault(v)) continue;
      // proto3 JSON leaves out empty repeated and map fields.
      if (Array.isArray(v) && v.length === 0) continue;
      if (MAP_FIELDS.has(k) && Object.keys(v).length === 0) continue;
      out[k] = projectGrpcMessage(v, k);
    }
    // A Value whose oneof is a default scalar still names its kind on the wire.
    if (value.valueType && !(value.valueType in out)) {
      out[value.valueType] = projectGrpcMessage(value[value.valueType], value.valueType);
    }
    return out;
  }
  if (typeof value === "number" && key === "doubleValue") {
    if (Number.isNaN(value)) return "NaN";
    if (value === Infinity) return "Infinity";
    if (value === -Infinity) return "-Infinity";
  }
  return value;
}

/**
 * Refuses a corpus that addresses anything but the sandbox database through a reviewed method,
 * or exceeds the request cap. Returns the number of recorded requests.
 */
export function validateCorpus(programs) {
  let requests = 0;
  const programIds = new Set();
  for (const program of programs) {
    if (programIds.has(program.id)) throw new Error(`duplicate program ${program.id}`);
    programIds.add(program.id);
    if (!/^fs-query-index\/[a-z0-9-]+\/[a-z0-9-]+(\/[a-z0-9-]+)*$/.test(program.id))
      throw new Error(`${program.id}: program id must be fs-query-index/<area>/<case>`);
    for (const [name] of program.seed ?? []) assertRelativePath(name, `${program.id} seed`);
    const stepIds = new Set();
    for (const step of program.steps) {
      requests += 1;
      if (stepIds.has(step.id)) throw new Error(`${program.id}: duplicate step ${step.id}`);
      stepIds.add(step.id);
      const transport = step.transport ?? "rest";
      if (!RPCS[transport]?.has(step.rpc))
        throw new Error(`${program.id}#${step.id}: ${transport} ${step.rpc} is not reviewed`);
      if (step.parent !== undefined) assertRelativePath(step.parent, `${program.id}#${step.id}`);
      if (step.path !== undefined && !step.path.startsWith("v1/{docs}"))
        throw new Error(`${program.id}#${step.id}: an explicit path must stay under {docs}`);
      if (transport === "grpc" && (step.path !== undefined || step.rawBody !== undefined))
        throw new Error(`${program.id}#${step.id}: gRPC steps take a body only`);
    }
  }
  if (requests > REQUEST_CAP)
    throw new Error(`corpus exceeds the request cap (${requests} > ${REQUEST_CAP})`);
  return requests;
}

function assertRelativePath(path, where) {
  if (typeof path !== "string" || /^\/|\/\/|\.\.|^[a-z]+:/i.test(path))
    throw new Error(`${where}: path must be relative to the documents root`);
}

function walkStrings(value, visit) {
  if (typeof value === "string") visit(value);
  else if (Array.isArray(value)) for (const v of value) walkStrings(v, visit);
  else if (value && typeof value === "object")
    for (const v of Object.values(value)) walkStrings(v, visit);
}

/** Resource names in a request may only name the sandbox project. */
function assertOnlySandboxProject(value, ctx) {
  walkStrings(value, (text) => {
    for (const [, project] of text.matchAll(/projects\/([^/\s"]+)/g)) {
      if (project !== ctx.project) throw new Error(`request names another project: ${project}`);
    }
  });
}

/**
 * The last check before a REST request leaves the process: the resolved URL must be this
 * project's `(default)` documents resource on the target's host, and the body may only name
 * this project. Only the harness itself (wipe, seed) may use it for anything but a reviewed
 * query method; the local emulator's reset endpoint is harness-only.
 */
export function guardRestRequest({ url, init }, ctx, { harness = false } = {}) {
  const parsed = new URL(url);
  const raw = url.slice(parsed.origin.length);
  if (/%2e|%2f|\/\.\.?(\/|$)|\?/i.test(raw))
    throw new Error(`request path is not canonical: ${raw}`);
  const expectedOrigin =
    ctx.target.kind === "production" ? PRODUCTION_ORIGIN : new URL(ctx.target.origin).origin;
  if (parsed.origin !== expectedOrigin) throw new Error("request left the target");
  const database = `/v1/${databaseName(ctx)}/documents`;
  const path = decodeURIComponent(parsed.pathname);
  const reset = `/emulator/v1/${databaseName(ctx)}/documents`;
  const allowed =
    path === database ||
    path.startsWith(`${database}/`) ||
    path.startsWith(`${database}:`) ||
    (harness && ctx.target.kind === "local" && path === reset);
  if (!allowed) throw new Error(`request path is outside the sandbox database: ${path}`);
  if (typeof init.body === "string" && init.headers["content-type"] === "application/json") {
    let body;
    try {
      body = JSON.parse(init.body);
    } catch {
      body = init.body;
    }
    assertOnlySandboxProject(body, ctx);
  }
}

/** The same guard for a gRPC request: its parent or database must be the sandbox database. */
export function guardGrpcRequest({ request }, ctx) {
  const scope = request.parent ?? request.database;
  if (scope !== databaseName(ctx) && !String(scope).startsWith(`${databaseName(ctx)}/documents`))
    throw new Error(`gRPC request is outside the sandbox database: ${scope}`);
  assertOnlySandboxProject(request, ctx);
}

const TRANSIENT_MESSAGE = /^(RESOURCE_EXHAUSTED|UNAVAILABLE|DEADLINE_EXCEEDED|INTERNAL)\b/;

/** A recorded answer that says nothing about behaviour: transport failure, 5xx, rate limit. */
export function isTransient(recorded) {
  if (!recorded) return false;
  // -1: a step whose dependency returned nothing; transient only when that dependency was.
  if (recorded.status === -1) return recorded.dependencyTransient === true;
  if (recorded.transport === "grpc")
    return [4, 8, 13, 14].includes(recorded.code) || recorded.code === -1;
  if (recorded.status === 0 || recorded.status === 429 || recorded.status >= 500) return true;
  const element = Array.isArray(recorded.body) ? recorded.body.at(-1) : recorded.body;
  return TRANSIENT_MESSAGE.test(String(element?.error?.status ?? ""));
}

const INSTANT = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z$/;
const DURATION = /^\d+(\.\d{1,9})?s$/;
const OPAQUE_KEYS = new Map([
  ["nextPageToken", "<page-token>"],
  ["transaction", "<transaction>"],
]);
const INDEX_LINK = /(create_(?:composite|exemption))=([A-Za-z0-9_-]+)/g;

function inRunWindow(text, ctx) {
  if (!INSTANT.test(text)) return false;
  const millis = Date.parse(text);
  return millis >= ctx.window.from && millis <= ctx.window.to;
}

/**
 * The console link production puts in a missing-index message carries the index name, and so
 * the project id, as base64url protobuf. The recorded form decodes it, replaces the project id
 * and encodes it again, so both sides stay comparable byte for byte.
 */
export function normalizeIndexLink(text, ctx) {
  return text.replaceAll(INDEX_LINK, (_, kind, blob) => {
    const bytes = Buffer.from(blob, "base64url").toString("latin1");
    const replaced = bytes.replaceAll(ctx.project, RECORDED_PROJECT);
    return `${kind}=${Buffer.from(replaced, "latin1").toString("base64url")}`;
  });
}

function normalizeString(text, ctx) {
  if (inRunWindow(text, ctx)) return "<run-time>";
  return normalizeIndexLink(text, ctx).replaceAll(ctx.project, RECORDED_PROJECT);
}

export function normalizeValue(value, key, ctx) {
  if (OPAQUE_KEYS.has(key) && typeof value === "string" && value !== "")
    return OPAQUE_KEYS.get(key);
  if (key === "executionDuration" && typeof value === "string") {
    if (!DURATION.test(value)) throw new Error(`unexpected executionDuration ${value}`);
    return "<duration>";
  }
  if (typeof value === "string") return normalizeString(value, ctx);
  if (Array.isArray(value)) return value.map((v) => normalizeValue(v, key, ctx));
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([k, v]) => [k, normalizeValue(v, k, ctx)]),
    );
  }
  return value;
}

/** The recorded form of one REST answer. */
export function normalizeRestResponse(status, text, ctx) {
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    return { status, nonJson: normalizeString(text.slice(0, 400), ctx) };
  }
  return { status, body: normalizeValue(body, "", ctx) };
}

/** The recorded form of one gRPC answer: the projected messages and the final status. */
export function normalizeGrpcResponse({ messages, code, details, errorDetails }, ctx) {
  return {
    transport: "grpc",
    code,
    ...(details ? { message: normalizeString(details, ctx) } : {}),
    ...(errorDetails?.length ? { errorDetails: normalizeValue(errorDetails, "", ctx) } : {}),
    messages: normalizeValue(
      messages.map((m) => projectGrpcMessage(m)),
      "",
      ctx,
    ),
  };
}

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .toSorted()
        .map((k) => [k, canonical(value[k])]),
    );
  }
  return value;
}

export const sameRecording = (a, b) => isDeepStrictEqual(canonical(a), canonical(b));

/** Row keys (`program#step`) whose two production recordings differ. */
export function diffRecordings(first, second) {
  const rows = [];
  for (const [programId, program] of Object.entries(first)) {
    for (const [stepId, recorded] of Object.entries(program.steps)) {
      if (!sameRecording(recorded, second[programId]?.steps?.[stepId]))
        rows.push(`${programId}#${stepId}`);
    }
  }
  return rows;
}
