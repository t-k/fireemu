// Pure building blocks of the sandbox harness shared by FS-QUERY-INDEX and FS-DATA-WRITE-LIST: request construction for REST and
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
    "listDocuments",
    "listCollectionIds",
  ]),
  grpc: new Set([
    "runQuery",
    "runAggregationQuery",
    "partitionQuery",
    "executePipeline",
    "listDocuments",
    "listCollectionIds",
  ]),
};

/**
 * The query parameters a REST listDocuments step may send: its request message fields, by JSON
 * and by proto name (HTTP transcoding binds both), and one unknown name.
 */
export const LIST_QUERY_KEYS = new Set([
  "pageSize",
  "pageToken",
  "orderBy",
  "mask.fieldPaths",
  "showMissing",
  "readTime",
  "transaction",
  "page_size",
  "page_token",
  "order_by",
  "mask.field_paths",
  "show_missing",
  "read_time",
  "unknownParameter",
]);

/** gRPC method paths and whether they stream their responses. */
export const GRPC_METHODS = {
  runQuery: { method: "RunQuery", stream: true },
  runAggregationQuery: { method: "RunAggregationQuery", stream: true },
  partitionQuery: { method: "PartitionQuery", stream: false },
  executePipeline: { method: "ExecutePipeline", stream: true },
  listDocuments: { method: "ListDocuments", stream: false },
  listCollectionIds: { method: "ListCollectionIds", stream: false },
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
    if (target.projectNumber !== undefined && !/^[1-9]\d{5,}$/.test(target.projectNumber)) {
      throw new Error("project number must be numeric");
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
    startedMs,
    project: SANDBOX_PROJECT,
    target,
    // Read-time steps ask for up to about an hour before the run, so the window starts two hours
    // early.
    window: { from: startedMs - 2 * 3_600_000, to: startedMs + 12 * 3_600_000 },
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

function chained(reference, raw) {
  const found = lookup(raw.get(reference.$from), reference.path);
  // proto-loader fills absent gRPC strings with "", which means the same as absent.
  if (found === undefined || found === "")
    throw new Error(`step ${reference.$from} recorded nothing at ${reference.path}`);
  return found;
}

const NANOS_PER_SECOND = 1_000_000_000n;

/** An RFC 3339 instant shifted by whole seconds and nanoseconds, with nanosecond precision. */
export function shiftInstant(text, addSeconds = 0, addNanos = 0) {
  const match = /^(.*T\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?Z$/.exec(String(text));
  if (!match) throw new Error(`not an instant: ${text}`);
  const seconds = BigInt(Date.parse(`${match[1]}Z`) / 1000);
  const total =
    seconds * NANOS_PER_SECOND +
    BigInt((match[2] ?? "").padEnd(9, "0")) +
    BigInt(addSeconds) * NANOS_PER_SECOND +
    BigInt(addNanos);
  const whole = total / NANOS_PER_SECOND;
  const fraction = String(total % NANOS_PER_SECOND)
    .padStart(9, "0")
    .replace(/0+$/, "");
  const base = new Date(Number(whole) * 1000).toISOString().replace(/\.\d{3}Z$/, "");
  return `${base}${fraction ? `.${fraction}` : ""}Z`;
}

/**
 * Resolves placeholders, `$from` references to earlier raw responses and `$time` shifts of a
 * chained instant in a request value.
 */
export function resolveValue(value, ctx, raw) {
  if (Array.isArray(value)) return value.map((v) => resolveValue(v, ctx, raw));
  if (value && typeof value === "object") {
    if (typeof value.$from === "string") return chained(value, raw);
    if (value.$time !== undefined) {
      const { addSeconds = 0, addNanos = 0, ...reference } = value.$time;
      return shiftInstant(chained(reference, raw), addSeconds, addNanos);
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

/**
 * The resolved query parameters of a listDocuments step, in order: `step.query` is a list of
 * `[key, value]` pairs so a key (`mask.fieldPaths`) can repeat.
 */
export function resolveQuery(step, ctx, raw) {
  return (step.query ?? []).map(([key, value]) => [key, String(resolveValue(value, ctx, raw))]);
}

/** The URL and fetch init for one REST step against the context's target. */
export function buildRestRequest(step, ctx, raw) {
  const origin = ctx.target.kind === "production" ? PRODUCTION_ORIGIN : ctx.target.origin;
  let path;
  if (step.path !== undefined) path = substitute(step.path, ctx);
  else if (step.rpc === "get") path = `v1/${stepParent(step, ctx)}`;
  else if (step.rpc === "listDocuments") {
    const query = resolveQuery(step, ctx, raw)
      .map(([key, value]) => `${key}=${encodeURIComponent(value)}`)
      .join("&");
    path = `v1/${stepParent(step, ctx)}/${encodeURIComponent(step.collectionId)}${query ? `?${query}` : ""}`;
  } else if (step.rpc === "executePipeline" || step.rpc === "commit")
    path = `v1/${databaseName(ctx)}/documents:${step.rpc}`;
  else path = `v1/${stepParent(step, ctx)}:${step.rpc}`;
  const headers = {
    authorization: `Bearer ${ctx.target.kind === "production" ? ctx.target.token : "owner"}`,
  };
  if (ctx.target.kind === "production") headers["x-goog-user-project"] = ctx.target.quotaProject;
  const get = step.rpc === "get" || step.rpc === "listDocuments";
  const init = { method: get ? "GET" : "POST", headers };
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
  if (key === "nullValue") return "NULL_VALUE";
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

/** A google.protobuf.Struct as proto-loader decodes it: every field value names its `kind`. */
const isStruct = (value) =>
  value &&
  typeof value === "object" &&
  value.fields &&
  typeof value.fields === "object" &&
  Object.keys(value).every((k) => k === "fields") &&
  Object.values(value.fields).every((v) => v && typeof v.kind === "string");

function structValue(value) {
  if (value.structValue) return structFields(value.structValue.fields ?? {});
  if (value.listValue) return (value.listValue.values ?? []).map(structValue);
  if (value.kind === "stringValue") return value.stringValue;
  if (value.kind === "numberValue") return value.numberValue;
  if (value.kind === "boolValue") return value.boolValue;
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
    if (isStruct(value)) return structFields(value.fields);
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
export function validateCorpus(programs, lane = "fs-query-index") {
  let requests = 0;
  const programIds = new Set();
  const programId = new RegExp(`^${lane}/[a-z0-9-]+/[a-z0-9-]+(/[a-z0-9-]+)*$`);
  for (const program of programs) {
    if (programIds.has(program.id)) throw new Error(`duplicate program ${program.id}`);
    programIds.add(program.id);
    if (!programId.test(program.id))
      throw new Error(`${program.id}: program id must be ${lane}/<area>/<case>`);
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
      // An explicit path names the step's own method, so no step reaches a method (a
      // transaction, a write) the corpus review did not see.
      if (
        step.path !== undefined &&
        (step.rpc === "get" || step.rpc === "listDocuments" || !step.path.endsWith(`:${step.rpc}`))
      )
        throw new Error(`${program.id}#${step.id}: an explicit path must end in :${step.rpc}`);
      if (transport === "grpc" && (step.path !== undefined || step.rawBody !== undefined))
        throw new Error(`${program.id}#${step.id}: gRPC steps take a body only`);
      if (transport === "grpc" && step.body && ("parent" in step.body || "database" in step.body))
        throw new Error(`${program.id}#${step.id}: a gRPC body must not set its own scope`);
      if (step.query !== undefined && (transport !== "rest" || step.rpc !== "listDocuments"))
        throw new Error(`${program.id}#${step.id}: only a REST listDocuments step takes a query`);
      for (const [key, value] of step.query ?? []) {
        if (!LIST_QUERY_KEYS.has(key))
          throw new Error(`${program.id}#${step.id}: query parameter ${key} is not reviewed`);
        // A transaction is never chained from an answer: only a fixed, invalid literal.
        if (key === "transaction" && typeof value !== "string")
          throw new Error(`${program.id}#${step.id}: a transaction parameter must be a literal`);
      }
      if (
        step.rpc === "listDocuments" &&
        transport === "rest" &&
        (typeof step.collectionId !== "string" ||
          !/^[A-Za-z0-9_.~-]+$/.test(step.collectionId) ||
          /^\.{1,2}$/.test(step.collectionId))
      )
        throw new Error(`${program.id}#${step.id}: a REST listDocuments step names one collection`);
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

/** A documents-root name or a canonical path below it (no empty, `.` or `..` segment). */
function withinDocuments(name, ctx) {
  const root = documentsName(ctx);
  if (name === root) return true;
  if (!String(name).startsWith(`${root}/`)) return false;
  return String(name)
    .slice(root.length + 1)
    .split("/")
    .every((segment) => segment !== "" && segment !== "." && segment !== "..");
}

/** Keys whose values address a resource the request acts on (not a value it compares). */
const SCOPE_KEYS = new Set(["delete", "parent", "database", "document"]);
/** Messages whose `name` is the document a write acts on. */
const NAMED_TARGETS = new Set(["update", "document"]);

/**
 * Resource names a request acts on (written or deleted documents, parents) must be in the
 * sandbox `(default)` database; a request never carries its own transaction.
 */
function assertScopedToDatabase(body, ctx) {
  const check = (key, value) => {
    const ok = key === "database" ? value === databaseName(ctx) : withinDocuments(value, ctx);
    if (!ok) throw new Error(`request acts on a resource outside the sandbox database: ${value}`);
  };
  const visit = (value, key) => {
    if (Array.isArray(value)) value.forEach((v) => visit(v, key));
    else if (value && typeof value === "object") {
      for (const [k, v] of Object.entries(value)) {
        if (k === "transaction" || k === "newTransaction")
          throw new Error("a request must not carry a transaction");
        if (k === "referenceValue") continue;
        if (k === "name" && NAMED_TARGETS.has(key) && typeof v === "string") check(k, v);
        else visit(v, k);
      }
    } else if (SCOPE_KEYS.has(key) && typeof value === "string") check(key, value);
  };
  visit(body, "");
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
  const [raw, ...queries] = url.slice(parsed.origin.length).split("?");
  if (/%2e|%2f|\/\.\.?(\/|$)|#/i.test(raw) || queries.length > 1)
    throw new Error(`request path is not canonical: ${raw}`);
  if (queries.length) {
    // Only a GET listDocuments carries parameters: reviewed keys, values naming no other project.
    if (init.method !== "GET" || init.body !== undefined)
      throw new Error("only a GET request may carry query parameters");
    for (const [key, value] of parsed.searchParams) {
      if (!LIST_QUERY_KEYS.has(key)) throw new Error(`query parameter ${key} is not reviewed`);
      assertOnlySandboxProject(value, ctx);
    }
  }
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
    assertScopedToDatabase(body, ctx);
  }
}

/** The same guard for a gRPC request: its parent or database must be the sandbox database. */
export function guardGrpcRequest({ request }, ctx) {
  const inScope =
    request.parent !== undefined
      ? request.database === undefined && withinDocuments(request.parent, ctx)
      : request.database === databaseName(ctx);
  if (!inScope)
    throw new Error(
      `gRPC request is outside the sandbox database: ${request.parent ?? request.database}`,
    );
  assertOnlySandboxProject(request, ctx);
  const { parent: _parent, database: _database, ...rest } = request;
  assertScopedToDatabase(rest, ctx);
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

/**
 * The symbols of one step's run-window instants. An instant a request of the program carried
 * (a chained or shifted read time) keeps its program-wide anchor `<r1>`, `<r2>`, ... so an answer
 * echoing it shows that; every other instant is numbered by first appearance within the step
 * (`<t1>`, `<t2>`, ...), so one differing step never renumbers the rest of the program.
 */
export const stepSymbols = (anchors = new Map()) => ({
  anchors,
  local: new Map(),
  tokens: new Set(),
});

/**
 * The instant an RFC 3339 text names, as nanoseconds since the epoch, so spellings that differ
 * only in fraction digits (`.1Z`, `.100Z`) share one symbol.
 */
function instantKey(text) {
  const match = /^(.*T\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?Z$/.exec(text);
  if (!match) return text;
  const seconds = BigInt(Date.parse(`${match[1]}Z`) / 1000);
  return String(seconds * NANOS_PER_SECOND + BigInt((match[2] ?? "").padEnd(9, "0")));
}

function instantSymbol(text, symbols) {
  const key = instantKey(text);
  if (symbols.anchors.has(key)) return symbols.anchors.get(key);
  if (!symbols.local.has(key)) symbols.local.set(key, `<t${symbols.local.size + 1}>`);
  return symbols.local.get(key);
}

const EMBEDDED_INSTANT = /\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z/g;

function normalizeString(text, ctx, symbols) {
  if (inRunWindow(text, ctx)) return instantSymbol(text, symbols);
  let out = text;
  // A page token the request carried, echoed by the answer (an error naming it).
  for (const token of symbols.tokens ?? []) out = out.replaceAll(token, "<page-token>");
  out = normalizeIndexLink(out, ctx)
    .replaceAll(EMBEDDED_INSTANT, (instant) =>
      inRunWindow(instant, ctx) ? instantSymbol(instant, symbols) : instant,
    )
    .replaceAll(ctx.project, RECORDED_PROJECT);
  if (ctx.target.projectNumber) out = out.replaceAll(ctx.target.projectNumber, "<project-number>");
  return out;
}

/**
 * Registers the run-window instants a request carries (chained or shifted read times) before
 * its answer is normalized, so an answer that echoes one gets the same symbol.
 */
export function registerRequestInstants(value, ctx, symbols) {
  if (typeof value === "string") {
    if (inRunWindow(value, ctx) && !symbols.anchors.has(instantKey(value)))
      symbols.anchors.set(instantKey(value), `<r${symbols.anchors.size + 1}>`);
  } else if (Array.isArray(value)) value.forEach((v) => registerRequestInstants(v, ctx, symbols));
  else if (value && typeof value === "object") {
    for (const key of Object.keys(value).toSorted())
      registerRequestInstants(value[key], ctx, symbols);
  }
}

/** Page tokens shorter than this are corpus literals (`garbage`), never server tokens. */
const OPAQUE_TOKEN_LENGTH = 16;

/**
 * Registers the page tokens a request carries (a body or gRPC `pageToken`, a `pageToken` or
 * `page_token` query pair), so an answer that echoes one records `<page-token>`, as the
 * token itself is recorded.
 */
export function registerRequestTokens(value, symbols) {
  const add = (token) => {
    if (typeof token === "string" && token.length >= OPAQUE_TOKEN_LENGTH) symbols.tokens.add(token);
  };
  if (Array.isArray(value)) {
    if (value.length === 2 && (value[0] === "pageToken" || value[0] === "page_token"))
      add(value[1]);
    else value.forEach((v) => registerRequestTokens(v, symbols));
  } else if (value && typeof value === "object") {
    for (const [key, v] of Object.entries(value)) {
      if (key === "pageToken") add(v);
      else registerRequestTokens(v, symbols);
    }
  }
}

/**
 * Normalizes one decoded answer. Object keys are visited in sorted order, because production
 * map key order is not deterministic and symbols are numbered by first appearance.
 */
export function normalizeValue(value, key, ctx, symbols = stepSymbols()) {
  if (OPAQUE_KEYS.has(key) && typeof value === "string" && value !== "")
    return OPAQUE_KEYS.get(key);
  if (key === "executionDuration" && typeof value === "string") {
    if (!DURATION.test(value)) throw new Error(`unexpected executionDuration ${value}`);
    return "<duration>";
  }
  // JSON cannot carry a negative zero through a round trip; keep it as its proto3 JSON string.
  if (key === "doubleValue" && Object.is(value, -0)) return "-0";
  if (typeof value === "string") return normalizeString(value, ctx, symbols);
  if (Array.isArray(value)) return value.map((v) => normalizeValue(v, key, ctx, symbols));
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .toSorted()
        .map((k) => [k, normalizeValue(value[k], k, ctx, symbols)]),
    );
  }
  return value;
}

/** The recorded form of one REST answer. */
export function normalizeRestResponse(status, text, ctx, symbols = stepSymbols()) {
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    return { status, nonJson: normalizeString(text.slice(0, 400), ctx, symbols) };
  }
  return { status, body: normalizeValue(body, "", ctx, symbols) };
}

/** Reads the fields of one protobuf message: field number to a list of varints or byte runs. */
function protoFields(bytes) {
  const fields = new Map();
  let at = 0;
  const varint = () => {
    let result = 0n;
    let shift = 0n;
    for (;;) {
      if (at >= bytes.length) throw new Error("truncated varint");
      const byte = bytes[at++];
      result |= BigInt(byte & 0x7f) << shift;
      if (!(byte & 0x80)) return result;
      shift += 7n;
    }
  };
  while (at < bytes.length) {
    const tag = Number(varint());
    const number = tag >> 3;
    const wire = tag & 7;
    let value;
    if (wire === 0) value = varint();
    else if (wire === 2) {
      const length = Number(varint());
      value = bytes.subarray(at, at + length);
      at += length;
    } else throw new Error(`unsupported wire type ${wire}`);
    fields.set(number, [...(fields.get(number) ?? []), value]);
  }
  return fields;
}

const text = (bytes) => Buffer.from(bytes ?? []).toString("utf8");

/** google.rpc.ErrorInfo and google.rpc.Help as JSON; anything else as base64. */
export function decodeStatusDetail({ typeUrl, bytes }) {
  const buffer = Buffer.from(bytes, "base64");
  try {
    if (typeUrl === "type.googleapis.com/google.rpc.ErrorInfo") {
      const f = protoFields(buffer);
      const metadata = Object.fromEntries(
        (f.get(3) ?? []).map((entry) => {
          const e = protoFields(entry);
          return [text(e.get(1)?.[0]), text(e.get(2)?.[0])];
        }),
      );
      return {
        "@type": typeUrl,
        reason: text(f.get(1)?.[0]),
        domain: text(f.get(2)?.[0]),
        ...(Object.keys(metadata).length ? { metadata } : {}),
      };
    }
    if (typeUrl === "type.googleapis.com/google.rpc.Help") {
      const links = (protoFields(buffer).get(1) ?? []).map((link) => {
        const l = protoFields(link);
        return { description: text(l.get(1)?.[0]), url: text(l.get(2)?.[0]) };
      });
      return { "@type": typeUrl, links };
    }
  } catch {
    /* recorded as bytes */
  }
  return { "@type": typeUrl, bytes };
}

/** The recorded form of one gRPC answer: the projected messages and the final status. */
export function normalizeGrpcResponse(
  { messages, code, details, errorDetails },
  ctx,
  symbols = stepSymbols(),
) {
  return {
    transport: "grpc",
    code,
    ...(details ? { message: normalizeString(details, ctx, symbols) } : {}),
    ...(errorDetails?.length
      ? { errorDetails: normalizeValue(errorDetails.map(decodeStatusDetail), "", ctx, symbols) }
      : {}),
    messages: normalizeValue(
      messages.map((m) => projectGrpcMessage(m)),
      "",
      ctx,
      symbols,
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

/**
 * The recorded row of one step from what was sent and received: `raw.request` is the resolved
 * request body (REST JSON text or the gRPC body before conversion), `raw.response` the REST
 * `{status, text}` or the gRPC `{messages, code, details, errorDetails}`. Pure, so a saved raw
 * recording can be normalized again after the harness changes.
 */
export function normalizeStep(raw, ctx, anchors) {
  const symbols = stepSymbols(anchors);
  if (raw.request !== undefined) {
    registerRequestInstants(raw.request, ctx, symbols);
    registerRequestTokens(raw.request, symbols);
  }
  if (raw.response.transportError !== undefined)
    return { status: 0, transportError: raw.response.transportError };
  if (raw.transport === "grpc") return normalizeGrpcResponse(raw.response, ctx, symbols);
  return normalizeRestResponse(raw.response.status, raw.response.text, ctx, symbols);
}

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
