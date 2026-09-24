// Pure building blocks of the FS-RULES sandbox harness: the run context, request construction for
// Firestore REST and gRPC calls made as an end user, the request guard, the projection of gRPC
// messages to their REST JSON shape, response normalization and the comparison of two
// recordings. Nothing here performs I/O.
//
// Production is only ever the disposable Identity Platform sandbox (`SANDBOX_PROJECT`), whose
// Firestore and Rules this lane owns; the local side is fireemu on loopback ports, started with the
// same project id. Recorded values never contain the sandbox project id, its number, the API key,
// a token, a generated id or a run-window time.

import { isDeepStrictEqual } from "node:util";

export const SANDBOX_PROJECT = "fireemu-oracle-idp";
export const RECORDED_PROJECT = "demo-fs-rules";
export const DEFAULT_DATABASE = "(default)";
export const REQUEST_CAP = 4000;
export const PASSWORD = "fsr-Passw0rd-7";
/** The sandbox's configured test numbers (fixed code 123456); no SMS is ever sent to them. */
export const TEST_PHONES = ["+16505550105", "+16505550106"];
export const TEST_PHONE_CODE = "123456";

export const PRODUCTION = {
  firestore: "https://firestore.googleapis.com",
  itk: "https://identitytoolkit.googleapis.com",
  securetoken: "https://securetoken.googleapis.com",
  rules: "https://firebaserules.googleapis.com",
  grpc: { host: "firestore.googleapis.com", port: 443 },
};
const LOOPBACK = new Set(["127.0.0.1", "localhost", "[::1]"]);

/**
 * Binds a run id, the run start time and one target (production sandbox or local fireemu). The
 * named databases of a run are derived from the run id so both sides use the same length.
 */
export function createContext({ run, target, startedMs = Date.now() }) {
  if (!/^\d{8,}$/.test(String(run))) throw new Error("run id must be numeric");
  if (!Number.isFinite(startedMs)) throw new Error("run start must be a time");
  if (target.kind === "production") {
    if (!target.adminToken || !target.apiKey) {
      throw new Error("production needs an owner access token and the API key");
    }
    if (target.quotaProject !== SANDBOX_PROJECT) {
      throw new Error("quota project must be the sandbox project");
    }
    if (!/^[1-9]\d{5,}$/.test(String(target.projectNumber ?? ""))) {
      throw new Error("production needs the sandbox project number");
    }
  } else if (target.kind === "local") {
    for (const origin of [target.firestoreOrigin, target.authOrigin]) {
      const url = new URL(origin);
      if (url.protocol !== "http:" || !LOOPBACK.has(url.hostname)) {
        throw new Error("local targets must be loopback http origins");
      }
    }
    if (!LOOPBACK.has(String(target.grpcHost)) || !Number.isInteger(target.grpcPort)) {
      throw new Error("local gRPC target must be a loopback host and port");
    }
  } else {
    throw new Error(`unknown target kind ${target.kind}`);
  }
  const tail = String(run).slice(-8);
  return {
    run: String(run),
    startedMs,
    project: SANDBOX_PROJECT,
    target,
    databases: { named: `fsr-${tail}-a`, bare: `fsr-${tail}-b` },
    window: { from: startedMs - 2 * 3_600_000, to: startedMs + 12 * 3_600_000 },
  };
}

/** The database id a step addresses: `(default)`, or one of the run's named databases. */
export function databaseId(ctx, which = "default") {
  if (which === "default") return DEFAULT_DATABASE;
  const id = ctx.databases[which];
  if (!id) throw new Error(`unknown database ${which}`);
  return id;
}

export const databaseName = (ctx, which) =>
  `projects/${ctx.project}/databases/${databaseId(ctx, which)}`;
export const documentsName = (ctx, which) => `${databaseName(ctx, which)}/documents`;

export const principalEmail = (ctx, name) => `fsr-${ctx.run}-${name}@example.com`;

/**
 * Substitutes the run's names in a request string: `{docs}`, `{db}`, `{project}`, `{run}`,
 * `UID(name)` (the uid of a principal of this run) and `EMAIL(name)`.
 */
export function substitute(text, ctx, principals, which = "default") {
  return String(text)
    .replaceAll("{docs}", documentsName(ctx, which))
    .replaceAll("{db}", databaseName(ctx, which))
    .replaceAll("{project}", ctx.project)
    .replaceAll("{run}", ctx.run)
    .replaceAll(/EMAIL\(([a-z0-9-]+)\)/g, (_, name) => principalEmail(ctx, name))
    .replaceAll(/UID\(([a-z0-9-]+)\)/g, (_, name) => {
      const uid = principals?.get(name)?.uid;
      if (!uid) throw new Error(`principal ${name} has no uid`);
      return uid;
    });
}

/** Resolves placeholders and `$from` references to earlier raw answers in a request value. */
export function resolveValue(value, ctx, raw, principals, which) {
  if (Array.isArray(value)) return value.map((v) => resolveValue(v, ctx, raw, principals, which));
  if (value && typeof value === "object") {
    if (typeof value.$from === "string") {
      let current = raw.get(value.$from);
      for (const segment of String(value.path).split(".")) {
        if (current === null || current === undefined) break;
        current = current[segment];
      }
      if (current === undefined || current === null || current === "")
        throw new Error(`step ${value.$from} recorded nothing at ${value.path}`);
      return Buffer.isBuffer(current) ? current.toString("base64") : current;
    }
    if (value.$repeat !== undefined) {
      return Array.from({ length: value.$repeat.count }, (_, i) =>
        resolveValue(
          JSON.parse(JSON.stringify(value.$repeat.item).replaceAll("$i", String(i))),
          ctx,
          raw,
          principals,
          which,
        ),
      );
    }
    return Object.fromEntries(
      Object.entries(value).map(([k, v]) => [k, resolveValue(v, ctx, raw, principals, which)]),
    );
  }
  if (typeof value === "string") return substitute(value, ctx, principals, which);
  return value;
}

/** The Firestore RPCs a recorded step may call, and their REST and gRPC forms. */
export const RPCS = {
  get: { method: "GetDocument", stream: false },
  create: { method: "CreateDocument", stream: false },
  patch: { method: "UpdateDocument", stream: false },
  delete: { method: "DeleteDocument", stream: false },
  commit: { method: "Commit", stream: false },
  batchGet: { method: "BatchGetDocuments", stream: true },
  batchWrite: { method: "BatchWrite", stream: false },
  beginTransaction: { method: "BeginTransaction", stream: false },
  rollback: { method: "Rollback", stream: false },
  runQuery: { method: "RunQuery", stream: true },
  runAggregationQuery: { method: "RunAggregationQuery", stream: true },
  listDocuments: { method: "ListDocuments", stream: false },
  listCollectionIds: { method: "ListCollectionIds", stream: false },
  partitionQuery: { method: "PartitionQuery", stream: false },
};

const DATABASE_RPCS = new Set(["commit", "batchGet", "batchWrite", "beginTransaction", "rollback"]);
const PARENT_RPCS = new Set([
  "runQuery",
  "runAggregationQuery",
  "listCollectionIds",
  "partitionQuery",
]);

function query(entries) {
  const search = new URLSearchParams();
  for (const [k, v] of entries) {
    if (Array.isArray(v)) for (const item of v) search.append(k, String(item));
    else if (v !== undefined) search.set(k, String(v));
  }
  const text = search.toString();
  return text ? `?${text}` : "";
}

/**
 * The URL and fetch init of one Firestore REST step. `bearer` is the resolved Authorization
 * header value, or undefined for an unauthenticated request.
 */
export function buildFirestoreRest(step, ctx, raw, principals, bearer) {
  const which = step.database ?? "default";
  const origin =
    ctx.target.kind === "production" ? PRODUCTION.firestore : ctx.target.firestoreOrigin;
  const docs = documentsName(ctx, which);
  const at = (path) => (path ? `${docs}/${substitute(path, ctx, principals, which)}` : docs);
  const params = resolveValue(step.params ?? {}, ctx, raw, principals, which);
  let path;
  let method = "POST";
  switch (step.rpc) {
    case "get":
      method = "GET";
      path = `v1/${at(step.doc)}${query(Object.entries(params))}`;
      break;
    case "patch":
      method = "PATCH";
      path = `v1/${at(step.doc)}${query(Object.entries(params))}`;
      break;
    case "delete":
      method = "DELETE";
      path = `v1/${at(step.doc)}${query(Object.entries(params))}`;
      break;
    case "create":
      path = `v1/${at(step.collection)}${query(Object.entries(params))}`;
      break;
    case "listDocuments":
      method = "GET";
      path = `v1/${at(step.collection)}${query(Object.entries(params))}`;
      break;
    default:
      if (DATABASE_RPCS.has(step.rpc))
        path = `v1/${databaseName(ctx, which)}/documents:${step.rpc}`;
      else if (PARENT_RPCS.has(step.rpc)) path = `v1/${at(step.parent)}:${step.rpc}`;
      else throw new Error(`${step.id}: unknown rpc ${step.rpc}`);
  }
  const headers = {};
  if (bearer !== undefined) headers.authorization = bearer;
  const init = { method, headers };
  if (step.body !== undefined) {
    headers["content-type"] = "application/json";
    init.body = JSON.stringify(resolveValue(step.body, ctx, raw, principals, which));
  }
  return { url: `${origin}/${path}`, init };
}

/** The gRPC method and request message of one step, from its REST form. */
export function buildFirestoreGrpc(step, ctx, raw, principals) {
  const spec = RPCS[step.rpc];
  if (!spec) throw new Error(`${step.id}: no gRPC mapping for ${step.rpc}`);
  const which = step.database ?? "default";
  const docs = documentsName(ctx, which);
  const at = (path) => (path ? `${docs}/${substitute(path, ctx, principals, which)}` : docs);
  const body = resolveValue(step.body ?? {}, ctx, raw, principals, which);
  const params = resolveValue(step.params ?? {}, ctx, raw, principals, which);
  let request;
  switch (step.rpc) {
    case "get":
      request = { name: at(step.doc), ...params };
      break;
    case "delete":
      request = { name: at(step.doc), ...params };
      break;
    case "patch":
      request = { document: { ...body, name: at(step.doc) }, ...params };
      break;
    case "listDocuments": {
      const segments = at(step.collection).split("/");
      request = {
        parent: segments.slice(0, -1).join("/"),
        collectionId: segments.at(-1),
        ...params,
      };
      break;
    }
    default:
      request = DATABASE_RPCS.has(step.rpc)
        ? { database: databaseName(ctx, which), ...body }
        : { parent: at(step.parent), ...body };
  }
  const routing = request.database
    ? `database=${encodeURIComponent(request.database)}`
    : `${request.parent ? "parent" : "name"}=${encodeURIComponent(request.parent ?? request.name ?? request.document?.name)}`;
  return {
    ...spec,
    request: toGrpcMessage(request),
    routing,
    resourcePrefix: databaseName(ctx, which),
  };
}

/** Fields whose proto type is a wrapper message; REST JSON writes them as bare scalars. */
const WRAPPED = new Set(["limit"]);

/** REST JSON to the plain-object form the gRPC serializer accepts. */
export function toGrpcMessage(value, key = "") {
  if (Array.isArray(value)) return value.map((v) => toGrpcMessage(v, key));
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, toGrpcMessage(v, k)]));
  }
  if (WRAPPED.has(key) && typeof value === "number") return { value };
  if (typeof value === "string" && (key === "timestampValue" || key.endsWith("Time"))) {
    const millis = Date.parse(value);
    if (Number.isFinite(millis)) {
      const nanos = /\.(\d+)Z$/.exec(value)?.[1] ?? "";
      return { seconds: String(Math.floor(millis / 1000)), nanos: Number(nanos.padEnd(9, "0")) };
    }
  }
  if (
    (key === "bytesValue" || key === "transaction" || key === "newTransaction") &&
    typeof value === "string"
  )
    return key === "newTransaction" ? value : Buffer.from(value, "base64");
  if (key === "nullValue") return "NULL_VALUE";
  return value;
}

/**
 * Refuses any Firestore request that would leave the target's host, address a database of
 * another project, or reach a path that is not a document path of the run's databases.
 */
export function guardFirestoreRequest({ url }, ctx) {
  const parsed = new URL(url);
  const expected =
    ctx.target.kind === "production"
      ? PRODUCTION.firestore
      : new URL(ctx.target.firestoreOrigin).origin;
  if (parsed.origin !== expected) throw new Error("request left the Firestore target");
  const raw = url.slice(parsed.origin.length).split("?")[0];
  if (/%2e%2e|\/\.\.?(\/|$)/i.test(raw)) throw new Error(`request path is not canonical: ${raw}`);
  const allowed = [DEFAULT_DATABASE, ctx.databases.named, ctx.databases.bare].map(
    (db) => `/v1/projects/${ctx.project}/databases/${db}/documents`,
  );
  const path = decodeURIComponent(parsed.pathname);
  if (
    !allowed.some(
      (prefix) => path === prefix || path.startsWith(`${prefix}/`) || path.startsWith(`${prefix}:`),
    )
  ) {
    throw new Error(`request path is not a document path of this run: ${path}`);
  }
}

export function guardGrpcRequest(built, ctx) {
  const names = [
    built.request.database,
    built.request.parent,
    built.request.name,
    built.request.document?.name,
  ].filter(Boolean);
  const allowed = [DEFAULT_DATABASE, ctx.databases.named, ctx.databases.bare].map(
    (db) => `projects/${ctx.project}/databases/${db}`,
  );
  for (const name of names) {
    if (!allowed.some((prefix) => name === prefix || name.startsWith(`${prefix}/`)))
      throw new Error(`gRPC request names another database: ${name}`);
  }
}

const TIME_KEYS = new Set(["createTime", "updateTime", "readTime", "commitTime"]);
const OPAQUE_KEYS = new Set(["transaction", "nextPageToken", "resumeToken"]);
const INSTANT = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z$/;

function runTime(value, ctx) {
  if (typeof value === "string" && INSTANT.test(value)) {
    const millis = Date.parse(value);
    if (millis >= ctx.window.from && millis <= ctx.window.to) return "<run-time>";
  }
  if (value && typeof value === "object" && "seconds" in value && "nanos" in value) {
    const millis = Number(value.seconds) * 1000;
    if (millis >= ctx.window.from && millis <= ctx.window.to) return "<run-time>";
  }
  return undefined;
}

/**
 * Replaces run-specific strings: principal uids and emails, the project, its number, the API key,
 * the run's databases and the run id.
 */
export function normalizeString(text, ctx, principals) {
  let out = String(text);
  for (const [name, principal] of principals ?? []) {
    if (principal.uid) out = out.replaceAll(principal.uid, `<uid:${name}>`);
  }
  for (const [which, id] of Object.entries(ctx.databases))
    out = out.replaceAll(id, `<database:${which}>`);
  out = out.replaceAll(ctx.run, "<run>").replaceAll(ctx.project, RECORDED_PROJECT);
  if (ctx.target.projectNumber)
    out = out.replaceAll(String(ctx.target.projectNumber), "<project-number>");
  if (ctx.target.kind === "production") out = out.replaceAll(ctx.target.apiKey, "<api-key>");
  return out;
}

function normalizeValue(value, key, ctx, principals) {
  if (OPAQUE_KEYS.has(key) && value !== null && value !== undefined && value !== "")
    return `<${key}>`;
  if (TIME_KEYS.has(key) || typeof value === "string" || key === "timestampValue") {
    const masked = runTime(value, ctx);
    if (masked) return masked;
  }
  if (typeof value === "string") return normalizeString(value, ctx, principals);
  if (Array.isArray(value)) return value.map((v) => normalizeValue(v, key, ctx, principals));
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([k, v]) => [k, normalizeValue(v, k, ctx, principals)]),
    );
  }
  return value;
}

/** The recorded form of one REST answer. */
export function normalizeRest(status, text, ctx, principals) {
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    return { status, nonJson: true };
  }
  return { status, body: normalizeValue(body, "", ctx, principals) };
}

/** A proto-loader oneof discriminator: a `*Type`/`kind`/`result`/`consistencySelector` naming a sibling. */
const isDiscriminator = (key, value, object) =>
  (key === "kind" ||
    key.endsWith("Type") ||
    key.endsWith("Selector") ||
    key === "result" ||
    key === "operation") &&
  typeof value === "string" &&
  value !== key &&
  Object.hasOwn(object, value);

function isDefault(value) {
  return (
    value === null ||
    value === undefined ||
    value === 0 ||
    value === "0" ||
    value === "" ||
    value === false ||
    (Array.isArray(value) && value.length === 0) ||
    (Buffer.isBuffer(value) && value.length === 0) ||
    (value?.type === "Buffer" && Array.isArray(value.data) && value.data.length === 0)
  );
}

function timestampText({ seconds, nanos }) {
  const base = new Date(Number(seconds) * 1000).toISOString().replace(/\.\d{3}Z$/, "");
  const fraction = String(nanos ?? 0)
    .padStart(9, "0")
    .replace(/0+$/, "");
  return `${base}${fraction ? `.${fraction}` : ""}Z`;
}

/** A proto-loader message in its REST JSON shape: defaults dropped, timestamps as text. */
export function grpcToJson(value) {
  if (Buffer.isBuffer(value)) return value.length ? value.toString("base64") : undefined;
  if (value?.type === "Buffer" && Array.isArray(value.data))
    return value.data.length ? Buffer.from(value.data).toString("base64") : undefined;
  if (Array.isArray(value)) return value.map(grpcToJson);
  if (value && typeof value === "object") {
    const keys = Object.keys(value);
    if (keys.length === 2 && keys.includes("seconds") && keys.includes("nanos"))
      return timestampText(value);
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      if (isDiscriminator(k, v, value)) continue;
      if (k === "nullValue") {
        out[k] = null;
        continue;
      }
      // A present wrapper or map entry keeps its (possibly default) value.
      const converted = grpcToJson(v);
      if (k === "value" && keys.length === 1) return converted ?? 0;
      if (
        isDefault(converted) &&
        !["fields", "booleanValue", "integerValue", "doubleValue"].includes(k)
      )
        continue;
      out[k] = converted;
    }
    return out;
  }
  if (typeof value === "string" && /^-?\d+$/.test(value) && value.length > 15) return value;
  return value;
}

/** The recorded form of one gRPC answer: status code, its text, and every message. */
export function normalizeGrpc({ code, details, messages }, ctx, principals) {
  return {
    grpc: code,
    details: normalizeString(details ?? "", ctx, principals),
    ...(messages.length
      ? { messages: normalizeValue(messages.map(grpcToJson), "", ctx, principals) }
      : {}),
  };
}

const TRANSIENT_GRPC = new Set([4, 8, 13, 14]);

/** A recorded answer that says nothing about behaviour: transport failure, 5xx, rate limit. */
export function isTransient(recorded) {
  if (!recorded) return false;
  if (recorded.status === -1) return recorded.dependencyTransient === true;
  if (recorded.transport || recorded.publication === "unsettled") return true;
  if (recorded.grpc !== undefined) return TRANSIENT_GRPC.has(recorded.grpc);
  return recorded.status === 0 || recorded.status === 429 || recorded.status >= 500;
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

/** Row keys (`program#step`) whose two recordings differ. */
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
