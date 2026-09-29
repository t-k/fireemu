import { createHash } from "node:crypto";

// Closed response schemas for the declared STORAGE-RULES requests. A schema names what a response *is*; whether that is
// the response a step needs is the controller's decision. Kinds without a reviewed schema fail closed. This module
// performs no I/O and holds no secret: download tokens and other bearer values never reach a fact.
const nativeLength = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(Uint8Array.prototype), "length").get;
const kindEntry = (implemented) => Object.freeze({ implemented });
const IMPLEMENTED = ["subject-observed", "settle-read", "gcs-seed-upload", "gcs-delete", "gcs-metadata-read", "gcs-media-read"];
const PENDING = [
  "gcs-patch", "gcs-prefix-list", "firebase-create-token", "session-start", "session-command",
  "firestore-read", "firestore-write",
  "rules-test", "rules-release-read", "rules-release-create", "rules-release-patch", "rules-release-delete",
  "rules-ruleset-create", "rules-ruleset-read", "rules-ruleset-delete", "rules-list-page",
  "preflight-identity", "preflight-project", "preflight-key-metadata", "preflight-key-string", "preflight-permissions",
  "preflight-bucket-metadata", "preflight-bucket-iam", "preflight-bucket-permissions", "preflight-database", "preflight-project-iam",
  "credential-cache", "auth",
];
export const ACCEPTANCE_KINDS = Object.freeze(Object.fromEntries([...IMPLEMENTED.map((k) => [k, kindEntry(true)]), ...PENDING.map((k) => [k, kindEntry(false)])]));
export const unimplementedKinds = () => Object.freeze(Object.keys(ACCEPTANCE_KINDS).filter((kind) => !ACCEPTANCE_KINDS[kind].implemented));

const PREFLIGHT_KINDS = new Map([
  ["owner/identity", "preflight-identity"], ["query/project", "preflight-project"], ["idp/project", "preflight-project"],
  ["query/key-metadata", "preflight-key-metadata"], ["idp/key-metadata", "preflight-key-metadata"],
  ["query/key-string", "preflight-key-string"], ["idp/key-string", "preflight-key-string"],
  ["query/permissions", "preflight-permissions"], ["idp/permissions", "preflight-permissions"],
  ["bucket/metadata", "preflight-bucket-metadata"], ["bucket/iam", "preflight-bucket-iam"], ["bucket/permissions", "preflight-bucket-permissions"],
  ["query/database", "preflight-database"], ["query/iam", "preflight-project-iam"],
]);
const GCS_KINDS = { upload: "gcs-seed-upload", patch: "gcs-patch", delete: "gcs-delete", "get-metadata": "gcs-metadata-read", "get-media": "gcs-media-read", list: "gcs-prefix-list" };
const bad = (message) => { throw new Error(message); };
// Every family and its stages, as the full manifest declares them. A row outside this table has no kind.
const STAGES = new Map(Object.entries({
  declared: /^(?:baseline|before|after|cleanup|setup|step|subject|comparison)$/,
  management: /^(?:absence-media|absence-metadata|after-media|after-metadata|baseline-media|baseline-metadata|before-media|before-metadata|cleanup-metadata|delete|prefix-empty|restore-owner-media|seed|seed-media|seed-metadata|subject)$/,
  "recovery-object": /^(?:metadata|delete|absence-metadata|absence-media)$/,
  "recovery-document": /^(?:current|delete|absence)$/,
  "recovery-session": /^(?:current|cancel|terminal)$/,
  "recovery-control": /^restore-owner-media$/,
  "recovery-prefix": /^prefix-empty$/,
  "recovery-ruleset": /^(?:current|delete|absence)$/,
  ruleset: /^(?:create|read-source|delete|absence)$/,
  "rulesets-list": /^page-[1-9]\d*$/,
  compile: /^(?:before|after-invalid|test)$/,
  release: /^(?:entry|no-release-entry-after|final|before-switch|publish|after-switch|owner-before-delete|delete|bucket-absence|bucketless-absence)$/,
  settle: /^cycle-[1-9]\d*$/,
  preflight: /^readback$/,
  "credential-cache": /^acquire$/,
  auth: /^(?:absence|baseline|clear-claims|create|delete|lookup-claims|lookup-created|lookup-plain|lookup-revoked|lookup-token|revoke|set-claims|sign-in|sign-in-plain|sign-up)$/,
}));

/** The closed acceptance kind of one declared manifest row. */
export function acceptanceKindOf(row) {
  const fail = () => bad("invalid acceptance kind");
  if (!row || typeof row !== "object" || typeof row.family !== "string" || typeof row.stage !== "string" || typeof row.id !== "string" || !row.request || typeof row.request !== "object") fail();
  const { family, stage, service, request } = row;
  if (!STAGES.get(family)?.test(stage)) fail();
  const { method, operation, dialect } = request;
  if (!["GET", "POST", "PATCH", "DELETE"].includes(method)) fail();
  if (family === "credential-cache") return "credential-cache";
  if (family === "auth") return "auth";
  if (family === "preflight") return PREFLIGHT_KINDS.get(row.id.replace(/^preflight\//, "")) ?? fail();
  if (family === "compile") return stage === "test" ? "rules-test" : ["before", "after-invalid"].includes(stage) ? "rules-release-read" : fail();
  if (family === "ruleset" || family === "recovery-ruleset") return stage === "create" ? "rules-ruleset-create" : stage === "delete" ? "rules-ruleset-delete" : ["read-source", "current", "absence"].includes(stage) ? "rules-ruleset-read" : fail();
  if (family === "rulesets-list") return "rules-list-page";
  if (family === "release") return { GET: "rules-release-read", POST: "rules-release-create", PATCH: "rules-release-patch", DELETE: "rules-release-delete" }[method];
  if (family === "settle") return service === "storage" && dialect === "firebase" && operation === "get-media" && method === "GET" ? "settle-read" : fail();
  if (service === "firestore") return method === "GET" ? "firestore-read" : "firestore-write";
  if (service !== "storage") fail();
  if (stage === "subject" || stage === "comparison") return "subject-observed";
  const headers = request.headers && typeof request.headers === "object" ? request.headers : {};
  if (dialect === "firebase") {
    if (operation === "create-token") return "firebase-create-token";
    if (operation === "upload" && headers["x-goog-upload-command"] === "start") return "session-start";
    if (request.sessionUrlReference) return "session-command";
    if (["get-media", "upload"].includes(operation) && request.credential === "user-a") return "subject-observed";
    fail();
  }
  if (dialect === "gcs" && Object.hasOwn(GCS_KINDS, operation)) return GCS_KINDS[operation];
  return fail();
}

function readResponse(value) {
  const fail = () => bad("invalid acceptance response");
  if (!value || typeof value !== "object" || Object.getPrototypeOf(value) !== Object.prototype) fail();
  const keys = Reflect.ownKeys(value);
  if (keys.length !== 3 || !["status", "rawHeaders", "bytes"].every((key) => keys.includes(key))) fail();
  for (const key of keys) {
    const field = Object.getOwnPropertyDescriptor(value, key);
    if (!field?.enumerable || !Object.hasOwn(field, "value")) fail();
  }
  const { status, rawHeaders, bytes } = value;
  if (!Number.isInteger(status) || status < 100 || status > 599) fail();
  if (!Array.isArray(rawHeaders) || Object.getPrototypeOf(rawHeaders) !== Array.prototype || rawHeaders.length % 2 !== 0 || rawHeaders.length > 512) fail();
  const headerKeys = Reflect.ownKeys(rawHeaders);
  if (headerKeys.length !== rawHeaders.length + 1) fail();
  for (const key of headerKeys) {
    if (key === "length") continue;
    const field = Object.getOwnPropertyDescriptor(rawHeaders, key);
    if (typeof key !== "string" || !/^(?:0|[1-9]\d*)$/.test(key) || !field?.enumerable || !Object.hasOwn(field, "value") || typeof field.value !== "string") fail();
  }
  if (!Buffer.isBuffer(bytes) || Object.getPrototypeOf(bytes) !== Buffer.prototype) fail();
  const size = nativeLength.call(bytes);
  const headers = new Map();
  for (let index = 0; index < rawHeaders.length; index += 2) {
    const name = rawHeaders[index].toLowerCase();
    headers.set(name, [...(headers.get(name) ?? []), rawHeaders[index + 1]]);
  }
  const copy = Buffer.alloc(size);
  Uint8Array.prototype.set.call(copy, bytes);
  return { status, headers, bytes: copy };
}

const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const single = (headers, name) => (headers.get(name)?.length === 1 ? headers.get(name)[0] : headers.has(name) ? null : undefined);
function jsonBody(response) {
  const type = single(response.headers, "content-type");
  if (typeof type !== "string" || !/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(type.trim())) return undefined;
  try { return JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(response.bytes)); } catch { return undefined; }
}
const isObject = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const decimal = (value, max = 19) => typeof value === "string" && new RegExp(`^[1-9]\\d{0,${max - 1}}$`).test(value);
const size = (value) => typeof value === "string" && /^(?:0|[1-9]\d{0,15})$/.test(value);
const common = (response) => Object.freeze({ status: response.status, bodyBytes: response.bytes.length, bodySha256: digest(response.bytes) });
const result = (kind, verdict, facts) => Object.freeze({ kind, verdict, facts: Object.freeze(facts) });
const unexpected = (kind, response) => result(kind, "unexpected", common(response));

function storageObject(body, bucket, name) {
  return isObject(body) && body.kind === "storage#object" && body.bucket === bucket && body.name === name && decimal(body.generation) && decimal(body.metageneration);
}
function gcsNotFound(response) {
  const body = jsonBody(response);
  return response.status === 404 && isObject(body) && isObject(body.error) && body.error.code === 404 && Array.isArray(body.error.errors) && isObject(body.error.errors[0]) && body.error.errors[0].reason === "notFound";
}
function objectContext(row, prefix) {
  const match = new RegExp(`^${prefix}/b/([^/]+)/o(?:/|$)`).exec(row.request.path ?? "");
  if (!match || typeof row.request.objectName !== "string") bad("invalid acceptance kind");
  return { bucket: match[1], name: row.request.objectName };
}

const CLASSIFIERS = {
  "subject-observed": (row, response) => result("subject-observed", "observed", common(response)),
  "settle-read": (row, response, ctx) => {
    const body = response.status === 403 ? jsonBody(response) : undefined;
    if (response.status === 200 && digest(response.bytes) === ctx.expectedSha256) return result("settle-read", "allowed", common(response));
    if (isObject(body) && isObject(body.error) && body.error.code === 403 && typeof body.error.message === "string" && body.error.message.startsWith("Permission denied")) return result("settle-read", "denied", common(response));
    return result("settle-read", "other", common(response));
  },
  "gcs-seed-upload": (row, response) => {
    const { bucket, name } = objectContext(row, "/upload/storage/v1");
    const declared = row.request.body?.base64;
    if (typeof declared !== "string") bad("invalid acceptance kind");
    const body = jsonBody(response);
    if (response.status === 200 && storageObject(body, bucket, name) && body.size === String(Buffer.from(declared, "base64").length) && body.metageneration === "1") {
      return result("gcs-seed-upload", "accepted", { status: 200, generation: body.generation, metageneration: body.metageneration, size: body.size });
    }
    return unexpected("gcs-seed-upload", response);
  },
  "gcs-delete": (row, response) => (
    response.status === 204 && response.bytes.length === 0 ? result("gcs-delete", "accepted", { status: 204, deleteAcknowledged: true }) : unexpected("gcs-delete", response)
  ),
  "gcs-metadata-read": (row, response) => {
    const { bucket, name } = objectContext(row, "/storage/v1");
    const body = jsonBody(response);
    if (response.status === 200 && storageObject(body, bucket, name) && size(body.size)) {
      const tokens = isObject(body.metadata) ? body.metadata.firebaseStorageDownloadTokens : undefined;
      return result("gcs-metadata-read", "present", { status: 200, generation: body.generation, metageneration: body.metageneration, size: body.size, hasDownloadToken: typeof tokens === "string" && tokens.length > 0 });
    }
    if (gcsNotFound(response)) return result("gcs-metadata-read", "absent", { status: 404 });
    return unexpected("gcs-metadata-read", response);
  },
  "gcs-media-read": (row, response) => {
    objectContext(row, "/storage/v1");
    if (response.status === 200) {
      const generation = single(response.headers, "x-goog-generation");
      if (generation === null || (generation !== undefined && !decimal(generation))) return unexpected("gcs-media-read", response);
      return result("gcs-media-read", "present", { ...common(response), ...(generation === undefined ? {} : { generation }) });
    }
    if (gcsNotFound(response)) return result("gcs-media-read", "absent", { status: 404 });
    return unexpected("gcs-media-read", response);
  },
};

function checkContext(kind, ctx) {
  const fail = () => bad("invalid acceptance context");
  if (kind !== "settle-read") { if (ctx !== undefined) fail(); return; }
  if (!ctx || typeof ctx !== "object" || Object.getPrototypeOf(ctx) !== Object.prototype) fail();
  const keys = Reflect.ownKeys(ctx);
  const field = Object.getOwnPropertyDescriptor(ctx, "expectedSha256");
  if (keys.length !== 1 || !field?.enumerable || !Object.hasOwn(field, "value") || typeof field.value !== "string" || !/^[0-9a-f]{64}$/.test(field.value)) fail();
}

/** Classify one complete response of a declared row. Unknown or unreviewed kinds throw. */
export function classifyResponse(row, response, ctx) {
  const kind = acceptanceKindOf(row);
  if (!ACCEPTANCE_KINDS[kind].implemented) bad("acceptance kind not implemented");
  checkContext(kind, ctx);
  return CLASSIFIERS[kind](row, readResponse(response), ctx);
}
