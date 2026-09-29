import { createHash } from "node:crypto";
import { isValidRefValue, referenceOf } from "./runtime-refs.mjs";

// Turns one manifest row into the exact request the transport may send. Nothing is sent from here and no credential value
// is read: the dispatch gate adds authorization later. Every target must match one closed route for its origin, method
// and path, must stay inside the owned bucket, prefix, documents and Rules resources, and every run-time value comes from
// the caller's resolver and is checked against its grammar again. Any failure is the one fixed error.
const QUERY = "fireemu-oracle-query";
const IDP = "fireemu-oracle-idp";
const GCS = "https://storage.googleapis.com";
const FIREBASE = "https://firebasestorage.googleapis.com";
const FIRESTORE = "https://firestore.googleapis.com";
const RULES = "https://firebaserules.googleapis.com";
const MAX_BODY_BYTES = 256 * 1024;
const CREDENTIALS = new Set(["admin", "user-a", "user-b", "user-plain", "anonymous", "revoked-token", "foreign-project-token", "malformed-token", "malformed-oauth", "api-key-only", "owner-oauth", "adc-refresh"]);
const QUERY_REFS = new Set(["generation", "metageneration", "update-time", "page-token", "download-token"]);
const BODY_REFS = new Set(["ruleset-name"]);
const FORBIDDEN_HEADERS = new Set(["authorization", "cookie", "host", "connection", "content-length", "transfer-encoding", "proxy-authorization", "proxy-connection", "upgrade", "expect", "accept-encoding", "x-goog-user-project"]);
const escape = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const bad = () => { throw new Error("invalid target row"); };
const sha256 = (value) => createHash("sha256").update(value).digest("hex");

function closedRecord(value, keys) {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) return false;
  const actual = Reflect.ownKeys(value);
  if (actual.length !== keys.length || actual.some((key) => !keys.includes(key))) return false;
  return keys.every((key) => { const field = Object.getOwnPropertyDescriptor(value, key); return field?.enumerable && Object.hasOwn(field, "value"); });
}

export function createTargetBuilder(options) {
  const fail = () => { throw new Error("invalid target builder options"); };
  if (!closedRecord(options, ["manifest", "digestSalt"])) fail();
  const { manifest, digestSalt } = options;
  if (typeof digestSalt !== "string" || !/^[0-9a-f]{64}$/.test(digestSalt)) fail();
  if (!manifest || manifest.sendAuthorized !== false || !Array.isArray(manifest.rows) || manifest.rows.length === 0 || typeof manifest.binding?.bucket !== "string" || typeof manifest.binding?.prefix !== "string" || !Array.isArray(manifest.resources?.documents)) fail();
  const { bucket, prefix } = manifest.binding;
  if (!/^[a-z0-9][a-z0-9._-]{2,221}$/.test(bucket) || !/^STORAGE-RULES\/[a-z0-9-]+\/$/.test(prefix)) fail();
  const ids = new Set(manifest.rows.map((row) => row.id));
  const documents = new Set(manifest.resources.documents);
  const B = escape(bucket);
  const owned = (name) => typeof name === "string" && name.startsWith(prefix) && name.length > prefix.length && name.length <= 1024 && !/[\0-\x1f\x7f]/.test(name) && !name.split("/").some((part) => part === "" || part === "." || part === "..");
  const ownedPrefix = (value) => typeof value === "string" && value.startsWith(prefix) && !/[\0-\x1f\x7f]/.test(value) && !value.split("/").slice(0, -1).some((part) => part === "." || part === "..");
  const subset = (query, allowed) => Object.keys(query).every((key) => allowed.includes(key));
  const objectSegment = (segment, request) => {
    let name;
    try { name = decodeURIComponent(segment); } catch { return false; }
    return encodeURIComponent(name) === segment && name === request.objectName && owned(name);
  };
  const numeric = (value, max) => typeof value === "string" && /^[1-9]\d{0,3}$/.test(value) && Number(value) <= max;
  const documentName = (path) => `projects/${QUERY}/databases/(default)/documents/${path}`;
  const routes = [
    { origin: GCS, methods: ["GET", "PATCH", "DELETE"], path: new RegExp(`^/storage/v1/b/${B}/o/([^/]+)$`), check: (m, q, r, method) => objectSegment(m[1], r) && subset(q, { GET: ["alt"], PATCH: ["ifGenerationMatch", "ifMetagenerationMatch"], DELETE: ["ifGenerationMatch"] }[method]) && (q.alt === undefined || q.alt === "media") },
    { origin: GCS, methods: ["POST"], path: new RegExp(`^/upload/storage/v1/b/${B}/o$`), check: (m, q, r) => subset(q, ["name", "uploadType", "ifGenerationMatch"]) && q.name === r.objectName && owned(q.name) && q.uploadType === "media" && (q.ifGenerationMatch === undefined || q.ifGenerationMatch === "0") },
    { origin: GCS, methods: ["GET"], path: new RegExp(`^/storage/v1/b/${B}/o$`), check: (m, q) => subset(q, ["prefix", "maxResults"]) && ownedPrefix(q.prefix) && numeric(q.maxResults, 1000) },
    { origin: GCS, methods: ["GET"], path: new RegExp(`^/storage/v1/b/${B}(?:/iam|/iam/testPermissions)?$`), family: "preflight", check: (m, q) => subset(q, ["optionsRequestedPolicyVersion", "permissions"]) },
    { origin: FIREBASE, methods: ["GET", "PATCH", "DELETE", "POST"], path: new RegExp(`^/v0/b/${B}/o/([^/]+)$`), check: (m, q, r, method) => objectSegment(m[1], r) && subset(q, { GET: ["alt", "token"], PATCH: [], DELETE: [], POST: ["create_token"] }[method]) && (q.alt === undefined || q.alt === "media") && (q.create_token === undefined || q.create_token === "true") },
    { origin: FIREBASE, methods: ["POST"], path: new RegExp(`^/v0/b/${B}/o$`), check: (m, q, r) => subset(q, ["name", "uploadType"]) && q.name === r.objectName && owned(q.name) && (q.uploadType === undefined || ["multipart", "resumable"].includes(q.uploadType)) },
    { origin: FIREBASE, methods: ["GET"], path: new RegExp(`^/v0/b/${B}/o$`), check: (m, q) => subset(q, ["prefix", "maxResults"]) && ownedPrefix(q.prefix) && numeric(q.maxResults, 1000) },
    { origin: FIRESTORE, methods: ["GET", "PATCH", "DELETE"], path: /^\/v1\/projects\/fireemu-oracle-query\/databases\/\(default\)\/documents\/([A-Za-z0-9._\/-]+)$/, check: (m, q, r, method) => documents.has(documentName(m[1])) && subset(q, { GET: [], PATCH: ["currentDocument.updateTime", "updateMask.fieldPaths"], DELETE: ["currentDocument.updateTime"] }[method]) },
    { origin: FIRESTORE, methods: ["POST"], path: /^\/v1\/projects\/fireemu-oracle-query\/databases\/\(default\)\/documents\/([A-Za-z0-9._\/-]+)$/, check: (m, q) => subset(q, ["documentId"]) && typeof q.documentId === "string" && documents.has(`${documentName(m[1])}/${q.documentId}`) },
    { origin: FIRESTORE, methods: ["GET"], path: /^\/v1\/projects\/fireemu-oracle-query\/databases\/\(default\)$/, family: "preflight", check: (m, q) => subset(q, []) },
    { origin: RULES, methods: ["POST"], path: new RegExp(`^/v1/projects/${QUERY}:test$`), check: (m, q) => subset(q, []) },
    { origin: RULES, methods: ["POST", "GET"], path: new RegExp(`^/v1/projects/${QUERY}/rulesets$`), check: (m, q, r, method) => subset(q, method === "GET" ? ["pageSize", "pageToken"] : []) && (q.pageSize === undefined || q.pageSize === "100") },
    { origin: RULES, methods: ["GET", "DELETE"], path: new RegExp(`^/v1/projects/${QUERY}/rulesets/[A-Za-z0-9_-]{1,128}$`), check: (m, q) => subset(q, []) },
    { origin: RULES, methods: ["POST"], path: new RegExp(`^/v1/projects/${QUERY}/releases$`), check: (m, q) => subset(q, []) },
    { origin: RULES, methods: ["GET", "PATCH", "DELETE"], path: new RegExp(`^/v1/projects/${QUERY}/releases/firebase\\.storage/${B}$`), check: (m, q) => subset(q, []) },
    { origin: RULES, methods: ["GET"], path: new RegExp(`^/v1/projects/${QUERY}/releases/firebase\\.storage$`), check: (m, q) => subset(q, []) },
    { origin: "https://www.googleapis.com", methods: ["GET"], path: /^\/oauth2\/v2\/userinfo$/, family: "preflight", check: (m, q) => subset(q, []) },
    { origin: "https://cloudresourcemanager.googleapis.com", methods: ["GET"], path: /^\/v3\/projects\/\d{1,20}$/, family: "preflight", check: (m, q) => subset(q, []) },
    { origin: "https://cloudresourcemanager.googleapis.com", methods: ["POST"], path: /^\/v3\/projects\/\d{1,20}:(?:testIamPermissions|getIamPolicy)$/, family: "preflight", check: (m, q) => subset(q, []) },
    { origin: "https://apikeys.googleapis.com", methods: ["GET"], path: /^\/v2\/projects\/\d{1,20}\/locations\/global\/keys\/[A-Za-z0-9_-]{1,128}(?:\/keyString)?$/, family: "preflight", check: (m, q) => subset(q, []) },
  ];

  // Reference objects come in two shapes: the runtime reference and the corpus's own (Firestore-program values, session URLs, tokens).
  function resolveValue(reference, allowed, rowId, resolve) {
    const found = reference && typeof reference === "object" && reference.kind !== "runtime-reference" ? referenceOf(reference) : null;
    let type;
    if (found) type = found.type;
    else {
      if (!closedRecord(reference, ["kind", "type", "key", "resolveOnlyAfterDurableProof"]) || reference.kind !== "runtime-reference" || reference.resolveOnlyAfterDurableProof !== true) bad();
      type = reference.type;
    }
    if (!allowed.has(type)) bad();
    const value = resolve(reference, rowId);
    if (!isValidRefValue(type, value)) bad();
    return value;
  }
  const refType = (entry) => (entry && typeof entry === "object" && entry.kind !== "runtime-reference" ? referenceOf(entry)?.type : entry?.type);
  const encode = (text) => encodeURIComponent(text);
  const issued = new WeakSet();
  const digestOf = ({ rowId, method, url, headers, body, credential, project }) => sha256([digestSalt, JSON.stringify({ rowId, method, url, headers, body: body === null ? null : sha256(body), credential, project })].join("\0"));

  function build(row, resolve) {
    if (!row || typeof row !== "object" || typeof row.id !== "string" || !ids.has(row.id) || typeof resolve !== "function") bad();
    const request = row.request;
    if (!request || typeof request !== "object" || ["auth", "credential-cache"].includes(row.family) || !CREDENTIALS.has(request.credential)) bad();
    if (typeof request.origin !== "string" || !["GET", "POST", "PATCH", "DELETE"].includes(request.method)) bad();
    const literal = { ...(request.query ?? {}) };
    const query = Object.create(null); const pieces = []; const redactedPieces = [];
    for (const [key, value] of Object.entries(literal)) {
      if (!/^[A-Za-z][A-Za-z0-9._]{0,63}$/.test(key)) bad();
      const list = Array.isArray(value) ? value : [value];
      if (Array.isArray(value) && value.length === 0) bad();
      const resolved = list.map((entry) => {
        // A parameter that carries a capability must come from a bound reference, never from a literal in a row.
        if (typeof entry === "string") { if (entry.length > 2048 || /[\0-\x1f\x7f]/.test(entry) || /^(?:token|key|upload_id|access_token|id_token|refresh_token|sig|signature)$/i.test(key)) bad(); return { text: entry, redacted: entry }; }
        if (entry && typeof entry === "object" && !Array.isArray(value)) return { text: resolveValue(entry, QUERY_REFS, row.id, resolve), redacted: `<ref:${refType(entry)}>` };
        return bad();
      });
      query[key] = Array.isArray(value) ? resolved.map((entry) => entry.text) : resolved[0].text;
      for (const entry of resolved) { pieces.push(`${encode(key)}=${encode(entry.text)}`); redactedPieces.push(`${encode(key)}=${entry.redacted.startsWith("<ref:") ? entry.redacted : encode(entry.redacted)}`); }
    }
    let sessionUrl = null;
    if (request.sessionUrlReference !== undefined) {
      if (request.method !== "POST" || (request.path !== null && request.path !== undefined) || pieces.length !== 0 || request.pathReference !== undefined) bad();
      sessionUrl = resolveValue(request.sessionUrlReference, new Set(["session-url"]), row.id, resolve);
    }
    let path; let redactedPath;
    if (sessionUrl !== null) {
      path = new URL(sessionUrl).pathname;
      redactedPath = `${path}?<ref:session-url>`;
    } else if (request.pathReference !== undefined) {
      if (request.path !== null && request.path !== undefined) bad();
      path = resolveValue(request.pathReference, new Set(["ruleset-path"]), row.id, resolve);
      redactedPath = "<ref:ruleset-path>";
    } else {
      path = request.path; redactedPath = request.path;
    }
    if (typeof path !== "string" || !path.startsWith("/") || /[\0-\x1f\x7f?#\\]|\.\.\/|\/\.\.|\/\.\/|%2e|%2E|%00|%2f|%5c/i.test(path.replace(/%2F/g, "%20"))) bad();
    const url = sessionUrl ?? `${request.origin}${path}${pieces.length ? `?${pieces.join("&")}` : ""}`;
    const parsed = new URL(url);
    if (parsed.href !== url || parsed.protocol !== "https:" || `${parsed.protocol}//${parsed.host}` !== request.origin || parsed.username || parsed.password || parsed.hash) bad();
    if (sessionUrl !== null) {
      // A resumable session URL: the owned bucket's object collection, this row's object, the resumable protocol, and only the known parameters, once each.
      const seen = new Map();
      for (const [key, value] of parsed.searchParams) { if (seen.has(key) || !["name", "upload_id", "upload_protocol", "uploadType"].includes(key)) bad(); seen.set(key, value); }
      if (request.origin !== FIREBASE || parsed.pathname !== `/v0/b/${bucket}/o` || seen.get("name") !== request.objectName || !owned(seen.get("name")) || seen.get("upload_protocol") !== "resumable" || !/^[A-Za-z0-9._-]{8,256}$/.test(seen.get("upload_id") ?? "")) bad();
    }
    const matches = sessionUrl !== null ? [{ route: { check: () => true }, match: [] }] : routes.filter((route) => route.origin === request.origin && route.methods.includes(request.method) && (route.family === undefined || route.family === row.family)).map((route) => ({ route, match: route.path.exec(path) })).filter((entry) => entry.match);
    if (matches.length !== 1 || !matches[0].route.check(matches[0].match, query, request, request.method)) bad();
    const headers = {};
    for (const [name, value] of Object.entries(request.headers ?? {})) {
      if (!/^[a-z0-9-]{1,64}$/.test(name) || FORBIDDEN_HEADERS.has(name) || typeof value !== "string" || !/^[\x20-\x7e]{0,1024}$/.test(value)) bad();
      headers[name] = value;
    }
    let body = null;
    if (request.body !== null && request.body !== undefined) {
      if (closedRecord(request.body, ["base64"])) {
        const text = request.body.base64;
        if (typeof text !== "string" || !/^[A-Za-z0-9+/]*={0,2}$/.test(text) || text.length > Math.ceil((MAX_BODY_BYTES * 4) / 3) + 4) bad();
        body = Buffer.from(text, "base64");
        if (body.toString("base64") !== text || body.length > MAX_BODY_BYTES) bad();
      } else if (closedRecord(request.body, ["json"])) {
        const walk = (value, depth = 0) => {
          if (depth > 16) bad();
          if (value === null || ["string", "boolean"].includes(typeof value)) return value;
          if (typeof value === "number") { if (!Number.isFinite(value)) bad(); return value; }
          if (Array.isArray(value)) return value.map((item) => walk(item, depth + 1));
          if (value && typeof value === "object" && Object.getPrototypeOf(value) === Object.prototype) {
            if (value.kind === "runtime-reference") return resolveValue(value, BODY_REFS, row.id, resolve);
            return Object.fromEntries(Object.entries(value).map(([key, inner]) => [key, walk(inner, depth + 1)]));
          }
          return bad();
        };
        body = Buffer.from(JSON.stringify(walk(request.body.json)));
        if (body.length > MAX_BODY_BYTES) bad();
        if (headers["content-type"] === undefined) headers["content-type"] = "application/json; charset=utf-8";
      } else bad();
    }
    // The project a request is billed to is one of the two sandbox projects and agrees with the project its path names.
    const project = request.project === undefined ? QUERY : request.project;
    if (project !== QUERY && project !== IDP) bad();
    const named = /\/projects\/(fireemu-oracle-[a-z]+)(?=[/:]|$)/.exec(new URL(url).pathname);
    if (named !== null && named[1] !== project) bad();
    const sorted = Object.fromEntries(Object.entries(headers).sort(([a], [b]) => (a < b ? -1 : 1)));
    const targetSha256 = digestOf({ rowId: row.id, method: request.method, url, headers: sorted, body, credential: request.credential, project });
    const redacted = `${request.method} ${request.origin}${redactedPath}${redactedPieces.length ? `?${redactedPieces.join("&")}` : ""}`;
    const prepared = { rowId: row.id, credential: request.credential, project, redacted, targetSha256 };
    Object.defineProperty(prepared, "spec", { value: Object.freeze({ url, method: request.method, headers: Object.freeze(sorted), body }), enumerable: false });
    Object.freeze(prepared);
    issued.add(prepared);
    return prepared;
  }

  /** Whether this exact object was issued here and its request still hashes to the digest recorded for it. */
  function verify(prepared) {
    try {
      if (!prepared || typeof prepared !== "object" || !issued.has(prepared) || !prepared.spec) return false;
      const { url, method, headers, body } = prepared.spec;
      return digestOf({ rowId: prepared.rowId, method, url, headers, body, credential: prepared.credential, project: prepared.project }) === prepared.targetSha256;
    } catch { return false; }
  }

  return Object.freeze({ prepare(row, resolve) { try { return build(row, resolve); } catch { return bad(); } }, verify });
}
