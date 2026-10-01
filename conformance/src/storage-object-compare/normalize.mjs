// Normalizes one captured Storage exchange (a production recording or a fireemu run) into the form
// the comparison judges: the status, the exact content type, the headers that are not
// infrastructure, and the body with only the run-specific values masked. Every mask has a reason
// (NORMALIZATIONS). Nothing else is rewritten: a value that is deterministic for the same request
// (sizes, md5Hash, crc32c, metageneration, an object's bytes, an error message) is compared exactly.

import { createHash } from "node:crypto";

export const NORMALIZATION_VERSION = 1;

/** The masks, each with the reason that it is run-specific, and where it applies. */
export const NORMALIZATIONS = Object.freeze([
  {
    id: "RUN",
    mask: "<RUN>",
    reason: "the run's 20-hex ID is chosen at random for each run and is in every object name",
  },
  {
    id: "BUCKET",
    mask: "<BUCKET>",
    reason: "the bucket differs between the production project and a local run",
  },
  {
    id: "PROJECT",
    mask: "<PROJECT>",
    reason: "the project differs between the production project and a local run",
  },
  {
    id: "GEN",
    mask: "<GEN:n>",
    reason:
      "a generation is a time in production and a counter locally; n is the order of first appearance in the recipe, so equal and different generations stay distinguishable",
  },
  { id: "TIME", mask: "<TIME>", reason: "timestamps (RFC 3339) are the time of the run" },
  {
    id: "HTTPDATE",
    mask: "<HTTPDATE>",
    reason: "HTTP dates (Last-Modified, Expires when relative to now) are the time of the run",
  },
  {
    id: "ETAG",
    mask: "<ETAG>",
    reason:
      "an opaque etag is derived from the generation; a quoted md5 etag is content-derived and is kept",
  },
  {
    id: "TOKEN",
    mask: "<TOKEN:n>",
    reason:
      "download tokens (UUIDs) are random; n is the order of first appearance in the recipe, so reuse and replacement stay distinguishable",
  },
  { id: "UPLOAD_ID", mask: "<UPLOAD_ID>", reason: "resumable session IDs are opaque and random" },
  {
    id: "PAGE_TOKEN",
    mask: "<PAGE_TOKEN>",
    reason:
      "a page token is opaque by contract (production's is the base64 of the last entry's name, which carries the run ID)",
  },
  { id: "JWT", mask: "<JWT>", reason: "ID tokens are credentials and carry times and identifiers" },
  { id: "API_KEY", mask: "<API_KEY>", reason: "an API key is a credential" },
  { id: "UID", mask: "<UID>", reason: "identity ids and refresh tokens are random credentials" },
  {
    id: "OWNER",
    mask: "<OWNER>",
    reason: "a copied object's owner.entity names the requesting principal (an account email)",
  },
  {
    id: "EPOCH",
    mask: "<EPOCH>",
    reason:
      "account creation, sign-in and validity times (createdAt, lastLoginAt, validSince and the like) are the time of the run",
  },
  {
    id: "DIGEST",
    mask: "<DIGEST>",
    reason:
      "md5Hash, crc32c and the headers that repeat them, in a recipe whose objects' bytes carry the run ID: the digest of bytes that differ for each run differs for each run",
  },
]);

/** Headers that identify the serving infrastructure or the transport, not the emulator's behavior. */
export const INFRASTRUCTURE_HEADERS = Object.freeze({
  date: "the time of the response",
  server: "the serving front end (UploadServer, ESF), not Storage behavior",
  "alt-svc": "HTTP/3 advertisement of the Google front end",
  "x-guploader-uploadid": "a random identifier of the serving upload server",
  "x-goog-gcs-base-ts": "an internal serving timestamp",
  "content-length": "derived from the body, which is compared",
  "transfer-encoding": "transport framing",
  connection: "transport",
  "keep-alive": "transport",
});

const UUID = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g;
const ISO = /\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z/g;
const HTTPDATE =
  /(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d\d (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4} \d\d:\d\d:\d\d GMT/g;
const STATIC_HTTPDATE = "Mon, 01 Jan 1990 00:00:00 GMT";
const GENERATION = /(?<![\d])\d{16}(?![\d])/g;

/** The state a recipe's masks share: the ordinals of generations and tokens, in order of appearance. */
export function createContext({ runId, bucket, project, contentCarriesRun = false }) {
  for (const [name, value] of Object.entries({ runId, bucket, project }))
    if (typeof value !== "string" || value === "") throw new Error(`context needs ${name}`);
  return { runId, bucket, project, contentCarriesRun, generations: new Map(), tokens: new Map() };
}

const ordinal = (map, value) => {
  if (!map.has(value)) map.set(value, map.size + 1);
  return map.get(value);
};

/** Mask the run-specific values in a string. */
export function maskText(text, ctx) {
  let out = String(text);
  // The bucket contains the project's name; mask the longer one first.
  out = out.split(ctx.bucket).join("<BUCKET>");
  out = out.split(ctx.project).join("<PROJECT>");
  out = out.split(ctx.runId).join("<RUN>");
  out = out.replace(/eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g, "<JWT>");
  out = out.replace(/(upload_id=)[^&"\s]+/g, "$1<UPLOAD_ID>");
  out = out.replace(/AP6rU[A-Za-z0-9_-]{20,}/g, "<UPLOAD_ID>");
  out = out.replace(/([?&](?:pageToken|key)=)[^&"\s]+/g, (_, head) =>
    head.endsWith("key=") ? `${head}<API_KEY>` : `${head}<PAGE_TOKEN>`,
  );
  out = out.replace(UUID, (value) => `<TOKEN:${ordinal(ctx.tokens, value)}>`);
  out = out.replace(ISO, "<TIME>");
  out = out.replace(HTTPDATE, (value) => (value === STATIC_HTTPDATE ? value : "<HTTPDATE>"));
  out = out.replace(GENERATION, (value) => `<GEN:${ordinal(ctx.generations, value)}>`);
  return out;
}

const OPAQUE_ETAG = /^[A-Za-z0-9+/_-]+=*$/;

const DIGEST_HEADERS = new Set(["x-goog-hash", "x-range-md5", "x-goog-running-hash"]);

function maskHeaderValue(name, value, ctx) {
  if (ctx.contentCarriesRun && DIGEST_HEADERS.has(name)) return "<DIGEST>";
  if (name === "etag")
    return /^"[0-9a-f]{32}"$/.test(value) ? (ctx.contentCarriesRun ? "<DIGEST>" : value) : "<ETAG>";
  if (name === "last-modified") return "<HTTPDATE>";
  return maskText(value, ctx);
}

/** The headers of a response, lower-cased, without the infrastructure ones, with the masks applied. */
export function normalizeHeaders(headers, ctx) {
  const out = {};
  for (const [rawName, value] of Object.entries(headers ?? {})) {
    const name = rawName.toLowerCase();
    if (Object.hasOwn(INFRASTRUCTURE_HEADERS, name)) continue;
    out[name] = maskHeaderValue(name, String(value), ctx);
  }
  return Object.fromEntries(Object.entries(out).toSorted(([a], [b]) => (a < b ? -1 : 1)));
}

const SECRET_MEMBERS = new Map([
  ["idToken", "<JWT>"],
  ["id_token", "<JWT>"],
  ["refreshToken", "<UID>"],
  ["refresh_token", "<UID>"],
  ["accessToken", "<JWT>"],
  ["access_token", "<JWT>"],
  ["localId", "<UID>"],
  ["user_id", "<UID>"],
  ["nextPageToken", "<PAGE_TOKEN>"],
]);
const EPOCH_MEMBERS = new Set([
  "createdAt",
  "lastLoginAt",
  "lastRefreshAt",
  "validSince",
  "passwordUpdatedAt",
  "expiresAt",
  "expirationTime",
]);
const DIGEST_MEMBERS = new Set(["md5Hash", "crc32c"]);

function maskJson(value, ctx, key = "", parent = "") {
  if (Array.isArray(value)) return value.map((item) => maskJson(item, ctx, key, parent));
  if (value && typeof value === "object") {
    const out = {};
    for (const name of Object.keys(value).toSorted())
      out[name] = maskJson(value[name], ctx, name, key);
    return out;
  }
  if (typeof value === "string" && parent === "owner" && key === "entity") return "<OWNER>";
  if ((typeof value === "string" || typeof value === "number") && EPOCH_MEMBERS.has(key))
    return "<EPOCH>";
  if (typeof value === "string") {
    if (SECRET_MEMBERS.has(key)) return SECRET_MEMBERS.get(key);
    if (ctx.contentCarriesRun && DIGEST_MEMBERS.has(key)) return "<DIGEST>";
    if (key === "etag") return OPAQUE_ETAG.test(value) ? "<ETAG>" : maskText(value, ctx);
    return maskText(value, ctx);
  }
  return value;
}

const INLINE_BYTES = 4096;

/** The response body as a comparable value: parsed JSON, text, bytes (inline or by digest) or empty. */
export function normalizeBody(bytes, contentType, ctx) {
  if (!bytes || bytes.length === 0) return { type: "empty" };
  const type = String(contentType ?? "")
    .split(";")[0]
    .trim()
    .toLowerCase();
  if (type === "application/json" || type.endsWith("+json")) {
    try {
      return { type: "json", value: maskJson(JSON.parse(bytes.toString("utf8")), ctx) };
    } catch {
      // Not parseable: kept as text below.
    }
  }
  if (type.startsWith("text/") || type.includes("xml") || type === "application/json") {
    const text = bytes.toString("utf8");
    if (!text.includes("\uFFFD")) return { type: "text", value: maskText(text, ctx) };
  }
  // Bytes that carry the run ID are compared with the ID masked.
  const masked = Buffer.from(bytes.toString("latin1").split(ctx.runId).join("<RUN>"), "latin1");
  const sha256 = createHash("sha256").update(masked).digest("hex");
  if (masked.length <= INLINE_BYTES)
    return { type: "bytes", length: masked.length, sha256, base64: masked.toString("base64") };
  return { type: "bytes", length: masked.length, sha256 };
}

/** A route class, for grouping and for the four routes local fireemu does not serve yet. */
export function routeOf(method, pathname) {
  const path = pathname.replace(/%2F/gi, "/");
  const transfer =
    /^\/storage\/v1\/b\/<BUCKET>\/o\/.+?\/(copyTo|rewriteTo)\/b\/<BUCKET>\/o\/.+$/.exec(path);
  if (transfer)
    return `${method} /storage/v1/b/<BUCKET>/o/<NAME>/${transfer[1]}/b/<BUCKET>/o/<NAME>`;
  return `${method} ${path.replace(/^(\/(?:storage\/v1|v0)\/b\/<BUCKET>\/o)\/.+$/, "$1/<NAME>")}`;
}

/**
 * One exchange, normalized. `exchange` has `method`, `url`, `status`, `headers` (the response's) and
 * `body` (a Buffer). The request's query is kept as sorted pairs so that equivalent requests have
 * the same key.
 */
export function normalizeExchange(exchange, ctx) {
  const url = new URL(exchange.url);
  const pathname = maskText(decodeURIComponent(url.pathname), ctx);
  const queryValue = (key, value) => {
    if (key === "pageToken") return "<PAGE_TOKEN>";
    if (key === "key") return "<API_KEY>";
    if (key === "upload_id") return "<UPLOAD_ID>";
    return maskText(value, ctx);
  };
  const query = [...url.searchParams.entries()]
    .map(([key, value]) => [key, queryValue(key, value)])
    .toSorted(([a, x], [b, y]) => (a === b ? (x < y ? -1 : 1) : a < b ? -1 : 1));
  const route = routeOf(exchange.method, pathname);
  const headers = normalizeHeaders(exchange.headers, ctx);
  return {
    method: exchange.method,
    route,
    path: pathname,
    query,
    status: exchange.status,
    contentType: exchange.headers?.["content-type"] ?? null,
    headers,
    body: normalizeBody(exchange.body, exchange.headers?.["content-type"], ctx),
  };
}
