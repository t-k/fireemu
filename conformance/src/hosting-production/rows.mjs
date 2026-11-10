// Shapes one HTTP answer (production edge or local fireemu) into the row the judge compares and
// the closure retains. Rules (pre-submission checklist section 2):
//  - bodies are compared by byte count and digest, never by stored text; a stored text is a
//    convenience copy of small bodies we uploaded or of an error page;
//  - the reserved initialization bodies (`/__/firebase/init.json|js`) hold a web API key and the
//    project number: they keep their byte count, line count and, for the JSON, the key order and
//    the type and byte length of each value, never a value, so a mask hides a value and not a
//    format;
//  - a response with Content-Encoding is compared by its decoded body, not by the wire bytes;
//  - the request origin inside a header value (an absolute Location) becomes `<origin>`, so an
//    absolute and a relative redirect still differ.
import { createHash } from "node:crypto";
import { brotliDecompressSync, gunzipSync, inflateSync } from "node:zlib";

export const ROW_SCHEMA = 1;

/** Headers whose values are compared (exactly unless listed in SHAPE_ONLY). */
export const COMPARED_HEADERS = new Set([
  "content-type",
  "cache-control",
  "location",
  "etag",
  "last-modified",
  "vary",
  "content-encoding",
  "content-length",
  "content-range",
  "accept-ranges",
  "strict-transport-security",
  "allow",
  "content-disposition",
  "x-content-type-options",
  "access-control-allow-origin",
  "refresh",
  "link",
  "set-cookie",
  "x-fixture",
]);
export const COMPARED_PATTERN = /^x-g\d\d$/;
/** Compared by form only: the value depends on the content hash or on the deploy time. */
export const SHAPE_ONLY = new Set(["etag", "last-modified"]);
/** Differ on every request or are set by the edge; recorded by name and value, never compared. */
export const VOLATILE_HEADERS = new Set([
  "date",
  "age",
  "via",
  "server",
  "alt-svc",
  "x-cache",
  "x-cache-hits",
  "x-served-by",
  "x-timer",
  "x-request-id",
  "x-cloud-trace-context",
  "connection",
  "keep-alive",
  "transfer-encoding",
]);

export const isComparedHeader = (name) => COMPARED_HEADERS.has(name) || COMPARED_PATTERN.test(name);

const MAX_TEXT_BYTES = 8192;
const MAX_DECODED_BYTES = 1 << 20;

export const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

/** `value` with every secret replaced by as many `#` (equal length). */
export function maskSecrets(value, secrets) {
  let out = String(value);
  for (const secret of secrets) {
    if (!secret || secret.length < 6) continue;
    out = out.split(secret).join("#".repeat(secret.length));
  }
  return out;
}

export function initKind(target) {
  const path = String(target).split("?")[0];
  if (path === "/__/firebase/init.json") return "init-json";
  if (path === "/__/firebase/init.js") return "init-js";
  return undefined;
}

function decode(bytes, encoding) {
  const limit = { maxOutputLength: MAX_DECODED_BYTES };
  if (encoding === "gzip") return gunzipSync(bytes, limit);
  if (encoding === "br") return brotliDecompressSync(bytes, limit);
  if (encoding === "deflate") return inflateSync(bytes, limit);
  return undefined;
}

const isUtf8 = (bytes) => {
  try {
    new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    return true;
  } catch {
    return false;
  }
};

function initLayout(kind, bytes) {
  const textBody = bytes.toString("utf8");
  if (kind === "init-js") return { lineCount: textBody.split("\n").length };
  try {
    const value = JSON.parse(textBody);
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
      return { unparsed: true };
    }
    const keys = Object.keys(value);
    return {
      keys,
      types: Object.fromEntries(keys.map((k) => [k, typeof value[k]])),
      valueBytes: Object.fromEntries(keys.map((k) => [k, Buffer.byteLength(String(value[k]))])),
    };
  } catch {
    return { unparsed: true };
  }
}

/** Header list `[[name, value], ...]` to `{ lowercaseName: [value, ...] }`, values masked. */
function groupHeaders(pairs, mask) {
  const out = {};
  for (const [name, value] of pairs) {
    const key = String(name).toLowerCase();
    (out[key] ??= []).push(mask(value));
  }
  return out;
}

/**
 * @param spec the corpus request ({ id, condition, also, method, target, infoOnly })
 * @param answer an edge-client answer: { outcome, reason, status, headers: [[n, v]...], body: Buffer }
 * @param ctx { origin: "https://host" | "http://127.0.0.1:port", secrets: string[], version }
 */
export function shapeRow(spec, answer, ctx) {
  const base = {
    schema: ROW_SCHEMA,
    id: spec.id,
    version: ctx.version ?? spec.id.split(".")[0],
    condition: spec.condition,
    ...(spec.also ? { also: spec.also } : {}),
    ...(spec.infoOnly ? { infoOnly: true } : {}),
    method: spec.method,
    target: spec.target,
  };
  if (answer.outcome !== "answered") {
    return { ...base, outcome: "unknown", reason: String(answer.reason ?? "no-answer") };
  }
  const mask = (value) =>
    maskSecrets(String(value), ctx.secrets).split(ctx.origin).join("<origin>");
  const headers = groupHeaders(answer.headers, mask);
  const body = answer.body ?? Buffer.alloc(0);
  const row = {
    ...base,
    outcome: "answered",
    status: answer.status,
    headers,
    headerNames: Object.keys(headers).toSorted(),
    bodyBytes: body.length,
  };
  const encoding = headers["content-encoding"]?.[0]?.toLowerCase();
  const kind = initKind(spec.target);
  let plain = body;
  if (encoding && encoding !== "identity") {
    try {
      plain = decode(body, encoding) ?? body;
      // A reserved init body holds the API key and the number: it keeps no digest of any form,
      // not even of its decoded bytes.
      if (!(kind && answer.status === 200)) {
        row.decodedBytes = plain.length;
        row.decodedSha256 = sha256(plain);
      }
    } catch {
      row.decodeError = encoding;
    }
  }
  if (kind && answer.status === 200) {
    row.bodyKind = kind;
    row.layout = initLayout(kind, plain);
    return row;
  }
  row.bodyKind = body.length === 0 ? "none" : isUtf8(plain) ? "text" : "binary";
  row.bodySha256 = sha256(body);
  if (row.bodyKind === "text" && plain.length <= MAX_TEXT_BYTES) {
    row.bodyText = maskSecrets(plain.toString("utf8"), ctx.secrets);
  }
  return row;
}

/** Throws when a row would retain a secret (the recorder checks every row before writing it). */
export function assertNoSecrets(value, secrets) {
  const text = JSON.stringify(value);
  for (const secret of secrets) {
    if (secret && secret.length >= 6 && text.includes(secret)) {
      throw new Error("a row would retain a private value");
    }
  }
}
