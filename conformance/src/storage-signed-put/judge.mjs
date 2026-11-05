// Judges of the signed PUT observation. The observer records every definitive answer as it came;
// the only verdicts are: unknown (the shared rule), whether the positive control failed (the run
// stops, because refusals recorded without a working control mean nothing), and the settlement
// of created and deleted objects.

import { createHash } from "node:crypto";

import { isUnknownStatus, redactSignedUrl } from "./guard.mjs";
import { MAX_CLOCK_SKEW_MS } from "./plan.mjs";

const ERROR_FIELDS = ["Code", "Message", "Details"];

/**
 * Reads a Cloud Storage XML error (`<Error><Code>..</Code><Message>..</Message>..</Error>`) from
 * the exact response bytes. Returns null when the bytes are not that shape; a shape that is not
 * recorded is reported as such, never guessed.
 */
export function parseXmlError(bytes) {
  const text = Buffer.from(bytes).toString("utf8");
  if (!/^\s*(<\?xml[^>]*\?>\s*)?<Error>[\s\S]*<\/Error>\s*$/.test(text)) return null;
  const fields = {};
  for (const name of ERROR_FIELDS) {
    const match = new RegExp(`<${name}>([\\s\\S]*?)</${name}>`).exec(text);
    if (match) fields[name] = match[1];
  }
  return fields.Code ? fields : null;
}

/** `unknown` | `accepted` | `refused`, from the status alone. */
export function classifyStatus(status) {
  if (isUnknownStatus(status)) return "unknown";
  return status >= 200 && status < 300 ? "accepted" : "refused";
}

/**
 * The verdict for one PUT answer. `stopRun` is true only when the positive control was not
 * accepted. `shape` says how the body reads: `empty`, `xml-error`, or `other` (not recorded
 * before, kept as it came).
 */
export function judgePut(testCase, answer) {
  const klass = classifyStatus(answer.status);
  const bytes = Buffer.from(answer.body ?? []);
  const xml = bytes.length ? parseXmlError(bytes) : null;
  const shape = bytes.length === 0 ? "empty" : xml ? "xml-error" : "other";
  return {
    class: klass,
    code: xml?.Code ?? null,
    shape,
    stopRun: klass !== "accepted" && testCase.control === true,
    // A refusal case answered 2xx: the object exists and cleanup must know it.
    createdUnexpectedly: klass === "accepted" && testCase.expect === "refuse",
  };
}

/** The local clock must be within MAX_CLOCK_SKEW_MS of the server `Date` header. */
export function clockSkewOk(localMs, serverDateHeader) {
  const server = Date.parse(serverDateHeader ?? "");
  if (!Number.isFinite(server)) return false;
  return Math.abs(localMs - server) <= MAX_CLOCK_SKEW_MS;
}

const VOLATILE_HEADERS = new Set([
  "date",
  "expires",
  "x-guploader-uploadid",
  "x-goog-generation",
  "etag",
  "alt-svc",
  "age",
  "last-modified",
]);

/** Response headers that carry meaning, with volatile ones dropped. */
export function normalizeHeaders(headers) {
  const out = {};
  for (const [key, value] of Object.entries(headers ?? {}).toSorted(([a], [b]) =>
    a.localeCompare(b),
  )) {
    const name = key.toLowerCase();
    if (!VOLATILE_HEADERS.has(name)) out[name] = value;
  }
  return out;
}

/**
 * The shape of the two volatile headers a successful upload carries, whose values differ per
 * request and so are not kept: the ETag (`quoted-md5-hex`: a quoted lower case MD5, and
 * `etagIsMd5` when it equals the MD5 in `x-goog-hash`) and the generation (`digits-16`).
 */
export function volatileHeaderShapes(headers) {
  const lower = {};
  for (const [key, value] of Object.entries(headers ?? {})) lower[key.toLowerCase()] = value;
  const etag = lower.etag;
  const generation = lower["x-goog-generation"];
  const md5 = /(?:^|, )md5=([A-Za-z0-9+/]{22}==)(?:,|$)/.exec(lower["x-goog-hash"] ?? "")?.[1];
  const quoted = typeof etag === "string" ? /^"([0-9a-f]{32})"$/.exec(etag) : null;
  return {
    etag: etag === undefined ? "absent" : quoted ? "quoted-md5-hex" : "other",
    etagIsMd5: Boolean(quoted && md5 && Buffer.from(md5, "base64").toString("hex") === quoted[1]),
    "x-goog-generation":
      generation === undefined ? "absent" : /^\d{16}$/.test(generation) ? "digits-16" : "other",
  };
}

/** Body text with the run's own names masked, so recordings and targets compare. */
export function normalizeBody(text, masks) {
  let out = redactSignedUrl(text);
  for (const [value, token] of masks) out = out.split(value).join(token);
  // Values a production error derives from the request time differ per request: the compact
  // date stamps, the digest on the last line of StringToSign (a hash of the canonical request,
  // which holds the date) and the expiry time an ExpiredToken names.
  return out
    .replace(/\d{8}T\d{6}Z/g, "<date>")
    .replace(/\n[0-9a-f]{64}<\/StringToSign>/g, "\n<string-to-sign-digest></StringToSign>")
    .replace(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+00:00/g, "<time>");
}

export const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

/** The stored row of one PUT answer (headers and body normalized, exact bytes kept by digest). */
export function putRow({ recording, testCase, answer, verdict, masks }) {
  const bytes = Buffer.from(answer.body ?? []);
  return {
    recording,
    id: testCase.id,
    status: answer.status,
    class: verdict.class,
    code: verdict.code,
    shape: verdict.shape,
    bodyBytes: bytes.length,
    bodySha256: sha256(bytes),
    // The recording number is masked too, so the two recordings' paths do not tell them apart.
    body: normalizeBody(bytes.toString("utf8"), [...masks, [`/rec${recording}/`, "/<rec>/"]]),
    headers: normalizeHeaders(answer.headers),
  };
}

// Everything a row holds that two recordings of the same target must agree on, including the
// digest of the exact response bytes. The body text is a normalized view (run-specific names and
// the recording number masked); the digest is the identity.
const COMPARED = ["status", "class", "code", "shape", "bodyBytes", "body", "bodySha256", "headers"];

function sameValue(a, b) {
  return JSON.stringify(a) === JSON.stringify(b);
}

/**
 * Rows that differ between two recordings of the same target (to be normalized or marked).
 * `digestOnly` says that the exact bytes differ while every normalized field agrees: the
 * difference sits inside masked values or in bytes the text view cannot tell apart.
 */
export function compareRecordings(rows) {
  const byId = new Map();
  for (const row of rows) {
    const entry = byId.get(row.id) ?? {};
    entry[row.recording] = row;
    byId.set(row.id, entry);
  }
  const differences = [];
  for (const [id, entry] of byId) {
    const first = entry[1];
    const second = entry[2];
    if (!first || !second) {
      differences.push({ id, fields: ["missing-recording"], digestOnly: false });
      continue;
    }
    const fields = COMPARED.filter((field) => !sameValue(first[field], second[field]));
    if (fields.length) {
      differences.push({
        id,
        fields,
        digestOnly: fields.length === 1 && fields[0] === "bodySha256",
      });
    }
  }
  return differences;
}

// The normalized comparison of two targets: the status, the XML error code, the body shape, the
// body length in bytes and the normalized body text. Two bodies of equal length and different
// text do not match. The exact comparison also needs the digest of the bytes.
const NORMALIZED_FIELDS = ["status", "code", "shape", "bodyBytes", "body"];
const EXACT_FIELDS = ["status", "code", "shape", "bodyBytes", "bodySha256"];

/**
 * Production against local, row by row on the first recording. `match` is the normalized
 * comparison and `fields` lists what differs in it; `exact` additionally requires identical bytes
 * (`exactFields` lists what differs, `bodySha256` included); `extra` lists differing headers.
 */
export function compareTargets(production, local) {
  const localById = new Map(local.filter((r) => r.recording === 1).map((r) => [r.id, r]));
  const rows = [];
  for (const prod of production.filter((r) => r.recording === 1)) {
    const mine = localById.get(prod.id);
    if (!mine) {
      rows.push({
        id: prod.id,
        match: false,
        exact: false,
        fields: ["missing-local"],
        exactFields: ["missing-local"],
        extra: [],
      });
      continue;
    }
    const fields = NORMALIZED_FIELDS.filter((f) => !sameValue(prod[f], mine[f]));
    const exactFields = EXACT_FIELDS.filter((f) => !sameValue(prod[f], mine[f]));
    const extra = ["headers"].filter((f) => !sameValue(prod[f], mine[f]));
    rows.push({
      id: prod.id,
      match: fields.length === 0,
      exact: exactFields.length === 0,
      fields,
      exactFields,
      extra,
    });
  }
  return rows;
}

// Response headers whose meaning a client relies on after a signed PUT; every other header
// (server, vary, CORS and security headers) is transport and reported apart.
const SEMANTIC_HEADERS = new Set([
  "content-type",
  "content-length",
  "x-goog-hash",
  "x-goog-generation",
  "x-goog-metageneration",
  "x-goog-stored-content-encoding",
  "x-goog-stored-content-length",
]);

/** The names of the headers whose value differs or that only one side has, split by kind. */
function headerDifferences(production, local) {
  const semantic = [];
  const transport = [];
  const names = new Set([...Object.keys(production ?? {}), ...Object.keys(local ?? {})]);
  for (const name of [...names].toSorted()) {
    if (production?.[name] === local?.[name]) continue;
    (SEMANTIC_HEADERS.has(name) ? semantic : transport).push(name);
  }
  return { semantic, transport };
}

/**
 * Production against local, row by row in each recording (rows pair by recording and id). `match`
 * is the normalized comparison of status, code, shape and body; `headers` lists the headers that
 * differ, the ones a client relies on (`semantic`) apart from transport and CORS ones.
 */
export function compareTargetRecordings(production, local) {
  const localByKey = new Map(local.map((r) => [`${r.recording}:${r.id}`, r]));
  return production.map((prod) => {
    const mine = localByKey.get(`${prod.recording}:${prod.id}`);
    if (!mine) {
      return {
        id: prod.id,
        recording: prod.recording,
        match: false,
        fields: ["missing-local"],
        headers: { semantic: [], transport: [] },
      };
    }
    const fields = NORMALIZED_FIELDS.filter((f) => !sameValue(prod[f], mine[f]));
    const headers = headerDifferences(prod.headers, mine.headers);
    for (const name of Object.keys({
      ...prod.volatileHeaders,
      ...mine.volatileHeaders,
    }).toSorted()) {
      if (prod.volatileHeaders?.[name] !== mine.volatileHeaders?.[name])
        headers.semantic.push(name);
    }
    return {
      id: prod.id,
      recording: prod.recording,
      match: fields.length === 0,
      fields,
      headers,
    };
  });
}

/**
 * Settlement of the objects a run touched, by the sandbox rules (presubmission checklist 3).
 * `events` is the ordered list of `{name, event, status?}` with events: `create` (a PUT; status),
 * `read` (a JSON read; status, 200 shows the name), `listed` (the list showed the name), `delete`
 * (status), `read-after-delete` (status). Returns `{closureReady, unresolved}`.
 *
 * - An unknown create settles only on a 2xx read or list showing the name; a 404 never settles it.
 * - A confirmed create settles as gone only by its own delete (2xx) followed by a 404 read.
 * - An unknown delete never settles in the run.
 */
export function settleObjects(events) {
  const state = new Map();
  const get = (name) => {
    if (!state.has(name)) state.set(name, { created: "none", deleted: "none", gone: false });
    return state.get(name);
  };
  for (const { name, event, status } of events) {
    const s = get(name);
    if (event === "create") {
      if (isUnknownStatus(status)) s.created = s.created === "confirmed" ? "confirmed" : "unknown";
      else if (status >= 200 && status < 300) s.created = "confirmed";
    } else if (event === "read") {
      if (status >= 200 && status < 300) s.created = "confirmed";
    } else if (event === "listed") {
      s.created = "confirmed";
    } else if (event === "delete") {
      if (isUnknownStatus(status)) s.deleted = "unknown";
      else if (status >= 200 && status < 300)
        s.deleted = s.deleted === "unknown" ? "unknown" : "ok";
      else s.deleted = s.deleted === "unknown" ? "unknown" : "refused";
    } else if (event === "read-after-delete") {
      s.gone = status === 404 && s.deleted === "ok";
    }
  }
  const unresolved = [];
  for (const [name, s] of state) {
    if (s.deleted === "unknown") unresolved.push({ name, reason: "unknown delete" });
    else if (s.created === "unknown")
      unresolved.push({ name, reason: "unknown create, no positive read" });
    else if (s.created === "confirmed" && !s.gone)
      unresolved.push({ name, reason: "created, not deleted and read back absent" });
  }
  return { closureReady: unresolved.length === 0, unresolved };
}

/** The non-secret parts of a signed URL, for the record. */
export function describeSignedUrl(url, masks) {
  const parsed = new URL(url);
  const get = (key) => parsed.searchParams.get(key);
  const credential = get("X-Goog-Credential") ?? "";
  const [signer, ...scope] = credential.split("/");
  return {
    path: normalizeBody(decodeURIComponent(parsed.pathname), masks),
    algorithm: get("X-Goog-Algorithm"),
    signedHeaders: get("X-Goog-SignedHeaders"),
    expires: get("X-Goog-Expires"),
    credentialScope: scope.slice(1).join("/"),
    hasCredential: signer.length > 0,
    signatureHexLength: (get("X-Goog-Signature") ?? "").length,
    paramNames: [...parsed.searchParams.keys()],
  };
}
