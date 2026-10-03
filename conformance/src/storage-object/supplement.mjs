// A bounded observation program. Supplied data and callbacks never grant production authority.
import { createHash } from "node:crypto";

export const SUPPLEMENT_PATHS = Object.freeze([
  "conformance/src/storage-object/supplement.mjs",
  "conformance/src/storage-object/supplement-record.mjs",
  "conformance/src/storage-object-compare/supplement-run.mjs",
  "conformance/src/storage-object-supplement.test.mjs",
  "conformance/src/storage-object-supplement-authority.test.mjs",
]);
export const LIMITS = Object.freeze({
  m1Normal: 25,
  m1Recovery: 6,
  m1: 31,
  m4: 28,
  storage: 59,
  oauth: 1,
  tokeninfo: 1,
  rules: 4,
  bucket: 1,
  record: 66,
  precheck: 8,
  campaign: 140,
});
export const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
export function supplementPlan() {
  return {
    schemaVersion: 2,
    kind: "STORAGE_OBJECT_SUPPLEMENT_PLAN",
    limits: { ...LIMITS },
    m1: { progress: 262144, wrongOffset: 262145, total: 262147, expectedStatus: "UNKNOWN" },
    m4: {
      cases: ["gcs-omitted", "gcs-empty", "firebase-omitted", "firebase-empty"],
      expectedStatus: "UNKNOWN",
      maximumBodyBytes: 512,
    },
    conditionIds: [
      "STORAGE-OBJECT/gcs-resumable-upload",
      "STORAGE-OBJECT/generation-preconditions",
      "STORAGE-OBJECT/cross-dialect-state",
      "STORAGE-OBJECT/invalid-object-name-errors",
    ],
    retainedOriginalConditionCount: 28,
    parentClosed: false,
    retries: 0,
    redirects: 0,
    unknownRecovery: {
      storageCap: 6,
      requiresNewGo: true,
      automaticCleanup: false,
      steps: [
        "born-session-cancel",
        "gcs-metadata",
        "firebase-metadata",
        "gcs-media",
        "firebase-media",
        "owned-prefix",
      ],
    },
  };
}
export function supplementPayload() {
  const bytes = Buffer.alloc(262147);
  for (let index = 0; index < 262144; index++) bytes[index] = index % 251;
  bytes.set([0, 1, 255], 262144);
  return bytes;
}
function jsonFail(code) {
  throw new Error(code);
}
/** Parse JSON without silently accepting duplicate keys, including escaped aliases. */
export function parseSupplementJson(input) {
  const source =
    typeof input === "string" ? input : new TextDecoder("utf-8", { fatal: true }).decode(input);
  let position = 0;
  const whitespace = () => {
    while (/[\x20\t\r\n]/.test(source[position] ?? "x")) position++;
  };
  const string = () => {
    const start = position++;
    while (position < source.length) {
      const char = source[position++];
      if (char === "\\") position++;
      else if (char === '"') return JSON.parse(source.slice(start, position));
    }
    jsonFail("INVALID_JSON");
  };
  const value = (depth) => {
    if (depth > 64) jsonFail("JSON_DEPTH");
    whitespace();
    if (source[position] === '"') return string();
    if (source[position] === "{" || source[position] === "[") {
      const object = source[position++] === "{";
      const result = object ? {} : [];
      const end = object ? "}" : "]";
      whitespace();
      if (source[position] === end) {
        position++;
        return result;
      }
      for (;;) {
        whitespace();
        if (object) {
          if (source[position] !== '"') jsonFail("INVALID_JSON");
          const key = string();
          if (Object.hasOwn(result, key)) jsonFail("DUPLICATE_JSON_KEY");
          whitespace();
          if (source[position++] !== ":") jsonFail("INVALID_JSON");
          Object.defineProperty(result, key, {
            value: value(depth + 1),
            enumerable: true,
            configurable: true,
            writable: true,
          });
        } else result.push(value(depth + 1));
        whitespace();
        const char = source[position++];
        if (char === end) return result;
        if (char !== ",") jsonFail("INVALID_JSON");
      }
    }
    const token = /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(
      source.slice(position),
    )?.[0];
    if (!token) jsonFail("INVALID_JSON");
    position += token.length;
    return JSON.parse(token);
  };
  const result = value(0);
  whitespace();
  if (position !== source.length) jsonFail("INVALID_JSON");
  return result;
}
export function admissionProblem(state, family) {
  if (!state.armed || state.failed || state.pending !== 0) return "INACTIVE_OR_PENDING";
  if (!state.sourceCurrent || !state.grantCurrent || !state.locksHeld) return "AUTHORITY_CHANGED";
  if (
    !state.costKnown ||
    ![state.priorSpent, state.priorReserved, state.reservation, state.ceiling].every(
      (value) => Number.isSafeInteger(value) && value >= 0,
    ) ||
    state.ceiling !== 10000000 ||
    state.priorSpent + state.priorReserved + state.reservation > state.ceiling
  )
    return "COST_UNKNOWN_OR_EXCEEDED";
  if (
    state.now < state.started ||
    state.now - state.started >= (state.stage === "precheck" ? 120000 : 900000)
  )
    return "RUN_DEADLINE";
  if (state.previousTerminal !== null && state.started - state.previousTerminal < 1800000)
    return "PROJECT_SPACING";
  if (
    state.now + 30000 >= state.grantExpires ||
    (family !== "oauth" && family !== "tokeninfo" && state.now + 30000 >= state.tokenExpires)
  )
    return "TOKEN_OR_GRANT_EXPIRY";
  if (family === "storage" && state.now - state.baselineObserved > 300000) return "BASELINE_STALE";
  const cap = state.stage === "precheck" ? 8 : 66;
  const familyCaps =
    state.stage === "precheck"
      ? { storage: 1, oauth: 1, tokeninfo: 1, rules: 4, bucket: 1 }
      : LIMITS;
  if (
    !Object.hasOwn(familyCaps, family) ||
    !Number.isSafeInteger(state.attempted) ||
    state.attempted >= cap ||
    !Number.isSafeInteger(state.families[family]) ||
    state.families[family] >= familyCaps[family]
  )
    return "PHYSICAL_CAP";
  return null;
}
function json(response) {
  if (!response?.complete || response.status === null || !response.body) return null;
  try {
    return parseSupplementJson(response.body);
  } catch {
    return null;
  }
}
export function exhaustedEmpty(response) {
  const value = json(response);
  return (
    response?.status === 200 &&
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).every((key) =>
      ["kind", "items", "prefixes", "nextPageToken"].includes(key),
    ) &&
    (!Object.hasOwn(value, "kind") || value.kind === "storage#objects") &&
    (!Object.hasOwn(value, "items") || (Array.isArray(value.items) && value.items.length === 0)) &&
    (!Object.hasOwn(value, "prefixes") ||
      (Array.isArray(value.prefixes) && value.prefixes.length === 0)) &&
    !Object.hasOwn(value, "nextPageToken")
  );
}
export function judgeM4Case({ before, subject, after }) {
  if (
    !Array.isArray(before) ||
    !Array.isArray(after) ||
    before.length !== 3 ||
    after.length !== 3 ||
    ![...before, ...after].every(exhaustedEmpty)
  )
    return "UNKNOWN";
  return subject?.complete &&
    Number.isInteger(subject.status) &&
    subject.status >= 400 &&
    subject.status < 500
    ? "RECORDED_UNREVIEWED"
    : "UNKNOWN";
}
export function cleanupGeneration({ name, bucket, bornGeneration, reads, fresh }) {
  if (
    !/^[1-9][0-9]{0,31}$/.test(bornGeneration ?? "") ||
    !Array.isArray(reads) ||
    reads.length !== 4 ||
    !Array.isArray(fresh) ||
    fresh.length !== 2
  )
    return null;
  const expected = supplementPayload();
  const all = [...reads, ...fresh];
  for (let index = 0; index < all.length; index++) {
    const response = all[index];
    if (!response?.complete || response.status !== 200) return null;
    if (index % 2 === 0) {
      const data = json(response);
      if (
        data?.name !== name ||
        data?.bucket !== bucket ||
        data?.generation !== bornGeneration ||
        String(data?.size) !== "262147"
      )
        return null;
    } else if (
      !Buffer.from(response.body ?? []).equals(expected) ||
      (response.headers?.["x-goog-generation"] !== undefined &&
        response.headers["x-goog-generation"] !== bornGeneration)
    )
      return null;
  }
  return bornGeneration;
}
const absent = (response) => response?.complete && response.status === 404;
const progress = (response) =>
  response?.complete && response.status === 308 && response.headers?.range === "bytes=0-262143";
const ok = (response) => response?.complete && response.status >= 200 && response.status < 300;
const enc = encodeURIComponent;
export function storageRequest({
  dialect,
  bucket,
  name,
  operation,
  body = Buffer.alloc(0),
  generation = null,
  prefix = null,
  session = null,
  runId,
}) {
  if (!/^[a-z0-9][a-z0-9.-]{2,221}$/.test(bucket) || !/^[a-f0-9]{20}$/.test(runId))
    throw new Error("INVALID_TARGET");
  if (
    name !== null &&
    (typeof name !== "string" || !name.startsWith(`fireemu-object-supplement/${runId}/`))
  )
    throw new Error("UNOWNED_NAME");
  const gcs = dialect === "gcs";
  if (!gcs && dialect !== "firebase") throw new Error("INVALID_DIALECT");
  let method = "GET";
  let url = new URL(
    gcs
      ? `https://storage.googleapis.com/storage/v1/b/${enc(bucket)}/o`
      : `https://firebasestorage.googleapis.com/v0/b/${enc(bucket)}/o`,
  );
  const headers = { accept: "application/json", "accept-encoding": "identity" };
  if (["query", "chunk", "wrong", "final", "cancel"].includes(operation)) {
    url = validateBornSessionUrl(session, { bucket, name });
    method = operation === "cancel" ? "DELETE" : "PUT";
    if (operation !== "cancel")
      headers["content-range"] =
        operation === "query"
          ? "bytes */262147"
          : operation === "chunk"
            ? "bytes 0-262143/262147"
            : operation === "wrong"
              ? "bytes 262145-262146/262147"
              : "bytes 262144-262146/262147";
  } else if (operation === "initiate" || operation === "unnamed") {
    method = "POST";
    if (gcs) url = new URL(`https://storage.googleapis.com/upload/storage/v1/b/${enc(bucket)}/o`);
    url.searchParams.set("uploadType", operation === "initiate" ? "resumable" : "media");
    if (operation === "initiate") {
      url.searchParams.set("name", name);
      headers["x-upload-content-length"] = "262147";
      headers["x-upload-content-type"] = "application/octet-stream";
    } else if (name !== null) url.searchParams.set("name", "");
  } else if (operation === "whole" || operation === "prefix") {
    url.searchParams.set("maxResults", "1");
    if (operation === "whole") {
      if (!gcs) throw new Error("WHOLE_REQUIRES_GCS");
      url.searchParams.set("versions", "true");
    } else {
      if (typeof prefix !== "string" || prefix !== `fireemu-object-supplement/${runId}/`)
        throw new Error("UNOWNED_PREFIX");
      url.searchParams.set("prefix", prefix);
    }
  } else if (["metadata", "media", "delete"].includes(operation)) {
    url.pathname += `/${enc(name)}`;
    if (operation === "media") url.searchParams.set("alt", "media");
    if (operation === "delete") {
      if (!gcs || !/^[1-9][0-9]{0,31}$/.test(generation ?? ""))
        throw new Error("CONDITIONAL_DELETE_REQUIRED");
      method = "DELETE";
      url.searchParams.set("ifGenerationMatch", generation);
    }
  } else throw new Error("UNKNOWN_OPERATION");
  if (body.length > 262144) throw new Error("REQUEST_BODY_CAP");
  headers["content-type"] = "application/octet-stream";
  return { family: "storage", method, url: url.href, headers, body };
}
export function validateBornSessionUrl(value, { bucket, name }) {
  if (typeof value !== "string" || value.length > 8192) throw new Error("INVALID_BORN_SESSION");
  const url = new URL(value);
  if (
    url.origin !== "https://storage.googleapis.com" ||
    url.username ||
    url.password ||
    url.hash ||
    url.pathname !== `/upload/storage/v1/b/${enc(bucket)}/o` ||
    url.searchParams.getAll("uploadType").length !== 1 ||
    url.searchParams.get("uploadType") !== "resumable" ||
    url.searchParams.getAll("upload_id").length !== 1 ||
    !url.searchParams.get("upload_id") ||
    [...url.searchParams.keys()].some(
      (key) => !["uploadType", "upload_id", "name"].includes(key),
    ) ||
    (url.searchParams.has("name") &&
      (url.searchParams.getAll("name").length !== 1 || url.searchParams.get("name") !== name))
  )
    throw new Error("INVALID_BORN_SESSION");
  return url;
}

export async function runSupplementProgram(dispatch, { bucket, runId, stage = "record1" }) {
  const name = `fireemu-object-supplement/${runId}/m1`;
  const prefix = `fireemu-object-supplement/${runId}/`;
  const rows = [];
  const request = async (label, dialect, operation, extra = {}) => {
    const response = await dispatch({
      ...storageRequest({ dialect, bucket, name, prefix, operation, runId, ...extra }),
      label,
    });
    rows.push({ label, response });
    return response;
  };
  const stop = (reason) => ({
    outcome: "UNKNOWN",
    reason,
    rows,
    automaticCleanup: false,
    recoveryRequiresNewGo: true,
  });
  if (stage === "precheck")
    return exhaustedEmpty(await request("precheck-whole", "gcs", "whole"))
      ? { outcome: "PRECHECK_CANDIDATE", rows }
      : stop("BUCKET_NOT_EXHAUSTED_EMPTY");
  if (!exhaustedEmpty(await request("m1-prefix-before", "gcs", "prefix")))
    return stop("OWNED_PREFIX_NOT_EMPTY");
  for (const dialect of ["gcs", "firebase"])
    if (!absent(await request(`m1-${dialect}-absent-before`, dialect, "metadata")))
      return stop("OWNED_NAME_PREEXISTS");
  const initiated = await request("m1-initiate", "gcs", "initiate");
  if (!ok(initiated) || typeof initiated.headers?.location !== "string")
    return stop("INITIATE_UNKNOWN");
  let session;
  try {
    session = validateBornSessionUrl(initiated.headers.location, { bucket, name }).href;
  } catch {
    return stop("FOREIGN_SESSION");
  }
  const payload = supplementPayload();
  if (
    !progress(
      await request("m1-correct-chunk", "gcs", "chunk", {
        session,
        body: payload.subarray(0, 262144),
      }),
    )
  )
    return stop("CHUNK_PROGRESS_UNKNOWN");
  if (!progress(await request("m1-query-before-wrong", "gcs", "query", { session })))
    return stop("INITIAL_PROGRESS_UNKNOWN");
  const wrong = await request("m1-wrong-offset", "gcs", "wrong", {
    session,
    body: payload.subarray(262145),
  });
  if (
    !wrong.complete ||
    !Number.isInteger(wrong.status) ||
    wrong.status < 400 ||
    wrong.status >= 500
  )
    return stop("WRONG_OFFSET_OUTCOME_UNKNOWN");
  if (!progress(await request("m1-query-after-wrong", "gcs", "query", { session })))
    return stop("WRONG_OFFSET_CHANGED_PROGRESS");
  for (const dialect of ["gcs", "firebase"])
    for (const operation of ["metadata", "media"])
      if (!absent(await request(`m1-${dialect}-${operation}-after-wrong`, dialect, operation)))
        return stop("WRONG_OFFSET_PUBLISHED_OR_UNKNOWN");
  const finalized = await request("m1-correct-final", "gcs", "final", {
    session,
    body: payload.subarray(262144),
  });
  const born = json(finalized)?.generation;
  if (!ok(finalized) || !/^[1-9][0-9]{0,31}$/.test(born ?? "")) return stop("FINALIZATION_UNKNOWN");
  const reads = [];
  for (const dialect of ["gcs", "firebase"])
    for (const operation of ["metadata", "media"])
      reads.push(await request(`m1-${dialect}-${operation}-positive`, dialect, operation));
  const fresh = [
    await request("m1-fresh-metadata", "gcs", "metadata"),
    await request("m1-fresh-media", "gcs", "media"),
  ];
  const generation = cleanupGeneration({ name, bucket, bornGeneration: born, reads, fresh });
  if (generation === null) return stop("POSITIVE_OWNERSHIP_NOT_ESTABLISHED");
  if (!ok(await request("m1-conditional-delete", "gcs", "delete", { generation })))
    return stop("DELETE_UNKNOWN");
  for (const dialect of ["gcs", "firebase"])
    for (const operation of ["metadata", "media"])
      if (!absent(await request(`m1-${dialect}-${operation}-absent-after`, dialect, operation)))
        return stop("DELETE_READBACK_UNKNOWN");
  if (!exhaustedEmpty(await request("m1-prefix-after", "gcs", "prefix")))
    return stop("OWNED_PREFIX_REMAINS");
  for (const caseId of supplementPlan().m4.cases) {
    const before = [
      await request(`${caseId}-whole-before`, "gcs", "whole"),
      await request(`${caseId}-gcs-prefix-before`, "gcs", "prefix"),
      await request(`${caseId}-firebase-prefix-before`, "firebase", "prefix"),
    ];
    if (!before.every(exhaustedEmpty)) return stop("M4_BASELINE_NOT_EMPTY");
    const dialect = caseId.startsWith("gcs") ? "gcs" : "firebase";
    const subject = await request(`${caseId}-subject`, dialect, "unnamed", {
      name: caseId.endsWith("omitted") ? null : name,
      body: Buffer.from(`object-supplement:${runId}:${caseId}`),
    });
    // A potentially successful unnamed write has no safe guessed cleanup target.
    if (
      !subject.complete ||
      !Number.isInteger(subject.status) ||
      subject.status < 400 ||
      subject.status >= 500
    )
      return stop("M4_SUBJECT_UNKNOWN_NO_UNNAMED_CLEANUP");
    const after = [
      await request(`${caseId}-whole-after`, "gcs", "whole"),
      await request(`${caseId}-gcs-prefix-after`, "gcs", "prefix"),
      await request(`${caseId}-firebase-prefix-after`, "firebase", "prefix"),
    ];
    if (judgeM4Case({ before, subject, after }) !== "RECORDED_UNREVIEWED")
      return stop("M4_POSTSTATE_UNKNOWN");
  }
  return {
    outcome: "RECORDED_UNREVIEWED",
    rows,
    automaticCleanup: false,
    m1NormalRequests: 25,
    m4Requests: 28,
  };
}
