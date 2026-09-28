import { createHash } from "node:crypto";
import { buildCorpus } from "./corpus.mjs";
import { buildAuthCorpus } from "./auth-corpus.mjs";
import { buildProductionStage3DraftPlan } from "./stage3-plan.mjs";
import { validateProductionSessionUri } from "./production-session.mjs";
import {
  copyProductionCaptureBody,
  copyProductionCaptureArray,
  copyProductionCaptureRecord,
} from "./production-capture-input.mjs";

const inventories = new WeakMap(),
  authorities = new WeakMap();
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const origin = (step) =>
  `https://${step.dialect === "gcs" ? "storage" : "firebasestorage"}.googleapis.com`;
const bodyFor = (step) =>
  step.body && Object.hasOwn(step.body, "base64")
    ? Buffer.from(step.body.base64, "base64")
    : step.body?.json
      ? Buffer.from(JSON.stringify(step.body.json))
      : Buffer.alloc(0);
const sameHeaders = (a, b) =>
  a.length === b.length &&
  a.every(
    ([name, value], index) =>
      name.toLowerCase() === b[index][0].toLowerCase() && value === b[index][1],
  );

function authSteps(recipe) {
  const result = [];
  const normalize = (row, id) => ({
    ...row,
    id,
    dialect: row.service === "gcs-json" ? "gcs" : "firebase",
    objectName:
      row.method === "GET" && /^\/storage\/v1\/b\/[^/]+\/o$/.test(row.path) ? null : row.objectName,
    headers: row.method === "POST" ? { "content-type": "application/octet-stream" } : {},
  });
  for (const probe of recipe.probes) {
    if (probe.seed) result.push(normalize(probe.seed, `${recipe.id}/${probe.id}/owner-seed`));
    for (const row of probe.seedReadbacks)
      result.push(normalize(row, `${recipe.id}/${probe.id}/${row.id}`));
    for (const label of ["initial", "before", "after", "cleanup-fresh"])
      for (const row of probe[label === "cleanup-fresh" ? "before" : label])
        result.push(normalize(row, `${recipe.id}/${probe.id}/${label}-${row.id}`));
    result.push({
      ...normalize(probe.subject, `${recipe.id}/${probe.id}/subject`),
      dialect: "firebase",
    });
    for (const row of probe.cleanup)
      result.push(
        normalize(
          row,
          `${recipe.id}/${probe.id}/${row.id === "owned-delete" ? "owned-delete" : `cleanup-${row.id}`}`,
        ),
      );
  }
  return result;
}
function mediaPart(step, bytes) {
  if (!(step.headers?.["content-type"] ?? "").startsWith("multipart/related;")) return bytes;
  const begin = Buffer.from(
      "\r\n--fireemu-object-multipart-v1\r\nContent-Type: application/octet-stream\r\n\r\n",
    ),
    end = Buffer.from("\r\n--fireemu-object-multipart-v1--\r\n");
  const offset = bytes.indexOf(begin);
  if (offset < 0 || !bytes.subarray(bytes.length - end.length).equals(end)) return null;
  return bytes.subarray(offset + begin.length, bytes.length - end.length);
}
function rangePart(bytes, range) {
  const match = /^bytes=([0-9]*)-([0-9]*)$/.exec(range ?? "");
  if (!match || bytes.length === 0 || (!match[1] && !match[2])) return null;
  const begin = match[1] ? Number(match[1]) : Math.max(0, bytes.length - Number(match[2]));
  const end = match[1]
    ? match[2]
      ? Math.min(bytes.length - 1, Number(match[2]))
      : bytes.length - 1
    : bytes.length - 1;
  if (
    !Number.isSafeInteger(begin) ||
    !Number.isSafeInteger(end) ||
    begin > end ||
    begin >= bytes.length ||
    (!match[1] && Number(match[2]) === 0)
  )
    return null;
  return bytes.subarray(begin, end + 1);
}

function declaredUrlMatches(row, value) {
  if (typeof value !== "string" || value.length > 8192 || !value.isWellFormed()) return false;
  const url = new URL(value);
  if (
    url.href !== value ||
    url.origin !== row.origin ||
    url.username ||
    url.password ||
    url.port ||
    url.hash
  )
    return false;
  if (row.session) {
    validateProductionSessionUri(value, {
      dialect: row.dialect,
      bucket: row.bucket,
      prefix: row.prefix,
      objectName: row.objectName,
    });
    return true;
  }
  if (url.pathname !== row.path) return false;
  const actual = [...url.searchParams],
    expected = Object.entries(row.query);
  if (actual.length !== expected.length) return false;
  return expected.every(([key, child], index) => {
    const [actualKey, actualValue] = actual[index];
    if (actualKey !== key) return false;
    if (typeof child === "string") return actualValue === child;
    if (child?.kind === "metadata-field" && child.format === "positive-decimal-string")
      return /^[1-9][0-9]{0,19}$/.test(actualValue);
    if (child?.kind === "firebase-download-token" && ["token", "delete_token"].includes(key))
      return /^[\x21-\x7e]{1,4096}$/.test(actualValue);
    return false;
  });
}

/** Compile only the frozen corpus bytes; no caller hash or body can grant media authority. */
export function createProductionPayloadInventory(supplied) {
  try {
    const input = copyProductionCaptureRecord(supplied, ["projectId", "bucket", "runIds"]);
    if (
      Object.keys(input).length !== 3 ||
      typeof input.projectId !== "string" ||
      typeof input.bucket !== "string"
    )
      throw new Error();
    input.runIds = copyProductionCaptureArray(input.runIds, 2);
    if (input.runIds.length !== 2 || input.runIds.some((value) => typeof value !== "string"))
      throw new Error();
    const plan = buildProductionStage3DraftPlan(input),
      entries = new Map();
    for (const [recordingIndex, recording] of plan.recordings.entries()) {
      const corpus = buildCorpus({ bucket: plan.bucket, prefix: recording.prefix });
      const recipes = [
        ...corpus.recipes.map((recipe) =>
          Object.assign({}, recipe, {
            allSteps: [...recipe.preflight, ...recipe.steps, ...recipe.cleanup],
          }),
        ),
        ...buildAuthCorpus({
          projectId: plan.projectId,
          bucket: plan.bucket,
          runId: recording.runId,
        }).recipes.map((recipe) => Object.assign({}, recipe, { allSteps: authSteps(recipe) })),
      ];
      const payloads = new Map(),
        chunks = new Map();
      const learn = (name, bytes) => {
        if (typeof name !== "string" || !name.startsWith(recording.prefix) || bytes === null)
          return;
        const rows = payloads.get(name) ?? new Map();
        rows.set(hash(bytes), Buffer.from(bytes));
        payloads.set(name, rows);
      };
      for (const [index, recipe] of recipes.entries())
        for (const step of recipe.allSteps) {
          const bytes = bodyFor(step),
            operationId = `r${recordingIndex + 1}/p${index + 1}/${hash(step.id)}`;
          if (entries.has(operationId)) throw new Error();
          const requestKind = step.body && Object.hasOwn(step.body, "base64") ? "media" : "json";
          entries.set(operationId, {
            recording: recordingIndex + 1,
            objectName: step.objectName ?? null,
            method: step.method,
            origin: origin(step),
            dialect: step.dialect,
            bucket: plan.bucket,
            prefix: recording.prefix,
            path: step.path,
            query: step.query ?? {},
            session: !!step.sessionUriReference,
            headers: Object.entries(step.headers ?? {}),
            requestKind,
            requestSha256: hash(bytes),
            requestByteLength: bytes.length,
            range: step.headers?.range,
          });
          if (requestKind === "media") {
            const payload = mediaPart(step, bytes);
            learn(step.objectName, payload);
            if (step.sessionUriReference) {
              const offset =
                step.dialect === "firebase"
                  ? Number(step.headers["x-goog-upload-offset"])
                  : Number(/^bytes ([0-9]+)-/.exec(step.headers["content-range"] ?? "")?.[1]);
              if (Number.isSafeInteger(offset) && offset >= 0) {
                const rows = chunks.get(step.objectName) ?? new Map();
                rows.set(offset, bytes);
                chunks.set(step.objectName, rows);
              }
            }
          }
        }
      for (const [name, rows] of chunks) {
        const parts = [];
        let offset = 0;
        while (rows.has(offset)) {
          const part = rows.get(offset);
          if (part.length === 0) break;
          parts.push(part);
          offset += part.length;
        }
        if (parts.length) learn(name, Buffer.concat(parts));
      }
      for (let pass = 0; pass < recipes.length; pass++) {
        let changed = false;
        for (const recipe of recipes)
          for (const step of recipe.allSteps)
            if (step.transfer) {
              const source = payloads.get(step.transfer.sourceName);
              if (!source) continue;
              const count = payloads.get(step.objectName)?.size ?? 0;
              for (const bytes of source.values()) learn(step.objectName, bytes);
              changed ||= (payloads.get(step.objectName)?.size ?? 0) !== count;
            }
        if (!changed) break;
      }
      for (const row of entries.values())
        if (row.recording === recordingIndex + 1) {
          row.responseSha256 = new Set(payloads.get(row.objectName)?.keys() ?? []);
          if (row.range)
            for (const bytes of payloads.get(row.objectName)?.values() ?? []) {
              const part = rangePart(bytes, row.range);
              if (part) row.responseSha256.add(hash(part));
            }
        }
    }
    const inventory = Object.freeze({});
    inventories.set(inventory, entries);
    return inventory;
  } catch {
    throw new Error("invalid production payload inventory");
  }
}

/** Bind a resolved operation to exact declared request bytes and static headers before capture. */
export function bindProductionPayloadCapture(inventory, supplied) {
  try {
    const entries = inventories.get(inventory);
    if (!entries) return null;
    const input = copyProductionCaptureRecord(supplied, [
      "recording",
      "operationId",
      "method",
      "objectName",
      "headers",
      "body",
      "url",
    ]);
    if (Object.keys(input).length !== 7) return null;
    input.body = copyProductionCaptureBody(input.body);
    input.headers = copyProductionCaptureArray(input.headers, 256).map((pair) => {
      const copy = copyProductionCaptureArray(pair, 2);
      if (copy.length !== 2 || copy.some((part) => typeof part !== "string")) throw new Error();
      return copy;
    });
    const row = entries.get(input.operationId);
    if (
      !row ||
      row.recording !== input.recording ||
      row.method !== input.method ||
      row.objectName !== input.objectName ||
      row.requestByteLength !== input.body.length ||
      row.requestSha256 !== hash(input.body) ||
      !sameHeaders(row.headers, input.headers) ||
      !declaredUrlMatches(row, input.url)
    )
      return null;
    const capability = Object.freeze({});
    authorities.set(capability, { ...row, url: input.url });
    return capability;
  } catch {
    return null;
  }
}

export function isProductionPayloadAuthority(value) {
  return authorities.has(value);
}
export function productionPayloadRequestBodyKind(value) {
  return authorities.get(value)?.requestKind ?? "json";
}
export function productionPayloadStaticHeaderAllowed(value, name, child) {
  if (typeof name !== "string" || typeof child !== "string") return false;
  return (
    authorities
      .get(value)
      ?.headers.some(
        ([key, expected]) => key.toLowerCase() === name.toLowerCase() && expected === child,
      ) ?? false
  );
}
export function productionPayloadAuthorityMatches(capability, supplied) {
  try {
    const row = authorities.get(capability),
      input = copyProductionCaptureRecord(supplied, ["method", "objectName", "url"]);
    return (
      !!row &&
      Object.keys(input).length === 3 &&
      input.method === row.method &&
      input.objectName === row.objectName &&
      input.url === row.url
    );
  } catch {
    return false;
  }
}
export function productionPayloadCaptureIsCovered(capability, direction, supplied) {
  try {
    const row = authorities.get(capability);
    if (!row || !["request", "response"].includes(direction)) return false;
    const bytes = copyProductionCaptureBody(supplied);
    return direction === "request"
      ? row.requestByteLength === bytes.length && row.requestSha256 === hash(bytes)
      : row.responseSha256.has(hash(bytes));
  } catch {
    return false;
  }
}
