// Runs the Firestore semantics programs against one side and records what it answered.
//
// Each program wipes the database through the emulator's own
// `DELETE /emulator/v1/projects/{project}/databases/(default)/documents` route (the same
// route on both sides), seeds its documents with the privileged `Bearer owner` credential,
// then runs its steps in order. Every step is one REST request; a step may refer to a value
// an earlier step returned (`{ "$from": "<step id>", "path": "a.b.0" }`), which is how a
// transaction id or an `updateTime` precondition reaches the request that needs it.
//
// The recorded value is the HTTP status, the canonical error status and the normalized body:
// server-generated instants and transaction ids are replaced by placeholders, everything
// else -- documents, field values, result order, write results, error messages -- is kept
// as the side produced it.

import { open, readFile, rename, unlink, writeFile } from "node:fs/promises";
import { createHash, randomUUID } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { credentialMetadata, selectCredential } from "./credentials.mjs";
import { normalizeRecordedResponse } from "./production-normalization.mjs";
import { createRequestBudget } from "./request-budget.mjs";
import {
  makeWebChannelFormBody,
  projectWebChannelResponse,
  WEBCHANNEL_PATH,
} from "./webchannel-request-bytes.mjs";

const HOST = process.env.FIRESTORE_PROBE_HOST;
const PROJECT = process.env.FIRESTORE_PROBE_PROJECT ?? "demo-conformance";
const IN = process.env.FIRESTORE_PROBE_IN;
const OUT = process.env.FIRESTORE_PROBE_OUT;
const META_OUT = process.env.FIRESTORE_PROBE_META_OUT;
const MAX_REQUESTS = process.env.FIRESTORE_PROBE_MAX_REQUESTS;
const REQUEST_TIMEOUT_MS = Number(process.env.FIRESTORE_PROBE_TIMEOUT_MS ?? 20_000);
const MANAGED_CLEAR_JOURNAL =
  process.env.FIRESTORE_PROBE_DELTA_JOURNAL ?? process.env.FIRESTORE_PROBE_MANAGED_CLEAR_JOURNAL;
const MANAGED_CLEAR_NAMES = process.env.FIRESTORE_PROBE_MANAGED_CLEAR_NAMES;
// Production target: `https`, an OAuth bearer token instead of the emulator's `owner`, no
// emulator wipe route (documents are deleted through the public API instead), and the real
// project id normalized back to the recording project so a production run compares row by
// row with the emulator matrices without ever recording the production identifier.
const SCHEME = process.env.FIRESTORE_PROBE_SCHEME ?? "http";
const TOKEN = process.env.FIRESTORE_PROBE_TOKEN ?? "owner";
const USER_TOKEN = process.env.FIRESTORE_PROBE_USER_TOKEN;
const PRODUCTION = process.env.FIRESTORE_PROBE_TARGET === "production";
const RECOVERY_MODE = process.env.FIRESTORE_PROBE_RECOVERY_MODE;
const DELTA_V3_MODE = process.env.FIRESTORE_PROBE_DELTA_V3 === "1";
const DELTA_LOCK_HELD = process.env.FIRESTORE_PROBE_DELTA_LOCK_HELD === "1";
const CORPUS_DIGEST = process.env.FIRESTORE_PROBE_CORPUS_DIGEST;
const SOURCE_GIT_SHA = process.env.FIRESTORE_PROBE_SOURCE_GIT_SHA;
const MANAGED_POLL_MS = /^127\.0\.0\.1:\d+$/.test(HOST ?? "")
  ? Number(process.env.FIRESTORE_PROBE_MANAGED_POLL_MS ?? 60_000)
  : 60_000;
if (!Number.isInteger(MANAGED_POLL_MS) || MANAGED_POLL_MS < 1 || MANAGED_POLL_MS > 60_000) {
  throw new Error("invalid managed-clear polling interval");
}
const RECORD_PROJECT = process.env.FIRESTORE_PROBE_RECORD_PROJECT ?? PROJECT;
const DELETE_RUN_MARKER = "DELETE_RUN_ID";
const DELTA_STREAM_ID = "writes/write-stream-terminal/response-before-half-close";
let deleteRunId = DELETE_RUN_MARKER;
const SHRINK_CHUNK_SIZE = 1024;
// Twelve frozen targets need at most 152 transforms and about 194 other managed requests
// under the seven-clear worst case; retain headroom while staying below the 1000 REST cap.
const SHRINK_REQUEST_CAPS = { legacy: 180, v3: 400, "delta-v3": 400 };
const SANDBOX_DOCUMENTS = "projects/fireemu-oracle-sbx/databases/(default)/documents/";
const LEGACY_SHRINK_SPECS = [
  ["barrayname100012116n31", 998, 1, 12_116],
  ["barrayname100012121n32", 998, 1, 12_121],
  ["barrayname100012123n33", 998, 1, 12_123],
  ["barrayname20007179n45", 1400, 599, 7_179],
  ["barrayname20007183n47", 1400, 599, 7_183],
  ["barrayname20007184n49", 1400, 599, 7_184],
];
const V3_SHRINK_SPECS = [
  ["g500a", 498, 1, 19_999],
  ["g500b", 498, 1, 20_000],
  ["g2000a", 1400, 599, 7_184],
  ["g2000b", 1400, 599, 7_185],
  ["g1000a", 998, 1, 12_123],
  ["g1000b", 998, 1, 12_124],
  ...["rest", "commit", "batch-write"].flatMap((route) =>
    [12_112, 12_113].map((length) => [
      `del${route.replaceAll("-", "")}${length}${DELETE_RUN_MARKER}`,
      998 - (32 - DELETE_RUN_MARKER.length),
      1,
      length,
    ]),
  ),
];
const frozenResourceNames = (specs) =>
  specs.map(
    ([collectionPrefix, collectionBytes, documentBytes]) =>
      `${SANDBOX_DOCUMENTS}${collectionPrefix.padEnd(collectionBytes, "c")}/${"d".repeat(documentBytes)}`,
  );
const LEGACY_SHRINK_NAMES = frozenResourceNames(LEGACY_SHRINK_SPECS);
const V3_SHRINK_NAMES = frozenResourceNames(V3_SHRINK_SPECS);
const LEGACY_SHRINK_COLLECTIONS = new Set(
  LEGACY_SHRINK_NAMES.map((name) => name.split("/documents/")[1].split("/")[0]),
);
const FROZEN_ARRAY_LENGTHS = new Map(
  [...LEGACY_SHRINK_SPECS, ...V3_SHRINK_SPECS].map(
    ([collectionPrefix, collectionBytes, , length]) => [
      collectionPrefix.padEnd(collectionBytes, "c"),
      length,
    ],
  ),
);

function canonicalRunName(name) {
  return typeof name === "string" && deleteRunId !== DELETE_RUN_MARKER
    ? name.replaceAll(deleteRunId, DELETE_RUN_MARKER)
    : name;
}

function canonicalCollectionId(name) {
  return name.split("/documents/")[1].split("/")[0].replaceAll(deleteRunId, DELETE_RUN_MARKER);
}

export function createShrinkRequestCounter(limit, initial = 0) {
  if (
    !Number.isSafeInteger(limit) ||
    limit <= 0 ||
    !Number.isSafeInteger(initial) ||
    initial < 0 ||
    initial > limit
  ) {
    throw new Error("array shrink request limit must be a positive safe integer");
  }
  let requests = initial;
  return {
    claim() {
      if (requests >= limit)
        throw new Error("array shrink request cap reached before network send");
      requests += 1;
      return requests;
    },
    current() {
      return requests;
    },
  };
}

export function assertV3ProductionCleanupAllowed({ host, exactDeltaV3 = false }) {
  if (host && !/^127\.0\.0\.1:\d+$/.test(host) && !exactDeltaV3) {
    throw new Error(
      "v3 production cleanup is blocked: exact cleanup is over the fixed request caps and generic broad clear is disabled",
    );
  }
}

export function isExactDeltaV3ProductionScope({
  mode,
  lockHeld,
  host,
  scheme,
  project,
  maxRequests,
  deltaJournal,
  managedClearJournal,
  names,
}) {
  if (
    mode === true &&
    lockHeld === true &&
    host === "firestore.googleapis.com" &&
    scheme === "https" &&
    project === "fireemu-oracle-sbx" &&
    Number.isSafeInteger(maxRequests) &&
    maxRequests >= 1 &&
    maxRequests <= 430 &&
    typeof deltaJournal === "string" &&
    deltaJournal.length > 0 &&
    managedClearJournal === deltaJournal
  ) {
    try {
      if (!Array.isArray(names) || names.length !== 6) return false;
      managedClearScope(names, project, "(default)");
      const runIds = new Set(
        names.map(
          (name) =>
            name.match(/\/del(?:rest|commit|batchwrite)(?:12112|12113)([a-f0-9]{32})c*\//)?.[1],
        ),
      );
      const [runId] = runIds;
      const expectedNames = ["rest", "commit", "batchwrite"].flatMap((route) =>
        [12_112, 12_113].map((length) => {
          const rawCollection = `del${route}${length}${runId}`;
          return `${SANDBOX_DOCUMENTS}${rawCollection.padEnd(998, "c")}/d`;
        }),
      );
      return (
        runIds.size === 1 &&
        JSON.stringify(names.toSorted()) === JSON.stringify(expectedNames.toSorted())
      );
    } catch {
      return false;
    }
  }
  return false;
}
let requestCount = 0;
const requestBudget = MAX_REQUESTS === undefined ? null : createRequestBudget(Number(MAX_REQUESTS));
let managedClearBlocked = false;
let managedClearState = null;

export function legacyManagedClearNames() {
  return [...LEGACY_SHRINK_NAMES];
}

export function managedClearScope(names, project, database) {
  if (project !== "fireemu-oracle-sbx" || database !== "(default)" || !Array.isArray(names)) {
    throw new Error("managed clear requires the fixed sandbox database");
  }
  const prefix = `projects/${project}/databases/${database}/documents/`;
  const collections = [];
  for (const name of names) {
    if (typeof name !== "string" || !name.startsWith(prefix)) {
      throw new Error("managed clear name is outside the sandbox");
    }
    const parts = name.slice(prefix.length).split("/");
    if (parts.length !== 2 || parts.some((part) => !part || part === "." || part === "..")) {
      throw new Error("managed clear requires a root document");
    }
    collections.push(parts[0]);
  }
  if (collections.length === 0 || new Set(collections).size !== collections.length) {
    throw new Error("managed clear collection groups must be unique");
  }
  return collections;
}

export function managedShrinkScope(names, project, database) {
  if (project !== "fireemu-oracle-sbx" || database !== "(default)" || !Array.isArray(names)) {
    throw new Error("array shrink requires the fixed sandbox database");
  }
  if (names.some((name) => typeof name !== "string") || new Set(names).size !== names.length) {
    throw new Error("array shrink requires distinct frozen documents");
  }
  const canonicalNames = names.map(canonicalRunName);
  if (
    LEGACY_SHRINK_NAMES.length === canonicalNames.length &&
    LEGACY_SHRINK_NAMES.every((name) => canonicalNames.includes(name))
  )
    return "legacy";
  if (
    canonicalNames.length === 6 &&
    V3_SHRINK_NAMES.slice(0, 6).every((name) => canonicalNames.includes(name))
  )
    return "v3";
  if (
    canonicalNames.length === 6 &&
    V3_SHRINK_NAMES.slice(6).every((name) => canonicalNames.includes(name))
  )
    return "delta-v3";
  if (
    V3_SHRINK_NAMES.length === canonicalNames.length &&
    V3_SHRINK_NAMES.every((name) => canonicalNames.includes(name))
  )
    return "v3";
  throw new Error("array shrink names do not match the frozen legacy or corpus-v3 scope");
}

export function validateShrinkBoundaryDocument(document, expectedName) {
  const values = document?.fields?.a?.arrayValue?.values;
  if (
    document?.name !== expectedName ||
    typeof document.updateTime !== "string" ||
    !document.updateTime ||
    Object.keys(document.fields ?? {}).length !== 1 ||
    Object.keys(document.fields?.a ?? {}).length !== 1 ||
    !document.fields?.a?.arrayValue ||
    !Array.isArray(values) ||
    values.length > 20_000 ||
    values.some(
      (value, index) =>
        Object.keys(value ?? {}).length !== 1 || value?.integerValue !== String(index),
    )
  ) {
    throw new Error("array shrink document is not the frozen generated integer sequence");
  }
  return values;
}

export function validateShrinkBoundaryState(
  document,
  expectedName,
  expectedLength,
  { allowEmptyOmitted = false } = {},
) {
  const arrayValue = document?.fields?.a?.arrayValue;
  const omittedEmpty =
    allowEmptyOmitted &&
    arrayValue &&
    !Object.hasOwn(arrayValue, "values") &&
    Object.keys(arrayValue).length === 0;
  const values = omittedEmpty ? [] : arrayValue?.values;
  if (
    document?.name !== expectedName ||
    typeof document.updateTime !== "string" ||
    !document.updateTime ||
    Object.keys(document.fields ?? {}).length !== 1 ||
    Object.keys(document.fields?.a ?? {}).length !== 1 ||
    !arrayValue ||
    Object.keys(arrayValue).some((key) => key !== "values") ||
    !Array.isArray(values) ||
    !Number.isSafeInteger(expectedLength) ||
    expectedLength < 0
  ) {
    throw new Error("array shrink document is not a frozen boundary document");
  }
  if (values.length !== 0 && values.length !== expectedLength) {
    throw new Error("array shrink partial debris requires operator recovery");
  }
  if (
    values.some(
      (value, index) =>
        Object.keys(value ?? {}).length !== 1 || value?.integerValue !== String(index),
    )
  ) {
    throw new Error("array shrink document changed; operator recovery is required");
  }
  return values;
}

export function validateLegacyDebrisDocument(document, expectedName, expectedLength) {
  const arrayValue = document?.fields?.a?.arrayValue;
  const omittedEmpty = arrayValue && Object.keys(arrayValue).length === 0;
  const values = omittedEmpty ? [] : arrayValue?.values;
  if (
    document?.name !== expectedName ||
    typeof document.updateTime !== "string" ||
    !document.updateTime ||
    Object.keys(document.fields ?? {}).length !== 1 ||
    Object.keys(document.fields?.a ?? {}).length !== 1 ||
    !arrayValue ||
    Object.keys(arrayValue).some((key) => key !== "values") ||
    !Array.isArray(values) ||
    !Number.isSafeInteger(expectedLength) ||
    expectedLength <= 0 ||
    values.length > expectedLength
  ) {
    throw new Error("legacy debris is not a frozen typed document");
  }
  const firstValue = expectedLength - values.length;
  if (
    values.some(
      (value, index) =>
        Object.keys(value ?? {}).length !== 1 || value?.integerValue !== String(firstValue + index),
    )
  ) {
    throw new Error("legacy debris is not a deterministic suffix of its frozen integer sequence");
  }
  return values;
}

export function validateManagedClearReadback(names, rows) {
  return (
    Array.isArray(rows) &&
    rows.length === names.length &&
    new Set(rows.map((row) => row?.missing)).size === names.length &&
    names.every((name) => rows.some((row) => row?.missing === name && !row.found && !row.error))
  );
}

export function isManagedClearCommitRefusal(status, body, candidate, parentPath, allowedNames) {
  if (status !== 400 || parentPath !== "" || !candidate || !allowedNames?.includes(candidate)) {
    return false;
  }
  try {
    const error = JSON.parse(body)?.error;
    return (
      error?.status === "INVALID_ARGUMENT" &&
      error?.message === "Transaction too big. Decrease transaction size."
    );
  } catch {
    return false;
  }
}

export function validateManagedClearOperation(state, project) {
  const prefix = `projects/${project}/databases/(default)/operations/`;
  if (
    project !== "fireemu-oracle-sbx" ||
    state?.done !== true ||
    state.error ||
    typeof state.name !== "string" ||
    !state.name.startsWith(prefix) ||
    !/^[A-Za-z0-9_-]+$/.test(state.name.slice(prefix.length))
  ) {
    throw new Error("managed clear operation did not succeed in the fixed sandbox");
  }
  return state.name;
}

function trackedFetch(input, init) {
  return (async () => {
    if (managedClearState?.shrinkScope === "delta-v3") {
      if (requestCount >= 430)
        throw new Error("delta-v3 HTTP request cap reached before network send");
      const requestMethod = String(init?.method ?? "GET").toUpperCase();
      const isPendingResolutionRead = matchesPendingMutationResolutionRead(input, init);
      if (
        managedClearState.pendingMutation &&
        (managedClearState.pendingMutation.url !== String(input) ||
          managedClearState.pendingMutation.method !== requestMethod) &&
        !isPendingResolutionRead
      ) {
        throw new Error("delta-v3 has an unresolved write-ahead mutation; stop and recover");
      }
      if (requestBudget !== null) requestBudget.claim();
      requestCount += 1;
      await writeDeltaCleanupJournal("request-reserved");
      const response = await fetch(input, { ...init, redirect: "error" });
      if (managedClearState.pendingMutation && !isPendingResolutionRead) {
        managedClearState.lastMutation = {
          ...managedClearState.pendingMutation,
          httpStatus: response.status,
        };
        managedClearState.pendingMutation = null;
        await writeDeltaCleanupJournal("mutation-response-observed");
      }
      return response;
    }
    requestCount = requestBudget === null ? requestCount + 1 : requestBudget.claim();
    return fetch(input, init);
  })();
}

function matchesPendingMutationResolutionRead(input, init) {
  const name = managedClearState?.pendingMutationResolutionName;
  if (!name) return false;
  const method = String(init?.method ?? "GET").toUpperCase();
  if (method === "GET" && String(input) === urlForDocument(name)) return true;
  if (method !== "POST") return false;
  const api = `${SCHEME}://${HOST}/v1/projects/${PROJECT}/databases/(default)`;
  if (String(input) !== `${api}/documents:runQuery`) return false;
  let body;
  try {
    body = JSON.parse(init?.body ?? "null");
  } catch {
    return false;
  }
  const collectionId = name.split("/documents/")[1].split("/")[0];
  return (
    JSON.stringify(body) ===
    JSON.stringify({
      structuredQuery: {
        from: [{ collectionId, allDescendants: true }],
        select: { fields: [{ fieldPath: "__name__" }] },
        limit: 2,
      },
    })
  );
}

const replaceRunMarker = (value) => value.replaceAll(DELETE_RUN_MARKER, deleteRunId);
const url = (path) => `${SCHEME}://${HOST}${replaceRunMarker(path.replaceAll("PROJECT", PROJECT))}`;
const substituteProject = (value) =>
  JSON.parse(replaceRunMarker(JSON.stringify(value ?? null).replaceAll("PROJECT", PROJECT)));
const normalizeProbeResponse = (value, options) =>
  JSON.parse(
    JSON.stringify(normalizeRecordedResponse(value, options)).replaceAll(
      deleteRunId,
      "<delete-run>",
    ),
  );
const authorized = (headers = {}) => ({ ...headers, authorization: `Bearer ${TOKEN}` });
const timeoutSignal = () => AbortSignal.timeout(REQUEST_TIMEOUT_MS);

/** Wipes the emulator's documents so one program never sees another's writes. */
async function clear(database = "(default)", verifyManagedScope = false) {
  if (PRODUCTION) {
    if (managedClearBlocked) throw new Error("managed clear needs operator recovery");
    await clearThroughPublicApi(database, verifyManagedScope);
    return;
  }
  await trackedFetch(
    `http://${HOST}/emulator/v1/projects/${PROJECT}/databases/${database}/documents`,
    {
      method: "DELETE",
      signal: timeoutSignal(),
    },
  );
}

/**
 * Production has no wipe route: every document under every root collection is deleted
 * through `:runQuery` (names only) and `:commit`, recursing into subcollections. Only the
 * probe project is ever addressed, and only documents the probes seeded can exist there.
 */
async function clearThroughPublicApi(database, verifyManagedScope) {
  const base = `${SCHEME}://${HOST}/v1/projects/${PROJECT}/databases/${database}/documents`;
  const shrinkScopeActive = managedClearState !== null && database === "(default)";
  if (managedClearState?.shrinkScope === "delta-v3") {
    await clearDeltaV3Exact(base, verifyManagedScope);
    return;
  }
  if (shrinkScopeActive) {
    managedClearBlocked = true;
    managedClearState.preflightDone = false;
  }
  // Listing is paged and only eventually reflects deletes: loop until a full listing is empty.
  for (let round = 0; round < 8; round += 1) {
    const collectionIds = await listCollectionIds(base, "");
    if (collectionIds === null) {
      if (shrinkScopeActive) throw new Error("array shrink database scope could not be listed");
      managedClearBlocked = false;
      return;
    }
    if (collectionIds.length === 0) {
      if (shrinkScopeActive && verifyManagedScope) {
        await verifyManagedShrinkScopeAbsent(base);
        if (managedClearState.shrinkScope === "v3") {
          await writeV3CleanupJournal("complete", {
            verifiedAbsentNames: [...managedClearState.names],
          });
        }
      }
      managedClearBlocked = false;
      return;
    }
    if (shrinkScopeActive) {
      if (managedClearState.shrinkScope === "v3") {
        if (!managedClearState.legacyDebrisAudited) {
          await auditLegacyDebris(base);
          managedClearState.legacyDebrisAudited = true;
        }
      }
      const shrinkCollectionIds = new Set(
        managedClearState.names.map((name) => name.split("/documents/")[1].split("/")[0]),
      );
      const cleanableCollectionIds = collectionIds.filter(
        (collectionId) =>
          managedClearState.shrinkScope !== "v3" || !LEGACY_SHRINK_COLLECTIONS.has(collectionId),
      );
      if (cleanableCollectionIds.length === 0) {
        if (verifyManagedScope) {
          await verifyManagedShrinkScopeAbsent(base);
          if (managedClearState.shrinkScope === "v3") {
            await writeV3CleanupJournal("complete", {
              verifiedAbsentNames: [...managedClearState.names],
            });
          }
        }
        managedClearBlocked = false;
        return;
      }
      if (cleanableCollectionIds.some((collectionId) => shrinkCollectionIds.has(collectionId))) {
        await preflightManagedShrinkScope();
        managedClearState.preflightDone = true;
      }
    }
    const managedFailures = [];
    for (const collectionId of collectionIds) {
      if (
        shrinkScopeActive &&
        managedClearState.shrinkScope === "v3" &&
        LEGACY_SHRINK_COLLECTIONS.has(collectionId)
      ) {
        continue;
      }
      managedFailures.push(...(await deleteCollection(base, "", collectionId)));
    }
    if (managedFailures.length > 0) await managedClear(database, managedFailures);
  }
  throw new Error("clear: the production database still lists collections after 8 rounds");
}

async function auditLegacyDebris(base) {
  if (!managedClearState || managedClearState.shrinkScope !== "v3") {
    throw new Error("legacy debris audit is restricted to corpus-v3 cleanup");
  }
  // This audit is read-only and runs once before this collector's first v3 cleanup write.
  // External writer exclusivity remains an operator precondition; this process cannot enforce it.
  const api = `${SCHEME}://${HOST}/v1/projects/${PROJECT}/databases/(default)`;
  const managedFetch = (input, init) =>
    managedShrinkRequest("legacy debris child collection audit", input, init);
  const groups = new Map();
  for (let index = 0; index < LEGACY_SHRINK_NAMES.length; index += 1) {
    const name = LEGACY_SHRINK_NAMES[index];
    const collectionId = name.split("/documents/")[1].split("/")[0];
    const groupNames = await managedGroupNames(api, collectionId, managedShrinkRequest);
    if (groupNames.length > 1 || (groupNames.length === 1 && groupNames[0] !== name)) {
      throw new Error("legacy debris collection group contains an unexpected document");
    }
    groups.set(name, groupNames.length === 1);
  }
  const readback = await managedShrinkRequest("legacy debris typed read", `${base}:batchGet`, {
    method: "POST",
    headers: authorized({ "content-type": "application/json" }),
    body: JSON.stringify({ documents: LEGACY_SHRINK_NAMES }),
    signal: timeoutSignal(),
  });
  if (!readback.ok) throw new Error(`legacy debris typed read ${readback.status}`);
  const rows = await readback.json();
  if (!Array.isArray(rows) || rows.length !== LEGACY_SHRINK_NAMES.length) {
    throw new Error("legacy debris typed read returned an incomplete result");
  }
  const seen = new Set();
  for (const row of rows) {
    const hasFound = Object.hasOwn(row ?? {}, "found");
    const hasMissing = Object.hasOwn(row ?? {}, "missing");
    const name = hasFound ? row.found?.name : row?.missing;
    if (
      hasFound === hasMissing ||
      !LEGACY_SHRINK_NAMES.includes(name) ||
      seen.has(name) ||
      row?.error ||
      (hasMissing && row.missing !== name)
    ) {
      throw new Error("legacy debris typed read returned an unexpected result");
    }
    seen.add(name);
    const found = Boolean(row.found);
    if (found !== groups.get(name)) {
      throw new Error("legacy debris changed during its read-only scope audit");
    }
    if (found) {
      const expectedLength = FROZEN_ARRAY_LENGTHS.get(canonicalCollectionId(name));
      validateLegacyDebrisDocument(row.found, name, expectedLength);
      const relative = name.slice(name.indexOf("/documents/") + "/documents/".length);
      const childCollections = await listCollectionIds(base, relative, managedFetch);
      if (!childCollections || childCollections.length !== 0) {
        throw new Error("legacy debris document has unexpected subcollections");
      }
    }
  }
  if (seen.size !== LEGACY_SHRINK_NAMES.length) {
    throw new Error("legacy debris typed read omitted a frozen name");
  }
}

/** Every collection id under `parentPath` (all pages), or `null` for a missing database. */
async function listCollectionIds(base, parentPath, request = trackedFetch) {
  const parent = parentPath ? `${base}/${parentPath}` : base;
  const ids = [];
  let pageToken;
  do {
    const input = `${parent}:listCollectionIds`;
    const init = {
      method: "POST",
      headers: authorized({ "content-type": "application/json" }),
      body: JSON.stringify(pageToken ? { pageToken } : {}),
      signal: timeoutSignal(),
    };
    const listed = await request(input, init);
    if (listed.status === 404) return null;
    if (!listed.ok) {
      throw new Error(`clear: listCollectionIds ${listed.status} ${await listed.text()}`);
    }
    const page = await listed.json();
    ids.push(...(page.collectionIds ?? []));
    pageToken = page.nextPageToken;
  } while (pageToken);
  return ids;
}

async function deleteCollection(base, parentPath, collectionId) {
  const parent = parentPath ? `${base}/${parentPath}` : base;
  // `showMissing` lists the parents that exist only through their subcollections, so the
  // recursion reaches every document however it was left behind.
  const names = [];
  const missing = [];
  const managedFailures = [];
  let pageToken;
  do {
    const query = new URLSearchParams({
      showMissing: "true",
      "mask.fieldPaths": "__name__",
      pageSize: "300",
      ...(pageToken ? { pageToken } : {}),
    });
    const listed = await trackedFetch(`${parent}/${collectionId}?${query}`, {
      headers: authorized(),
      signal: timeoutSignal(),
    });
    if (!listed.ok) throw new Error(`clear: list ${listed.status} ${await listed.text()}`);
    const page = await listed.json();
    for (const document of page.documents ?? []) {
      (document.createTime === undefined ? missing : names).push(document.name);
    }
    pageToken = page.nextPageToken;
  } while (pageToken);
  const shrinkScopeActive =
    managedClearState !== null && base.endsWith("/databases/(default)/documents");
  const scopedName = shrinkScopeActive
    ? managedClearState.names.find((name) => {
        const relative = name.slice(name.indexOf("/documents/") + "/documents/".length);
        return relative.split("/")[0] === collectionId;
      })
    : undefined;
  if (scopedName) {
    managedClearBlocked = true;
    if (!managedClearState.preflightDone) {
      await preflightManagedShrinkScope();
      managedClearState.preflightDone = true;
    }
    if (names.length !== 1 || names[0] !== scopedName || missing.length !== 0) {
      throw new Error("array shrink scope contains an unexpected document");
    }
    const scopedGroupNames = await managedGroupNames(
      `${SCHEME}://${HOST}/v1/projects/${PROJECT}/databases/(default)`,
      collectionId,
      managedShrinkRequest,
    );
    if (scopedGroupNames.length !== 1 || scopedGroupNames[0] !== scopedName) {
      throw new Error("array shrink scope contains an unexpected document");
    }
  }
  for (const name of [...names, ...missing]) {
    const relative = name.slice(name.indexOf("/documents/") + "/documents/".length);
    for (const child of (await listCollectionIds(base, relative)) ?? []) {
      managedFailures.push(...(await deleteCollection(base, relative, child)));
    }
  }
  const deleteChunkSize = scopedName && names.includes(scopedName) ? 1 : 400;
  for (let index = 0; index < names.length; index += deleteChunkSize) {
    const writes = names.slice(index, index + deleteChunkSize).map((name) => {
      if (scopedName && name === scopedName) {
        const updateTime = managedClearState.preflightUpdateTimes.get(name);
        if (!updateTime) throw new Error("array shrink target was not present in global preflight");
        return { delete: name, currentDocument: { updateTime } };
      }
      return { delete: name };
    });
    const candidate = writes.length === 1 ? writes[0].delete : null;
    const commitRequest = scopedName && candidate === scopedName ? managedShrinkRequest : null;
    const commitInit = {
      method: "POST",
      headers: authorized({ "content-type": "application/json" }),
      body: JSON.stringify({ writes }),
      signal: timeoutSignal(),
    };
    const scopedUpdateTime =
      scopedName && candidate === scopedName
        ? managedClearState.preflightUpdateTimes.get(candidate)
        : undefined;
    const commit = commitRequest
      ? managedClearState.shrinkScope === "v3"
        ? await sendV3CleanupDelete(
            "delete attempt",
            candidate,
            scopedUpdateTime,
            `${base}:commit`,
            commitInit,
          )
        : await commitRequest("delete attempt", `${base}:commit`, commitInit)
      : await trackedFetch(`${base}:commit`, commitInit);
    if (!commit.ok) {
      const body = await commit.text();
      if (
        PRODUCTION &&
        writes.length === 1 &&
        isManagedClearCommitRefusal(
          commit.status,
          body,
          candidate,
          parentPath,
          managedClearState?.names,
        )
      ) {
        if (managedClearState?.names.includes(candidate)) {
          managedClearBlocked = true;
          if (managedClearState.shrinkScope === "v3") {
            managedClearState.cleanupDeleteIntent = null;
            await writeV3CleanupJournal("shrinking", { lastRefusedName: candidate });
          }
          const retryUpdateTime = await shrinkBoundaryDocument(candidate);
          const retryInit = {
            method: "POST",
            headers: authorized({ "content-type": "application/json" }),
            body: JSON.stringify({
              writes: [{ delete: candidate, currentDocument: { updateTime: retryUpdateTime } }],
            }),
            signal: timeoutSignal(),
          };
          const retry =
            managedClearState.shrinkScope === "v3"
              ? await sendV3CleanupDelete(
                  "delete retry",
                  candidate,
                  retryUpdateTime,
                  `${base}:commit`,
                  retryInit,
                )
              : await managedShrinkRequest("delete retry", `${base}:commit`, retryInit);
          if (!retry.ok) {
            const retryBody = await retry.text();
            throw new Error(`clear: shrunk document delete ${retry.status} ${retryBody}`);
          }
        } else {
          managedFailures.push(candidate);
        }
      } else {
        throw new Error(`clear: commit ${commit.status} ${body}`);
      }
    }
    if (scopedName && candidate === scopedName) {
      await verifyShrunkDocumentAbsent(base, candidate);
      if (managedClearState.shrinkScope === "v3") {
        managedClearState.cleanupDeletedNames.push(candidate);
        managedClearState.cleanupDeleteIntent = null;
        await writeV3CleanupJournal("deleting");
      }
    }
  }
  return managedFailures;
}

async function managedShrinkRequest(label, input, init) {
  if (!managedClearState) throw new Error("array shrink has no frozen names");
  managedClearState.shrinkRequestCounter.claim();
  return trackedFetch(input, init);
}

async function preflightManagedShrinkScope() {
  if (!managedClearState) throw new Error("array shrink preflight has no frozen names");
  managedClearState.preflightUpdateTimes = new Map();
  const api = `${SCHEME}://${HOST}/v1/projects/${PROJECT}/databases/(default)`;
  const expectedByCollection = new Map(
    managedClearState.names.map((name) => [name.split("/documents/")[1].split("/")[0], name]),
  );
  const presentNames = [];
  for (const [collectionId, expectedName] of expectedByCollection) {
    const found = await managedGroupNames(api, collectionId, managedShrinkRequest);
    if (found.length > 1 || (found.length === 1 && found[0] !== expectedName)) {
      throw new Error(
        "array shrink global preflight found an unexpected collection-group document",
      );
    }
    if (found.length === 1) presentNames.push(expectedName);
  }
  for (const name of presentNames) {
    const response = await managedShrinkRequest(
      "global preflight document read",
      urlForDocument(name),
      {
        headers: authorized(),
        signal: timeoutSignal(),
      },
    );
    if (!response.ok) throw new Error(`array shrink global preflight read ${response.status}`);
    const expectedLength = FROZEN_ARRAY_LENGTHS.get(canonicalCollectionId(name));
    const document = await response.json();
    validateShrinkBoundaryState(document, name, expectedLength, { allowEmptyOmitted: true });
    managedClearState.preflightUpdateTimes.set(name, document.updateTime);
  }
}

async function shrinkBoundaryDocument(name) {
  const base = `${SCHEME}://${HOST}/v1/projects/${PROJECT}/databases/(default)/documents`;
  const read = await managedShrinkRequest("document read", urlForDocument(name), {
    headers: authorized(),
    signal: timeoutSignal(),
  });
  if (!read.ok) throw new Error(`array shrink read ${read.status}`);
  const document = await read.json();
  const preflightUpdateTime = managedClearState?.preflightUpdateTimes.get(name);
  if (!preflightUpdateTime || document.updateTime !== preflightUpdateTime) {
    throw new Error("array shrink target changed after global preflight");
  }
  const expectedLength = FROZEN_ARRAY_LENGTHS.get(canonicalCollectionId(name));
  let values = validateCurrentShrinkState(document, name, expectedLength);
  let updateTime = document.updateTime;
  while (values.length > 0) {
    let chunkSize = Math.min(SHRINK_CHUNK_SIZE, values.length);
    let committed;
    while (true) {
      const removed = values.slice(0, chunkSize);
      committed = await managedShrinkRequest("arrayRemove commit", `${base}:commit`, {
        method: "POST",
        headers: authorized({ "content-type": "application/json" }),
        body: JSON.stringify({
          writes: [
            {
              transform: {
                document: name,
                fieldTransforms: [{ fieldPath: "a", removeAllFromArray: { values: removed } }],
              },
              currentDocument: { updateTime },
            },
          ],
        }),
        signal: timeoutSignal(),
      });
      if (committed.ok) break;
      const body = await committed.text();
      if (!isTransactionTooBigRefusal(committed.status, body)) {
        throw new Error(`array shrink transform ${committed.status} ${body}`);
      }
      if (chunkSize <= 1) throw new Error("array shrink refused the minimum single-value chunk");
      chunkSize = Math.max(1, Math.floor(chunkSize / 2));
    }
    const result = await committed.json();
    const nextUpdateTime = result?.writeResults?.[0]?.updateTime;
    if (typeof nextUpdateTime !== "string" || !nextUpdateTime) {
      throw new Error("array shrink transform omitted its updateTime");
    }
    updateTime = nextUpdateTime;
    values = values.slice(chunkSize);
  }
  const readback = await managedShrinkRequest("post-shrink read", urlForDocument(name), {
    headers: authorized(),
    signal: timeoutSignal(),
  });
  if (!readback.ok) throw new Error(`array shrink verification ${readback.status}`);
  const shrunkDocument = await readback.json();
  if (shrunkDocument.updateTime !== updateTime) {
    throw new Error("array shrink target changed during post-shrink verification");
  }
  const shrunk = validateCurrentShrinkState(shrunkDocument, name, expectedLength);
  if (shrunk.length !== 0) throw new Error("array shrink left indexed array values behind");
  return shrunkDocument.updateTime;
}

function validateCurrentShrinkState(document, name, expectedLength) {
  if (managedClearState?.shrinkScope === "legacy") {
    return validateLegacyDebrisDocument(document, name, expectedLength);
  }
  return validateShrinkBoundaryState(document, name, expectedLength, { allowEmptyOmitted: true });
}

function isTransactionTooBigRefusal(status, body) {
  if (status !== 400) return false;
  try {
    const error = JSON.parse(body)?.error;
    return (
      error?.status === "INVALID_ARGUMENT" &&
      error?.message === "Transaction too big. Decrease transaction size."
    );
  } catch {
    return false;
  }
}

async function validateDeleteAcknowledgement(response) {
  let acknowledgement;
  try {
    acknowledgement = await response.json();
  } catch (error) {
    throw new Error("managed cleanup delete acknowledgement is not JSON", { cause: error });
  }
  const results = acknowledgement?.writeResults;
  if (
    !Array.isArray(results) ||
    results.length !== 1 ||
    !results[0] ||
    typeof results[0] !== "object" ||
    Array.isArray(results[0]) ||
    (Object.hasOwn(results[0], "updateTime") &&
      (typeof results[0].updateTime !== "string" || !results[0].updateTime))
  ) {
    throw new Error("managed cleanup delete acknowledgement is uncertain");
  }
}

async function writeV3CleanupJournal(status, extra = {}) {
  if (!MANAGED_CLEAR_JOURNAL || managedClearState?.shrinkScope !== "v3") {
    throw new Error("corpus-v3 cleanup journal is unavailable");
  }
  await writePrivateJsonDurably(MANAGED_CLEAR_JOURNAL, {
    schemaVersion: 1,
    mode: "cleanup-corpus-v3",
    status,
    project: PROJECT,
    database: "(default)",
    runId: deleteRunId,
    corpusDigest: CORPUS_DIGEST,
    sourceGitSha: SOURCE_GIT_SHA,
    names: managedClearState.names,
    deletedNames: [...managedClearState.cleanupDeletedNames],
    deleteIntent: managedClearState.cleanupDeleteIntent,
    ...extra,
  });
}

async function writeDeltaCleanupJournal(status, extra = {}) {
  if (!MANAGED_CLEAR_JOURNAL || managedClearState?.shrinkScope !== "delta-v3") return;
  await writePrivateJsonDurably(MANAGED_CLEAR_JOURNAL, {
    schemaVersion: 1,
    mode: "cleanup-delta-v3",
    status,
    project: PROJECT,
    database: "(default)",
    runId: deleteRunId,
    corpusDigest: CORPUS_DIGEST,
    sourceGitSha: SOURCE_GIT_SHA,
    writerExclusivity: "task-lock-held; run-specific six collection groups have no external writer",
    names: managedClearState.names,
    httpRequestCount: requestCount,
    managedRequestCount: managedClearState.shrinkRequestCounter.current(),
    bulkDeleteIntent: managedClearState.bulkDeleteIntent ?? null,
    bulkDeleteOperation: managedClearState.bulkDeleteOperation ?? null,
    pendingMutation: managedClearState.pendingMutation ?? null,
    lastMutation: managedClearState.lastMutation ?? null,
    ...extra,
  });
}

async function clearDeltaV3Exact(base, verifyManagedScope) {
  if (!managedClearState || managedClearState.shrinkScope !== "delta-v3") {
    throw new Error("delta-v3 cleanup escaped its exact six-name scope");
  }
  managedClearBlocked = true;
  managedClearState.preflightDone = false;
  await preflightManagedShrinkScope();
  managedClearState.preflightDone = true;
  for (const name of managedClearState.names) {
    const relative = name.slice(name.indexOf("/documents/") + "/documents/".length);
    const children = await listCollectionIds(base, relative, (input, init) =>
      managedShrinkRequest("delta-v3 child-collection preflight", input, init),
    );
    if (children === null || children.length !== 0) {
      throw new Error("delta-v3 found an absent/changed target or unexpected child collection");
    }
  }
  const collectionIds = managedClearScope(managedClearState.names, PROJECT, "(default)");
  const presentNames = [...managedClearState.preflightUpdateTimes.keys()];
  const presentCollections = collectionIds.filter((collectionId) =>
    presentNames.some((name) => name.split("/documents/")[1].split("/")[0] === collectionId),
  );
  if (presentCollections.length > 0) {
    if (managedClearState.bulkDeleteIntent || managedClearState.bulkDeleteOperation) {
      throw new Error("delta-v3 cleanup has an unresolved prior bulk-delete operation");
    }
    managedClearState.bulkDeleteIntent = {
      collectionIds: presentCollections,
      names: presentNames,
      updateTimes: Object.fromEntries(managedClearState.preflightUpdateTimes),
    };
    await writeDeltaCleanupJournal("bulk-delete-intent");
    const api = `${SCHEME}://${HOST}/v1/projects/${PROJECT}/databases/(default)`;
    const started = await managedShrinkRequest(
      "delta-v3 bulk-delete start",
      `${api}:bulkDeleteDocuments`,
      {
        method: "POST",
        headers: authorized({ "content-type": "application/json" }),
        body: JSON.stringify({ collectionIds: presentCollections, namespaceIds: [""] }),
        signal: timeoutSignal(),
      },
    );
    if (!started.ok) throw new Error(`delta-v3 bulk-delete start ${started.status}`);
    const operation = (await started.json()).name;
    const operationPrefix = `projects/${PROJECT}/databases/(default)/operations/`;
    if (
      typeof operation !== "string" ||
      !operation.startsWith(operationPrefix) ||
      !/^[A-Za-z0-9_-]+$/.test(operation.slice(operationPrefix.length))
    ) {
      throw new Error("delta-v3 bulk-delete operation escaped the fixed sandbox");
    }
    managedClearState.bulkDeleteOperation = operation;
    await writeDeltaCleanupJournal("bulk-delete-active");
    await pollDeltaV3BulkDelete();
  }
  if (verifyManagedScope) {
    await verifyManagedShrinkScopeAbsent(base);
    await writeDeltaCleanupJournal("complete");
  }
  managedClearBlocked = false;
}

async function pollDeltaV3BulkDelete() {
  if (!managedClearState?.bulkDeleteOperation) {
    throw new Error("delta-v3 recovery cannot resume without a durable bulk-delete operation");
  }
  const api = `${SCHEME}://${HOST}/v1`;
  const pollLimit = Math.min(100, 400 - managedClearState.shrinkRequestCounter.current());
  for (let attempt = 0; attempt < pollLimit; attempt += 1) {
    const response = await managedShrinkRequest(
      "delta-v3 bulk-delete poll",
      `${api}/${managedClearState.bulkDeleteOperation}`,
      { headers: authorized(), signal: timeoutSignal() },
    );
    if (!response.ok) throw new Error(`delta-v3 bulk-delete poll ${response.status}`);
    const state = await response.json();
    if (state.done === true) {
      validateManagedClearOperation(state, PROJECT);
      managedClearState.bulkDeleteOperation = null;
      managedClearState.bulkDeleteIntent = null;
      await writeDeltaCleanupJournal("bulk-delete-done");
      return;
    }
  }
  throw new Error(
    "delta-v3 bulk-delete remains nonterminal; preserve its journal and block new sends",
  );
}

async function sendV3CleanupDelete(action, name, updateTime, input, init) {
  if (!managedClearState || managedClearState.shrinkScope !== "v3") {
    throw new Error("corpus-v3 cleanup delete escaped its frozen scope");
  }
  managedClearState.cleanupDeleteIntent = {
    action,
    name,
    updateTime,
    priorDeletedNames: [...managedClearState.cleanupDeletedNames],
  };
  await writeV3CleanupJournal("deleting");
  const response = await managedShrinkRequest(action, input, init);
  if (response.ok) await validateDeleteAcknowledgement(response.clone());
  return response;
}

async function writeManagedRecoveryJournal(status, extra = {}) {
  if (!MANAGED_CLEAR_JOURNAL) throw new Error("managed recovery journal is required");
  const recovery = managedClearState?.recoveryJournal;
  const entry = {
    schemaVersion: 1,
    mode: "recover-legacy",
    status,
    project: PROJECT,
    database: "(default)",
    names: LEGACY_SHRINK_NAMES,
    ...(recovery ? { deletedNames: recovery.deletedNames } : {}),
    ...(recovery ? { verifiedAbsentNames: recovery.verifiedAbsentNames } : {}),
    ...(recovery?.deleteIntent ? { deleteIntent: recovery.deleteIntent } : {}),
    ...extra,
  };
  await writePrivateJsonDurably(MANAGED_CLEAR_JOURNAL, entry);
}

export async function writePrivateJsonDurably(
  path,
  value,
  {
    writeTemp = (handle, contents) => handle.writeFile(contents),
    syncFile = (handle) => handle.sync(),
    renameTemp = (temporary, target) => rename(temporary, target),
    syncDirectory = (handle) => handle.sync(),
  } = {},
) {
  const parent = dirname(path);
  const temporary = join(parent, `.${randomUUID()}.journal-tmp`);
  let renamed = false;
  let fileHandle;
  try {
    fileHandle = await open(temporary, "wx", 0o600);
    await writeTemp(fileHandle, `${JSON.stringify(value)}\n`);
    await syncFile(fileHandle);
    await fileHandle.close();
    fileHandle = null;
    await renameTemp(temporary, path);
    renamed = true;
    const directoryHandle = await open(parent, "r");
    try {
      await syncDirectory(directoryHandle);
    } finally {
      await directoryHandle.close();
    }
  } catch (error) {
    throw new Error("could not durably persist private journal", { cause: error });
  } finally {
    if (fileHandle) await fileHandle.close().catch(() => {});
    if (!renamed) await unlink(temporary).catch(() => {});
  }
}

export async function sendDeleteAfterWriteAhead(persistIntent, sendDelete) {
  await persistIntent();
  return sendDelete();
}

async function readManagedRecoveryJournal() {
  let journal;
  try {
    journal = JSON.parse(await readFile(MANAGED_CLEAR_JOURNAL, "utf8"));
  } catch (error) {
    if (error?.code === "ENOENT") {
      return { deletedNames: [], verifiedAbsentNames: [], deleteIntent: null };
    }
    throw new Error("legacy recovery journal is unreadable", { cause: error });
  }
  const deletedNames = journal?.deletedNames ?? [];
  const verifiedAbsentNames = journal?.verifiedAbsentNames ?? [];
  const deleteIntent = journal?.deleteIntent ?? null;
  if (
    journal?.schemaVersion !== 1 ||
    journal.mode !== "recover-legacy" ||
    journal.project !== PROJECT ||
    journal.database !== "(default)" ||
    JSON.stringify(journal.names) !== JSON.stringify(LEGACY_SHRINK_NAMES) ||
    !Array.isArray(deletedNames) ||
    deletedNames.some((name) => !LEGACY_SHRINK_NAMES.includes(name)) ||
    new Set(deletedNames).size !== deletedNames.length ||
    !Array.isArray(verifiedAbsentNames) ||
    verifiedAbsentNames.some((name) => !LEGACY_SHRINK_NAMES.includes(name)) ||
    new Set(verifiedAbsentNames).size !== verifiedAbsentNames.length ||
    verifiedAbsentNames.some((name) => deletedNames.includes(name)) ||
    (deleteIntent !== null &&
      (deleteIntent.action !== "commit-delete" ||
        !LEGACY_SHRINK_NAMES.includes(deleteIntent.name) ||
        typeof deleteIntent.updateTime !== "string" ||
        !deleteIntent.updateTime ||
        !Array.isArray(deleteIntent.priorDeletedNames) ||
        JSON.stringify(deleteIntent.priorDeletedNames) !== JSON.stringify(deletedNames)))
  ) {
    throw new Error("legacy recovery journal does not match the frozen deletion scope");
  }
  return { deletedNames, verifiedAbsentNames, deleteIntent };
}

async function preflightLegacyRecoveryScope(base) {
  if (!managedClearState || managedClearState.shrinkScope !== "legacy") {
    throw new Error("legacy recovery preflight has no exact frozen scope");
  }
  managedClearState.preflightUpdateTimes = new Map();
  const api = `${SCHEME}://${HOST}/v1/projects/${PROJECT}/databases/(default)`;
  const groupPresence = new Map();
  for (const name of LEGACY_SHRINK_NAMES) {
    const collectionId = name.split("/documents/")[1].split("/")[0];
    const names = await managedGroupNames(api, collectionId, managedShrinkRequest);
    if (names.length > 1 || (names.length === 1 && names[0] !== name)) {
      throw new Error("legacy recovery collection group contains an unexpected document");
    }
    groupPresence.set(name, names.length === 1);
  }
  const readback = await managedShrinkRequest(
    "legacy recovery typed preflight",
    `${base}:batchGet`,
    {
      method: "POST",
      headers: authorized({ "content-type": "application/json" }),
      body: JSON.stringify({ documents: LEGACY_SHRINK_NAMES }),
      signal: timeoutSignal(),
    },
  );
  if (!readback.ok) throw new Error(`legacy recovery typed preflight ${readback.status}`);
  const rows = await readback.json();
  if (!Array.isArray(rows) || rows.length !== LEGACY_SHRINK_NAMES.length) {
    throw new Error("legacy recovery typed preflight is incomplete");
  }
  const seen = new Set();
  for (const row of rows) {
    const hasFound = Object.hasOwn(row ?? {}, "found");
    const hasMissing = Object.hasOwn(row ?? {}, "missing");
    const name = hasFound ? row.found?.name : row?.missing;
    if (
      hasFound === hasMissing ||
      !LEGACY_SHRINK_NAMES.includes(name) ||
      seen.has(name) ||
      row?.error ||
      (hasMissing && row.missing !== name)
    ) {
      throw new Error("legacy recovery typed preflight returned an unexpected result");
    }
    seen.add(name);
    const found = Boolean(row.found);
    if (found !== groupPresence.get(name)) {
      throw new Error("legacy recovery changed during its read-only scope preflight");
    }
    if (found) {
      const collectionId = name.split("/documents/")[1].split("/")[0];
      validateLegacyDebrisDocument(row.found, name, FROZEN_ARRAY_LENGTHS.get(collectionId));
      managedClearState.preflightUpdateTimes.set(name, row.found.updateTime);
    }
    const relative = name.slice(name.indexOf("/documents/") + "/documents/".length);
    const children = await listCollectionIds(base, relative, (input, init) =>
      managedShrinkRequest("legacy recovery child collection preflight", input, init),
    );
    if (children === null || children.length !== 0) {
      throw new Error("legacy recovery target has an unexpected or unverified child collection");
    }
  }
  if (seen.size !== LEGACY_SHRINK_NAMES.length) {
    throw new Error("legacy recovery typed preflight omitted a frozen name");
  }
}

async function recoverLegacyManagedClear() {
  const base = `${SCHEME}://${HOST}/v1/projects/${PROJECT}/databases/(default)/documents`;
  managedClearBlocked = true;
  managedClearState.recoveryJournal = await readManagedRecoveryJournal();
  await writeManagedRecoveryJournal("starting");
  await preflightLegacyRecoveryScope(base);
  const { deletedNames, deleteIntent } = managedClearState.recoveryJournal;
  if (deletedNames.some((name) => managedClearState.preflightUpdateTimes.has(name))) {
    throw new Error("legacy recovery found a previously deleted name present again");
  }
  if (
    managedClearState.recoveryJournal.verifiedAbsentNames.some((name) =>
      managedClearState.preflightUpdateTimes.has(name),
    )
  ) {
    throw new Error("legacy recovery found a previously verified-absent name present again");
  }
  if (deleteIntent && !managedClearState.preflightUpdateTimes.has(deleteIntent.name)) {
    managedClearState.recoveryJournal.deletedNames.push(deleteIntent.name);
    managedClearState.recoveryJournal.verifiedAbsentNames =
      managedClearState.recoveryJournal.verifiedAbsentNames.filter(
        (name) => name !== deleteIntent.name,
      );
    managedClearState.recoveryJournal.deleteIntent = null;
    await writeManagedRecoveryJournal("deleting");
  }
  const pendingAcknowledgedName =
    deleteIntent && !managedClearState.preflightUpdateTimes.has(deleteIntent.name)
      ? deleteIntent.name
      : null;
  managedClearState.recoveryJournal.verifiedAbsentNames = [
    ...new Set([
      ...managedClearState.recoveryJournal.verifiedAbsentNames,
      ...LEGACY_SHRINK_NAMES.filter(
        (name) =>
          !managedClearState.preflightUpdateTimes.has(name) &&
          !managedClearState.recoveryJournal.deletedNames.includes(name) &&
          name !== pendingAcknowledgedName,
      ),
    ]),
  ];
  await writeManagedRecoveryJournal("preflight-complete", {
    presentNames: [...managedClearState.preflightUpdateTimes.keys()],
    absentNames: LEGACY_SHRINK_NAMES.filter(
      (name) => !managedClearState.preflightUpdateTimes.has(name),
    ),
    verifiedAbsentNames: managedClearState.recoveryJournal.verifiedAbsentNames,
  });
  for (const name of LEGACY_SHRINK_NAMES) {
    if (!managedClearState.preflightUpdateTimes.has(name)) continue;
    const updateTime = await shrinkBoundaryDocument(name);
    managedClearState.recoveryJournal.deleteIntent = {
      action: "commit-delete",
      name,
      priorDeletedNames: [...managedClearState.recoveryJournal.deletedNames],
      updateTime,
    };
    const deleted = await sendDeleteAfterWriteAhead(
      () => writeManagedRecoveryJournal("deleting"),
      () =>
        managedShrinkRequest("exact legacy document delete", `${base}:commit`, {
          method: "POST",
          headers: authorized({ "content-type": "application/json" }),
          body: JSON.stringify({
            writes: [{ delete: name, currentDocument: { updateTime } }],
          }),
          signal: timeoutSignal(),
        }),
    );
    if (!deleted.ok) {
      const body = await deleted.text();
      throw new Error(`legacy recovery exact delete ${deleted.status} ${body}`);
    }
    const acknowledgement = await deleted.json();
    if (
      !Array.isArray(acknowledgement?.writeResults) ||
      acknowledgement.writeResults.length !== 1 ||
      !acknowledgement.writeResults[0] ||
      typeof acknowledgement.writeResults[0] !== "object" ||
      Array.isArray(acknowledgement.writeResults[0]) ||
      (Object.hasOwn(acknowledgement.writeResults[0], "updateTime") &&
        typeof acknowledgement.writeResults[0].updateTime !== "string")
    ) {
      throw new Error("legacy recovery exact delete acknowledgement is uncertain");
    }
    const readback = await managedShrinkRequest(
      "legacy recovery exact delete absence",
      `${base}:batchGet`,
      {
        method: "POST",
        headers: authorized({ "content-type": "application/json" }),
        body: JSON.stringify({ documents: [name] }),
        signal: timeoutSignal(),
      },
    );
    if (!readback.ok || !validateManagedClearReadback([name], await readback.json())) {
      throw new Error("legacy recovery exact delete typed absence was not proved");
    }
    managedClearState.recoveryJournal.deletedNames.push(name);
    managedClearState.recoveryJournal.deleteIntent = null;
    await writeManagedRecoveryJournal("deleting");
  }
  await verifyManagedShrinkScopeAbsent(base);
  await writeManagedRecoveryJournal("complete");
  managedClearBlocked = false;
}

async function runLegacyRecoveryOnly() {
  if (!HOST || !META_OUT || !MANAGED_CLEAR_JOURNAL) {
    throw new Error("legacy recovery requires a target, private journal and metadata");
  }
  const names = JSON.parse(MANAGED_CLEAR_NAMES ?? "null");
  if (JSON.stringify(names) !== JSON.stringify(LEGACY_SHRINK_NAMES)) {
    throw new Error("legacy recovery names do not match the exact frozen scope");
  }
  if (!requestBudget || MAX_REQUESTS !== "1000") {
    throw new Error("legacy recovery requires the fixed 1000-request session cap");
  }
  managedClearScope(names, PROJECT, "(default)");
  managedClearState = {
    names,
    shrinkScope: "legacy",
    recoveryOnly: true,
    preflightUpdateTimes: new Map(),
    shrinkRequestCounter: createShrinkRequestCounter(SHRINK_REQUEST_CAPS.legacy),
  };
  try {
    await recoverLegacyManagedClear();
  } finally {
    await writeFile(META_OUT, `${JSON.stringify({ requestCount })}\n`, { mode: 0o600 });
  }
}

async function runV3RecoveryOnly() {
  if (
    !PRODUCTION ||
    PROJECT !== "fireemu-oracle-sbx" ||
    !HOST ||
    !META_OUT ||
    !MANAGED_CLEAR_JOURNAL
  ) {
    throw new Error("corpus-v3 recovery requires the fixed production sandbox and private journal");
  }
  if (!requestBudget || MAX_REQUESTS !== "1000") {
    throw new Error("corpus-v3 recovery requires the fixed 1000-request cap");
  }
  let journal;
  try {
    journal = JSON.parse(await readFile(MANAGED_CLEAR_JOURNAL, "utf8"));
  } catch (error) {
    throw new Error("corpus-v3 recovery journal is unreadable", { cause: error });
  }
  const staticNames = JSON.parse(MANAGED_CLEAR_NAMES ?? "null");
  if (
    !/^[a-f0-9]{32}$/.test(journal?.runId ?? "") ||
    !/^[a-f0-9]{64}$/.test(journal?.corpusDigest ?? "") ||
    !/^[a-f0-9]{40}$/.test(journal?.sourceGitSha ?? "") ||
    journal.schemaVersion !== 1 ||
    journal.mode !== "cleanup-corpus-v3" ||
    journal.project !== PROJECT ||
    journal.database !== "(default)" ||
    !Array.isArray(staticNames) ||
    JSON.stringify(staticNames.map((name) => name.replaceAll(DELETE_RUN_MARKER, journal.runId))) !==
      JSON.stringify(journal.names) ||
    !Array.isArray(journal.deletedNames) ||
    journal.deletedNames.some((name) => !journal.names.includes(name)) ||
    new Set(journal.deletedNames).size !== journal.deletedNames.length ||
    !["prepared", "active", "deleting", "shrinking", "complete", "recovering"].includes(
      journal.status,
    ) ||
    (journal.deleteIntent !== null &&
      (!journal.names.includes(journal.deleteIntent?.name) ||
        !["delete attempt", "delete retry"].includes(journal.deleteIntent?.action) ||
        typeof journal.deleteIntent.updateTime !== "string" ||
        !journal.deleteIntent.updateTime ||
        !Array.isArray(journal.deleteIntent.priorDeletedNames) ||
        JSON.stringify(journal.deleteIntent.priorDeletedNames) !==
          JSON.stringify(journal.deletedNames)))
  ) {
    throw new Error("corpus-v3 recovery journal escaped its exact frozen scope");
  }
  deleteRunId = journal.runId;
  const names = journal.names;
  managedClearScope(names, PROJECT, "(default)");
  managedClearState = {
    names,
    shrinkScope: "v3",
    recoveryOnly: true,
    preflightUpdateTimes: new Map(),
    shrinkRequestCounter: createShrinkRequestCounter(SHRINK_REQUEST_CAPS.v3),
    legacyDebrisAudited: true,
    cleanupDeletedNames: [...journal.deletedNames],
    cleanupDeleteIntent: journal.deleteIntent,
    preflightDone: false,
  };
  if (journal.status === "complete") {
    throw new Error("corpus-v3 recovery journal is already complete");
  }
  const base = `${SCHEME}://${HOST}/v1/projects/${PROJECT}/databases/(default)/documents`;
  managedClearBlocked = true;
  try {
    await writeV3CleanupJournal("recovering", { recoveredFrom: journal.status });
    await preflightManagedShrinkScope();
    managedClearState.preflightDone = true;
    for (const name of names) {
      const relative = name.split("/documents/")[1];
      const children = await listCollectionIds(base, relative, (input, init) =>
        managedShrinkRequest("v3 recovery child-collection preflight", input, init),
      );
      if (children === null || children.length !== 0) {
        throw new Error("corpus-v3 recovery found an unexpected child collection");
      }
    }
    const intent = managedClearState.cleanupDeleteIntent;
    if (intent && !managedClearState.preflightUpdateTimes.has(intent.name)) {
      managedClearState.cleanupDeletedNames.push(intent.name);
      managedClearState.cleanupDeleteIntent = null;
      await writeV3CleanupJournal("deleting");
    }
    for (const name of names) {
      const present = managedClearState.preflightUpdateTimes.has(name);
      if (managedClearState.cleanupDeletedNames.includes(name)) {
        if (present)
          throw new Error("corpus-v3 recovery found a previously deleted name present again");
        continue;
      }
      if (!present) {
        managedClearState.cleanupDeletedNames.push(name);
        await writeV3CleanupJournal("deleting");
        continue;
      }
      const collectionId = name.split("/documents/")[1].split("/")[0];
      const failures = await deleteCollection(base, "", collectionId);
      if (failures.length !== 0)
        throw new Error("corpus-v3 recovery left an exact-scope delete failure");
    }
    await verifyManagedShrinkScopeAbsent(base);
    await writeV3CleanupJournal("complete", { verifiedAbsentNames: [...names] });
    managedClearBlocked = false;
  } finally {
    await writeFile(META_OUT, `${JSON.stringify({ requestCount })}\n`, { mode: 0o600 });
  }
}

async function runDeltaV3RecoveryOnly() {
  if (
    !DELTA_V3_MODE ||
    !DELTA_LOCK_HELD ||
    !PRODUCTION ||
    PROJECT !== "fireemu-oracle-sbx" ||
    !HOST ||
    !META_OUT ||
    !MANAGED_CLEAR_JOURNAL
  ) {
    throw new Error("delta-v3 recovery requires the fixed sandbox target and private journal");
  }
  let journal;
  try {
    journal = JSON.parse(await readFile(MANAGED_CLEAR_JOURNAL, "utf8"));
  } catch (error) {
    throw new Error("delta-v3 recovery journal is unreadable", { cause: error });
  }
  const staticNames = JSON.parse(MANAGED_CLEAR_NAMES ?? "null");
  if (
    !/^[a-f0-9]{32}$/.test(journal?.runId ?? "") ||
    journal.runId !== process.env.FIRESTORE_PROBE_DELETE_RUN_ID
  ) {
    throw new Error("delta-v3 recovery run ID does not match its invocation");
  }
  deleteRunId = journal.runId;
  if (
    journal?.schemaVersion !== 1 ||
    journal.mode !== "cleanup-delta-v3" ||
    journal.project !== PROJECT ||
    journal.database !== "(default)" ||
    journal.status === "complete" ||
    !/^[a-f0-9]{64}$/.test(journal.corpusDigest ?? "") ||
    journal.corpusDigest !== CORPUS_DIGEST ||
    !/^[a-f0-9]{40}$/.test(journal.sourceGitSha ?? "") ||
    journal.sourceGitSha !== SOURCE_GIT_SHA ||
    journal.writerExclusivity !==
      "task-lock-held; run-specific six collection groups have no external writer" ||
    !Array.isArray(staticNames) ||
    JSON.stringify(staticNames.map((name) => name.replaceAll(DELETE_RUN_MARKER, journal.runId))) !==
      JSON.stringify(journal.names) ||
    managedShrinkScope(journal.names, PROJECT, "(default)") !== "delta-v3" ||
    !Number.isSafeInteger(journal.httpRequestCount) ||
    journal.httpRequestCount < 0 ||
    journal.httpRequestCount >= 430 ||
    !Number.isSafeInteger(journal.managedRequestCount) ||
    journal.managedRequestCount < 0 ||
    journal.managedRequestCount > 400
  ) {
    throw new Error("delta-v3 recovery journal escaped its source-bound six-name scope");
  }
  if (journal.bulkDeleteIntent && !journal.bulkDeleteOperation) {
    throw new Error(
      "delta-v3 bulk-delete send is uncertain; preserve its blocker and do not resend",
    );
  }
  if (
    journal.bulkDeleteOperation &&
    !new RegExp(`^projects/${PROJECT}/databases/\\(default\\)/operations/[A-Za-z0-9_-]+$`).test(
      journal.bulkDeleteOperation,
    )
  ) {
    throw new Error("delta-v3 recovery operation escaped the fixed sandbox");
  }
  const remainingHttp = 430 - journal.httpRequestCount;
  if (!requestBudget || Number(MAX_REQUESTS) !== remainingHttp) {
    throw new Error("delta-v3 recovery must use the journal's remaining HTTP reservation");
  }
  deleteRunId = journal.runId;
  requestCount = journal.httpRequestCount;
  managedClearState = {
    names: journal.names,
    shrinkScope: "delta-v3",
    recoveryOnly: true,
    preflightUpdateTimes: new Map(),
    shrinkRequestCounter: createShrinkRequestCounter(400, journal.managedRequestCount),
    legacyDebrisAudited: true,
    cleanupDeletedNames: [],
    cleanupDeleteIntent: null,
    bulkDeleteIntent: journal.bulkDeleteIntent ?? null,
    bulkDeleteOperation: journal.bulkDeleteOperation ?? null,
    pendingMutation: journal.pendingMutation ?? null,
    lastMutation: journal.lastMutation ?? null,
  };
  const base = `${SCHEME}://${HOST}/v1/projects/${PROJECT}/databases/(default)/documents`;
  managedClearBlocked = true;
  await resolveDeltaPendingMutation();
  if (managedClearState.bulkDeleteOperation) await pollDeltaV3BulkDelete();
  await clearDeltaV3Exact(base, true);
  if (META_OUT) await writeFile(META_OUT, `${JSON.stringify({ requestCount })}\n`, { mode: 0o600 });
}

async function resolveDeltaPendingMutation() {
  const pending = managedClearState?.pendingMutation;
  if (!pending) return;
  const name = pending.name;
  if (
    !managedClearState.names.includes(name) ||
    !["seed", "delete"].includes(pending.stepId) ||
    !/^[a-f0-9]{64}$/.test(pending.bodySha256 ?? "")
  ) {
    throw new Error("delta-v3 pending mutation is outside its exact journaled target");
  }
  const collectionId = name.split("/documents/")[1].split("/")[0];
  const route = collectionId.startsWith("delrest")
    ? "rest"
    : collectionId.startsWith("delcommit")
      ? "commit"
      : collectionId.startsWith("delbatchwrite")
        ? "batch-write"
        : null;
  const isPatchSeed = pending.stepId === "seed" && pending.method === "PATCH";
  const expectedMethod =
    pending.stepId === "seed"
      ? isPatchSeed
        ? "PATCH"
        : "POST"
      : route === "rest"
        ? "DELETE"
        : route
          ? "POST"
          : null;
  const expectedPath = isPatchSeed
    ? `/v1/${name}`
    : pending.stepId === "seed" || route === "commit"
      ? `/v1/projects/${PROJECT}/databases/(default)/documents:commit`
      : route === "rest"
        ? `/v1/${name}`
        : route === "batch-write"
          ? `/v1/projects/${PROJECT}/databases/(default)/documents:batchWrite`
          : null;
  let actualPath;
  try {
    actualPath = new URL(pending.url).pathname;
  } catch {
    actualPath = null;
  }
  if (!expectedMethod || pending.method !== expectedMethod || actualPath !== expectedPath) {
    throw new Error(
      "delta-v3 pending mutation does not match its frozen seed or route-specific DELETE",
    );
  }
  const expectedLength = FROZEN_ARRAY_LENGTHS.get(canonicalCollectionId(name));
  if (!expectedLength) throw new Error("delta-v3 pending target has no frozen generated length");
  const expectedBody =
    pending.stepId === "seed"
      ? isPatchSeed
        ? JSON.stringify({
            fields: {
              a: {
                arrayValue: {
                  values: Array.from({ length: expectedLength }, (_, index) => ({
                    integerValue: String(index),
                  })),
                },
              },
            },
          })
        : JSON.stringify({
            writes: [
              {
                update: {
                  name,
                  fields: {
                    a: {
                      arrayValue: {
                        values: Array.from({ length: expectedLength }, (_, index) => ({
                          integerValue: String(index),
                        })),
                      },
                    },
                  },
                },
              },
            ],
          })
      : route === "rest"
        ? ""
        : JSON.stringify({ writes: [{ delete: name }] });
  if (createHash("sha256").update(expectedBody).digest("hex") !== pending.bodySha256) {
    throw new Error("delta-v3 pending mutation body differs from its frozen seed or DELETE recipe");
  }
  managedClearState.pendingMutationResolutionName = name;
  let found;
  try {
    const response = await managedShrinkRequest(
      "pending mutation typed recovery read",
      urlForDocument(name),
      {
        headers: authorized(),
        signal: timeoutSignal(),
      },
    );
    if (response.status === 404) {
      found = null;
    } else if (response.ok) {
      const document = await response.json();
      validateShrinkBoundaryState(document, name, expectedLength);
      found = document;
    } else {
      throw new Error(`delta-v3 pending mutation read ${response.status}`);
    }
    const api = `${SCHEME}://${HOST}/v1/projects/${PROJECT}/databases/(default)`;
    const members = await managedGroupNames(api, collectionId, (label, input, init) =>
      managedShrinkRequest(label, input, init),
    );
    if (found ? members.length !== 1 || members[0] !== name : members.length !== 0) {
      throw new Error("delta-v3 pending mutation typed and collection-group reads disagree");
    }
  } finally {
    managedClearState.pendingMutationResolutionName = null;
  }
  managedClearState.pendingMutation = null;
  managedClearState.lastMutation = {
    ...pending,
    recoveredOutcome: found ? "target-present" : "target-absent",
    responseObserved: false,
  };
  await writeDeltaCleanupJournal("pending-mutation-resolved");
}

function urlForDocument(name) {
  const prefix = `projects/${PROJECT}/databases/(default)/documents/`;
  if (!name.startsWith(prefix)) throw new Error("array shrink document escaped the sandbox");
  return `${SCHEME}://${HOST}/v1/${name}`;
}

async function verifyShrunkDocumentAbsent(base, name) {
  const readback = await managedShrinkRequest("typed absence read", `${base}:batchGet`, {
    method: "POST",
    headers: authorized({ "content-type": "application/json" }),
    body: JSON.stringify({ documents: [name] }),
    signal: timeoutSignal(),
  });
  if (!readback.ok || !validateManagedClearReadback([name], await readback.json())) {
    throw new Error("array shrink cleanup did not prove exact typed absence");
  }
  const collectionId = name.split("/documents/")[1].split("/")[0];
  const api = `${SCHEME}://${HOST}/v1/projects/${PROJECT}/databases/(default)`;
  if ((await managedGroupNames(api, collectionId, managedShrinkRequest)).length !== 0) {
    throw new Error("array shrink cleanup collection group remains populated");
  }
}

async function verifyManagedShrinkScopeAbsent(base) {
  if (!managedClearState) throw new Error("array shrink absence check has no frozen names");
  const readback = await managedShrinkRequest("exact scope absence", `${base}:batchGet`, {
    method: "POST",
    headers: authorized({ "content-type": "application/json" }),
    body: JSON.stringify({ documents: managedClearState.names }),
    signal: timeoutSignal(),
  });
  if (
    !readback.ok ||
    !validateManagedClearReadback(managedClearState.names, await readback.json())
  ) {
    throw new Error("array shrink scope exact typed absence was not proved");
  }
  const api = `${SCHEME}://${HOST}/v1/projects/${PROJECT}/databases/(default)`;
  for (const collectionId of managedClearScope(managedClearState.names, PROJECT, "(default)")) {
    if ((await managedGroupNames(api, collectionId, managedShrinkRequest)).length !== 0) {
      throw new Error("array shrink scope collection group remains populated");
    }
  }
  if (managedClearState.recoveryOnly || managedClearState.shrinkScope === "delta-v3") {
    for (const name of managedClearState.names) {
      const relative = name.slice(name.indexOf("/documents/") + "/documents/".length);
      const children = await listCollectionIds(base, relative, (input, init) =>
        managedShrinkRequest("legacy recovery final child check", input, init),
      );
      if (children === null || children.length !== 0) {
        throw new Error("legacy recovery final child collection check was not empty");
      }
    }
  }
}

async function managedGroupNames(api, collectionId, request = trackedFetch) {
  const input = `${api}/documents:runQuery`;
  const init = {
    method: "POST",
    headers: authorized({ "content-type": "application/json" }),
    body: JSON.stringify({
      structuredQuery: {
        from: [{ collectionId, allDescendants: true }],
        select: { fields: [{ fieldPath: "__name__" }] },
        limit: 2,
      },
    }),
    signal: timeoutSignal(),
  };
  const response =
    request === trackedFetch
      ? await trackedFetch(input, init)
      : await request("collection-group confirmation", input, init);
  if (!response.ok) throw new Error(`managed clear scope query ${response.status}`);
  const rows = await response.json();
  if (!Array.isArray(rows) || rows.some((row) => row.error)) {
    throw new Error("managed clear scope query returned an invalid result");
  }
  return rows.filter((row) => row.document).map((row) => row.document.name);
}

async function managedClear(database, names) {
  managedClearBlocked = true;
  if (!managedClearState || !MANAGED_CLEAR_JOURNAL || database !== "(default)") {
    throw new Error("managed clear is not enabled for this observation");
  }
  const collectionIds = managedClearScope(names, PROJECT, database);
  if (names.some((name) => !managedClearState.names.includes(name))) {
    throw new Error("managed clear found a name outside the frozen corpus");
  }
  const api = `${SCHEME}://${HOST}/v1/projects/${PROJECT}/databases/${database}`;
  for (const [index, collectionId] of collectionIds.entries()) {
    const found = await managedGroupNames(api, collectionId);
    if (found.length !== 1 || found[0] !== names[index]) {
      throw new Error("managed clear collection group contains an unexpected document");
    }
  }
  const journal = { status: "starting", project: PROJECT, database, names, collectionIds };
  await writeFile(MANAGED_CLEAR_JOURNAL, `${JSON.stringify(journal)}\n`, { mode: 0o600 });
  const started = await trackedFetch(`${api}:bulkDeleteDocuments`, {
    method: "POST",
    headers: authorized({ "content-type": "application/json" }),
    body: JSON.stringify({ collectionIds, namespaceIds: [""] }),
    signal: timeoutSignal(),
  });
  if (!started.ok) throw new Error(`managed clear start ${started.status}`);
  const operation = (await started.json()).name;
  if (
    typeof operation !== "string" ||
    !new RegExp(`^projects/${PROJECT}/databases/\\(default\\)/operations/[A-Za-z0-9_-]+$`).test(
      operation,
    )
  ) {
    throw new Error("managed clear operation escaped the sandbox");
  }
  journal.status = "active";
  journal.operation = operation;
  await writeFile(MANAGED_CLEAR_JOURNAL, `${JSON.stringify(journal)}\n`, { mode: 0o600 });
  let terminal = false;
  for (let attempt = 0; attempt < 360; attempt += 1) {
    await new Promise((wake) => setTimeout(wake, MANAGED_POLL_MS));
    const response = await trackedFetch(`${SCHEME}://${HOST}/v1/${operation}`, {
      headers: authorized(),
      signal: timeoutSignal(),
    });
    if (!response.ok) throw new Error(`managed clear poll ${response.status}`);
    const state = await response.json();
    if (state.done === true) {
      validateManagedClearOperation(state, PROJECT);
      terminal = true;
      break;
    }
  }
  if (!terminal) throw new Error("managed clear operation did not finish within six hours");
  const readback = await trackedFetch(`${api}/documents:batchGet`, {
    method: "POST",
    headers: authorized({ "content-type": "application/json" }),
    body: JSON.stringify({ documents: names }),
    signal: timeoutSignal(),
  });
  if (!readback.ok || !validateManagedClearReadback(names, await readback.json())) {
    throw new Error("managed clear exact-name typed absence was not proved");
  }
  for (const collectionId of collectionIds) {
    if ((await managedGroupNames(api, collectionId)).length !== 0) {
      throw new Error("managed clear collection group remains populated");
    }
  }
  journal.status = "complete";
  await writeFile(MANAGED_CLEAR_JOURNAL, `${JSON.stringify(journal)}\n`, { mode: 0o600 });
  managedClearBlocked = false;
}

async function seed(documents) {
  for (const document of documents ?? []) {
    const input = url(document.path);
    const name = replaceRunMarker(document.path.replace(/^\/v1\//, ""));
    const body = JSON.stringify({ fields: substituteProject(document.fields) });
    await writeDeltaMutationIntent(name, "PATCH", "seed", input, body);
    const response = await trackedFetch(url(document.path), {
      method: "PATCH",
      headers: authorized({ "content-type": "application/json" }),
      body,
      signal: timeoutSignal(),
    });
    if (!response.ok) {
      throw new Error(`seed ${document.path}: ${response.status} ${await response.text()}`);
    }
  }
}

async function writeDeltaMutationIntent(name, method, stepId, input, body) {
  if (managedClearState?.shrinkScope !== "delta-v3") return;
  if (!managedClearState.names.includes(name)) {
    throw new Error("delta-v3 mutation target is outside the frozen six-name scope");
  }
  if (managedClearState.pendingMutation) {
    throw new Error("delta-v3 previous mutation is unresolved; stop and recover");
  }
  managedClearState.pendingMutation = {
    name,
    method,
    stepId,
    url: String(input),
    bodySha256: createHash("sha256")
      .update(body ?? "")
      .digest("hex"),
  };
  await writeDeltaCleanupJournal("write-ahead-mutation");
}

/** `a.b.0` into a recorded value; `undefined` when the path does not resolve. */
function lookup(value, path) {
  let current = value;
  for (const segment of path.split(".")) {
    if (current === null || current === undefined) return undefined;
    current = current[segment];
  }
  return current;
}

/** Replaces every `{ "$from": id, "path": p }` with the raw value step `id` recorded there. */
function resolve(value, raw) {
  if (Array.isArray(value)) return value.map((v) => resolve(v, raw));
  if (value && typeof value === "object") {
    if (typeof value.$from === "string") {
      const source = raw.get(value.$from);
      const found = lookup(source, value.path);
      if (found === undefined) {
        throw new Error(`step ${value.$from} recorded nothing at ${value.path}`);
      }
      return found;
    }
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, resolve(v, raw)]));
  }
  return value;
}

/**
 * `{{step.a.b}}` in a request path becomes the URL-encoded raw value step `step` recorded at
 * `a.b`; a bare `{{step}}` is that step's `transaction`.
 */
function resolvePath(path, raw) {
  return path.replaceAll(/\{\{([^}]+)\}\}/g, (_, expression) => {
    const [id, ...rest] = expression.split(".");
    const found = lookup(raw.get(id), rest.length === 0 ? "transaction" : rest.join("."));
    if (found === undefined) throw new Error(`step ${id} recorded nothing at ${expression}`);
    return encodeURIComponent(String(found));
  });
}

async function step(spec, raw) {
  const init = { method: spec.method, headers: { ...spec.headers } };
  const credential = selectCredential(spec, { ownerToken: TOKEN, userToken: USER_TOKEN });
  for (const name of spec.credential === undefined ? [] : Object.keys(init.headers)) {
    if (name.toLowerCase() === "authorization") delete init.headers[name];
  }
  if (spec.webchannelBodyBytes !== undefined) {
    if (spec.method !== "POST" || spec.path !== WEBCHANNEL_PATH || spec.body !== undefined) {
      throw new Error("invalid fixed WebChannel byte probe");
    }
    init.headers["content-type"] = "application/x-www-form-urlencoded;charset=UTF-8";
    init.body = makeWebChannelFormBody(spec.webchannelBodyBytes);
    init.redirect = "error";
  } else if (spec.body !== undefined) {
    init.headers["content-type"] = "application/json";
    init.body =
      typeof spec.body === "string"
        ? spec.body
        : JSON.stringify(resolve(substituteProject(spec.body), raw));
  }
  if (credential.authorization !== null) init.headers.authorization = credential.authorization;
  // A request the side never answers is recorded as such rather than hanging the run: the
  // official emulator's REST adapter drops the connection on a bytes-typed query parameter
  // (`?transaction=`) without writing a response.
  init.signal = AbortSignal.timeout(REQUEST_TIMEOUT_MS);
  let response;
  try {
    const resolvedPath = resolvePath(spec.path, raw);
    const input = url(resolvedPath);
    if (new Set(["POST", "PATCH", "DELETE"]).has(spec.method.toUpperCase())) {
      let target;
      const write = init.body ? JSON.parse(init.body)?.writes?.[0] : null;
      target = write?.update?.name ?? write?.delete ?? write?.transform?.document;
      if (!target && resolvedPath.includes("/documents/")) {
        target = resolvedPath.replace(/^\/v1\//, "").split(/[?#]/, 1)[0];
      }
      if (target) {
        await writeDeltaMutationIntent(
          replaceRunMarker(target),
          spec.method.toUpperCase(),
          spec.id,
          input,
          init.body ?? "",
        );
      }
    }
    response = await trackedFetch(input, init);
  } catch (error) {
    if (error?.name === "TimeoutError" || error?.name === "AbortError") {
      return {
        recorded: { status: 0, code: "no-response", message: "no response within the timeout" },
        raw: null,
      };
    }
    throw error;
  }
  const text = await response.text();
  if (spec.webchannelBodyBytes !== undefined) {
    return { recorded: projectWebChannelResponse(response.status, text), raw: null };
  }
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    return {
      recorded: { status: response.status, code: "non-json", message: text.slice(0, 200) },
      raw: null,
    };
  }
  // `runQuery` and `batchGet` stream an array; an error arrives as its single element.
  const error = Array.isArray(body) ? body.find((e) => e?.error)?.error : body?.error;
  if (error) {
    return {
      recorded: {
        status: response.status,
        code: error.status ?? String(error.code ?? ""),
        message: normalizeProbeResponse(String(error.message ?? "").slice(0, 400), {
          project: PROJECT,
          recordProject: RECORD_PROJECT,
          scope: "error",
        }),
      },
      raw: body,
    };
  }
  return {
    recorded: {
      status: response.status,
      code: "OK",
      body: normalizeProbeResponse(body, {
        project: PROJECT,
        recordProject: RECORD_PROJECT,
        scope:
          spec.path.includes("/databases") && !spec.path.includes("/documents")
            ? "database-metadata"
            : "document",
      }),
    },
    raw: body,
  };
}

function deleteBoundaryLength(program) {
  const match =
    /^writes\/limits\/near-limit-delete-refusal\/(?:rest|commit|batch-write)\/(12112|12113)$/.exec(
      program.id,
    );
  return match ? Number(match[1]) : null;
}

function validateDeltaV3Corpus(programs, names) {
  const expectedIds = new Set(
    ["rest", "commit", "batch-write"].flatMap((route) =>
      [12112, 12113].map((count) => `writes/limits/near-limit-delete-refusal/${route}/${count}`),
    ),
  );
  if (
    !DELTA_V3_MODE ||
    programs?.schemaVersion !== 1 ||
    programs.sourceCorpusSha256 !== CORPUS_DIGEST ||
    !Array.isArray(programs.restPrograms) ||
    !Array.isArray(programs.streamRecipes) ||
    programs.restPrograms.length !== 6 ||
    new Set(programs.restPrograms.map((program) => program.id)).size !== 6 ||
    JSON.stringify(programs.restPrograms.map((program) => program.id).toSorted()) !==
      JSON.stringify([...expectedIds].toSorted()) ||
    programs.restRequestCount !== 30 ||
    programs.streamRecipes.length !== 1 ||
    programs.streamRecipes[0]?.id !== DELTA_STREAM_ID ||
    programs.streamRecipes[0]?.transport !== "grpc" ||
    programs.streamRecipes[0]?.maxFrames !== 2
  ) {
    throw new Error("delta-v3 input differs from the source-bound six-recipe packet");
  }
  const seededNames = [];
  for (const program of programs.restPrograms) {
    if (
      JSON.stringify(program.steps.map((recipeStep) => recipeStep.id)) !==
      JSON.stringify(["seed", "before-delete", "delete", "after-delete", "group-after-delete"])
    ) {
      throw new Error("delta-v3 recipe step order is not the frozen delete proof sequence");
    }
    const write = program.steps[0].body?.writes?.[0]?.update;
    const name = replaceRunMarker(write?.name ?? "");
    if (!name || !names.includes(name))
      throw new Error("delta-v3 seed escaped its frozen six names");
    if (
      program.steps[0].method !== "POST" ||
      !program.steps[0].path.endsWith("/documents:commit")
    ) {
      throw new Error("delta-v3 seed route changed");
    }
    const before = replaceRunMarker(program.steps[1].path.replace(/^\/v1\//, ""));
    if (program.steps[1].method !== "GET" || before !== name) {
      throw new Error("delta-v3 immediate typed pre-delete read is not exact");
    }
    seededNames.push(name);
  }
  if (
    new Set(seededNames).size !== 6 ||
    JSON.stringify(seededNames.toSorted()) !== JSON.stringify(names.toSorted())
  ) {
    throw new Error("delta-v3 corpus does not own exactly the six frozen document names");
  }
}

function provesDeleteTargetExists(program, stepSpec, document, recorded) {
  const expectedLength = deleteBoundaryLength(program);
  const expectedName = replaceRunMarker(
    stepSpec.path.replaceAll("PROJECT", PROJECT).replace(/^\/v1\//, ""),
  );
  const values = document?.fields?.a?.arrayValue?.values;
  return (
    expectedLength !== null &&
    recorded?.status === 200 &&
    recorded.code === "OK" &&
    document?.name === expectedName &&
    typeof document?.updateTime === "string" &&
    document.updateTime.length > 0 &&
    Object.keys(document.fields ?? {}).length === 1 &&
    Object.keys(document.fields?.a ?? {}).length === 1 &&
    Array.isArray(values) &&
    values.length === expectedLength &&
    values.every(
      (value, index) =>
        Object.keys(value ?? {}).length === 1 && value.integerValue === String(index),
    )
  );
}

function provesDeleteOutcome(program, steps, raw) {
  const deletion = steps.delete;
  const afterDelete = steps["after-delete"];
  const group = steps["group-after-delete"];
  if (
    !deletion ||
    deletion.status < 200 ||
    (deletion.status >= 300 && deletion.status < 400) ||
    afterDelete?.status !== 200 ||
    afterDelete.code !== "OK" ||
    group?.status !== 200 ||
    group.code !== "OK"
  )
    return false;
  if (deletion.status >= 200 && deletion.status < 300) {
    if (deletion.code !== "OK") return false;
  } else if (
    deletion.status !== 400 ||
    deletion.code !== "INVALID_ARGUMENT" ||
    deletion.message !== "Transaction too big. Decrease transaction size."
  ) {
    return false;
  }
  const afterRaw = raw.get("after-delete");
  const groupRaw = raw.get("group-after-delete");
  const count = deleteBoundaryLength(program);
  const beforeSpec = program.steps.find((candidate) => candidate.id === "before-delete");
  const name = replaceRunMarker(
    beforeSpec.path.replaceAll("PROJECT", PROJECT).replace(/^\/v1\//, ""),
  );
  if (deletion.status >= 200 && deletion.status < 300) {
    return (
      Array.isArray(afterRaw) &&
      afterRaw.length === 1 &&
      afterRaw[0]?.missing === name &&
      Array.isArray(groupRaw) &&
      groupRaw.length === 0
    );
  }
  const found = Array.isArray(afterRaw) && afterRaw.length === 1 ? afterRaw[0]?.found : null;
  const foundValues = found?.fields?.a?.arrayValue?.values;
  return (
    found?.name === name &&
    typeof found.updateTime === "string" &&
    Array.isArray(foundValues) &&
    foundValues.length === count &&
    foundValues.every((value, index) => value?.integerValue === String(index)) &&
    Array.isArray(groupRaw) &&
    groupRaw.length === 1 &&
    groupRaw[0]?.document?.name === name
  );
}

function deleteBoundaryProof(program, steps, raw, blocked) {
  const count = deleteBoundaryLength(program);
  if (count === null) return null;
  const beforeSpec = program.steps.find((candidate) => candidate.id === "before-delete");
  const name = replaceRunMarker(
    beforeSpec.path.replaceAll("PROJECT", PROJECT).replace(/^\/v1\//, ""),
  );
  const targetExists =
    !blocked &&
    provesDeleteTargetExists(program, beforeSpec, raw.get("before-delete"), steps["before-delete"]);
  const outcomeProven = targetExists && provesDeleteOutcome(program, steps, raw);
  const after = raw.get("after-delete");
  const group = raw.get("group-after-delete");
  const accepted =
    steps.delete?.status >= 200 && steps.delete.status < 300 && steps.delete.code === "OK";
  const refused =
    steps.delete?.status === 400 &&
    steps.delete.code === "INVALID_ARGUMENT" &&
    steps.delete.message === "Transaction too big. Decrease transaction size.";
  return {
    documentCount: count,
    deleteTargetExists: targetExists,
    deleteOutcomeProven: outcomeProven,
    outcome: accepted ? "accepted" : refused ? "refused" : "unknown",
    postDeleteAbsent:
      accepted && Array.isArray(after) && after.length === 1 && after[0]?.missing === name,
    groupEmpty: accepted && Array.isArray(group) && group.length === 0,
    postDeletePresent:
      refused && Array.isArray(after) && after.length === 1 && after[0]?.found?.name === name,
    groupContainsTarget:
      refused && Array.isArray(group) && group.length === 1 && group[0]?.document?.name === name,
  };
}

async function main() {
  const deltaNames = (() => {
    try {
      return JSON.parse(MANAGED_CLEAR_NAMES ?? "null");
    } catch {
      return null;
    }
  })();
  const deltaScope = isExactDeltaV3ProductionScope({
    mode: DELTA_V3_MODE,
    lockHeld: DELTA_LOCK_HELD,
    host: HOST,
    scheme: SCHEME,
    project: PROJECT,
    maxRequests: Number(MAX_REQUESTS),
    deltaJournal: process.env.FIRESTORE_PROBE_DELTA_JOURNAL,
    managedClearJournal: MANAGED_CLEAR_JOURNAL,
    names: deltaNames,
  });
  assertV3ProductionCleanupAllowed({ host: HOST, exactDeltaV3: deltaScope });
  if (RECOVERY_MODE !== undefined) {
    if (!["recover-legacy", "recover-v3", "recover-delta-v3"].includes(RECOVERY_MODE)) {
      throw new Error("unsupported Firestore probe recovery mode");
    }
    if (!PRODUCTION || PROJECT !== "fireemu-oracle-sbx" || !HOST || !TOKEN) {
      throw new Error("legacy recovery requires the fixed sandbox production target");
    }
    if (RECOVERY_MODE === "recover-v3") await runV3RecoveryOnly();
    else if (RECOVERY_MODE === "recover-delta-v3") await runDeltaV3RecoveryOnly();
    else await runLegacyRecoveryOnly();
    return;
  }
  if (!HOST || !IN || !OUT) {
    throw new Error(
      "FIRESTORE_PROBE_HOST, FIRESTORE_PROBE_IN and FIRESTORE_PROBE_OUT are required",
    );
  }
  const corpusInput = JSON.parse(await readFile(IN, "utf8"));
  const programs = Array.isArray(corpusInput) ? corpusInput : corpusInput.restPrograms;
  const fixedLocalRunId = process.env.FIRESTORE_PROBE_DELETE_RUN_ID;
  deleteRunId =
    /^[a-f0-9]{32}$/.test(fixedLocalRunId ?? "") && (/^127\.0\.0\.1:\d+$/.test(HOST) || PRODUCTION)
      ? fixedLocalRunId
      : randomUUID().replaceAll("-", "");
  if (PRODUCTION && (MANAGED_CLEAR_NAMES || MANAGED_CLEAR_JOURNAL)) {
    if (!MANAGED_CLEAR_NAMES || !MANAGED_CLEAR_JOURNAL) {
      throw new Error("managed clear requires both frozen names and a private journal");
    }
    const names = JSON.parse(MANAGED_CLEAR_NAMES).map(replaceRunMarker);
    const shrinkScope = managedShrinkScope(names, PROJECT, "(default)");
    if (shrinkScope === "delta-v3") {
      if (
        !DELTA_V3_MODE ||
        !DELTA_LOCK_HELD ||
        !process.env.FIRESTORE_PROBE_DELTA_JOURNAL ||
        process.env.FIRESTORE_PROBE_MANAGED_CLEAR_JOURNAL ||
        Number(MAX_REQUESTS) !== 430
      ) {
        throw new Error("delta-v3 requires its separate journal and exact 430-request cap");
      }
    } else if (DELTA_V3_MODE) {
      throw new Error("delta-v3 mode cannot use the historical six- or full-v3-name scope");
    }
    if (
      names.length !== V3_SHRINK_NAMES.length &&
      !(
        /^127\.0\.0\.1:\d+$/.test(HOST) &&
        ["legacy", "v3"].includes(shrinkScope) &&
        names.length === 6
      ) &&
      shrinkScope !== "delta-v3"
    ) {
      throw new Error("managed clear requires the exact frozen corpus-v3 names");
    }
    if (shrinkScope === "delta-v3") validateDeltaV3Corpus(corpusInput, names);
    managedClearScope(names, PROJECT, "(default)");
    managedClearState = {
      names,
      shrinkScope,
      preflightUpdateTimes: new Map(),
      shrinkRequestCounter: createShrinkRequestCounter(
        SHRINK_REQUEST_CAPS[managedShrinkScope(names, PROJECT, "(default)")],
      ),
      legacyDebrisAudited: false,
      cleanupDeletedNames: [],
      cleanupDeleteIntent: null,
      bulkDeleteIntent: null,
      bulkDeleteOperation: null,
      pendingMutation: null,
      lastMutation: null,
    };
    try {
      const previous = JSON.parse(await readFile(MANAGED_CLEAR_JOURNAL, "utf8"));
      if (shrinkScope === "delta-v3") {
        throw new Error(
          "delta-v3 attempt journal already exists; recover it without starting a new recording",
        );
      }
      if (previous.status !== "complete") {
        throw new Error("managed clear operation requires recovery before a new recording");
      }
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
    if (
      PRODUCTION &&
      (!/^[a-f0-9]{32}$/.test(deleteRunId) ||
        !/^[a-f0-9]{64}$/.test(CORPUS_DIGEST ?? "") ||
        !/^[a-f0-9]{40}$/.test(SOURCE_GIT_SHA ?? ""))
    ) {
      throw new Error("production managed cleanup provenance is incomplete");
    }
    if (shrinkScope === "v3") await writeV3CleanupJournal("prepared");
    if (shrinkScope === "delta-v3") await writeDeltaCleanupJournal("prepared");
  }
  const results = {};
  const touchedDatabases = new Set(["(default)"]);
  try {
    if (managedClearState?.shrinkScope === "delta-v3") await clear();
    for (const program of programs) {
      if (managedClearState?.shrinkScope !== "delta-v3") await clear();
      for (const database of program.databases ?? []) {
        touchedDatabases.add(database);
        await clear(database);
      }
      try {
        await seed(program.seed);
      } catch (error) {
        results[program.id] = { seedError: String(error.message ?? error).slice(0, 400) };
        continue;
      }
      const raw = new Map();
      const steps = {};
      let candidateDeleteBlocked = false;
      for (const spec of program.steps) {
        if (candidateDeleteBlocked) {
          steps[spec.id] = { status: 0, code: "not-run", message: "indeterminate prerequisite" };
          raw.set(spec.id, null);
          continue;
        }
        if (spec.id === "delete" && deleteBoundaryLength(program) !== null) {
          const beforeDelete = raw.get("before-delete");
          const beforeDeleteSpec = program.steps.find(
            (candidate) => candidate.id === "before-delete",
          );
          if (
            !beforeDeleteSpec ||
            !provesDeleteTargetExists(
              program,
              beforeDeleteSpec,
              beforeDelete,
              steps["before-delete"],
            )
          ) {
            candidateDeleteBlocked = true;
            steps[spec.id] = {
              status: 0,
              code: "indeterminate",
              message: "fresh typed pre-delete read did not prove the exact seeded document exists",
            };
            raw.set(spec.id, null);
            continue;
          }
        }
        let outcome;
        try {
          outcome = await step(spec, raw);
        } catch (error) {
          outcome = {
            recorded: { status: 0, code: "probe-error", message: String(error.message ?? error) },
            raw: null,
          };
        }
        raw.set(spec.id, outcome.raw);
        steps[spec.id] = {
          ...outcome.recorded,
          ...(spec.credential === undefined
            ? {}
            : { credential: credentialMetadata({ kind: spec.credential }) }),
        };
      }
      results[program.id] = {
        steps,
        ...(deleteBoundaryLength(program) === null
          ? {}
          : {
              conditionEvidence:
                !candidateDeleteBlocked && provesDeleteOutcome(program, steps, raw)
                  ? "complete"
                  : "indeterminate",
              ...(DELTA_V3_MODE
                ? { deleteProof: deleteBoundaryProof(program, steps, raw, candidateDeleteBlocked) }
                : {}),
            }),
      };
    }
  } finally {
    try {
      if (!managedClearBlocked) {
        for (const database of touchedDatabases) await clear(database, true);
      }
    } finally {
      if (META_OUT) {
        await writeFile(META_OUT, `${JSON.stringify({ requestCount })}\n`);
      }
    }
  }
  await writeFile(OUT, `${JSON.stringify(results, null, 2)}\n`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) await main();
