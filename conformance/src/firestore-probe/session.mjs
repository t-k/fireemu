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
import { randomUUID } from "node:crypto";
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
const MANAGED_CLEAR_JOURNAL = process.env.FIRESTORE_PROBE_MANAGED_CLEAR_JOURNAL;
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
const MANAGED_POLL_MS = /^127\.0\.0\.1:\d+$/.test(HOST ?? "")
  ? Number(process.env.FIRESTORE_PROBE_MANAGED_POLL_MS ?? 60_000)
  : 60_000;
if (!Number.isInteger(MANAGED_POLL_MS) || MANAGED_POLL_MS < 1 || MANAGED_POLL_MS > 60_000) {
  throw new Error("invalid managed-clear polling interval");
}
const RECORD_PROJECT = process.env.FIRESTORE_PROBE_RECORD_PROJECT ?? PROJECT;
const SHRINK_CHUNK_SIZE = 1024;
const SHRINK_REQUEST_CAPS = { legacy: 180, v3: 160 };
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

export function createShrinkRequestCounter(limit) {
  if (!Number.isSafeInteger(limit) || limit <= 0) {
    throw new Error("array shrink request limit must be a positive safe integer");
  }
  let requests = 0;
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
  if (
    names.length !== 6 ||
    names.some((name) => typeof name !== "string") ||
    new Set(names).size !== 6
  ) {
    throw new Error("array shrink requires six distinct frozen documents");
  }
  if (LEGACY_SHRINK_NAMES.every((name) => names.includes(name))) return "legacy";
  if (V3_SHRINK_NAMES.every((name) => names.includes(name))) return "v3";
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
  requestCount = requestBudget === null ? requestCount + 1 : requestBudget.claim();
  return fetch(input, init);
}

const url = (path) => `${SCHEME}://${HOST}${path.replaceAll("PROJECT", PROJECT)}`;
const substituteProject = (value) =>
  JSON.parse(JSON.stringify(value ?? null).replaceAll("PROJECT", PROJECT));
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
      if (shrinkScopeActive && verifyManagedScope) await verifyManagedShrinkScopeAbsent(base);
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
        if (verifyManagedScope) await verifyManagedShrinkScopeAbsent(base);
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
      const collectionId = name.split("/documents/")[1].split("/")[0];
      const expectedLength = FROZEN_ARRAY_LENGTHS.get(collectionId);
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
    const commit = commitRequest
      ? await commitRequest("delete attempt", `${base}:commit`, commitInit)
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
          const retryUpdateTime = await shrinkBoundaryDocument(candidate);
          const retry = await managedShrinkRequest("delete retry", `${base}:commit`, {
            method: "POST",
            headers: authorized({ "content-type": "application/json" }),
            body: JSON.stringify({
              writes: [{ delete: candidate, currentDocument: { updateTime: retryUpdateTime } }],
            }),
            signal: timeoutSignal(),
          });
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
    const collectionId = name.split("/documents/")[1].split("/")[0];
    const expectedLength = FROZEN_ARRAY_LENGTHS.get(collectionId);
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
  const collectionId = name.split("/documents/")[1].split("/")[0];
  const expectedLength = FROZEN_ARRAY_LENGTHS.get(collectionId);
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
  if (managedClearState.recoveryOnly) {
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
    const response = await trackedFetch(url(document.path), {
      method: "PATCH",
      headers: authorized({ "content-type": "application/json" }),
      body: JSON.stringify({ fields: substituteProject(document.fields) }),
      signal: timeoutSignal(),
    });
    if (!response.ok) {
      throw new Error(`seed ${document.path}: ${response.status} ${await response.text()}`);
    }
  }
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
    response = await trackedFetch(url(resolvePath(spec.path, raw)), init);
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
        message: normalizeRecordedResponse(String(error.message ?? "").slice(0, 400), {
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
      body: normalizeRecordedResponse(body, {
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

async function main() {
  if (RECOVERY_MODE !== undefined) {
    if (RECOVERY_MODE !== "recover-legacy") {
      throw new Error("unsupported Firestore probe recovery mode");
    }
    if (!PRODUCTION || PROJECT !== "fireemu-oracle-sbx" || !HOST || !TOKEN) {
      throw new Error("legacy recovery requires the fixed sandbox production target");
    }
    await runLegacyRecoveryOnly();
    return;
  }
  if (!HOST || !IN || !OUT) {
    throw new Error(
      "FIRESTORE_PROBE_HOST, FIRESTORE_PROBE_IN and FIRESTORE_PROBE_OUT are required",
    );
  }
  const programs = JSON.parse(await readFile(IN, "utf8"));
  if (PRODUCTION && (MANAGED_CLEAR_NAMES || MANAGED_CLEAR_JOURNAL)) {
    if (!MANAGED_CLEAR_NAMES || !MANAGED_CLEAR_JOURNAL) {
      throw new Error("managed clear requires both frozen names and a private journal");
    }
    const names = JSON.parse(MANAGED_CLEAR_NAMES);
    if (names.length !== 6) throw new Error("managed clear requires six frozen boundary names");
    managedClearScope(names, PROJECT, "(default)");
    managedClearState = {
      names,
      shrinkScope: managedShrinkScope(names, PROJECT, "(default)"),
      preflightUpdateTimes: new Map(),
      shrinkRequestCounter: createShrinkRequestCounter(
        SHRINK_REQUEST_CAPS[managedShrinkScope(names, PROJECT, "(default)")],
      ),
      legacyDebrisAudited: false,
    };
    try {
      const previous = JSON.parse(await readFile(MANAGED_CLEAR_JOURNAL, "utf8"));
      if (previous.status !== "complete") {
        throw new Error("managed clear operation requires recovery before a new recording");
      }
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
  }
  const results = {};
  const touchedDatabases = new Set(["(default)"]);
  try {
    for (const program of programs) {
      await clear();
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
      for (const spec of program.steps) {
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
      results[program.id] = { steps };
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
