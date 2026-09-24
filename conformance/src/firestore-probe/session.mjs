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

import { readFile, writeFile } from "node:fs/promises";
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
const RECORD_PROJECT = process.env.FIRESTORE_PROBE_RECORD_PROJECT ?? PROJECT;
let requestCount = 0;
const requestBudget = MAX_REQUESTS === undefined ? null : createRequestBudget(Number(MAX_REQUESTS));
let managedClearBlocked = false;
let managedClearState = null;

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
async function clear(database = "(default)") {
  if (PRODUCTION) {
    if (managedClearBlocked) throw new Error("managed clear needs operator recovery");
    await clearThroughPublicApi(database);
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
async function clearThroughPublicApi(database) {
  const base = `${SCHEME}://${HOST}/v1/projects/${PROJECT}/databases/${database}/documents`;
  // Listing is paged and only eventually reflects deletes: loop until a full listing is empty.
  for (let round = 0; round < 8; round += 1) {
    const collectionIds = await listCollectionIds(base, "");
    if (collectionIds === null || collectionIds.length === 0) return;
    const managedFailures = [];
    for (const collectionId of collectionIds) {
      managedFailures.push(...(await deleteCollection(base, "", collectionId)));
    }
    if (managedFailures.length > 0) await managedClear(database, managedFailures);
  }
  throw new Error("clear: the production database still lists collections after 8 rounds");
}

/** Every collection id under `parentPath` (all pages), or `null` for a missing database. */
async function listCollectionIds(base, parentPath) {
  const parent = parentPath ? `${base}/${parentPath}` : base;
  const ids = [];
  let pageToken;
  do {
    const listed = await trackedFetch(`${parent}:listCollectionIds`, {
      method: "POST",
      headers: authorized({ "content-type": "application/json" }),
      body: JSON.stringify(pageToken ? { pageToken } : {}),
      signal: timeoutSignal(),
    });
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
  for (const name of [...names, ...missing]) {
    const relative = name.slice(name.indexOf("/documents/") + "/documents/".length);
    for (const child of (await listCollectionIds(base, relative)) ?? []) {
      managedFailures.push(...(await deleteCollection(base, relative, child)));
    }
  }
  for (let index = 0; index < names.length; index += 400) {
    const writes = names.slice(index, index + 400).map((name) => ({ delete: name }));
    const commit = await trackedFetch(`${base}:commit`, {
      method: "POST",
      headers: authorized({ "content-type": "application/json" }),
      body: JSON.stringify({ writes }),
      signal: timeoutSignal(),
    });
    if (!commit.ok) {
      const body = await commit.text();
      const candidate = writes.length === 1 ? writes[0].delete : null;
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
        managedFailures.push(candidate);
      } else {
        throw new Error(`clear: commit ${commit.status} ${body}`);
      }
    }
  }
  return managedFailures;
}

async function managedGroupNames(api, collectionId) {
  const response = await trackedFetch(`${api}/documents:runQuery`, {
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
  });
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
    await new Promise((wake) => setTimeout(wake, 60_000));
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
    managedClearState = { names };
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
        for (const database of touchedDatabases) await clear(database);
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
