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

const HOST = process.env.FIRESTORE_PROBE_HOST;
const PROJECT = process.env.FIRESTORE_PROBE_PROJECT ?? "demo-conformance";
const IN = process.env.FIRESTORE_PROBE_IN;
const OUT = process.env.FIRESTORE_PROBE_OUT;
const REQUEST_TIMEOUT_MS = Number(process.env.FIRESTORE_PROBE_TIMEOUT_MS ?? 20_000);
// Production target: `https`, an OAuth bearer token instead of the emulator's `owner`, no
// emulator wipe route (documents are deleted through the public API instead), and the real
// project id normalized back to the recording project so a production run compares row by
// row with the emulator matrices without ever recording the production identifier.
const SCHEME = process.env.FIRESTORE_PROBE_SCHEME ?? "http";
const TOKEN = process.env.FIRESTORE_PROBE_TOKEN ?? "owner";
const PRODUCTION = process.env.FIRESTORE_PROBE_TARGET === "production";
const RECORD_PROJECT = process.env.FIRESTORE_PROBE_RECORD_PROJECT ?? PROJECT;

const url = (path) => `${SCHEME}://${HOST}${path.replaceAll("PROJECT", PROJECT)}`;
const substituteProject = (value) =>
  JSON.parse(JSON.stringify(value ?? null).replaceAll("PROJECT", PROJECT));
const authorized = (headers = {}) => ({ ...headers, authorization: `Bearer ${TOKEN}` });
const timeoutSignal = () => AbortSignal.timeout(REQUEST_TIMEOUT_MS);

/** Wipes the emulator's documents so one program never sees another's writes. */
async function clear(database = "(default)") {
  if (PRODUCTION) {
    await clearThroughPublicApi(database);
    return;
  }
  await fetch(`http://${HOST}/emulator/v1/projects/${PROJECT}/databases/${database}/documents`, {
    method: "DELETE",
    signal: timeoutSignal(),
  });
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
    for (const collectionId of collectionIds) {
      await deleteCollection(base, "", collectionId);
    }
  }
  throw new Error("clear: the production database still lists collections after 8 rounds");
}

/** Every collection id under `parentPath` (all pages), or `null` for a missing database. */
async function listCollectionIds(base, parentPath) {
  const parent = parentPath ? `${base}/${parentPath}` : base;
  const ids = [];
  let pageToken;
  do {
    const listed = await fetch(`${parent}:listCollectionIds`, {
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
  let pageToken;
  do {
    const query = new URLSearchParams({
      showMissing: "true",
      "mask.fieldPaths": "__name__",
      pageSize: "300",
      ...(pageToken ? { pageToken } : {}),
    });
    const listed = await fetch(`${parent}/${collectionId}?${query}`, {
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
      await deleteCollection(base, relative, child);
    }
  }
  for (let index = 0; index < names.length; index += 400) {
    const writes = names.slice(index, index + 400).map((name) => ({ delete: name }));
    const commit = await fetch(`${base}:commit`, {
      method: "POST",
      headers: authorized({ "content-type": "application/json" }),
      body: JSON.stringify({ writes }),
      signal: timeoutSignal(),
    });
    if (!commit.ok) throw new Error(`clear: commit ${commit.status} ${await commit.text()}`);
  }
}

async function seed(documents) {
  for (const document of documents ?? []) {
    const response = await fetch(url(document.path), {
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

const INSTANT = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z$/;

/**
 * Server-generated values become placeholders. An instant is server-generated when its
 * year is 2026 or later: every seeded timestamp in the corpus is dated before 2025, the
 * official emulator runs on the wall clock and fireemu's probe configuration pins its clock
 * to 2026, so the rule separates the two without a list of key names. Transaction ids are
 * opaque on both sides.
 */
function normalize(value, key = "") {
  if (typeof value === "string") {
    if (PROJECT !== RECORD_PROJECT) value = value.replaceAll(PROJECT, RECORD_PROJECT);
    if (INSTANT.test(value) && Number(value.slice(0, 4)) >= 2026) return "<now>";
    if (key === "transaction") return "<txn>";
    // Page tokens are opaque and shaped differently by each side; a generated document id
    // is twenty alphanumerics that no seeded id in this corpus has.
    if (key === "nextPageToken") return "<token>";
    if (key === "name") return value.replace(/\/[A-Za-z0-9]{20}$/, "/<auto-id>");
    return value;
  }
  if (Array.isArray(value)) return value.map((v) => normalize(v, key));
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, normalize(v, k)]));
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
  if (spec.body !== undefined) {
    init.headers["content-type"] = "application/json";
    init.body =
      typeof spec.body === "string"
        ? spec.body
        : JSON.stringify(resolve(substituteProject(spec.body), raw));
  }
  if (spec.owner !== false) init.headers.authorization = `Bearer ${TOKEN}`;
  // A request the side never answers is recorded as such rather than hanging the run: the
  // official emulator's REST adapter drops the connection on a bytes-typed query parameter
  // (`?transaction=`) without writing a response.
  init.signal = AbortSignal.timeout(REQUEST_TIMEOUT_MS);
  let response;
  try {
    response = await fetch(url(resolvePath(spec.path, raw)), init);
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
        message: normalize(String(error.message ?? "").slice(0, 400)),
      },
      raw: body,
    };
  }
  return {
    recorded: { status: response.status, code: "OK", body: normalize(body) },
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
  const results = {};
  for (const program of programs) {
    await clear();
    for (const database of program.databases ?? []) await clear(database);
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
      steps[spec.id] = outcome.recorded;
    }
    results[program.id] = { steps };
  }
  await writeFile(OUT, `${JSON.stringify(results, null, 2)}\n`);
}

await main();
