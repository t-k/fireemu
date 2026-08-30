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

const url = (path) => `http://${HOST}${path.replaceAll("PROJECT", PROJECT)}`;
const substituteProject = (value) =>
  JSON.parse(JSON.stringify(value ?? null).replaceAll("PROJECT", PROJECT));

/** Wipes the emulator's documents so one program never sees another's writes. */
async function clear(database = "(default)") {
  await fetch(`http://${HOST}/emulator/v1/projects/${PROJECT}/databases/${database}/documents`, {
    method: "DELETE",
  });
}

async function seed(documents) {
  for (const document of documents ?? []) {
    const response = await fetch(url(document.path), {
      method: "PATCH",
      headers: { "content-type": "application/json", authorization: "Bearer owner" },
      body: JSON.stringify({ fields: substituteProject(document.fields) }),
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
  if (spec.owner !== false) init.headers.authorization = "Bearer owner";
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
        message: String(error.message ?? "").slice(0, 400),
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
