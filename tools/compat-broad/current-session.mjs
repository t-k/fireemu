// Current bounded local fork of the pinned Firestore session. Legacy files stay immutable.
// The JSON normalize function is byte-equivalent to the historical session and tested.
import { readFile, writeFile } from "node:fs/promises";
import {
  credentialMetadata,
  selectCredential,
} from "../../conformance/src/firestore-probe/credentials.mjs";

import { receiveHttp } from "./record-http.mjs";

const HOST = process.env.FIRESTORE_PROBE_HOST;
const PROJECT = process.env.FIRESTORE_PROBE_PROJECT ?? "demo-conformance";
const IN = process.env.FIRESTORE_PROBE_IN;
const OUT = process.env.FIRESTORE_PROBE_OUT;
const REQUEST_TIMEOUT_MS = Number(process.env.FIRESTORE_PROBE_TIMEOUT_MS ?? 20_000);
const SCHEME = "http";
const TOKEN = "owner";
const USER_TOKEN = process.env.FIRESTORE_PROBE_USER_TOKEN;
const RECORD_PROJECT = PROJECT;
const origin = `http://${HOST}`;
const wireOptions = { origin, privateDirectory: process.env.FIRESTORE_PROBE_WIRE_DIR };
if (process.env.FIRESTORE_PROBE_TARGET !== "local" || !wireOptions.privateDirectory)
  throw new Error("current recorder is local-only");

const url = (path) => `${SCHEME}://${HOST}${path.replaceAll("PROJECT", PROJECT)}`;
const substituteProject = (value) =>
  JSON.parse(JSON.stringify(value ?? null).replaceAll("PROJECT", PROJECT));
const authorized = (headers = {}) => ({ ...headers, authorization: `Bearer ${TOKEN}` });
const timeoutSignal = () => AbortSignal.timeout(REQUEST_TIMEOUT_MS);

async function clear(database = "(default)") {
  const wire = await receiveHttp(
    `${origin}/emulator/v1/projects/${PROJECT}/databases/${database}/documents`,
    { method: "DELETE", signal: timeoutSignal() },
    wireOptions,
  );
  if (!wire.http.complete || wire.http.status < 200 || wire.http.status >= 300)
    throw new Error("owned reset failed");
}

async function seed(documents) {
  for (const document of documents ?? []) {
    const wire = await receiveHttp(
      url(document.path),
      {
        method: "PATCH",
        headers: authorized({ "content-type": "application/json" }),
        body: JSON.stringify({ fields: substituteProject(document.fields) }),
        signal: timeoutSignal(),
      },
      wireOptions,
    );
    if (!wire.http.complete || wire.http.status < 200 || wire.http.status >= 300)
      throw new Error("owned seed failed");
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
  const credential = selectCredential(spec, { ownerToken: TOKEN, userToken: USER_TOKEN });
  for (const name of spec.credential === undefined ? [] : Object.keys(init.headers)) {
    if (name.toLowerCase() === "authorization") delete init.headers[name];
  }
  if (spec.body !== undefined) {
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
  const wire = await receiveHttp(url(resolvePath(spec.path, raw)), init, wireOptions);
  if (!wire.http.complete)
    return {
      recorded: {
        status: wire.http.status ?? 0,
        code: wire.http.failure === "timeout" ? "no-response" : "probe-error",
        http: wire.http,
      },
      raw: null,
    };
  if (wire.http.bodyKind !== "json")
    return { recorded: { status: wire.http.status, code: "non-json", http: wire.http }, raw: null };
  const body = wire.body;
  const response = { status: wire.http.status };
  // `runQuery` and `batchGet` stream an array; an error arrives as its single element.
  const error = Array.isArray(body) ? body.find((e) => e?.error)?.error : body?.error;
  if (error) {
    return {
      recorded: {
        status: response.status,
        http: wire.http,
        code: error.status ?? String(error.code ?? ""),
        message: normalize(String(error.message ?? "").slice(0, 400)),
      },
      raw: body,
    };
  }
  return {
    recorded: { status: response.status, code: "OK", body: normalize(body), http: wire.http },
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
      steps[spec.id] = {
        ...outcome.recorded,
        ...(spec.credential === undefined
          ? {}
          : { credential: credentialMetadata({ kind: spec.credential }) }),
      };
    }
    results[program.id] = { steps };
    await writeFile(OUT, JSON.stringify(results, null, 2) + "\n");
  }
  await writeFile(OUT, `${JSON.stringify(results, null, 2)}\n`);
}

await main();
