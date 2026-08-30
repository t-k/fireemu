// One side of a storage-probe run, executed inside that side's supervisor.
//
// The probe speaks raw HTTP to whichever Storage emulator the environment names, so the two
// runs differ in nothing but the emulator that answered: the same request bytes, the same
// rules text (loaded by each supervisor from `storage-probe.rules`), the same trigger
// codebase, and the same Firestore documents seeded with owner credentials. Every program
// records, per step, the status, a fixed set of response headers and the normalized body,
// or the trigger events its handlers reported back to the sink this process listens on.
//
//   STORAGE_PROBE_STORAGE_HOST    host:port of the Storage emulator
//   STORAGE_PROBE_FIRESTORE_HOST  host:port of the Firestore emulator (seeding, REST)
//   STORAGE_PROBE_PROJECT         the project id; the bucket is <project>.appspot.com
//   STORAGE_PROBE_OUT             file the run's JSON is written to
//   STORAGE_PROBE_ONLY            optional substring filter on program ids
//
// The process exits 0 when it produced a run: a program that throws is a recorded fault,
// not a harness failure.

import { createServer } from "node:http";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

import { PROGRAMS } from "./programs.mjs";

const STORAGE_HOST = process.env.STORAGE_PROBE_STORAGE_HOST;
const FIRESTORE_HOST = process.env.STORAGE_PROBE_FIRESTORE_HOST;
const PROJECT = process.env.STORAGE_PROBE_PROJECT ?? "demo-storage-probe";
const OUT = process.env.STORAGE_PROBE_OUT;
const ONLY = process.env.STORAGE_PROBE_ONLY ?? null;
/** The port `storage-probe-functions/index.js` reports events to. */
export const SINK_PORT = 32310;

for (const [name, value] of Object.entries({ STORAGE_HOST, FIRESTORE_HOST, OUT })) {
  if (!value) {
    console.error(`storage-probe session: ${name} is not set`);
    process.exit(2);
  }
}

const BUCKET = `${PROJECT}.appspot.com`;

// ------------------------------------------------------------------------------------------
// normalization
// ------------------------------------------------------------------------------------------

/** Response headers a step records when present; everything else is dropped. */
export const RECORDED_HEADERS = [
  "content-type",
  "content-disposition",
  "content-encoding",
  "content-language",
  "content-length",
  "content-range",
  "cache-control",
  "accept-ranges",
  "etag",
  "location",
  "range",
  "retry-after",
  "x-goog-generation",
  "x-goog-metageneration",
  "x-goog-metadatageneration",
  "x-goog-storage-class",
  "x-goog-stored-content-length",
  "x-goog-hash",
  "x-goog-upload-status",
  "x-goog-upload-size-received",
  "x-goog-upload-chunk-granularity",
  "x-goog-upload-control-url",
  "x-goog-upload-url",
  "x-gupload-uploadid",
  "access-control-allow-origin",
  "access-control-allow-credentials",
  "access-control-allow-methods",
  "access-control-allow-headers",
  "access-control-expose-headers",
  "access-control-allow-private-network",
  "vary",
];

const HOST_PORT = /\b(127\.0\.0\.1|localhost|\[::1\]):\d{2,5}\b/g;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;
const JWT = /^ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/;
const UPLOAD_ID_PARAM = /upload_id=[^&\s]+/g;
const GENERATION_PARAM = /generation=\d+/g;

/** Keys whose value is an object generation on both sides, in a different numbering. */
const GENERATION_KEYS = new Set(["generation", "x-goog-generation"]);
/** Keys whose value is derived from the generation and therefore never comparable. */
const ETAG_KEYS = new Set(["etag"]);
/** Keys carrying an emulator-generated identifier. */
const UPLOAD_ID_KEYS = new Set(["x-gupload-uploadid"]);

function normalizeString(value) {
  if (UUID.test(value)) return "<uuid>";
  if (TIMESTAMP.test(value)) return "<timestamp>";
  if (JWT.test(value)) return "<jwt>";
  const parts = value.split(",");
  if (parts.length > 1 && parts.every((p) => UUID.test(p))) {
    return parts.map(() => "<uuid>").join(",");
  }
  return value
    .replace(HOST_PORT, "<host>")
    .replace(UPLOAD_ID_PARAM, "upload_id=<upload-id>")
    .replace(GENERATION_PARAM, "generation=<generation>");
}

/**
 * Normalizes one recorded value. Object keys are sorted so the record never depends on
 * property insertion order; the key-specific rules erase only what both a correct oracle and
 * a correct fireemu are free to choose differently.
 */
export function normalize(value, key = "") {
  if (value === null || value === undefined) return null;
  if (typeof value === "number" || typeof value === "boolean") return value;
  if (typeof value === "string") {
    if (GENERATION_KEYS.has(key) && /^\d+$/.test(value)) return "<generation>";
    if (ETAG_KEYS.has(key)) return "<etag>";
    if (UPLOAD_ID_KEYS.has(key)) return "<upload-id>";
    if (key === "id") {
      const m = value.match(/^(.*)\/(\d+)$/);
      if (m && m[1].includes("/")) return `${normalizeString(m[1])}/<generation>`;
    }
    return normalizeString(value);
  }
  if (Array.isArray(value)) return value.map((v) => normalize(v, key));
  if (typeof value === "object") {
    const out = {};
    for (const k of Object.keys(value).toSorted()) out[k] = normalize(value[k], k);
    return out;
  }
  return String(value);
}

// ------------------------------------------------------------------------------------------
// the event sink
// ------------------------------------------------------------------------------------------

const received = [];
const waiters = [];

function notifyWaiters() {
  for (const waiter of waiters.splice(0)) waiter();
}

const sink = createServer((req, res) => {
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", () => {
    try {
      received.push(JSON.parse(Buffer.concat(chunks).toString("utf8")));
    } catch {
      received.push({ api: "malformed", raw: Buffer.concat(chunks).toString("utf8") });
    }
    res.statusCode = 204;
    res.end();
    notifyWaiters();
  });
});
await new Promise((resolve, reject) => {
  sink.once("error", reject);
  sink.listen(SINK_PORT, "127.0.0.1", resolve);
});

/** The events the handlers reported, sorted by API and type so delivery order is not a row. */
const eventKey = (e) => `${e.api}|${e.type ?? e.eventType}|${e.data?.name ?? ""}`;

async function awaitEvents(count, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (received.length < count && Date.now() < deadline) {
    await new Promise((resolve) => {
      waiters.push(resolve);
      setTimeout(resolve, Math.min(250, Math.max(1, deadline - Date.now())));
    });
  }
  // A quiet period so a straggler shows up as an extra event rather than leaking into the
  // next step.
  await new Promise((resolve) => setTimeout(resolve, 400));
  const events = received.splice(0).toSorted((a, b) => (eventKey(a) < eventKey(b) ? -1 : 1));
  return events;
}

// ------------------------------------------------------------------------------------------
// the request helpers
// ------------------------------------------------------------------------------------------

async function http({ method, path, query, headers = {}, body }) {
  const qs = query
    ? `?${Object.entries(query)
        .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
        .join("&")}`
    : "";
  const url = path.startsWith("http") ? path : `http://${STORAGE_HOST}${path}${qs}`;
  // A hung request must become a recorded fault, never a hung run.
  const init = { method, headers, redirect: "manual", signal: AbortSignal.timeout(30_000) };
  if (body !== undefined && method !== "GET" && method !== "HEAD") init.body = body;
  const response = await fetch(url, init);
  const bytes = Buffer.from(await response.arrayBuffer());
  const contentType = response.headers.get("content-type") ?? "";
  const sentOrigin = Object.keys(headers).some((h) => h.toLowerCase() === "origin");
  const recorded = {};
  for (const name of RECORDED_HEADERS) {
    // Transport artifacts of the serving framework are not protocol rows: CORS headers are
    // compared only on the steps that send an Origin, express stamps its own weak ETag on
    // every JSON body (the object etag is compared inside the body), and content-length
    // restates a body the record already carries.
    if ((name.startsWith("access-control-") || name === "vary") && !sentOrigin) continue;
    if (name === "etag" && contentType.includes("application/json")) continue;
    if (name === "content-length") continue;
    const value = response.headers.get(name);
    if (value !== null) recorded[name] = value;
  }
  let parsed;
  if (contentType.includes("application/json")) {
    try {
      parsed = JSON.parse(bytes.toString("utf8"));
    } catch {
      parsed = { unparsableJson: bytes.toString("utf8") };
    }
  } else if (bytes.length === 0) {
    parsed = "";
  } else if (bytes.length <= 512 && !bytes.includes(0)) {
    parsed = bytes.toString("utf8");
  } else {
    parsed = { bytesLength: bytes.length };
  }
  return { status: response.status, headers: recorded, body: parsed, raw: bytes };
}

/** Standard base64url without padding. */
const b64url = (s) => Buffer.from(s).toString("base64url");

/**
 * An unsigned ID token of the shape @firebase/rules-unit-testing mints. The official Storage
 * emulator decodes it without verifying; fireemu's firebase profile admits it when the
 * audience names the project.
 */
function mockToken(uid, claims = {}) {
  const header = b64url(JSON.stringify({ alg: "none", typ: "JWT" }));
  const payload = b64url(
    JSON.stringify({
      iss: `https://securetoken.google.com/${PROJECT}`,
      aud: PROJECT,
      iat: 0,
      exp: 3600,
      auth_time: 0,
      sub: uid,
      user_id: uid,
      firebase: { identities: {}, sign_in_provider: "custom" },
      ...claims,
    }),
  );
  return `${header}.${payload}.`;
}

async function seedDocument(path, fields) {
  const url = `http://${FIRESTORE_HOST}/v1/projects/${PROJECT}/databases/(default)/documents/${path}`;
  const response = await fetch(url, {
    method: "PATCH",
    headers: { authorization: "Bearer owner", "content-type": "application/json" },
    body: JSON.stringify({ fields }),
  });
  if (!response.ok) {
    throw new Error(`seeding ${path}: ${response.status} ${await response.text()}`);
  }
}

/** A multipart/related upload body the way the SDKs frame it. */
export function multipart(metadata, contentType, data, boundary = "probe-boundary") {
  const head = Buffer.from(
    `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${JSON.stringify(metadata)}\r\n--${boundary}\r\nContent-Type: ${contentType}\r\n\r\n`,
  );
  const tail = Buffer.from(`\r\n--${boundary}--\r\n`);
  return {
    contentType: `multipart/related; boundary=${boundary}`,
    body: Buffer.concat([head, Buffer.from(data), tail]),
  };
}

// ------------------------------------------------------------------------------------------
// running the programs
// ------------------------------------------------------------------------------------------

function createContext() {
  const steps = {};
  const order = [];
  const redactions = new Map();
  const redact = (value) => {
    if (typeof value === "string") {
      let out = value;
      for (const [literal, placeholder] of redactions) out = out.replaceAll(literal, placeholder);
      return out;
    }
    if (Array.isArray(value)) return value.map(redact);
    if (value && typeof value === "object") {
      return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, redact(v)]));
    }
    return value;
  };
  const ctx = {
    project: PROJECT,
    bucket: BUCKET,
    enc: encodeURIComponent,
    http,
    multipart,
    mockToken,
    seedDocument,
    /** Declares one emulator-generated literal nondeterministic in every later value. */
    redact(literal, placeholder) {
      if (typeof literal === "string" && literal.length >= 8) redactions.set(literal, placeholder);
      return literal;
    },
    /** Records the normalized value `fn` returns, or the error it threw. */
    async step(id, fn) {
      if (id in steps) throw new Error(`duplicate step id ${id}`);
      if (process.env.STORAGE_PROBE_TRACE) console.error(`[storage-probe]   step ${id}`);
      let value;
      try {
        value = await fn();
      } catch (error) {
        value = { thrown: true, message: String(error?.message ?? error) };
      }
      const { raw: _raw, ...rest } = value && typeof value === "object" ? value : { value };
      const recorded = normalize(redact(value && typeof value === "object" ? rest : value));
      steps[id] = recorded;
      order.push(id);
      return value;
    },
    /** Waits for `count` trigger events (or the timeout) and returns them sorted. */
    events(count, timeoutMs = 10_000) {
      return awaitEvents(count, timeoutMs);
    },
    /** Drops whatever events arrived so far. */
    drainEvents() {
      received.splice(0);
    },
  };
  return { ctx, steps, order };
}

const results = {};
for (const program of PROGRAMS) {
  if (ONLY && !program.id.includes(ONLY)) continue;
  const { ctx, steps, order } = createContext();
  let fault = null;
  try {
    await program.run(ctx);
  } catch (error) {
    fault = String(error?.stack ?? error?.message ?? error);
  }
  results[program.id] = { area: program.area, fault, order, steps };
  console.error(
    `[storage-probe] ${program.id}: ${order.length} steps${fault ? ` FAULT ${fault}` : ""}`,
  );
}

await mkdir(dirname(OUT), { recursive: true });
await writeFile(OUT, `${JSON.stringify({ project: PROJECT, programs: results }, null, 2)}\n`);
sink.close();
process.exit(0);
