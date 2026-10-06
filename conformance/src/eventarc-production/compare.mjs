// Offline comparison of Eventarc stage A recordings.
//
//   node compare.mjs pair --a <capture.jsonl> --b <capture.jsonl> [--out <report.json>]
//       classifies every aligned row of two production recordings as identical, identical after masking
//       the values that differ by construction (request IDs, byte counts that are a function of the
//       request), different because of the state of the project (the publishing API enabled or not), or
//       different.
//   node compare.mjs replay --capture <capture.jsonl> --base <http://host:port> --profile <label>
//                           [--strip-v1] [--out <report.json>]
//       sends every replayable row of a recording to a local listener and compares the answer with the
//       recorded one, row by row, with the same masks. `--strip-v1` drops the `/v1` of the path, as the Admin SDK
//       does against an emulator host.
//
// Nothing here sends anything to production: the recordings are read from disk and the replay goes to the
// listener it is given. The Service Usage rows (the state of the publishing API, its enabling and the
// operation of that enabling) are a different product and are classified, not replayed; so are the
// publishes answered while the publishing API was still disabled (a state a local listener does not model).

import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";

/**
 * The operations that are Service Usage's whatever their path: not part of the Eventarc surface a local
 * listener serves. `getOperation` is not among them, because the recorder uses that name for the operations
 * of both products: see `isServiceUsageRow`.
 */
export const SERVICE_USAGE_OPS = new Set(["getService", "enableService", "listEnabledServices"]);

/**
 * Whether a row is a Service Usage exchange. A Service Usage operation is read at `/v1/operations/<name>`; an
 * Eventarc one (the create and delete of a channel, in stage B) lives under a project and a location and is
 * replayed like any other row.
 */
export function isServiceUsageRow(row) {
  if (SERVICE_USAGE_OPS.has(row.op)) return true;
  return row.op === "getOperation" && !String(row.request?.path ?? "").startsWith("/v1/projects/");
}

/**
 * The credentials of the first six requests of the auth-errors case, which the capture does not record: the
 * case creates its own channel with the default credential, then lists and publishes with none and with an
 * invalid one, then creates with none.
 */
const AUTH_ERRORS_TOKENS = ["default", "none", "none", "invalid", "invalid", "none"];
const INVALID_TOKEN = "invalid-token-for-the-recording";
/** The shape of a Google access token: what a real client sends, and what the strict listener accepts. */
const DEFAULT_TOKEN = "ya29.replay-token";
const REQUEST_ID = /^[0-9a-f]{16}$/;
const SIZE_IN_TEXT = /\((\d+) bytes\)/g;
const ANY_TYPE_URL = "type.googleapis.com/io.cloudevents.v1.CloudEvent";

/** The rows of a capture (the request/answer entries, not the notes). */
export function loadRows(path) {
  return readFileSync(path, "utf8")
    .split("\n")
    .filter((line) => line.trim() !== "")
    .map((line) => JSON.parse(line))
    .filter((entry) => typeof entry.op === "string");
}

/** The run ID of a capture: the one in its run-start note. */
export function runIdOf(path) {
  for (const line of readFileSync(path, "utf8").split("\n")) {
    if (line.trim() === "") continue;
    const entry = JSON.parse(line);
    if (entry.note === "run-start") return entry.runId;
  }
  throw new Error(`${path} has no run-start note`);
}

/**
 * The state of the publishing API a recording found (`DISABLED` or `ENABLED`), from the `before` member of its
 * service-state note, or null when the recording has no such note.
 */
export function serviceStateOf(path) {
  for (const line of readFileSync(path, "utf8").split("\n")) {
    if (line.trim() === "") continue;
    const entry = JSON.parse(line);
    if (entry.note === "service-state" && typeof entry.before === "string") return entry.before;
  }
  return null;
}

/** The credential each row was sent with: see `AUTH_ERRORS_TOKENS` for the first rows of auth-errors, otherwise default. */
export function tokenModes(rows) {
  let seen = 0;
  return rows.map((row) => {
    if (row.case === "auth-errors" && seen < AUTH_ERRORS_TOKENS.length) {
      seen += 1;
      return AUTH_ERRORS_TOKENS[seen - 1];
    }
    return "default";
  });
}

/**
 * The body a recorded request carried, with the text the capture omitted rebuilt. The recorder builds a
 * large text as `JSON.stringify("x".repeat(n - 2))`; the rebuilt text must match the recorded digest, or
 * the row cannot be replayed (`null`). A request with no body is `undefined`.
 */
export function requestBody(row) {
  const body = row.request?.body;
  if (body === undefined) return undefined;
  let replayable = true;
  const rebuild = (value) => {
    if (Array.isArray(value)) return value.map(rebuild);
    if (value !== null && typeof value === "object") {
      const keys = Object.keys(value);
      if (keys.length === 1 && keys[0] === "omitted") {
        const { length, sha256 } = value.omitted;
        const text = JSON.stringify("x".repeat(length - 2));
        if (text.length !== length || createHash("sha256").update(text).digest("hex") !== sha256)
          replayable = false;
        return text;
      }
      return Object.fromEntries(keys.map((key) => [key, rebuild(value[key])]));
    }
    return value;
  };
  const rebuilt = rebuild(body);
  return replayable ? rebuilt : null;
}

// --- the size the publishing API reports --------------------------------------------------------------
//
// "The event size (N bytes) is too large": N is the serialized size of the whole PublishEventsRequest
// (field 1 the channel name, field 2 each event as an Any), not of the event. Reproduced exactly from the
// recorded requests of both recordings (1,048,883, 4,194,614, 10,486,070 and 8,390,420 bytes).

const varintLength = (n) => {
  let length = 1;
  for (let rest = n; rest >= 128; rest = Math.floor(rest / 128)) length += 1;
  return length;
};
const field = (length) => 1 + varintLength(length) + length; // a tag below 16 and a length-delimited value
const textLength = (value) => Buffer.byteLength(value, "utf8");

function timestampLength(text) {
  const match = /^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.(\d{1,9}))?Z$/.exec(text);
  if (match === null) return null;
  const millis = Date.parse(`${text.split(".")[0].replace("Z", "")}Z`);
  const seconds = Math.floor(millis / 1000);
  const nanos = match[7] === undefined ? 0 : Number(match[7].padEnd(9, "0"));
  return (
    (seconds === 0 ? 0 : 1 + varintLength(seconds)) + (nanos === 0 ? 0 : 1 + varintLength(nanos))
  );
}

/** The serialized size of one CloudEvent given in the proto JSON form, or null for a form not covered. */
export function cloudEventSize(event) {
  let size = 0;
  for (const key of ["id", "source", "specVersion", "type"]) {
    if (event[key] === undefined || event[key] === "") continue;
    if (typeof event[key] !== "string") return null;
    size += field(textLength(event[key]));
  }
  for (const [key, value] of Object.entries(event.attributes ?? {})) {
    let inner;
    if (typeof value?.ceString === "string") inner = field(textLength(value.ceString));
    else if (typeof value?.ceTimestamp === "string") {
      const length = timestampLength(value.ceTimestamp);
      if (length === null) return null;
      inner = field(length);
    } else return null;
    const entry = field(Buffer.byteLength(key, "utf8")) + field(inner);
    size += field(entry);
  }
  if (event.textData !== undefined) {
    // A text the capture omitted and the caller did not rebuild is not a text: its size is not known.
    if (typeof event.textData !== "string") return null;
    size += field(textLength(event.textData));
  } else if (event.binaryData !== undefined) return null;
  return size;
}

/** The serialized size of a publish request for the channel, with each event as an Any, or null. */
export function publishRequestSize(channel, events) {
  let size = field(Buffer.byteLength(channel, "utf8"));
  for (const event of events) {
    const inner = cloudEventSize(event);
    if (inner === null) return null;
    const any = field(Buffer.byteLength(ANY_TYPE_URL, "utf8")) + field(inner);
    size += field(any);
  }
  return size;
}

/** The channel resource name a publish path names (`/v1` prefix and the `:publishEvents` verb removed). */
export function publishedChannel(path) {
  const bare = path
    .split("?")[0]
    .replace(/^\/v1\//, "/")
    .replace(/^\//, "");
  return bare.endsWith(":publishEvents") ? bare.slice(0, -":publishEvents".length) : null;
}

// --- masks ---------------------------------------------------------------------------------------------

/** Masks the `requestId` of a `RequestInfo` detail: a fresh 16-hex value in every answer. */
export function maskRequestIds(value) {
  if (Array.isArray(value)) return value.map(maskRequestIds);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [
        key,
        key === "requestId" && typeof item === "string" && REQUEST_ID.test(item)
          ? "<requestId>"
          : maskRequestIds(item),
      ]),
    );
  }
  return value;
}

/** Replaces the run ID where a name carries it (lower and upper case). */
export function maskRun(value, runId) {
  if (typeof value === "string")
    return value.split(runId).join("<run>").split(runId.toUpperCase()).join("<RUN>");
  if (Array.isArray(value)) return value.map((item) => maskRun(item, runId));
  if (value !== null && typeof value === "object")
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [key, maskRun(item, runId)]),
    );
  return value;
}

/** Replaces every "(N bytes)" with "(<size> bytes)". */
export function maskSizes(value) {
  if (typeof value === "string") return value.replace(SIZE_IN_TEXT, "(<size> bytes)");
  if (Array.isArray(value)) return value.map(maskSizes);
  if (value !== null && typeof value === "object")
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, maskSizes(item)]));
  return value;
}

/** The byte counts a text names. */
const sizesIn = (value) => (JSON.stringify(value) ?? "").match(/\((\d+) bytes\)/g) ?? [];

/** Whether every byte count in an answer is the serialized size of the request it answers. */
export function sizesFollowRequest(row) {
  const named = sizesIn(row.response?.body);
  if (named.length === 0) return true;
  const channel = publishedChannel(row.request.path);
  const body = requestBody(row);
  if (channel === null || body === null || body === undefined) return false;
  const size = publishRequestSize(channel, body.events ?? []);
  return size !== null && named.every((text) => text === `(${size} bytes)`);
}

const ERROR_INFO = "type.googleapis.com/google.rpc.ErrorInfo";

/** Whether two objects have the same members with the same values, in any order. */
function sameMembers(a, b) {
  const plain = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
  if (!plain(a) || !plain(b)) return sameJson(a, b);
  const keys = Object.keys(a);
  return (
    keys.length === Object.keys(b).length &&
    keys.every((key) => key in b && sameJson(a[key], b[key]))
  );
}

/**
 * Deep equality of parsed JSON, member order included: production's order is recorded (the recorder keeps
 * the order of the parsed body) and is part of what a listener reproduces. The one exemption is the
 * `metadata` of an `ErrorInfo`, a proto map whose order varies between answers of the same request
 * (six places of r1 against r2).
 */
export function sameJson(a, b) {
  if (a === b) return true;
  if (a === null || b === null || typeof a !== "object" || typeof b !== "object") return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  if (Array.isArray(a))
    return a.length === b.length && a.every((item, index) => sameJson(item, b[index]));
  const keys = Object.keys(a);
  const other = Object.keys(b);
  const info = a["@type"] === ERROR_INFO;
  return (
    keys.length === other.length &&
    keys.every(
      (key, index) =>
        key === other[index] &&
        (info && key === "metadata" ? sameMembers(a[key], b[key]) : sameJson(a[key], b[key])),
    )
  );
}

/** Compare CloudEvent member names as a set while retaining their unmodelled wire order. */
export function compareCloudEventKeys(recorded, actual) {
  const recordedSet = new Set(recorded);
  const actualSet = new Set(actual);
  return {
    verdict:
      recordedSet.size === actualSet.size && [...recordedSet].every((key) => actualSet.has(key))
        ? "MATCH"
        : "DIVERGES",
    order:
      recorded.length === actual.length && recorded.every((key, index) => key === actual[index])
        ? "MATCH"
        : "UNMODELLED",
    missing: recorded.filter((key) => !actualSet.has(key)),
    extra: actual.filter((key) => !recordedSet.has(key)),
  };
}

/** The paths at which two JSON values differ; the path of an object whose members only changed order ends in `#order`. */
export function diffPaths(a, b, path = "$") {
  if (sameJson(a, b)) return [];
  if (
    a === null ||
    b === null ||
    typeof a !== "object" ||
    typeof b !== "object" ||
    Array.isArray(a) !== Array.isArray(b)
  )
    return [path];
  const keys = [...new Set([...Object.keys(a), ...Object.keys(b)])].toSorted();
  const paths = keys.flatMap((key) => diffPaths(a[key], b[key], `${path}.${key}`));
  return paths.length === 0 ? [`${path}#order`] : paths;
}

// --- classes of rows -----------------------------------------------------------------------------------

/** The recorded answer is the publishing API's "disabled" refusal: the state of the project, not of the API. */
export function isServiceDisabled(row) {
  return (
    row.response?.status === 403 &&
    JSON.stringify(row.response.body ?? "").includes('"reason":"SERVICE_DISABLED"')
  );
}

/**
 * Why a row is not replayed, or null when it is: the project's state (Service Usage, a publish answered while
 * the API was disabled). A body that cannot be rebuilt is not a reason to skip: `replay` reports it as a
 * divergence to review.
 */
export function skipReason(row) {
  if (isServiceUsageRow(row)) return "service-usage";
  if (isServiceDisabled(row)) return "service-disabled";
  return null;
}

/** A short name of an answer's family, for grouping: status, canonical status, the message with numbers removed. */
export function answerFamily(response) {
  const error = response?.body?.error;
  if (error === undefined)
    return `${response?.status}${response?.body && Object.keys(response.body).length === 0 ? " {}" : ""}`;
  const message = String(error.message ?? "")
    .replaceAll(/projects\/[\w-]+/g, "projects/<p>")
    .replaceAll(/\d+/g, "<n>")
    .replaceAll(/'[^']*'/g, "'<x>'")
    .slice(0, 70);
  return `${response.status} ${error.status ?? ""} ${message}`.trim();
}

/**
 * Compares the same row of two recordings. `identical`: equal after the run ID is masked; `masked`: equal
 * once the requestIds are masked and every byte count is shown to be the size of its own request; `state`:
 * different because the publishing API was enabled in only one recording (the service-state case);
 * `different`: anything else.
 */
export function classifyPair(rowA, rowB, runA, runB) {
  const answerA = maskRun(rowA.response, runA);
  const answerB = maskRun(rowB.response, runB);
  if (sameJson(answerA, answerB)) return { kind: "identical", paths: [] };
  const maskedA = maskRequestIds(answerA);
  const maskedB = maskRequestIds(answerB);
  if (sameJson(maskedA, maskedB)) return { kind: "masked", paths: diffPaths(answerA, answerB) };
  if (sizesFollowRequest(rowA) && sizesFollowRequest(rowB)) {
    const sizedA = maskSizes(maskedA);
    const sizedB = maskSizes(maskedB);
    if (sameJson(sizedA, sizedB)) return { kind: "masked", paths: diffPaths(answerA, answerB) };
  }
  const echoA = maskEcho(maskedA, channelIdOf(rowA.request));
  const echoB = maskEcho(maskedB, channelIdOf(rowB.request));
  if (sameJson(echoA, echoB)) return { kind: "masked", paths: diffPaths(answerA, answerB) };
  // A difference in the service-state case is the state of the project only when one of the two rows is a
  // Service Usage exchange or a publish answered while the API was disabled.
  if (rowA.case === "service-state" && (isProjectState(rowA) || isProjectState(rowB)))
    return { kind: "state", paths: diffPaths(answerA, answerB) };
  return { kind: "different", paths: diffPaths(answerA, answerB) };
}

/** The channel ID a request names: the last segment of the channel path, or the `channelId` query. */
export function channelIdOf(request) {
  const [path, query = ""] = request.path.split("?");
  const created = new URLSearchParams(query).get("channelId");
  if (created !== null) return created;
  const match = /\/channels\/([^/:?]+)/.exec(path);
  return match === null ? null : match[1];
}

const escapeRegExp = (text) => text.replaceAll(/[.*+?^${}()|[\]\\]/g, "\\$&");

/**
 * Replaces the channel ID of the request where an answer echoes it as a whole name: after `channels/`, or
 * quoted. An ID inside a word, or the start of a longer name, is not touched.
 */
export function maskEcho(value, id) {
  if (id === null || id === "") return value;
  const name = escapeRegExp(id);
  const pattern = new RegExp(`(?<=channels/)${name}(?![\\w-])|(?<=['"])${name}(?=['"])`, "g");
  const walk = (item) => {
    if (typeof item === "string") return item.replaceAll(pattern, "<id>");
    if (Array.isArray(item)) return item.map(walk);
    if (item !== null && typeof item === "object")
      return Object.fromEntries(Object.entries(item).map(([key, member]) => [key, walk(member)]));
    return item;
  };
  return walk(value);
}

/** The key that aligns the rows of two recordings: the case, the operation and the position in that case. */
function alignKey(rows) {
  const counts = new Map();
  return rows.map((row) => {
    const base = `${row.case}/${row.op}`;
    const index = counts.get(base) ?? 0;
    counts.set(base, index + 1);
    return `${base}#${index}`;
  });
}

/** A row only one recording has: the state of the publishing API when it is in the service-state case. */
const isProjectState = (row) => isServiceUsageRow(row) || isServiceDisabled(row);

/**
 * A row only one recording has. In the service-state case it is a row of the project's state when the two
 * recordings found the project in different states (one took the disabled branch, the other did not).
 */
const unpairedKind = (row, states) =>
  row.case === "service-state" &&
  states[0] !== null &&
  states[1] !== null &&
  states[0] !== states[1]
    ? "state"
    : "unpaired";

/** Aligns two recordings and classifies every pair; rows present in only one are `unpaired`. */
export function comparePair(rowsA, rowsB, runA, runB, states = [null, null]) {
  const keysA = alignKey(rowsA);
  const keysB = alignKey(rowsB);
  const byKeyB = new Map(keysB.map((key, index) => [key, rowsB[index]]));
  const used = new Set();
  const rows = [];
  rowsA.forEach((row, index) => {
    const other = byKeyB.get(keysA[index]);
    if (other === undefined) {
      rows.push({
        key: keysA[index],
        a: row.n,
        b: null,
        kind: unpairedKind(row, states),
        paths: [],
      });
      return;
    }
    used.add(keysA[index]);
    const result = classifyPair(row, other, runA, runB);
    rows.push({ key: keysA[index], a: row.n, b: other.n, ...result });
  });
  keysB.forEach((key, index) => {
    if (!used.has(key))
      rows.push({
        key,
        a: null,
        b: rowsB[index].n,
        kind: unpairedKind(rowsB[index], states),
        paths: [],
      });
  });
  return rows;
}

// --- replay --------------------------------------------------------------------------------------------

/** Sends one recorded row to `base` and returns the status and the parsed body ({raw} for a text). */
export async function replayRow(row, token, { base, stripV1 = false, fetchImpl = fetch }) {
  const headers = {};
  const body = requestBody(row);
  if (body !== undefined) headers["content-type"] = "application/json";
  if (token === "invalid") headers.authorization = `Bearer ${INVALID_TOKEN}`;
  else if (token === "default") headers.authorization = `Bearer ${DEFAULT_TOKEN}`;
  const reply = await fetchImpl(
    `${base}${stripV1 ? row.request.path.replace(/^\/v1\//, "/") : row.request.path}`,
    {
      method: row.request.method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(30_000),
    },
  );
  const text = await reply.text();
  let parsed;
  if (text === "") parsed = null;
  else {
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = { raw: text.slice(0, 4096) };
    }
  }
  return { status: reply.status, body: parsed };
}

/** Compares the recorded answer with the answer of a listener: `match`, or `diverge` with the differing paths. */
export function compareAnswer(recorded, actual) {
  const wanted = maskRequestIds(recorded);
  const got = maskRequestIds(actual);
  if (wanted.status !== got.status)
    return { verdict: "diverge", reason: "status", paths: ["$.status"] };
  if (sameJson(wanted.body ?? null, got.body ?? null)) return { verdict: "match", paths: [] };
  return {
    verdict: "diverge",
    reason: "body",
    paths: diffPaths(wanted.body ?? null, got.body ?? null, "$.body"),
  };
}

/** Replays a recording against a listener, row by row. */
export async function replay(rows, options) {
  const modes = tokenModes(rows);
  const results = [];
  for (const [index, row] of rows.entries()) {
    const skipped = skipReason(row);
    const common = {
      n: row.n,
      case: row.case,
      op: row.op,
      family: answerFamily(row.response),
    };
    if (skipped === null && requestBody(row) === null) {
      // Not a skip: coverage that is lost silently is coverage nobody notices is gone.
      results.push({ ...common, verdict: "diverge", reason: "unreplayable-body", paths: [] });
      continue;
    }
    if (skipped !== null) {
      results.push({ ...common, verdict: "skipped", reason: skipped, paths: [] });
      continue;
    }
    let actual;
    try {
      actual = await replayRow(row, modes[index], options);
    } catch (error) {
      results.push({
        ...common,
        verdict: "diverge",
        reason: `transport: ${error.message}`,
        paths: [],
      });
      continue;
    }
    const compared = compareAnswer(row.response, actual);
    results.push({
      ...common,
      ...compared,
      ...(compared.verdict === "diverge"
        ? { recorded: row.response, actual: { status: actual.status, body: actual.body } }
        : {}),
    });
  }
  return results;
}

/** Counts of verdicts, and of verdicts by answer family, for the report. */
export function summarize(results) {
  const total = {};
  const families = {};
  for (const result of results) {
    total[result.verdict] = (total[result.verdict] ?? 0) + 1;
    const key = `${result.family}`;
    families[key] ??= { match: 0, diverge: 0, skipped: 0, rows: [] };
    families[key][result.verdict] += 1;
    families[key].rows.push(result.n);
  }
  return { total, families };
}

const flag = (args, name) => {
  const index = args.indexOf(`--${name}`);
  return index < 0 ? undefined : args[index + 1];
};

export async function main(argv, io = { stdout: process.stdout, stderr: process.stderr }) {
  const [command, ...args] = argv;
  const out = flag(args, "out");
  let report;
  if (command === "pair") {
    const pathA = flag(args, "a");
    const pathB = flag(args, "b");
    if (pathA === undefined || pathB === undefined) {
      io.stderr.write("pair needs --a and --b\n");
      return 2;
    }
    const rows = comparePair(loadRows(pathA), loadRows(pathB), runIdOf(pathA), runIdOf(pathB), [
      serviceStateOf(pathA),
      serviceStateOf(pathB),
    ]);
    const counts = {};
    for (const row of rows) counts[row.kind] = (counts[row.kind] ?? 0) + 1;
    report = {
      command,
      a: pathA,
      b: pathB,
      counts,
      rows: rows.filter((row) => row.kind !== "identical"),
    };
  } else if (command === "replay") {
    const capture = flag(args, "capture");
    const base = flag(args, "base");
    const profile = flag(args, "profile");
    if (capture === undefined || base === undefined || profile === undefined) {
      io.stderr.write("replay needs --capture, --base and --profile\n");
      return 2;
    }
    const results = await replay(loadRows(capture), { base, stripV1: args.includes("--strip-v1") });
    report = { command, capture, profile, ...summarize(results), results };
  } else {
    io.stderr.write("usage: compare.mjs pair|replay ...\n");
    return 2;
  }
  const text = `${JSON.stringify(report, null, 2)}\n`;
  if (out === undefined) io.stdout.write(text);
  else writeFileSync(out, text, { mode: 0o600 });
  return 0;
}

if (import.meta.url === `file://${process.argv[1]}`)
  process.exitCode = await main(process.argv.slice(2));
