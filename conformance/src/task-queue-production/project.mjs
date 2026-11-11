// The comparable projection of a recording (or of a local replay): one record per case of the program, with the run's
// identities masked to forms and every time reduced to a form, so that two runs, and production and fireemu, can be
// compared case by case. A mask hides a value, never a format: the digits of a fraction, the zone of a time, the length of an
// id and of a body stay in the record.
//
// Nothing here reads a file or sends a request.
import { createHash } from "node:crypto";

export const PROJECTION_VERSION = 1;
export const MASK_PROJECT = "demo-task-queue";
const NUMBER_MASK = "123456789012";

const ROLES = "def|retry|limit|window|conc1|conc2|rate|dead|none";
const RE = {
  run: /tqrun-[0-9a-f]{16}/g,
  // The queue and function ids carry the run's suffix in a recording and none in a local run.
  queue: new RegExp(`\\b(tq(?:${ROLES}))[0-9a-f]{6}\\b`, "g"),
  host: /https:\/\/(tq(?:def|retry|limit|window|conc1|conc2|rate|dead))(?:[0-9a-f]{6})?-[a-z0-9]{10}-uc\.a\.run\.app/g,
  time: /\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.(\d+))?(Z|[+-]\d\d:\d\d)/g,
  unix: /\b\d{10}\.(\d+)\b/g,
  numericId: /\b\d{16,20}\b/g,
  project: /fireemu-oracle-[a-z0-9-]+/g,
};

/** Text with its identities masked: the form of each time, the length of each numeric id, never the values. */
export function maskText(text, { projectNumber = null, messageTimes = false } = {}) {
  let out = String(text);
  if (projectNumber) out = out.replaceAll(String(projectNumber), NUMBER_MASK);
  out = out.replace(RE.run, "tqrun-RUN");
  out = out.replace(RE.host, (_, role) => `https://${role}-HOST-uc.a.run.app`);
  out = out.replace(RE.queue, "$1");
  out = out.replace(RE.project, MASK_PROJECT);
  // In a message, Cloud Tasks prints a time with its trailing zeros trimmed, so the digits are not a form there.
  out = out.replace(RE.time, (_, fraction, zone) =>
    messageTimes
      ? `TIME(${zone === "Z" ? "Z" : "offset"})`
      : `TIME(f${(fraction ?? "").length},${zone === "Z" ? "Z" : "offset"})`,
  );
  out = out.replace(RE.unix, (_, fraction) => `UNIX(f${fraction.length})`);
  out = out.replace(RE.numericId, (m) => `ID(${m.length})`);
  return out;
}

const maskValue = (value, options) => {
  if (typeof value === "string") return maskText(value, options);
  if (Array.isArray(value)) return value.map((item) => maskValue(item, options));
  if (value !== null && typeof value === "object")
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [key, maskValue(item, options)]),
    );
  return value;
};

/** A task's masked body: the base64 `httpRequest.body` of a FULL view is decoded and masked as text, so that a run's id is not in it. */
function maskBody(json, options) {
  const masked = maskValue(json, options);
  const body = json?.httpRequest?.body;
  if (typeof body === "string" && masked?.httpRequest)
    masked.httpRequest.body = {
      base64Of: maskText(Buffer.from(body, "base64").toString("utf8"), options),
    };
  return masked;
}

/** The shape of a JSON value: object keys in order with the shape of their values, and the type of a leaf. */
export function shapeOfValue(value) {
  if (Array.isArray(value)) return value.map(shapeOfValue);
  if (value !== null && typeof value === "object")
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, shapeOfValue(v)]));
  return value === null ? "null" : typeof value;
}

/** The admission answer of a create, a delete or a read: the status, the error code and text, and the masked body. */
export function projectAnswer(answer, options) {
  if (!answer) return null;
  const json = answer.json ?? null;
  const error = json?.error;
  return {
    status: answer.status ?? null,
    ...(error
      ? {
          error: {
            code: error.code ?? null,
            status: error.status ?? null,
            message: maskText(error.message ?? "", { ...options, messageTimes: true }),
          },
        }
      : { body: maskBody(json, options), shape: shapeOfValue(json) }),
  };
}

const FIXED_HEADERS = new Set([
  "content-type",
  "user-agent",
  "accept-encoding",
  "x-forwarded-proto",
  "x-cloudtasks-taskretrycount",
  "x-cloudtasks-taskexecutioncount",
  "x-cloudtasks-taskpreviousresponse",
  "x-cloudtasks-taskretryreason",
  "authorization",
]);

/** One delivery's header projection: every name (sorted), the fixed values, and the forms of the ones that vary. */
export function projectHeaders(headers, options) {
  const names = Object.keys(headers).toSorted();
  const fixed = {};
  for (const name of names) {
    const value = headers[name];
    if (FIXED_HEADERS.has(name) && value !== null) fixed[name] = value;
  }
  return {
    names,
    fixed,
    queueName: maskText(headers["x-cloudtasks-queuename"] ?? "", options),
    taskName: maskText(headers["x-cloudtasks-taskname"] ?? "", options),
    eta: maskText(headers["x-cloudtasks-tasketa"] ?? "", options),
    contentLength: headers["content-length"] === undefined ? null : "present",
  };
}

export function projectDelivery(delivery, options) {
  const { request, context, step } = delivery;
  const text = request.bodyText ?? null;
  return {
    retryCount: delivery.retryCount,
    request: {
      method: request.method,
      path: request.path,
      headers: projectHeaders(request.headers, options),
      body: { length: request.bodyLength, text: text === null ? null : maskText(text, options) },
    },
    context: {
      retryCount: context.retryCount,
      executionCount: context.executionCount,
      previousResponse: context.previousResponse,
      retryReason: context.retryReason,
      hasAuth: context.hasAuth,
    },
    step: step ?? null,
  };
}

/** The timings of a case, kept apart because they are compared by bounds: from the send and from the server's create time. */
export function timingsOf(deliveries, t0 = null) {
  const at = (iso) => (t0 === null || !iso ? null : Date.parse(iso) - t0);
  const starts = deliveries.map((d) => d.startFromCreateMs ?? d.startMs ?? null);
  const gaps = starts
    .slice(1)
    .map((ms, i) => (ms !== null && starts[i] !== null ? ms - starts[i] : null));
  return {
    firstMs: starts[0] ?? null,
    gapsMs: gaps,
    startsAtMs: deliveries.map((d) => at(d.startedAt)),
    endsAtMs: deliveries.map((d) => at(d.endedAt)),
    holdMs: deliveries.map((d) =>
      d.endMs !== null && d.startMs !== null && d.endMs !== undefined ? d.endMs - d.startMs : null,
    ),
  };
}

export function projectCase(record, options) {
  const deliveries = record.deliveries ?? [];
  return {
    kind: record.kind,
    sent: record.sent,
    admission: projectAnswer(record.answer, options),
    deliveries: deliveries.map((d) => projectDelivery(d, options)),
    timing: timingsOf(deliveries, options.t0 ?? null),
  };
}

/**
 * A recording's judged cases as the comparable projection. `result` is the recorder's result (`judged.cases`);
 * `meta` names the recording. The corpus digest binds the projection to the program that produced it.
 */
export function projectRecording({ result, alias, meta = {}, corpusSha256, projectNumber }) {
  // Offsets in the timings are from the earliest delivery of the recording, so that deliveries of different cases can be ordered.
  const started = Object.values(result.judged.cases)
    .flatMap((record) => record.deliveries ?? [])
    .map((d) => Date.parse(d.startedAt))
    .filter(Number.isFinite);
  const options = { projectNumber, t0: started.length ? Math.min(...started) : null };
  const cases = Object.fromEntries(
    Object.entries(result.judged.cases).map(([key, record]) => [key, projectCase(record, options)]),
  );
  return {
    schemaVersion: 1,
    projection: PROJECTION_VERSION,
    alias,
    ...meta,
    corpusSha256,
    cases,
  };
}

export const digestOf = (value) => createHash("sha256").update(JSON.stringify(value)).digest("hex");

/** Throws when a projection's text still holds the project number or any other twelve or thirteen digit number (the placeholder excepted). */
export function refuseUnmaskedNumbers(text, projectNumber = null) {
  if (projectNumber && text.includes(String(projectNumber)))
    throw new Error("the projection still holds the project number");
  if (/\b\d{12,13}\b/.test(text.replaceAll(NUMBER_MASK, "")))
    throw new Error("the projection still holds a twelve or thirteen digit number");
}
