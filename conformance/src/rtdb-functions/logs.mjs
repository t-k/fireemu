// The capture: Cloud Logging entries.list over the exact stdout origin of each of the eight handlers,
// and the parser of the CV14_FRAME lines. Adapted from the FUNCTIONS-EVENTS capture (record/logs.mjs),
// which is bound to that recorder's project and 22 handlers. The parser never throws on a shape it
// does not know: it counts what it could not use and the run goes on. Nothing here decides whether an
// event was delivered; sequence.mjs does that.

import { PROJECT } from "../../functions-http/harness.mjs";
import { FIXTURE_HANDLERS, FRAME_MARKER, LOCATION } from "./frames.mjs";

export const LOGGING_HOST = "https://logging.googleapis.com";
export const IGNORED = ["notTyped", "notFrame", "unparsed", "unknownHandler", "foreignOrigin"];
const PAGE_SIZE = 200;

/** The exact origin of one handler's stdout: log name, monitored resource type and labels. */
export function origin({ name, generation }) {
  return generation === 1
    ? {
        logName: `projects/${PROJECT}/logs/cloudfunctions.googleapis.com%2Fcloud-functions`,
        resourceType: "cloud_function",
        labels: { function_name: name, region: LOCATION },
      }
    : {
        logName: `projects/${PROJECT}/logs/run.googleapis.com%2Fstdout`,
        resourceType: "cloud_run_revision",
        labels: { service_name: name.toLowerCase(), location: LOCATION },
      };
}

/** The filter of one poll: the eight origins, the frame marker, and the window (RFC 3339 UTC strings). */
export function logFilter({ start, end }) {
  const origins = FIXTURE_HANDLERS.map((handler) => {
    const o = origin(handler);
    const terms = [
      `logName="${o.logName}"`,
      `resource.type="${o.resourceType}"`,
      ...Object.entries(o.labels).map(([key, value]) => `resource.labels.${key}="${value}"`),
    ];
    return `(${terms.join(" AND ")})`;
  }).join(" OR ");
  const marker = FRAME_MARKER.trim();
  return `(${origins}) AND timestamp>="${start}" AND timestamp<="${end}" AND (textPayload:"${marker}" OR jsonPayload.message:"${marker}")`;
}

/** One bounded entries:list request (a POST the recorder sends through its control client). */
export function listRequest({ start, end, pageToken }) {
  return {
    method: "POST",
    url: `${LOGGING_HOST}/v2/entries:list`,
    body: {
      resourceNames: [`projects/${PROJECT}`],
      filter: logFilter({ start, end }),
      orderBy: "timestamp asc",
      pageSize: PAGE_SIZE,
      ...(pageToken ? { pageToken } : {}),
    },
  };
}

const known = new Map(FIXTURE_HANDLERS.map((handler) => [handler.name, handler]));

/** The frames in one entries:list answer, read once per insert id against `seen` (a Set, updated). */
export function parseEntries(body, { readAt, seen = new Set() }) {
  const result = {
    entries: 0,
    frames: [],
    ignored: Object.fromEntries(IGNORED.map((key) => [key, 0])),
    nextPageToken: null,
  };
  if (!body || typeof body !== "object") return result;
  if (typeof body.nextPageToken === "string" && body.nextPageToken) {
    result.nextPageToken = body.nextPageToken;
  }
  if (!Array.isArray(body.entries)) return result;
  for (const entry of body.entries) {
    result.entries += 1;
    if (!entry || typeof entry !== "object") {
      result.ignored.notTyped += 1;
      continue;
    }
    const text =
      typeof entry.textPayload === "string" ? entry.textPayload : entry.jsonPayload?.message;
    if (typeof text !== "string" || !text.startsWith(FRAME_MARKER)) {
      result.ignored.notFrame += 1;
      continue;
    }
    let frame;
    try {
      frame = JSON.parse(text.slice(FRAME_MARKER.length));
    } catch {
      result.ignored.unparsed += 1;
      continue;
    }
    const handler = known.get(frame?.handler);
    if (!handler || frame.generation !== handler.generation) {
      result.ignored.unknownHandler += 1;
      continue;
    }
    const o = origin(handler);
    const labels = entry.resource?.labels ?? {};
    if (
      entry.logName !== o.logName ||
      entry.resource?.type !== o.resourceType ||
      Object.entries(o.labels).some(([key, value]) => labels[key] !== value)
    ) {
      result.ignored.foreignOrigin += 1;
      continue;
    }
    const key =
      typeof entry.insertId === "string" ? entry.insertId : `${entry.timestamp}:${handler.name}`;
    if (seen.has(key)) continue;
    seen.add(key);
    result.frames.push({
      insertId: typeof entry.insertId === "string" ? entry.insertId : null,
      logTimestamp: typeof entry.timestamp === "string" ? entry.timestamp : null,
      readAt,
      handler: handler.name,
      generation: handler.generation,
      frame,
    });
  }
  return result;
}
