// The capture: Cloud Logging entries.list over the exact stdout origin of each of the 22 handlers,
// and the parser of the FE_EVENTS_FRAME lines. The parser never throws on a shape it does not know:
// it counts what it could not use and the run goes on. Nothing here decides whether an event was
// delivered; that is the comparator's work.

import { PROJECT, REGION } from "./script.mjs";

export const FRAME_MARKER = "FE_EVENTS_FRAME ";

export const HANDLERS = [
  ["fsCreatedV1", 1, "firestore"], ["fsCreatedV2", 2, "firestore"],
  ["fsUpdatedV1", 1, "firestore"], ["fsUpdatedV2", 2, "firestore"],
  ["fsDeletedV1", 1, "firestore"], ["fsDeletedV2", 2, "firestore"],
  ["fsWrittenV1", 1, "firestore"], ["fsWrittenV2", 2, "firestore"],
  ["fsWrittenWithAuthContextV2", 2, "firestore"], ["fsRetryV2", 2, "firestore"],
  ["storageFinalizedV1", 1, "storage"], ["storageFinalizedV2", 2, "storage"],
  ["storageDeletedV1", 1, "storage"], ["storageDeletedV2", 2, "storage"],
  ["storageMetadataUpdatedV1", 1, "storage"], ["storageMetadataUpdatedV2", 2, "storage"],
  ["storageArchivedV1", 1, "storage"], ["storageArchivedV2", 2, "storage"],
  ["authCreatedV1", 1, "auth"], ["authDeletedV1", 1, "auth"],
  ["pubsubPublishedV1", 1, "pubsub"], ["pubsubPublishedV2", 2, "pubsub"],
].map(([name, generation, source]) => ({ name, generation, source }));

/** The exact origin of one handler's stdout: log name, monitored resource type and labels. */
export function origin({ name, generation }) {
  return generation === 1
    ? {
        logName: `projects/${PROJECT}/logs/cloudfunctions.googleapis.com%2Fcloud-functions`,
        resourceType: "cloud_function",
        labels: { function_name: name, region: REGION },
      }
    : {
        logName: `projects/${PROJECT}/logs/run.googleapis.com%2Fstdout`,
        resourceType: "cloud_run_revision",
        labels: { service_name: name.toLowerCase(), location: REGION },
      };
}

/** The filter of one poll: the 22 origins, the frame marker, and the time window (RFC 3339 UTC strings). */
export function logFilter({ start, end }) {
  const origins = HANDLERS.map((handler) => {
    const o = origin(handler);
    return `(${[`logName="${o.logName}"`, `resource.type="${o.resourceType}"`, ...Object.entries(o.labels).map(([k, v]) => `resource.labels.${k}="${v}"`)].join(" AND ")})`;
  }).join(" OR ");
  const marker = FRAME_MARKER.trim();
  return `(${origins}) AND timestamp>="${start}" AND timestamp<="${end}" AND (textPayload:"${marker}" OR jsonPayload.message:"${marker}")`;
}

export function listRequest({ start, end, pageToken }) {
  return {
    id: "capture.list",
    role: "capture",
    method: "POST",
    url: "https://logging.googleapis.com/v2/entries:list",
    auth: "oauth",
    mutation: false,
    expect: [200],
    body: {
      resourceNames: [`projects/${PROJECT}`],
      filter: logFilter({ start, end }),
      orderBy: "timestamp asc",
      pageSize: 1000,
      ...(pageToken ? { pageToken } : {}),
    },
  };
}

const known = new Map(HANDLERS.map((handler) => [handler.name, handler]));
export const IGNORED = ["notTyped", "notFrame", "unparsed", "unknownHandler", "foreignOrigin"];

/** The frames in one entries:list answer, deduplicated by insertId against `seen` (a Set, updated). */
export function parseEntries(body, { readAt, seen = new Set() }) {
  const result = { entries: 0, frames: [], ignored: Object.fromEntries(IGNORED.map((k) => [k, 0])), nextPageToken: null };
  if (!body || typeof body !== "object") return result;
  if (typeof body.nextPageToken === "string" && body.nextPageToken) result.nextPageToken = body.nextPageToken;
  if (!Array.isArray(body.entries)) return result;
  for (const entry of body.entries) {
    result.entries += 1;
    if (!entry || typeof entry !== "object") {
      result.ignored.notTyped += 1;
      continue;
    }
    const text = typeof entry.textPayload === "string" ? entry.textPayload : entry.jsonPayload?.message;
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
    if (entry.logName !== o.logName || entry.resource?.type !== o.resourceType || Object.entries(o.labels).some(([k, v]) => labels[k] !== v)) {
      result.ignored.foreignOrigin += 1;
      continue;
    }
    const key = typeof entry.insertId === "string" ? entry.insertId : `${entry.timestamp}:${handler.name}`;
    if (seen.has(key)) continue;
    seen.add(key);
    result.frames.push({
      insertId: typeof entry.insertId === "string" ? entry.insertId : null,
      logTimestamp: typeof entry.timestamp === "string" ? entry.timestamp : null,
      readAt,
      handler: handler.name,
      generation: handler.generation,
      source: handler.source,
      frame,
    });
  }
  return result;
}
