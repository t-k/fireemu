// Cloud Logging reads of the delivery recording: the filters, the request, and the parsers. The parsers
// never throw on a shape they do not know: they count what they could not use and the run goes on.
// Nothing here decides whether anything was delivered correctly; that is for the comparison.
import {
  ALL_FUNCTIONS,
  FRAME_MARK,
  FUNCTIONS,
  PROJECT,
  REGION,
  jobIds,
  runServiceId,
} from "./plan.mjs";

/** The exact origin of one function's stdout: log name, monitored resource type and labels. */
export function frameOrigin(fn) {
  return FUNCTIONS.v1.includes(fn)
    ? {
        logName: `projects/${PROJECT}/logs/cloudfunctions.googleapis.com%2Fcloud-functions`,
        resourceType: "cloud_function",
        labels: { function_name: fn, region: REGION },
      }
    : {
        logName: `projects/${PROJECT}/logs/run.googleapis.com%2Fstdout`,
        resourceType: "cloud_run_revision",
        labels: { service_name: runServiceId(fn), location: REGION },
      };
}

const RFC3339 = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/;
const need = (time) => {
  if (!RFC3339.test(time ?? "")) throw new Error("a log window is an RFC 3339 UTC time");
  return time;
};

/** The filter of one frame poll: the five origins, the frame marker, and the time window. */
export function frameFilter({ start, end }) {
  const origins = ALL_FUNCTIONS.map((fn) => {
    const o = frameOrigin(fn);
    return `(${[
      `logName="${o.logName}"`,
      `resource.type="${o.resourceType}"`,
      ...Object.entries(o.labels).map(([k, v]) => `resource.labels.${k}="${v}"`),
    ].join(" AND ")})`;
  }).join(" OR ");
  return `(${origins}) AND timestamp>="${need(start)}" AND timestamp<="${need(end)}" AND (textPayload:"${FRAME_MARK}" OR jsonPayload.message:"${FRAME_MARK}")`;
}

/**
 * The filter of one Scheduler-execution poll: every entry of the jobs of the run, whatever its payload.
 * The shape of these entries is not recorded anywhere yet, so nothing narrows them by payload type.
 */
export function schedulerFilter({ runId, start, end }) {
  const jobs = jobIds(runId)
    .map((id) => `resource.labels.job_id="${id}"`)
    .join(" OR ");
  return `resource.type="cloud_scheduler_job" AND (${jobs}) AND timestamp>="${need(start)}" AND timestamp<="${need(end)}"`;
}

export function listRequest({ id, filter, pageToken }) {
  return {
    id,
    method: "POST",
    url: "https://logging.googleapis.com/v2/entries:list",
    json: {
      resourceNames: [`projects/${PROJECT}`],
      filter,
      orderBy: "timestamp asc",
      pageSize: 200,
      ...(pageToken ? { pageToken } : {}),
    },
  };
}

export const IGNORED = ["notFrame", "unparsed", "foreignOrigin"];

const text = (entry) => {
  if (typeof entry.textPayload === "string") return entry.textPayload;
  if (typeof entry.jsonPayload?.message === "string") return entry.jsonPayload.message;
  return null;
};

const originMatches = (entry, fn) => {
  const o = frameOrigin(fn);
  return (
    entry.logName === o.logName &&
    entry.resource?.type === o.resourceType &&
    Object.entries(o.labels).every(([k, v]) => entry.resource?.labels?.[k] === v)
  );
};

/**
 * The frames in a page of entries, deduplicated by `insertId` against the entries already `seen` (a Set the
 * caller keeps). Returns `{frames, ignored}`; every entry is either a frame or counted in `ignored`.
 */
export function parseFrames(entries, seen = new Set()) {
  const frames = [];
  const ignored = Object.fromEntries(IGNORED.map((k) => [k, 0]));
  for (const entry of Array.isArray(entries) ? entries : []) {
    const id = entry?.insertId;
    if (typeof id === "string") {
      if (seen.has(id)) continue;
      seen.add(id);
    }
    const body = entry && typeof entry === "object" ? text(entry) : null;
    const at = body === null ? -1 : body.indexOf(FRAME_MARK + " ");
    if (at < 0) {
      ignored.notFrame++;
      continue;
    }
    let frame;
    try {
      frame = JSON.parse(body.slice(at + FRAME_MARK.length + 1));
    } catch {
      ignored.unparsed++;
      continue;
    }
    if (!frame || typeof frame.handler !== "string" || !ALL_FUNCTIONS.includes(frame.handler)) {
      ignored.unparsed++;
      continue;
    }
    if (!originMatches(entry, frame.handler)) {
      ignored.foreignOrigin++;
      continue;
    }
    frames.push({ insertId: id ?? null, timestamp: entry.timestamp ?? null, frame });
  }
  return { frames, ignored };
}

/** The Scheduler execution entries of a page, deduplicated by `insertId`, kept as they came. */
export function parseSchedulerEntries(entries, seen = new Set()) {
  const kept = [];
  for (const entry of Array.isArray(entries) ? entries : []) {
    if (!entry || typeof entry !== "object") continue;
    const id = entry.insertId;
    if (typeof id === "string") {
      if (seen.has(id)) continue;
      seen.add(id);
    }
    kept.push(entry);
  }
  return kept;
}
