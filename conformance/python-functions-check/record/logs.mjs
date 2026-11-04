// Cloud Logging reads of the check: the filters, the request, and the parsers. The parsers never throw on a shape they
// do not know: they count what they could not use and the run goes on. Nothing here decides whether a delivery is what
// was expected; that is for the judge.
import { ALL_FUNCTIONS, FRAME_MARK, PROJECT, REGION } from "./plan.mjs";

/** The exact origin of one Gen2 function's stdout and stderr: log names, monitored resource type and labels. */
export function frameOrigin(fn) {
  return {
    logNames: ["stdout", "stderr"].map((s) => `projects/${PROJECT}/logs/run.googleapis.com%2F${s}`),
    resourceType: "cloud_run_revision",
    labels: { service_name: fn, location: REGION },
  };
}

const RFC3339 = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/;
const need = (time) => {
  if (!RFC3339.test(time ?? "")) throw new Error("a log window is an RFC 3339 UTC time");
  return time;
};

const services = () =>
  ALL_FUNCTIONS.map((fn) => `resource.labels.service_name="${fn}"`).join(" OR ");
const base = `resource.type="cloud_run_revision" AND resource.labels.location="${REGION}"`;

/** The filter of one frame poll: the run's services, the frame marker, and the time window. */
export function frameFilter({ start, end }) {
  return `${base} AND (${services()}) AND timestamp>="${need(start)}" AND timestamp<="${need(end)}" AND (textPayload:"${FRAME_MARK}" OR jsonPayload.message:"${FRAME_MARK}")`;
}

/** The filter of one error poll: what the run's services logged at ERROR or worse (a Python traceback is one). */
export function errorFilter({ start, end }) {
  return `${base} AND (${services()}) AND severity>=ERROR AND timestamp>="${need(start)}" AND timestamp<="${need(end)}"`;
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

const textOf = (entry) => {
  if (typeof entry.textPayload === "string") return entry.textPayload;
  if (typeof entry.jsonPayload?.message === "string") return entry.jsonPayload.message;
  return null;
};

const originMatches = (entry, fn) => {
  const o = frameOrigin(fn);
  return (
    o.logNames.includes(entry.logName) &&
    entry.resource?.type === o.resourceType &&
    Object.entries(o.labels).every(([k, v]) => entry.resource?.labels?.[k] === v)
  );
};

function frameOf(body) {
  const at = body === null ? -1 : body.indexOf(FRAME_MARK + " ");
  if (at < 0) return { notFrame: true };
  try {
    return { frame: JSON.parse(body.slice(at + FRAME_MARK.length + 1)) };
  } catch {
    return { unparsed: true };
  }
}

const usable = (frame) =>
  frame &&
  typeof frame === "object" &&
  typeof frame.function === "string" &&
  ALL_FUNCTIONS.includes(frame.function) &&
  typeof frame.kind === "string";

/**
 * The frames in a page of entries, deduplicated by `insertId` against the entries already `seen` (a Set the caller
 * keeps). Returns `{frames, ignored}`; every entry is either a frame or counted in `ignored`. A frame is kept only
 * when it came from the origin of the function it names.
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
    const parsed = frameOf(entry && typeof entry === "object" ? textOf(entry) : null);
    if (parsed.notFrame) ignored.notFrame++;
    else if (parsed.unparsed || !usable(parsed.frame)) ignored.unparsed++;
    else if (!originMatches(entry, parsed.frame.function)) ignored.foreignOrigin++;
    else
      frames.push({
        insertId: id ?? null,
        timestamp: entry.timestamp ?? null,
        frame: parsed.frame,
      });
  }
  return { frames, ignored };
}

/** The ERROR entries of a page, reduced to the service, the time and the first 600 characters of the text. */
export function parseErrors(entries, seen = new Set()) {
  const errors = [];
  for (const entry of Array.isArray(entries) ? entries : []) {
    if (!entry || typeof entry !== "object") continue;
    const id = entry.insertId;
    if (typeof id === "string") {
      if (seen.has(id)) continue;
      seen.add(id);
    }
    const service = entry.resource?.labels?.service_name;
    if (!ALL_FUNCTIONS.includes(service)) continue;
    const body =
      textOf(entry) ?? JSON.stringify(entry.jsonPayload ?? entry.protoPayload?.status ?? null);
    errors.push({
      function: service,
      timestamp: entry.timestamp ?? null,
      text: String(body).slice(0, 600),
    });
  }
  return errors;
}

/** The frames in fireemu's own output (the local dry run): every line that carries the marker. */
export function parseFramesFromText(text) {
  const frames = [];
  let ignored = 0;
  for (const line of String(text).split("\n")) {
    const parsed = frameOf(line);
    if (parsed.notFrame) continue;
    if (parsed.unparsed || !usable(parsed.frame)) ignored++;
    else frames.push({ insertId: null, timestamp: parsed.frame.at ?? null, frame: parsed.frame });
  }
  return { frames, ignored };
}
