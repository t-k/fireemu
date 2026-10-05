// How the strict profile delivers a scheduled run the way production's Cloud Scheduler does, recorded in the second
// SCHEDULED-FUNCTIONS delivery recording (run 156715222b86ea44, 2026-10-05, 97 handler frames, project
// fireemu-oracle-sbx, us-central1):
//
// - a Gen2 `onSchedule` function is called as an HTTP function: `POST /` with `x-cloudscheduler: true`, the job's id in
//   `x-cloudscheduler-jobname` (not its resource name) and the schedule time in `x-cloudscheduler-scheduletime`
//   written in America/Los_Angeles with its offset (`2026-10-05T01:45:00-07:00`) whatever the job's own time zone
//   (UTC and Asia/Tokyo jobs alike), `user-agent: Google-Cloud-Scheduler`, an empty body. The SDK builds the event
//   from those headers, including the non-enumerable `context` getter, and answers 200, or 500 when the handler
//   throws (after logging the error); the Scheduler judges the attempt by that status.
// - a Gen1 `pubsub.schedule` handler gets the context of a Pub/Sub message published to the job's topic: a
//   17-digit message id as `eventId`, the topic as `resource.name`, `resource.type` the PubsubMessage type, and the
//   message's publish time (milliseconds at most, trailing zeros dropped) as `timestamp`.
//
// The Authorization (OIDC) header, trace headers, `forwarded` and `x-forwarded-for` of the recording are not
// reproduced: nothing here can sign a token for Google, and the others carry a trace id and a client address.
import { createHash } from "node:crypto";

const INSTANT = /^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.(\d{1,9}))?Z$/;

function parseInstant(value, what) {
  const match = typeof value === "string" ? INSTANT.exec(value) : null;
  if (!match) throw new Error(`the ${what} is not an RFC 3339 UTC instant: ${String(value)}`);
  const [year, month, day, hour, minute, second] = match.slice(1, 7).map(Number);
  const millis = Date.UTC(year, month - 1, day, hour, minute, second);
  const back = new Date(millis);
  if (
    back.getUTCFullYear() !== year ||
    back.getUTCMonth() !== month - 1 ||
    back.getUTCDate() !== day ||
    back.getUTCHours() !== hour ||
    back.getUTCMinutes() !== minute ||
    back.getUTCSeconds() !== second
  )
    throw new Error(`the ${what} is not an RFC 3339 UTC instant: ${value}`);
  return { millis, fraction: (match[7] ?? "").replace(/0+$/, ""), digits: match[7] ?? "" };
}

const LOS_ANGELES = new Intl.DateTimeFormat("en-US", {
  timeZone: "America/Los_Angeles",
  hourCycle: "h23",
  year: "numeric",
  month: "2-digit",
  day: "2-digit",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
});

/** An RFC 3339 UTC instant written in America/Los_Angeles with its offset, the fraction kept without trailing zeros. */
export function schedulerTimestamp(instant) {
  const { millis, fraction } = parseInstant(instant, "scheduled time");
  const parts = Object.fromEntries(
    LOS_ANGELES.formatToParts(new Date(millis)).map((part) => [part.type, part.value]),
  );
  const local = Date.UTC(
    Number(parts.year),
    Number(parts.month) - 1,
    Number(parts.day),
    Number(parts.hour),
    Number(parts.minute),
    Number(parts.second),
  );
  const offset = (local - millis) / 60_000;
  const sign = offset < 0 ? "-" : "+";
  const abs = Math.abs(offset);
  const clock = `${parts.hour}:${parts.minute}:${parts.second}`;
  const zone = `${sign}${String(Math.floor(abs / 60)).padStart(2, "0")}:${String(abs % 60).padStart(2, "0")}`;
  return `${parts.year}-${parts.month}-${parts.day}T${clock}${fraction ? "." + fraction : ""}${zone}`;
}

/** The job id: the last segment of a job's resource name (an id passes through). */
export function schedulerJobId(jobName) {
  if (typeof jobName !== "string" || jobName.length === 0)
    throw new Error("the scheduled run names no job name");
  return jobName.split("/").at(-1);
}

const NAME = /^[A-Za-z0-9-]+$/;

/**
 * The public host of a function: `<region>-<project>.cloudfunctions.net`, from the project and location of a job's
 * resource name (recorded: `us-central1-<project>.cloudfunctions.net` in all 150 Gen2 frames). A job id alone names
 * neither, and then no host is invented.
 */
function functionHost(jobName) {
  const match = /^projects\/([^/]*)\/locations\/([^/]*)\/jobs\//.exec(String(jobName));
  return match && NAME.test(match[1]) && NAME.test(match[2])
    ? `${match[2]}-${match[1]}.cloudfunctions.net`
    : undefined;
}

/** The request production's Cloud Scheduler sends a Gen2 function, as an Express-like object. */
export function schedulerRequest({ jobName, scheduleTime }) {
  const host = functionHost(jobName);
  const headers = {
    "x-cloudscheduler": "true",
    "x-cloudscheduler-jobname": schedulerJobId(jobName),
    "x-cloudscheduler-scheduletime": schedulerTimestamp(scheduleTime),
    "user-agent": "Google-Cloud-Scheduler",
    "content-length": "0",
    // constant in every recorded frame: the front end's encodings and protocol
    "accept-encoding": "gzip, deflate, br",
    "x-forwarded-proto": "https",
    ...(host ? { host } : {}),
  };
  const header = (name) => headers[String(name).toLowerCase()];
  return {
    method: "POST",
    url: "/",
    originalUrl: "/",
    headers,
    header,
    get: header,
    body: undefined,
    rawBody: undefined,
  };
}

function responseDouble() {
  const res = {
    statusCode: 200,
    answered: false,
    status(code) {
      res.statusCode = code;
      return res;
    },
    sendStatus(code) {
      res.statusCode = code;
      res.answered = true;
      return res;
    },
    send() {
      res.answered = true;
      return res;
    },
    json() {
      res.answered = true;
      return res;
    },
    end() {
      res.answered = true;
      return res;
    },
    setHeader() {
      return res;
    },
    set() {
      return res;
    },
    header() {
      return res;
    },
  };
  return res;
}

/**
 * Calls a Gen2 scheduled function's HTTP wrapper with the scheduler's request. Resolves when the function answered
 * with a status below 400; rejects when it answered 400 or more (the SDK's 500 for a handler that threw), threw, or
 * never answered.
 */
export async function deliverSchedule(fn, data) {
  const res = responseDouble();
  await fn(schedulerRequest(data), res);
  if (!res.answered) throw new Error("the scheduled function did not answer");
  if (res.statusCode >= 400) throw new Error(`the scheduled function answered ${res.statusCode}`);
}

/** A Pub/Sub message id: 17 digits, the first a 2, derived from the event id (the same event, the same id). */
export function pubsubMessageId(eventId) {
  if (typeof eventId !== "string" || eventId.length === 0)
    throw new Error("a Pub/Sub message id needs an event id");
  const digest = createHash("sha256").update(eventId).digest();
  const number = digest.readBigUInt64BE(0) % 10_000_000_000_000_000n;
  return "2" + number.toString().padStart(16, "0");
}

/** A publish time as Pub/Sub prints it to a Gen1 handler: milliseconds at most, trailing zeros dropped. */
function publishTime(instant) {
  const { millis, digits } = parseInstant(instant, "publish time");
  const fraction = digits.padEnd(3, "0").slice(0, 3).replace(/0+$/, "");
  return new Date(millis).toISOString().slice(0, 19) + (fraction ? "." + fraction : "") + "Z";
}

/** The context of a Gen1 `pubsub.schedule` handler: the message published to the job's topic. */
export function v1ScheduleContext(event) {
  const id = schedulerJobId(event?.data?.jobName);
  const project = String(event.data.jobName).match(/^projects\/([^/]+)\//)?.[1];
  return {
    eventId: pubsubMessageId(event.id),
    eventType: "google.pubsub.topic.publish",
    resource: {
      name: project ? `projects/${project}/topics/${id}` : id,
      service: "pubsub.googleapis.com",
      type: "type.googleapis.com/google.pubsub.v1.PubsubMessage",
    },
    timestamp: publishTime(event.time),
    params: {},
  };
}
