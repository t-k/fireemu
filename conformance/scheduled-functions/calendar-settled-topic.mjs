// Native calendar-5a73ba99b7014cfd: sequence30 records97B absence,150/153 record433B.
// This narrow recovery proof does not change seed judges or authorize transport.
import { calendarRequests, calendarResources, CALENDAR_CASES } from "./calendar.mjs";

const encoded = (json) => Buffer.from(JSON.stringify(json, null, 2) + "\n");
const ownJob = (job) =>
  typeof job === "string" &&
  /^projects\/fireemu-oracle-sbx\/locations\/us-central1\/jobs\/fe-scheduled-calendar-[a-f0-9]{16}-c0[1-8]$/.test(
    job,
  );
export function recordedRecoveryLayout(answer, status, json, bodyBytes) {
  return (
    answer?.status === status &&
    !answer.bodyUnknown &&
    Buffer.isBuffer(answer.rawBytes) &&
    answer.bodyBytes === bodyBytes &&
    answer.rawBytes.length === bodyBytes &&
    answer.rawBytes.equals(encoded(json))
  );
}
export function recordedRecoveryJobAbsent(answer, job, layout = "either") {
  if (!ownJob(job) || !["either", "plain", "detailed"].includes(layout)) return false;
  const plain = { error: { code: 404, message: "Job not found.", status: "NOT_FOUND" } };
  const detailed = {
    error: {
      code: 404,
      message: "Resource '" + job + "' was not found",
      status: "NOT_FOUND",
      details: [{ "@type": "type.googleapis.com/google.rpc.ResourceInfo", resourceName: job }],
    },
  };
  return (
    (layout !== "detailed" && recordedRecoveryLayout(answer, 404, plain, 97)) ||
    (layout !== "plain" && recordedRecoveryLayout(answer, 404, detailed, 433))
  );
}
export function recordedRecoveryTopicOwned(answer, own) {
  return recordedRecoveryLayout(answer, 200, { name: own.topic }, 90);
}
export function recordedRecoveryTopicAbsent(answer, own) {
  return recordedRecoveryLayout(
    answer,
    404,
    {
      error: {
        code: 404,
        message: "Resource not found (resource=" + own.prefix + ").",
        status: "NOT_FOUND",
      },
    },
    152,
  );
}
export function recordedRecoveryEmpty(answer) {
  return recordedRecoveryLayout(answer, 200, {}, 3);
}
const failure = () => {
  throw new Error("settled calendar job proof differs");
};
const millis = (value) => {
  if (
    typeof value !== "string" ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) ||
    !Number.isFinite(Date.parse(value)) ||
    new Date(value).toISOString() !== value
  )
    failure();
  return Date.parse(value);
};
const microTime = (value) =>
  typeof value === "string" &&
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/.test(value) &&
  Number.isFinite(Date.parse(value)) &&
  new Date(value).toISOString().slice(0, 19) === value.slice(0, 19);
const secondTime = (value) =>
  typeof value === "string" &&
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value) &&
  Number.isFinite(Date.parse(value)) &&
  new Date(value).toISOString().slice(0, 19) === value.slice(0, 19);

export function proveSettledCalendarJobs(journal, packet) {
  if (!Array.isArray(journal) || journal.length !== 162) failure();
  const own = calendarResources(packet.runId);
  const templates = calendarRequests(
    packet.runId,
    packet.projectNumber,
    millis(journal[0]?.dispatchAt),
  );
  const omitted = new Set([
    "delete-topic",
    ...["c07", "c08"].flatMap((id) => [id + "-pause", id + "-read-paused", id + "-delete"]),
  ]);
  const expected = templates.filter((r) => !omitted.has(r.id));
  if (expected.length !== 54) failure();
  const groups = new Map();
  let lastResponse = -Infinity;
  for (let i = 0; i < expected.length; i++) {
    const spec = expected[i],
      [before, headers, persisted] = journal.slice(i * 3, i * 3 + 3);
    if (
      before?.state !== "before-send" ||
      headers?.state !== "response-headers" ||
      persisted?.state !== "response-persisted" ||
      [before, headers, persisted].some((r) => r.id !== spec.id) ||
      before.method !== spec.method ||
      before.url !== spec.url ||
      JSON.stringify(before.json ?? null) !== JSON.stringify(spec.json ?? null) ||
      before.timeoutMs !== (spec.timeoutMs ?? 10000) ||
      persisted.dispatchAt !== before.dispatchAt ||
      headers.status !== persisted.status ||
      !Number.isSafeInteger(persisted.status) ||
      typeof persisted.bodyBase64 !== "string"
    )
      failure();
    const dispatch = millis(before.dispatchAt),
      received = millis(headers.responseAt),
      complete = millis(persisted.responseAt);
    if (
      dispatch < lastResponse ||
      received < dispatch ||
      complete < received ||
      ![200, 400, 404].includes(persisted.status)
    )
      failure();
    lastResponse = complete;
    const rawBytes = Buffer.from(persisted.bodyBase64, "base64");
    if (
      rawBytes.toString("base64") !== persisted.bodyBase64 ||
      rawBytes.length !== persisted.bodyBytes ||
      rawBytes.length > 1048576
    )
      failure();
    let json;
    try {
      json = JSON.parse(rawBytes);
    } catch {
      failure();
    }
    groups.set(spec.id, {
      status: persisted.status,
      json,
      bodyBytes: persisted.bodyBytes,
      rawBytes,
      dispatch,
      complete,
    });
  }
  const get = (id) => groups.get(id);
  for (const id of ["before-list-jobs", "before-list-topics", "final-list-jobs"])
    if (!recordedRecoveryEmpty(get(id))) failure();
  if (!recordedRecoveryTopicAbsent(get("before-topic"), own)) failure();
  for (const id of ["create-topic", "read-topic", "read-deleted-topic"])
    if (!recordedRecoveryTopicOwned(get(id), own)) failure();
  if (
    !recordedRecoveryLayout(get("final-list-topics"), 200, { topics: [{ name: own.topic }] }, 124)
  )
    failure();
  let lastPause = -Infinity;
  for (const [index, item] of CALENDAR_CASES.entries()) {
    const id = item.id,
      job = own.jobs[id];
    if (!recordedRecoveryJobAbsent(get(id + "-before"), job, "plain")) failure();
    if (index >= 6) {
      const refusal = {
        error: {
          code: 400,
          message: "The provided schedule or timezone are invalid.",
          status: "INVALID_ARGUMENT",
        },
      };
      if (
        !recordedRecoveryLayout(get(id + "-create"), 400, refusal, 136) ||
        !recordedRecoveryJobAbsent(get(id + "-read-deleted"), job, "detailed")
      )
        failure();
      continue;
    }
    for (const action of ["create", "pause", "read-paused"]) {
      const answer = get(id + "-" + action),
        body = answer.json;
      if (
        !microTime(body?.userUpdateTime) ||
        (action === "create" && !secondTime(body?.scheduleTime))
      )
        failure();
      const expectedBody = {
        name: job,
        pubsubTarget: { topicName: own.topic, data: "c2VlZC1vbmx5" },
        userUpdateTime: body.userUpdateTime,
        state: action === "create" ? "ENABLED" : "PAUSED",
        status: { code: -1 },
        ...(action === "create" ? { scheduleTime: body.scheduleTime } : {}),
        schedule: item.schedule,
        timeZone: item.timeZone,
      };
      const bytes =
        action === "create"
          ? [457, 461, 463, 474, 472, 472][index]
          : [414, 418, 420, 431, 429, 429][index];
      if (!recordedRecoveryLayout(answer, 200, expectedBody, bytes)) failure();
      if (action === "pause") lastPause = Math.max(lastPause, answer.complete);
    }
    if (
      !recordedRecoveryEmpty(get(id + "-delete")) ||
      !recordedRecoveryJobAbsent(get(id + "-read-deleted"), job, "plain")
    )
      failure();
  }
  if (get("c01-delete").dispatch - lastPause < 60000) failure();
  return { requests: 54, createdJobs: 6, refusedJobs: ["c07", "c08"] };
}
