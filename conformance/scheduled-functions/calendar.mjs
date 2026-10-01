// Coordinator-only native calendar seed; importing this module acquires no credentials.
import { readFileSync } from "node:fs";
import { createRequestCapture, ownedResources, PROJECT } from "./shape.mjs";
import { recordedAbsent, recordedPaused, recordedMutationBusy } from "./recovery.mjs";

export const CALENDAR_CASES = Object.freeze(
  JSON.parse(readFileSync(new URL("./calendar-cases.json", import.meta.url), "utf8")).map(
    Object.freeze,
  ),
);

export function calendarResources(runId) {
  ownedResources(runId);
  const prefix = "fe-scheduled-calendar-" + runId;
  return {
    prefix,
    topic: "projects/" + PROJECT + "/topics/" + prefix,
    jobs: Object.fromEntries(
      CALENDAR_CASES.map(({ id }) => [
        id,
        "projects/" + PROJECT + "/locations/us-central1/jobs/" + prefix + "-" + id,
      ]),
    ),
  };
}

export function calendarRequests(runId, projectNumber, now = Date.now()) {
  if (!/^\d{12,13}$/.test(projectNumber ?? "")) throw new Error("invalid project number");
  if (
    !Number.isFinite(now) ||
    now < Date.parse("2026-09-30T00:00:00Z") ||
    now >= Date.parse("2026-10-31T00:00:00Z")
  )
    throw new Error("outside the calendar seed window");
  const own = calendarResources(runId);
  const scheduler = "https://cloudscheduler.googleapis.com/v1/";
  const pubsub = "https://pubsub.googleapis.com/v1/";
  const jobs = scheduler + "projects/" + PROJECT + "/locations/us-central1/jobs";
  const topics = pubsub + "projects/" + PROJECT + "/topics";
  const get = (id, url) => ({ id, method: "GET", url });
  const mutate = (id, method, url, json) => ({
    id,
    method,
    url,
    ...(json ? { json } : {}),
    ...(["create-topic", "delete-topic"].includes(id) || /^c0[1-8]-create$/.test(id)
      ? { timeoutMs: 30000 }
      : {}),
  });
  return [
    get(
      "identity",
      "https://firebaserules.googleapis.com/v1/projects/" + PROJECT + "/releases/cloud.firestore",
    ),
    ...["cloudscheduler.googleapis.com", "pubsub.googleapis.com"].map((service) =>
      get(
        "service-" + service,
        "https://serviceusage.googleapis.com/v1/projects/" + projectNumber + "/services/" + service,
      ),
    ),
    get("appengine-location", "https://appengine.googleapis.com/v1/apps/" + PROJECT),
    get("before-list-jobs", jobs + "?pageSize=500"),
    get("before-list-topics", topics + "?pageSize=1000"),
    get("before-topic", pubsub + own.topic),
    mutate("create-topic", "PUT", pubsub + own.topic, {}),
    get("read-topic", pubsub + own.topic),
    ...CALENDAR_CASES.flatMap((c) => [
      get(c.id + "-before", scheduler + own.jobs[c.id]),
      mutate(c.id + "-create", "POST", jobs, {
        name: own.jobs[c.id],
        schedule: c.schedule,
        timeZone: c.timeZone,
        pubsubTarget: { topicName: own.topic, data: "c2VlZC1vbmx5" },
      }),
      mutate(c.id + "-pause", "POST", scheduler + own.jobs[c.id] + ":pause", {}),
      get(c.id + "-read-paused", scheduler + own.jobs[c.id]),
    ]),
    ...CALENDAR_CASES.flatMap(({ id }) => [
      mutate(id + "-delete", "DELETE", scheduler + own.jobs[id]),
      get(id + "-read-deleted", scheduler + own.jobs[id]),
    ]),
    get("final-list-jobs", jobs + "?pageSize=500"),
    mutate("delete-topic", "DELETE", pubsub + own.topic),
    get("read-deleted-topic", pubsub + own.topic),
    get("final-list-topics", topics + "?pageSize=1000"),
  ];
}

export function recordedEmptyList(answer) {
  return (
    answer?.status === 200 &&
    !answer.bodyUnknown &&
    !!answer.json &&
    typeof answer.json === "object" &&
    !Array.isArray(answer.json) &&
    Object.keys(answer.json).length === 0
  );
}

export function recordedTopicAbsent(answer, own) {
  const error = answer?.json?.error;
  return (
    answer?.status === 404 &&
    !answer.bodyUnknown &&
    error?.code === 404 &&
    error.status === "NOT_FOUND" &&
    error.message === "Resource not found (resource=" + own.prefix + ")."
  );
}

export function recordedTopicOwned(answer, own) {
  return answer?.status === 200 && !answer.bodyUnknown && answer.json?.name === own.topic;
}

export function recordedEnabled(answer, own) {
  return (
    answer?.status === 200 &&
    !answer.bodyUnknown &&
    answer.json?.name === own.job &&
    answer.json?.state === "ENABLED" &&
    answer.json?.pubsubTarget?.topicName === own.topic
  );
}

export async function collectCalendar({
  runId,
  projectNumber,
  accessToken,
  save,
  send,
  clock = Date.now,
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
}) {
  const own = calendarResources(runId);
  const requests = new Map(calendarRequests(runId, projectNumber, clock()).map((r) => [r.id, r]));
  const { capture: captureAnswer, counts } = createRequestCapture({
    accessToken,
    save,
    send,
    clock,
    maxRequests: 64,
  });
  const unsettledCreates = new Set();
  let unknownDelete = false;
  const capture = async (spec) => {
    const answer = await captureAnswer(spec);
    if (
      !answer ||
      answer.bodyUnknown ||
      answer.status < 200 ||
      (answer.status >= 300 && answer.status < 400) ||
      answer.status >= 500
    ) {
      if (spec.id === "create-topic" || /^c0[1-8]-create$/.test(spec.id))
        unsettledCreates.add(spec.id);
      if (spec.method === "DELETE") unknownDelete = true;
    } else if (spec.method === "GET") {
      if (
        spec.url === "https://pubsub.googleapis.com/v1/" + own.topic &&
        recordedTopicOwned(answer, own)
      )
        unsettledCreates.delete("create-topic");
      for (const { id } of CALENDAR_CASES) {
        const target = { job: own.jobs[id], topic: own.topic };
        if (
          spec.url === "https://cloudscheduler.googleapis.com/v1/" + target.job &&
          (recordedEnabled(answer, target) || recordedPaused(answer, target))
        )
          unsettledCreates.delete(id + "-create");
      }
    }
    return answer;
  };
  const take = (id) => capture(requests.get(id));
  const summary = (closureReady) => ({
    outcome: "calendar-needs-review",
    ...counts(),
    closureReady,
    cleanupVerified: false,
  });
  for (const id of [
    "identity",
    "service-cloudscheduler.googleapis.com",
    "service-pubsub.googleapis.com",
    "appengine-location",
    "before-list-jobs",
    "before-list-topics",
    "before-topic",
  ]) {
    const answer = await take(id);
    if (id === "appengine-location") continue; // Capture-only; never initialize an application.
    if (!answer || answer.bodyUnknown) return summary(false);
    if (id === "identity") {
      if (
        answer.status !== 200 ||
        answer.json?.name !== "projects/" + PROJECT + "/releases/cloud.firestore" ||
        typeof answer.json?.rulesetName !== "string" ||
        !new RegExp("^projects/" + PROJECT + "/rulesets/[A-Za-z0-9_-]+$").test(
          answer.json.rulesetName,
        )
      )
        return summary(false);
    } else if (id.startsWith("service-")) {
      if (answer.status !== 200 || answer.json?.state !== "ENABLED") return summary(false);
    } else if (id === "before-topic") {
      if (!recordedTopicAbsent(answer, own)) return summary(false);
    } else if (!recordedEmptyList(answer)) return summary(false);
  }
  const createdTopic = await take("create-topic");
  let identityContradiction = !!(
    createdTopic &&
    !createdTopic.bodyUnknown &&
    createdTopic.status >= 200 &&
    createdTopic.status < 300 &&
    !recordedTopicOwned(createdTopic, own)
  );
  const topicIntent =
    !identityContradiction && !(createdTopic?.status >= 400 && createdTopic.status < 500);
  let extraRequestsLeft = 3;
  let topicRead = await take("read-topic");
  let topicPoll = 0;
  if (topicIntent && !identityContradiction && !recordedTopicOwned(createdTopic, own)) {
    while (
      extraRequestsLeft > 0 &&
      (!topicRead || topicRead.bodyUnknown || recordedTopicAbsent(topicRead, own))
    ) {
      await sleep(10000);
      extraRequestsLeft--;
      topicPoll++;
      topicRead = await capture({
        ...requests.get("read-topic"),
        id: "read-topic-poll-" + topicPoll,
      });
    }
  }
  let stopped = !recordedTopicOwned(createdTopic, own) || !recordedTopicOwned(topicRead, own);
  const attemptedCases = new Set(),
    intents = new Set(),
    eligible = new Set(),
    absentBeforeDelete = new Set();
  for (const { id } of CALENDAR_CASES) {
    if (stopped) break;
    if (!recordedAbsent(await take(id + "-before"))) break;
    attemptedCases.add(id);
    intents.add(id); // The recorded preflight was absent; retain ambiguous create intent.
    const answer = await take(id + "-create");
    if (answer?.status >= 400 && answer.status < 500) {
      intents.delete(id); // A definitive client refusal never owns a raced resource.
      stopped = answer.status !== 400 || answer.bodyUnknown;
      continue;
    }
    const target = { job: own.jobs[id], topic: own.topic };
    if (!recordedEnabled(answer, target)) {
      stopped = true;
      if (answer && !answer.bodyUnknown && answer.status >= 200 && answer.status < 300) {
        identityContradiction = true;
        intents.delete(id);
        continue; // A contradictory complete success body is not an owned-create proof.
      }
      // Prove identity before containment; this read shares the bounded extra-request budget.
      extraRequestsLeft--;
      const ownedRead = await capture({
        ...requests.get(id + "-read-paused"),
        id: id + "-read-before-pause",
      });
      if (recordedPaused(ownedRead, target)) {
        eligible.add(id);
        continue;
      }
      if (recordedAbsent(ownedRead)) {
        absentBeforeDelete.add(id);
        continue;
      }
      if (!recordedEnabled(ownedRead, target)) continue;
    }
    const pause = await take(id + "-pause");
    if (!recordedPaused(pause, target)) stopped = true;
    const paused = await take(id + "-read-paused");
    if (recordedPaused(paused, { job: own.jobs[id], topic: own.topic })) eligible.add(id);
    else if (recordedAbsent(paused)) absentBeforeDelete.add(id);
    else {
      if (recordedEnabled(paused, target)) eligible.add(id);
      stopped = true;
    }
  }
  if (intents.size) await sleep(60000); // Every pause attempt has completed before this wait.
  let jobsAbsent = true;
  for (const id of attemptedCases) {
    let settled = absentBeforeDelete.has(id) || !intents.has(id);
    if (eligible.has(id)) {
      let attempt = 0;
      while (true) {
        const spec = requests.get(id + "-delete");
        const answer = await capture({
          ...spec,
          id: attempt ? id + "-delete-retry-" + attempt : spec.id,
        });
        if (answer && !answer.bodyUnknown && answer.status >= 200 && answer.status < 300) {
          settled = true;
          break;
        }
        if (!recordedMutationBusy(answer, { job: own.jobs[id] }) || extraRequestsLeft === 0) break;
        extraRequestsLeft--;
        attempt++;
        await sleep(60000);
      }
    }
    const after = await take(id + "-read-deleted");
    jobsAbsent = jobsAbsent && settled && recordedAbsent(after);
  }
  const jobsList = await take("final-list-jobs");
  const jobProof =
    jobsAbsent && recordedEmptyList(jobsList) && unsettledCreates.size === 0 && !unknownDelete;
  let topicSettled = !topicIntent && !identityContradiction;
  if (topicIntent && recordedTopicOwned(topicRead, own) && jobProof) {
    const answer = await take("delete-topic");
    topicSettled = !!(answer && !answer.bodyUnknown && answer.status >= 200 && answer.status < 300);
  }
  const topicAfter = await take("read-deleted-topic");
  const topicsList = await take("final-list-topics");
  return summary(
    !identityContradiction &&
      unsettledCreates.size === 0 &&
      !unknownDelete &&
      topicSettled &&
      jobProof &&
      recordedTopicAbsent(topicAfter, own) &&
      recordedEmptyList(topicsList),
  );
}
