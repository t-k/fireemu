// Coordinator-only calendar recovery. Import never obtains credentials or sends requests.
import { createRequestCapture, PROJECT } from "./shape.mjs";
import { recordedAbsent, recordedPaused, recordedMutationBusy } from "./recovery.mjs";
import {
  CALENDAR_CASES,
  calendarResources,
  recordedEmptyList,
  recordedTopicAbsent,
  recordedTopicOwned,
  recordedEnabled,
} from "./calendar.mjs";

export const CALENDAR_RECOVERY_MAX_REQUESTS = 64;
export const CALENDAR_RECOVERY_DELETE_ATTEMPTS = 3;

export function calendarRecoveryRequests(originalRunId) {
  const own = calendarResources(originalRunId);
  const scheduler = "https://cloudscheduler.googleapis.com/v1/",
    pubsub = "https://pubsub.googleapis.com/v1/";
  const get = (id, url) => ({ id, method: "GET", url });
  return [
    get("read-topic-before", pubsub + own.topic),
    ...CALENDAR_CASES.flatMap(({ id }) => [
      get(id + "-before", scheduler + own.jobs[id]),
      { id: id + "-pause", method: "POST", url: scheduler + own.jobs[id] + ":pause", json: {} },
      get(id + "-read-paused", scheduler + own.jobs[id]),
      ...Array.from({ length: CALENDAR_RECOVERY_DELETE_ATTEMPTS }, (_, index) => ({
        id: id + "-delete-" + (index + 1),
        method: "DELETE",
        url: scheduler + own.jobs[id],
      })),
      get(id + "-after", scheduler + own.jobs[id]),
    ]),
    get(
      "final-list-jobs",
      scheduler + "projects/" + PROJECT + "/locations/us-central1/jobs?pageSize=500",
    ),
    { id: "delete-topic", method: "DELETE", url: pubsub + own.topic },
    get("read-topic-after", pubsub + own.topic),
    get("final-list-topics", pubsub + "projects/" + PROJECT + "/topics?pageSize=1000"),
  ];
}

export async function collectCalendarRecovery({
  originalRunId,
  runId,
  accessToken,
  save,
  send,
  clock = Date.now,
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
}) {
  const own = calendarResources(originalRunId);
  calendarResources(runId);
  if (runId === originalRunId) throw new Error("recovery needs a distinct attempt ID");
  const requests = new Map(
    calendarRecoveryRequests(originalRunId).map((request) => [request.id, request]),
  );
  const { capture, counts } = createRequestCapture({
    accessToken,
    save,
    send,
    clock,
    maxRequests: CALENDAR_RECOVERY_MAX_REQUESTS,
  });
  const take = (id) => capture(requests.get(id));
  const topicBefore = await take("read-topic-before"),
    eligible = new Set(),
    absent = new Set();
  for (const { id } of CALENDAR_CASES) {
    const before = await take(id + "-before"),
      target = { job: own.jobs[id], topic: own.topic };
    if (recordedAbsent(before)) absent.add(id);
    else if (recordedPaused(before, target)) eligible.add(id);
    else if (recordedEnabled(before, target)) {
      await take(id + "-pause");
      if (recordedPaused(await take(id + "-read-paused"), target)) eligible.add(id);
    }
  }
  if (eligible.size) await sleep(60000); // All containment pause attempts precede settlement.
  let jobsAbsent = true;
  for (const { id } of CALENDAR_CASES) {
    let settled = absent.has(id);
    if (eligible.has(id)) {
      for (let attempt = 1; attempt <= CALENDAR_RECOVERY_DELETE_ATTEMPTS; attempt++) {
        if (attempt > 1) await sleep(60000);
        const answer = await take(id + "-delete-" + attempt);
        if (answer && !answer.bodyUnknown && answer.status >= 200 && answer.status < 300) {
          settled = true; // Captured acknowledgment is not independently an absence proof.
          break;
        }
        if (!recordedMutationBusy(answer, { job: own.jobs[id] })) break;
      }
    }
    const after = await take(id + "-after");
    jobsAbsent = jobsAbsent && settled && recordedAbsent(after);
  }
  const jobProof = recordedEmptyList(await take("final-list-jobs")) && jobsAbsent;
  let topicSettled = recordedTopicAbsent(topicBefore, own);
  if (jobProof && recordedTopicOwned(topicBefore, own)) {
    const answer = await take("delete-topic");
    topicSettled = !!(answer && !answer.bodyUnknown && answer.status >= 200 && answer.status < 300);
  }
  const topicAfter = await take("read-topic-after"),
    topics = await take("final-list-topics");
  return {
    outcome: "calendar-recovery-needs-review",
    ...counts(),
    cleanupVerified: false,
    closureReady:
      jobProof && topicSettled && recordedTopicAbsent(topicAfter, own) && recordedEmptyList(topics),
  };
}
