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

export function calendarRecoveryRequests(originalRunId, recoveryScope = "jobs-and-topic") {
  if (!["jobs-and-topic", "topic-only"].includes(recoveryScope))
    throw new Error("invalid recovery scope");
  const own = calendarResources(originalRunId);
  const scheduler = "https://cloudscheduler.googleapis.com/v1/",
    pubsub = "https://pubsub.googleapis.com/v1/";
  const get = (id, url) => ({ id, method: "GET", url });
  if (recoveryScope === "topic-only")
    return [
      get(
        "before-list-jobs",
        scheduler + "projects/" + PROJECT + "/locations/us-central1/jobs?pageSize=500",
      ),
      get("read-topic-before", pubsub + own.topic),
      { id: "delete-topic", method: "DELETE", url: pubsub + own.topic, timeoutMs: 30000 },
      get("read-topic-after", pubsub + own.topic),
      ...Array.from({ length: 3 }, (_, index) =>
        get("read-topic-poll-" + (index + 1), pubsub + own.topic),
      ),
      get(
        "final-list-jobs",
        scheduler + "projects/" + PROJECT + "/locations/us-central1/jobs?pageSize=500",
      ),
      get("final-list-topics", pubsub + "projects/" + PROJECT + "/topics?pageSize=1000"),
    ];
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
  recoveryScope = "jobs-and-topic",
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
    calendarRecoveryRequests(originalRunId, recoveryScope).map((request) => [request.id, request]),
  );
  const { capture, counts } = createRequestCapture({
    accessToken,
    save,
    send,
    clock,
    maxRequests: recoveryScope === "topic-only" ? 9 : CALENDAR_RECOVERY_MAX_REQUESTS,
  });
  const take = (id) => capture(requests.get(id));
  if (recoveryScope === "topic-only") {
    const summary = (closureReady) => ({
      outcome: "calendar-recovery-needs-review",
      ...counts(),
      cleanupVerified: false,
      closureReady,
    });
    if (!recordedEmptyList(await take("before-list-jobs"))) return summary(false);
    let polls = 0;
    const pollTopic = async (answer, afterDelete) => {
      while (
        polls < 3 &&
        (!answer ||
          answer.bodyUnknown ||
          (afterDelete ? recordedTopicOwned(answer, own) : recordedTopicAbsent(answer, own)))
      ) {
        await sleep(10000);
        polls++;
        answer = await take("read-topic-poll-" + polls);
      }
      return answer;
    };
    const before = await pollTopic(await take("read-topic-before"), false);
    let topicSettled = false;
    if (recordedTopicOwned(before, own)) {
      const answer = await take("delete-topic");
      // A complete404 is only a candidate; separate absence and list proofs are mandatory.
      topicSettled = recordedEmptyList(answer) || (answer?.status === 404 && !answer.bodyUnknown);
    }
    const after = await pollTopic(await take("read-topic-after"), true);
    const jobs = await take("final-list-jobs"),
      topics = await take("final-list-topics");
    return summary(
      topicSettled &&
        recordedTopicAbsent(after, own) &&
        recordedEmptyList(jobs) &&
        recordedEmptyList(topics),
    );
  }
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
