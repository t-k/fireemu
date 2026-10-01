// Concrete job-only recovery. Imports never acquire credentials or send requests.
import { createRequestCapture, ownedResources, PROJECT } from "./shape.mjs";

export const RECOVERY_MAX_REQUESTS = 8;

export function recordedPaused(result, owned) {
  return (
    result?.status === 200 &&
    !result.bodyUnknown &&
    result.json?.name === owned.job &&
    result.json?.state === "PAUSED" &&
    result.json?.pubsubTarget?.topicName === owned.topic
  );
}

export function recordedAbsent(result) {
  return (
    result?.status === 404 &&
    !result.bodyUnknown &&
    result.json?.error?.code === 404 &&
    result.json.error.status === "NOT_FOUND" &&
    result.json.error.message === "Job not found."
  );
}

export function recordedMutationBusy(result, owned) {
  const error = result?.json?.error;
  return (
    result?.status === 409 &&
    !result.bodyUnknown &&
    error?.code === 409 &&
    error.status === "ABORTED" &&
    error.message === "sync mutate calls cannot be queued" &&
    Array.isArray(error.details) &&
    error.details.length === 1 &&
    error.details[0]?.["@type"] === "type.googleapis.com/google.rpc.ResourceInfo" &&
    error.details[0].resourceName === owned.job
  );
}

export function recordedCleanList(result) {
  const body = result?.json;
  if (
    result?.status !== 200 ||
    result.bodyUnknown ||
    !body ||
    typeof body !== "object" ||
    Array.isArray(body) ||
    Object.hasOwn(body, "nextPageToken")
  )
    return false;
  if (!Object.hasOwn(body, "jobs")) return Object.keys(body).length === 0;
  return (
    Array.isArray(body.jobs) &&
    body.jobs.every(
      (job) => typeof job?.name === "string" && !job.name.includes("fe-scheduled-shape-"),
    )
  );
}

export async function collectRecovery({
  originalRunId,
  runId,
  accessToken,
  save,
  send,
  clock = Date.now,
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
}) {
  const owned = ownedResources(originalRunId);
  ownedResources(runId);
  if (runId === originalRunId) throw new Error("recovery needs a distinct attempt ID");
  const { capture, counts } = createRequestCapture({
    accessToken,
    save,
    send,
    clock,
    maxRequests: RECOVERY_MAX_REQUESTS,
  });
  const jobUrl = "https://cloudscheduler.googleapis.com/v1/" + owned.job;
  const result = (closureReady) => ({
    outcome: "recovery-needs-review",
    ...counts(),
    closureReady,
    cleanupVerified: false,
  });
  const before = await capture({ id: "read-job-before", method: "GET", url: jobUrl });
  if (!recordedAbsent(before) && !recordedPaused(before, owned)) return result(false);

  let writesSettled = recordedAbsent(before);
  if (!writesSettled) {
    for (let attempt = 1; attempt <= 4; attempt++) {
      await sleep(60000);
      const answer = await capture({
        id: "delete-job-" + attempt,
        method: "DELETE",
        url: jobUrl,
      });
      // DELETE has no recorded success body yet; 2xx is captured without a body judge.
      if (answer && !answer.bodyUnknown && answer.status >= 200 && answer.status < 300) {
        writesSettled = true;
        break;
      }
      if (!recordedMutationBusy(answer, owned)) break;
    }
  }
  // Read-only postflight runs even after uncertain or exhausted DELETE attempts.
  const after = await capture({ id: "read-job-after", method: "GET", url: jobUrl });
  const list = await capture({
    id: "list-jobs",
    method: "GET",
    url:
      "https://cloudscheduler.googleapis.com/v1/projects/" +
      PROJECT +
      "/locations/us-central1/jobs?pageSize=500",
  });
  return result(writesSettled && recordedAbsent(after) && recordedCleanList(list));
}
