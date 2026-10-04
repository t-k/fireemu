// Calendar packet v6: the case table, the judges and the collector for the Cloud Scheduler
// calendar observations on the disposable sandbox project. Importing this module acquires no
// credentials and sends nothing; a collector run needs an injected `send` and a token.
//
// Cleanup rule (the one the v5 recorder only half followed): every name a run creates is first
// written to the durable journal as `issued`. A name is deleted only if the run's own create of
// that name was answered 2xx, or if an unknown answer was settled by a direct GET of that name
// that showed the run's own job. A definitive refusal or an absence never earns a DELETE, and a
// listing alone never settles anything.
import { readFileSync } from "node:fs";

export const PROJECT = "fireemu-oracle-sbx";
export const REGION = "us-central1";
export const MAX_REQUESTS = 240;
export const MAX_JOBS = 50;
const MAX_BODY_BYTES = 1024 * 1024;
const RUN_ID = /^[a-f0-9]{16}$/;
const SCHEDULER = "https://cloudscheduler.googleapis.com/v1/";
const PUBSUB = "https://pubsub.googleapis.com/v1/";

export const CASES = Object.freeze(
  JSON.parse(readFileSync(new URL("./calendar-v6-cases.json", import.meta.url), "utf8")).map(
    Object.freeze,
  ),
);

export function resources(runId, cases = CASES) {
  if (!RUN_ID.test(runId ?? "")) throw new Error("invalid run ID");
  if (cases.length > MAX_JOBS) throw new Error("too many jobs");
  const prefix = "fe-cal6-" + runId;
  const ids = new Set();
  for (const { id } of cases) {
    if (!/^[a-z]{2}\d{2}$/.test(id) || ids.has(id)) throw new Error("invalid case ID " + id);
    ids.add(id);
  }
  return {
    prefix,
    topic: "projects/" + PROJECT + "/topics/" + prefix,
    jobs: Object.fromEntries(
      cases.map(({ id }) => [
        id,
        "projects/" + PROJECT + "/locations/" + REGION + "/jobs/" + prefix + "-" + id,
      ]),
    ),
  };
}

export function createBody(c, own) {
  return {
    name: own.jobs[c.id],
    schedule: c.schedule,
    timeZone: c.timeZone,
    pubsubTarget: { topicName: own.topic, data: Buffer.from("calendar-v6").toString("base64") },
    ...(c.retryConfig ? { retryConfig: c.retryConfig } : {}),
    ...(c.attemptDeadline ? { attemptDeadline: c.attemptDeadline } : {}),
  };
}

// ---- judges: pure functions of a captured answer ------------------------------------------
// An answer is `{status, json, rawBytes, bodyBytes, bodyUnknown}`. Layout is judged on the
// persisted raw bytes: a re-serialised body is an unrecorded shape and proves nothing.

const encoded = (json) => Buffer.from(JSON.stringify(json, null, 2) + "\n");
export const layoutOk = (a) =>
  !!a &&
  !a.bodyUnknown &&
  Buffer.isBuffer(a.rawBytes) &&
  a.bodyBytes === a.rawBytes.length &&
  a.json !== null &&
  typeof a.json === "object" &&
  a.rawBytes.equals(encoded(a.json));
const complete = (a, status) => layoutOk(a) && a.status === status;
const sameJson = (a, expected) => layoutOk(a) && a.rawBytes.equals(encoded(expected));

export const REFUSED_400 = Object.freeze({
  error: {
    code: 400,
    message: "The provided schedule or timezone are invalid.",
    status: "INVALID_ARGUMENT",
  },
});
const jobMessage = "Job not found.";

export function emptyList(a) {
  return complete(a, 200) && a.rawBytes.equals(Buffer.from("{}\n"));
}
export function deleted(a) {
  return complete(a, 200) && a.rawBytes.equals(Buffer.from("{}\n"));
}
export function topicOwned(a, own) {
  return sameJson(a, { name: own.topic }) && a.status === 200;
}
export function topicAbsent(a, own) {
  return (
    a?.status === 404 &&
    sameJson(a, {
      error: {
        code: 404,
        message: "Resource not found (resource=" + own.prefix + ").",
        status: "NOT_FOUND",
      },
    })
  );
}
export function jobAbsentPlain(a) {
  return (
    a?.status === 404 &&
    sameJson(a, { error: { code: 404, message: jobMessage, status: "NOT_FOUND" } })
  );
}
export function jobAbsentDetailed(a, name) {
  return (
    a?.status === 404 &&
    sameJson(a, {
      error: {
        code: 404,
        message: "Resource '" + name + "' was not found",
        status: "NOT_FOUND",
        details: [{ "@type": "type.googleapis.com/google.rpc.ResourceInfo", resourceName: name }],
      },
    })
  );
}
export const jobAbsent = (a, name) => jobAbsentPlain(a) || jobAbsentDetailed(a, name);

/** The answer shows this run's own job in one of the given states (identity only). */
export function ownJob(a, c, own, states = ["ENABLED", "PAUSED"]) {
  const j = a?.json;
  return (
    a?.status === 200 &&
    !a.bodyUnknown &&
    j?.name === own.jobs[c.id] &&
    j.pubsubTarget?.topicName === own.topic &&
    states.includes(j.state)
  );
}
/** A recorded accepted create: the own job, ENABLED, in the recorded layout. */
export function createAccepted(c, a, own) {
  return layoutOk(a) && ownJob(a, c, own, ["ENABLED"]);
}
export function paused(c, a, own) {
  return layoutOk(a) && ownJob(a, c, own, ["PAUSED"]) && !("scheduleTime" in a.json);
}
export function createRefusedExact(a) {
  return sameJson(a, REFUSED_400) && a.status === 400 && a.bodyBytes === 136;
}
/** A complete 4xx answer with an error body that is not the recorded 400: new data, no job. */
export function createRefusedOther(a) {
  return (
    !!a &&
    !a.bodyUnknown &&
    a.status >= 400 &&
    a.status < 500 &&
    a.status !== 409 &&
    a.status !== 429 &&
    layoutOk(a) &&
    typeof a.json?.error?.message === "string" &&
    !createRefusedExact(a)
  );
}
export function mutationBusy(a, name) {
  const error = a?.json?.error;
  return (
    a?.status === 409 &&
    !a.bodyUnknown &&
    error?.code === 409 &&
    error.status === "ABORTED" &&
    error.message === "sync mutate calls cannot be queued" &&
    Array.isArray(error.details) &&
    error.details.length === 1 &&
    error.details[0]?.["@type"] === "type.googleapis.com/google.rpc.ResourceInfo" &&
    error.details[0].resourceName === name
  );
}
// ---- timing ---------------------------------------------------------------------------------

/** Milliseconds to wait from `now` so that a request dispatched then meets `timing`. */
export function waitFor(timing, now) {
  if (!timing) return 0;
  if (timing.kind === "before-minute-boundary") {
    let target = (Math.floor(now / 60000) + 1) * 60000 - timing.leadMs;
    if (target < now + 2000) target += 60000;
    return target - now;
  }
  if (timing.kind === "after-run") {
    const period = timing.everyMinutes * 60000;
    const next = Math.ceil((now + 5000) / period) * period;
    return next + timing.afterMs - now;
  }
  throw new Error("unknown timing " + timing.kind);
}

// ---- request allowlist and capture ----------------------------------------------------------

function allowedRequest({ method, url, json }, own, projectNumber) {
  const exact = (m, u) => method === m && url === u;
  const jobUrls = Object.values(own.jobs).map((name) => SCHEDULER + name);
  const jobsCollection = SCHEDULER + "projects/" + PROJECT + "/locations/" + REGION + "/jobs";
  return (
    exact(
      "GET",
      "https://firebaserules.googleapis.com/v1/projects/" + PROJECT + "/releases/cloud.firestore",
    ) ||
    ["cloudscheduler", "pubsub"].some((s) =>
      exact(
        "GET",
        "https://serviceusage.googleapis.com/v1/projects/" +
          projectNumber +
          "/services/" +
          s +
          ".googleapis.com",
      ),
    ) ||
    exact("GET", jobsCollection + "?pageSize=500") ||
    exact("GET", PUBSUB + "projects/" + PROJECT + "/topics?pageSize=1000") ||
    (["PUT", "GET", "DELETE"].includes(method) && url === PUBSUB + own.topic) ||
    (method === "POST" && url === jobsCollection && Object.values(own.jobs).includes(json?.name)) ||
    (["GET", "DELETE"].includes(method) && jobUrls.includes(url)) ||
    (method === "POST" && jobUrls.some((u) => url === u + ":pause"))
  );
}

async function boundedBody(response) {
  const bytes = Buffer.from(await response.arrayBuffer());
  if (bytes.length > MAX_BODY_BYTES) throw new Error("body too large");
  return bytes;
}

export function createCapture({ accessToken, save, send, clock, maxRequests, own, projectNumber }) {
  if (typeof accessToken !== "string" || !accessToken || /[\r\n]/.test(accessToken))
    throw new Error("coordinator token required");
  if (typeof save !== "function") throw new Error("private persistence required");
  if (!Number.isSafeInteger(maxRequests) || maxRequests < 1 || maxRequests > MAX_REQUESTS)
    throw new Error("invalid request cap");
  if (!/^\d{12,13}$/.test(projectNumber ?? "")) throw new Error("invalid project number");
  let attempted = 0,
    completed = 0;
  const longCreate = (spec) =>
    (["PUT", "DELETE"].includes(spec.method) && spec.url === PUBSUB + own.topic) ||
    (spec.method === "POST" && !spec.url.endsWith(":pause"));
  async function capture(spec) {
    if (!allowedRequest(spec, own, projectNumber))
      throw new Error("request not allowed: " + spec.id);
    if (attempted >= maxRequests) throw new Error("request cap exceeded");
    const timeoutMs = longCreate(spec) ? 30000 : 10000;
    const dispatchAt = new Date(clock()).toISOString();
    try {
      await save({
        id: spec.id,
        state: "before-send",
        method: spec.method,
        url: spec.url,
        ...(spec.json ? { json: spec.json } : {}),
        dispatchAt,
        timeoutMs,
      });
    } catch {
      throw new Error("private persistence failed before dispatch");
    }
    attempted++;
    let response;
    try {
      response = await send({
        method: spec.method,
        url: spec.url,
        redirect: "manual",
        signal: AbortSignal.timeout(timeoutMs),
        headers: {
          authorization: "Bearer " + accessToken,
          "x-goog-user-project": PROJECT,
          "content-type": "application/json",
        },
        ...(spec.json ? { body: JSON.stringify(spec.json) } : {}),
      });
    } catch {
      await save({
        id: spec.id,
        state: "transport-unknown",
        responseAt: new Date(clock()).toISOString(),
      });
      return null;
    }
    await save({
      id: spec.id,
      state: "response-headers",
      status: response.status,
      responseAt: new Date(clock()).toISOString(),
    });
    let rawBytes;
    try {
      rawBytes = await boundedBody(response);
    } catch {
      await save({
        id: spec.id,
        state: "body-unknown",
        status: response.status,
        responseAt: new Date(clock()).toISOString(),
      });
      return { status: response.status, json: null, bodyUnknown: true };
    }
    if (rawBytes.toString("utf8").includes(accessToken))
      throw new Error("response reflected a credential; capture stopped");
    const responseAt = new Date(clock()).toISOString();
    await save({
      id: spec.id,
      state: "response-persisted",
      status: response.status,
      contentType: response.headers.get("content-type"),
      dispatchAt,
      responseAt,
      bodyBase64: rawBytes.toString("base64"),
      bodyBytes: rawBytes.length,
    });
    completed++;
    let json;
    try {
      json = JSON.parse(rawBytes.toString("utf8"));
    } catch {
      json = null;
    }
    return {
      status: response.status,
      json,
      rawBytes,
      bodyBytes: rawBytes.length,
      dispatchAt,
      responseAt,
    };
  }
  return { capture, counts: () => ({ attempted, completed, unknown: attempted - completed }) };
}

// ---- the collector --------------------------------------------------------------------------

export async function collect({
  runId,
  projectNumber,
  accessToken,
  save,
  send,
  clock = Date.now,
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  cases = CASES,
  budget = MAX_REQUESTS,
}) {
  const own = resources(runId, cases);
  const { capture, counts } = createCapture({
    accessToken,
    save,
    send,
    clock,
    maxRequests: budget,
    own,
    projectNumber,
  });
  let topicIssued = false;
  const jobUrl = (c) => SCHEDULER + own.jobs[c.id];
  const records = new Map(
    cases.map((c) => [c.id, { id: c.id, issued: false, outcome: "not-attempted" }]),
  );
  const topicUrl = PUBSUB + own.topic;
  let extra = 12; // bounded settlement reads, pause checks and DELETE retries
  const summary = (stage, closureReady) => {
    const known = counts();
    const all = [...records.values()];
    return {
      outcome: "calendar-v6-needs-review",
      stage,
      ...known,
      closureReady:
        closureReady &&
        known.unknown === 0 &&
        all.every((r) => !r.issued || r.settled === true) &&
        all.every((r) => !["unknown-unsettled", "identity-contradiction"].includes(r.outcome)),
      cleanupVerified: false,
      topicIssued,
      cases: all,
    };
  };

  // Preflight: read-only.
  const identity = await capture({
    id: "identity",
    method: "GET",
    url:
      "https://firebaserules.googleapis.com/v1/projects/" + PROJECT + "/releases/cloud.firestore",
  });
  if (
    identity?.status !== 200 ||
    identity.json?.name !== "projects/" + PROJECT + "/releases/cloud.firestore" ||
    !new RegExp("^projects/" + PROJECT + "/rulesets/[A-Za-z0-9_-]+$").test(
      identity.json?.rulesetName ?? "",
    )
  )
    return summary("preflight", false);
  for (const service of ["cloudscheduler", "pubsub"]) {
    const answer = await capture({
      id: "service-" + service,
      method: "GET",
      url:
        "https://serviceusage.googleapis.com/v1/projects/" +
        projectNumber +
        "/services/" +
        service +
        ".googleapis.com",
    });
    if (answer?.status !== 200 || answer.json?.state !== "ENABLED")
      return summary("preflight", false);
  }
  const beforeJobs = await capture({
    id: "before-list-jobs",
    method: "GET",
    url: SCHEDULER + "projects/" + PROJECT + "/locations/" + REGION + "/jobs?pageSize=500",
  });
  const beforeTopics = await capture({
    id: "before-list-topics",
    method: "GET",
    url: PUBSUB + "projects/" + PROJECT + "/topics?pageSize=1000",
  });
  if (!emptyList(beforeJobs) || !emptyList(beforeTopics)) return summary("preflight", false);
  if (!topicAbsent(await capture({ id: "before-topic", method: "GET", url: topicUrl }), own))
    return summary("preflight", false);

  // The topic.
  await save({ id: "issue-topic", state: "issued", name: own.topic });
  topicIssued = true;
  const createdTopic = await capture({
    id: "create-topic",
    method: "PUT",
    url: topicUrl,
    json: {},
  });
  let topicProven = topicOwned(createdTopic, own);
  const refusedTopic =
    createdTopic &&
    !createdTopic.bodyUnknown &&
    createdTopic.status >= 400 &&
    createdTopic.status < 500;
  if (!topicProven && !refusedTopic) {
    // Unknown or contradictory: settle by a direct GET of the name, patiently (a topic has been
    // seen to appear ten seconds late).
    for (let poll = 0; poll < 4 && !topicProven; poll++) {
      if (poll > 0) await sleep(10000);
      topicProven = topicOwned(
        await capture({
          id: "read-topic" + (poll ? "-poll-" + poll : ""),
          method: "GET",
          url: topicUrl,
        }),
        own,
      );
    }
  }
  if (!topicProven) return summary("topic", false);

  // The jobs: untimed cases first, timed ones last (each waits for its moment).
  const ordered = [...cases.filter((c) => !c.timing), ...cases.filter((c) => c.timing)];
  for (const c of ordered) {
    const rec = records.get(c.id);
    // Never start a job the remaining budget could not clean up: each created job needs a
    // DELETE and a read-back, each issued name a read-back, and the end needs a fixed reserve.
    const open = [...records.values()].filter((r) => r.issued);
    const cleanup = open.reduce((n, r) => n + (r.created && !r.deleted ? 2 : 1), 0);
    if (counts().attempted + cleanup + 4 /* this job */ + 6 /* end */ + extra > budget) {
      rec.outcome = "skipped-budget";
      continue;
    }
    await save({ id: "issue-" + c.id, state: "issued", name: own.jobs[c.id] });
    rec.issued = true;
    if (c.timing) await sleep(waitFor(c.timing, clock()));
    const answer = await capture({
      id: c.id + "-create",
      method: "POST",
      url: SCHEDULER + "projects/" + PROJECT + "/locations/" + REGION + "/jobs",
      json: createBody(c, own),
    });
    if (answer && !answer.bodyUnknown && createAccepted(c, answer, own)) {
      rec.outcome = "accepted";
      rec.created = true;
    } else if (createRefusedExact(answer)) {
      rec.outcome = "refused";
    } else if (createRefusedOther(answer)) {
      rec.outcome = "refused-other";
    } else if (answer && !answer.bodyUnknown && ownJob(answer, c, own)) {
      // Complete 200 that names the own job but not in the recorded layout: it is ours.
      rec.outcome = "accepted-unrecorded-layout";
      rec.created = true;
    } else if (answer && !answer.bodyUnknown && answer.status >= 200 && answer.status < 300) {
      rec.outcome = "identity-contradiction";
    } else {
      // Unknown or ambiguous: settle by a direct GET of this name.
      rec.outcome = "unknown-unsettled";
      for (let poll = 0; poll < 3 && extra > 0; poll++) {
        if (poll > 0) await sleep(10000);
        extra--;
        const read = await capture({
          id: c.id + "-settle-create-" + (poll + 1),
          method: "GET",
          url: jobUrl(c),
        });
        if (ownJob(read, c, own)) {
          rec.outcome = "accepted-settled-by-get";
          rec.created = true;
          break;
        }
        if (read?.status === 200 && !read.bodyUnknown) {
          rec.outcome = "identity-contradiction";
          break;
        }
      }
    }
    if (rec.created) {
      const pause = await capture({
        id: c.id + "-pause",
        method: "POST",
        url: jobUrl(c) + ":pause",
        json: {},
      });
      rec.paused = paused(c, pause, own);
      if (!rec.paused && extra > 0) {
        extra--;
        const read = await capture({
          id: c.id + "-read-after-pause",
          method: "GET",
          url: jobUrl(c),
        });
        rec.paused = paused(c, read, own);
      }
    }
  }

  // Delete only what this run created (own 2xx create, or settled by GET), after the pauses
  // have settled: a DELETE straight after a pause is answered 409.
  const eligible = [...records.values()].filter((r) => r.created);
  if (eligible.length) await sleep(60000);
  for (const rec of eligible) {
    const c = cases.find(({ id }) => id === rec.id);
    for (let attempt = 0; attempt < 4 && !rec.deleted; attempt++) {
      const answer = await capture({
        id: c.id + (attempt ? "-delete-retry-" + attempt : "-delete"),
        method: "DELETE",
        url: jobUrl(c),
      });
      if (answer && !answer.bodyUnknown && answer.status >= 200 && answer.status < 300) {
        rec.deleted = true;
        break;
      }
      if (mutationBusy(answer, own.jobs[c.id]) && extra > 0) {
        extra--;
        await sleep(60000);
        continue;
      }
      if (extra <= 0) break;
      // Unknown: settle by a direct GET of this name, never by a listing.
      extra--;
      const read = await capture({
        id: c.id + "-settle-delete-" + attempt,
        method: "GET",
        url: jobUrl(c),
      });
      if (jobAbsent(read, own.jobs[c.id])) {
        rec.deleted = true;
        rec.deletedSettledByGet = true;
      }
    }
  }
  // Read every issued name back directly.
  let allAbsent = true;
  for (const c of ordered) {
    const rec = records.get(c.id);
    if (!rec.issued) continue; // a skipped case has no name to read back
    const read = await capture({ id: c.id + "-read-deleted", method: "GET", url: jobUrl(c) });
    rec.settled = jobAbsent(read, own.jobs[c.id]) && (!rec.created || rec.deleted === true);
    allAbsent = allAbsent && rec.settled;
  }
  const finalJobs = await capture({
    id: "final-list-jobs",
    method: "GET",
    url: SCHEDULER + "projects/" + PROJECT + "/locations/" + REGION + "/jobs?pageSize=500",
  });
  const jobsClean = emptyList(finalJobs);

  // The topic goes only when every job of the run is settled.
  const unresolved = [...records.values()].some((r) =>
    ["unknown-unsettled", "identity-contradiction"].includes(r.outcome),
  );
  let topicSettled = false;
  if (allAbsent && jobsClean && !unresolved) {
    const gone = await capture({ id: "delete-topic", method: "DELETE", url: topicUrl });
    topicSettled = !!(gone && !gone.bodyUnknown && gone.status >= 200 && gone.status < 300);
  }
  const topicAfter = await capture({ id: "read-deleted-topic", method: "GET", url: topicUrl });
  const finalTopics = await capture({
    id: "final-list-topics",
    method: "GET",
    url: PUBSUB + "projects/" + PROJECT + "/topics?pageSize=1000",
  });
  const out = summary(
    "done",
    allAbsent &&
      jobsClean &&
      topicSettled &&
      topicAbsent(topicAfter, own) &&
      emptyList(finalTopics),
  );
  for (const r of out.cases) if (r.issued && r.settled !== true) out.closureReady = false;
  return out;
}
