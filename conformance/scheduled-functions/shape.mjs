// Observation-only bootstrap. Imports never acquire credentials or send requests.
export const PROJECT = "fireemu-oracle-sbx";
export const MAX_REQUESTS = 64;
export const SERVICES = [
  "cloudscheduler.googleapis.com",
  "pubsub.googleapis.com",
  "appengine.googleapis.com",
];
const MAX_BYTES = 1024 * 1024;

export function ownedResources(runId) {
  if (!/^[a-f0-9]{16}$/.test(runId ?? "")) throw new Error("invalid run ID");
  const prefix = `fe-scheduled-shape-${runId}`;
  return {
    job: `projects/${PROJECT}/locations/us-central1/jobs/${prefix}`,
    topic: `projects/${PROJECT}/topics/${prefix}`,
    subscription: `projects/${PROJECT}/subscriptions/${prefix}`,
  };
}

export function shapeRequests({ runId, projectNumber, now }) {
  const owned = ownedResources(runId);
  if (!/^\d{12,13}$/.test(projectNumber ?? "")) throw new Error("invalid project number");
  if (
    !Number.isFinite(now) ||
    now < Date.parse("2026-09-30T00:00:00Z") ||
    now >= Date.parse("2026-10-08T00:00:00Z")
  ) {
    throw new Error("shape packet expired or outside its bootstrap window");
  }
  const resourceUrl = (kind) =>
    `https://${kind === "job" ? "cloudscheduler" : "pubsub"}.googleapis.com/v1/${owned[kind]}`;
  const list = (kind, phase) => ({
    id: `${phase}-list-${kind}`,
    method: "GET",
    cleanup: phase === "final",
    url:
      kind === "jobs"
        ? `https://cloudscheduler.googleapis.com/v1/projects/${PROJECT}/locations/us-central1/jobs?pageSize=500`
        : `https://pubsub.googleapis.com/v1/projects/${PROJECT}/${kind}?pageSize=1000`,
  });
  const serviceRead = (phase) =>
    SERVICES.map((service) => ({
      id: `service-${phase}-${service}`,
      method: "GET",
      serviceReady: phase === "after",
      url: `https://serviceusage.googleapis.com/v1/projects/${projectNumber}/services/${service}`,
    }));
  return [
    {
      id: "identity",
      method: "GET",
      url: `https://firebaserules.googleapis.com/v1/projects/${PROJECT}/releases/cloud.firestore`,
    },
    ...serviceRead("before"),
    {
      id: "enable-apis",
      method: "POST",
      url: `https://serviceusage.googleapis.com/v1/projects/${projectNumber}/services:batchEnable`,
      json: { serviceIds: SERVICES },
    },
    ...serviceRead("after"),
    {
      id: "appengine-location",
      method: "GET",
      observationOnly: true,
      url: `https://appengine.googleapis.com/v1/apps/${PROJECT}`,
    },
    ...["job", "topic", "subscription"].map((kind) => ({
      id: `before-${kind}`,
      method: "GET",
      absence: true,
      url: resourceUrl(kind),
    })),
    ...["jobs", "topics", "subscriptions"].map((kind) => list(kind, "before")),
    { id: "create-topic", method: "PUT", url: resourceUrl("topic"), creates: "topic", json: {} },
    { id: "read-topic", method: "GET", url: resourceUrl("topic") },
    {
      id: "create-subscription",
      method: "PUT",
      url: resourceUrl("subscription"),
      creates: "subscription",
      json: { topic: owned.topic, ackDeadlineSeconds: 10 },
    },
    { id: "read-subscription", method: "GET", url: resourceUrl("subscription") },
    {
      id: "create-job",
      method: "POST",
      url: resourceUrl("job").slice(0, resourceUrl("job").lastIndexOf("/")),
      creates: "job",
      json: {
        name: owned.job,
        schedule: "0 0 1 4 *",
        timeZone: "UTC",
        pubsubTarget: {
          topicName: owned.topic,
          data: Buffer.from("shape-only").toString("base64"),
        },
      },
    },
    {
      id: "pause-job",
      method: "POST",
      url: `${resourceUrl("job")}:pause`,
      json: {},
      cleanup: true,
      owned: "job",
    },
    { id: "read-paused-job", method: "GET", url: resourceUrl("job"), cleanup: true, owned: "job" },
    ...["job", "subscription", "topic"].flatMap((kind) => [
      {
        id: `delete-${kind}`,
        method: "DELETE",
        url: resourceUrl(kind),
        cleanup: true,
        owned: kind,
      },
      {
        id: `read-deleted-${kind}`,
        method: "GET",
        url: resourceUrl(kind),
        cleanup: true,
        owned: kind,
      },
    ]),
    ...["jobs", "topics", "subscriptions"].map((kind) => list(kind, "final")),
  ];
}

async function responseBytes(response) {
  const reader = response.body?.getReader();
  if (!reader) return Buffer.alloc(0);
  const chunks = [];
  let size = 0;
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_BYTES) throw new Error("response byte bound");
      chunks.push(Buffer.from(value));
    }
    return Buffer.concat(chunks, size);
  } finally {
    await reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}

export function createRequestCapture({
  accessToken,
  save,
  send = (request) => fetch(request.url, request),
  clock = Date.now,
  maxRequests = MAX_REQUESTS,
}) {
  if (typeof accessToken !== "string" || !accessToken || /[\r\n]/.test(accessToken))
    throw new Error("coordinator token required");
  if (typeof save !== "function") throw new Error("private persistence required");
  if (!Number.isSafeInteger(maxRequests) || maxRequests < 1 || maxRequests > MAX_REQUESTS)
    throw new Error("invalid request cap");
  let attempted = 0,
    completed = 0;
  async function capture(spec) {
    if (attempted >= maxRequests) throw new Error("request cap exceeded");
    const dispatchAt = new Date(clock()).toISOString();
    try {
      await save({
        id: spec.id,
        state: "before-send",
        method: spec.method,
        url: spec.url,
        ...(spec.json ? { json: spec.json } : {}),
        dispatchAt,
      });
    } catch {
      throw new Error("private persistence failed before dispatch");
    }
    attempted++;
    let response, bytes;
    try {
      response = await send({
        ...spec,
        redirect: "manual",
        signal: AbortSignal.timeout(10000),
        headers: {
          authorization: `Bearer ${accessToken}`,
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
    try {
      bytes = await responseBytes(response);
    } catch {
      await save({
        id: spec.id,
        state: "body-unknown",
        status: response.status,
        responseAt: new Date(clock()).toISOString(),
      });
      return { status: response.status, json: null, bodyUnknown: true };
    }
    const body = bytes.toString("utf8");
    // No credentials are expected in these bodies; never persist a reflected bearer.
    if (body.includes(accessToken))
      throw new Error("response reflected a credential; capture stopped");
    await save({
      id: spec.id,
      state: "response-persisted",
      status: response.status,
      contentType: response.headers.get("content-type"),
      dispatchAt,
      responseAt: new Date(clock()).toISOString(),
      bodyBase64: bytes.toString("base64"),
      bodyBytes: bytes.length,
    });
    completed++;
    let json;
    try {
      json = JSON.parse(body);
    } catch {
      json = null;
    }
    return { status: response.status, json };
  }
  return {
    capture,
    counts: () => ({ attempted, completed, unknown: attempted - completed }),
  };
}

export async function collectShape({
  runId,
  projectNumber,
  accessToken,
  save,
  send = (request) => fetch(request.url, request),
  clock = Date.now,
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  now = clock(),
}) {
  const requests = shapeRequests({ runId, projectNumber, now });
  const { capture, counts } = createRequestCapture({ accessToken, save, send, clock });
  const intents = new Set();
  let stopped = false;
  for (const spec of requests) {
    if (stopped && !spec.cleanup) continue;
    if (spec.owned && !intents.has(spec.owned)) continue;
    if (stopped && spec.id.startsWith("final-list-") && !intents.size) continue;
    if (spec.id === "appengine-location") await sleep(90000);
    // Native Scheduler can reject DELETE while the preceding pause mutation settles.
    if (spec.id === "delete-job") await sleep(60000);
    if (spec.creates) intents.add(spec.creates);
    const result = await capture(spec);
    // A definitive client refusal does not establish ownership of a conflicting resource.
    if (spec.creates && result?.status >= 400 && result.status < 500) intents.delete(spec.creates);
    if (spec.cleanup) continue;
    if (spec.observationOnly) continue;
    if (!result || result.bodyUnknown || result.status < 200 || result.status >= 300) {
      if (!(spec.absence && result?.status === 404)) stopped = true;
      continue;
    }
    if (spec.absence) stopped = true;
    if (
      spec.id === "identity" &&
      (result.status !== 200 ||
        result.json?.name !== `projects/${PROJECT}/releases/cloud.firestore` ||
        typeof result.json?.rulesetName !== "string" ||
        !new RegExp(`^projects/${PROJECT}/rulesets/[A-Za-z0-9_-]+$`).test(result.json.rulesetName))
    )
      stopped = true;
    if (spec.serviceReady && result.json?.state !== "ENABLED") stopped = true;
    if (spec.id === "enable-apis") {
      let operation = result;
      if (!/^operations\/[A-Za-z0-9._-]+$/.test(operation.json?.name ?? "")) {
        stopped = true;
        continue;
      }
      const name = operation.json.name;
      for (let index = 1; operation.json?.done !== true && index <= 15; index++) {
        await sleep(8000);
        operation = await capture({
          id: `enable-poll-${index}`,
          method: "GET",
          url: `https://serviceusage.googleapis.com/v1/${name}`,
        });
        if (!operation || operation.status !== 200) break;
      }
      if (operation?.json?.done !== true || operation.json.error) stopped = true;
    }
  }
  return {
    outcome: "shape-needs-review",
    ...counts(),
    ownedIntents: [...intents],
    cleanupVerified: false,
  };
}
