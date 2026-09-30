// The STORAGE-OBJECT probe: seventeen requests, sent through the lean wire, that record how
// production answers the routes the recorder's judges stop on (absence reads, list bodies, the
// identity lookup, a no-credential read, the start, status, cancel and follow-up of one GCS and one
// Firebase resumable session) before a recording depends on them. No object is created: a resumable
// session that is started and cancelled holds no bytes. Nothing is judged here: every status is an
// answer and is recorded; only a request that cannot be completed (a lost connection, a timeout, a
// capture failure) stops the run. A session request whose URL the wire refuses before it sends is
// recorded as skipped. See the probe packet.
//
// Each request has the shape the recorder's own corpus declares for the same kind of step, and goes
// through `createLeanWire` like a recorder request does, so the headers (the owner token, the
// quota project) are the ones the recorder will send. `storage-object-probe.test.mjs` compares the
// two.

import { buildStage3DraftPlan } from "./stage3-plan.mjs";

export const PROBE_MAX_REQUESTS = 17;
export const PROBE_RESERVE_USD = 0.05;
export const PROBE_ESTIMATE_USD = 0.01;

const OWNER = "Bearer owner";
const JSON_TYPE = { "content-type": "application/json" };

/**
 * The ordered plan for one probe run: the identity request first, then the Storage reads. Names
 * are under the run's own prefix, which nothing has written, so every object read is an absent one.
 */
export function buildProbePlan({ projectId, bucket, runId, otherRunId }) {
  const plan = buildStage3DraftPlan({ projectId, bucket, runIds: [runId, otherRunId] });
  const prefix = plan.recordings[0].prefix;
  const scope = `${prefix}probe/`;
  const name = `${scope}absent.bin`;
  const firebaseObject = `/v0/b/${bucket}/o/${encodeURIComponent(name)}`;
  const gcsObject = `/storage/v1/b/${bucket}/o/${encodeURIComponent(name)}`;
  const read = (id, service, path, query, credential) => ({
    id,
    service,
    method: "GET",
    path,
    query,
    headers: {},
    credential,
  });
  const steps = [
    {
      id: "identity-owner-lookup",
      service: "identitytoolkit",
      method: "POST",
      path: `/identitytoolkit.googleapis.com/v1/projects/${projectId}/accounts:lookup`,
      query: {},
      headers: JSON_TYPE,
      credential: "owner",
      body: {
        email: [`storage-object-probe-${runId}@example.com`],
        targetProjectId: projectId,
      },
    },
    read("gcs-metadata-owner", "storage", gcsObject, {}, "owner"),
    read("gcs-media-owner", "storage", gcsObject, { alt: "media" }, "owner"),
    read("firebase-metadata-owner", "storage", firebaseObject, {}, "owner"),
    read("firebase-media-owner", "storage", firebaseObject, { alt: "media" }, "owner"),
    read("firebase-metadata-none", "storage", firebaseObject, {}, "none"),
    read("firebase-media-none", "storage", firebaseObject, { alt: "media" }, "none"),
  ];
  // The two lists come last, after the sessions, so that they also read back what the sessions
  // could have left under the run's prefix. Only the GCS one is judged, and only for that.
  const readbacks = [
    {
      ...read("gcs-list-owner", "storage", `/storage/v1/b/${bucket}/o`, { prefix: scope }, "owner"),
      judgesPrefix: true,
    },
    read("firebase-list-owner", "storage", `/v0/b/${bucket}/o`, { prefix: scope }, "owner"),
  ];
  const gcsSessionName = `${scope}session-gcs.bin`;
  const firebaseSessionName = `${scope}session-firebase.bin`;
  // As the corpus declares the resumable initiate of each dialect, for a 262,147-byte object that
  // is never sent.
  const gcsStatus = { "content-length": "0", "content-range": "bytes */262147" };
  const firebaseCommand = (command) => ({ "x-goog-upload-command": command });
  const continuation = (id, method, headers) => ({ id, method, headers, credential: "owner" });
  const sessions = [
    {
      objectName: gcsSessionName,
      urlHeader: "location",
      start: {
        id: "gcs-session-start",
        service: "storage",
        method: "POST",
        path: `/upload/storage/v1/b/${bucket}/o`,
        query: { uploadType: "resumable", name: gcsSessionName, ifGenerationMatch: "0" },
        headers: {
          "content-type": "application/json",
          "x-upload-content-type": "application/octet-stream",
          "x-upload-content-length": "262147",
        },
        credential: "owner",
        body: {
          name: gcsSessionName,
          contentType: "application/octet-stream",
          metadata: { marker: "gcs-resumable" },
        },
      },
      continuations: [
        continuation("gcs-session-status", "PUT", gcsStatus),
        continuation("gcs-session-cancel", "DELETE", {}),
        continuation("gcs-session-status-after-cancel", "PUT", gcsStatus),
      ],
    },
    {
      objectName: firebaseSessionName,
      urlHeader: "x-goog-upload-url",
      start: {
        id: "firebase-session-start",
        service: "storage",
        method: "POST",
        path: `/v0/b/${bucket}/o`,
        query: { name: firebaseSessionName },
        headers: {
          "x-goog-upload-protocol": "resumable",
          "x-goog-upload-command": "start",
          "x-goog-upload-header-content-length": "262147",
          "x-goog-upload-header-content-type": "application/octet-stream",
          "content-type": "application/json; charset=utf-8",
        },
        credential: "owner",
        body: { name: firebaseSessionName, contentType: "application/octet-stream" },
      },
      continuations: [
        continuation("firebase-session-query", "POST", firebaseCommand("query")),
        continuation("firebase-session-cancel", "POST", firebaseCommand("cancel")),
        continuation("firebase-session-query-after-cancel", "POST", firebaseCommand("query")),
      ],
    },
  ];
  return Object.freeze({
    prefix,
    scope,
    objectName: name,
    steps: Object.freeze(steps),
    sessions: Object.freeze(sessions),
    readbacks: Object.freeze(readbacks),
  });
}

/** The placeholder URL and init the lean wire takes for one step. */
export function probeRequest(step, origins) {
  const url = new URL(
    step.path,
    step.service === "identitytoolkit" ? origins.auth : origins.storage,
  );
  for (const [key, value] of Object.entries(step.query)) url.searchParams.set(key, value);
  return {
    href: url.href,
    init: {
      method: step.method,
      headers: {
        ...step.headers,
        ...(step.credential === "owner" ? { authorization: OWNER } : {}),
      },
      ...(step.body ? { body: JSON.stringify(step.body) } : {}),
    },
  };
}

/** A session request: the session URL the start answered with, and the step's method and headers. */
export function sessionContinuation(row, url) {
  return {
    href: url,
    init: { method: row.method, headers: { ...row.headers, authorization: OWNER } },
  };
}

/** Whether a GCS list answer says the prefix holds nothing: a 200 with no items and no next page. */
export function emptyList(status, text) {
  if (status !== 200) return false;
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    return false;
  }
  return (
    body !== null &&
    typeof body === "object" &&
    !Array.isArray(body) &&
    (body.items === undefined || (Array.isArray(body.items) && body.items.length === 0)) &&
    body.nextPageToken === undefined
  );
}

const firstLine = (error) =>
  String(error?.message ?? error)
    .split("\n")[0]
    .slice(0, 200);

/**
 * Send the plan in order, one request at a time: the identity request and the reads, each session,
 * then the two lists. A response of any status is an answer. A request that throws stops the run at once, so
 * nothing after an identity or connection failure is sent. The one exception is a session
 * request the wire refuses before it sends anything (a session URL of a shape its route table does
 * not know): that is recorded as skipped, with the wire's reason, and the run goes on.
 * Resolves with one row per request: `{ id, status }`, or `{ id, skipped }`. The GCS list row also
 * says whether it showed the prefix empty (`prefixEmpty`), the one thing the run closes on.
 */
export async function sendProbe({ wire, plan, origins }) {
  const answers = [];
  const stop = (error, id) => {
    error.probeStep = id;
    error.answered = answers;
    return error;
  };
  for (const step of plan.steps) {
    const { href, init } = probeRequest(step, origins);
    let response;
    try {
      // The wire has read the whole body and captured it before it answers.
      response = await wire.fetch(href, init);
    } catch (error) {
      throw stop(error, step.id);
    }
    answers.push({ id: step.id, status: response.status });
  }
  const placeholders = Object.values(origins);
  for (const group of plan.sessions) {
    const { href, init } = probeRequest(group.start, origins);
    let response;
    try {
      response = await wire.fetch(href, init);
    } catch (error) {
      throw stop(error, group.start.id);
    }
    answers.push({ id: group.start.id, status: response.status });
    // The wire has already put its own origin in place of the real host in these headers.
    const url =
      response.status >= 200 && response.status < 300
        ? response.headers.get(group.urlHeader)
        : null;
    const usable =
      typeof url === "string" && placeholders.some((origin) => url.startsWith(`${origin}/`));
    for (const row of group.continuations) {
      if (!usable) {
        answers.push({ id: row.id, skipped: "no session URL" });
        continue;
      }
      const request = sessionContinuation(row, url);
      try {
        response = await wire.fetch(request.href, request.init);
      } catch (error) {
        // Only a refusal by the route table (nothing was sent) is an answer. Any other failure, an
        // unavailable token or wire included, stops the run.
        if (error?.routeRefused !== true) throw stop(error, row.id);
        answers.push({ id: row.id, skipped: firstLine(error) });
        continue;
      }
      answers.push({ id: row.id, status: response.status });
    }
  }
  for (const step of plan.readbacks) {
    const { href, init } = probeRequest(step, origins);
    let response;
    let text;
    try {
      response = await wire.fetch(href, init);
      text = await response.text();
    } catch (error) {
      throw stop(error, step.id);
    }
    answers.push({
      id: step.id,
      status: response.status,
      ...(step.judgesPrefix ? { prefixEmpty: emptyList(response.status, text) } : {}),
    });
  }
  return answers;
}
