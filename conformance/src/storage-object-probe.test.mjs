// The read-only probe: its nine requests, their order, what stops it, and that each one has the
// shape (URL form, headers, credential) the recorder's own corpus declares for the same kind of
// step, because both go through the same lean wire.

import assert from "node:assert/strict";
import test from "node:test";
import { buildAuthCorpus } from "./storage-object/auth-corpus.mjs";
import { buildCorpus } from "./storage-object/corpus.mjs";
import {
  createLeanWire,
  LEAN_PLACEHOLDER_ADMIN,
  LEAN_PLACEHOLDER_API_KEY,
} from "./storage-object/lean-wire.mjs";
import {
  buildProbePlan,
  PROBE_MAX_REQUESTS,
  probeRequest,
  sendProbe,
  sessionContinuation,
} from "./storage-object/probe.mjs";

const BUCKET = "fireemu-oracle-query.firebasestorage.app";
const PROJECT = "fireemu-oracle-query";
const RUN = "0123456789abcdef0123";
const OTHER = "fedcba9876543210fedc";
const TOKEN = "ya29.synthetic-owner-access-token-value";
const ORIGINS = {
  storage: "http://127.0.0.1:19199",
  auth: "http://127.0.0.1:19099",
  control: "http://127.0.0.1:19198",
};

const plan = buildProbePlan({ projectId: PROJECT, bucket: BUCKET, runId: RUN, otherRunId: OTHER });

function makeWire({ fetchImpl } = {}) {
  const calls = [];
  const captures = [];
  const wire = createLeanWire({
    bucket: BUCKET,
    projectId: PROJECT,
    prefix: plan.prefix,
    origins: ORIGINS,
    adminToken: async () => TOKEN,
    authApiKey: "AIzaSyD-synthetic-web-api-key-value-000000",
    readRules: async () => ({ source: "x" }),
    fetchImpl:
      fetchImpl ??
      (async (url, init) => {
        calls.push({ url: String(url), init });
        return new Response("{}", { status: 404, headers: { "content-type": "application/json" } });
      }),
    capture: async (record) => captures.push(record),
    pacer: { dispatch: (_name, attempt) => attempt() },
  });
  return { wire, calls, captures };
}

/** What went out, with the token and the object name masked so two shapes compare. */
function shapeOf(call) {
  const url = new URL(call.url);
  const query = [...url.searchParams.entries()]
    .map(([key, value]) => `${key}=${key === "prefix" ? "<prefix>" : value}`)
    .toSorted();
  const headers = Object.fromEntries(
    [...new Headers(call.init.headers).entries()]
      .map(([key, value]) => [key, value === `Bearer ${TOKEN}` ? "Bearer <owner>" : value])
      .toSorted(([a], [b]) => (a < b ? -1 : 1)),
  );
  return {
    method: call.init.method,
    origin: url.origin,
    path: url.pathname.replace(/\/o\/[^/]+$/, "/o/<name>"),
    query,
    headers,
  };
}

// ---- the plan -------------------------------------------------------------------------------------

test("the plan is nine requests and two sessions, the identity request first, every Storage name under the run", () => {
  assert.equal(PROBE_MAX_REQUESTS, 17);
  assert.equal(plan.steps.length, 9);
  assert.equal(plan.sessions.length, 2);
  assert.deepEqual(
    plan.steps.map((step) => step.id),
    [
      "identity-owner-lookup",
      "gcs-metadata-owner",
      "gcs-media-owner",
      "gcs-list-owner",
      "firebase-metadata-owner",
      "firebase-media-owner",
      "firebase-list-owner",
      "firebase-metadata-none",
      "firebase-media-none",
    ],
  );
  assert.equal(plan.objectName, `storage-object/${RUN}/probe/absent.bin`);
  assert.equal(plan.scope, `storage-object/${RUN}/probe/`);
  for (const step of plan.steps.slice(1)) {
    assert.equal(step.method, "GET");
    assert.equal(step.service, "storage");
  }
  assert.deepEqual(plan.steps[0].body, {
    email: [`storage-object-probe-${RUN}@example.com`],
    targetProjectId: PROJECT,
  });
});

test("no request in the plan writes: the one POST is the identity lookup", () => {
  const posts = plan.steps.filter((step) => step.method !== "GET");
  assert.deepEqual(
    posts.map((step) => step.path),
    [`/identitytoolkit.googleapis.com/v1/projects/${PROJECT}/accounts:lookup`],
  );
});

// ---- through the real lean wire --------------------------------------------------------------------

test("through the lean wire each request goes to the real host with exactly these headers", async () => {
  const { wire, calls } = makeWire();
  await sendProbe({ wire, plan, origins: ORIGINS });
  const name = encodeURIComponent(plan.objectName);
  const scope = encodeURIComponent(plan.scope);
  const owner = { authorization: `Bearer ${TOKEN}`, "x-goog-user-project": PROJECT };
  assert.deepEqual(
    calls.slice(0, 9).map((call) => ({
      method: call.init.method,
      url: call.url,
      headers: Object.fromEntries(
        [...new Headers(call.init.headers).entries()].toSorted(([a], [b]) => (a < b ? -1 : 1)),
      ),
    })),
    [
      {
        method: "POST",
        url: `https://identitytoolkit.googleapis.com/v1/projects/${PROJECT}/accounts:lookup`,
        headers: { ...owner, "content-type": "application/json" },
      },
      {
        method: "GET",
        url: `https://storage.googleapis.com/storage/v1/b/${BUCKET}/o/${name}`,
        headers: owner,
      },
      {
        method: "GET",
        url: `https://storage.googleapis.com/storage/v1/b/${BUCKET}/o/${name}?alt=media`,
        headers: owner,
      },
      {
        method: "GET",
        url: `https://storage.googleapis.com/storage/v1/b/${BUCKET}/o?prefix=${scope}`,
        headers: owner,
      },
      {
        method: "GET",
        url: `https://firebasestorage.googleapis.com/v0/b/${BUCKET}/o/${name}`,
        headers: owner,
      },
      {
        method: "GET",
        url: `https://firebasestorage.googleapis.com/v0/b/${BUCKET}/o/${name}?alt=media`,
        headers: owner,
      },
      {
        method: "GET",
        url: `https://firebasestorage.googleapis.com/v0/b/${BUCKET}/o?prefix=${scope}`,
        headers: owner,
      },
      {
        method: "GET",
        url: `https://firebasestorage.googleapis.com/v0/b/${BUCKET}/o/${name}`,
        headers: {},
      },
      {
        method: "GET",
        url: `https://firebasestorage.googleapis.com/v0/b/${BUCKET}/o/${name}?alt=media`,
        headers: {},
      },
    ],
  );
});

test("the identity lookup body is the one the corpus sends, and it reaches the wire once", async () => {
  const { wire, calls } = makeWire();
  await sendProbe({ wire, plan, origins: ORIGINS });
  assert.deepEqual(JSON.parse(Buffer.from(calls[0].init.body).toString()), plan.steps[0].body);
});

test("a status of any kind is an answer, recorded, and the run goes on", async () => {
  const statuses = [200, 401, 403, 404, 404, 500, 200, 302, 404, 404, 403];
  let index = 0;
  const { wire, captures } = makeWire({
    fetchImpl: async () =>
      new Response("{}", {
        status: statuses[index++],
        headers: { "content-type": "application/json" },
      }),
  });
  const answers = await sendProbe({ wire, plan, origins: ORIGINS });
  assert.deepEqual(
    answers.filter((row) => row.status !== undefined).map((row) => row.status),
    statuses,
  );
  assert.equal(captures.length, 11, "every answer was captured");
  assert.deepEqual(
    captures.map((record) => record.response.status),
    statuses,
  );
});

test("a request that fails stops the run: the identity request is first, nothing follows it", async () => {
  const calls = [];
  const { wire } = makeWire({
    fetchImpl: async (url) => {
      calls.push(String(url));
      throw new TypeError("fetch failed");
    },
  });
  await assert.rejects(
    sendProbe({ wire, plan, origins: ORIGINS }),
    (error) => error.probeStep === "identity-owner-lookup" && error.answered.length === 0,
  );
  assert.equal(calls.length, 1);
});

test("a lost connection part-way stops there and says what had been answered", async () => {
  let count = 0;
  const { wire } = makeWire({
    fetchImpl: async () => {
      if (++count === 4) throw new TypeError("fetch failed");
      return new Response("{}", { status: 404, headers: { "content-type": "application/json" } });
    },
  });
  await assert.rejects(
    sendProbe({ wire, plan, origins: ORIGINS }),
    (error) => error.probeStep === "gcs-list-owner" && error.answered.length === 3,
  );
  assert.equal(count, 4, "no request went out after the failure");
});

test("a capture failure stops the run", async () => {
  const wire = createLeanWire({
    bucket: BUCKET,
    projectId: PROJECT,
    prefix: plan.prefix,
    origins: ORIGINS,
    adminToken: async () => TOKEN,
    authApiKey: "AIzaSyD-synthetic-web-api-key-value-000000",
    readRules: async () => ({ source: "x" }),
    fetchImpl: async () => new Response("{}", { status: 404 }),
    capture: async () => {
      throw new Error("disk full");
    },
    pacer: { dispatch: (_name, attempt) => attempt() },
  });
  await assert.rejects(sendProbe({ wire, plan, origins: ORIGINS }), /disk full|halted|capture/i);
  assert.equal(wire.snapshot().realRequests, 1);
});

// ---- the same shape as the recorder's corpus ------------------------------------------------------

function corpusSteps() {
  const corpus = buildCorpus({ bucket: BUCKET, prefix: plan.prefix });
  const auth = buildAuthCorpus({ projectId: PROJECT, bucket: BUCKET, runId: RUN });
  const steps = [];
  const walk = (node) => {
    if (Array.isArray(node)) return node.forEach(walk);
    if (!node || typeof node !== "object") return;
    if (typeof node.method === "string" && typeof node.path === "string") steps.push(node);
    for (const value of Object.values(node)) walk(value);
  };
  walk(corpus.recipes);
  walk(auth.recipes);
  return steps;
}

/** As the sender builds it: a placeholder URL, the admin placeholder for an admin credential. */
function corpusCall(step) {
  if (step.service === "identitytoolkit") {
    const url = new URL(
      `/identitytoolkit.googleapis.com/v1/projects/${PROJECT}/accounts:lookup`,
      ORIGINS.auth,
    );
    return {
      href: url.href,
      init: {
        method: step.method,
        headers: { "content-type": "application/json", authorization: LEAN_PLACEHOLDER_ADMIN },
        body: JSON.stringify(step.body),
      },
    };
  }
  const url = new URL(step.path, ORIGINS.storage);
  for (const [key, value] of Object.entries(step.query ?? {}))
    if (typeof value === "string") url.searchParams.set(key, value);
  const admin = step.credential === "admin" || step.credential === "owner";
  return {
    href: url.href,
    init: {
      method: step.method,
      headers: { ...step.headers, ...(admin ? { authorization: LEAN_PLACEHOLDER_ADMIN } : {}) },
    },
  };
}

function findCorpusStep(steps, kind) {
  const found = steps.find((step) => {
    if (kind.identity)
      return (
        step.service === "identitytoolkit" &&
        step.id.endsWith("-email-absence") &&
        step.credential === "owner"
      );
    if (step.method !== "GET" || step.service === "identitytoolkit") return false;
    const dialect = step.dialect ?? (step.path.startsWith("/v0/") ? "firebase" : "gcs");
    const keys = Object.keys(step.query ?? {}).toSorted();
    const credential = step.credential === "owner" ? "admin" : step.credential;
    return (
      dialect === kind.dialect &&
      credential === kind.credential &&
      Boolean(step.collection) === kind.collection &&
      JSON.stringify(keys) === JSON.stringify(kind.keys) &&
      (kind.media ? step.query.alt === "media" : step.query?.alt === undefined)
    );
  });
  assert.ok(found, `the corpus has a step of kind ${JSON.stringify(kind)}`);
  return found;
}

const KINDS = {
  "identity-owner-lookup": { identity: true },
  "gcs-metadata-owner": { dialect: "gcs", credential: "admin", collection: false, keys: [] },
  "gcs-media-owner": {
    dialect: "gcs",
    credential: "admin",
    collection: false,
    keys: ["alt"],
    media: true,
  },
  "gcs-list-owner": {
    dialect: "gcs",
    credential: "admin",
    collection: true,
    keys: ["prefix"],
  },
  "firebase-metadata-owner": {
    dialect: "firebase",
    credential: "admin",
    collection: false,
    keys: [],
  },
  "firebase-media-owner": {
    dialect: "firebase",
    credential: "admin",
    collection: false,
    keys: ["alt"],
    media: true,
  },
  "firebase-list-owner": {
    dialect: "firebase",
    credential: "admin",
    collection: true,
    keys: ["prefix"],
  },
};

test("each owner-credential probe request has the shape of the corpus step of the same kind", async () => {
  const steps = corpusSteps();
  for (const step of plan.steps.filter((row) => row.id in KINDS)) {
    const corpusStep = findCorpusStep(steps, KINDS[step.id]);
    const probe = probeRequest(step, ORIGINS);
    const theirs = corpusCall(corpusStep);
    const a = makeWire();
    const b = makeWire();
    await (await a.wire.fetch(probe.href, probe.init)).arrayBuffer();
    await (await b.wire.fetch(theirs.href, theirs.init)).arrayBuffer();
    assert.deepEqual(shapeOf(a.calls[0]), shapeOf(b.calls[0]), step.id);
  }
});

test("the no-credential probe reads carry what the corpus's no-credential reads carry: nothing", async () => {
  const steps = corpusSteps();
  const corpusNone = steps.find(
    (step) => step.credential === "none" && step.method === "GET" && step.path.startsWith("/v0/"),
  );
  assert.ok(corpusNone, "the corpus declares a no-credential Firebase read");
  const theirs = corpusCall(corpusNone);
  const b = makeWire();
  await (await b.wire.fetch(theirs.href, theirs.init)).arrayBuffer();
  const reference = shapeOf(b.calls[0]).headers;
  for (const id of ["firebase-metadata-none", "firebase-media-none"]) {
    const probe = probeRequest(
      plan.steps.find((row) => row.id === id),
      ORIGINS,
    );
    const a = makeWire();
    await (await a.wire.fetch(probe.href, probe.init)).arrayBuffer();
    assert.deepEqual(shapeOf(a.calls[0]).headers, reference, id);
    assert.equal(a.calls[0].init.headers.get("authorization"), null);
    assert.equal(a.calls[0].init.headers.get("x-goog-user-project"), null);
  }
});

test("the placeholder credentials never leave the process", async () => {
  const { wire, calls } = makeWire();
  await sendProbe({ wire, plan, origins: ORIGINS });
  for (const call of calls) {
    const text = JSON.stringify([call.url, [...new Headers(call.init.headers).entries()]]);
    assert.ok(!text.includes(LEAN_PLACEHOLDER_API_KEY));
    assert.ok(!text.includes("Bearer owner"));
  }
});

// ---- the two resumable sessions -------------------------------------------------------------------------

const REAL_GCS_UPLOAD = "https://storage.googleapis.com/upload/storage/v1/b";
const REAL_FIREBASE = "https://firebasestorage.googleapis.com/v0/b";

/** A fake production that answers the two session starts with a real-host session URL. */
function sessionFetch({
  calls,
  gcsStatus = 200,
  firebaseStatus = 200,
  gcsUrl,
  firebaseUrl,
  after,
}) {
  return async (url, init) => {
    const href = String(url);
    calls.push({ url: href, init });
    const json = { "content-type": "application/json" };
    if (href.startsWith(`${REAL_GCS_UPLOAD}/${BUCKET}/o?`) && init.method === "POST")
      return new Response("", {
        status: gcsStatus,
        headers: {
          ...json,
          ...(gcsUrl === null
            ? {}
            : {
                location:
                  gcsUrl ??
                  `${REAL_GCS_UPLOAD}/${BUCKET}/o?uploadType=resumable&name=${encodeURIComponent(plan.sessions[0].objectName)}&upload_id=AbC-1_x`,
              }),
        },
      });
    if (
      href.startsWith(`${REAL_FIREBASE}/${BUCKET}/o?`) &&
      init.method === "POST" &&
      !href.includes("upload_id")
    )
      return new Response("", {
        status: firebaseStatus,
        headers: {
          "x-goog-upload-status": "active",
          ...(firebaseUrl === null
            ? {}
            : {
                "x-goog-upload-url":
                  firebaseUrl ??
                  `${REAL_FIREBASE}/${BUCKET}/o?name=${encodeURIComponent(plan.sessions[1].objectName)}&upload_id=Qz-9_y&upload_protocol=resumable`,
              }),
        },
      });
    return (await after?.(href, init)) ?? new Response("{}", { status: 404, headers: json });
  };
}

test("the plan has a GCS and a Firebase session under the run, four requests each, and no object is created", () => {
  const [gcs, firebase] = plan.sessions;
  assert.equal(gcs.objectName, `storage-object/${RUN}/probe/session-gcs.bin`);
  assert.equal(firebase.objectName, `storage-object/${RUN}/probe/session-firebase.bin`);
  assert.deepEqual(
    [gcs.start.id, ...gcs.continuations.map((row) => row.id)],
    [
      "gcs-session-start",
      "gcs-session-status",
      "gcs-session-cancel",
      "gcs-session-status-after-cancel",
    ],
  );
  assert.deepEqual(
    [firebase.start.id, ...firebase.continuations.map((row) => row.id)],
    [
      "firebase-session-start",
      "firebase-session-query",
      "firebase-session-cancel",
      "firebase-session-query-after-cancel",
    ],
  );
  assert.equal(PROBE_MAX_REQUESTS, plan.steps.length + 8);
  // No request of a session carries an object body: a start has a JSON description only, and the
  // status and cancel requests have no body, so nothing can be uploaded.
  for (const row of plan.sessions.flatMap((group) => group.continuations))
    assert.equal(row.body, undefined, row.id);
  assert.deepEqual(
    plan.sessions.map((group) => group.start.body.name),
    [gcs.objectName, firebase.objectName],
  );
});

test("a session's four requests reach the real host with the headers the corpus declares", async () => {
  const calls = [];
  const { wire } = makeWire({ fetchImpl: sessionFetch({ calls }) });
  const answers = await sendProbe({ wire, plan, origins: ORIGINS });
  const sessionCalls = calls.slice(9);
  assert.equal(sessionCalls.length, 8);
  const name = (index) => encodeURIComponent(plan.sessions[index].objectName);
  const shape = (call) => ({
    method: call.init.method,
    url: call.url,
    headers: Object.fromEntries(
      [...new Headers(call.init.headers).entries()]
        .filter(
          ([key]) =>
            key.startsWith("x-goog-upload") ||
            key.startsWith("x-upload") ||
            key.startsWith("content-"),
        )
        .toSorted(([a], [b]) => (a < b ? -1 : 1)),
    ),
  });
  const gcsUrl = `${REAL_GCS_UPLOAD}/${BUCKET}/o?uploadType=resumable&name=${name(0)}&upload_id=AbC-1_x`;
  const firebaseUrl = `${REAL_FIREBASE}/${BUCKET}/o?name=${name(1)}&upload_id=Qz-9_y&upload_protocol=resumable`;
  assert.deepEqual(sessionCalls.slice(0, 4).map(shape), [
    {
      method: "POST",
      url: `${REAL_GCS_UPLOAD}/${BUCKET}/o?uploadType=resumable&name=${name(0)}&ifGenerationMatch=0`,
      headers: {
        "content-type": "application/json",
        "x-upload-content-length": "262147",
        "x-upload-content-type": "application/octet-stream",
      },
    },
    {
      method: "PUT",
      url: gcsUrl,
      headers: { "content-length": "0", "content-range": "bytes */262147" },
    },
    { method: "DELETE", url: gcsUrl, headers: {} },
    {
      method: "PUT",
      url: gcsUrl,
      headers: { "content-length": "0", "content-range": "bytes */262147" },
    },
  ]);
  assert.deepEqual(sessionCalls.slice(4).map(shape), [
    {
      method: "POST",
      url: `${REAL_FIREBASE}/${BUCKET}/o?name=${name(1)}`,
      headers: {
        "content-type": "application/json; charset=utf-8",
        "x-goog-upload-command": "start",
        "x-goog-upload-header-content-length": "262147",
        "x-goog-upload-header-content-type": "application/octet-stream",
        "x-goog-upload-protocol": "resumable",
      },
    },
    { method: "POST", url: firebaseUrl, headers: { "x-goog-upload-command": "query" } },
    { method: "POST", url: firebaseUrl, headers: { "x-goog-upload-command": "cancel" } },
    { method: "POST", url: firebaseUrl, headers: { "x-goog-upload-command": "query" } },
  ]);
  for (const call of sessionCalls) {
    assert.equal(new Headers(call.init.headers).get("authorization"), `Bearer ${TOKEN}`);
    assert.equal(new Headers(call.init.headers).get("x-goog-user-project"), PROJECT);
  }
  assert.equal(answers.length, 17);
  assert.deepEqual(
    answers.slice(9).map((row) => row.id),
    [
      "gcs-session-start",
      "gcs-session-status",
      "gcs-session-cancel",
      "gcs-session-status-after-cancel",
      "firebase-session-start",
      "firebase-session-query",
      "firebase-session-cancel",
      "firebase-session-query-after-cancel",
    ],
  );
});

test("the session start bodies name the owned object and its type, nothing else", async () => {
  const calls = [];
  const { wire } = makeWire({ fetchImpl: sessionFetch({ calls }) });
  await sendProbe({ wire, plan, origins: ORIGINS });
  const starts = [calls[9], calls[13]];
  assert.deepEqual(
    starts.map((call) => JSON.parse(Buffer.from(call.init.body).toString())),
    [
      {
        name: plan.sessions[0].objectName,
        contentType: "application/octet-stream",
        metadata: { marker: "gcs-resumable" },
      },
      { name: plan.sessions[1].objectName, contentType: "application/octet-stream" },
    ],
  );
});

test("a session that does not start gets no continuation, and the run goes on to the next group", async () => {
  const calls = [];
  const { wire } = makeWire({ fetchImpl: sessionFetch({ calls, gcsStatus: 403 }) });
  const answers = await sendProbe({ wire, plan, origins: ORIGINS });
  assert.equal(
    calls.filter((call) => /upload_id/.test(call.url)).length,
    3,
    "the three continuations of the Firebase session only",
  );
  const gcs = answers.filter((row) => row.id.startsWith("gcs-session"));
  assert.deepEqual(
    gcs.map((row) => row.status ?? row.skipped),
    [403, "no session URL", "no session URL", "no session URL"],
  );
  assert.equal(answers.filter((row) => row.id.startsWith("firebase-session")).length, 4);
});

test("a start without a session URL header, or with one that is not on the wire's origin, is skipped", async () => {
  for (const options of [
    { gcsUrl: null, firebaseUrl: null },
    { gcsUrl: "https://elsewhere.example/upload?upload_id=x", firebaseUrl: "not a url" },
  ]) {
    const calls = [];
    const { wire } = makeWire({ fetchImpl: sessionFetch({ calls, ...options }) });
    const answers = await sendProbe({ wire, plan, origins: ORIGINS });
    assert.equal(calls.length, 11, "nine reads and two starts, no continuation");
    assert.equal(answers.filter((row) => row.skipped === "no session URL").length, 6);
    assert.ok(!calls.some((call) => call.url.includes("elsewhere")));
  }
});

test("a continuation the wire refuses before sending is skipped, and a network failure is not", async () => {
  // A production session URL of a shape the route table does not know (no `name`).
  const calls = [];
  const { wire } = makeWire({
    fetchImpl: sessionFetch({
      calls,
      gcsUrl: `${REAL_GCS_UPLOAD}/${BUCKET}/o?uploadType=resumable&upload_id=AbC-1_x`,
    }),
  });
  const answers = await sendProbe({ wire, plan, origins: ORIGINS });
  const gcs = answers.filter((row) => row.id.startsWith("gcs-session"));
  assert.equal(gcs[0].status, 200);
  for (const row of gcs.slice(1)) assert.match(row.skipped, /route|name/i, row.id);
  assert.equal(
    calls.filter((call) => call.url.includes("upload_id=AbC-1_x")).length,
    0,
    "nothing was sent to a URL the wire refused",
  );
  // The lost connection on a continuation stops the run.
  let count = 0;
  const lost = makeWire({
    fetchImpl: sessionFetch({
      calls: [],
      after: async (href) => {
        if (href.includes("upload_id=AbC-1_x") && ++count === 2)
          throw new TypeError("fetch failed");
        return undefined;
      },
    }),
  });
  await assert.rejects(
    sendProbe({ wire: lost.wire, plan, origins: ORIGINS }),
    (error) => error.probeStep === "gcs-session-cancel" && error.answered.length === 11,
  );
});

test("a halted wire stops a session instead of skipping it", async () => {
  const calls = [];
  const wire = createLeanWire({
    bucket: BUCKET,
    projectId: PROJECT,
    prefix: plan.prefix,
    origins: ORIGINS,
    adminToken: async () => TOKEN,
    authApiKey: "AIzaSyD-synthetic-web-api-key-value-000000",
    readRules: async () => ({ source: "x" }),
    fetchImpl: sessionFetch({ calls }),
    capture: async (record) => {
      // The capture of the first status probe of the GCS session fails.
      if (record.request?.method === "PUT") throw new Error("disk full");
    },
    pacer: { dispatch: (_name, attempt) => attempt() },
  });
  await assert.rejects(sendProbe({ wire, plan, origins: ORIGINS }), /CAPTURE_FAILED/);
  assert.equal(calls.filter((call) => call.url.includes("upload_id=Qz-9_y")).length, 0);
});

test("a session continuation is the session URL with the step's method and headers, and nothing of the start", () => {
  const url = `http://127.0.0.1:19199/upload/storage/v1/b/${BUCKET}/o?uploadType=resumable&name=n&upload_id=x`;
  const request = sessionContinuation(plan.sessions[0].continuations[1], url);
  assert.equal(request.href, url);
  assert.equal(request.init.method, "DELETE");
  assert.deepEqual(request.init.headers, { authorization: "Bearer owner" });
});

const SESSION_KINDS = {
  "gcs-session-start": {
    dialect: "gcs",
    pick: (step) => step.id === "initiate" && step.path.startsWith("/upload/"),
  },
  "firebase-session-start": {
    dialect: "firebase",
    pick: (step) => step.id === "initiate" && step.path === `/v0/b/${BUCKET}/o`,
  },
};

test("each session start has the shape of the corpus's initiate step for the same dialect", async () => {
  const steps = corpusSteps();
  for (const group of plan.sessions) {
    const id = group.start.id;
    const corpusStep = steps.find(SESSION_KINDS[id].pick);
    assert.ok(corpusStep, id);
    const theirs = corpusCall({ ...corpusStep, credential: "admin" });
    const probe = probeRequest(group.start, ORIGINS);
    const a = makeWire();
    const b = makeWire();
    await (await a.wire.fetch(probe.href, probe.init)).arrayBuffer();
    await (
      await b.wire.fetch(theirs.href, {
        ...theirs.init,
        headers: { ...theirs.init.headers, ...corpusStep.headers },
        body: JSON.stringify(corpusStep.body.json),
      })
    ).arrayBuffer();
    const one = shapeOf(a.calls[0]);
    const two = shapeOf(b.calls[0]);
    // The corpus start also asks for a generation match; only the object name differs otherwise.
    assert.deepEqual(one.headers, two.headers, id);
    assert.equal(one.method, two.method);
    assert.equal(one.origin, two.origin);
    assert.equal(one.path, two.path);
  }
});

test("a session URL on a look-alike host of the placeholder is not used", async () => {
  const calls = [];
  const { wire } = makeWire({
    fetchImpl: sessionFetch({
      calls,
      gcsUrl: "https://storage.googleapis.com/upload/storage/v1/b/x/o?upload_id=1",
    }),
  });
  // Stand in for a wire that hands back a look-alike of its own origin.
  const lookAlike = {
    fetch: async (href, init) => {
      const response = await wire.fetch(href, init);
      if (!response.headers.get("location")) return response;
      const headers = new Headers(response.headers);
      headers.set("location", "http://127.0.0.1:19199.example.com/upload?upload_id=1&name=n");
      return new Response("", { status: response.status, headers });
    },
    snapshot: () => wire.snapshot(),
  };
  const answers = await sendProbe({ wire: lookAlike, plan, origins: ORIGINS });
  assert.deepEqual(
    answers
      .filter((row) => row.id.startsWith("gcs-session"))
      .map((row) => row.skipped ?? row.status),
    [200, "no session URL", "no session URL", "no session URL"],
  );
  assert.ok(!calls.some((call) => call.url.includes("example.com")));
});

test("a session start that cannot be completed stops the run there", async () => {
  let count = 0;
  const { wire } = makeWire({
    fetchImpl: async () => {
      if (++count === 10) throw new TypeError("fetch failed");
      return new Response("{}", { status: 404, headers: { "content-type": "application/json" } });
    },
  });
  await assert.rejects(
    sendProbe({ wire, plan, origins: ORIGINS }),
    (error) => error.probeStep === "gcs-session-start" && error.answered.length === 9,
  );
  assert.equal(count, 10);
});

test("the status of each session request is what production answered", async () => {
  const calls = [];
  const { wire } = makeWire({
    fetchImpl: sessionFetch({
      calls,
      after: async (href, init) => {
        if (!href.includes("upload_id")) return undefined;
        const status = init.method === "DELETE" ? 499 : init.method === "PUT" ? 308 : 200;
        return new Response("", { status: status === 499 ? 499 : status });
      },
    }),
  });
  const answers = await sendProbe({ wire, plan, origins: ORIGINS });
  assert.deepEqual(
    answers.slice(9).map((row) => row.status),
    [200, 308, 499, 308, 200, 200, 200, 200],
  );
});

/** A wire that answers the nine reads and the GCS session start, then refuses what comes next. */
function refusingWire({ message, halted }) {
  let count = 0;
  return {
    fetch: async () => {
      count++;
      // Request 14 is the Firebase session start; it is answered without a session URL.
      if (count > 10 && count !== 14) throw new Error(message);
      const headers = new Headers();
      if (count === 10)
        headers.set(
          "location",
          "http://127.0.0.1:19199/upload/storage/v1/b/x/o?upload_id=1&name=n",
        );
      return new Response("", { status: 200, headers });
    },
    snapshot: () => ({ realRequests: 10, halted }),
  };
}

test("a refusal's reason is one short line", async () => {
  const wire = refusingWire({
    message: `route is not in the table\nsecond line ${"x".repeat(300)}`,
    halted: false,
  });
  const answers = await sendProbe({ wire, plan, origins: ORIGINS });
  const skipped = answers.filter((row) => row.skipped);
  assert.equal(skipped[0].skipped, "route is not in the table");
  assert.ok(skipped.every((row) => row.skipped.length <= 200 && !row.skipped.includes("\n")));
});

test("a wire that is halted stops the run even when it refused before sending", async () => {
  const wire = refusingWire({ message: "LEAN_WIRE_UNAVAILABLE", halted: true });
  await assert.rejects(
    sendProbe({ wire, plan, origins: ORIGINS }),
    (error) => error.probeStep === "gcs-session-status" && error.answered.length === 10,
  );
});
