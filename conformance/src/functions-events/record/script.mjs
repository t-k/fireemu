// The source script of the FUNCTIONS-EVENTS formal production recording: one pass of the 25 frozen
// corpus scenarios, as declared REST requests. A run plays the pass twice against one deploy. Nothing
// here sends anything; the recorder sends exactly the requests built here and nothing else.

import { createHash } from "node:crypto";

export const PROJECT = "fireemu-oracle-events";
export const REGION = "us-central1";
export const PRIMARY_BUCKET = `${PROJECT}.firebasestorage.app`;
export const CONTROL_BUCKET = `${PROJECT}-fe-events-control`;
export const PRIMARY_TOPIC = "fe-events-primary";
export const CONTROL_TOPIC = "fe-events-control";
export const DECLARED_TOPICS = [PRIMARY_TOPIC, CONTROL_TOPIC];
export const PRIMARY_COLLECTION = "fe_events_primary";
export const CONTROL_COLLECTION = "fe_events_control";
export const MARKER_COLLECTION = "fe_events_retry_markers";
export const DECLARED_COLLECTIONS = [PRIMARY_COLLECTION, CONTROL_COLLECTION, MARKER_COLLECTION];

/** The hosts any request of the recorder may reach (the destination guard narrows this to patterns). */
export const ALLOWED_HOSTS = [
  "firestore.googleapis.com",
  "storage.googleapis.com",
  "identitytoolkit.googleapis.com",
  "pubsub.googleapis.com",
  "logging.googleapis.com",
  "cloudfunctions.googleapis.com",
  "run.googleapis.com",
  "eventarc.googleapis.com",
  "artifactregistry.googleapis.com",
  "cloudresourcemanager.googleapis.com",
  "serviceusage.googleapis.com",
  "firebaserules.googleapis.com",
  "oauth2.googleapis.com",
];

export const POSITIVE_SETTLE_SECONDS = 30;
export const NEGATIVE_WINDOW_SECONDS = 120;
export const RETRY_WINDOW_SECONDS = 240;
export const SEED_WAIT_SECONDS = 20;
export const STEP_GAP_SECONDS = 5;

const handlers = {
  created: ["fsCreatedV1", "fsCreatedV2"],
  updated: ["fsUpdatedV1", "fsUpdatedV2"],
  deleted: ["fsDeletedV1", "fsDeletedV2"],
  written: ["fsWrittenV1", "fsWrittenV2"],
  authContext: ["fsWrittenWithAuthContextV2"],
  retry: ["fsRetryV2"],
  finalized: ["storageFinalizedV1", "storageFinalizedV2"],
  objectDeleted: ["storageDeletedV1", "storageDeletedV2"],
  metadata: ["storageMetadataUpdatedV1", "storageMetadataUpdatedV2"],
  archived: ["storageArchivedV1", "storageArchivedV2"],
  userCreated: ["authCreatedV1"],
  userDeleted: ["authDeletedV1"],
  published: ["pubsubPublishedV1", "pubsubPublishedV2"],
};
const docCreate = [...handlers.created, ...handlers.written, ...handlers.authContext];
const docUpdate = [...handlers.updated, ...handlers.written, ...handlers.authContext];
const docDelete = [...handlers.deleted, ...handlers.written, ...handlers.authContext];

/**
 * Which handlers each scenario delivers to (seed and cleanup events included, because they are
 * real deliveries) and which it must leave silent. `silent` is the negative observation; the
 * order of the pass gives each of them a delivering scenario before and after it.
 */
export const SCENARIO_EVENTS = {
  "fs-create": { delivers: docCreate, silent: [] },
  "fs-delete": { delivers: [...docCreate, ...docDelete], silent: [] },
  "fs-update": { delivers: [...docCreate, ...docUpdate], silent: [] },
  "fs-noop": { delivers: docCreate, silent: handlers.written },
  "fs-other-path": { delivers: [], silent: handlers.created },
  "fs-auth-admin": { delivers: docCreate, silent: [] },
  "fs-auth-client": { delivers: docCreate, silent: [] },
  "fs-retry": { delivers: [...handlers.retry, ...docCreate], silent: [] },
  "storage-upload": { delivers: handlers.finalized, silent: [] },
  "storage-failed-upload": { delivers: [], silent: handlers.finalized },
  "storage-overwrite": { delivers: handlers.finalized, silent: [] },
  "storage-metadata": { delivers: [...handlers.finalized, ...handlers.metadata], silent: [] },
  "storage-other-bucket": { delivers: [], silent: handlers.finalized },
  "storage-delete": { delivers: [...handlers.finalized, ...handlers.objectDeleted], silent: [] },
  "storage-delete-missing": { delivers: [], silent: handlers.objectDeleted },
  "storage-other-prefix": { delivers: handlers.finalized, silent: [] },
  "storage-archive": {
    delivers: [...handlers.finalized, ...handlers.archived, ...handlers.objectDeleted],
    silent: [],
  },
  "auth-admin-create": { delivers: handlers.userCreated, silent: [] },
  "auth-delete": { delivers: [...handlers.userCreated, ...handlers.userDeleted], silent: [] },
  "auth-repeat-signin": { delivers: handlers.userCreated, silent: handlers.userCreated },
  "auth-bulk-delete": { delivers: [...handlers.userCreated, ...handlers.userDeleted], silent: handlers.userDeleted },
  "auth-signup": { delivers: [...handlers.userCreated, ...handlers.userDeleted], silent: [] },
  "pubsub-publish": { delivers: handlers.published, silent: [] },
  "pubsub-other-topic": { delivers: [], silent: handlers.published },
  "pubsub-ordering": { delivers: handlers.published, silent: [] },
};

export const SCENARIO_ORDER = [
  "fs-create",
  "fs-delete",
  "fs-update",
  "fs-noop",
  "fs-other-path",
  "fs-auth-admin",
  "fs-auth-client",
  "fs-retry",
  "storage-upload",
  "storage-failed-upload",
  "storage-overwrite",
  "storage-metadata",
  "storage-other-bucket",
  "storage-delete",
  "storage-delete-missing",
  "storage-other-prefix",
  "storage-archive",
  "auth-admin-create",
  "auth-delete",
  "auth-repeat-signin",
  "auth-bulk-delete",
  "auth-signup",
  "pubsub-publish",
  "pubsub-other-topic",
  "pubsub-ordering",
];

const FAMILY = (id) => id.split("-")[0].replace("fs", "firestore");

// ---- request builders ----------------------------------------------------------------------

const documents = `https://firestore.googleapis.com/v1/projects/${PROJECT}/databases/(default)/documents`;
const objectsUrl = (bucket, name) =>
  `https://storage.googleapis.com/storage/v1/b/${encodeURIComponent(bucket)}/o/${encodeURIComponent(name)}`;
const uploadUrl = (bucket, name, extra = "") =>
  `https://storage.googleapis.com/upload/storage/v1/b/${encodeURIComponent(bucket)}/o?uploadType=media&name=${encodeURIComponent(name)}${extra}`;
const identity = `https://identitytoolkit.googleapis.com/v1/projects/${PROJECT}`;
const topicUrl = (topic) => `https://pubsub.googleapis.com/v1/projects/${PROJECT}/topics/${topic}`;

const fields = (data) =>
  Object.fromEntries(
    Object.entries(data).map(([key, value]) => [
      key,
      typeof value === "number" ? { integerValue: String(value) } : { stringValue: value },
    ]),
  );
const documentData = (value, count = 1, kind = "ordinary") => ({ fixtureKind: kind, value, count });

const md5 = (text) => createHash("md5").update(text).digest("base64");
const PASSWORD = "fe-events-recording-password-1";

class Builder {
  constructor(scenarioId, newId) {
    this.scenarioId = scenarioId;
    this.newId = newId;
    this.requests = [];
    this.subject = [];
  }

  add(role, spec, { subject = false } = {}) {
    const id = `${this.scenarioId}.${this.requests.length + 1}`;
    const request = {
      id,
      role,
      method: spec.method,
      url: spec.url,
      auth: spec.auth ?? "oauth",
      mutation: spec.mutation ?? spec.method !== "GET",
      expect: spec.expect ?? [200],
      ...(spec.headers ? { headers: spec.headers } : {}),
      ...(spec.body !== undefined ? { body: spec.body } : {}),
      ...(spec.contentType ? { contentType: spec.contentType } : {}),
      ...(spec.capture ? { capture: spec.capture } : {}),
      ...(spec.when ? { when: spec.when } : {}),
    };
    this.requests.push(request);
    if (subject) this.subject.push(id);
    return request;
  }
}

const docCreateRequest = (b, collection, id, data, spec = {}) =>
  b.add(spec.role ?? "setup", {
    method: "POST",
    url: `${documents}/${collection}?documentId=${id}`,
    body: { fields: fields(data) },
    auth: spec.auth ?? "oauth",
    expect: [200],
  }, { subject: spec.subject });
const docGet = (b, collection, id, expect = [200], role = "readback") =>
  b.add(role, { method: "GET", url: `${documents}/${collection}/${id}`, expect });
const docDelete_ = (b, collection, id, role = "cleanup") =>
  b.add(role, { method: "DELETE", url: `${documents}/${collection}/${id}`, expect: [200, 404] });

function firestoreStep(scenarioId, newId) {
  const b = new Builder(scenarioId, newId);
  const id = newId("fs");
  const collection = scenarioId === "fs-other-path" ? CONTROL_COLLECTION : PRIMARY_COLLECTION;
  const path = `${collection}/${id}`;
  let seed = false;
  let settle = POSITIVE_SETTLE_SECONDS;
  switch (scenarioId) {
    case "fs-create":
    case "fs-other-path":
    case "fs-auth-admin":
      docCreateRequest(b, collection, id, documentData("created"), { role: "subject", subject: true });
      docGet(b, collection, id);
      docDelete_(b, collection, id);
      docGet(b, collection, id, [404]);
      if (scenarioId === "fs-other-path") settle = NEGATIVE_WINDOW_SECONDS;
      break;
    case "fs-update":
      docCreateRequest(b, collection, id, documentData("before"));
      seed = true;
      b.add("subject", {
        method: "PATCH",
        url: `${documents}/${collection}/${id}?updateMask.fieldPaths=value&updateMask.fieldPaths=count&currentDocument.exists=true`,
        body: { fields: fields({ value: "updated", count: 2 }) },
      }, { subject: true });
      docGet(b, collection, id);
      docDelete_(b, collection, id);
      docGet(b, collection, id, [404]);
      break;
    case "fs-delete":
      docCreateRequest(b, collection, id, documentData("before"));
      seed = true;
      b.add("subject", { method: "DELETE", url: `${documents}/${collection}/${id}`, expect: [200] }, { subject: true });
      docGet(b, collection, id, [404]);
      break;
    case "fs-noop":
      docCreateRequest(b, collection, id, documentData("before"));
      seed = true;
      b.add("subject", {
        method: "PATCH",
        url: `${documents}/${collection}/${id}?currentDocument.exists=true`,
        body: { fields: fields(documentData("before")) },
      }, { subject: true });
      docGet(b, collection, id);
      docDelete_(b, collection, id);
      docGet(b, collection, id, [404]);
      settle = NEGATIVE_WINDOW_SECONDS;
      break;
    case "fs-retry": {
      docCreateRequest(b, collection, id, documentData("retry", 1, "retry"), { role: "subject", subject: true });
      b.add("readback", {
        method: "POST",
        url: `${documents}:runQuery`,
        mutation: false,
        body: {
          structuredQuery: {
            from: [{ collectionId: MARKER_COLLECTION }],
            where: { fieldFilter: { field: { fieldPath: "documentPath" }, op: "EQUAL", value: { stringValue: path } } },
            limit: 10,
          },
        },
        capture: { markerName: "$[0].document.name" },
      });
      docGet(b, collection, id);
      docDelete_(b, collection, id);
      b.add("cleanup", { method: "DELETE", url: "https://firestore.googleapis.com/v1/${markerName}", expect: [200, 404], when: "markerName" });
      docGet(b, collection, id, [404]);
      settle = RETRY_WINDOW_SECONDS;
      break;
    }
    case "fs-auth-client": {
      const email = `${id}@example.test`;
      b.add("setup", {
        method: "POST",
        url: "https://identitytoolkit.googleapis.com/v1/accounts:signUp",
        auth: "apikey",
        body: { email, password: PASSWORD, returnSecureToken: true },
        capture: { idToken: "$.idToken", uid: "$.localId" },
      });
      docCreateRequest(b, collection, id, documentData("client"), { role: "subject", subject: true, auth: "idtoken" });
      docGet(b, collection, id);
      docDelete_(b, collection, id);
      docGet(b, collection, id, [404]);
      b.add("cleanup", { method: "POST", url: `${identity}/accounts:delete`, body: { localId: "${uid}" } });
      break;
    }
    default:
      throw new Error(`not a Firestore scenario: ${scenarioId}`);
  }
  return {
    b,
    matchKey: { kind: "firestore", value: path },
    sourceResult: "typed-success",
    seed,
    settle,
  };
}

const objectName = (scenarioId, id) =>
  scenarioId === "storage-other-prefix" ? `other/${id}.txt` : `fe-events/${id}.txt`;
const textUpload = (b, bucket, name, text, { role, subject = false, precondition = true, expect = [200], capture } = {}) =>
  b.add(role, {
    method: "POST",
    url: uploadUrl(bucket, name, precondition ? "&ifGenerationMatch=0" : ""),
    contentType: "text/plain",
    body: text,
    expect,
    ...(capture ? { capture } : {}),
  }, { subject });
const objectGet = (b, bucket, name, expect = [200]) =>
  b.add("readback", { method: "GET", url: objectsUrl(bucket, name), expect });
const objectDelete = (b, bucket, name, expect = [204], role = "cleanup") =>
  b.add(role, { method: "DELETE", url: objectsUrl(bucket, name), expect });
const versionList = (b, bucket, name) =>
  b.add("readback", {
    method: "GET",
    url: `https://storage.googleapis.com/storage/v1/b/${encodeURIComponent(bucket)}/o?versions=true&prefix=${encodeURIComponent(name)}`,
  });
const bucketVersioning = (b, bucket) =>
  b.add("readback", {
    method: "GET",
    url: `https://storage.googleapis.com/storage/v1/b/${encodeURIComponent(bucket)}?fields=versioning`,
  });
const setVersioning = (b, bucket, enabled, role) =>
  b.add(role, {
    method: "PATCH",
    url: `https://storage.googleapis.com/storage/v1/b/${encodeURIComponent(bucket)}?fields=versioning`,
    body: { versioning: { enabled } },
  });

function storageStep(scenarioId, newId) {
  const b = new Builder(scenarioId, newId);
  const id = newId("obj");
  const bucket = scenarioId === "storage-other-bucket" ? CONTROL_BUCKET : PRIMARY_BUCKET;
  const name = objectName(scenarioId, id);
  let seed = false;
  let settle = POSITIVE_SETTLE_SECONDS;
  let sourceResult = "typed-success";
  switch (scenarioId) {
    case "storage-upload":
    case "storage-other-bucket":
    case "storage-other-prefix":
      textUpload(b, bucket, name, "created", { role: "subject", subject: true });
      objectGet(b, bucket, name);
      objectDelete(b, bucket, name);
      versionList(b, bucket, name);
      if (scenarioId === "storage-other-bucket") settle = NEGATIVE_WINDOW_SECONDS;
      break;
    case "storage-overwrite":
      textUpload(b, bucket, name, "before", { role: "setup" });
      seed = true;
      textUpload(b, bucket, name, "updated", { role: "subject", subject: true, precondition: false });
      objectGet(b, bucket, name);
      objectDelete(b, bucket, name);
      versionList(b, bucket, name);
      break;
    case "storage-failed-upload":
      b.add("subject", {
        method: "POST",
        url: uploadUrl(bucket, name),
        contentType: "text/plain",
        headers: { "x-goog-hash": `md5=${md5("hello")}` },
        body: "hellp",
        expect: [400],
      }, { subject: true });
      versionList(b, bucket, name);
      sourceResult = "typed-refusal";
      settle = NEGATIVE_WINDOW_SECONDS;
      break;
    case "storage-delete":
      textUpload(b, bucket, name, "before", { role: "setup" });
      seed = true;
      b.add("subject", { method: "DELETE", url: objectsUrl(bucket, name), expect: [204] }, { subject: true });
      objectGet(b, bucket, name, [404]);
      versionList(b, bucket, name);
      break;
    case "storage-delete-missing":
      b.add("subject", { method: "DELETE", url: objectsUrl(bucket, name), expect: [404] }, { subject: true });
      versionList(b, bucket, name);
      sourceResult = "typed-refusal";
      settle = NEGATIVE_WINDOW_SECONDS;
      break;
    case "storage-metadata":
      textUpload(b, bucket, name, "before", { role: "setup" });
      seed = true;
      b.add("subject", {
        method: "PATCH",
        url: objectsUrl(bucket, name),
        body: { metadata: { fixtureMarker: "updated" } },
      }, { subject: true });
      objectGet(b, bucket, name);
      objectDelete(b, bucket, name);
      versionList(b, bucket, name);
      break;
    case "storage-archive":
      bucketVersioning(b, bucket);
      setVersioning(b, bucket, true, "setup");
      bucketVersioning(b, bucket);
      textUpload(b, bucket, name, "before", { role: "setup", capture: { firstGeneration: "$.generation" } });
      seed = true;
      textUpload(b, bucket, name, "updated", {
        role: "subject",
        subject: true,
        precondition: false,
        capture: { secondGeneration: "$.generation" },
      });
      versionList(b, bucket, name);
      b.add("cleanup", { method: "DELETE", url: `${objectsUrl(bucket, name)}?generation=\${firstGeneration}`, expect: [204, 404] });
      b.add("cleanup", { method: "DELETE", url: `${objectsUrl(bucket, name)}?generation=\${secondGeneration}`, expect: [204, 404] });
      versionList(b, bucket, name);
      setVersioning(b, bucket, false, "cleanup");
      bucketVersioning(b, bucket);
      break;
    default:
      throw new Error(`not a Storage scenario: ${scenarioId}`);
  }
  return { b, matchKey: { kind: "storage", bucket, value: name }, sourceResult, seed, settle };
}

const accountLookup = (b, ids) =>
  b.add("readback", { method: "POST", url: `${identity}/accounts:lookup`, mutation: false, body: { localId: ids } });
const accountCreate = (b, uid, email, role, subject = false) =>
  b.add(role, {
    method: "POST",
    url: `${identity}/accounts`,
    body: { localId: uid, email, password: PASSWORD, emailVerified: false },
  }, { subject });
const accountDelete = (b, uid, role = "cleanup") =>
  b.add(role, { method: "POST", url: `${identity}/accounts:delete`, body: { localId: uid } });

function authStep(scenarioId, newId) {
  const b = new Builder(scenarioId, newId);
  const uid = newId("user");
  const email = `${uid}@example.test`;
  let seed = false;
  let matchKey = { kind: "auth", value: uid };
  let settle = POSITIVE_SETTLE_SECONDS;
  switch (scenarioId) {
    case "auth-admin-create":
      accountCreate(b, uid, email, "subject", true);
      accountLookup(b, [uid]);
      accountDelete(b, uid);
      accountLookup(b, [uid]);
      break;
    case "auth-signup":
      b.add("subject", {
        method: "POST",
        url: "https://identitytoolkit.googleapis.com/v1/accounts:signUp",
        auth: "apikey",
        body: { email, password: PASSWORD, returnSecureToken: true },
        capture: { uid: "$.localId" },
      }, { subject: true });
      accountLookup(b, ["${uid}"]);
      accountDelete(b, "${uid}");
      accountLookup(b, ["${uid}"]);
      matchKey = { kind: "auth", value: "${uid}" };
      break;
    case "auth-repeat-signin":
      accountCreate(b, uid, email, "setup");
      seed = true;
      b.add("subject", {
        method: "POST",
        url: "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword",
        auth: "apikey",
        body: { email, password: PASSWORD, returnSecureToken: true },
      }, { subject: true });
      accountLookup(b, [uid]);
      accountDelete(b, uid);
      accountLookup(b, [uid]);
      settle = NEGATIVE_WINDOW_SECONDS;
      break;
    case "auth-delete":
      accountCreate(b, uid, email, "setup");
      seed = true;
      b.add("subject", { method: "POST", url: `${identity}/accounts:delete`, body: { localId: uid } }, { subject: true });
      accountLookup(b, [uid]);
      break;
    case "auth-bulk-delete": {
      const second = newId("user");
      accountCreate(b, uid, email, "setup");
      accountCreate(b, second, `${second}@example.test`, "setup");
      seed = true;
      b.add("subject", {
        method: "POST",
        url: `${identity}/accounts:batchDelete`,
        body: { localIds: [uid, second], force: true },
      }, { subject: true });
      accountLookup(b, [uid, second]);
      matchKey = { kind: "auth", value: uid, values: [uid, second] };
      settle = NEGATIVE_WINDOW_SECONDS;
      break;
    }
    default:
      throw new Error(`not an Auth scenario: ${scenarioId}`);
  }
  return { b, matchKey, sourceResult: "typed-success", seed, settle };
}

const publish = (b, topic, text, extra = {}) =>
  b.add("subject", {
    method: "POST",
    url: `${topicUrl(topic)}:publish`,
    body: { messages: [{ data: Buffer.from(text).toString("base64"), attributes: { probe: text }, ...extra }] },
    capture: { messageId: "$.messageIds[0]" },
  }, { subject: true });

function pubsubStep(scenarioId, newId) {
  const b = new Builder(scenarioId, newId);
  const id = newId("msg");
  let topic = PRIMARY_TOPIC;
  let extra = {};
  let settle = POSITIVE_SETTLE_SECONDS;
  if (scenarioId === "pubsub-other-topic") {
    topic = CONTROL_TOPIC;
    settle = NEGATIVE_WINDOW_SECONDS;
  } else if (scenarioId === "pubsub-ordering") {
    extra = { orderingKey: "fe-events-order" };
  } else if (scenarioId !== "pubsub-publish") {
    throw new Error(`not a Pub/Sub scenario: ${scenarioId}`);
  }
  publish(b, topic, id, extra);
  return { b, matchKey: { kind: "pubsub", value: "${messageId}", topic, probe: id }, sourceResult: "typed-success", seed: false, settle };
}

// ---- a pass --------------------------------------------------------------------------------

const BUILDERS = { fs: firestoreStep, storage: storageStep, auth: authStep, pubsub: pubsubStep };

/**
 * One pass of the script. `newId(role)` makes a fresh resource id; the runner gives it a random
 * source, a test a counter. A step carries its requests in order, which of them is the observed
 * source call (`subject`), what that call should return, and how long the capture keeps watching.
 */
export function buildPass({ pass, newId }) {
  const steps = SCENARIO_ORDER.map((scenarioId) => {
    const built = BUILDERS[scenarioId.split("-")[0]](scenarioId, newId);
    return {
      scenarioId,
      role: "subject",
      family: FAMILY(scenarioId),
      requests: built.b.requests,
      subject: built.b.subject,
      matchKey: built.matchKey,
      expectedSourceResult: built.sourceResult,
      seedWaitSeconds: built.seed ? SEED_WAIT_SECONDS : 0,
      settleSeconds: built.settle,
    };
  });
  return { pass, steps };
}

export function passSummary({ steps }) {
  const perFamily = { requests: {}, mutations: {} };
  let seconds = 0;
  for (const step of steps) {
    const family = step.family;
    perFamily.requests[family] = (perFamily.requests[family] ?? 0) + step.requests.length;
    const writes = step.requests.filter(({ mutation }) => mutation).length;
    perFamily.mutations[family] = (perFamily.mutations[family] ?? 0) + writes;
    seconds += step.seedWaitSeconds + step.settleSeconds + STEP_GAP_SECONDS + step.requests.length;
  }
  const sum = (o) => Object.values(o).reduce((a, b) => a + b, 0);
  return {
    perFamily,
    requests: sum(perFamily.requests),
    mutations: sum(perFamily.mutations),
    minutes: Math.round(seconds / 60),
  };
}

// ---- once per run ---------------------------------------------------------------------------

/** The data resources the run creates before the pass and removes after the last. */
export function runSetupRequests() {
  return [
    { id: "setup.topic-primary", role: "setup", method: "PUT", url: topicUrl(PRIMARY_TOPIC), body: {}, auth: "oauth", mutation: true, expect: [200] },
    { id: "setup.topic-control", role: "setup", method: "PUT", url: topicUrl(CONTROL_TOPIC), body: {}, auth: "oauth", mutation: true, expect: [200] },
    {
      id: "setup.bucket-control",
      role: "setup",
      method: "POST",
      url: `https://storage.googleapis.com/storage/v1/b?project=${PROJECT}`,
      body: { name: CONTROL_BUCKET, location: "US-CENTRAL1" },
      auth: "oauth",
      mutation: true,
      expect: [200],
    },
    { id: "setup.topic-primary-get", role: "readback", method: "GET", url: topicUrl(PRIMARY_TOPIC), auth: "oauth", mutation: false, expect: [200] },
    { id: "setup.topic-control-get", role: "readback", method: "GET", url: topicUrl(CONTROL_TOPIC), auth: "oauth", mutation: false, expect: [200] },
  ];
}

export function runCleanupRequests() {
  return [
    { id: "cleanup.topic-primary", role: "cleanup", method: "DELETE", url: topicUrl(PRIMARY_TOPIC), auth: "oauth", mutation: true, expect: [200, 404] },
    { id: "cleanup.topic-control", role: "cleanup", method: "DELETE", url: topicUrl(CONTROL_TOPIC), auth: "oauth", mutation: true, expect: [200, 404] },
    { id: "cleanup.bucket-control", role: "cleanup", method: "DELETE", url: `https://storage.googleapis.com/storage/v1/b/${CONTROL_BUCKET}`, auth: "oauth", mutation: true, expect: [204, 404] },
  ];
}
