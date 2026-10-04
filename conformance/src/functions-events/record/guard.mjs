// The destination guard: every request the recorder sends must match one rule here: method, host,
// path shape, query keys and values, the body, and whether the request changes anything. A request
// that matches none is refused before it leaves the process. The rules name the declared resources
// only: the project, the region, the two collections plus the marker collection, the two buckets, the
// two topics, the owned object prefixes and the test user email domain.

import {
  CONTROL_BUCKET,
  CONTROL_COLLECTION,
  CONTROL_TOPIC,
  MARKER_COLLECTION,
  PRIMARY_BUCKET,
  PRIMARY_COLLECTION,
  PRIMARY_TOPIC,
  PROJECT,
  REGION,
} from "./script.mjs";

const P = PROJECT.replaceAll("-", "\\-");
const COLLECTION_LIST = [PRIMARY_COLLECTION, CONTROL_COLLECTION, MARKER_COLLECTION];
const COLLECTIONS = COLLECTION_LIST.join("|");
const BUCKETS = [PRIMARY_BUCKET, CONTROL_BUCKET].map((b) => b.replaceAll(".", "\\.")).join("|");
const TOPICS = [PRIMARY_TOPIC, CONTROL_TOPIC].join("|");
const ID = "[A-Za-z0-9_-]{1,128}";
const OBJECT = "(?:fe-events|other)%2F[A-Za-z0-9_-]{1,128}\\.txt";
const OBJECT_NAME = /^(?:fe-events|other)\/[A-Za-z0-9_-]{1,128}\.txt$/;
const OBJECT_PREFIX = /^(?:fe-events|other)\/(?:[A-Za-z0-9_-]{1,128}\.txt)?$/;
const FIELD_NAMES = ["fixtureKind", "value", "count"];

// ---- body and value checks (each returns a problem text or undefined) ---------------------------

const isObject = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const onlyKeys = (value, allowed) =>
  isObject(value) && Object.keys(value).every((key) => allowed.includes(key));
const exactKeys = (value, keys) =>
  isObject(value) && Object.keys(value).length === keys.length && keys.every((key) => key in value);
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const noBody = ({ body }) => (body === undefined ? undefined : "this request takes no body");
const emailOk = (email) =>
  typeof email === "string" && /^[A-Za-z0-9_-]{1,160}@example\.test$/.test(email);

const documentFields = (body) => {
  if (!onlyKeys(body, ["fields"]) || !isObject(body.fields))
    return "the document body must be {fields}";
  return onlyKeys(body.fields, FIELD_NAMES)
    ? undefined
    : "the document has a field outside fixtureKind, value and count";
};

const rule = (name, method, host, path, { query = [], mutation = false, check = noBody } = {}) => ({
  name,
  method,
  host,
  path: new RegExp(`^${path}$`),
  query: new Set(query),
  mutation,
  check,
});

const fs = (tail) => `/v1/projects/${P}/databases/\\(default\\)/documents${tail}`;
const storage = `/storage/v1/b/(?:${BUCKETS})`;
const identity = `/v1/projects/${P}`;
const region = `/projects/${P}/locations/${REGION}`;

export const RULES = [
  // Firestore data: the declared collections only.
  rule("firestore-create", "POST", "firestore.googleapis.com", fs(`/(?:${COLLECTIONS})`), {
    query: ["documentId"],
    mutation: true,
    check: ({ params, body }) =>
      new RegExp(`^${ID}$`).test(params.get("documentId") ?? "")
        ? documentFields(body)
        : "documentId is not an owned id",
  }),
  rule("firestore-get", "GET", "firestore.googleapis.com", fs(`/(?:${COLLECTIONS})/${ID}`)),
  rule("firestore-patch", "PATCH", "firestore.googleapis.com", fs(`/(?:${COLLECTIONS})/${ID}`), {
    query: ["updateMask.fieldPaths", "currentDocument.exists"],
    mutation: true,
    check: ({ params, body }) => {
      if (params.get("currentDocument.exists") !== "true")
        return "a patch must carry currentDocument.exists=true";
      if (
        !params.getAll("updateMask.fieldPaths").every((name) => ["value", "count"].includes(name))
      )
        return "the update mask names a field outside value and count";
      return documentFields(body);
    },
  }),
  rule("firestore-delete", "DELETE", "firestore.googleapis.com", fs(`/(?:${COLLECTIONS})/${ID}`), {
    mutation: true,
  }),
  rule("firestore-query", "POST", "firestore.googleapis.com", fs(":runQuery"), {
    check: ({ body }) => {
      const query = body?.structuredQuery;
      if (!exactKeys(body, ["structuredQuery"]) || !onlyKeys(query, ["from", "where", "limit"]))
        return "the query body is not a structured query";
      const from = query.from;
      return Array.isArray(from) &&
        from.length === 1 &&
        COLLECTION_LIST.includes(from[0]?.collectionId)
        ? undefined
        : "the query reads a collection that is not declared";
    },
  }),
  rule(
    "firestore-database",
    "GET",
    "firestore.googleapis.com",
    `/v1/projects/${P}/databases/\\(default\\)`,
  ),
  // Storage: the declared buckets, the owned object names, the versioning field, the control bucket's life.
  rule("storage-upload", "POST", "storage.googleapis.com", `/upload${storage}/o`, {
    query: ["uploadType", "name", "ifGenerationMatch"],
    mutation: true,
    check: ({ params, body, headers }) => {
      if (params.get("uploadType") !== "media") return "an upload must be uploadType=media";
      if (!OBJECT_NAME.test(params.get("name") ?? ""))
        return "the object name is outside the owned prefixes";
      if (params.has("ifGenerationMatch") && params.get("ifGenerationMatch") !== "0")
        return "ifGenerationMatch may only be 0";
      if (typeof body !== "string" || body.length > 64)
        return "the upload body is not a short text";
      return Object.keys(headers ?? {}).every((name) => name.toLowerCase() === "x-goog-hash")
        ? undefined
        : "an upload may only add x-goog-hash";
    },
  }),
  rule("storage-object-get", "GET", "storage.googleapis.com", `${storage}/o/${OBJECT}`),
  rule("storage-object-patch", "PATCH", "storage.googleapis.com", `${storage}/o/${OBJECT}`, {
    mutation: true,
    check: ({ body }) =>
      isObject(body) &&
      exactKeys(body, ["metadata"]) &&
      exactKeys(body.metadata, ["fixtureMarker"]) &&
      typeof body.metadata.fixtureMarker === "string"
        ? undefined
        : "an object patch may only set metadata.fixtureMarker",
  }),
  rule("storage-object-delete", "DELETE", "storage.googleapis.com", `${storage}/o/${OBJECT}`, {
    query: ["generation"],
    mutation: true,
    check: ({ params, body }) =>
      /^[0-9]{1,20}$/.test(params.get("generation") ?? "0")
        ? noBody({ body })
        : "the generation is not a number",
  }),
  rule("storage-object-list", "GET", "storage.googleapis.com", `${storage}/o`, {
    query: ["versions", "prefix", "maxResults"],
    check: ({ params, body }) =>
      OBJECT_PREFIX.test(params.get("prefix") ?? "") &&
      (!params.has("versions") || params.get("versions") === "true")
        ? noBody({ body })
        : "an object list must name an owned prefix",
  }),
  rule("storage-bucket-get", "GET", "storage.googleapis.com", storage, { query: ["fields"] }),
  rule(
    "storage-bucket-versioning",
    "PATCH",
    "storage.googleapis.com",
    `/storage/v1/b/(?:${BUCKETS})`,
    {
      query: ["fields"],
      mutation: true,
      check: ({ params, body }) =>
        params.get("fields") === "versioning" &&
        exactKeys(body, ["versioning"]) &&
        exactKeys(body.versioning, ["enabled"]) &&
        typeof body.versioning.enabled === "boolean"
          ? undefined
          : "a bucket patch may only set versioning.enabled",
    },
  ),
  rule("storage-control-bucket-create", "POST", "storage.googleapis.com", "/storage/v1/b", {
    query: ["project"],
    mutation: true,
    check: ({ params, body }) =>
      params.get("project") === PROJECT &&
      exactKeys(body, ["name", "location"]) &&
      body.name === CONTROL_BUCKET &&
      body.location === "US-CENTRAL1"
        ? undefined
        : "only the control bucket may be created, in the sandbox project",
  }),
  rule("storage-bucket-list", "GET", "storage.googleapis.com", "/storage/v1/b", {
    query: ["project", "prefix"],
    check: ({ params, body }) =>
      params.get("project") === PROJECT && params.get("prefix") === CONTROL_BUCKET
        ? noBody({ body })
        : "a bucket list must name the sandbox project and the control bucket prefix",
  }),
  rule(
    "storage-control-bucket-delete",
    "DELETE",
    "storage.googleapis.com",
    `/storage/v1/b/${CONTROL_BUCKET}`,
    { mutation: true },
  ),
  // Auth: the project's accounts, the two client calls with the API key, and the key's project.
  rule("auth-create", "POST", "identitytoolkit.googleapis.com", `${identity}/accounts`, {
    mutation: true,
    check: ({ body }) =>
      onlyKeys(body, ["localId", "email", "password", "emailVerified"]) && emailOk(body.email)
        ? undefined
        : "an account may only be created with a test email",
  }),
  rule("auth-lookup", "POST", "identitytoolkit.googleapis.com", `${identity}/accounts:lookup`, {
    check: ({ body }) =>
      exactKeys(body, ["localId"]) || exactKeys(body, ["email"])
        ? undefined
        : "a lookup is by localId or by email",
  }),
  rule("auth-delete", "POST", "identitytoolkit.googleapis.com", `${identity}/accounts:delete`, {
    mutation: true,
    check: ({ body }) =>
      exactKeys(body, ["localId"]) && typeof body.localId === "string"
        ? undefined
        : "a delete names one localId",
  }),
  rule(
    "auth-batch-delete",
    "POST",
    "identitytoolkit.googleapis.com",
    `${identity}/accounts:batchDelete`,
    {
      mutation: true,
      check: ({ body }) =>
        exactKeys(body, ["localIds", "force"]) &&
        Array.isArray(body.localIds) &&
        body.localIds.length <= 10 &&
        body.force === true
          ? undefined
          : "a batch delete names a few localIds with force",
    },
  ),
  rule("auth-sign-up", "POST", "identitytoolkit.googleapis.com", "/v1/accounts:signUp", {
    mutation: true,
    check: ({ body }) =>
      exactKeys(body, ["email", "password", "returnSecureToken"]) && emailOk(body.email)
        ? undefined
        : "a sign-up uses a test email",
  }),
  rule(
    "auth-sign-in",
    "POST",
    "identitytoolkit.googleapis.com",
    "/v1/accounts:signInWithPassword",
    {
      mutation: true,
      check: ({ body }) =>
        exactKeys(body, ["email", "password", "returnSecureToken"]) && emailOk(body.email)
          ? undefined
          : "a sign-in uses a test email",
    },
  ),
  rule("auth-config", "GET", "identitytoolkit.googleapis.com", `/admin/v2/projects/${P}/config`),
  // The API key's project: the answer names the project that owns the key (read with the key, no credential).
  rule("auth-key-project", "GET", "identitytoolkit.googleapis.com", "/v1/projects"),
  // Pub/Sub: the two topics; list reads.
  rule(
    "pubsub-topic-create",
    "PUT",
    "pubsub.googleapis.com",
    `/v1/projects/${P}/topics/(?:${TOPICS})`,
    {
      mutation: true,
      check: ({ body }) => (same(body, {}) ? undefined : "a topic is created with an empty body"),
    },
  ),
  rule(
    "pubsub-topic-get",
    "GET",
    "pubsub.googleapis.com",
    `/v1/projects/${P}/topics/(?:${TOPICS})`,
  ),
  rule(
    "pubsub-topic-delete",
    "DELETE",
    "pubsub.googleapis.com",
    `/v1/projects/${P}/topics/(?:${TOPICS})`,
    { mutation: true },
  ),
  rule(
    "pubsub-publish",
    "POST",
    "pubsub.googleapis.com",
    `/v1/projects/${P}/topics/(?:${TOPICS}):publish`,
    {
      mutation: true,
      check: ({ body }) => {
        const messages = body?.messages;
        if (!exactKeys(body, ["messages"]) || !Array.isArray(messages) || messages.length !== 1)
          return "a publish carries exactly one message";
        return onlyKeys(messages[0], ["data", "attributes", "orderingKey"])
          ? undefined
          : "a message has a member outside data, attributes and orderingKey";
      },
    },
  ),
  rule("pubsub-topic-list", "GET", "pubsub.googleapis.com", `/v1/projects/${P}/topics`, {
    query: ["pageSize", "pageToken"],
  }),
  rule(
    "pubsub-subscription-list",
    "GET",
    "pubsub.googleapis.com",
    `/v1/projects/${P}/subscriptions`,
    { query: ["pageSize", "pageToken"] },
  ),
  // The capture.
  rule("logging-list", "POST", "logging.googleapis.com", "/v2/entries:list", {
    check: ({ body }) => {
      if (!onlyKeys(body, ["resourceNames", "filter", "orderBy", "pageSize", "pageToken"]))
        return "a log read has a member outside the declared ones";
      if (!same(body.resourceNames, [`projects/${PROJECT}`]))
        return "a log read must name only the sandbox project";
      return body.pageSize <= 200 ? undefined : "a log page may hold at most 200 entries";
    },
  }),
  // Deploy readiness and cleanup verification: lists only.
  rule("functions-v1-list", "GET", "cloudfunctions.googleapis.com", `/v1${region}/functions`, {
    query: ["pageToken"],
  }),
  rule("functions-v2-list", "GET", "cloudfunctions.googleapis.com", `/v2${region}/functions`, {
    query: ["pageToken"],
  }),
  rule("run-services-list", "GET", "run.googleapis.com", `/v2${region}/services`, {
    query: ["pageToken"],
  }),
  rule("eventarc-triggers-list", "GET", "eventarc.googleapis.com", `/v1${region}/triggers`, {
    query: ["pageToken"],
  }),
  rule(
    "artifact-registry-read",
    "GET",
    "artifactregistry.googleapis.com",
    `/v1${region}/repositories/gcf\\-artifacts(?:/packages(?:/[A-Za-z0-9%_.-]+/versions)?)?`,
    { query: ["pageSize", "pageToken"] },
  ),
  rule(
    "artifact-registry-repository",
    "GET",
    "artifactregistry.googleapis.com",
    `/v1${region}/repositories`,
    { query: ["pageToken"] },
  ),
  rule(
    "iam-policy-read",
    "POST",
    "cloudresourcemanager.googleapis.com",
    `/v1/projects/${P}:getIamPolicy`,
    {
      check: ({ body }) => (same(body, {}) ? undefined : "an IAM read has an empty body"),
    },
  ),
  rule("project-read", "GET", "cloudresourcemanager.googleapis.com", `/v1/projects/${P}`),
  rule("services-read", "GET", "serviceusage.googleapis.com", `/v1/projects/${P}/services`, {
    query: ["filter", "pageSize", "pageToken"],
  }),
  rule(
    "rules-release-read",
    "GET",
    "firebaserules.googleapis.com",
    `/v1/projects/${P}/releases/cloud\\.firestore`,
  ),
  rule(
    "rules-ruleset-read",
    "GET",
    "firebaserules.googleapis.com",
    `/v1/projects/${P}/rulesets/[A-Za-z0-9-]+`,
  ),
];

// Which destinations get `x-goog-user-project`. The header names the quota project of the owner's
// credential, which these API calls need; it is wrong on the calls that do not carry that credential
// (the client sign-in calls and the key's project read use the API key), and some Google endpoints
// refuse it outright (oauth2/v2/userinfo answers 403 USER_PROJECT_DENIED), so the decision is made per
// rule here and pinned by a test, never for every request.
const WITHOUT_QUOTA_PROJECT = new Set(["auth-sign-up", "auth-sign-in", "auth-key-project"]);
export const quotaProjectFor = (ruleName) => !WITHOUT_QUOTA_PROJECT.has(ruleName);

/**
 * The rule a resolved request (no placeholders left) matches, or a reason it may not be sent. `body`
 * is the resolved body (an object, or a string for a text upload) and `headers` the extra headers.
 */
export function destination({ method, url, mutation, body, headers }) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return { problem: "the URL does not parse" };
  }
  if (
    parsed.protocol !== "https:" ||
    parsed.port ||
    parsed.username ||
    parsed.password ||
    parsed.hash
  ) {
    return { problem: "only a plain https URL without credentials, port or fragment may be sent" };
  }
  for (const entry of RULES) {
    if (
      entry.method !== method ||
      entry.host !== parsed.hostname ||
      !entry.path.test(parsed.pathname)
    )
      continue;
    const keys = [...parsed.searchParams.keys()];
    if (keys.some((key) => !entry.query.has(key) && key !== "key"))
      return { problem: `${entry.name}: a query parameter is not declared` };
    if (
      keys.includes("key") &&
      !["auth-sign-up", "auth-sign-in", "auth-key-project"].includes(entry.name)
    ) {
      return {
        problem: `${entry.name}: an API key may only go to the two client sign-in calls and the key's project read`,
      };
    }
    if (entry.mutation !== Boolean(mutation))
      return {
        problem: `${entry.name}: the request says mutation=${Boolean(mutation)} but the rule says ${entry.mutation}`,
      };
    const problem = entry.check({ params: parsed.searchParams, body, headers });
    if (problem) return { problem: `${entry.name}: ${problem}` };
    return { rule: entry.name, quotaProject: quotaProjectFor(entry.name) };
  }
  return { problem: `no rule allows ${method} ${parsed.hostname}${parsed.pathname}` };
}
