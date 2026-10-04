// The destination guard: every request the recorder sends must match one rule here (method, host,
// path shape, query keys and whether it changes anything). A request that matches none is refused
// before it leaves the process. The rules name the declared resources only: the project, the
// region, the two collections plus the marker collection, the two buckets, the two topics.

import {
  CONTROL_BUCKET,
  CONTROL_COLLECTION,
  MARKER_COLLECTION,
  PRIMARY_BUCKET,
  PRIMARY_COLLECTION,
  PRIMARY_TOPIC,
  CONTROL_TOPIC,
  PROJECT,
  REGION,
} from "./script.mjs";

const P = PROJECT.replaceAll("-", "\\-");
const COLLECTIONS = [PRIMARY_COLLECTION, CONTROL_COLLECTION, MARKER_COLLECTION].join("|");
const BUCKETS = [PRIMARY_BUCKET, CONTROL_BUCKET].map((b) => b.replaceAll(".", "\\.")).join("|");
const TOPICS = [PRIMARY_TOPIC, CONTROL_TOPIC].join("|");
const ID = "[A-Za-z0-9_-]{1,128}";
const OBJECT = "(?:fe-events|other)%2F[A-Za-z0-9_-]{1,128}\\.txt";
const rule = (name, method, host, path, { query = [], mutation = false } = {}) => ({
  name,
  method,
  host,
  path: new RegExp(`^${path}$`),
  query: new Set(query),
  mutation,
});

const fs = (tail) => `/v1/projects/${P}/databases/\\(default\\)/documents${tail}`;
const storage = `/storage/v1/b/(?:${BUCKETS})`;
const identity = `/v1/projects/${P}`;

export const RULES = [
  // Firestore data: the declared collections only.
  rule("firestore-create", "POST", "firestore.googleapis.com", fs(`/(?:${COLLECTIONS})`), {
    query: ["documentId"],
    mutation: true,
  }),
  rule("firestore-get", "GET", "firestore.googleapis.com", fs(`/(?:${COLLECTIONS})/${ID}`)),
  rule("firestore-patch", "PATCH", "firestore.googleapis.com", fs(`/(?:${COLLECTIONS})/${ID}`), {
    query: ["updateMask.fieldPaths", "currentDocument.exists"],
    mutation: true,
  }),
  rule("firestore-delete", "DELETE", "firestore.googleapis.com", fs(`/(?:${COLLECTIONS})/${ID}`), {
    mutation: true,
  }),
  rule("firestore-query", "POST", "firestore.googleapis.com", fs(":runQuery")),
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
  }),
  rule("storage-object-get", "GET", "storage.googleapis.com", `${storage}/o/${OBJECT}`),
  rule("storage-object-patch", "PATCH", "storage.googleapis.com", `${storage}/o/${OBJECT}`, {
    mutation: true,
  }),
  rule("storage-object-delete", "DELETE", "storage.googleapis.com", `${storage}/o/${OBJECT}`, {
    query: ["generation"],
    mutation: true,
  }),
  rule("storage-object-list", "GET", "storage.googleapis.com", `${storage}/o`, {
    query: ["versions", "prefix", "maxResults"],
  }),
  rule("storage-bucket-get", "GET", "storage.googleapis.com", storage, { query: ["fields"] }),
  rule(
    "storage-bucket-versioning",
    "PATCH",
    "storage.googleapis.com",
    `/storage/v1/b/(?:${BUCKETS})`,
    { query: ["fields"], mutation: true },
  ),
  rule("storage-control-bucket-create", "POST", "storage.googleapis.com", "/storage/v1/b", {
    query: ["project"],
    mutation: true,
  }),
  rule(
    "storage-control-bucket-delete",
    "DELETE",
    "storage.googleapis.com",
    `/storage/v1/b/${CONTROL_BUCKET}`,
    { mutation: true },
  ),
  // Auth: the project's accounts, and the two client calls with the API key.
  rule("auth-create", "POST", "identitytoolkit.googleapis.com", `${identity}/accounts`, {
    mutation: true,
  }),
  rule("auth-lookup", "POST", "identitytoolkit.googleapis.com", `${identity}/accounts:lookup`),
  rule("auth-delete", "POST", "identitytoolkit.googleapis.com", `${identity}/accounts:delete`, {
    mutation: true,
  }),
  rule(
    "auth-batch-delete",
    "POST",
    "identitytoolkit.googleapis.com",
    `${identity}/accounts:batchDelete`,
    { mutation: true },
  ),
  rule("auth-sign-up", "POST", "identitytoolkit.googleapis.com", "/v1/accounts:signUp", {
    mutation: true,
  }),
  rule(
    "auth-sign-in",
    "POST",
    "identitytoolkit.googleapis.com",
    "/v1/accounts:signInWithPassword",
    { mutation: true },
  ),
  rule("auth-config", "GET", "identitytoolkit.googleapis.com", `/admin/v2/projects/${P}/config`),
  // Pub/Sub: the two topics; list reads.
  rule(
    "pubsub-topic-create",
    "PUT",
    "pubsub.googleapis.com",
    `/v1/projects/${P}/topics/(?:${TOPICS})`,
    { mutation: true },
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
    { mutation: true },
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
  rule("logging-list", "POST", "logging.googleapis.com", "/v2/entries:list"),
  // Deploy readiness and cleanup verification: lists only.
  rule(
    "functions-v1-list",
    "GET",
    "cloudfunctions.googleapis.com",
    `/v1/projects/${P}/locations/${REGION}/functions`,
    { query: ["pageToken"] },
  ),
  rule(
    "functions-v2-list",
    "GET",
    "cloudfunctions.googleapis.com",
    `/v2/projects/${P}/locations/${REGION}/functions`,
    { query: ["pageToken"] },
  ),
  rule(
    "run-services-list",
    "GET",
    "run.googleapis.com",
    `/v2/projects/${P}/locations/${REGION}/services`,
    { query: ["pageToken"] },
  ),
  rule(
    "eventarc-triggers-list",
    "GET",
    "eventarc.googleapis.com",
    `/v1/projects/${P}/locations/${REGION}/triggers`,
    { query: ["pageToken"] },
  ),
  rule(
    "artifact-registry-read",
    "GET",
    "artifactregistry.googleapis.com",
    `/v1/projects/${P}/locations/${REGION}/repositories/gcf\\-artifacts(?:/packages(?:/[A-Za-z0-9%_.-]+/versions)?)?`,
    { query: ["pageSize", "pageToken"] },
  ),
  rule(
    "artifact-registry-repository",
    "GET",
    "artifactregistry.googleapis.com",
    `/v1/projects/${P}/locations/${REGION}/repositories`,
    { query: ["pageToken"] },
  ),
  rule(
    "iam-policy-read",
    "POST",
    "cloudresourcemanager.googleapis.com",
    `/v1/projects/${P}:getIamPolicy`,
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
  rule("oauth-token", "POST", "oauth2.googleapis.com", "/token"),
];

// Which destinations get `x-goog-user-project`. The header names the quota project of the owner's
// authorized-user credential, which these API calls need; it is wrong on the calls that do not carry
// that credential (the two client sign-in calls use the API key, the token refresh has none), and
// some Google endpoints refuse it outright (oauth2/v2/userinfo answers 403 USER_PROJECT_DENIED), so the
// decision is made per rule here and pinned by a test, never for every request.
const WITHOUT_QUOTA_PROJECT = new Set(["auth-sign-up", "auth-sign-in", "oauth-token"]);
export const quotaProjectFor = (ruleName) => !WITHOUT_QUOTA_PROJECT.has(ruleName);

/** The rule a resolved request (no placeholders left) matches, or a reason it may not be sent. */
export function destination({ method, url, mutation }) {
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
    if (keys.some((key) => !entry.query.has(key) && key !== "key")) {
      return { problem: `${entry.name}: a query parameter is not declared` };
    }
    if (keys.includes("key") && !["auth-sign-up", "auth-sign-in"].includes(entry.name)) {
      return { problem: `${entry.name}: an API key may only go to the two client sign-in calls` };
    }
    if (entry.mutation !== Boolean(mutation)) {
      return {
        problem: `${entry.name}: the request says mutation=${Boolean(mutation)} but the rule says ${entry.mutation}`,
      };
    }
    return { rule: entry.name, quotaProject: quotaProjectFor(entry.name) };
  }
  return { problem: `no rule allows ${method} ${parsed.hostname}${parsed.pathname}` };
}
