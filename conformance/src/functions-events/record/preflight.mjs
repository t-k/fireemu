// The preflight: reads only. The recorder never enables an API, creates a database or bucket, adds an
// IAM binding, changes Rules or initializes Auth; it checks that they are there and stops when they are
// not. Every check is a pure function of the parsed answer, so each can be tested on its own.

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

export const REQUIRED_APIS = [
  "artifactregistry.googleapis.com",
  "cloudbuild.googleapis.com",
  "cloudfunctions.googleapis.com",
  "cloudresourcemanager.googleapis.com",
  "eventarc.googleapis.com",
  "firebaserules.googleapis.com",
  "firebasestorage.googleapis.com",
  "firestore.googleapis.com",
  "identitytoolkit.googleapis.com",
  "logging.googleapis.com",
  "pubsub.googleapis.com",
  "run.googleapis.com",
  "storage.googleapis.com",
];

const get = (id, url, expect = [200]) => ({
  id: `preflight.${id}`,
  role: "preflight",
  method: "GET",
  url,
  auth: "oauth",
  mutation: false,
  expect,
});
const post = (id, url, body) => ({
  id: `preflight.${id}`,
  role: "preflight",
  method: "POST",
  url,
  auth: "oauth",
  mutation: false,
  expect: [200],
  body,
});
const region = `projects/${PROJECT}/locations/${REGION}`;
const lastSegment = (name) =>
  String(name ?? "")
    .split("/")
    .at(-1);
const ok = () => ({ ok: true });
const emptyList = (json, key, label) =>
  json?.nextPageToken
    ? bad(`the ${label} list has more than one page`)
    : (json?.[key] ?? []).length
      ? bad(`${label} already exist`)
      : ok();
const bad = (reason) => ({ ok: false, reason });

/**
 * The notification configs of a bucket (`storage#notifications`: `{ kind }` for none, `{ kind, items }` otherwise,
 * recorded on the primary bucket and on a bucket without any), as `{ id, topic, eventTypes, payloadFormat, etag }`
 * sorted by id; `null` when the answer is not that shape. The recorder only reads them: the one config the primary bucket
 * has is managed by Cloud Functions and is never deleted.
 */
export function notificationConfigs(json) {
  if (json?.kind !== "storage#notifications") return null;
  if (json.items === undefined) return [];
  if (!Array.isArray(json.items)) return null;
  const configs = [];
  for (const item of json.items) {
    if (!item || typeof item !== "object" || typeof item.id !== "string" || item.id === "")
      return null;
    configs.push({
      id: item.id,
      topic: item.topic ?? null,
      eventTypes: Array.isArray(item.event_types) ? item.event_types.toSorted() : null,
      payloadFormat: item.payload_format ?? null,
      etag: item.etag ?? null,
    });
  }
  return configs.toSorted((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
}

/** What changed between two reads of the configs: new ids, ids that are gone, ids whose config differs. Only a new one is a problem. */
export function notificationDiff(before, after) {
  const was = new Map(before.map((config) => [config.id, config]));
  const is = new Map(after.map((config) => [config.id, config]));
  return {
    before: before.map((config) => config.id),
    after: after.map((config) => config.id),
    added: [...is.keys()].filter((id) => !was.has(id)),
    removed: [...was.keys()].filter((id) => !is.has(id)),
    changed: [...is.keys()].filter(
      (id) => was.has(id) && JSON.stringify(was.get(id)) !== JSON.stringify(is.get(id)),
    ),
  };
}

/** The preflight steps in order. `check(answer, context)` returns {ok, reason}; it may add to `context`. */
export const PREFLIGHT = [
  {
    ...get("project", `https://cloudresourcemanager.googleapis.com/v1/projects/${PROJECT}`),
    check: ({ json }, context) => {
      if (json?.projectId !== PROJECT || json?.lifecycleState !== "ACTIVE")
        return bad("the project is not the active sandbox project");
      if (!/^[0-9]{6,20}$/.test(json.projectNumber ?? ""))
        return bad("the project number is not typed");
      context.projectNumber = json.projectNumber;
      return ok();
    },
  },
  {
    ...get(
      "services",
      `https://serviceusage.googleapis.com/v1/projects/${PROJECT}/services?filter=state:ENABLED&pageSize=200`,
    ),
    check: ({ json }, context) => {
      if (json?.nextPageToken) return bad("the enabled-services list has more than one page");
      const enabled = new Set((json?.services ?? []).map((s) => s?.config?.name));
      context.servicesBefore = [...enabled];
      const missing = REQUIRED_APIS.filter((api) => !enabled.has(api));
      return missing.length ? bad(`APIs not enabled: ${missing.join(", ")}`) : ok();
    },
  },
  {
    ...get(
      "firestore-database",
      `https://firestore.googleapis.com/v1/projects/${PROJECT}/databases/(default)`,
    ),
    check: ({ json }) =>
      json?.type === "FIRESTORE_NATIVE"
        ? ok()
        : bad("the (default) Firestore database is missing or not native"),
  },
  {
    ...get(
      "primary-bucket",
      `https://storage.googleapis.com/storage/v1/b/${encodeURIComponent(PRIMARY_BUCKET)}?fields=versioning`,
    ),
    check: ({ json }) =>
      json?.versioning?.enabled === true
        ? bad("the primary bucket already has versioning enabled (the restore would be wrong)")
        : ok(),
  },
  {
    ...get(
      "notification-configs",
      `https://storage.googleapis.com/storage/v1/b/${encodeURIComponent(PRIMARY_BUCKET)}/notificationConfigs`,
    ),
    check: ({ json }, context) => {
      const configs = notificationConfigs(json);
      if (configs === null)
        return bad("the primary bucket's notification configs are not a list of configs");
      context.notificationsBefore = configs;
      return ok();
    },
  },
  {
    ...get(
      "control-bucket",
      `https://storage.googleapis.com/storage/v1/b/${encodeURIComponent(CONTROL_BUCKET)}?fields=versioning`,
      [404],
    ),
    check: ({ status }) =>
      status === 404 ? ok() : bad("the control bucket already exists (the recorder creates it)"),
  },
  {
    ...get("topics", `https://pubsub.googleapis.com/v1/projects/${PROJECT}/topics?pageSize=100`),
    check: ({ json }) => {
      if (json?.nextPageToken) return bad("the topic list has more than one page");
      const names = new Set((json?.topics ?? []).map((t) => lastSegment(t?.name)));
      const present = [PRIMARY_TOPIC, CONTROL_TOPIC].filter((t) => names.has(t));
      return present.length ? bad(`topics already exist: ${present.join(", ")}`) : ok();
    },
  },
  {
    ...get(
      "artifact-repository",
      `https://artifactregistry.googleapis.com/v1/${region}/repositories/gcf-artifacts`,
    ),
    check: ({ json }) =>
      String(json?.name ?? "").endsWith("/repositories/gcf-artifacts")
        ? ok()
        : bad("the gcf-artifacts repository is missing"),
  },
  {
    ...get(
      "artifact-packages",
      `https://artifactregistry.googleapis.com/v1/${region}/repositories/gcf-artifacts/packages?pageSize=100`,
      [200, 404],
    ),
    check: () => ok(),
  },
  {
    ...post(
      "iam",
      `https://cloudresourcemanager.googleapis.com/v1/projects/${PROJECT}:getIamPolicy`,
      {},
    ),
    check: ({ json }, context) => {
      context.iamBefore = json;
      const member = `serviceAccount:service-${context.projectNumber}@gcp-sa-eventarc.iam.gserviceaccount.com`;
      const held = (json?.bindings ?? []).some(
        (b) =>
          b.role === "roles/eventarc.serviceAgent" &&
          !b.condition &&
          (b.members ?? []).includes(member),
      );
      return held
        ? ok()
        : bad("the Eventarc service agent does not hold roles/eventarc.serviceAgent");
    },
  },
  {
    ...get(
      "auth-config",
      `https://identitytoolkit.googleapis.com/admin/v2/projects/${PROJECT}/config`,
    ),
    check: ({ json }) =>
      json?.signIn?.email?.enabled === true
        ? ok()
        : bad("Authentication is not initialized with email/password enabled"),
  },
  {
    ...get(
      "rules-release",
      `https://firebaserules.googleapis.com/v1/projects/${PROJECT}/releases/cloud.firestore`,
    ),
    check: ({ json }, context) => {
      const ruleset = String(json?.rulesetName ?? "");
      if (!/^projects\/[^/]+\/rulesets\/[A-Za-z0-9-]+$/.test(ruleset))
        return bad("no Firestore Rules release");
      context.rulesetId = ruleset.split("/").at(-1);
      return ok();
    },
  },
  {
    // The client write of the auth-context scenario needs a Rules release that lets a signed-in user create in the primary collection.
    id: "preflight.rules-ruleset",
    role: "preflight",
    method: "GET",
    url: `https://firebaserules.googleapis.com/v1/projects/${PROJECT}/rulesets/\${rulesetId}`,
    auth: "oauth",
    mutation: false,
    expect: [200],
    check: ({ json }) => {
      const source = (json?.source?.files ?? []).map((f) => f?.content ?? "").join("\n");
      return source.includes(PRIMARY_COLLECTION) && source.includes("request.auth")
        ? ok()
        : bad("the released Rules do not mention the primary collection and request.auth");
    },
  },
  // The region and the run's namespaces must be empty: the cleanup and the CLI's name filters (prefix matches) then cannot touch anything that is not the run's.
  ...[
    [
      "functions-v1",
      `https://cloudfunctions.googleapis.com/v1/${region}/functions`,
      "functions",
      "Gen1 functions",
    ],
    [
      "functions-v2",
      `https://cloudfunctions.googleapis.com/v2/${region}/functions`,
      "functions",
      "Gen2 functions",
    ],
    [
      "run-services",
      `https://run.googleapis.com/v2/${region}/services`,
      "services",
      "Cloud Run services",
    ],
    [
      "eventarc-triggers",
      `https://eventarc.googleapis.com/v1/${region}/triggers`,
      "triggers",
      "Eventarc triggers",
    ],
  ].map(([id, url, key, label]) => ({
    ...get(id, url),
    check: ({ json }) => emptyList(json, key, label),
  })),
  ...["fe-events/", "other/"].map((prefix) => ({
    ...get(
      `objects-${prefix.replace("/", "")}`,
      `https://storage.googleapis.com/storage/v1/b/${encodeURIComponent(PRIMARY_BUCKET)}/o?versions=true&prefix=${encodeURIComponent(prefix)}`,
    ),
    check: ({ json }) => emptyList(json, "items", `objects under ${prefix} in the primary bucket`),
  })),
  ...[PRIMARY_COLLECTION, CONTROL_COLLECTION, MARKER_COLLECTION].map((collection) => ({
    ...post(
      `collection-${collection}`,
      `https://firestore.googleapis.com/v1/projects/${PROJECT}/databases/(default)/documents:runQuery`,
      { structuredQuery: { from: [{ collectionId: collection }], limit: 1 } },
    ),
    check: ({ json }) => {
      const found = Array.isArray(json) ? json.filter((row) => row?.document) : null;
      if (found === null) return bad(`the ${collection} query did not answer with a list`);
      return found.length ? bad(`the ${collection} collection is not empty`) : ok();
    },
  })),
  // The browser API key belongs to the sandbox project (read with the key, no credential; the answer names the project number).
  {
    id: "preflight.api-key-project",
    role: "preflight",
    method: "GET",
    url: "https://identitytoolkit.googleapis.com/v1/projects",
    auth: "apikey",
    mutation: false,
    expect: [200],
    // Identity Toolkit answers `projectId` with the project NUMBER (a digit string); it is compared with
    // the number the same run read from the project itself, never with a number written in the code.
    check: ({ json }, context) => {
      const digits = /^[0-9]{6,20}$/;
      if (typeof context.projectNumber !== "string" || !digits.test(context.projectNumber)) {
        return bad("the project number of this run is not known, so the API key cannot be bound");
      }
      if (typeof json?.projectId !== "string" || !digits.test(json.projectId)) {
        return bad("the API key's project answer is not a project number");
      }
      return json.projectId === context.projectNumber
        ? ok()
        : bad("the API key does not belong to the sandbox project");
    },
  },
];

/**
 * Runs every step through `request(spec, vars)` (the transport) and returns the problems. Reading
 * the answers is the transport's job; a step whose request fails to answer is a problem too.
 */
export async function runPreflight(request) {
  const context = {};
  const problems = [];
  for (const step of PREFLIGHT) {
    const { check, ...spec } = step;
    const request_ = { ...spec, url: spec.url };
    let answer;
    try {
      answer = await request(request_, context);
    } catch (error) {
      problems.push(`${step.id}: ${error.message}`);
      continue;
    }
    if (answer.skipped) continue;
    if (answer.kind === "unknown") {
      problems.push(`${step.id}: no usable answer`);
      continue;
    }
    if (!step.expect.includes(answer.status)) {
      problems.push(`${step.id}: HTTP ${answer.status}`);
      continue;
    }
    const verdict = check(answer, context);
    if (!verdict.ok) problems.push(`${step.id}: ${verdict.reason}`);
  }
  return {
    problems,
    projectNumber: context.projectNumber ?? null,
    iamBefore: context.iamBefore ?? null,
    servicesBefore: context.servicesBefore ?? null,
    notificationsBefore: context.notificationsBefore ?? null,
  };
}

/** The (role, member) pairs of an IAM policy as strings, user accounts redacted: enough to name what a deploy added. */
export function iamPairs(policy) {
  const pairs = [];
  for (const binding of policy?.bindings ?? []) {
    for (const member of binding.members ?? [])
      pairs.push(
        `${binding.role} ${member.startsWith("user:") ? "user:<redacted>" : member}${binding.condition ? " (conditional)" : ""}`,
      );
  }
  return pairs.toSorted();
}

export function iamDiff(before, after) {
  const was = new Set(iamPairs(before));
  const is = new Set(iamPairs(after));
  return { added: [...is].filter((p) => !was.has(p)), removed: [...was].filter((p) => !is.has(p)) };
}
