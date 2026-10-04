// The preflight: reads only. The recorder never enables an API, creates a database or bucket, adds an
// IAM binding, changes Rules or initializes Auth; it checks that they are there and stops when they are
// not. Every check is a pure function of the parsed answer, so each can be tested on its own.

import { HANDLERS } from "./logs.mjs";
import { CONTROL_BUCKET, CONTROL_TOPIC, PRIMARY_BUCKET, PRIMARY_COLLECTION, PRIMARY_TOPIC, PROJECT, REGION } from "./script.mjs";

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

const get = (id, url, expect = [200]) => ({ id: `preflight.${id}`, role: "preflight", method: "GET", url, auth: "oauth", mutation: false, expect });
const post = (id, url, body) => ({ id: `preflight.${id}`, role: "preflight", method: "POST", url, auth: "oauth", mutation: false, expect: [200], body });
const region = `projects/${PROJECT}/locations/${REGION}`;
const lowerNames = HANDLERS.map(({ name }) => name.toLowerCase());
const lastSegment = (name) => String(name ?? "").split("/").at(-1);
const ok = () => ({ ok: true });
const bad = (reason) => ({ ok: false, reason });

/** The preflight steps in order. `check(answer, context)` returns {ok, reason}; it may add to `context`. */
export const PREFLIGHT = [
  {
    ...get("project", `https://cloudresourcemanager.googleapis.com/v1/projects/${PROJECT}`),
    check: ({ json }, context) => {
      if (json?.projectId !== PROJECT || json?.lifecycleState !== "ACTIVE") return bad("the project is not the active sandbox project");
      if (!/^[0-9]{6,20}$/.test(json.projectNumber ?? "")) return bad("the project number is not typed");
      context.projectNumber = json.projectNumber;
      return ok();
    },
  },
  {
    ...get("services", `https://serviceusage.googleapis.com/v1/projects/${PROJECT}/services?filter=state:ENABLED&pageSize=200`),
    check: ({ json }) => {
      if (json?.nextPageToken) return bad("the enabled-services list has more than one page");
      const enabled = new Set((json?.services ?? []).map((s) => s?.config?.name));
      const missing = REQUIRED_APIS.filter((api) => !enabled.has(api));
      return missing.length ? bad(`APIs not enabled: ${missing.join(", ")}`) : ok();
    },
  },
  {
    ...get("firestore-database", `https://firestore.googleapis.com/v1/projects/${PROJECT}/databases/(default)`),
    check: ({ json }) => (json?.type === "FIRESTORE_NATIVE" ? ok() : bad("the (default) Firestore database is missing or not native")),
  },
  {
    ...get("primary-bucket", `https://storage.googleapis.com/storage/v1/b/${encodeURIComponent(PRIMARY_BUCKET)}?fields=versioning`),
    check: ({ json }) => (json?.versioning?.enabled === true ? bad("the primary bucket already has versioning enabled (the restore would be wrong)") : ok()),
  },
  {
    ...get("control-bucket", `https://storage.googleapis.com/storage/v1/b/${encodeURIComponent(CONTROL_BUCKET)}?fields=versioning`, [404]),
    check: ({ status }) => (status === 404 ? ok() : bad("the control bucket already exists (the recorder creates it)")),
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
    ...get("artifact-repository", `https://artifactregistry.googleapis.com/v1/${region}/repositories/gcf-artifacts`),
    check: ({ json }) => (String(json?.name ?? "").endsWith("/repositories/gcf-artifacts") ? ok() : bad("the gcf-artifacts repository is missing")),
  },
  {
    ...get("artifact-packages", `https://artifactregistry.googleapis.com/v1/${region}/repositories/gcf-artifacts/packages?pageSize=100`, [200, 404]),
    check: () => ok(),
  },
  {
    ...post("iam", `https://cloudresourcemanager.googleapis.com/v1/projects/${PROJECT}:getIamPolicy`, {}),
    check: ({ json }, context) => {
      context.iamBefore = json;
      const member = `serviceAccount:service-${context.projectNumber}@gcp-sa-eventarc.iam.gserviceaccount.com`;
      const held = (json?.bindings ?? []).some((b) => b.role === "roles/eventarc.serviceAgent" && !b.condition && (b.members ?? []).includes(member));
      return held ? ok() : bad("the Eventarc service agent does not hold roles/eventarc.serviceAgent");
    },
  },
  {
    ...get("auth-config", `https://identitytoolkit.googleapis.com/admin/v2/projects/${PROJECT}/config`),
    check: ({ json }) => (json?.signIn?.email?.enabled === true ? ok() : bad("Authentication is not initialized with email/password enabled")),
  },
  {
    ...get("rules-release", `https://firebaserules.googleapis.com/v1/projects/${PROJECT}/releases/cloud.firestore`),
    check: ({ json }, context) => {
      const ruleset = String(json?.rulesetName ?? "");
      if (!/^projects\/[^/]+\/rulesets\/[A-Za-z0-9-]+$/.test(ruleset)) return bad("no Firestore Rules release");
      context.rulesetId = ruleset.split("/").at(-1);
      return ok();
    },
  },
  {
    // The client write of the auth-context scenario needs a Rules release that lets a signed-in user create in the primary collection.
    id: "preflight.rules-ruleset",
    role: "preflight",
    method: "GET",
    url: `https://firebaserules.googleapis.com/v1/projects/${PROJECT}/rulesets/` + "${rulesetId}",
    auth: "oauth",
    mutation: false,
    expect: [200],
    check: ({ json }) => {
      const source = (json?.source?.files ?? []).map((f) => f?.content ?? "").join("\n");
      return source.includes(PRIMARY_COLLECTION) && source.includes("request.auth") ? ok() : bad("the released Rules do not mention the primary collection and request.auth");
    },
  },
  {
    ...get("functions-v1", `https://cloudfunctions.googleapis.com/v1/${region}/functions`),
    check: ({ json }) => {
      const ours = (json?.functions ?? []).map((f) => lastSegment(f?.name)).filter((n) => HANDLERS.some((h) => h.name === n));
      return ours.length ? bad(`Gen1 functions already deployed: ${ours.join(", ")}`) : ok();
    },
  },
  {
    ...get("functions-v2", `https://cloudfunctions.googleapis.com/v2/${region}/functions`),
    check: ({ json }) => {
      const ours = (json?.functions ?? []).map((f) => lastSegment(f?.name)).filter((n) => lowerNames.includes(n.toLowerCase()));
      return ours.length ? bad(`Gen2 functions already deployed: ${ours.join(", ")}`) : ok();
    },
  },
  {
    ...get("run-services", `https://run.googleapis.com/v2/${region}/services`),
    check: ({ json }) => {
      const ours = (json?.services ?? []).map((s) => lastSegment(s?.name)).filter((n) => lowerNames.includes(n));
      return ours.length ? bad(`Cloud Run services already exist: ${ours.join(", ")}`) : ok();
    },
  },
  {
    ...get("eventarc-triggers", `https://eventarc.googleapis.com/v1/${region}/triggers`),
    check: ({ json }) => {
      const ours = (json?.triggers ?? []).map((t) => lastSegment(t?.name)).filter((n) => lowerNames.some((l) => n.startsWith(`${l}-`)));
      return ours.length ? bad(`Eventarc triggers already exist: ${ours.join(", ")}`) : ok();
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
  return { problems, projectNumber: context.projectNumber ?? null, iamBefore: context.iamBefore ?? null };
}

/** The (role, member) pairs of an IAM policy as strings, user accounts redacted: enough to name what a deploy added. */
export function iamPairs(policy) {
  const pairs = [];
  for (const binding of policy?.bindings ?? []) {
    for (const member of binding.members ?? []) pairs.push(`${binding.role} ${member.startsWith("user:") ? "user:<redacted>" : member}${binding.condition ? " (conditional)" : ""}`);
  }
  return pairs.sort();
}

export function iamDiff(before, after) {
  const was = new Set(iamPairs(before));
  const is = new Set(iamPairs(after));
  return { added: [...is].filter((p) => !was.has(p)), removed: [...was].filter((p) => !is.has(p)) };
}
