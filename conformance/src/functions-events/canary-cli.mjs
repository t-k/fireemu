import { isAbsolute } from "node:path";

const canaries = new Set([
  "fsCreatedV1",
  "fsCreatedV2",
  "storageFinalizedV1",
  "storageFinalizedV2",
]);
const captureModes = new Set(["reject-canary", "stdout"]);

// The Firestore, Storage and Pub/Sub handlers of the second delivery probe (FE 013), in the order the
// probe reads them back. They deploy and delete as one set, in one CLI command each.
export const probeCanaries = [
  "fsUpdatedV1",
  "fsUpdatedV2",
  "fsDeletedV1",
  "fsDeletedV2",
  "fsWrittenV1",
  "fsWrittenV2",
  "storageDeletedV1",
  "storageDeletedV2",
  "storageMetadataUpdatedV1",
  "storageMetadataUpdatedV2",
  "pubsubPublishedV1",
  "pubsubPublishedV2",
];

// The 22 handlers of the formal recording (every export of the fixture), in the order the capture
// lists them. Like the probe set, they deploy and delete as one set, in one CLI command each.
export const formalHandlers = [
  "fsCreatedV1",
  "fsCreatedV2",
  "fsUpdatedV1",
  "fsUpdatedV2",
  "fsDeletedV1",
  "fsDeletedV2",
  "fsWrittenV1",
  "fsWrittenV2",
  "fsWrittenWithAuthContextV2",
  "fsRetryV2",
  "storageFinalizedV1",
  "storageFinalizedV2",
  "storageDeletedV1",
  "storageDeletedV2",
  "storageMetadataUpdatedV1",
  "storageMetadataUpdatedV2",
  "storageArchivedV1",
  "storageArchivedV2",
  "authCreatedV1",
  "authDeletedV1",
  "pubsubPublishedV1",
  "pubsubPublishedV2",
];

const reviewedSets = [probeCanaries, formalHandlers];
const isReviewedSet = (names) =>
  Array.isArray(names) &&
  reviewedSets.some(
    (set) => names.length === set.length && names.every((name, index) => name === set[index]),
  );

function requireProject(projectId) {
  if (!/^[a-z][a-z0-9-]{4,28}[a-z0-9]$/.test(projectId)) {
    throw new Error("canary project ID is invalid");
  }
}

function requireOptions(options) {
  for (const key of ["configHome", "configPath", "workDir", "home"]) {
    if (typeof options?.[key] !== "string" || !isAbsolute(options[key])) {
      throw new Error(`canary CLI requires an absolute ${key}`);
    }
  }
  if (typeof options.path !== "string" || !options.path) {
    throw new Error("canary CLI requires an explicit PATH");
  }
  const captureMode = options.captureMode === undefined ? "reject-canary" : options.captureMode;
  if (!captureModes.has(captureMode)) throw new Error("canary CLI capture mode is not reviewed");
  return captureMode;
}

function canaryEnvironment(projectId, options, captureMode) {
  return {
    HOME: options.home,
    PATH: options.path,
    XDG_CONFIG_HOME: options.configHome,
    GOOGLE_CLOUD_QUOTA_PROJECT: projectId,
    GCLOUD_PROJECT: projectId,
    FIREBASE_CONFIG: JSON.stringify({ projectId }),
    FE_EVENTS_MODE: "production",
    FE_EVENTS_PROJECT_ID: projectId,
    FE_EVENTS_PRIMARY_COLLECTION: "fe_events_primary",
    FE_EVENTS_PRIMARY_BUCKET: `${projectId}.firebasestorage.app`,
    FE_EVENTS_PRIMARY_TOPIC: "fe-events-primary",
    FE_EVENTS_CAPTURE_MODE: captureMode,
  };
}

// One deploy or delete command for one whole reviewed set (the probe set or the formal set, and nothing else).
// `options.force` and `options.dryRun` are for the deploy only and are off unless `true`: `--force` skips the
// failure-policy and minimum-instances prompts (a non-interactive deploy of a function that retries is refused
// without it), and `--dry-run` appended last makes the same command prepare and validate without deploying.
export function buildCanaryBatchCli(action, projectId, names, options) {
  requireProject(projectId);
  if (!isReviewedSet(names)) {
    throw new Error("canary batch CLI takes exactly one reviewed set");
  }
  const captureMode = requireOptions(options);
  if ((options.force !== undefined || options.dryRun !== undefined) && action !== "deploy")
    throw new Error("canary CLI --force and --dry-run are for the deploy only");
  for (const flag of [options.force, options.dryRun])
    if (flag !== undefined && typeof flag !== "boolean")
      throw new Error("canary CLI --force and --dry-run take a boolean");
  let args;
  if (action === "deploy") {
    args = [
      "deploy",
      "--config",
      options.configPath,
      "--project",
      projectId,
      "--only",
      names.map((name) => `functions:events:${name}`).join(","),
      "--non-interactive",
      ...(options.force === true ? ["--force"] : []),
      "--debug",
      ...(options.dryRun === true ? ["--dry-run"] : []),
    ];
  } else if (action === "delete") {
    args = [
      "functions:delete",
      ...names,
      "--config",
      options.configPath,
      "--region",
      "us-central1",
      "--project",
      projectId,
      "--non-interactive",
      "--force",
      "--debug",
    ];
  } else {
    throw new Error("unknown canary CLI action");
  }
  return { args, cwd: options.workDir, env: canaryEnvironment(projectId, options, captureMode) };
}

export function buildCanaryCli(action, projectId, name, options) {
  requireProject(projectId);
  if (!canaries.has(name)) throw new Error("unreviewed canary function");
  const captureMode = requireOptions(options);
  let args;
  if (action === "deploy") {
    args = [
      "deploy",
      "--config",
      options.configPath,
      "--project",
      projectId,
      "--only",
      `functions:events:${name}`,
      "--non-interactive",
      "--debug",
    ];
  } else if (action === "delete") {
    args = [
      "functions:delete",
      name,
      "--config",
      options.configPath,
      "--region",
      "us-central1",
      "--project",
      projectId,
      "--non-interactive",
      "--force",
      "--debug",
    ];
  } else {
    throw new Error("unknown canary CLI action");
  }
  return { args, cwd: options.workDir, env: canaryEnvironment(projectId, options, captureMode) };
}
