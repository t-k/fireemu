import { isAbsolute } from "node:path";

const canaries = new Set(["fsCreatedV1", "fsCreatedV2", "storageFinalizedV1", "storageFinalizedV2"]);
const captureModes = new Set(["reject-canary", "stdout"]);

export function buildCanaryCli(action, projectId, name, options) {
  if (!/^[a-z][a-z0-9-]{4,28}[a-z0-9]$/.test(projectId)) {
    throw new Error("canary project ID is invalid");
  }
  if (!canaries.has(name)) throw new Error("unreviewed canary function");
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
  return {
    args,
    cwd: options.workDir,
    env: {
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
    },
  };
}
