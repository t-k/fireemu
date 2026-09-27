import { isAbsolute } from "node:path";

const canaries = new Set(["fsCreatedV1", "fsCreatedV2"]);

export function buildCanaryCli(action, projectId, name, configHome) {
  if (!/^[a-z][a-z0-9-]{4,28}[a-z0-9]$/.test(projectId)) {
    throw new Error("canary project ID is invalid");
  }
  if (!canaries.has(name)) throw new Error("unreviewed canary function");
  if (typeof configHome !== "string" || !isAbsolute(configHome)) {
    throw new Error("canary CLI requires an isolated absolute XDG config home");
  }
  let args;
  if (action === "deploy") {
    args = [
      "deploy",
      "--config",
      "conformance/functions-events/firebase.json",
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
      "conformance/functions-events/firebase.json",
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
  return { args, env: { GOOGLE_CLOUD_QUOTA_PROJECT: projectId, XDG_CONFIG_HOME: configHome } };
}
