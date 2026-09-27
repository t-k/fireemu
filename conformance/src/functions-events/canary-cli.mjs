const canaries = new Set(["fsCreatedV1", "fsCreatedV2"]);

export function buildCanaryCli(action, projectId, name) {
  if (!/^[a-z][a-z0-9-]{4,28}[a-z0-9]$/.test(projectId)) {
    throw new Error("canary project ID is invalid");
  }
  if (!canaries.has(name)) throw new Error("unreviewed canary function");
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
    ];
  } else if (action === "delete") {
    args = ["functions:delete", name, "--region", "us-central1", "--project", projectId, "--force"];
  } else {
    throw new Error("unknown canary CLI action");
  }
  return { args, env: { GOOGLE_CLOUD_QUOTA_PROJECT: projectId } };
}
