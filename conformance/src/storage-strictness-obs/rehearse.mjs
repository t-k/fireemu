// Pass the same --run-id to run.mjs --local after starting fireemu with this configuration.
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { CORS, targetOf } from "./guard.mjs";

export function rehearsalConfig(target) {
  return {
    schemaVersion: 1,
    profile: "strict",
    storage: {
      defaultBucket: "firebasestorage.app",
      buckets: [target.defaultBucket, target.tempBucket],
      undeclaredBuckets: "refuse",
      cors: { [target.tempBucket]: CORS },
    },
  };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const { values } = parseArgs({
      options: {
        project: { type: "string" },
        "default-bucket": { type: "string" },
        "run-id": { type: "string" },
      },
    });
    const target = targetOf({
      project: values.project,
      defaultBucket: values["default-bucket"],
      runId: values["run-id"],
    });
    console.log(JSON.stringify(rehearsalConfig(target), null, 2));
  } catch {
    console.error("Invalid rehearsal arguments");
    process.exitCode = 1;
  }
}
