// The stage 3 runner currently exposes only a local, non-sending plan. Production recording
// remains disabled until the corpus, total HTTP budget, credential wire and cleanup are reviewed.

import { buildStage3DraftPlan } from "./stage3-plan.mjs";

const [command, projectId, bucket, firstRunId, secondRunId] = process.argv.slice(2);

if (command === "record-production") {
  process.stderr.write("record-production is disabled: the stage 3 sender is not implemented\n");
  process.exitCode = 2;
} else if (command === "plan") {
  try {
    const plan = buildStage3DraftPlan({ projectId, bucket, runIds: [firstRunId, secondRunId] });
    process.stdout.write(`${JSON.stringify(plan, null, 2)}\n`);
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 2;
  }
} else {
  process.stderr.write("usage: node src/storage-object/run.mjs plan <project> <bucket> <run-id-1> <run-id-2>\n");
  process.exitCode = 2;
}
