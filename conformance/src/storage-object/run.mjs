// The STORAGE-OBJECT runner. `plan` prints the local, non-sending draft; `pins` prints the digests
// a lean packet pins; `record-production <1|2>` runs one recording of the lean recorder (see
// record.mjs) and needs an approved packet, an owner ledger row, a project lock and a clean tree;
// `probe-production` runs the probe (reads and two cancelled sessions; no object; see probe.mjs) and
// `probe3-production` runs probe-v3 (seven small objects, recorded and removed; see probe3.mjs),
// and `probe4-production` runs probe-v4 (two small objects and the write answers recording 1
// depends on; see probe4.mjs), under the same conditions. A probe packet is named for its kit
// (`probe-v2`, `probe-v3`, `probe-v4`).

import { buildStage3DraftPlan } from "./stage3-plan.mjs";

const [command, projectId, bucket, firstRunId, secondRunId] = process.argv.slice(2);

if (command === "record-production") {
  const { realDeps, recordCommand } = await import("./record-cli.mjs");
  process.exitCode = await recordCommand(process.argv.slice(3), process.env, realDeps());
} else if (command === "probe-production") {
  const { probeCommand, realDeps } = await import("./record-cli.mjs");
  process.exitCode = await probeCommand(process.argv.slice(3), process.env, realDeps());
} else if (command === "probe3-production") {
  const { probeCommand, realDeps } = await import("./record-cli.mjs");
  const { PROBE_V3_KIT } = await import("./probe-run.mjs");
  process.exitCode = await probeCommand(
    process.argv.slice(3),
    process.env,
    realDeps(),
    PROBE_V3_KIT,
  );
} else if (command === "probe4-production") {
  const { probeCommand, realDeps } = await import("./record-cli.mjs");
  const { PROBE_V4_KIT } = await import("./probe-run.mjs");
  process.exitCode = await probeCommand(
    process.argv.slice(3),
    process.env,
    realDeps(),
    PROBE_V4_KIT,
  );
} else if (command === "pins") {
  const { pinsCommand, realDeps } = await import("./record-cli.mjs");
  process.exitCode = await pinsCommand(realDeps());
} else if (command === "plan") {
  try {
    const plan = buildStage3DraftPlan({ projectId, bucket, runIds: [firstRunId, secondRunId] });
    process.stdout.write(`${JSON.stringify(plan, null, 2)}\n`);
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 2;
  }
} else {
  process.stderr.write(
    "usage: node src/storage-object/run.mjs plan <project> <bucket> <run-id-1> <run-id-2>\n" +
      "       node src/storage-object/run.mjs pins\n" +
      "       node src/storage-object/run.mjs record-production <1|2>\n" +
      "       node src/storage-object/run.mjs probe-production\n" +
      "       node src/storage-object/run.mjs probe3-production\n" +
      "       node src/storage-object/run.mjs probe4-production\n",
  );
  process.exitCode = 2;
}
