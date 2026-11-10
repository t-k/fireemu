// Reads the saved production recording of the pipeline regex observation and fireemu's answers
// (the `fireemu.json` that `run.mjs check` writes for each profile) and prints one line per pair
// of function and subject, then the counts. The recording is the lane's own fixture.
//
//   FIREEMU_SANDBOX_LANE=fs-ent-pipeline-regex node src/fs-query-index/run.mjs check
//   cp .runs/fs-ent-pipeline-regex/fireemu.json /path/strict.json
//   FIREEMU_SANDBOX_LANE=fs-ent-pipeline-regex-emulator node src/fs-query-index/run.mjs check
//   cp .runs/fs-ent-pipeline-regex/fireemu.json /path/emulator.json
//   node src/fs-ent-pipeline/regex-report.mjs fs-ent-pipeline-regex-production.json strict.json emulator.json

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { isMainModule } from "../fs-query-index/main-module.mjs";
import { reportRows } from "./regex-judge.mjs";

const PREDICTIONS = fileURLToPath(new URL("./regex-predictions.json", import.meta.url));

/** One outcome as a short text. */
export function show(outcome) {
  switch (outcome.kind) {
    case "bool":
    case "string":
      return `${outcome.kind}:${JSON.stringify(outcome.value)}`;
    case "array":
      return `[${outcome.items.map(show).join(",")}]`;
    case "unknown":
      return `unknown(${outcome.reason})`;
    default:
      return outcome.kind;
  }
}

export function formatRows(report) {
  return report.rows
    .map((row) =>
      [
        row.id,
        `production=${show(row.production)}`,
        `prediction=${show(row.prediction)}`,
        `strict=${show(row.strict)}`,
        `emulator=${show(row.emulator)}`,
        `vsPrediction=${row.vsPrediction}`,
        `vsStrict=${row.vsStrict}`,
        `vsEmulator=${row.vsEmulator}`,
      ].join("\t"),
    )
    .join("\n");
}

export function main(argv, read = (path) => JSON.parse(readFileSync(path, "utf8"))) {
  const [fixturePath, strictPath, emulatorPath] = argv;
  if (!fixturePath || !strictPath || !emulatorPath)
    throw new Error(
      "usage: regex-report.mjs <fixture> <strict fireemu.json> <emulator fireemu.json>",
    );
  const report = reportRows({
    fixture: read(fixturePath),
    strict: read(strictPath),
    emulator: read(emulatorPath),
    predictions: read(PREDICTIONS),
  });
  return `${formatRows(report)}\n${JSON.stringify(report.counts)}\n`;
}

if (isMainModule(import.meta)) process.stdout.write(main(process.argv.slice(2)));
