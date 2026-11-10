// Writes the REST requests of the Pipeline regex observation (the programs the regex production
// fixture holds) to conformance/fs-ent-pipeline-regex-requests.json. The strict refusal gate in
// crates/fireemu-adapter-grpc/src/pipeline_shape.rs reads it together with
// conformance/fs-ent-pipeline-regex-production.json, so that the two texts production recorded for
// these functions ("Unsupported regex syntax." and "At most one capture group is supported.")
// pass the gate for the request shapes that were recorded.
//
//   node src/fs-ent-pipeline/regex-requests.mjs          write the file
//   node src/fs-ent-pipeline/regex-requests.mjs --check  exit 1 when the file is stale

import { readFile, writeFile } from "node:fs/promises";

import { isMainModule } from "../fs-query-index/main-module.mjs";
import { exportText, recordedPrograms } from "./export-requests.mjs";
import { PROGRAMS } from "./regex-corpus.mjs";
import { FIXTURE_PATH } from "./regex-rows.mjs";

export const EXPORT = new URL("../../fs-ent-pipeline-regex-requests.json", import.meta.url);

export const regexRequestsText = () => exportText(recordedPrograms(PROGRAMS, FIXTURE_PATH));

if (isMainModule(import.meta)) {
  const text = regexRequestsText();
  if (process.argv[2] === "--check") {
    const current = await readFile(EXPORT, "utf8").catch(() => "");
    if (current !== text) {
      console.error(`${EXPORT.pathname} is stale; run node src/fs-ent-pipeline/regex-requests.mjs`);
      process.exit(1);
    }
  } else {
    await writeFile(EXPORT, text);
  }
}
