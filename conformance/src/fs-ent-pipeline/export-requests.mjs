// Writes the REST requests of the FS-ENT-ORACLE pipeline corpus programs the production
// fixture holds (seeds and steps, `{docs}` left as written) to
// conformance/fs-ent-pipeline-requests.json, for the Rust replay test in
// crates/fireemu-adapter-grpc that runs them against the in-process REST surface and compares
// the answers with conformance/fs-ent-pipeline-production.json.
//
//   node src/fs-ent-pipeline/export-requests.mjs          write the file
//   node src/fs-ent-pipeline/export-requests.mjs --check  exit 1 when the file is stale
import { readFile, writeFile } from "node:fs/promises";

import { readFileSync } from "node:fs";

import { PROGRAMS } from "./corpus.mjs";

export const EXPORT = new URL("../../fs-ent-pipeline-requests.json", import.meta.url);
const FIXTURE = new URL("../../fs-ent-pipeline-production.json", import.meta.url);

/** The programs the production fixture holds rows for: the replay compares only those. */
export function recordedPrograms(programs = PROGRAMS) {
  const recorded = JSON.parse(readFileSync(FIXTURE, "utf8")).programs;
  return programs.filter((program) => recorded[program.id] !== undefined);
}

/** The export's text: every recorded program's seed and REST steps, gRPC steps left out. */
export function exportText(programs = recordedPrograms()) {
  const out = {
    generator: "conformance/src/fs-ent-pipeline/export-requests.mjs",
    programs: programs.map((program) => ({
      id: program.id,
      seed: program.seed ?? [],
      steps: program.steps
        .filter((step) => (step.transport ?? "rest") === "rest")
        .map(({ id, rpc, body, parent }) => ({ id, rpc, body, parent })),
    })),
  };
  return `${JSON.stringify(out)}\n`;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const text = exportText();
  if (process.argv[2] === "--check") {
    const current = await readFile(EXPORT, "utf8").catch(() => "");
    if (current !== text) {
      console.error(
        `${EXPORT.pathname} is stale; run node src/fs-ent-pipeline/export-requests.mjs`,
      );
      process.exit(1);
    }
  } else {
    await writeFile(EXPORT, text);
  }
}
