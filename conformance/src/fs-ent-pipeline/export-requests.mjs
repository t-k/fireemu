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

import { assertCompleteFixture } from "../fs-query-index/fixture-scan.mjs";
import { PROGRAMS } from "./corpus.mjs";
import { isMainModule } from "../fs-query-index/main-module.mjs";

export const EXPORT = new URL("../../fs-ent-pipeline-requests.json", import.meta.url);
const FIXTURE = new URL("../../fs-ent-pipeline-production.json", import.meta.url);

/** The programs the production fixture holds rows for: the replay compares only those. */
export function recordedPrograms(programs = PROGRAMS, fixture = FIXTURE) {
  const recorded = assertCompleteFixture(
    JSON.parse(readFileSync(fixture, "utf8")),
    fixture,
  ).programs;
  return programs.filter((program) => recorded[program.id] !== undefined);
}

/** How many arrays and objects a value nests (a scalar is 0). */
export function bodyDepth(value) {
  if (value === null || typeof value !== "object") return 0;
  return 1 + Math.max(0, ...Object.values(value).map(bodyDepth));
}

/**
 * The deepest body the export keeps as an object. The Rust tests read the whole export through
 * the REST body parser, which stops at 100 levels, and a step sits five levels down in it. A
 * deeper body (an O-8A nesting probe) is exported as the text of its JSON, which nests nothing.
 */
export const EXPORT_BODY_DEPTH = 90;

/** One exported step: its body as written when it is a text or too deep to export as an object. */
export function exportStep({ id, rpc, body, parent, rawBody }) {
  if (body !== undefined && bodyDepth(body) > EXPORT_BODY_DEPTH) {
    return { id, rpc, parent, rawBody: JSON.stringify(body) };
  }
  return { id, rpc, body, parent, rawBody };
}

/** The export's text: every recorded program's seed and REST steps, gRPC steps left out. */
export function exportText(programs = recordedPrograms()) {
  const out = {
    generator: "conformance/src/fs-ent-pipeline/export-requests.mjs",
    programs: programs.map((program) => ({
      id: program.id,
      seed: program.seed ?? [],
      steps: program.steps.filter((step) => (step.transport ?? "rest") === "rest").map(exportStep),
    })),
  };
  return `${JSON.stringify(out)}\n`;
}

if (isMainModule(import.meta)) {
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
