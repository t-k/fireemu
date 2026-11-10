// The recorded production rows of the pipeline regex observation as one table that the Rust
// replay test reads (crates/fireemu-adapter-grpc/src/pipeline_regex/production_rows.json): per
// pair, the subject, the pattern and the answer of each of the four functions. The Rust test
// replays every row through the evaluator in both profiles, so the table must be exactly what
// the fixture holds; regex-rows.test.mjs fails when the saved table drifts from it.
//
//   node src/fs-ent-pipeline/regex-rows.mjs > ../crates/fireemu-adapter-grpc/src/pipeline_regex/production_rows.json

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { isMainModule } from "../fs-query-index/main-module.mjs";
import { PAIRS, PROBE, REGEX_FUNCTIONS, REGEX_PREFIX, stepIdOf } from "./regex-corpus.mjs";
import { readAnswer } from "./regex-judge.mjs";

export const FIXTURE_PATH = fileURLToPath(
  new URL("../../fs-ent-pipeline-regex-production.json", import.meta.url),
);

/** One outcome in the shape the Rust test parses: bool, string, null, array, or a refusal. */
function encode(outcome) {
  switch (outcome.kind) {
    case "bool":
    case "string":
      return { kind: outcome.kind, value: outcome.value };
    case "array":
      return { kind: "array", items: outcome.items.map(encode) };
    case "null":
    case "refused-syntax":
    case "refused-captures":
      return { kind: outcome.kind };
    default:
      throw new Error(`a recorded row has the unusable outcome ${outcome.kind}`);
  }
}

/** The rows in corpus order. Throws when any recorded answer is unknown or missing. */
export function productionRows(fixture) {
  return PAIRS.map((pair) => {
    const program = fixture.programs[`${REGEX_PREFIX}rx/${pair.group}`];
    const answers = {};
    for (const name of REGEX_FUNCTIONS) {
      const stepId = stepIdOf(name, pair.label);
      if (program.second && Object.hasOwn(program.second, stepId))
        throw new Error(`${stepId}: the second recording differs from the first`);
      answers[name] = encode(readAnswer(program.steps[stepId]));
    }
    return {
      label: pair.label,
      subject: PROBE[pair.subject].stringValue,
      pattern: pair.pattern,
      answers,
    };
  });
}

/** The saved table as text: JSON with every non-ASCII code point escaped, one row per line. */
export function formatRows(rows) {
  const escape = (text) =>
    text.replace(/[^\x20-\x7e]/gu, (ch) => {
      const n = ch.codePointAt(0);
      return n > 0xffff
        ? `\\u${(0xd800 + ((n - 0x10000) >> 10)).toString(16)}\\u${(0xdc00 + ((n - 0x10000) & 0x3ff)).toString(16)}`
        : `\\u${n.toString(16).padStart(4, "0")}`;
    });
  return `[\n${rows.map((row) => `  ${escape(JSON.stringify(row))}`).join(",\n")}\n]\n`;
}

if (isMainModule(import.meta))
  process.stdout.write(formatRows(productionRows(JSON.parse(readFileSync(FIXTURE_PATH, "utf8")))));
