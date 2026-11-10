// The Rust replay table equals what the fixture records (see regex-rows.mjs).

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import { PAIRS } from "./regex-corpus.mjs";
import { FIXTURE_PATH, formatRows, productionRows } from "./regex-rows.mjs";

const TABLE = fileURLToPath(
  new URL(
    "../../../crates/fireemu-adapter-grpc/src/pipeline_regex/production_rows.json",
    import.meta.url,
  ),
);
const fixture = JSON.parse(readFileSync(FIXTURE_PATH, "utf8"));

test("the table has one row per recorded pair and no unknown answer", () => {
  const rows = productionRows(fixture);
  assert.equal(rows.length, PAIRS.length);
  assert.equal(rows.length * 4, 272);
  assert.equal(new Set(rows.map((row) => row.label)).size, rows.length);
});

test("the saved Rust replay table is exactly the table of the fixture", () => {
  assert.equal(readFileSync(TABLE, "utf8"), formatRows(productionRows(fixture)));
});

test("the table keeps the recorded facts the issue names", () => {
  const byLabel = new Map(productionRows(fixture).map((row) => [row.label, row]));
  assert.deepEqual(byLabel.get("d-arabic").answers.regex_contains, { kind: "bool", value: false });
  assert.deepEqual(byLabel.get("posix-digit").answers.regex_find_all, { kind: "refused-syntax" });
  assert.deepEqual(byLabel.get("cap-two").answers.regex_find, { kind: "refused-captures" });
  assert.deepEqual(byLabel.get("cap-two").answers.regex_match, { kind: "bool", value: true });
  assert.deepEqual(byLabel.get("cap-all-alt").answers.regex_find_all, {
    kind: "array",
    items: [
      { kind: "string", value: "a" },
      { kind: "null" },
      { kind: "string", value: "a" },
      { kind: "null" },
    ],
  });
});

test("the saved request export of the strict refusal gate is exactly the regex programs", async () => {
  const { EXPORT, regexRequestsText } = await import("./regex-requests.mjs");
  assert.equal(readFileSync(EXPORT, "utf8"), regexRequestsText());
});

test("an unknown answer or a differing second recording stops the export", () => {
  const stepId = "regex-contains-d-arabic";
  const programId = "fs-ent-pipeline-regex/rx/digit";
  const mutate = (change) => {
    const copy = structuredClone(fixture);
    change(copy.programs[programId]);
    return copy;
  };
  assert.throws(
    () => productionRows(mutate((program) => (program.steps[stepId].status = 503))),
    /unusable outcome/,
  );
  assert.throws(
    () => productionRows(mutate((program) => (program.second = { [stepId]: { status: 200 } }))),
    /second recording differs/,
  );
  // A second recording that does not hold the step is no difference.
  assert.equal(
    productionRows(mutate((program) => (program.second = { other: {} }))).length,
    PAIRS.length,
  );
});

test("the saved table escapes every code point outside printable ASCII, astral ones as pairs", () => {
  const text = formatRows([
    { label: "x", subject: "a\u{e9}\u{1f600}\u{7f}~ ", pattern: "", answers: {} },
  ]);
  assert.match(text, /"subject":"a\\u00e9\\ud83d\\ude00\\u007f~ "/);
  for (const ch of text) assert.ok(ch === "\n" || (ch >= " " && ch <= "~"), ch);
  assert.deepEqual(JSON.parse(text)[0].subject, "a\u{e9}\u{1f600}\u{7f}~ ");
});
