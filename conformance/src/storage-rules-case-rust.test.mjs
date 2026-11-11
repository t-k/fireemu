import "./storage-signed-put/test-preload.mjs";

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { CASE_ROWS, conditionOf } from "./storage-rules-s9/plan-case.mjs";

const file = fileURLToPath(
  new URL("../../crates/fireemu-core-rules/tests/storage_case_mapping.rs", import.meta.url),
);
const text = readFileSync(file, "utf8");

/** A Rust string literal body to the string it spells (escapes `\u{..}`, `\"`, `\\`). */
const unescape = (body) =>
  body.replace(/\\u\{([0-9a-f]+)\}|\\(["\\])/g, (_, hex, plain) =>
    hex ? String.fromCodePoint(Number.parseInt(hex, 16)) : plain,
  );

const ROW =
  /^ {4}row\("([^"]+)", Kind::(Literal|Capture|Resource), "((?:[^"\\]|\\.)*)", "((?:[^"\\]|\\.)*)", \[(true|false), (true|false), (true|false)\]\),$/gm;
const rustRows = [...text.matchAll(ROW)].map((m) => ({
  id: m[1],
  kind: m[2].toLowerCase(),
  leaf: unescape(m[3]),
  condition: unescape(m[4]),
  allowed: [m[5], m[6], m[7]].map((v) => v === "true"),
}));

describe("the Rust strict-side table of the case family", () => {
  it("is ASCII, so no tool can normalize a probe in it", () => {
    assert.ok([...text].every((c) => c.charCodeAt(0) < 0x80));
  });

  it("holds the plan's rows in the plan's order, with the same condition, object leaf and predictions", () => {
    assert.equal(rustRows.length, CASE_ROWS.length);
    assert.match(text, new RegExp(`const ROW_COUNT: usize = ${CASE_ROWS.length};`));
    CASE_ROWS.forEach((row, index) => {
      const rust = rustRows[index];
      assert.equal(rust.id, row.id);
      assert.equal(rust.kind, row.kind);
      assert.equal(rust.leaf, row.kind === "literal" ? "x" : row.objectName, row.id);
      assert.equal(rust.condition, conditionOf(row), row.id);
      assert.deepEqual(
        rust.allowed,
        [row.candidates.ascii, row.candidates.full, row.candidates.simple],
        row.id,
      );
    });
  });

  it("ignores all three candidate tests and runs the table and the controls", () => {
    assert.equal((text.match(/#\[ignore = /g) ?? []).length, 3);
    for (const name of [
      "candidate_ascii_only_letters_a_to_z_change",
      "candidate_full_unicode_default_mapping",
      "candidate_simple_one_character_mapping",
    ])
      assert.match(text, new RegExp(`#\\[ignore = [^\\n]*\\]\\nfn ${name}\\(\\)`));
    assert.match(text, /#\[test\]\nfn the_table_holds_every_row_once/);
    assert.match(text, /#\[test\]\nfn the_controls_hold_today/);
  });
});
