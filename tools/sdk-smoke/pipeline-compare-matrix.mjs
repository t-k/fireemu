// Records how the official Firestore emulator answers the six pipeline comparisons over every
// pair of operand classes, the fixture of the emulator profile's comparisons
// (crates/fireemu-core-firestore/src/pipeline_exec/official_compare.json). Design input for the
// emulator profile, never production evidence.
//
//   java -jar ~/.cache/firebase/emulators/cloud-firestore-emulator-v1.22.0.jar \
//     --host 127.0.0.1 --port 8095 --database-edition enterprise &
//   FIRESTORE_EMULATOR_HOST=127.0.0.1:8095 node tools/sdk-smoke/pipeline-compare-matrix.mjs \
//     --write crates/fireemu-core-firestore/src/pipeline_exec/official_compare.json
//
// `--check <file>` records again and exits 1 when the answer differs from the file.
//
// The operands are written over REST with explicit types, so that a double 1.0, both zeros
// and the infinities stay doubles (the Admin SDK writes a JS 1.0 as an integer). Each cell is
// one select alias `op(field(left), field(right))` on one document; `x` is a missing field.
import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { Firestore } from "@google-cloud/firestore";
import * as P from "@google-cloud/firestore/pipelines";

const [mode, file] = process.argv.slice(2);
assert.ok(["--write", "--check"].includes(mode) && file, "usage: --write|--check <file>");
const host = process.env.FIRESTORE_EMULATOR_HOST;
assert.ok(host, "FIRESTORE_EMULATOR_HOST must name the official emulator");
const project = "demo-app";

// Operand classes: name and REST value (`x` is missing).
const OPERANDS = [
  ["x", null],
  ["n", { nullValue: null }],
  ["nan", { doubleValue: "NaN" }],
  ["i", { integerValue: "1" }],
  ["i2", { integerValue: "2" }],
  ["d5", { doubleValue: 1.5 }],
  ["one", { doubleValue: 1 }],
  ["iz", { integerValue: "0" }],
  ["dz", { doubleValue: 0 }],
  ["nz", { doubleValue: "-0.0" }],
  ["i53", { integerValue: "9007199254740992" }],
  ["d53", { doubleValue: 9007199254740992 }],
  ["i53p", { integerValue: "9007199254740993" }],
  ["imax", { integerValue: "9223372036854775807" }],
  ["d63", { doubleValue: 9223372036854775808 }],
  ["inf", { doubleValue: "Infinity" }],
  ["ninf", { doubleValue: "-Infinity" }],
  ["s", { stringValue: "a" }],
  ["s2", { stringValue: "b" }],
  ["by", { bytesValue: "AAE=" }],
  ["ref", { referenceValue: `projects/${project}/databases/(default)/documents/c/a` }],
  ["geo", { geoPointValue: { latitude: 0, longitude: 1 } }],
  ["b", { booleanValue: true }],
  ["bf", { booleanValue: false }],
  ["arr", { arrayValue: { values: [{ integerValue: "1" }, { stringValue: "a" }] } }],
  ["arr2", { arrayValue: { values: [{ integerValue: "1" }, { stringValue: "b" }] } }],
  ["arrn", { arrayValue: { values: [{ nullValue: null }] } }],
  ["m", { mapValue: { fields: { a: { integerValue: "1" } } } }],
  ["m2", { mapValue: { fields: { a: { integerValue: "2" } } } }],
  ["ts", { timestampValue: "1970-01-01T00:00:00Z" }],
  ["ts2", { timestampValue: "1970-01-01T00:00:01Z" }],
];
const OPS = {
  equal: "equal",
  not_equal: "notEqual",
  less_than: "lessThan",
  less_than_or_equal: "lessThanOrEqual",
  greater_than: "greaterThan",
  greater_than_or_equal: "greaterThanOrEqual",
};

const fields = Object.fromEntries(OPERANDS.filter(([, value]) => value).map(([name, value]) => [name, value]));
const written = await fetch(
  `http://${host}/v1/projects/${project}/databases/(default)/documents/cmp/d`,
  {
    method: "PATCH",
    headers: { authorization: "Bearer owner", "content-type": "application/json" },
    body: JSON.stringify({ fields }),
  },
);
assert.equal(written.status, 200, await written.text());

const db = new Firestore({ projectId: project });
const names = OPERANDS.map(([name]) => name);
const aliases = [];
for (const [op, method] of Object.entries(OPS)) {
  for (const left of names) {
    for (const right of names) {
      aliases.push([`${op}__${left}__${right}`, P[method](P.field(left), P.field(right))]);
    }
  }
}
// The official emulator answers at most 64 select fields per stage.
const answers = {};
for (let k = 0; k < aliases.length; k += 64) {
  const batch = aliases.slice(k, k + 64).map(([alias, expr]) => expr.as(alias));
  const result = await db.pipeline().collection("cmp").select(...batch).execute();
  assert.equal(result.results.length, 1);
  Object.assign(answers, result.results[0].data());
}
await db.terminate();

// One row string per left operand: `T` true, `.` false, `A` absent.
const cell = (key) => {
  if (!(key in answers)) return "A";
  assert.equal(typeof answers[key], "boolean", key);
  return answers[key] ? "T" : ".";
};
const lines = [
  "{",
  `  "generator": "tools/sdk-smoke/pipeline-compare-matrix.mjs",`,
  `  "emulator": "firebase-tools 15.28.2, Firestore emulator 1.22.0, Enterprise",`,
  `  "operands": "${names.join(" ")}",`,
  ...Object.keys(OPS).map((op, index, all) => {
    const rows = names.map((left) => `"${names.map((right) => cell(`${op}__${left}__${right}`)).join("")}"`);
    return `  "${op}": [${rows.join(", ")}]${index + 1 < all.length ? "," : ""}`;
  }),
  "}",
  "",
];
const text = lines.join("\n");
JSON.parse(text);
if (mode === "--write") {
  writeFileSync(file, text);
  console.log(`wrote ${file}`);
} else if (readFileSync(file, "utf8") !== text) {
  console.error(`${file} differs from the official emulator's answer:\n${text}`);
  process.exit(1);
} else {
  console.log(`${file} matches the official emulator`);
}
