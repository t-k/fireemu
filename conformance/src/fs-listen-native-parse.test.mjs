import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { listedNames, readBack } from "./fs-listen/native-parse.mjs";

const matrix = JSON.parse(
  readFileSync(new URL("../firestore-production-matrix.json", import.meta.url), "utf8"),
);

/** Every value in the recorded matrix that `pick` accepts, with where it was found. */
function collect(value, pick, path = "", out = []) {
  if (pick(value)) out.push({ path, value });
  if (value && typeof value === "object")
    for (const [key, item] of Object.entries(value)) collect(item, pick, `${path}/${key}`, out);
  return out;
}

// Production answers of BatchGetDocuments and ListDocuments, as recorded in the FS-DATA-WRITE
// matrix (the production side of each step): the parsers must read exactly these shapes.
const batchGets = collect(
  matrix,
  (v) =>
    Array.isArray(v) &&
    v.length > 0 &&
    v.every((r) => r && typeof r === "object" && ("found" in r || "missing" in r)),
).filter(({ path }) => !path.includes("emulator"));
const pages = collect(
  matrix,
  (v) =>
    v &&
    typeof v === "object" &&
    !Array.isArray(v) &&
    Array.isArray(v.documents) &&
    v.documents.length > 0,
).filter(({ path }) => !path.includes("emulator"));

test("the recorded production corpus holds BatchGetDocuments and ListDocuments answers to replay", () => {
  assert.ok(batchGets.length >= 2, `${batchGets.length} batch answers`);
  assert.ok(pages.length >= 1, `${pages.length} list pages`);
  assert.ok(batchGets.some(({ value }) => value.some((r) => "found" in r)));
  assert.ok(batchGets.some(({ value }) => value.some((r) => "missing" in r)));
});

test("readBack reads every recorded production BatchGetDocuments answer", () => {
  for (const { path, value } of batchGets) {
    const names = value.map((r) => r.found?.name ?? r.missing);
    const read = readBack(names, value);
    assert.deepEqual(
      read.map((e) => e.name),
      names,
      path,
    );
    assert.deepEqual(
      read.map((e) => e.exists),
      value.map((r) => "found" in r),
      path,
    );
  }
});

test("readBack does not depend on the order of the answers, and stops on a name the answer does not mention", () => {
  const results = [{ missing: "n/2" }, { found: { name: "n/1" } }];
  assert.deepEqual(readBack(["n/1", "n/2"], results), [
    { name: "n/1", exists: true },
    { name: "n/2", exists: false },
  ]);
  assert.throws(() => readBack(["n/1", "n/3"], results), /did not mention a requested name/);
  assert.throws(() => readBack(["n/1"], []), /did not mention/);
  assert.throws(
    () => readBack(["n/1"], [{ found: {} }, {}, null, { missing: 7 }]),
    /did not mention/,
  );
  assert.deepEqual(readBack([], []), []);
});

test("listedNames reads every recorded production ListDocuments page and filters by id prefix", () => {
  for (const { path, value } of pages) {
    const all = value.documents.map((d) => d.name);
    assert.deepEqual(listedNames(value, ""), all, path);
    const first = all[0].split("/").at(-1);
    const hits = listedNames(value, first.slice(0, 1));
    assert.ok(hits.includes(all[0]), path);
    assert.deepEqual(listedNames(value, "zz-no-such-prefix"), [], path);
  }
});

test("listedNames copes with an empty page, a page without documents and a document without a name", () => {
  assert.deepEqual(listedNames({}, "r"), []);
  assert.deepEqual(listedNames(undefined, "r"), []);
  assert.deepEqual(
    listedNames(
      { documents: [{}, { name: 7 }, { name: "a/b/r1-x" }, { name: "a/b/other" }] },
      "r1",
    ),
    ["a/b/r1-x"],
  );
});
