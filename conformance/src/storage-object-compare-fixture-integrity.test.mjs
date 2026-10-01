// The committed production fixture (normalized from the two lean-v5 recordings) is internally
// consistent, carries nothing the masks should have removed, and is what the normalizer's rules say.

import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { digestRows, FIXTURE_SCHEMA_VERSION } from "./storage-object-compare/fixture.mjs";
import { loadFixture } from "./storage-object-compare/run.mjs";
import { scanFixtureText } from "./storage-object-compare/scan.mjs";

const DIRECTORY = fileURLToPath(new URL("../fixtures/storage-object-production/", import.meta.url));
const fixture = loadFixture(DIRECTORY);
const MASKS =
  /<(RUN|BUCKET|PROJECT|GEN:\d+|TIME|HTTPDATE|ETAG|TOKEN:\d+|UPLOAD_ID|ORIGIN|PAGE_TOKEN|JWT|API_KEY|UID|EPOCH|OWNER|DIGEST)>/g;

test("the index names two recordings that normalize to the same rows", () => {
  assert.equal(fixture.index.runIds.length, 2);
  for (const id of fixture.index.runIds) assert.match(id, /^[0-9a-f]{20}$/);
  assert.equal(fixture.index.equivalentRecordings, true);
  for (const entry of fixture.index.recipes) {
    assert.deepEqual(Object.keys(entry.digests).toSorted(), fixture.index.runIds.toSorted());
    assert.equal(new Set(Object.values(entry.digests)).size, 1, entry.recipeId);
  }
});

test("the committed index has the schema version the tool writes", () => {
  assert.equal(fixture.index.schemaVersion, FIXTURE_SCHEMA_VERSION);
  assert.equal(FIXTURE_SCHEMA_VERSION, 1);
});

test("there are 26 recipes and 2,436 exchanges, and every file is listed in the index", () => {
  assert.equal(fixture.index.recipes.length, 26);
  assert.equal(
    fixture.index.recipes.reduce((sum, entry) => sum + entry.rows, 0),
    2436,
  );
  const files = readdirSync(DIRECTORY)
    .filter((name) => name !== "index.json")
    .toSorted();
  assert.deepEqual(files, fixture.index.recipes.map((entry) => entry.file).toSorted());
});

test("every recipe's rows are numbered from 1 and carry the fields the comparison reads", () => {
  for (const [recipeId, rows] of fixture.recipes) {
    rows.forEach((row, index) => {
      assert.equal(row.n, index + 1, `${recipeId} row ${index + 1}`);
      assert.equal(typeof row.method, "string");
      assert.equal(typeof row.route, "string");
      assert.equal(typeof row.path, "string");
      assert.ok(Array.isArray(row.query));
      assert.ok(Number.isSafeInteger(row.status) && row.status >= 100 && row.status < 600);
      assert.ok(row.contentType === null || typeof row.contentType === "string");
      assert.equal(typeof row.headers, "object");
      assert.ok(["json", "text", "bytes", "empty"].includes(row.body.type));
      assert.equal("content-length" in row.headers, false);
      assert.equal("date" in row.headers, false);
    });
  }
});

test("every file passes the secret scan, and no recipe file names a run", () => {
  for (const name of readdirSync(DIRECTORY)) {
    const text = readFileSync(join(DIRECTORY, name), "utf8");
    scanFixtureText(text, { runIds: name === "index.json" ? [] : fixture.index.runIds });
  }
});

test("only the declared masks appear, and each appears in the form the index declares", () => {
  const declared = new Set(fixture.index.normalizations.map((row) => row.id));
  for (const id of [
    "RUN",
    "BUCKET",
    "PROJECT",
    "GEN",
    "TIME",
    "HTTPDATE",
    "ETAG",
    "TOKEN",
    "UPLOAD_ID",
    "PAGE_TOKEN",
    "JWT",
    "API_KEY",
    "UID",
    "EPOCH",
    "OWNER",
    "DIGEST",
  ])
    assert.ok(declared.has(id), id);
  for (const name of readdirSync(DIRECTORY).filter((file) => file !== "index.json")) {
    const text = readFileSync(join(DIRECTORY, name), "utf8");
    // <NAME> is the route class's placeholder for an object name, not a mask.
    for (const [, mask] of text.matchAll(/<([A-Z_]+)(?::\d+)?>/g))
      assert.ok(declared.has(mask) || mask === "NAME", `${name}: ${mask}`);
    assert.equal(text.replaceAll(MASKS, "").includes("<RUN"), false);
  }
});

test("the run's own names are masked everywhere: every object name is under <RUN>", () => {
  for (const [recipeId, rows] of fixture.recipes)
    for (const row of rows) {
      for (const [key, value] of row.query)
        if (key === "name" || key === "prefix")
          assert.match(value, /^storage-object\/<RUN>\//, `${recipeId} #${row.n} ${key}`);
    }
});

test("the recorded production shapes the closure depends on are present", () => {
  const find = (recipeId, predicate) => fixture.recipes.get(recipeId).find(predicate);
  // Not-match guards naming the current value are answered 304 with no body.
  const notMatch = fixture.recipes
    .get("storage-object/gcs/generation-preconditions")
    .filter(
      (row) => row.query.some(([key]) => key === "ifGenerationNotMatch") && row.status === 304,
    );
  assert.ok(notMatch.length >= 3);
  for (const row of notMatch) assert.deepEqual(row.body, { type: "empty" });
  // The Firebase list with maxResults=0 is a 400 with the recorded message.
  const zero = find("storage-object/firebase/list", (row) =>
    row.query.some(([key, value]) => key === "maxResults" && value === "0"),
  );
  assert.equal(zero.status, 400);
  assert.equal(zero.body.value.error.message, "Expect maxResults to be a positive number.");
  // A bad range is a 416 with an XML body on both dialects.
  const ranges = fixture.recipes
    .get("storage-object/errors/range")
    .filter((row) => row.status === 416);
  assert.equal(ranges.length, 8);
  for (const row of ranges) assert.equal(row.body.type, "text");
  // The accepted PUT carries the object resource, with metadata.
  const put = find(
    "storage-object/gcs/metageneration-preconditions",
    (row) => row.method === "PUT" && row.status === 200,
  );
  assert.equal(put.body.value.kind, "storage#object");
});

test("every recipe file matches the digests the index states for it", () => {
  for (const entry of fixture.index.recipes) {
    const digest = digestRows(fixture.recipes.get(entry.recipeId));
    for (const [run, expected] of Object.entries(entry.digests))
      assert.equal(digest, expected, `${entry.recipeId} (${run})`);
  }
});

test("the layout and the order of production's members are in the fixture", () => {
  // Production pretty-prints its JSON: the pretty-printing is bytes beyond the compact form.
  const rows = [...fixture.recipes.values()].flat();
  const jsonRows = rows.filter((row) => row.body.type === "json");
  assert.ok(jsonRows.length > 1500);
  assert.ok(jsonRows.filter((row) => row.layout > 0).length > 1500);
  assert.ok(rows.every((row) => row.layout === null || Number.isSafeInteger(row.layout)));
  // An object resource has production's member order, not alphabetical order.
  const resource = fixture.recipes
    .get("storage-object/gcs/download")
    .find((row) => row.body.type === "json" && row.body.value.kind === "storage#object");
  assert.deepEqual(Object.keys(resource.body.value).slice(0, 6), [
    "kind",
    "id",
    "selfLink",
    "mediaLink",
    "name",
    "bucket",
  ]);
});

test("times keep their format: millisecond fractions in every recorded time, and no epoch hides a time of another format", () => {
  const text = readdirSync(DIRECTORY)
    .filter((name) => name !== "index.json")
    .map((name) => readFileSync(join(DIRECTORY, name), "utf8"))
    .join("\n");
  const times = new Set([...text.matchAll(/<TIME:(\d+)>/g)].map(([, digits]) => digits));
  assert.deepEqual([...times], ["3"]);
  assert.ok(/"lastRefreshAt":"<TIME:3>"/.test(text));
  assert.ok(/"createdAt":"<EPOCH:string:13>"/.test(text));
  assert.ok(/"passwordUpdatedAt":"<EPOCH:number:13>"/.test(text));
});

test("the index records the scan: a private list was used, with its entry count only, no digest and no path", () => {
  assert.equal(fixture.index.scan.forbiddenFileUsed, true);
  assert.ok(fixture.index.scan.forbiddenEntries >= 1);
  assert.deepEqual(Object.keys(fixture.index.scan).toSorted(), [
    "forbiddenEntries",
    "forbiddenFileUsed",
  ]);
});

test("exactly the four rows whose stored body holds a recorder-hashed member have no layout", () => {
  const unjudged = [];
  for (const [recipeId, rows] of fixture.recipes)
    for (const row of rows) if (row.layout === null) unjudged.push(`${recipeId}#${row.n}`);
  assert.equal(unjudged.length, 4, unjudged.join(" "));
  for (const entry of unjudged)
    assert.match(entry, /^storage-object\/(auth\/firebase-id-token|errors\/authorization)#/);
});
