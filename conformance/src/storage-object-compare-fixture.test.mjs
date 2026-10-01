import assert from "node:assert/strict";
import test from "node:test";
import {
  buildFixture,
  digestRows,
  FIXTURE_SCHEMA_VERSION,
  indexText,
  normalizeRecipe,
  recipeFileText,
  recipeSlug,
} from "./storage-object-compare/fixture.mjs";

const BUCKET = "prod-bucket.firebasestorage.app";
const PROJECT = "prod-bucket";
const exchange = (sequence, run, extra = {}) => ({
  sequence,
  method: "GET",
  url: `https://x.example/storage/v1/b/${BUCKET}/o/storage-object%2F${run}%2Fa.bin?alt=media`,
  status: 200,
  headers: { "content-type": "application/octet-stream" },
  body: Buffer.from("hello"),
  ...extra,
});
const recording = (run, bodies = ["hello"]) => ({
  runId: run,
  recipes: [
    {
      recipeId: "storage-object/gcs/a",
      exchanges: bodies.map((body, index) => exchange(index + 1, run, { body: Buffer.from(body) })),
    },
    {
      recipeId: "storage-object/firebase/b",
      exchanges: [
        exchange(9, run, {
          url: `https://x.example/v0/b/${BUCKET}/o`,
          body: Buffer.from("{}"),
          headers: { "content-type": "application/json" },
        }),
      ],
    },
  ],
});
const RUN1 = "0123456789abcdef0123";
const RUN2 = "fedcba9876543210fedc";

test("recipes are named by slug", () => {
  assert.equal(recipeSlug("storage-object/gcs/resumable-upload"), "gcs--resumable-upload");
  assert.equal(recipeSlug("storage-object/errors/range"), "errors--range");
});

test("a recipe's rows are numbered from 1 in the recording's order", () => {
  const rows = normalizeRecipe(recording(RUN1, ["a", "b", "c"]).recipes[0], {
    runId: RUN1,
    bucket: BUCKET,
    project: PROJECT,
  });
  assert.deepEqual(
    rows.map((row) => row.n),
    [1, 2, 3],
  );
});

test("a digest depends on every part of every row", () => {
  const a = [{ n: 1, x: 1 }];
  assert.equal(digestRows(a), digestRows([{ n: 1, x: 1 }]));
  assert.notEqual(digestRows(a), digestRows([{ n: 1, x: 2 }]));
  assert.notEqual(digestRows(a), digestRows([]));
  assert.match(digestRows(a), /^[0-9a-f]{64}$/);
});

test("digests are masked in a recipe whose media bytes carry the run ID, and kept in one that does not", () => {
  const carrying = {
    recipeId: "storage-object/gcs/a",
    exchanges: [
      exchange(1, RUN1, { body: Buffer.from(`bytes ${RUN1}`) }),
      exchange(2, RUN1, {
        url: `https://x.example/storage/v1/b/${BUCKET}/o/x`,
        headers: { "content-type": "application/json" },
        body: Buffer.from('{"md5Hash":"abc","crc32c":"def"}'),
      }),
    ],
  };
  const rows = normalizeRecipe(carrying, { runId: RUN1, bucket: BUCKET, project: PROJECT });
  assert.deepEqual(rows[1].body.value, { crc32c: "<DIGEST>", md5Hash: "<DIGEST>" });
  const plain = { ...carrying, exchanges: [exchange(1, RUN1), carrying.exchanges[1]] };
  assert.deepEqual(
    normalizeRecipe(plain, { runId: RUN1, bucket: BUCKET, project: PROJECT })[1].body.value,
    { crc32c: "def", md5Hash: "abc" },
  );
  // A name in a JSON body carries the run ID in every recipe: that does not count.
  const named = {
    ...carrying,
    exchanges: [
      exchange(1, RUN1, {
        url: `https://x.example/storage/v1/b/${BUCKET}/o`,
        headers: { "content-type": "application/json" },
        body: Buffer.from(`{"name":"${RUN1}"}`),
      }),
      carrying.exchanges[1],
    ],
  };
  assert.deepEqual(
    normalizeRecipe(named, { runId: RUN1, bucket: BUCKET, project: PROJECT })[1].body.value,
    { crc32c: "def", md5Hash: "abc" },
  );
  // A failed media read does not count either.
  const failed = {
    ...carrying,
    exchanges: [exchange(1, RUN1, { status: 404, body: Buffer.from(RUN1) }), carrying.exchanges[1]],
  };
  assert.deepEqual(
    normalizeRecipe(failed, { runId: RUN1, bucket: BUCKET, project: PROJECT })[1].body.value,
    { crc32c: "def", md5Hash: "abc" },
  );
});

test("two recordings that differ only in run-specific values are equivalent", () => {
  const fixture = buildFixture({
    recordings: [recording(RUN1), recording(RUN2)],
    bucket: BUCKET,
    project: PROJECT,
    source: "test",
  });
  assert.equal(fixture.index.equivalentRecordings, true);
  assert.deepEqual(fixture.index.runIds, [RUN1, RUN2]);
  assert.equal(fixture.index.schemaVersion, FIXTURE_SCHEMA_VERSION);
  assert.deepEqual(
    fixture.index.recipes.map((row) => [row.recipeId, row.file, row.rows]),
    [
      ["storage-object/gcs/a", "gcs--a.json", 1],
      ["storage-object/firebase/b", "firebase--b.json", 1],
    ],
  );
  for (const row of fixture.index.recipes)
    assert.equal(new Set(Object.values(row.digests)).size, 1);
  assert.deepEqual(Object.keys(fixture.index.recipes[0].digests), [RUN1, RUN2]);
});

test("two recordings that differ in a deterministic value are not equivalent", () => {
  const fixture = buildFixture({
    recordings: [recording(RUN1), recording(RUN2, ["different"])],
    bucket: BUCKET,
    project: PROJECT,
    source: "test",
  });
  assert.equal(fixture.index.equivalentRecordings, false);
});

test("a recording that lacks a recipe, or has another set, is refused", () => {
  const short = recording(RUN2);
  short.recipes.pop();
  assert.throws(
    () =>
      buildFixture({
        recordings: [recording(RUN1), short],
        bucket: BUCKET,
        project: PROJECT,
        source: "t",
      }),
    /different set|missing/,
  );
  const other = recording(RUN2);
  other.recipes[1].recipeId = "storage-object/firebase/c";
  assert.throws(
    () =>
      buildFixture({
        recordings: [recording(RUN1), other],
        bucket: BUCKET,
        project: PROJECT,
        source: "t",
      }),
    /missing from run/,
  );
  assert.throws(
    () => buildFixture({ recordings: [], bucket: BUCKET, project: PROJECT, source: "t" }),
    /no recording/,
  );
});

test("a recipe file has one row per line, and the index lists the masks", () => {
  const fixture = buildFixture({
    recordings: [recording(RUN1, ["a", "b"])],
    bucket: BUCKET,
    project: PROJECT,
    source: "test",
  });
  const text = recipeFileText(fixture.recipes[0]);
  const parsed = JSON.parse(text);
  assert.equal(parsed.recipeId, "storage-object/gcs/a");
  assert.equal(parsed.rows, 2);
  assert.equal(parsed.exchanges.length, 2);
  assert.deepEqual(
    text
      .split("\n")
      .slice(1, 3)
      .map((line) => JSON.parse(line.replace(/,$/, "")).n),
    [1, 2],
  );
  assert.equal("runIds" in parsed, false, "a recipe file never names a run");
  const index = JSON.parse(indexText(fixture.index));
  assert.ok(index.normalizations.length >= 14);
  assert.equal(index.normalizationVersion, 1);
});

test("only a successful media read decides that an object's bytes carry the run ID", () => {
  const rowsFor = (status) =>
    normalizeRecipe(
      {
        recipeId: "storage-object/gcs/a",
        exchanges: [
          exchange(1, RUN1, {
            status,
            body: Buffer.from(`payload ${RUN1}`),
            headers: { "content-type": "application/octet-stream", etag: `"${"a".repeat(32)}"` },
          }),
        ],
      },
      { runId: RUN1, bucket: BUCKET, project: PROJECT },
    )[0];
  assert.equal(rowsFor(206).headers.etag, "<DIGEST>");
  assert.equal(rowsFor(200).headers.etag, "<DIGEST>");
  assert.equal(rowsFor(207).headers.etag, `"${"a".repeat(32)}"`);
  assert.equal(rowsFor(404).headers.etag, `"${"a".repeat(32)}"`);
});
