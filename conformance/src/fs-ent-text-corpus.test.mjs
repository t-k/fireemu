import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { Firestore } from "@google-cloud/firestore";
import { documentMatches, score } from "@google-cloud/firestore/pipelines";
import { PROGRAMS, INDEXES } from "./fs-ent-pipeline/text-corpus.mjs";
import { validateCorpus } from "./fs-ent-pipeline/harness.mjs";
import { LANES } from "./fs-query-index/lanes.mjs";

test("text observations use the existing named Enterprise sandbox lane and bounded request guard", () => {
  assert.equal(LANES["fs-ent-text"].database, "entpipe1");
  assert.equal(LANES["fs-ent-text"].harness, "src/fs-ent-pipeline");
  assert.equal(validateCorpus(PROGRAMS, "fs-ent-text"), PROGRAMS[0].steps.length);
  assert.ok(PROGRAMS[0].steps.length >= 60 && PROGRAMS[0].steps.length <= 140);
});
test("the corpus preserves exact score and ordering requests over both transports", () => {
  const steps = PROGRAMS.flatMap((p) => p.steps);
  for (const id of [
    "rank-desc",
    "rank-asc",
    "default-order",
    "offset-limit",
    "retrieval-depth",
    "negative-only",
    "unicode-fold",
    "cjk",
    "phrase-cross-field",
    "after-update",
    "after-delete",
  ]) {
    assert.ok(
      steps.some((s) => s.id === id),
      id,
    );
    assert.ok(
      steps.some((s) => s.id === `${id}-grpc`),
      `${id}-grpc`,
    );
  }
  const scoredOptions = steps.find((s) => s.id === "rank-desc").body.structuredPipeline.pipeline
    .stages[1].options;
  assert.deepEqual(scoredOptions.add_fields, {
    mapValue: { fields: { rank: { functionValue: { name: "score", args: [] } } } },
  });
  assert.equal(
    scoredOptions.sort.arrayValue.values[0].mapValue.fields.direction.stringValue,
    "descending",
  );
});
test("native index definitions and all text seeds share one finite owned collection", () => {
  assert.equal(INDEXES.indexes.length, 1);
  assert.equal(INDEXES.indexes[0].collectionGroup, "textobs1");
  assert.equal(INDEXES.indexes[0].searchIndexOptions.textLanguage, "en");
  for (const p of PROGRAMS)
    for (const [name] of p.seed) assert.match(name, /^textobs1\/[a-z0-9-]+$/);
  const seeds = PROGRAMS[0].seed;
  assert.ok(seeds.some(([, d]) => d.title?.stringValue?.includes("Straße")));
  assert.ok(seeds.some(([, d]) => d.title?.stringValue?.includes("東京")));
  assert.ok(seeds.some(([, d]) => d.title?.integerValue));
});

test("the score observation uses the installed SDK wire shape without sending a request", async () => {
  const db = new Firestore({ projectId: "demo-text-wire" });
  try {
    const actual = db
      .pipeline()
      .collection("textobs1")
      .search({
        query: documentMatches("fox"),
        sort: score().descending(),
        addFields: [score().as("rank")],
      })
      ._toProto();
    // Protobuf omits empty repeated fields and empty option maps in either representation.
    const canonical = (v) =>
      Array.isArray(v)
        ? v.map(canonical)
        : v && typeof v === "object"
          ? Object.fromEntries(
              Object.entries(v)
                .filter(
                  ([k, x]) =>
                    !(k === "args" && Array.isArray(x) && x.length === 0) &&
                    !(k === "options" && Object.keys(x).length === 0),
                )
                .map(([k, x]) => [k, canonical(x)]),
            )
          : v;
    const expected = PROGRAMS[0].steps.find((s) => s.id === "rank-desc").body.structuredPipeline
      .pipeline;
    assert.deepEqual(canonical(actual), canonical(expected));
  } finally {
    await db.terminate();
  }
});

test("local index files and named-database routing match the reviewed text corpus", async () => {
  const load = async (name) =>
    JSON.parse(await readFile(new URL(`../${name}`, import.meta.url), "utf8"));
  assert.deepEqual(await load("fs-ent-text.indexes.json"), INDEXES);
  assert.deepEqual((await load("fs-ent-text.firebase.json")).firestore, [
    { database: "entpipe1", rules: "firestore-probe.rules", indexes: "fs-ent-text.indexes.json" },
  ]);
  assert.equal(
    LANES["fs-ent-text"].indexes,
    null,
    "shared default-database index deployment is never used",
  );
});
