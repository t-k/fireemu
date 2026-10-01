import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { buildCorpus } from "./storage-rules/corpus.mjs";
import { buildDeclaredRequestManifest } from "./storage-rules/manifest.mjs";

const closure = JSON.parse(
  readFileSync(new URL("../../spec/compatibility/closure/STORAGE-RULES.json", import.meta.url)),
);
const binding = {
  bucket: "synthetic-rules-bucket",
  prefix: "STORAGE-RULES/local-run/",
  uidA: "local-user-a",
  uidB: "local-user-b",
};

test("declared request manifest gives every object and Firestore step one stable ID", () => {
  const corpus = buildCorpus(binding);
  const manifest = buildDeclaredRequestManifest(corpus, closure);
  assert.equal(manifest.status, "LOCAL_PARTIAL_NO_SEND");
  assert.equal(manifest.sendAuthorized, false);
  assert.equal(manifest.rows.length, 3799);
  assert.deepEqual(manifest.counts, { storage: 3739, firestore: 60 });
  assert.equal(new Set(manifest.rows.map((row) => row.id)).size, manifest.rows.length);
  assert.equal(manifest.rows.filter((row) => row.stage === "subject").length, 331);
  assert.equal(
    manifest.rows.some((row) => row.id.includes("token-expired") || row.id.includes("iam-denied")),
    false,
  );
  assert.equal(manifest.rows.filter((row) => row.stage === "comparison").length, 1);
  assert.deepEqual(
    new Set(
      manifest.rows.filter((row) => row.family === "firestore-program").map((row) => row.programId),
    ),
    new Set(corpus.firestorePrograms.map((program) => program.id)),
  );
  assert.ok(manifest.rows.every((row) => row.request.capture.body === "raw-bytes"));
  assert.equal(buildDeclaredRequestManifest(buildCorpus(binding), closure).sha256, manifest.sha256);
});

test("manifest rejects a changed declaration and does not alias mutable inputs", () => {
  const changed = buildCorpus(binding);
  changed.cases[0].subject.path = "/storage/v1/b/unowned/o";
  assert.throws(
    () => buildDeclaredRequestManifest(changed, closure),
    /request|corpus|route|declaration/,
  );

  const corpus = buildCorpus(binding);
  const manifest = buildDeclaredRequestManifest(corpus, closure);
  const originalPath = manifest.rows[0].request.path;
  corpus.cases[0].baseline[0].path = "/changed";
  assert.equal(manifest.rows[0].request.path, originalPath);
});
