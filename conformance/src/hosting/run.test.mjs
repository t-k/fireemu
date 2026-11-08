import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
const fixtures = new URL("../../hosting-fixtures/", import.meta.url);
test("every HTTP condition names a fixture configuration and is unique", async () => {
  const corpus = JSON.parse(await readFile(new URL("cases.json", fixtures), "utf8"));
  const ids = new Set();
  for (const row of corpus.cases) {
    assert.ok(corpus.configs[row.config], row.id);
    assert.ok(!ids.has(row.id), row.id);
    ids.add(row.id);
    assert.ok(row.path.startsWith("/"));
  }
  for (const name of Object.keys(corpus.configs))
    assert.ok(
      corpus.cases.some((row) => row.config === name),
      name,
    );
});
test("the committed manifest closes every fixture input", async () => {
  const manifest = JSON.parse(await readFile(new URL("manifest.json", fixtures), "utf8"));
  for (const path of manifest.files)
    assert.ok((await readFile(new URL(path, fixtures))).length > 0, path);
  const corpus = JSON.parse(await readFile(new URL("cases.json", fixtures), "utf8"));
  assert.equal(manifest.count, corpus.cases.length);
});
