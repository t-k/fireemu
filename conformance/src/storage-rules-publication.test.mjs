import assert from "node:assert/strict";
import test from "node:test";
import { buildCorpus } from "./storage-rules/corpus.mjs";
import { buildPublicationSources } from "./storage-rules/publication.mjs";

const binding = {
  bucket: "synthetic-rules-bucket",
  prefix: "STORAGE-RULES/local-run/",
  uidA: "local-user-a",
  uidB: "local-user-b",
};

test("publication bundles preserve every isolated case body under its Rules version", () => {
  const corpus = buildCorpus(binding);
  const bundles = buildPublicationSources(corpus, binding);
  assert.deepEqual(bundles.map((bundle) => [bundle.version, bundle.caseIds.length]), [[1, 7], [2, 329]]);
  const expectedIds = [...corpus.cases, ...corpus.firestorePrograms].map((entry) => entry.id);
  assert.deepEqual(new Set(bundles.flatMap((bundle) => bundle.caseIds)), new Set(expectedIds));
  assert.equal(bundles.flatMap((bundle) => bundle.caseIds).length, expectedIds.length);
  for (const bundle of bundles) {
    assert.ok(bundle.bytes < 256 * 1024);
    assert.match(bundle.sha256, /^[a-f0-9]{64}$/);
    for (const id of bundle.caseIds) {
      const entry = [...corpus.cases, ...corpus.firestorePrograms].find((item) => item.id === id);
      const fragment = entry.rulesSource.match(/    match \/[^\n]+ \{[\s\S]*?\n    \}/)?.[0];
      assert.ok(fragment, id);
      assert.ok(bundle.content.includes(fragment), id);
    }
  }
});

test("publication refuses overlapping owned paths and a changed match prefix", () => {
  const corpus = buildCorpus(binding);
  corpus.cases[1].rulesSource = corpus.cases[1].rulesSource.replace(corpus.cases[1].casePrefix, corpus.cases[0].casePrefix);
  corpus.cases[1].casePrefix = corpus.cases[0].casePrefix;
  assert.throws(() => buildPublicationSources(corpus, binding), /case prefix|overlap|duplicate/);
  const changed = buildCorpus(binding);
  changed.cases[0].rulesSource = changed.cases[0].rulesSource.replace(changed.cases[0].casePrefix, `${binding.prefix}other/`);
  assert.throws(() => buildPublicationSources(changed, binding), /match prefix/);
});

test("publication refuses a case match outside the owned run prefix", () => {
  const corpus = buildCorpus(binding);
  const original = corpus.cases[0].casePrefix;
  corpus.cases[0].casePrefix = `unowned/${corpus.cases[0].id}/`;
  corpus.cases[0].rulesSource = corpus.cases[0].rulesSource.replace(original, corpus.cases[0].casePrefix);
  assert.throws(() => buildPublicationSources(corpus, binding), /owned prefix|case prefix/);
});

test("publication refuses a sibling match with noncanonical indentation", () => {
  const corpus = buildCorpus(binding);
  corpus.cases[0].rulesSource = corpus.cases[0].rulesSource.replace(
    "\n    }\n  }\n}\n",
    "\n    }\n     match /{allPaths=**} {\n       allow read: if true;\n     }\n  }\n}\n",
  );
  assert.throws(() => buildPublicationSources(corpus, binding), /wrapper|match count/);
});

test("publication refuses a malformed wrapper", () => {
  const corpus = buildCorpus(binding);
  corpus.cases[0].rulesSource = corpus.cases[0].rulesSource.slice(0, -2);
  assert.throws(() => buildPublicationSources(corpus, binding), /wrapper/);
});
