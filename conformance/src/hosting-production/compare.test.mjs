import assert from "node:assert/strict";
import test from "node:test";

import { compareFiles } from "./compare.mjs";
import { buildCorpus, corpusManifest } from "./corpus.mjs";
import { shapeRow } from "./rows.mjs";

const corpus = buildCorpus();
const requests = corpus.versions.flatMap((v) => v.requests);
const answer = (status = 200) => ({
  outcome: "answered",
  status,
  headers: [["content-type", "text/plain"]],
  body: Buffer.from("x"),
});
const rowsOf = (status) =>
  requests.map((spec) => shapeRow(spec, answer(status), { origin: "http://o", secrets: [] }));
const file = (name, rows, corpusSha256 = corpusManifest(corpus).corpusSha256) => ({
  name,
  sha256: "0".repeat(64),
  value: { corpusSha256, rows },
});

test("identical row files match on every request and every condition is closable", () => {
  const result = compareFiles({
    kind: "production-vs-local",
    left: file("a", rowsOf(200)),
    right: file("b", rowsOf(200)),
    corpus,
  });
  assert.equal(result.summary.MATCH, requests.length);
  assert.ok(Object.values(result.conditions).every((c) => c.closable));
  assert.equal(result.conditions["path-safety"], undefined);
});

test("a changed status is a mismatch that names the request; a missing row is unknown", () => {
  const left = rowsOf(200);
  const right = rowsOf(200);
  right[0] = shapeRow(requests[0], answer(404), { origin: "http://o", secrets: [] });
  right.pop();
  const result = compareFiles({
    kind: "production-vs-local",
    left: file("a", left),
    right: file("b", right),
    corpus,
  });
  assert.equal(result.rows[0].status, "MISMATCH");
  assert.equal(result.rows.at(-1).status, "UNKNOWN");
  assert.equal(result.summary.MISMATCH, 1);
});

test("a row file of another corpus is refused", () => {
  assert.throws(
    () =>
      compareFiles({
        kind: "run-vs-run",
        left: file("a", rowsOf(200), "f".repeat(64)),
        right: file("b", rowsOf(200)),
        corpus,
      }),
    /not a row file of the pinned corpus/,
  );
});
