import assert from "node:assert/strict";
import test from "node:test";

import { compareFiles, loadKnownDifferences } from "./compare.mjs";
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

test("the init.js layout is compared between two recordings, not between production and local", () => {
  const initJs = requests.find((r) => r.target === "/__/firebase/init.js");
  const rowOf = (lines) =>
    requests.map((spec) =>
      spec.id === initJs.id
        ? shapeRow(
            spec,
            { ...answer(200), body: Buffer.from("x\n".repeat(lines)) },
            { origin: "http://o", secrets: [] },
          )
        : shapeRow(spec, answer(200), { origin: "http://o", secrets: [] }),
    );
  const [a, b] = [file("a", rowOf(3)), file("b", rowOf(5))];
  const local = compareFiles({ kind: "production-vs-local", left: a, right: b, corpus });
  assert.equal(local.rows.find((r) => r.id === initJs.id).status, "MATCH");
  const runs = compareFiles({ kind: "run-vs-run", left: a, right: b, corpus });
  assert.equal(runs.rows.find((r) => r.id === initJs.id).status, "MISMATCH");
});

test("the known differences name corpus rows, a reason, an authority and the comparisons they apply to", () => {
  const entries = loadKnownDifferences(corpus);
  const ids = new Set(requests.map((request) => request.id));
  assert.equal(new Set(entries.map((entry) => entry.id)).size, entries.length);
  for (const entry of entries) {
    assert.ok(entry.rows.length > 0 && entry.rows.every((id) => ids.has(id)), entry.id);
    assert.ok(
      entry.fields === "*" || (Array.isArray(entry.fields) && entry.fields.length > 0),
      entry.id,
    );
    assert.ok(entry.reason.length > 60, `${entry.id} has a reason`);
    assert.match(entry.authority, /coordinator ruling 1[5-7]/, entry.id);
    assert.ok(
      entry.appliesTo.length > 0 &&
        entry.appliesTo.every((kind) => ["production-vs-local", "run-vs-run"].includes(kind)),
    );
  }
  // an unknown row id is refused when the file is loaded
  assert.throws(
    () => loadKnownDifferences({ versions: [{ requests: [{ id: "v01.none" }] }] }),
    /not a corpus request/,
  );
});

test("a known difference is reported by the comparison and a covered row is not a mismatch", () => {
  const known = [
    { id: "KD-T", rows: [requests[0].id], fields: ["status"], appliesTo: ["production-vs-local"] },
  ];
  const left = rowsOf(200);
  const right = rowsOf(200);
  right[0] = shapeRow(requests[0], answer(404), { origin: "http://o", secrets: [] });
  const withEntry = compareFiles({
    kind: "production-vs-local",
    left: file("a", left),
    right: file("b", right),
    corpus,
    known,
  });
  assert.equal(withEntry.summary.MISMATCH, 0);
  assert.deepEqual(withEntry.knownDifferences, [{ id: "KD-T", rows: 1 }]);
  assert.deepEqual(withEntry.rows[0].known, [{ field: "status", entry: "KD-T" }]);
  const without = compareFiles({
    kind: "production-vs-local",
    left: file("a", left),
    right: file("b", right),
    corpus,
    known: [],
  });
  assert.equal(without.summary.MISMATCH, 1);
  // the same entry does not apply to a run-vs-run comparison
  const runs = compareFiles({
    kind: "run-vs-run",
    left: file("a", left),
    right: file("b", right),
    corpus,
    known,
  });
  assert.equal(runs.summary.MISMATCH, 1);
});
