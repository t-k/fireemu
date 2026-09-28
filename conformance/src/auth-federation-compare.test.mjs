import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import {
  COMPARISONS,
  classify,
  compareRows,
  differences,
  evidenceOf,
  summarize,
} from "./auth-federation/compare.mjs";
import { SOURCES, programDigests } from "./auth-federation/record.mjs";

const row = (status) => ({ status: 200, body: { status } });

test("a row matches production's first recording, or its second as nondeterministic", () => {
  const production = { status: 200, body: { a: 1, b: [1, 2] } };
  // Member order does not matter; array order does.
  assert.equal(
    classify({ production, fireemu: { body: { b: [1, 2], a: 1 }, status: 200 } }),
    "MATCH",
  );
  assert.equal(
    classify({ production, fireemu: { status: 200, body: { a: 1, b: [2, 1] } } }),
    "MISMATCH",
  );
  const alternative = row("other");
  assert.equal(
    classify({ production, alternative, fireemu: row("other") }),
    "MATCH_NONDETERMINISTIC",
  );
  assert.equal(classify({ production, alternative, fireemu: row("third") }), "MISMATCH");
  assert.equal(classify({ production, fireemu: undefined }), "MISSING");
  assert.equal(classify({ production: undefined, fireemu: production }), "MISSING");
  assert.equal(classify({ stale: true, production, fireemu: production }), "STALE");
});

test("a program changed since its recording is stale, and a fixture program without one is an orphan", () => {
  const programs = [
    { id: "auth-federation/x", steps: [{ id: "one" }, { id: "two" }] },
    { id: "auth-federation/y", steps: [{ id: "one" }] },
  ];
  const digests = programDigests(programs);
  const fixture = {
    programs: {
      "auth-federation/x": {
        corpusDigest: digests["auth-federation/x"],
        steps: { one: row("a"), two: row("b") },
        second: { two: row("c") },
      },
      "auth-federation/y": { corpusDigest: "changed", steps: { one: row("a") } },
      "auth-federation/gone": { corpusDigest: "d", steps: { one: row("a") } },
    },
  };
  const results = {
    "auth-federation/x": { steps: { one: row("a"), two: row("c") } },
    "auth-federation/y": { steps: { one: row("a") } },
  };
  const { rows, orphans } = compareRows({ programs }, fixture, results);
  assert.deepEqual(
    rows.map(({ row: id, status }) => [id, status]),
    [
      ["auth-federation/x#one", "MATCH"],
      ["auth-federation/x#two", "MATCH_NONDETERMINISTIC"],
      ["auth-federation/y#one", "STALE"],
    ],
  );
  assert.deepEqual(orphans, ["auth-federation/gone"]);
  assert.deepEqual(summarize(rows), { MATCH: 1, MATCH_NONDETERMINISTIC: 1, STALE: 1 });
});

test("the public evidence names member paths of a differing row, never its values", () => {
  const production = {
    status: 200,
    body: { name: "projects/1/x", enabled: true, nested: { a: 1 } },
  };
  const fireemu = {
    status: 200,
    body: { name: "projects/p/x", nested: { a: 2 }, extra: "secret-value" },
  };
  assert.deepEqual(differences(production, fireemu), [
    "body.enabled",
    "body.extra",
    "body.name",
    "body.nested.a",
  ]);
  const corpus = COMPARISONS["record-oidc"];
  const comparison = {
    artifactSha256: "a".repeat(64),
    summary: { MATCH: 1, MISMATCH: 1 },
    rows: [
      { row: "p#one", status: "MATCH", production, fireemu: production },
      { row: "p#two", status: "MISMATCH", production, fireemu },
    ],
  };
  const evidence = evidenceOf(corpus, comparison, "fixture text");
  assert.deepEqual(evidence, {
    kind: "auth-federation-comparison-v1",
    artifactSha256: "a".repeat(64),
    fixtureSha256: createHash("sha256").update("fixture text").digest("hex"),
    summary: { MATCH: 1, MISMATCH: 1 },
    rows: [
      { row: "p#one", status: "MATCH" },
      {
        row: "p#two",
        status: "MISMATCH",
        differences: ["body.enabled", "body.extra", "body.name", "body.nested.a"],
      },
    ],
  });
  assert.ok(!JSON.stringify(evidence).includes("secret-value"));
});

test("each corpus is compared with its own fixture under its own evidence kind", () => {
  assert.deepEqual(Object.keys(COMPARISONS), ["record-oidc", "record-saml", "record-followup"]);
  const kinds = Object.values(COMPARISONS).map(({ kind }) => kind);
  assert.equal(new Set(kinds).size, kinds.length);
  for (const corpus of Object.values(COMPARISONS)) {
    const path = fileURLToPath(new URL(`../${corpus.fixture}`, import.meta.url));
    // A corpus not yet recorded has no fixture to cover.
    if (!existsSync(path)) continue;
    const fixture = JSON.parse(readFileSync(path, "utf8"));
    // Every fixture program is a program of its corpus: the comparison covers the fixture.
    const ids = new Set(corpus.programs.map(({ id }) => id));
    assert.deepEqual(
      Object.keys(fixture.programs).filter((id) => !ids.has(id)),
      [],
      corpus.fixture,
    );
  }
});

test("the comparison is not part of the recorded harness", () => {
  assert.ok(!SOURCES.some((path) => path.endsWith("/compare.mjs")));
});
