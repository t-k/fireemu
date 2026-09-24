import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

import { PROGRAMS } from "./auth-account/corpus.mjs";

const readJson = (relativePath) =>
  JSON.parse(readFileSync(fileURLToPath(new URL(relativePath, import.meta.url)), "utf8"));

test("current AUTH-ACCOUNT comparison and inherited regression cover the saved fixture", () => {
  const fixtureText = readFileSync(
    fileURLToPath(new URL("../auth-account-production.json", import.meta.url)),
    "utf8",
  );
  const fixture = JSON.parse(fixtureText);
  const expectedRows = PROGRAMS.flatMap(({ id, steps }) =>
    steps.map(({ id: step }) => `${id}#${step}`),
  );
  const comparisons = [
    readJson("../../spec/compatibility/closure/evidence/AUTH-ACCOUNT-comparison.json"),
    readJson("../../spec/compatibility/closure/evidence/AUTH-CREDENTIAL-account-regression.json"),
  ];

  for (const comparison of comparisons) {
    assert.equal(comparison.kind, "auth-account-comparison-v1");
    assert.equal(
      comparison.fixtureSha256,
      createHash("sha256").update(fixtureText).digest("hex"),
    );
    assert.deepEqual(
      comparison.rows.map(({ row }) => row).toSorted(),
      expectedRows.toSorted(),
    );
    assert.deepEqual(comparison.summary, { MATCH: expectedRows.length });
    assert.ok(comparison.rows.every(({ status }) => status === "MATCH"));
    assert.equal(
      comparison.rows.find(({ row }) => row === "auth-account/admin/custom-attributes#invalid-json")
        ?.status,
      "MATCH",
    );
  }

  assert.deepEqual(comparisons[0], comparisons[1]);
  assert.equal(Object.keys(fixture.programs).length, new Set(PROGRAMS.map(({ id }) => id)).size);
});
