import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

import { PROGRAMS } from "./auth-account/corpus.mjs";
import { PROGRAMS as CREDENTIAL_PROGRAMS } from "./auth-credential/corpus.mjs";

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
  const execution = comparisons[0].execution;
  assert.equal(execution.schemaVersion, 1);
  assert.match(execution.receiptSha256, /^[0-9a-f]{64}$/);
  assert.equal(execution.artifactSha256, comparisons[0].artifactSha256);
  assert.match(execution.buildReceiptSha256, /^[0-9a-f]{64}$/);
  assert.equal(execution.runId, "auth-a12-attested-recompare-20260924T124006Z");
  assert.deepEqual(
    execution.commands.map(({ argv, selector, rowCount, fixtureSha256, sanitizedExportSha256 }) => ({
      argv,
      selector,
      rowCount,
      fixtureSha256,
      sanitizedExportSha256,
    })),
    [
      {
        argv: ["node", "src/auth-account/run.mjs", "check"],
        selector: { environment: "AUTH_ACCOUNT_PROGRAMS", state: "unset", meaning: "all corpus programs" },
        rowCount: 631,
        fixtureSha256: "253e48959ca7ccdefd42c64bb8371107d7aeca698a969e78bb7974898e84b8b0",
        sanitizedExportSha256: "ac7bfb7faf098cf45a590be10151d405d364e9a979ac07232bacdaef466b804b",
      },
      {
        argv: ["node", "src/auth-credential/run.mjs", "check"],
        selector: { environment: "AUTH_CREDENTIAL_PROGRAMS", state: "unset", meaning: "all corpus programs" },
        rowCount: 222,
        fixtureSha256: "fcffa45131e136404cbf3ff7f9fa40e6f78329ee665e0d27698c81f51772c0dc",
        sanitizedExportSha256: "114089e4e0cb660ae8bdd2ac5d3b69c867aa8c164c34a79efc4e2e03301f3e5c",
      },
    ],
  );
  assert.equal(Object.keys(fixture.programs).length, new Set(PROGRAMS.map(({ id }) => id)).size);
});

test("current AUTH-CREDENTIAL comparison covers every saved credential fixture row", () => {
  const fixtureText = readFileSync(
    fileURLToPath(new URL("../auth-credential-production.json", import.meta.url)),
    "utf8",
  );
  const expectedRows = CREDENTIAL_PROGRAMS.flatMap(({ id, steps }) =>
    steps.map(({ id: step }) => `${id}#${step}`),
  );
  const comparison = readJson(
    "../../spec/compatibility/closure/evidence/AUTH-CREDENTIAL-comparison.json",
  );
  const execution = comparison.execution;

  assert.equal(comparison.kind, "auth-credential-comparison-v1");
  assert.equal(
    comparison.artifactSha256,
    "a8bfc5dc1737dee01bae028b2e3dd421f04326e12640cb4936d896ebfcfa358a",
  );
  assert.equal(comparison.fixtureSha256, createHash("sha256").update(fixtureText).digest("hex"));
  assert.deepEqual(comparison.rows.map(({ row }) => row).toSorted(), expectedRows.toSorted());
  assert.deepEqual(comparison.summary, { MATCH: 222 });
  assert.ok(comparison.rows.every(({ status }) => status === "MATCH"));
  assert.equal(execution.runId, "auth-credential-current-attested-20260924T125915Z");
  assert.equal(
    execution.receiptSha256,
    "3d8b5919e47af2a86e79b956a4747c88cffcbc9723de7686a848c951b33d82c9",
  );
  assert.equal(
    execution.buildReceiptSha256,
    "45f3aece5f4303cf5ed4ea099872dab0e6e21ac9b8d2dbb5bb466777ad81c976",
  );
  assert.equal(execution.artifactSha256, comparison.artifactSha256);
  assert.deepEqual(execution.command, ["node", "src/auth-credential/run.mjs", "check"]);
  assert.deepEqual(execution.selector, {
    environment: "AUTH_CREDENTIAL_PROGRAMS",
    state: "unset",
    meaning: "all corpus programs",
  });
  assert.equal(execution.rowCount, expectedRows.length);
  assert.equal(
    execution.sanitizedExportSha256,
    "114089e4e0cb660ae8bdd2ac5d3b69c867aa8c164c34a79efc4e2e03301f3e5c",
  );
});
