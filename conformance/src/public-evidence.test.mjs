import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import * as evidence from "./evidence.mjs";
import { collectHistoricalReplay } from "./release-strict-regression.mjs";

const publicEvidence = evidence.publicEvidence;

test("every inventoried JavaScript public exporter calls the shared guard", () => {
  const sources = [
    "auth-account/run.mjs",
    "auth-action/run.mjs",
    "auth-config-sdk/run.mjs",
    "auth-credential/run.mjs",
    "auth-federation/compare.mjs",
    "auth-fs-cross/run.mjs",
    "auth-fs-cross/stage2-run.mjs",
    "auth-mfa/run.mjs",
    "auth-tenant-blocking/run.mjs",
    "fs-config-lifecycle/run.mjs",
    "fs-query-index/run.mjs",
    "fs-rules-v1/run.mjs",
    "fs-rules/run.mjs",
    "fs-ent-pipeline/native-positive.mjs",
    "eventarc-production/run.mjs",
    "fs-listen/closure-evidence.mjs",
    "storage-object-compare/closure-evidence.mjs",
    "functions-events/compare/closure-evidence.mjs",
  ];
  for (const source of sources) {
    const text = readFileSync(new URL(`../../conformance/src/${source}`, import.meta.url), "utf8");
    assert.match(text, /publicEvidence\(/, source);
  }
});

test("the evidence module exposes the shared public value guard", () => {
  assert.equal(typeof publicEvidence, "function");
});

test("the guard preserves safe values and safe repository-relative path forms", () => {
  assert.equal(typeof publicEvidence, "function");
  if (typeof publicEvidence !== "function") return;

  const value = {
    comparisonPath: "spec/compatibility/closure/evidence/example.json",
    relativeAlias: "spec/compatibility/closure/evidence/../evidence/example.json",
    name: "projects/demo/topics/topic-1",
  };
  assert.equal(publicEvidence(value), value);
});

test("the guard rejects path escapes, absolute paths and Windows traversal", () => {
  assert.equal(typeof publicEvidence, "function");
  if (typeof publicEvidence !== "function") return;

  for (const unsafe of [
    { path: "../../outside.json" },
    { comparisonPath: "safe/../../outside.json" },
    { path: "/tmp/outside.json" },
    { path: "C:\\private\\artifact.json" },
    { path: "\\\\server\\share\\artifact.json" },
    { path: "safe\\..\\..\\outside.json" },
    { path: "file:///tmp/private.json" },
    { path: "/../../outside.json", selector: true },
    { note: "local artifact path: /tmp/private.json" },
    { note: "diagnostic at /var/lib/fireemu/cache.json" },
    { path: "~/private/fireemu" },
  ]) {
    assert.throws(() => publicEvidence(unsafe));
  }
});

test("the guard refuses forbidden directories in keys or nested values without echoing them", () => {
  assert.equal(typeof publicEvidence, "function");
  if (typeof publicEvidence !== "function") return;

  const unsafe = [
    { path: "docs.local/runs/private/record.json" },
    { sourcePath: ".codex/private/notes.json" },
    { reviewPath: "docs/superpowers/private/plan.md" },
    { nested: [{ "docs.local/private": "safe" }] },
  ];
  for (const value of unsafe) {
    assert.throws(
      () => publicEvidence(value),
      (error) => {
        assert.equal(error.message.includes("docs.local"), false);
        assert.equal(error.message.includes(".codex"), false);
        assert.equal(error.message.includes("superpowers"), false);
        assert.equal(error.message.includes("private"), false);
        return true;
      },
    );
  }
});

test("the guard keeps contextual URLs, API routes, RPC identifiers and JSON selectors", () => {
  assert.equal(typeof publicEvidence, "function");
  if (typeof publicEvidence !== "function") return;

  const value = {
    url: "https://example.invalid/v1/projects/demo",
    firestoreOrigin: "https://firestore.example.invalid",
    authority: "https://firebase.google.com",
    request: { path: "/v1/projects/demo/databases/(default)/documents" },
    rpc: { path: "/google.firestore.v1.Firestore/Commit" },
    selector: "/rows/0/status",
    selectorList: "/rows/1; /groups/0",
    coordinate: "/conditions/2/cases/1",
    knownDifferences: "/knownDifferences/triggerEventShapeEmulatorProfile",
    production: ["/"],
    local: ["/"],
    rootUrl: "/",
  };
  assert.equal(publicEvidence(value), value);
  assert.throws(() => publicEvidence({ arbitrary: "/arbitrary/slash-rooted/value" }));
  assert.throws(() => publicEvidence({ selector: "/arbitrary/selector/path" }));
  assert.throws(() => publicEvidence({ selector: "/var/lib/fireemu" }));
});

test("base64 Firestore byte values preserve binary bytes but cannot hide encoded paths", () => {
  assert.equal(publicEvidence({ bytesValue: "/w==" }).bytesValue, "/w==");
  assert.equal(
    publicEvidence({ bytesValue: Buffer.from([0xff]).toString("base64") }).bytesValue,
    "/w==",
  );
  assert.throws(() =>
    publicEvidence({ bytesValue: Buffer.from("/tmp/private.json").toString("base64") }),
  );
  assert.throws(() =>
    publicEvidence({ bytesValue: Buffer.from("docs.local/private.json").toString("base64") }),
  );
});

test("release bundle validation refuses before creating either output and preserves valid bytes", async () => {
  const directory = mkdtempSync(join(tmpdir(), "public-evidence-release-"));
  const input = join(directory, "run");
  const output = join(directory, "out");
  mkdirSync(input);
  mkdirSync(output);
  const summaryPath = join(input, "historical-production-comparison.json");
  const rawPath = join(input, "fireemu-historical-production.json");
  const summaryBytes = Buffer.from('{"artifact":{"path":"../../outside.json"}}\n');
  const rawBytes = Buffer.from('{"rows":[]}\n');
  writeFileSync(summaryPath, summaryBytes);
  writeFileSync(rawPath, rawBytes);
  try {
    await assert.rejects(collectHistoricalReplay(input, output));
    assert.deepEqual(await import("node:fs").then(({ readdirSync }) => readdirSync(output)), []);

    writeFileSync(summaryPath, Buffer.from('{"artifact":{"path":"target/release/fireemu"}}\n'));
    await collectHistoricalReplay(input, output);
    assert.deepEqual(
      readFileSync(join(output, "R11-fireemu-historical-production.json")),
      rawBytes,
    );
    assert.deepEqual(
      readFileSync(join(output, "R11-historical-production-comparison.json")),
      readFileSync(summaryPath),
    );
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
