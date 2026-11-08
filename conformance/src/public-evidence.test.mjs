import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import * as evidence from "./evidence.mjs";
import { collectHistoricalReplay } from "./release-strict-regression.mjs";

const publicEvidence = evidence.publicEvidence;

test("unbound JavaScript public exporters call the shared guard", () => {
  // Digest-bound exporters retain their historical bytes; release copies validate new output.
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
    "fs-rules-v1/run.mjs",
    "fs-rules/run.mjs",
    "fs-ent-pipeline/native-positive.mjs",
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
    { path: "docs/./superpowers/private/plan.md" },
    { path: "docs//superpowers/private/plan.md" },
    { path: "docs/intermediate/../superpowers/private/plan.md" },
    { "docs/intermediate/../superpowers/private/plan.md": "safe" },
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
    source: "https://firebase.google.com/docs",
    request: { path: "/v1/projects/demo/databases/(default)/documents" },
    actionRequest: {
      path: "/v1/projects/demo/databases/(default)/documents:executePipeline",
    },
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
  assert.throws(() => publicEvidence({ selector: "//home-of-a-user/private.json" }));
  assert.throws(() => publicEvidence({ selector: "//home-of-a-user/private.json; /rows/0" }));
  assert.throws(() => publicEvidence({ selector: "/var/lib/fireemu" }));
  assert.throws(() => publicEvidence({ path: "/v1/../../etc/private.json" }));
  assert.throws(() =>
    publicEvidence({ rpcPath: "/google.firestore.v1.Firestore/../../etc/private.json" }),
  );
  assert.throws(() => publicEvidence({ artifactPath: "/v1/projects/demo" }));
});

test("the guard validates every selector component and percent-encoded paths", () => {
  const path = "/" + ["Users", "alice", "private.json"].join("/");
  for (const selector of [
    `/rows/0; /${path}`,
    `/rows/0; C:${path}`,
    encodeURIComponent(`/${path}`),
    `/rows/0; ${encodeURIComponent(`/${path}`)}`,
    "/rows/0, /arbitrary/private.json",
    "/rows/0 /arbitrary/private.json",
  ]) {
    assert.throws(() => publicEvidence({ selector }));
  }
  const safe = { selector: "%2Frows%2F0; %2Fgroups%2F0" };
  assert.equal(publicEvidence(safe), safe);
});

test("only the historical comparison root profileBinding bypasses the guard", async (t) => {
  const directory = mkdtempSync(join(tmpdir(), "public-evidence-binding-"));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const output = join(directory, "out");
  mkdirSync(output);
  const summaryPath = join(directory, "historical-production-comparison.json");
  const rawPath = join(directory, "fireemu-historical-production.json");
  const profileBinding = {
    cwd: "/repo/conformance",
    config: { path: "/repo/config.json" },
    indexes: { path: "/repo/indexes.json" },
    argv: ["/repo/fireemu", "--config", "/repo/config.json"],
  };
  const comparison = { profileBinding, rows: [] };
  assert.throws(() => publicEvidence(comparison));
  const bytes = Buffer.from(JSON.stringify(comparison));
  writeFileSync(summaryPath, bytes);
  writeFileSync(rawPath, '{"rows":[]}');
  const collected = await collectHistoricalReplay(directory, output);
  assert.deepEqual(collected.result, comparison);
  assert.deepEqual(readFileSync(join(output, "R11-historical-production-comparison.json")), bytes);

  for (const extra of [
    { nested: { profileBinding } },
    { rows: [{ profileBinding }] },
    { path: "/repo/private.json" },
  ]) {
    writeFileSync(summaryPath, JSON.stringify({ ...comparison, ...extra }));
    await assert.rejects(collectHistoricalReplay(directory, output));
  }
  for (const binding of [
    { ...profileBinding, unexpected: { path: "/repo/private.json" } },
    { ...profileBinding, config: { ...profileBinding.config, extra: "/repo/private.json" } },
    { ...profileBinding, argv: [{ path: "/repo/private.json" }] },
  ]) {
    writeFileSync(summaryPath, JSON.stringify({ profileBinding: binding, rows: [] }));
    await assert.rejects(collectHistoricalReplay(directory, output));
  }
  for (const comparison of ["/repo/private.json", [{ profileBinding }]]) {
    writeFileSync(summaryPath, JSON.stringify(comparison));
    await assert.rejects(collectHistoricalReplay(directory, output));
  }
  writeFileSync(summaryPath, bytes);
  writeFileSync(rawPath, JSON.stringify({ profileBinding }));
  await assert.rejects(collectHistoricalReplay(directory, output));
});

test("the historical daemonLog may name only the binding's own paths", async (t) => {
  const directory = mkdtempSync(join(tmpdir(), "public-evidence-daemon-log-"));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const output = join(directory, "out");
  mkdirSync(output);
  const summaryPath = join(directory, "historical-production-comparison.json");
  writeFileSync(join(directory, "fireemu-historical-production.json"), '{"rows":[]}');
  const cwd = "/work/fireemu/fireemu/conformance";
  const config = `${cwd}/.runs/firestore-probe/strict-config-1.json`;
  // The banner fireemu exec prints, as the strict historical replay records it (v0.45.0 run).
  const daemonLog = [
    `note: ${config}: firestore.rules is accepted but never read`,
    "fireemu exec",
    `  config:           ${config} (--config); ${cwd}/firebase.json in a parent directory is not loaded`,
    "  control API:      http://127.0.0.1:64251/v1/  (health: /health/live)",
    "  profile: strict (behaves like production Firebase where the official emulators do not)",
    "",
  ].join("\n");
  const profileBinding = {
    requestedProfile: "strict",
    effectiveProfile: "strict",
    daemonLog,
    cwd,
    // A relative argument is not a path the binding publishes, so it masks nothing.
    argv: ["exec", "--config", config, "--", "node", "Users"],
    binary: { path: "/tmp/fireemu-verify.x/fireemu try ✓/bin/fireemu" },
    config: { path: config, sourcePath: `${cwd}/firestore-probe.fireemu.json` },
    indexes: { path: `${cwd}/.runs/firestore-probe/strict-indexes-1.json` },
  };
  const bytes = Buffer.from(JSON.stringify({ profileBinding, rows: [] }));
  writeFileSync(summaryPath, bytes);
  await collectHistoricalReplay(directory, output);
  assert.deepEqual(readFileSync(join(output, "R11-historical-production-comparison.json")), bytes);

  for (const extra of [
    // Home prefixes are built from parts: published files may not spell them (publication hygiene).
    `\n  logging: /${"home"}/runner/private.log\n`,
    `\n  note: /${"Users"}/someone/secret.json\n`,
    `\n  note: ${cwd}-other/secret.json\n`,
    "\n  note: C:\\Users\\someone\\secret.json\n",
    // Only the exact exempt path is masked: a dot in it matches no other character.
    "\n  binary: /tmp/fireemu-verifyXx/fireemu try ✓/bin/fireemu\n",
  ]) {
    const binding = { ...profileBinding, daemonLog: `${daemonLog}${extra}` };
    writeFileSync(summaryPath, JSON.stringify({ profileBinding: binding, rows: [] }));
    await assert.rejects(collectHistoricalReplay(directory, output), extra);
  }
  // A daemonLog outside the root profileBinding gets no allowance.
  writeFileSync(summaryPath, JSON.stringify({ profileBinding, rows: [{ daemonLog }] }));
  await assert.rejects(collectHistoricalReplay(directory, output));
});

test("the API exception preserves finite EVENTARC channel query shapes and refuses unsafe queries", () => {
  const safe = {
    pageSize: { path: "/v1/projects/demo/locations/global/channels?pageSize=1" },
    invalidPageSize: { path: "/v1/projects/demo/locations/global/channels?pageSize=-1" },
    largePageSize: { path: "/v1/projects/demo/locations/global/channels?pageSize=100000" },
    pageToken: { path: "/v1/projects/demo/locations/global/channels?pageToken=next_page-1" },
    scalarFilter: {
      path: "/v1/projects/demo/locations/global/channels?filter=type%3Dgoogle.cloud.audit.log.v1.written%20OR%20state%3DACTIVE",
    },
    resourceFilter: {
      path: "/v1/projects/demo/locations/global/channels?filter=name%3Dprojects%2Fdemo%2Flocations%2Fglobal%2Fchannels%2Fone",
    },
    createChannel: {
      path: "/v1/projects/demo/locations/global/channels?channelId=channel-one",
    },
  };
  assert.equal(publicEvidence(safe), safe);

  for (const path of [
    "/v1/projects/demo/locations/global/channels?pageToken=%2e%2e%2Fetc",
    "/v1/projects/demo/locations/global/channels?pageSize=%2Ftmp%2Fprivate.json",
    "/v1/projects/demo/locations/global/channels?filter=docs%2Elocal",
    "/v1/projects/demo/locations/global/channels?filter=%2Ftmp%2Fprivate.json",
    "/v1/projects/demo/locations/global/channels?filter=name%3D..%2Fetc",
    "/v1/projects/demo/locations/global/channels?filter=arbitrary%2Fprivate%2Fpath",
    "/v1/projects/demo/locations/global/channels?unexpected=value",
  ]) {
    assert.throws(() => publicEvidence({ path }));
  }
});

test("base64 Firestore byte values preserve binary bytes but cannot hide encoded paths", () => {
  assert.equal(publicEvidence({ bytesValue: "/w==" }).bytesValue, "/w==");
  assert.equal(publicEvidence({ bytesValue: "/wAA" }).bytesValue, "/wAA");
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

test("release export copies validate all retained snapshots before writing exact bytes", async (t) => {
  const { copyValidatedExportSnapshots } = await import("./release-strict-regression.mjs");
  assert.equal(typeof copyValidatedExportSnapshots, "function");
  const dir = mkdtempSync(join(tmpdir(), "release-export-snapshots-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const firstSource = join(dir, "R1-export.json");
  const secondSource = join(dir, "R2-export.json");
  const firstOutput = join(dir, "comparison-1.json");
  const secondOutput = join(dir, "comparison-2.json");
  const firstBytes = Buffer.from('{"rows":[]}\r\n');
  const secondBytes = Buffer.from('{"url":"https://firebase.google.com"}\n');
  writeFileSync(firstSource, firstBytes);
  writeFileSync(secondSource, '{"path":"docs.local/private-export.json"}\n');
  writeFileSync(firstOutput, "keep first output");
  writeFileSync(secondOutput, "keep second output");
  const copies = [
    { from: "R1-export.json", to: "comparison-1.json" },
    { from: "R2-export.json", to: "comparison-2.json" },
  ];
  await assert.rejects(copyValidatedExportSnapshots(dir, copies));
  assert.equal(readFileSync(firstOutput, "utf8"), "keep first output");
  assert.equal(readFileSync(secondOutput, "utf8"), "keep second output");

  writeFileSync(secondSource, secondBytes);
  let reads = 0;
  let writes = 0;
  await copyValidatedExportSnapshots(dir, copies, {
    readSource: (path) => {
      reads += 1;
      return readFileSync(path);
    },
    writeDestination: (path, bytes) => {
      writes += 1;
      if (writes === 1)
        writeFileSync(secondSource, '{"path":"docs.local/changed-after-read.json"}\n');
      writeFileSync(path, bytes);
    },
  });
  assert.equal(reads, 2);
  assert.equal(writes, 2);
  assert.deepEqual(readFileSync(firstOutput), firstBytes);
  assert.deepEqual(readFileSync(secondOutput), secondBytes);
});
