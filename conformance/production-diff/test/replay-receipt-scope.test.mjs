// Orchestration regression: byte-identical pilot/core/registry, real file I/O and
// process supervision. Preparation, comparison and the daemon are EXPLICIT test
// doubles: no Firebase runtime, historical oracle, or production is exercised.
import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { test } from "node:test";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { CASES } from "../registry.mjs";
import { sha256 } from "../core.mjs";

const source = new URL("../", import.meta.url);
const syntheticBinary = "SYNTHETIC-DAEMON-TEST-DOUBLE\n";

async function harness(t, adapter, options = {}) {
  const root = await fs.mkdtemp(join(tmpdir(), "pilot-receipt-scope-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const repo = join(root, "repository 日本語");
  const modules = join(repo, "conformance", "production-diff");
  await fs.mkdir(modules, { recursive: true });
  // Do not extract or rewrite the function under test. Copy these full modules.
  for (const name of ["pilot.mjs", "core.mjs", "registry.mjs"]) {
    const bytes = await fs.readFile(new URL(name, source));
    await fs.writeFile(join(modules, name), bytes);
    assert.deepEqual(await fs.readFile(join(modules, name)), bytes);
  }
  await fs.writeFile(join(modules, "fixture-options.json"), JSON.stringify(options));
  await fs.writeFile(join(modules, "fixture.mjs"), `
import { promises as fs } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { digestJson, sha256, equal } from "./core.mjs";
export const options = JSON.parse(await fs.readFile(new URL("fixture-options.json", import.meta.url)));
export const syntheticBinary = ${JSON.stringify(syntheticBinary)};
export function compare({ entry, actual }) {
  const ids = entry.adapter === "g0" ? ["fixture-g0-row"] : entry.stepIds;
  const mismatch = actual.fixtureMismatch === true;
  return {
    verdict: mismatch ? "MISMATCH" : "MATCH",
    counts: { match: ids.length - Number(mismatch), mismatch: Number(mismatch), indeterminate: 0 },
    rows: ids.map((id, i) => ({ stepId: id, comparison: mismatch && i === 0 ? "MISMATCH" : "MATCH" })),
    issues: [], legacySummary: null, legacyMismatchesIncludesIndeterminate: false,
  };
}
export async function prepare(repo, registered) {
  const program = {
    id: registered.programId, area: "writes", seed: [{ fixture: true }],
    steps: registered.stepIds.map(id => ({ id, method: "GET", path: "/v1/projects/PROJECT/databases/(default)/documents/fixture/x" })),
  };
  const entry = { ...registered, programDigest: digestJson(program) };
  return {
    entry, program, production: { fixture: true }, state: { head: "a".repeat(40), dirty: false },
    comparator: ({ fireemu }) => ({ rows: entry.stepIds.map(id => ({
      id, comparison: fireemu[entry.programId].steps[id].status === 200 ? "match" : "mismatch",
      production: { fixture: true }, local: { fixture: true },
    })) }),
    provenance: { oracle: { fixture: true }, implementation: {
      adapterSha256: { fixture: "a".repeat(64) },
      comparatorSliceSha256: entry.comparatorSliceSha256,
      sessionBlob: entry.sessionBlob, credentialsBlob: entry.credentialsBlob,
      build: entry.adapter === "g0" ? {
        artifactSha256: sha256(syntheticBinary), retainedManifestSha256: "b".repeat(64),
        artifactProfile: "fixture", runtimeSourceCommit: "a".repeat(40), sourceInputsDigest: "c".repeat(64),
      } : null,
    } },
  };
}
export async function unchanged() { return !options.sourceChanged; }
`);
  await fs.writeFile(join(modules, "legacy.mjs"), `
export { prepare, unchanged as sourceUnchanged } from "./fixture.mjs";
import { promises as fs } from "node:fs";
export async function stageLegacy(_prepared, directory) { await fs.mkdir(directory); }
`);
  await fs.writeFile(join(modules, "commit-transform.mjs"), `
export { prepare as prepareCommitTransform, unchanged as commitTransformSourceUnchanged, compare as compareCommitTransform } from "./fixture.mjs";
`);
  await fs.writeFile(join(modules, "g0.mjs"), `
export { prepare as prepareG0, unchanged as g0SourceUnchanged, compare as compareG0 } from "./fixture.mjs";
`);
  // The wrapper changes only the native executable to a scripted session fixture.
  // The real supervisor owns/reaps the actual Node child and invokes onSpawn.
  const realIo = new URL("io.mjs", source).href;
  await fs.writeFile(join(modules, "io.mjs"), `
export * from ${JSON.stringify(realIo)};
import * as io from ${JSON.stringify(realIo)};
import { promises as fs } from "node:fs";
import { fileURLToPath } from "node:url";
import { sha256 } from "./core.mjs";
import { syntheticBinary } from "./fixture.mjs";
export async function snapshotBinary(_path, destination) {
  await io.publish(destination, syntheticBinary);
  return { sha256: sha256(syntheticBinary), bytes: Buffer.byteLength(syntheticBinary), sourceBinding: "synthetic-test-double" };
}
export async function runProcess(command, args, options) {
  await fs.appendFile(new URL("spawns.jsonl", import.meta.url), JSON.stringify({ hasOnSpawn: typeof options.onSpawn === "function" }) + "\\n");
  return io.runProcess(process.execPath, [fileURLToPath(new URL("fixture-session.mjs", import.meta.url))], options);
}
`);
  await fs.writeFile(join(modules, "fixture-session.mjs"), `
import net from "node:net";
import { promises as fs } from "node:fs";
import { join } from "node:path";
import { selectCase } from "./registry.mjs";
import { sha256, digestJson } from "./core.mjs";
import { options } from "./fixture.mjs";
const directory = process.env.PILOT_RUN_DIR;
const entry = selectCase(process.env.PILOT_CASE_ID);
const plan = JSON.parse(await fs.readFile(join(directory, "program.json")));
const local = { ...(entry.adapter === "batch-write" ? {} : { fixtureMismatch: options.mismatch === true }), [entry.programId]: {
  steps: Object.fromEntries(entry.stepIds.map((id, index) => [id, {
    status: options.mismatch && index === 0 ? 400 : 200,
    code: options.mismatch && index === 0 ? "INVALID_ARGUMENT" : "OK", body: { fixture: true },
  }])),
} };
const localBytes = JSON.stringify(local, null, 2) + "\\n";
await fs.writeFile(join(directory, "local.json"), localBytes);
const server = net.createServer();
await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
const endpoint = "http://127.0.0.1:" + server.address().port;
await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
const phases = [...(entry.sessionSetupPhases ?? []), ...entry.stepIds];
const session = {
  schema: "fireemu-production-diff-session-v1", caseId: entry.id,
  localSha256: options.badHash ? "0".repeat(64) : sha256(localBytes),
  programDigest: digestJson(plan), completed: !options.sessionFailure,
  failure: options.sessionFailure ? "fixture-session-failed" : null,
  requests: phases.map(phase => ({ phase, status: 200 })), requestCount: phases.length,
  productionRequests: options.productionCount ?? 0, authRequests: 0, endpoint,
  cleanup: options.cleanupUnknown ? { state: "unconfirmed", absent: [], requests: 0 } : {
    state: "confirmed", absent: entry.ownedDocuments,
    requests: entry.ownedDocuments.length + (entry.cleanupResetRequests ?? 0),
  },
};
await fs.writeFile(join(directory, "session-result.json"), JSON.stringify(session));
const receiptPath = join(directory, "launch-receipt.json");
if (options.removeReceipt) await fs.unlink(receiptPath);
if (options.oversizeReceipt) await fs.writeFile(receiptPath, "x".repeat(128 * 1024 + 1));
if (options.symlinkReceipt) {
  await fs.unlink(receiptPath).catch(error => { if (error.code !== "ENOENT") throw error; });
  await fs.symlink(join(directory, "local.json"), receiptPath);
}
process.exitCode = options.processExit ?? 0;
`);
  const { main } = await import(pathToFileURL(join(modules, "pilot.mjs")));
  const entry = CASES.find(c => c.adapter === adapter);
  assert.ok(entry, adapter);
  const runDir = join(root, "run");
  const invoke = (mode, out, extra) => main([mode, "--repo", repo, "--case", entry.id, "--out", out, ...extra]);
  const code = await invoke("replay", runDir, ["--binary", process.execPath, "--timeout", "10"]);
  const read = async name => JSON.parse(await fs.readFile(join(runDir, name)));
  const exists = async name => fs.lstat(join(runDir, name)).then(() => true, error => {
    if (error.code !== "ENOENT") throw error;
    return false;
  });
  return {
    code, entry, read, exists, runDir,
    async recompare() {
      const out = join(root, "recompare");
      const code = await invoke("compare", out, ["--run-dir", runDir]);
      return { code, result: JSON.parse(await fs.readFile(join(out, "result.json"))) };
    },
    async spawns() { return (await fs.readFile(join(modules, "spawns.jsonl"), "utf8")).trim().split("\n").map(JSON.parse); },
  };
}

for (const adapter of ["batch-write", "commit-transform"]) {
  test(`${adapter}: replay and stored comparison need no G0 launch receipt`, { timeout: 15000 }, async t => {
    const h = await harness(t, adapter);
    assert.equal(h.code, 0);
    assert.equal(await h.exists("launch-receipt.json"), false);
    const recording = await h.read("recording.json");
    const result = await h.read("result.json");
    assert.equal(Object.hasOwn(recording.execution, "launchReceiptSha256"), false);
    assert.equal(result.gatePassed, true);
    assert.equal(result.productionExecuted, false);
    assert.equal(result.parentPromotion, false);
    assert.equal(result.evidenceKind, h.entry.evidenceKind);
    assert.equal(result.execution.process.state, "stopped");
    assert.equal(result.execution.sourceUnchanged, true);
    assert.equal(result.execution.artifact.sourceBinding, "synthetic-test-double");
    const repeated = await h.recompare();
    assert.equal(repeated.code, 0);
    assert.equal(repeated.result.execution.freshLocalExecution, false);
    assert.deepEqual(await h.spawns(), [{ hasOnSpawn: false }]);
  });

  test(`${adapter}: complete semantic mismatch is saved, not masked by a missing G0 receipt`, { timeout: 15000 }, async t => {
    const h = await harness(t, adapter, { mismatch: true });
    assert.equal(h.code, 1);
    const result = await h.read("result.json");
    assert.equal(result.comparison.verdict, "MISMATCH");
    assert.equal(result.complete, true);
    assert.equal(result.gatePassed, false);
    assert.equal(await h.exists("failure.json"), false);
  });

  for (const [name, options] of [
    ["unknown cleanup", { cleanupUnknown: true }],
    ["failed process", { processExit: 3 }],
    ["source changed", { sourceChanged: true }],
    ["failed session", { sessionFailure: true }],
  ]) test(`${adapter}: ${name} stays INDETERMINATE and records the actual failure`, { timeout: 15000 }, async t => {
    const h = await harness(t, adapter, options);
    assert.equal(h.code, 2);
    const result = await h.read("result.json");
    assert.equal(result.comparison.verdict, "INDETERMINATE");
    assert.equal(result.complete, false);
    assert.equal(result.gatePassed, false);
    assert.equal(await h.exists("recording.json"), true);
    assert.equal(Object.hasOwn(result.execution, "launchReceiptSha256"), false);
    if (options.processExit) assert.equal(result.execution.process.exitCode, 3);
    if (options.sourceChanged) assert.equal(result.execution.failure, "source-changed");
  });

  for (const [name, options] of [
    ["wrong local hash", { badHash: true }],
    ["unexpected production count", { productionCount: 1 }],
  ]) test(`${adapter}: ${name} still fails the session binding`, { timeout: 15000 }, async t => {
    const h = await harness(t, adapter, options);
    assert.equal(h.code, 2);
    assert.equal((await h.read("failure.json")).code, "local-execution-incomplete");
    assert.equal(await h.exists("recording.json"), false);
  });
}

test("G0: the real onSpawn callback publishes a receipt whose exact bytes are hashed", { timeout: 15000 }, async t => {
  const h = await harness(t, "g0");
  assert.equal(h.code, 0);
  const bytes = await fs.readFile(join(h.runDir, "launch-receipt.json"));
  const receipt = JSON.parse(bytes);
  const recording = await h.read("recording.json");
  assert.equal(receipt.schema, "fireemu-g0-launch-v1");
  assert.ok(receipt.pid > 0);
  assert.equal(await fs.realpath(receipt.runDirectory.path), await fs.realpath(h.runDir));
  assert.equal(recording.execution.launchReceiptSha256, sha256(bytes));
  assert.equal((await h.read("result.json")).execution.launchReceiptSha256, sha256(bytes));
  assert.deepEqual(await h.spawns(), [{ hasOnSpawn: true }]);
});

for (const [name, options] of [
  ["missing", { removeReceipt: true }],
  ["symlink", { symlinkReceipt: true }],
  ["oversized", { oversizeReceipt: true }],
]) test(`G0: ${name} launch receipt still refuses publication`, { timeout: 15000 }, async t => {
  const h = await harness(t, "g0", options);
  assert.equal(h.code, 2);
  assert.equal((await h.read("failure.json")).gatePassed, false);
  assert.equal(await h.exists("recording.json"), false);
  assert.equal(await h.exists("result.json"), false);
});
