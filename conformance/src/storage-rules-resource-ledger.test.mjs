import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { buildCorpus } from "./storage-rules/corpus.mjs";
import { buildFullRequestManifest } from "./storage-rules/full-manifest.mjs";

const closure = JSON.parse(readFileSync(new URL("../../spec/compatibility/closure/STORAGE-RULES.json", import.meta.url)));
const options = { runId: "local-run", sourceCommit: "a".repeat(40), queryProjectNumber: "1".repeat(12), idpProjectNumber: "2".repeat(12), queryApiKeyId: "00000000-0000-4000-8000-000000000001", idpApiKeyId: "00000000-0000-4000-8000-000000000002" };
const binding = { bucket: "synthetic-rules-bucket", prefix: "STORAGE-RULES/local-run/", uidA: "storage-rules-local-run-user-a", uidB: "storage-rules-local-run-user-b" };
const manifest = buildFullRequestManifest(buildCorpus(binding), closure, options);
const load = async () => {
  const module = await import("./storage-rules/resource-ledger.mjs").catch((error) => { if (error.code === "ERR_MODULE_NOT_FOUND") return {}; throw error; });
  assert.equal(typeof module.createResourceLedger, "function");
  return module;
};
const ledger = async () => (await load()).createResourceLedger({ manifest });
const row = (id) => manifest.rows.find((r) => r.id === id) ?? assert.fail(id);
const present = (kind, generation = "1700000000000001", extra = {}) => ({ kind, verdict: "present", facts: { status: 200, generation, metageneration: "1", ...extra } });
const absent = (kind) => ({ kind, verdict: "absent", facts: { status: 404 } });

// A present-case object: baseline read, seed, cleanup readback, cleanup delete (declared) and its recovery twin.
const caseId = "method-read-get-metadata-present";
const ids = {
  baselineMetadata: `case/${caseId}/baseline/baseline-absence-metadata`, seed: `case/${caseId}/setup/seed`,
  cleanupMetadata: `case/${caseId}/after/after-metadata`, cleanupAbsence: `case/${caseId}/cleanup/cleanup-absence-metadata`, cleanupDelete: `case/${caseId}/cleanup/cleanup-delete`,
  recoveryMetadata: "recovery/object-1/metadata", recoveryDelete: "recovery/object-1/delete", recoveryAbsence: "recovery/object-1/absence-metadata",
};
const exists = (id) => manifest.rows.some((r) => r.id === id);
test("the fixture rows exist in the manifest", () => { for (const id of Object.values(ids)) assert.ok(exists(id), id); });

test("a seed may go only after the namespace is proven absent, and only once", async () => {
  const l = await ledger();
  assert.equal(l.evaluate(row(ids.seed)).decision, "stop");
  l.recordOutcome(row(ids.baselineMetadata), absent("gcs-metadata-read"));
  assert.equal(l.evaluate(row(ids.seed)).decision, "go");
  l.recordIntent(row(ids.seed));
  assert.equal(l.evaluate(row(ids.seed)).decision, "stop");
  assert.throws(() => l.recordIntent(row(ids.seed)), /mutation already attempted/);
});

test("a cleanup delete goes when the latest readback shows the object, skips when it shows nothing and stops on doubt", async () => {
  const l = await ledger();
  l.recordOutcome(row(ids.baselineMetadata), absent("gcs-metadata-read"));
  l.recordIntent(row(ids.seed));
  assert.equal(l.evaluate(row(ids.cleanupDelete)).decision, "stop");
  l.recordOutcome(row(ids.seed), { kind: "gcs-seed-upload", verdict: "accepted", facts: { status: 200, generation: "1700000000000001", metageneration: "1", size: "4" } });
  l.recordOutcome(row(ids.cleanupMetadata), present("gcs-metadata-read"));
  assert.equal(l.evaluate(row(ids.cleanupDelete)).decision, "go");
  l.recordOutcome(row(ids.cleanupMetadata), absent("gcs-metadata-read"));
  assert.equal(l.evaluate(row(ids.cleanupDelete)).decision, "skip");
  l.recordOutcome(row(ids.cleanupAbsence), absent("gcs-metadata-read"));
  assert.equal(l.evaluate(row(ids.cleanupDelete)).decision, "skip");
});

test("a delete is never sent twice for one object, even under a recovery ID, and an unanswered delete needs recovery", async () => {
  const l = await ledger();
  l.recordOutcome(row(ids.baselineMetadata), absent("gcs-metadata-read"));
  l.recordIntent(row(ids.seed));
  l.recordOutcome(row(ids.seed), { kind: "gcs-seed-upload", verdict: "accepted", facts: { status: 200, generation: "1700000000000001", metageneration: "1", size: "4" } });
  l.recordOutcome(row(ids.cleanupMetadata), present("gcs-metadata-read"));
  l.recordIntent(row(ids.cleanupDelete));
  l.recordOutcome(row(ids.cleanupDelete), { uncertain: true });
  assert.throws(() => l.recordIntent(row(ids.recoveryDelete)), /mutation already attempted/);
  l.recordOutcome(row(ids.recoveryMetadata), present("gcs-metadata-read", "1700000000000001"));
  const decision = l.evaluate(row(ids.recoveryDelete));
  assert.equal(decision.decision, "stop");
  assert.ok(decision.failed.some((entry) => entry.token === "delete-not-attempted"));
  l.recordOutcome(row(ids.recoveryMetadata), absent("gcs-metadata-read"));
  assert.equal(l.evaluate(row(ids.recoveryDelete)).decision, "skip");
});

test("a recovery row for an object the run never touched is skipped, and a touched one is read", async () => {
  const l = await ledger();
  for (const id of [ids.recoveryMetadata, ids.recoveryAbsence, ids.recoveryDelete]) assert.equal(l.evaluate(row(id)).decision, "skip", id);
  l.recordOutcome(row(ids.baselineMetadata), absent("gcs-metadata-read"));
  assert.equal(l.evaluate(row(ids.recoveryMetadata)).decision, "skip");
  l.recordIntent(row(ids.seed));
  assert.equal(l.evaluate(row(ids.recoveryMetadata)).decision, "go");
  assert.equal(l.evaluate(row(ids.recoveryAbsence)).decision, "go");
});

test("an uncertain create is not owned: it stays unknown and its delete stops", async () => {
  const l = await ledger();
  l.recordOutcome(row(ids.baselineMetadata), absent("gcs-metadata-read"));
  l.recordIntent(row(ids.seed));
  l.recordOutcome(row(ids.seed), { uncertain: true });
  assert.equal(l.object(row(ids.seed).request.objectName).owned, false);
  assert.equal(l.evaluate(row(ids.cleanupDelete)).decision, "stop");
  l.recordOutcome(row(ids.cleanupMetadata), present("gcs-metadata-read"));
  assert.equal(l.evaluate(row(ids.cleanupDelete)).decision, "stop");
  assert.equal(l.object(row(ids.seed).request.objectName).deletable, false);
});

test("an unexpected seed answer is treated like an uncertain one", async () => {
  const l = await ledger();
  l.recordOutcome(row(ids.baselineMetadata), absent("gcs-metadata-read"));
  l.recordIntent(row(ids.seed));
  l.recordOutcome(row(ids.seed), { kind: "gcs-seed-upload", verdict: "unexpected", facts: { status: 412, bodyBytes: 0, bodySha256: "0".repeat(64) } });
  assert.equal(l.object(row(ids.seed).request.objectName).owned, false);
});

test("a patch needs a present object with a write history", async () => {
  const l = await ledger();
  const patch = manifest.rows.find((r) => r.request.operation === "patch" && r.stage === "setup" && r.request.objectName.includes(caseId));
  assert.ok(patch);
  assert.equal(l.evaluate(patch).decision, "stop");
  l.recordOutcome(row(ids.baselineMetadata), absent("gcs-metadata-read"));
  l.recordIntent(row(ids.seed));
  assert.equal(l.evaluate(patch).decision, "stop");
  l.recordOutcome(row(ids.seed), { kind: "gcs-seed-upload", verdict: "accepted", facts: { status: 200, generation: "1700000000000001", metageneration: "1", size: "4" } });
  assert.equal(l.evaluate(patch).decision, "go");
});

test("a subject write by a user marks the object started and unknown until the next readback", async () => {
  const l = await ledger();
  const subjectWrite = manifest.rows.find((r) => r.stage === "subject" && r.service === "storage" && r.request.credential === "user-a" && r.request.operation === "upload");
  const name = subjectWrite.request.objectName;
  l.recordOutcome(manifest.rows.find((r) => r.request.objectName === name && r.stage === "baseline" && r.request.operation === "get-metadata"), absent("gcs-metadata-read"));
  l.recordIntent(subjectWrite);
  assert.equal(l.object(name).started, true);
  assert.equal(l.object(name).latest, "unknown");
  l.recordOutcome(subjectWrite, { kind: "subject-observed", verdict: "observed", facts: { status: 200, bodyBytes: 1, bodySha256: "0".repeat(64) } });
  assert.equal(l.object(name).latest, "unknown");
  const after = manifest.rows.find((r) => r.request.objectName === name && r.stage === "after" && r.request.operation === "get-metadata");
  l.recordOutcome(after, present("gcs-metadata-read", "1700000000000009"));
  assert.equal(l.object(name).latest, "present");
  assert.equal(l.object(name).generation, "1700000000000009");
});

test("an object outside the owned set is refused", async () => {
  const l = await ledger();
  const seed = row(ids.seed);
  const foreign = { ...seed, request: { ...seed.request, objectName: "STORAGE-RULES/other-run/x.bin" } };
  for (const call of [() => l.evaluate(foreign), () => l.recordIntent(foreign), () => l.recordOutcome(foreign, absent("gcs-metadata-read"))]) assert.throws(call, /unowned resource/);
  assert.throws(() => l.object("STORAGE-RULES/other-run/x.bin"), /unowned resource/);
});

test("rows that no ledger guard covers are reported as unresolved, not silently allowed", async () => {
  const l = await ledger();
  const decision = l.evaluate(row(ids.cleanupDelete));
  assert.ok(Array.isArray(decision.unresolved));
  assert.ok(decision.unresolved.includes("canonical-program-state-and-fresh-credential"));
  const release = row("release/v1/publish");
  assert.ok(l.evaluate(release).unresolved.length > 0);
});

test("a snapshot carries digests and counts, never values", async () => {
  const l = await ledger();
  l.recordOutcome(row(ids.baselineMetadata), absent("gcs-metadata-read"));
  l.recordIntent(row(ids.seed));
  l.recordOutcome(row(ids.seed), { kind: "gcs-seed-upload", verdict: "accepted", facts: { status: 200, generation: "1700000000000001", metageneration: "1", size: "4" } });
  const snapshot = l.snapshot();
  assert.equal(Object.isFrozen(snapshot), true);
  assert.deepEqual(Object.keys(snapshot).sort(), ["mutations", "objects", "started"]);
  assert.equal(snapshot.started, 1);
  assert.equal(snapshot.mutations, 1);
  assert.equal(JSON.stringify(snapshot).includes("1700000000000001"), false);
});

test("inputs are closed", async () => {
  const { createResourceLedger } = await load();
  for (const bad of [null, {}, { manifest: {} }, { manifest, extra: 1 }, { manifest: { ...manifest, sendAuthorized: true } }]) assert.throws(() => createResourceLedger(bad), /invalid resource ledger options/);
  const l = createResourceLedger({ manifest });
  for (const bad of [null, {}, { id: "x" }]) assert.throws(() => l.evaluate(bad), /invalid resource ledger row/);
  assert.throws(() => l.recordOutcome(row(ids.seed), { kind: "x", verdict: "accepted" }), /invalid resource ledger outcome/);
  assert.throws(() => l.recordOutcome(row(ids.seed), null), /invalid resource ledger outcome/);
});
