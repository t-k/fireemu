import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";
import { buildCorpus } from "./storage-rules/corpus.mjs";
import { buildFullRequestManifest } from "./storage-rules/full-manifest.mjs";

const closure = JSON.parse(readFileSync(new URL("../../spec/compatibility/closure/STORAGE-RULES.json", import.meta.url)));
const options = { runId: "local-run", sourceCommit: "a".repeat(40), queryProjectNumber: "1".repeat(12), idpProjectNumber: "2".repeat(12), queryApiKeyId: "00000000-0000-4000-8000-000000000001", idpApiKeyId: "00000000-0000-4000-8000-000000000002" };
const binding = { bucket: "synthetic-rules-bucket", prefix: "STORAGE-RULES/local-run/", uidA: "storage-rules-local-run-user-a", uidB: "storage-rules-local-run-user-b" };
const manifest = buildFullRequestManifest(buildCorpus(binding), closure, options);
const load = async () => {
  const module = await import("./storage-rules/predicates.mjs").catch((error) => { if (error.code === "ERR_MODULE_NOT_FOUND") return {}; throw error; });
  assert.equal(typeof module.assertManifestPredicates, "function");
  return module;
};
const SKIP_TOKENS = ["object-not-absent-per-latest-readback", "document-not-absent-per-latest-readback", "session-active-per-latest-query"];
const STARTED_TOKEN = "resource-started-and-provenance-matches";

test("the registry keys are exactly the tokens the manifest uses", async () => {
  const { REQUIRES_REGISTRY } = await load();
  const used = new Set(manifest.rows.flatMap((r) => r.requires));
  assert.deepEqual([...used].sort(), Object.keys(REQUIRES_REGISTRY).sort());
  assert.equal(Object.isFrozen(REQUIRES_REGISTRY), true);
});

test("every entry has a closed category, a closed fact list and a stop-or-skip outcome", async () => {
  const { REQUIRES_REGISTRY, PREDICATE_CATEGORIES, PREDICATE_FACTS } = await load();
  assert.deepEqual([...PREDICATE_CATEGORIES].sort(), ["budget", "check", "guard", "input", "policy", "proof"]);
  const usedFacts = new Set();
  for (const [token, entry] of Object.entries(REQUIRES_REGISTRY)) {
    assert.deepEqual(Object.keys(entry).sort(), ["category", "needs", "onFalse"], token);
    assert.ok(PREDICATE_CATEGORIES.includes(entry.category), token);
    assert.ok(["stop", "skip"].includes(entry.onFalse), token);
    assert.ok(Array.isArray(entry.needs) && Object.isFrozen(entry) && Object.isFrozen(entry.needs), token);
    for (const fact of entry.needs) { assert.ok(PREDICATE_FACTS.includes(fact), `${token}: ${fact}`); usedFacts.add(fact); }
  }
  assert.deepEqual([...usedFacts].sort(), [...PREDICATE_FACTS].sort());
  assert.equal(new Set(PREDICATE_FACTS).size, PREDICATE_FACTS.length);
});

// The Firebase v0 capabilities (a session, a download token) are record-only: what a session row needs from the session is a reason to skip it, never to stop the run.
const SESSION_SKIP_TOKENS = ["cancel-not-attempted", "confirmed-active-session", "durable-verified-start-url-and-target"];
test("only the three explicit conditional-cleanup guards, the resource-started guard and the three record-only session guards may skip a row", async () => {
  const { REQUIRES_REGISTRY } = await load();
  assert.deepEqual(Object.entries(REQUIRES_REGISTRY).filter(([, e]) => e.onFalse === "skip").map(([t]) => t).sort(), [...SKIP_TOKENS, STARTED_TOKEN, ...SESSION_SKIP_TOKENS].sort());
  for (const token of [...SKIP_TOKENS, STARTED_TOKEN, "cancel-not-attempted", "confirmed-active-session"]) assert.equal(REQUIRES_REGISTRY[token].category, "guard");
  assert.equal(REQUIRES_REGISTRY["durable-verified-start-url-and-target"].category, "proof");
});

test("required-state and when values are closed sets equal to the manifest's", async () => {
  const { REQUIRED_STATES, WHEN_CONDITIONS } = await load();
  assert.deepEqual([...new Set(manifest.rows.filter((r) => r.requiredState).map((r) => r.requiredState))].sort(), [...REQUIRED_STATES].sort());
  assert.deepEqual([...new Set(manifest.rows.filter((r) => r.when).map((r) => r.when))].sort(), [...WHEN_CONDITIONS].sort());
  assert.ok(Object.isFrozen(REQUIRED_STATES) && Object.isFrozen(WHEN_CONDITIONS));
});

test("the conditional cleanup guards sit on exactly the rows whose write may already be moot", () => {
  const with_ = (token) => manifest.rows.filter((r) => r.requires.includes(token));
  const objectDeletes = manifest.rows.filter((r) => r.request.service !== "firestore" && r.service === "storage" && r.request.operation === "delete" && r.request.dialect === "gcs" && r.request.credential === "admin" && r.stage !== "subject");
  assert.equal(objectDeletes.length, 338 + 6 + 344);
  assert.deepEqual(with_(SKIP_TOKENS[0]).map((r) => r.id), objectDeletes.map((r) => r.id));
  const documentDeletes = manifest.rows.filter((r) => r.service === "firestore" && r.request.method === "DELETE");
  assert.equal(documentDeletes.length, 9 + 2 + 9);
  assert.deepEqual(with_(SKIP_TOKENS[1]).map((r) => r.id), documentDeletes.filter((r) => r.stage === "cleanup" || r.family === "recovery-document").map((r) => r.id));
  assert.equal(with_(SKIP_TOKENS[1]).length, 18);
  const cancels = manifest.rows.filter((r) => r.request.sessionUrlReference && r.request.headers["x-goog-upload-command"] === "cancel");
  assert.equal(cancels.length, 16);
  assert.deepEqual(with_(SKIP_TOKENS[2]).map((r) => r.id), cancels.map((r) => r.id));
});

test("a manifest with an unknown token, state or condition is refused", async () => {
  const { assertManifestPredicates } = await load();
  assertManifestPredicates(manifest);
  const first = manifest.rows[0];
  const withRow = (row) => ({ ...manifest, rows: [row, ...manifest.rows.slice(1)] });
  for (const changed of [
    { ...first, requires: [...first.requires, "made-up-token"] },
    { ...first, requires: [first.requires[0], first.requires[0]] },
    { ...first, requires: [7] }, { ...first, requires: [{ toString: () => "delete-not-attempted" }] }, { ...first, requires: undefined }, { ...first, requires: null }, { ...first, requires: { length: 0 } },
    { ...first, requires: "canonical-program-state-and-fresh-credential" },
    { ...first, requiredState: "made-up-state" },
    { ...first, when: "made-up-condition" },
    { ...first, when: "" }, { ...first, when: 0 }, { ...first, when: false }, { ...first, requiredState: "" }, { ...first, requiredState: {} }, { ...first, requiredState: false },
  ]) assert.throws(() => assertManifestPredicates(withRow(changed)), /invalid manifest predicate/);
  assert.throws(() => assertManifestPredicates({ rows: null }), /invalid manifest predicate/);
  assertManifestPredicates(withRow({ ...first, when: null, requiredState: null }));
});

test("the reviewed registry is pinned, so any change to a token, category, fact or outcome needs a deliberate update", async () => {
  const { REQUIRES_REGISTRY } = await load();
  assert.equal(createHash("sha256").update(JSON.stringify(REQUIRES_REGISTRY)).digest("hex"), "5b459003f4d0f8883ac747043dd532bc6f3f5646dec88482e3537fbfc4a541e3");
});
