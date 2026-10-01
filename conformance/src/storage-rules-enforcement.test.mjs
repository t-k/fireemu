import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { buildCorpus } from "./storage-rules/corpus.mjs";
import { ENFORCEMENT, enforcerOf } from "./storage-rules/enforcement.mjs";
import { buildFullRequestManifest } from "./storage-rules/full-manifest.mjs";
import { REQUIRES_REGISTRY } from "./storage-rules/predicates.mjs";
import { createResourceLedger } from "./storage-rules/resource-ledger.mjs";
import { createRunLedger } from "./storage-rules/run-ledger.mjs";

const closure = JSON.parse(readFileSync(new URL("../../spec/compatibility/closure/STORAGE-RULES.json", import.meta.url)));
const options = { runId: "local-run", sourceCommit: "a".repeat(40), queryProjectNumber: "1".repeat(12), idpProjectNumber: "2".repeat(12), queryApiKeyId: "00000000-0000-4000-8000-000000000001", idpApiKeyId: "00000000-0000-4000-8000-000000000002" };
const binding = { bucket: "synthetic-rules-bucket", prefix: "STORAGE-RULES/local-run/", uidA: "storage-rules-local-run-user-a", uidB: "storage-rules-local-run-user-b" };
const manifest = buildFullRequestManifest(buildCorpus(binding), closure, options);

test("every token of the registry has exactly one enforcer", () => {
  const all = Object.values(ENFORCEMENT).flat();
  assert.equal(new Set(all).size, all.length);
  assert.deepEqual([...all].sort(), Object.keys(REQUIRES_REGISTRY).sort());
  for (const token of Object.keys(REQUIRES_REGISTRY)) assert.ok(enforcerOf(token), token);
});

test("the ledgers answer exactly the tokens the table gives them", () => {
  const objects = createResourceLedger({ manifest });
  const run = createRunLedger({ manifest, objects });
  assert.deepEqual([...objects.tokens()].sort(), [...ENFORCEMENT["object-ledger"], ...ENFORCEMENT.shared].sort());
  assert.deepEqual([...run.ownedTokens()].sort(), [...ENFORCEMENT["run-ledger"], ...ENFORCEMENT.shared, ...ENFORCEMENT.both].sort());
  assert.deepEqual([...run.checkTokens()].sort(), [...ENFORCEMENT["post-check"], ...ENFORCEMENT.both].sort());
});

test("the category of each token fits its enforcer", () => {
  const expected = { "object-ledger": ["guard"], shared: ["guard"], both: ["check"], "run-ledger": ["guard", "proof"], "post-check": ["check"], admission: ["input"], delegate: ["guard", "proof"], refs: ["guard"], structure: ["budget"], policy: ["policy"] };
  for (const [enforcer, tokens] of Object.entries(ENFORCEMENT)) {
    for (const token of tokens) assert.ok(expected[enforcer].includes(REQUIRES_REGISTRY[token].category), `${token}: ${REQUIRES_REGISTRY[token].category} under ${enforcer}`);
  }
});

test("the table is frozen", () => {
  assert.equal(Object.isFrozen(ENFORCEMENT), true);
  for (const tokens of Object.values(ENFORCEMENT)) assert.equal(Object.isFrozen(tokens), true);
});
