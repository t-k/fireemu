import assert from "node:assert/strict";
import { test } from "node:test";

import {
  BRACKET_OWNED_NAMES,
  BRACKET_REST_IDS,
  BRACKET_STREAM_IDS,
} from "./fs-data-write-sandbox.mjs";
import {
  isExactBracketProductionScope,
  productionScopeFromEnvironment,
} from "./firestore-probe/sandbox-session.mjs";
import {
  bracketRequestBound,
  ownedMutationNamesForPrograms,
  prepareSandboxCorpus,
  productionAdmissionPlan,
  productionRestEnvironment,
  selectBracketRecipes,
} from "./fs-data-write-sandbox-run.mjs";

const common = {
  input: "/private/corpus.json",
  output: "/private/rest.json",
  meta: "/private/meta.json",
  token: "not-used",
  journal: "/private/journal.json",
  runId: "a".repeat(32),
  corpusDigest: "b".repeat(64),
  sourceGitSha: "c".repeat(40),
};

test("the bracket corpus records exactly the fixed boundary pairs, twice with the same bytes", async () => {
  const { corpus } = await prepareSandboxCorpus();
  const selection = selectBracketRecipes(corpus);
  const { recordingCorpus } = selection;
  assert.deepEqual(
    recordingCorpus.restPrograms.map((program) => program.id).toSorted(),
    [...BRACKET_REST_IDS].toSorted(),
  );
  assert.deepEqual(
    recordingCorpus.streamRecipes.map((recipe) => recipe.id),
    [...BRACKET_STREAM_IDS],
  );
  // Programs are the current corpus recipes byte for byte, so the supplement digests bind.
  for (const program of recordingCorpus.restPrograms) {
    assert.deepEqual(
      program,
      corpus.restPrograms.find((candidate) => candidate.id === program.id),
    );
  }
  assert.equal(recordingCorpus.restRequestCount, 38);
  assert.equal(recordingCorpus.sourceCorpusSha256, selection.sourceCorpusDigest);
  // No pass number or run marker appears in any name the corpus sends.
  assert.ok(!JSON.stringify(recordingCorpus).includes("DELETE_RUN_ID"));
  assert.throws(
    () =>
      selectBracketRecipes({
        ...corpus,
        restPrograms: corpus.restPrograms.filter((program) => program.id !== BRACKET_REST_IDS[0]),
        restRequestCount:
          corpus.restRequestCount -
          corpus.restPrograms.find((program) => program.id === BRACKET_REST_IDS[0]).steps.length,
      }),
    /bracket recipe/,
  );
});

test("bracket cleanup owns exactly the documents its recipes can create", async () => {
  const { corpus } = await prepareSandboxCorpus();
  const { recordingCorpus } = selectBracketRecipes(corpus);
  assert.deepEqual(ownedMutationNamesForPrograms(recordingCorpus.restPrograms), [
    ...BRACKET_OWNED_NAMES,
  ]);
  assert.equal(BRACKET_OWNED_NAMES.length, 14);
  // Two preflight reads, one delete per owned name and one typed-missing read per attempt.
  assert.deepEqual(bracketRequestBound(recordingCorpus), {
    declaredHttp: 38,
    preflightHttp: 2,
    cleanupHttp: 15,
    maxHttpRequests: 55,
    maxStreamFrames: 2,
  });
  assert.throws(
    () =>
      bracketRequestBound({
        ...recordingCorpus,
        restPrograms: recordingCorpus.restPrograms.slice(1),
        restRequestCount:
          recordingCorpus.restRequestCount - recordingCorpus.restPrograms[0].steps.length,
      }),
    /bracket recipe/,
  );
});

test("the bracket admission plan pins recipes, owned names and bounds", async () => {
  const { corpus } = await prepareSandboxCorpus();
  const selection = selectBracketRecipes(corpus);
  const plan = productionAdmissionPlan("bracket", selection);
  assert.equal(plan.mode, "bracket");
  assert.equal(plan.project, "fireemu-oracle-sbx");
  assert.deepEqual(plan.managedNames, [...BRACKET_OWNED_NAMES]);
  assert.deepEqual(plan.streamIds, [...BRACKET_STREAM_IDS]);
  assert.equal(plan.bounds.maxHttpRequests, 55);
  assert.equal(plan.attempts, 2);
  assert.equal(plan.attemptEstimateUsd, 0.5);
});

test("the child admits the bracket scope only as the parent sends it", async () => {
  const { corpus } = await prepareSandboxCorpus();
  const bound = bracketRequestBound(selectBracketRecipes(corpus).recordingCorpus);
  const env = productionRestEnvironment({
    ...common,
    managedNames: [...BRACKET_OWNED_NAMES],
    bracket: { maxHttpRequests: bound.maxHttpRequests },
  });
  assert.equal(env.FIRESTORE_PROBE_BRACKET, "1");
  assert.equal(env.FIRESTORE_PROBE_BRACKET_LOCK_HELD, "1");
  assert.equal(env.FIRESTORE_PROBE_MAX_REQUESTS, "55");
  assert.equal(env.FIRESTORE_PROBE_MANAGED_CLEAR_JOURNAL, common.journal);
  assert.equal(env.FIRESTORE_PROBE_PARTIAL, undefined);
  assert.equal(env.FIRESTORE_PROBE_DELTA_V3, undefined);
  assert.deepEqual(productionScopeFromEnvironment(env), {
    delta: false,
    partial: false,
    bracket: true,
  });
  for (const change of [
    { FIRESTORE_PROBE_HOST: "attacker.example" },
    { FIRESTORE_PROBE_SCHEME: "http" },
    { FIRESTORE_PROBE_PROJECT: "fireemu-35fe6" },
    { FIRESTORE_PROBE_MAX_REQUESTS: "56" },
    { FIRESTORE_PROBE_BRACKET_LOCK_HELD: undefined },
    { FIRESTORE_PROBE_MANAGED_CLEAR_JOURNAL: undefined },
    { FIRESTORE_PROBE_PARTIAL: "1" },
    { FIRESTORE_PROBE_DELTA_V3: "1" },
    {
      FIRESTORE_PROBE_MANAGED_CLEAR_NAMES: JSON.stringify(BRACKET_OWNED_NAMES.slice(1)),
    },
  ]) {
    assert.equal(productionScopeFromEnvironment({ ...env, ...change }).bracket, false);
  }
  for (const [bracket, message] of [
    [{ maxHttpRequests: 0 }, /bracket HTTP cap/],
    [{ maxHttpRequests: 56 }, /bracket HTTP cap/],
  ]) {
    assert.throws(
      () =>
        productionRestEnvironment({ ...common, managedNames: [...BRACKET_OWNED_NAMES], bracket }),
      message,
    );
  }
  assert.throws(
    () =>
      productionRestEnvironment({
        ...common,
        managedNames: BRACKET_OWNED_NAMES.slice(1),
        bracket: { maxHttpRequests: 55 },
      }),
    /managed-clear names/,
  );
  assert.throws(
    () =>
      productionRestEnvironment({
        ...common,
        managedNames: [...BRACKET_OWNED_NAMES],
        bracket: { maxHttpRequests: 55 },
        partial: { maxHttpRequests: 55 },
      }),
    /one recording mode/,
  );
});

test("the exact bracket scope refuses every other target", () => {
  const scope = {
    mode: true,
    lockHeld: true,
    otherMode: false,
    host: "firestore.googleapis.com",
    scheme: "https",
    project: "fireemu-oracle-sbx",
    maxRequests: 55,
    managedClearJournal: "/private/journal.json",
    names: BRACKET_OWNED_NAMES.toReversed(),
  };
  assert.equal(isExactBracketProductionScope(scope), true);
  for (const change of [
    { mode: false },
    { lockHeld: false },
    { otherMode: true },
    { host: "firestore.googleapis.com.attacker.example" },
    { scheme: "http" },
    { project: "fireemu-oracle-idp" },
    { maxRequests: 0 },
    { maxRequests: 56 },
    { maxRequests: Number.NaN },
    { managedClearJournal: "" },
    { names: [...BRACKET_OWNED_NAMES, BRACKET_OWNED_NAMES[0]] },
    { names: BRACKET_OWNED_NAMES.map((name) => name.replace("rawQuery", "rawQueryX")) },
    { names: null },
  ]) {
    assert.equal(isExactBracketProductionScope({ ...scope, ...change }), false, change);
  }
});
