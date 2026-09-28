import assert from "node:assert/strict";
import { test } from "node:test";
import { buildAuthCorpus } from "./storage-object/auth-corpus.mjs";

const options = {
  projectId: "example-project",
  bucket: "example.appspot.com",
  runId: "recordone",
};

test("both pending recipes declare sequential per-program accounts and twelve bounded controls", () => {
  const corpus = buildAuthCorpus(options);
  assert.equal(corpus.status, "DECLARED_NO_SEND");
  assert.equal(corpus.sendAuthorized, false);
  assert.deepEqual(
    corpus.recipes.map((recipe) => recipe.id),
    ["storage-object/errors/authorization", "storage-object/auth/firebase-id-token"],
  );
  assert.deepEqual(
    corpus.recipes.map((recipe) => recipe.probes.length),
    [8, 4],
  );
  assert.equal(corpus.subjectEntries, 156);
  assert.equal(corpus.cleanupEntries, 56);
  assert.equal(corpus.requestsPerRecording, 212);
  assert.notEqual(corpus.recipes[0].accounts.valid.ref, corpus.recipes[1].accounts.valid.ref);
  for (const recipe of corpus.recipes) {
    assert.equal(recipe.accountSetup.length, 6);
    assert.equal(recipe.accountCleanup.length, 4);
    assert.equal(recipe.accounts.valid.email, "storage-object@example.com");
    assert.notEqual(recipe.accounts.competitor.email, recipe.accounts.valid.email);
    assert.equal(recipe.accountLifecycle, "create-and-delete-per-program");
  }
});

test("all Storage object requests remain under one run prefix with owner-only conditional cleanup", () => {
  const corpus = buildAuthCorpus(options);
  const probes = corpus.recipes.flatMap((recipe) => recipe.probes);
  assert.equal(new Set(probes.map((probe) => probe.objectName)).size, 12);
  for (const probe of probes) {
    assert.match(probe.objectName, /^storage-object\/recordone\/auth\//);
    assert.equal(probe.initial.length, 3);
    assert.equal(probe.before.length, 3);
    assert.equal(probe.after.length, 3);
    assert.equal(probe.cleanup.length, 4);
    assert.equal(probe.seed === null, probe.action === "write");
    if (probe.seed) assert.equal(probe.seed.query.ifGenerationMatch, "0");
    assert.equal(probe.subject.service, "firebase-storage");
    assert.equal(probe.subject.credentialRef.kind, probe.credential);
    assert.equal(probe.cleanup[0].query.ifGenerationMatch.kind, "owned-generation");
    for (const request of [...probe.initial, ...probe.before, ...probe.after, ...probe.cleanup]) {
      assert.equal(request.objectName, probe.objectName);
      assert.equal(request.bucket, options.bucket);
    }
  }
});

test("token and API-key values are typed references rather than serialized secrets", () => {
  const corpus = buildAuthCorpus(options);
  const encoded = JSON.stringify(corpus);
  assert.ok(!encoded.includes("Authorization"));
  for (const recipe of corpus.recipes) {
    for (const step of recipe.accountSetup.filter((item) => item.id.endsWith("signup"))) {
      assert.deepEqual(step.query.key, { kind: "private-api-key" });
      assert.equal(step.body.password.kind, "private-password");
    }
    for (const probe of recipe.probes) {
      if (probe.credential === "valid" || probe.credential === "competitor")
        assert.equal(probe.subject.credentialRef.accountRef, recipe.accounts[probe.credential].ref);
    }
  }
});

test("an invalid destination cannot create auth requests", () => {
  assert.throws(() => buildAuthCorpus({ ...options, runId: "../outside" }));
  assert.throws(() => buildAuthCorpus({ ...options, bucket: "other/bucket" }));
});

test("owner seed readbacks preserve the first Firebase metadata observation before Auth subjects", () => {
  const corpus = buildAuthCorpus(options);
  const reads = corpus.recipes
    .flatMap((recipe) => recipe.probes)
    .filter((probe) => probe.action === "read");
  assert.equal(reads.length, 6);
  for (const probe of reads) {
    assert.deepEqual(
      probe.seedReadbacks.map((step) => step.service),
      ["gcs-json", "firebase-storage", "gcs-json"],
    );
    for (const step of probe.seedReadbacks) {
      assert.equal(step.method, "GET");
      assert.equal(step.objectName, probe.objectName);
      assert.equal(step.credential, "owner");
      assert.deepEqual(step.query, {});
    }
  }
  assert.equal(corpus.requestsPerRecording, 212);
});
