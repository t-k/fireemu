import assert from "node:assert/strict";
import { test } from "node:test";
import { buildCorpus } from "./storage-object/corpus.mjs";
import {
  buildSymbolicStorageAuthPlan,
  compareStorageRulesBaseline,
  validateSymbolicStorageAuthPlan,
} from "./storage-object/auth-plan.mjs";

const options = { projectId: "example-project", bucket: "example.appspot.com", runId: "authrun01" };
const make = () => buildSymbolicStorageAuthPlan(options);
const copy = (value) => structuredClone(value);

test("symbolic plan keeps both auth recipes pending and grants no authority", () => {
  const corpus = buildCorpus({ bucket: options.bucket, prefix: "owned-run/" });
  const plan = make();
  assert.deepEqual(plan.recipeIds, [
    "storage-object/errors/authorization",
    "storage-object/auth/firebase-id-token",
  ]);
  assert.deepEqual(corpus.remainingRecipeIds, plan.recipeIds);
  assert.equal(corpus.recipes.length, 24);
  assert.equal(plan.probes.length, 12);
  assert.equal(new Set(plan.probes.map((probe) => probe.objectName)).size, 12);
  assert.deepEqual(plan.programs.map((program) => program.recipeId), plan.recipeIds);
  assert.equal(plan.programs.every((program) => program.accountLifecycle === "create-and-delete-per-program"), true);
  assert.notEqual(plan.programs[0].validAccountRef, plan.programs[1].validAccountRef);
  assert.equal(plan.state, "PLANNED_NOT_DECLARED");
  assert.equal(plan.rules.verified, false);
  assert.equal(plan.sendAuthorized, false);
  assert.ok(plan.rules.requiredProofs.includes("rules-body-sha256-before-after-identical"));
  assert.equal(
    plan.rules.expectedSourceSha256,
    "dff1d21237c12a1f3d1e5ef1134ba996d0b79c99530cb88bb016a5241388dc9b",
  );
  assert.equal(plan.rules.approvedBaselineRef, "private-ref:approved-storage-rules-baseline");
  assert.deepEqual(plan.rules.expectedPolicy, {
    prefix: "storage-object/authrun01/",
    allowEmail: "storage-object@example.com",
    otherEmails: "deny",
    anonymous: "deny",
  });
  assert.ok(
    plan.rules.requiredProofs.includes(
      "approved-baseline-project-bucket-release-ruleset-body-binding",
    ),
  );
  assert.ok(plan.rules.requiredProofs.includes("observed-body-sha256-equals-approved-baseline"));
  assert.deepEqual(
    new Set(plan.probes.map((probe) => probe.id)),
    new Set([
      ...["anonymous", "malformed", "competitor", "valid"].flatMap((credential) =>
        ["read", "write"].map((action) => `authorization-errors/${credential}/${action}`),
      ),
      ...["valid", "competitor"].flatMap((credential) =>
        ["read", "write"].map((action) => `firebase-id-token/${credential}/${action}`),
      ),
    ]),
  );
  assert.deepEqual(validateSymbolicStorageAuthPlan(plan), {
    status: "SYMBOLIC_PLAN_CONSISTENT",
    recipesDeclared: false,
    projectBindingVerified: false,
    credentialsVerified: false,
    rulesBaselineVerified: false,
    ownershipVerified: false,
    compatibilityEstablished: false,
    sendAuthorized: false,
  });
});

test("credential references remain distinct and contain no raw secrets", () => {
  const plan = make();
  assert.deepEqual(
    Object.values(plan.credentials).map((credential) => credential.kind),
    ["anonymous", "owner-adc", "firebase-id-token", "firebase-id-token", "malformed-firebase-token"],
  );
  assert.equal(plan.credentials.owner.wireScheme, "Bearer");
  assert.equal(plan.credentials.valid.wireScheme, "Firebase");
  assert.equal(plan.credentials.competitor.wireScheme, "Firebase");
  assert.equal(plan.credentials.valid.expectedEmail, "storage-object@example.com");
  assert.notEqual(plan.credentials.competitor.expectedEmail, plan.credentials.valid.expectedEmail);
  assert.equal(plan.credentials.malformed.wireScheme, "Firebase");
  assert.equal(plan.credentials.anonymous.wireScheme, null);
  assert.ok(plan.credentials.valid.requiredProofs.includes("signup-uid-equals-lookup-uid"));
  assert.ok(plan.credentials.valid.requiredProofs.includes("token-not-expired-at-send"));
  assert.ok(plan.credentials.valid.requiredProofs.includes("wire-header-provenance"));
  assert.ok(
    plan.credentials.malformed.requiredProofs.includes("request-bound-malformed-wire-value"),
  );
  assert.ok(
    plan.credentials.malformed.requiredProofs.includes("wire-value-distinct-from-valid-token"),
  );
  assert.ok(plan.credentials.malformed.requiredProofs.includes("private-mode-0600"));
  assert.equal(plan.credentials.valid.proofsVerified, false);
  assert.ok(
    plan.interpretationRules.includes("valid-success-and-competitor-denial-required-for-email-gate"),
  );
  assert.ok(!JSON.stringify(plan).includes("Authorization"));
});

test("each read has owner seed and each write has complete GCS before and after reads", () => {
  for (const probe of make().probes) {
    assert.match(probe.objectName, /^storage-object\/authrun01\/auth\/(authorization-errors|firebase-id-token)\//);
    assert.equal(probe.requestDialect, "firebase");
    assert.notEqual(probe.credentialRef, "owner");
    assert.equal(probe.setupCredentialRef, "owner");
    assert.equal(probe.setupState, probe.action === "read" ? "owned-present" : "owned-absent");
    assert.deepEqual(probe.gcsInitialAbsence, ["metadata", "media", "prefix-all-pages"]);
    assert.equal(
      probe.setupCreatePrecondition,
      probe.action === "read" ? "ifGenerationMatch=0" : "not-applicable-no-owner-seed",
    );
    assert.equal(probe.setupOwnershipJournal, "durable-before-first-mutation");
    assert.deepEqual(probe.gcsBefore, ["metadata", "media", "prefix-all-pages"]);
    assert.deepEqual(probe.gcsAfter, ["metadata", "media", "prefix-all-pages"]);
    assert.equal(probe.outcome, "UNOBSERVED");
  }
});

test("credential, proof, rules and cleanup tampering are rejected", () => {
  const changes = [
    (plan) => {
      plan.credentials.valid.kind = "owner-adc";
    },
    (plan) => {
      plan.credentials.valid.wireScheme = "Bearer";
    },
    (plan) => {
      plan.credentials.valid.secretRef = "eyJhbGciOiJub25lIn0.payload.signature";
    },
    (plan) => {
      plan.credentials.valid.requiredProofs.pop();
    },
    (plan) => {
      plan.credentials.valid.proofsVerified = true;
    },
    (plan) => {
      plan.credentials.competitor.expectedEmail = plan.credentials.valid.expectedEmail;
    },
    (plan) => {
      plan.credentials.malformed.secretRef = plan.credentials.valid.secretRef;
    },
    (plan) => {
      plan.credentials.malformed.requiredProofs.pop();
    },
    (plan) => {
      plan.probes[0].credentialRef = "owner";
    },
    (plan) => {
      plan.probes[0].objectName = plan.probes[1].objectName;
    },
    (plan) => {
      plan.probes[0].gcsAfter.pop();
    },
    (plan) => {
      plan.probes[0].gcsInitialAbsence.pop();
    },
    (plan) => {
      plan.probes[0].setupCreatePrecondition = "none";
    },
    (plan) => {
      plan.rules.requiredProofs.pop();
    },
    (plan) => {
      plan.rules.expectedSourceSha256 = "0".repeat(64);
    },
    (plan) => {
      plan.rules.expectedPolicy.allowEmail = "someone-else@example.com";
    },
    (plan) => {
      plan.interpretationRules.pop();
    },
    (plan) => {
      plan.cleanup.verified = true;
    },
    (plan) => {
      plan.sendAuthorized = true;
    },
  ];
  for (const change of changes) {
    const plan = copy(make());
    change(plan);
    assert.throws(() => validateSymbolicStorageAuthPlan(plan));
  }
});

test("stable but wrong Rules snapshots cannot match the approved baseline", () => {
  const plan = make();
  const baseline = {
    approvalRef: plan.rules.approvedBaselineRef,
    projectId: options.projectId,
    bucket: plan.bucket,
    releaseName: "projects/example-project/releases/firebase.storage/example.appspot.com",
    rulesetName: "projects/example-project/rulesets/approved",
    bodySha256: plan.rules.expectedSourceSha256,
    sourceSha256: plan.rules.expectedSourceSha256,
  };
  const before = {
    ...baseline,
    bodySha256: "b".repeat(64),
    bucketlessReleaseAbsent: true,
  };
  assert.deepEqual(compareStorageRulesBaseline(plan, baseline, before, { ...before }), {
    status: "MISMATCH",
    rulesBaselineVerified: false,
    sendAuthorized: false,
  });
  const matching = { ...baseline, bucketlessReleaseAbsent: true };
  assert.deepEqual(compareStorageRulesBaseline(plan, baseline, matching, { ...matching }), {
    status: "SNAPSHOT_MATCHES_SUPPLIED_BASELINE",
    rulesBaselineVerified: false,
    sendAuthorized: false,
  });
  assert.equal(
    compareStorageRulesBaseline(plan, baseline, matching, { ...matching, rulesetName: "changed" })
      .status,
    "MISMATCH",
  );
  assert.equal(
    compareStorageRulesBaseline(
      plan,
      { ...baseline, sourceSha256: "c".repeat(64) },
      matching,
      matching,
    ).status,
    "MISMATCH",
  );
  assert.equal(
    compareStorageRulesBaseline(
      plan,
      { ...baseline, bodySha256: "a".repeat(64) },
      { ...matching, bodySha256: "a".repeat(64) },
      { ...matching, bodySha256: "a".repeat(64) },
    ).status,
    "MISMATCH",
  );
  assert.equal(
    compareStorageRulesBaseline(
      plan,
      {
        ...baseline,
        releaseName: "projects/example-project/releases/firebase.storage/other-bucket",
      },
      matching,
      matching,
    ).status,
    "MISMATCH",
  );
  assert.equal(
    compareStorageRulesBaseline(
      plan,
      baseline,
      { ...matching, bucketlessReleaseAbsent: false },
      matching,
    ).status,
    "MISMATCH",
  );
});

test("hidden and accessor properties reject without evaluating the accessor", () => {
  const hidden = copy(make());
  Object.defineProperty(hidden.credentials.valid, "token", { value: "secret", enumerable: false });
  assert.throws(() => validateSymbolicStorageAuthPlan(hidden));
  const symbol = copy(make());
  symbol.credentials.valid[Symbol("secret")] = "secret";
  assert.throws(() => validateSymbolicStorageAuthPlan(symbol));
  const getter = copy(make());
  let accessed = 0;
  Object.defineProperty(getter.credentials.valid, "secretRef", {
    enumerable: true,
    get() {
      accessed++;
      return "secret";
    },
  });
  assert.throws(() => validateSymbolicStorageAuthPlan(getter));
  assert.equal(accessed, 0);
});

test("invalid public selectors reject before generating object names", () => {
  for (const input of [
    { bucket: "a/b", runId: "authrun01" },
    { bucket: "example.appspot.com", runId: "../secret" },
    { bucket: "example.appspot.com", runId: "user@example.com" },
    { projectId: "../secret", bucket: "example.appspot.com", runId: "authrun01" },
  ])
    assert.throws(() => buildSymbolicStorageAuthPlan(input));
});
