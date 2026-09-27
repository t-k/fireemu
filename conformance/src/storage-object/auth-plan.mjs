const RECIPE_IDS = ["storage-object/errors/authorization", "storage-object/auth/firebase-id-token"];
const GCS_READBACKS = ["metadata", "media", "prefix-all-pages"];
const PROGRAM_CASES = [
  {
    id: "authorization-errors",
    recipeId: "storage-object/errors/authorization",
    credentials: ["anonymous", "malformed", "competitor", "valid"],
  },
  {
    id: "firebase-id-token",
    recipeId: "storage-object/auth/firebase-id-token",
    credentials: ["valid", "competitor"],
  },
];
const ACTIONS = ["read", "write"];
export const FIXED_PRODUCTION_RULES_SHA256 = "dff1d21237c12a1f3d1e5ef1134ba996d0b79c99530cb88bb016a5241388dc9b";

function selectors({ projectId, bucket, runId } = {}) {
  if (typeof projectId !== "string" || !/^[a-z][a-z0-9-]{4,29}$/.test(projectId))
    throw new Error("invalid symbolic project ID");
  if (
    typeof bucket !== "string" ||
    bucket.length < 3 ||
    bucket.length > 222 ||
    !bucket.split(".").every((part) => /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(part))
  )
    throw new Error("invalid symbolic bucket");
  if (typeof runId !== "string" || !/^[a-z0-9]{8,32}$/.test(runId))
    throw new Error("invalid symbolic run ID");
  return { projectId, bucket, runId };
}

function frozen(value) {
  if (value !== null && typeof value === "object") {
    for (const item of Object.values(value)) frozen(item);
    Object.freeze(value);
  }
  return value;
}

/** Build obligations with symbolic credential references only; this is not a request corpus. */
export function buildSymbolicStorageAuthPlan(input) {
  const { projectId, bucket, runId } = selectors(input);
  const programs = PROGRAM_CASES.map((program) => ({
    id: program.id,
    recipeId: program.recipeId,
    validAccountRef: `owned-account:${runId}:${program.id}:valid`,
    competitorAccountRef: `owned-account:${runId}:${program.id}:competitor`,
    accountLifecycle: "create-and-delete-per-program",
  }));
  const probes = PROGRAM_CASES.flatMap((program) =>
    program.credentials.flatMap((credentialRef) => ACTIONS.map((action) => ({
        id: `${program.id}/${credentialRef}/${action}`,
        programId: program.id,
        action,
        requestDialect: "firebase",
        credentialRef,
        objectName: `storage-object/${runId}/auth/${program.id}/${credentialRef}/${action}.bin`,
        setupCredentialRef: "owner",
        setupState: action === "read" ? "owned-present" : "owned-absent",
        gcsInitialAbsence: [...GCS_READBACKS],
        setupCreatePrecondition:
          action === "read" ? "ifGenerationMatch=0" : "not-applicable-no-owner-seed",
        setupOwnershipJournal: "durable-before-first-mutation",
        gcsBefore: [...GCS_READBACKS],
        gcsAfter: [...GCS_READBACKS],
        outcome: "UNOBSERVED",
      }))),
  );
  return frozen({
    schemaVersion: 1,
    state: "PLANNED_NOT_DECLARED",
    recipeIds: [...RECIPE_IDS],
    programs,
    projectId,
    bucket,
    runId,
    credentials: {
      anonymous: { kind: "anonymous", wireScheme: null },
      owner: { kind: "owner-adc", wireScheme: "Bearer", secretRef: "private-ref:owner-adc" },
      valid: {
        kind: "firebase-id-token",
        wireScheme: "Firebase",
        secretRef: `private-ref:${runId}:{programId}:id-token`,
        accountRef: `owned-account:${runId}:{programId}:valid`,
        expectedEmail: "storage-object@example.com",
        requiredProofs: [
          "signup-uid-equals-lookup-uid",
          "token-not-expired-at-send",
          "wire-header-provenance",
          "private-mode-0600",
        ],
        proofsVerified: false,
      },
      competitor: {
        kind: "firebase-id-token",
        wireScheme: "Firebase",
        secretRef: `private-ref:${runId}:{programId}:competitor-id-token`,
        accountRef: `owned-account:${runId}:{programId}:competitor`,
        expectedEmail: `storage-object-control-${runId}-{programId}@example.com`,
        requiredProofs: [
          "signup-uid-equals-lookup-uid",
          "token-not-expired-at-send",
          "wire-header-provenance",
          "private-mode-0600",
        ],
        proofsVerified: false,
      },
      malformed: {
        kind: "malformed-firebase-token",
        wireScheme: "Firebase",
        secretRef: `private-ref:${runId}:malformed-token`,
        requiredProofs: [
          "request-bound-malformed-wire-value",
          "wire-value-distinct-from-valid-token",
          "wire-header-provenance",
          "private-mode-0600",
        ],
        proofsVerified: false,
      },
    },
    rules: {
      approvedBaselineRef: "private-ref:approved-storage-rules-baseline",
      expectedSourceSha256: FIXED_PRODUCTION_RULES_SHA256,
      expectedPolicy: {
        prefix: `storage-object/${runId}/`,
        allowEmail: "storage-object@example.com",
        otherEmails: "deny",
        anonymous: "deny",
      },
      requiredProofs: [
        "approved-baseline-project-bucket-release-ruleset-body-binding",
        "approved-baseline-source-sha256-equals-fixed-source",
        "observed-body-sha256-equals-approved-baseline",
        "bucket-release-before-after-identical",
        "ruleset-before-after-identical",
        "rules-body-sha256-before-after-identical",
        "bucketless-release-absent-before-after",
      ],
      mutationAllowed: false,
      verified: false,
    },
    interpretationRules: [
      "valid-success-and-competitor-denial-required-for-email-gate",
      "anonymous-and-malformed-controls-keep-distinct-wire-provenance",
      "denied-write-requires-no-side-effect-readback",
    ],
    probes,
    cleanup: {
      account: "delete-both-owned-accounts-and-lookup-absence-per-program",
      objects: "owned-generation-match-delete-and-absence-readback",
      responsibility: "durable-journal-before-send",
      rules: "no-mutation",
      verified: false,
    },
    wireRequestBudget: null,
    recipesDeclared: false,
    projectBindingVerified: false,
    credentialsVerified: false,
    rulesBaselineVerified: false,
    ownershipVerified: false,
    compatibilityEstablished: false,
    sendAuthorized: false,
  });
}

/** Compare normalized snapshots to a supplied private baseline; this grants no admission authority. */
export function compareStorageRulesBaseline(plan, baseline, before, after) {
  validateSymbolicStorageAuthPlan(plan);
  const mismatch = () =>
    Object.freeze({
      status: "MISMATCH",
      rulesBaselineVerified: false,
      sendAuthorized: false,
    });
  if (
    baseline === null ||
    typeof baseline !== "object" ||
    baseline.projectId !== plan.projectId ||
    baseline.bucket !== plan.bucket ||
    baseline.approvalRef !== plan.rules.approvedBaselineRef ||
    baseline.sourceSha256 !== FIXED_PRODUCTION_RULES_SHA256 ||
    baseline.bodySha256 !== FIXED_PRODUCTION_RULES_SHA256 ||
    baseline.releaseName !==
      `projects/${baseline.projectId}/releases/firebase.storage/${plan.bucket}` ||
    typeof baseline.rulesetName !== "string" ||
    !baseline.rulesetName.startsWith(`projects/${baseline.projectId}/rulesets/`)
  )
    return mismatch();
  const expectedBaseline = {
    approvalRef: plan.rules.approvedBaselineRef,
    projectId: plan.projectId,
    bucket: plan.bucket,
    releaseName: baseline.releaseName,
    rulesetName: baseline.rulesetName,
    bodySha256: baseline.bodySha256,
    sourceSha256: FIXED_PRODUCTION_RULES_SHA256,
  };
  if (!plainSame(baseline, expectedBaseline)) return mismatch();
  const expectedSnapshot = { ...expectedBaseline, bucketlessReleaseAbsent: true };
  if (!plainSame(before, expectedSnapshot) || !plainSame(after, expectedSnapshot))
    return mismatch();
  return Object.freeze({
    status: "SNAPSHOT_MATCHES_SUPPLIED_BASELINE",
    rulesBaselineVerified: false,
    sendAuthorized: false,
  });
}

function plainSame(actual, expected) {
  if (Array.isArray(expected)) {
    if (
      !Array.isArray(actual) ||
      Object.getPrototypeOf(actual) !== Array.prototype ||
      actual.length !== expected.length
    )
      return false;
    const keys = Reflect.ownKeys(actual);
    if (
      keys.length !== expected.length + 1 ||
      keys.some((key, index) =>
        index < expected.length ? key !== String(index) : key !== "length",
      )
    )
      return false;
    for (let index = 0; index < expected.length; index++) {
      const descriptor = Object.getOwnPropertyDescriptor(actual, String(index));
      if (
        !descriptor?.enumerable ||
        !Object.hasOwn(descriptor, "value") ||
        !plainSame(descriptor.value, expected[index])
      )
        return false;
    }
    return true;
  }
  if (expected !== null && typeof expected === "object") {
    if (
      actual === null ||
      typeof actual !== "object" ||
      Array.isArray(actual) ||
      Object.getPrototypeOf(actual) !== Object.prototype
    )
      return false;
    const keys = Reflect.ownKeys(actual);
    const expectedKeys = Object.keys(expected);
    if (
      keys.length !== expectedKeys.length ||
      keys.some((key) => typeof key !== "string" || !expectedKeys.includes(key))
    )
      return false;
    for (const key of expectedKeys) {
      const descriptor = Object.getOwnPropertyDescriptor(actual, key);
      if (
        !descriptor?.enumerable ||
        !Object.hasOwn(descriptor, "value") ||
        !plainSame(descriptor.value, expected[key])
      )
        return false;
    }
    return true;
  }
  return Object.is(actual, expected);
}

/** Accept only the exact symbolic obligations, including hidden-field rejection. */
export function validateSymbolicStorageAuthPlan(plan) {
  const projectId = Object.getOwnPropertyDescriptor(plan ?? {}, "projectId");
  const bucket = Object.getOwnPropertyDescriptor(plan ?? {}, "bucket");
  const runId = Object.getOwnPropertyDescriptor(plan ?? {}, "runId");
  if (
    !projectId ||
    !Object.hasOwn(projectId, "value") ||
    !bucket ||
    !Object.hasOwn(bucket, "value") ||
    !runId ||
    !Object.hasOwn(runId, "value")
  )
    throw new Error("invalid symbolic auth plan");
  let expected;
  try {
    expected = buildSymbolicStorageAuthPlan({
      projectId: projectId.value,
      bucket: bucket.value,
      runId: runId.value,
    });
  } catch {
    throw new Error("invalid symbolic auth plan");
  }
  if (!plainSame(plan, expected)) throw new Error("invalid symbolic auth plan");
  return Object.freeze({
    status: "SYMBOLIC_PLAN_CONSISTENT",
    recipesDeclared: false,
    projectBindingVerified: false,
    credentialsVerified: false,
    rulesBaselineVerified: false,
    ownershipVerified: false,
    compatibilityEstablished: false,
    sendAuthorized: false,
  });
}
