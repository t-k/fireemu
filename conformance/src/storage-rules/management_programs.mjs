import { createHash } from "node:crypto";

const PROJECT = "fireemu-oracle-query";
const CAPTURE = { status: true, headers: "all", body: "raw-bytes" };
const rulesRoot = `/v1/projects/${PROJECT}`;
const testPath = `${rulesRoot}:test`;
const bucketlessReleaseName = `projects/${PROJECT}/releases/firebase.storage`;

const hash = (source) => createHash("sha256").update(source).digest("hex");
const pending = (id) => ({
  id,
  recipeId: `storage-rules/${id}`,
  projectId: PROJECT,
  observationStatus: "PENDING_PRODUCTION",
  sendAuthorized: false,
});
const request = (id, method, path, extra = {}) => ({
  id,
  service: "firebase-rules",
  method,
  path,
  capture: { ...CAPTURE },
  ...extra,
});

function compileProgram(binding, cases, firestorePrograms, switchCase) {
  const releaseName = `${bucketlessReleaseName}/${binding.bucket}`;
  const releasePath = `/v1/${releaseName}`;
  const sources = [
    ...cases.map((entry) => ({ ref: `case/${entry.id}`, content: entry.rulesSource })),
    ...firestorePrograms.map((entry) => ({ ref: `firestore/${entry.id}`, content: entry.rulesSource })),
    { ref: "release-switch/A", content: switchCase.sourceA },
    { ref: "release-switch/B", content: switchCase.sourceB },
  ];
  const validSources = sources.map(({ ref, content }) => ({ ref, sha256: hash(content), content }));
  const invalid = "rules_version = '2';\nservice firebase.storage {\n  match /b/{bucket}/o {\n    match /{path=**} {\n      allow get: if ;\n    }\n  }\n}\n";
  return {
    ...pending("storage-service-compile"),
    releaseName,
    bucketlessReleaseName,
    validSources,
    invalidSource: { ref: "invalid/storage-expression", sha256: hash(invalid), content: invalid },
    validSequence: [
      request("release-before", "GET", releasePath, { requiredState: "unchanged-baseline" }),
      request("test-valid-source", "POST", testPath, {
        body: { source: { files: [{ name: "storage.rules", contentRef: "validSources[].content" }] } },
        requiredState: "no-error-issues",
        repeatFor: "validSources",
      }),
    ],
    invalidSequence: [
      request("test-invalid-source", "POST", testPath, {
        body: { source: { files: [{ name: "storage.rules", contentRef: "invalidSource.content" }] } },
        requiredState: "error-issue-with-position",
      }),
      request("release-after-invalid", "GET", releasePath, { requiredState: "matches-release-before" }),
    ],
    fullBudgetAndFailureRecoveryPending: true,
  };
}

function allowOnly(objectName) {
  return `rules_version = '2';\nservice firebase.storage {\n  match /b/{bucket}/o {\n    match /${objectName} {\n      allow get: if true;\n    }\n  }\n}\n`;
}

function switchProgram(binding) {
  const objectA = `${binding.prefix}release-switch/old.bin`;
  const objectB = `${binding.prefix}release-switch/new.bin`;
  return {
    ...pending("release-switch"),
    releaseName: `${bucketlessReleaseName}/${binding.bucket}`,
    bucketlessReleaseName,
    expectedBaseline: "bucket-specific-and-bucketless-release-absent",
    objectA,
    objectB,
    sourceA: allowOnly(objectA),
    sourceB: allowOnly(objectB),
    requiredOwnedSeedAndReadback: [objectA, objectB],
    decisionOrder: [
      { release: "A", object: "A", role: "old-allow" },
      { release: "A", object: "B", role: "new-not-yet-allow" },
      { release: "B", object: "A", role: "old-no-longer-allow" },
      { release: "B", object: "B", role: "new-allow" },
    ],
    switch: [
      "create-and-read-source-A",
      "create-and-read-source-B",
      "create-bucket-release-A",
      "read-release-A-and-settle-effective-decision",
      "observe-A-and-B-with-admin-state-readback",
      "read-current-release-before-patch",
      "patch-bucket-release-to-B",
      "read-release-B-and-settle-effective-decision",
      "observe-A-and-B-with-admin-state-readback",
    ],
    restore: [
      "delete-owned-release",
      "confirm-release-absent",
      "confirm-bucketless-absent",
      "delete-unreferenced-rulesets",
      "confirm-rulesets-absent",
      "owned-object-cleanup",
    ],
    fullBudgetSettleAndFailureRecoveryPending: true,
  };
}

function noReleaseProgram(binding) {
  return {
    ...pending("no-release"),
    releaseName: `${bucketlessReleaseName}/${binding.bucket}`,
    bucketlessReleaseName,
    expectedBaseline: "bucket-specific-and-bucketless-release-absent",
    objectName: `${binding.prefix}no-release/object.bin`,
    stepOrder: [
      "confirm-releases-absent",
      "confirm-object-absent",
      "admin-seed",
      "admin-read-before",
      "firebase-get-without-release",
      "admin-read-after",
      "owned-admin-delete",
      "confirm-object-absent-after",
      "confirm-releases-still-absent",
    ],
    fullBudgetAndFailureRecoveryPending: true,
  };
}

/** Static management inputs only; no production sender, publisher, or approved HTTP budget. */
export function buildManagementPrograms(binding, cases, firestorePrograms) {
  const switched = switchProgram(binding);
  return [
    compileProgram(binding, cases, firestorePrograms, switched),
    switched,
    noReleaseProgram(binding),
  ];
}
