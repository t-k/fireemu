// PROD-DIFF-PILOT-001. Two whole historical programs, not a new oracle.
//
// Both cases are adapters over already-published, already-committed evidence; neither invents a
// production observation. They differ in what evidence was published for them:
//   - "batch-write" (legacy.mjs): the campaign published a full normalized production/local
//     row matrix (conformance/firestore-production-matrix.json). The pilot replays the pinned
//     upstream recorder and compares against that matrix via the pinned legacy comparator.
//   - "commit-transform" (commit-transform.mjs): the campaign published only a digest/summary
//     record; the raw request/response journal is private (see both saved-run files' own
//     `limitations` and docs/compatibility/fs-commit-transform-limits-production-result.md).
//     The pilot compiles the campaign's own deterministic request plan locally and compares
//     against a typed reference derived from that plan's declared contract plus the one literal
//     message the summary record publishes verbatim. See commit-transform.mjs for the full
//     rationale and disclosed scope.
export const CASE = Object.freeze({
  id: "fs.batch-write.saved-20260907.v1",
  adapter: "batch-write",
  evidenceKind: "saved-production-reference",
  oracleKind: "legacy-normalized-production-observation",
  programId: "writes/batch-write",
  programDigest: "cdda66d1fbb8f32a707188b58880134781c9d2ea105bec3924dea9dee98e57af",
  parent: "FS-DATA-WRITE",
  title: "BatchWrite duplicate refusal, post-state and empty/unknown-field controls",
  referenceCommit: "a0fd439618ca87914407875c6e93d1a06fc61bc0",
  observedSource: "2526c61eda5fc53ac91250307786127ae3c601be",
  matrixPath: "conformance/firestore-production-matrix.json",
  matrixBlob: "507a3412005c3b0a1b8c1f0a4a150dca101dac3b",
  corpusPath: "conformance/src/firestore-probe/programs.mjs",
  corpusBlob: "17f7d4c1ccaac2c114fc8cf0c8312e68151254d7",
  corpusDigest: "sha256-d4ae37c1b35ec7dcd162015f170c9da36a926ca5eb646177471d966e3a12bf2b",
  comparatorPath: "conformance/src/firestore-probe/run.mjs",
  comparatorBlob: "b4821287aba649c595599015a97f7d48ab29c4be",
  comparatorSliceSha256: "efa1ff6f51d740033eb9d73e3306208630afaf487b54157ce5b4c91d15ea24c2",
  sessionPath: "conformance/src/firestore-probe/session.mjs",
  sessionBlob: "f0cccf31eab09845e25ff4a9d356d347b04d721d",
  credentialsPath: "conformance/src/firestore-probe/credentials.mjs",
  credentialsBlob: "683058133f9912ce88ef0bec9a1c011c97cd055d",
  project: "demo-firestore-probe",
  profile: "strict",
  transport: "rest-owner",
  sessionScript: "local-session.mjs",
  sessionSetupPhases: Object.freeze(["reset", "seed"]),
  cleanupResetRequests: 1,
  stepIds: Object.freeze([
    "non-atomic-batch",
    "one-was-written",
    "existing-was-deleted",
    "empty-batch",
    "batch-with-transaction-is-refused",
  ]),
  ownedDocuments: Object.freeze(["bw/existing", "bw/one", "bw/none", "bw/two"]),
  compared: Object.freeze([
    "HTTP status",
    "canonical error code",
    "normalized success body",
    "the two recorded post-state reads",
  ]),
  notEstablished: Object.freeze([
    "Error message equality, error details erased by the legacy recorder",
    "Exact timestamps, commit-time relationships and token bytes",
    "Rules/user-token authorization, browser/SDK/gRPC or concurrent histories",
    "Non-atomic continuation for a valid non-duplicate BatchWrite",
    "Commit transform 500/501, other limits, or complete FS-DATA-WRITE parity",
    "A fresh production observation or independent compatibility approval",
  ]),
});

export const COMMIT_TRANSFORM_CASE = Object.freeze({
  id: "fs.commit-transform-limits.saved-031c74bfe.v1",
  adapter: "commit-transform",
  // Unlike CASE (a full normalized production/local row matrix, see legacy.mjs), the campaign
  // published only a digest/summary record for this case; the typed reference this case compares
  // against is derived from that summary plus the compiled request plan's own declared contract
  // (see commit-transform.mjs's documentedReference()), not from a saved production row matrix.
  evidenceKind: "documented-production-outcome-reference",
  oracleKind: "documented-outcome-contract",
  programId: "writes/commit-transform-limits",
  programDigest: "23b4820c1adee6d4d99d4ce4857a68013d8cdc3a098ac00c5e0387fffd1d135d",
  parent: "FS-DATA-WRITE",
  title: "Commit field-transform 500/501 per-document boundary, post-state and cleanup controls",
  referenceCommit: "031c74bfe372e5a1f7e667397c84a063503a53d6",
  savedRecompareCommit: "aa39de4b6f0dcc87430d72aaa0b9a8b00e31dc30",
  productionResultPath:
    "spec/compatibility/broad-runs/fs-commit-transform-limits-031c74bfe-production-result.json",
  productionResultBlob: "e48ef00dade31e7d923d5492d212842344f1e724",
  savedResultPath:
    "spec/compatibility/broad-runs/fs-commit-transform-limits-aa39de4b6-saved-result.json",
  savedResultBlob: "10c229400641bf5c37367501e3b2dd62dd26827e",
  compilerPath: "tools/compat-broad/fs-commit-transform-limits/transform_compiler.py",
  compilerBlob: "0a4693f04ab51d1b4aecb1052f8728b7dbba6d0e",
  comparatorPath: "tools/compat-broad/fs-commit-transform-limits/transform_comparator.py",
  comparatorBlob: "ddce2e22c203ca1f44a897dbcdf2a72e079602f2",
  refusedCommitMessage: "cannot have more than 500 field transforms on a single document",
  // This case has no upstream "legacy" Node recorder to pin (see commit-transform.mjs); these
  // three fields stay null so the recording-contract check in pilot.mjs compares like for like.
  comparatorSliceSha256: null,
  sessionBlob: null,
  credentialsBlob: null,
  project: "demo-firestore-probe",
  database: "(default)",
  nonce: "157f0725bcec13abb931658ca630a45f",
  profile: "strict",
  transport: "rest-owner",
  sessionScript: "commit-transform-session.mjs",
  sessionSetupPhases: Object.freeze([]),
  cleanupResetRequests: 0,
  stepIds: Object.freeze([
    "preflight-typed-absence:exact-500",
    "preflight-typed-absence:over-501",
    "create-only-patch:exact-500",
    "create-only-patch:over-501",
    "baseline-readback:exact-500",
    "baseline-readback:over-501",
    "commit-transform:exact-500",
    "poststate-readback:exact-500",
    "commit-transform:over-501",
    "poststate-readback:over-501",
    "poststate-control-readback:exact-500",
    "cleanup-ownership-read:exact-500",
    "cleanup-conditional-delete:exact-500",
    "cleanup-verify-absence:exact-500",
    "cleanup-ownership-read:over-501",
    "cleanup-conditional-delete:over-501",
    "cleanup-verify-absence:over-501",
  ]),
  ownedDocuments: Object.freeze([
    "projects/demo-firestore-probe/databases/(default)/documents/oracle/157f0725bcec13abb931658ca630a45f/commit-limits-03/exact-500",
    "projects/demo-firestore-probe/databases/(default)/documents/oracle/157f0725bcec13abb931658ca630a45f/commit-limits-03/over-501",
  ]),
  compared: Object.freeze([
    "HTTP status for all 17 rows",
    "canonical error code for the typed-absence and refusal rows",
    "transformResults count for the accepted (exact-500) Commit",
    "the literal refusal message text for the refused (over-501) Commit, pinned from the published production record",
    "post-state field identity for the two rows the field-transform boundary actually turns on",
  ]),
  notEstablished: Object.freeze([
    "Byte-exact parity with the private production request/response journal (not published; see commit-transform.mjs)",
    "Resource-name-normalized message parity for the four typed-absence rows that the repaired transform_comparator.py verifies against the real saved journal",
    "Exact timestamps, commitTime/updateTime relationships and token bytes",
    "Rules/user-token authorization, browser/SDK/gRPC or concurrent histories",
    "The catalog limits and unsupported write-path limits FS-DATA-WRITE still lists open",
    "A fresh production observation or independent compatibility approval",
  ]),
});

export const G0_CASE = Object.freeze({
  id: "fs.g0.saved-68012694.v1",
  adapter: "g0",
  evidenceKind: "saved-production-reference",
  oracleKind: "normalized-g0-runtime-recomparison",
  programId: "shared-g0-v1",
  programDigest: null,
  parent: "FS-DATA-WRITE",
  title: "Shared G0 BatchWrite runtime recomparison",
  referenceCommit: "a35f85b464743d62344a3a58763d382b5b3838ce",
  productionResultPath: "G0_PRIVATE_PRODUCTION_RESULT",
  productionResultSha256:
    "47672f4e3162b4a0ddfb7baaab622007602aeed6c1fa3d6e5e84034bcbb87772",
  nonce: "68012694f81df504600f8e67301410c6",
  project: "fireemu-35fe6",
  profile: "strict",
  transport: "local-only",
  sessionScript: "g0-session.mjs",
  sessionSetupPhases: Object.freeze([]),
  cleanupResetRequests: 0,
  stepIds: Object.freeze([]),
  ownedDocuments: Object.freeze([]),
  compared: Object.freeze([
    "12 normalized status/resource rows from the existing G0 comparator",
    "typed values, refusal state, missing rows and extra rows",
  ]),
  notEstablished: Object.freeze([
    "Byte-exact parity with the private production journal",
    "Exact timestamps, token bytes or unnormalized resource names",
    "A fresh production observation or parent promotion",
  ]),
});

// FS-EVID-TRANSFORMS-021: replay the WHOLE observed 18-step program. The
// "batch-write" adapter names the existing pinned REST recorder, not an API
// restriction. Do not rewrite malformed inputs or split a stateful program.
export const TRANSFORMS_CASE = Object.freeze({
  ...CASE,
  id: "fs.transforms.saved-20260907.v1",
  programId: "writes/transforms",
  programDigest: "b6cf42bea907f63553c645a5a03b0aa3d60c346174c9f228c3056ee8d117a6c5",
  title: "Saved production transforms, typed refusals and ordered post-state reads",
  // Raw responses for REQUEST_TIME precision/readback diagnostics only. The
  // historical normalized comparison and its evidence claims are unchanged.
  rawTimestampResponseSteps: Object.freeze([
    "server-timestamp-and-increments", "read-after-increments", "read-after-max-min",
    "read-after-array-transforms", "transform-only-write-creates",
    "read-transform-created", "read-set-and-transform",
  ]),
  stepIds: Object.freeze([
    "server-timestamp-and-increments",
    "read-after-increments",
    "maximum-and-minimum",
    "read-after-max-min",
    "array-transforms",
    "read-after-array-transforms",
    "transform-only-write-creates",
    "read-transform-created",
    "transform-write-with-exists-precondition",
    "increment-with-non-numeric-operand",
    "server-timestamp-on-a-delete",
    "set-and-transform-same-field",
    "read-set-and-transform",
    "integer-increment-saturates",
    "read-saturated",
    "increment-on-nan",
    "two-transforms-on-one-field-in-one-write",
    "read-dup",
  ]),
  ownedDocuments: Object.freeze([
    "tf/doc", "tf/created", "tf/none", "tf/sat", "tf/nan", "tf/dup",
  ]),
  compared: Object.freeze([
    "HTTP status and canonical error code for all 18 historical steps",
    "Normalized successful response bodies, including ordered transformResults",
    "The seven recorded document readbacks, including post-state after invalid field-path refusal",
    "Mixed numeric/missing/non-numeric increments, saturated int64, NaN and sequential same-field transforms in this exact program",
    "The saved array union/removal sequence and its final document state",
  ]),
  notEstablished: Object.freeze([
    "Successful maximum/minimum execution: that historical request is refused for unquoted max-missing",
    "All numeric equality, array union/removal or independent transform equivalence classes",
    "Error message/detail equality, exact timestamps or time relationships erased by the historical recorder",
    "A separate readback immediately after each of the four refused requests",
    "Rules/user-token authorization, browser/SDK/gRPC, concurrent histories or transform count limits",
    "A fresh production observation, current-artifact execution or independent compatibility approval merely from registering this case",
  ]),
});

// FS-EVID-PRECONDITIONS-022: the entire observed program, including the
// runtime updateTime references and generated-id control. Evidence remains the
// pinned normalized production matrix; the test fixture is NOT an oracle.
export const PRECONDITIONS_CASE = Object.freeze({
  ...CASE,
  id: "fs.preconditions-and-masks.saved-20260907.v1",
  programId: "writes/preconditions-and-masks",
  programDigest: "cd4fc7df2a0173b797fc0b5b45ed430d36a1706db83c9cbef6c31b3c03616bae",
  title: "Saved production preconditions, update masks, atomic refusal and CRUD",
  allowedMethods: Object.freeze(["GET", "POST", "PATCH", "DELETE"]),
  stepIds: Object.freeze([
    "create-with-exists-false",
    "create-again-is-already-exists",
    "update-missing-with-exists-true",
    "mask-sets-and-deletes",
    "read-after-mask",
    "mask-on-missing-document-creates-it",
    "read-masked-new",
    "mask-naming-an-absent-field-deletes-it",
    "read-after-delete-by-mask",
    "replace-without-mask",
    "read-after-replace",
    "update-time-precondition-matches",
    "update-time-precondition-is-stale",
    "update-time-precondition-on-a-missing-document",
    "delete-missing-is-ok",
    "delete-missing-with-exists-true",
    "atomic-failure-writes-nothing",
    "atomic-1-is-absent",
    "same-document-twice-in-one-commit",
    "read-twice",
    "empty-commit",
    "verify-write",
    "verify-missing",
    "no-op-set-keeps-update-time",
    "read-after-no-op",
    "patch-with-mask-and-exists-precondition-on-missing",
    "patch-creates",
    "read-patched",
    "create-document",
    "create-document-again",
    "create-document-with-generated-id",
    "delete-document",
    "delete-document-again",
    "delete-with-exists-precondition"
]),
  ownedDocuments: Object.freeze([
    "wr/existing", "wr/new", "wr/none", "wr/masked-new",
    "wr/atomic-1", "wr/twice", "wr/patched", "wr/created",
  ]),
  generatedDocumentSteps: Object.freeze({ "create-document-with-generated-id": "wr" }),
  compared: Object.freeze([
    "All 34 original HTTP status/canonical-code/normalized-success-body decisions",
    "Update masks: nested deletion, preservation, creation and unmasked replacement",
    "The matching and stale updateTime requests use the same earlier raw response value",
    "The recorded atomic refusal and its subsequent unpublished-document absence read",
    "Same-document Commit ordering, verify, empty/no-op Commit and recorded CRUD cases",
  ]),
  notEstablished: Object.freeze([
    "Exact error messages/details or timestamp/commit-time relationships erased by the old recorder",
    "No-op updateTime equality: both time values are independently normalized to <now>",
    "Auto-ID entropy/collision behavior: the old recorder normalizes matching generated names",
    "A post-state read immediately after every rejected operation, or complete atomicity coverage",
    "Rules/user tokens, gRPC/SDK, concurrency, limits or a fresh production observation",
    "Final-artifact parity or independent condition acceptance from registering/testing this adapter",
  ]),
});

// FS-EVID-PROJECTION-LISTING-027: the original complete 18-step read program.
// Reuses the pinned REST recorder and the production column only. The raw page
// token is taken from the preceding response, never from its normalized <token>.
export const PROJECTION_CASE = Object.freeze({
  ...CASE,
  id: "fs.projection-and-listing.saved-20260907.v1",
  programId: "queries/projection-and-listing",
  programArea: "queries",
  seedCount: 3,
  programDigest: "e8c30e076d75f6783e0fe3eba3157d36f05c5ba92caa7f43cb5a4d7e0d678589",
  title: "Saved production projection, listing, raw page-token handoff and masked BatchGet",
  sessionSetupPhases: Object.freeze(["reset", "seed", "seed", "seed"]),
  stepIds: Object.freeze([
    "select-fields",
    "select-missing-field",
    "select-with-empty-list",
    "list-documents",
    "list-documents-page-size-one",
    "list-documents-next-page",
    "list-documents-with-mask",
    "list-documents-descending",
    "list-documents-show-missing",
    "list-missing-parents",
    "list-subcollection-of-missing-parent",
    "list-empty-collection",
    "list-collection-ids-root",
    "list-collection-ids-of-a-missing-document",
    "list-collection-ids-paged",
    "get-with-mask",
    "get-missing-parent-document",
    "batch-get-mixed",
  ]),
  ownedDocuments: Object.freeze([
    "prj/a", "prj/b", "prj/missing-parent/sub/x", "prj/missing-parent", "prj/none",
  ]),
  compared: Object.freeze([
    "All 18 original status/canonical-code/normalized-success-body decisions",
    "Query projection of nested/missing fields and an explicitly empty projection list",
    "ListDocuments first/next page, masks, descending order and showMissing responses",
    "Subcollections below a missing parent and ListCollectionIds on the recorded paths",
    "GetDocument response mask, absent parent and masked BatchGet found/missing responses",
  ]),
  notEstablished: Object.freeze([
    "Opaque page-token bytes, token validation/expiry or pagination under concurrent changes",
    "Every pagination boundary: only the original first and next page are replayed",
    "Error message/details, timestamp relationships or values erased by the historical normalizer",
    "General BatchGet ordering guarantees beyond comparison of this recorded sequence",
    "Rules/user-token authorization, SDK/gRPC, concurrent histories or query-index parity as a whole",
    "A fresh production observation or independent current-artifact acceptance from registering this case",
  ]),
});

// FS-EVID-AGGREGATIONS-029: add the WHOLE existing 23-step query program.
// The test replies are synthetic; execution uses only the pinned production matrix.
// Reuse the reviewed 027 multi-seed/query-area support without changing the runner.
export const AGGREGATIONS_CASE = Object.freeze({
  ...CASE,
  id: "fs.aggregations.saved-20260907.v1",
  parent: "FS-QUERY-INDEX",
  programId: "queries/aggregations",
  programArea: "queries",
  seedCount: 6,
  indexFilePath: "conformance/firestore.indexes.json",
  indexFileBlob: "7c1ef93940752d8981ae29cfea40c210f27560f8",
  indexFileBytes: 2484,
  indexFileSha256: "sha256-8a4d4bd7a72c3ce2bed4e0f8c4adc0cdb3a7c428477578295e44a11ae063d01c",
  indexFilesDigest: "sha256-ad4a66f22bbfb41fd0a2e7585ed0cbd82f88e854a915049ee724e9f2afd4d01a",
  programDigest: "6123c1524b70e0ea1e32d18d5b177a73430ec10a76bfd1e82c92e4714832fdc2",
  title: "Saved production count/sum/avg, missing fields, numeric boundaries and refusals",
  sessionSetupPhases: Object.freeze(["reset", "seed", "seed", "seed", "seed", "seed", "seed"]),
  stepIds: Object.freeze([
    "count-all",
    "count-up-to",
    "count-with-filter",
    "count-with-limit",
    "count-with-offset",
    "count-empty",
    "sum-integers",
    "sum-mixed-numbers",
    "sum-doubles-only",
    "sum-empty",
    "sum-missing-field",
    "sum-overflow-saturates-or-promotes",
    "avg-integers",
    "avg-with-nan",
    "avg-empty",
    "several-aggregations",
    "count-collection-group",
    "count-with-cursor",
    "count-beside-a-sum-over-a-missing-field",
    "count-beside-an-avg-over-a-missing-field",
    "duplicate-alias",
    "no-aggregations",
    "sum-on-name"
]),
  ownedDocuments: Object.freeze(["agg/a", "agg/b", "agg/c", "agg/d", "agg/e", "agg/f"]),
  compared: Object.freeze([
    "All 23 original HTTP-status/canonical-code/normalized-response-body decisions",
    "Recorded count queries with upTo, filter, limit, offset, cursor and empty result",
    "Recorded sum/avg values and types, including NaN, missing fields and integer overflow inputs",
    "Combined aggregations, aliases and their recorded missing-field interactions",
    "Duplicate-alias, empty-aggregation-list and sum-on-name responses exactly as observed",
  ]),
  notEstablished: Object.freeze([
    "Floating-point accuracy for arbitrary data, large populations or all evaluation orders",
    "Nested collection-group breadth: the six historical seed documents are all root-level",
    "Successful rows inferred from case names; the pinned production outcome alone is the oracle",
    "Error message/details, raw readTime, runtime statistics or values erased by the historical normalizer",
    "Rules/user-token authorization, SDK/gRPC, index-requirement parity or concurrent snapshot behavior",
    "New production observations, current-artifact execution or independent acceptance from registering this case",
  ]),
});

export const CASES = Object.freeze([CASE, COMMIT_TRANSFORM_CASE, G0_CASE, TRANSFORMS_CASE, PRECONDITIONS_CASE, PROJECTION_CASE, AGGREGATIONS_CASE]);

export function selectCase(id = CASE.id) {
  const entry = CASES.find((c) => c.id === id);
  if (!entry) throw new Error("unknown-case");
  return entry;
}
