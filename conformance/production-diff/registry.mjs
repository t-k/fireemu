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

export const CASES = Object.freeze([CASE, COMMIT_TRANSFORM_CASE]);

export function selectCase(id = CASE.id) {
  const entry = CASES.find((c) => c.id === id);
  if (!entry) throw new Error("unknown-case");
  return entry;
}
