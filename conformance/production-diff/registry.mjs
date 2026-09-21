// PROD-DIFF-PILOT-001. A single *whole* historical program, not a new oracle.
export const CASE = Object.freeze({
  id: 'fs.batch-write.saved-20260907.v1',
  programId: 'writes/batch-write',
  programDigest: 'cdda66d1fbb8f32a707188b58880134781c9d2ea105bec3924dea9dee98e57af',
  parent: 'FS-DATA-WRITE',
  title: 'BatchWrite duplicate refusal, post-state and empty/unknown-field controls',
  referenceCommit: 'a0fd439618ca87914407875c6e93d1a06fc61bc0',
  observedSource: '2526c61eda5fc53ac91250307786127ae3c601be',
  matrixPath: 'conformance/firestore-production-matrix.json',
  matrixBlob: '507a3412005c3b0a1b8c1f0a4a150dca101dac3b',
  corpusPath: 'conformance/src/firestore-probe/programs.mjs',
  corpusBlob: '17f7d4c1ccaac2c114fc8cf0c8312e68151254d7',
  corpusDigest: 'sha256-d4ae37c1b35ec7dcd162015f170c9da36a926ca5eb646177471d966e3a12bf2b',
  comparatorPath: 'conformance/src/firestore-probe/run.mjs',
  comparatorBlob: 'b4821287aba649c595599015a97f7d48ab29c4be',
  comparatorSliceSha256: 'efa1ff6f51d740033eb9d73e3306208630afaf487b54157ce5b4c91d15ea24c2',
  sessionPath: 'conformance/src/firestore-probe/session.mjs',
  sessionBlob: 'f0cccf31eab09845e25ff4a9d356d347b04d721d',
  credentialsPath: 'conformance/src/firestore-probe/credentials.mjs',
  credentialsBlob: '683058133f9912ce88ef0bec9a1c011c97cd055d',
  project: 'demo-firestore-probe',
  profile: 'strict',
  transport: 'rest-owner',
  stepIds: Object.freeze([
    'non-atomic-batch', 'one-was-written', 'existing-was-deleted',
    'empty-batch', 'batch-with-transaction-is-refused',
  ]),
  ownedDocuments: Object.freeze(['bw/existing', 'bw/one', 'bw/none', 'bw/two']),
  compared: Object.freeze(['HTTP status', 'canonical error code', 'normalized success body',
    'the two recorded post-state reads']),
  notEstablished: Object.freeze([
    'Error message equality, error details erased by the legacy recorder',
    'Exact timestamps, commit-time relationships and token bytes',
    'Rules/user-token authorization, browser/SDK/gRPC or concurrent histories',
    'Non-atomic continuation for a valid non-duplicate BatchWrite',
    'Commit transform 500/501, other limits, or complete FS-DATA-WRITE parity',
    'A fresh production observation or independent compatibility approval',
  ]),
});

export function selectCase(id = CASE.id) {
  if (id !== CASE.id) throw new Error('unknown-case');
  return CASE;
}
