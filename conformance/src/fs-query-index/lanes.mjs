// The lanes that share the query sandbox harness. The first two record into `fireemu-oracle-query`
// `(default)` with the same indexes, the pipeline lane into its own named Enterprise database; each has its own corpus, fixture, ledger task id and
// comparison. `run.mjs` picks one with FIREEMU_SANDBOX_LANE (default `fs-query-index`).

export const LANES = {
  // Text observations reuse the existing named-database request guard and raw recorder.
  // Native index creation, readiness and cleanup are separate coordinator-owned phases.
  "fs-ent-text": {
    id: "fs-ent-text",
    taskId: "FS-ENT-TEXT-ORACLE",
    corpus: "../fs-ent-pipeline/text-corpus.mjs",
    fixture: "fs-ent-text-production.json",
    indexes: null,
    database: "entpipe1",
    edition: "ENTERPRISE",
    target:
      "production Firestore REST v1 and gRPC google.firestore.v1 text search, Enterprise Native, database entpipe1",
    localConfig: "fs-ent-text.fireemu.json",
    firebaseJson: "fs-ent-text.firebase.json",
    harness: "src/fs-ent-text",
    sources: ["src/fs-query-index", "src/fs-ent-pipeline", "src/fs-ent-text"],
  },
  "fs-query-index": {
    id: "fs-query-index",
    taskId: "FS-QUERY-INDEX-SANDBOX",
    corpus: "./corpus.mjs",
    divergences: "./divergences.mjs",
    fixture: "fs-query-index-production.json",
    indexes: "fs-query-index.indexes.json",
    localConfig: "fs-query-index.fireemu.json",
    harness: "src/fs-query-index",
    sources: ["src/fs-query-index"],
  },
  "fs-data-write-list": {
    id: "fs-data-write-list",
    taskId: "FS-DATA-WRITE-LIST",
    corpus: "../fs-list/corpus.mjs",
    fixture: "fs-data-write-list-production.json",
    indexes: "fs-query-index.indexes.json",
    localConfig: "fs-query-index.fireemu.json",
    harness: "src/fs-query-index",
    sources: ["src/fs-query-index", "src/fs-list"],
  },
  // FS-ENT-ORACLE O-1 (owner ledger 1468 Q1): pipeline semantics in the named Enterprise
  // database `entpipe1`, which this campaign creates and deletes in its own packet steps. No
  // index file: Enterprise runs pipelines without indexes, and the lane never deploys any. The
  // lane has its own copy of the request layer (harness.mjs, session.mjs with named-database
  // support), so the other lanes' recorded harness digest stays bound to theirs.
  "fs-ent-pipeline": {
    id: "fs-ent-pipeline",
    taskId: "FS-ENT-ORACLE",
    corpus: "../fs-ent-pipeline/corpus.mjs",
    fixture: "fs-ent-pipeline-production.json",
    indexes: null,
    database: "entpipe1",
    edition: "ENTERPRISE",
    target:
      "production Firestore REST v1 and gRPC google.firestore.v1, Enterprise edition, Native API, database entpipe1",
    localConfig: "fs-ent-pipeline.fireemu.json",
    firebaseJson: "fs-ent-pipeline.firebase.json",
    harness: "src/fs-ent-pipeline",
    sources: ["src/fs-query-index", "src/fs-ent-pipeline"],
  },
};

// The pipeline lane against the emulator profile, for local runs only: the lane's id, corpus,
// fixture and database, with the emulator profile's fireemu config. A recording always uses
// `fs-ent-pipeline`. Both lanes share the id, so both write `.runs/fs-ent-pipeline/`: copy
// `comparison.json` out after each profile's run.
LANES["fs-ent-pipeline-emulator"] = {
  ...LANES["fs-ent-pipeline"],
  localConfig: "fs-ent-pipeline.emulator.fireemu.json",
};

export function selectLane(name = process.env.FIREEMU_SANDBOX_LANE ?? "fs-query-index") {
  const lane = LANES[name];
  if (!lane) throw new Error(`unknown sandbox lane ${name}`);
  return lane;
}
