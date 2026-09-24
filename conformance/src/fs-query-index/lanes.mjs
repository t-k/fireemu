// The lanes that share the query sandbox harness. Both record into `fireemu-oracle-query`
// `(default)` with the same indexes; each has its own corpus, fixture, ledger task id and
// comparison. `run.mjs` picks one with FIREEMU_SANDBOX_LANE (default `fs-query-index`).

export const LANES = {
  "fs-query-index": {
    id: "fs-query-index",
    taskId: "FS-QUERY-INDEX-SANDBOX",
    corpus: "./corpus.mjs",
    divergences: "./divergences.mjs",
    fixture: "fs-query-index-production.json",
    indexes: "fs-query-index.indexes.json",
    localConfig: "fs-query-index.fireemu.json",
    sources: ["src/fs-query-index"],
  },
  "fs-data-write-list": {
    id: "fs-data-write-list",
    taskId: "FS-DATA-WRITE-LIST",
    corpus: "../fs-list/corpus.mjs",
    fixture: "fs-data-write-list-production.json",
    indexes: "fs-query-index.indexes.json",
    localConfig: "fs-query-index.fireemu.json",
    sources: ["src/fs-query-index", "src/fs-list"],
  },
};

export function selectLane(name = process.env.FIREEMU_SANDBOX_LANE ?? "fs-query-index") {
  const lane = LANES[name];
  if (!lane) throw new Error(`unknown sandbox lane ${name}`);
  return lane;
}
