// The cases of the Node SDK recording (FS-LISTEN-SDK packet L1): the 15 retained cases of the
// shared 18-case catalog, migrated to the collections the deployed Rules already allow (public
// `conf_listen/{id}` and owner-only `conf_rules_owner/{uid}`, OL-3), and three that the closure
// names beyond the catalog: limitToLast (103L), one transaction commit against separate commits
// (103T) and a document that leaves the query while the client is offline (111).

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

/** The catalog cases that belong to AUTH-FS-CROSS (movedCatalogCases of the closure). */
export const MOVED_CASES = new Set([
  "FS-LISTEN-SDK-106",
  "FS-LISTEN-SDK-109",
  "FS-LISTEN-SDK-109C",
]);

export { OWNER_COLLECTION, PUBLIC_COLLECTION } from "./sdk-deps-core.mjs";

const CATALOG = fileURLToPath(
  new URL("../../../spec/compatibility/fs-listen-sdk-cases.json", import.meta.url),
);

const queryListener = (extra = {}) => ({
  includeMetadataChanges: true,
  kind: "query",
  limit: 10,
  metadataIsCompared: false,
  name: "primary",
  orderBy: ["rank", "asc"],
  target: "docs",
  where: ["rank", "<", 10],
  ...extra,
});

const COMPARED = ["listener", "snapshotKind", "changes", "docs", "exists", "error"];

const base = {
  collapseMetadataOnly: true,
  comparedFields: COMPARED,
  comparison: "ordered-events",
  controlFor: null,
  discriminators: [],
  expectedLocal: [],
  ignoreCachedPrefix: false,
  invariants: [],
  requiresAuth: false,
  requiresRules: false,
};

/** The three cases the closure names beyond the catalog. */
export const EXTRA_CASES = [
  {
    ...base,
    caseId: "FS-LISTEN-SDK-103L",
    dimension: "query-change-order",
    role: "observation",
    title: "A limitToLast query reverses its window and reports indexes after a bounded update",
    documents: ["alpha", "beta", "gamma", "delta"],
    listeners: [queryListener({ limit: 2, limitToLast: true })],
    steps: [
      { kind: "seed", doc: "alpha", fields: { rank: 1, value: "a0" } },
      { kind: "seed", doc: "beta", fields: { rank: 2, value: "b0" } },
      { kind: "seed", doc: "gamma", fields: { rank: 3, value: "g0" } },
      { kind: "listen", listener: "primary" },
      { kind: "awaitServer", listener: "primary" },
      { kind: "baseline" },
      { kind: "write", client: "witness", doc: "beta", fields: { rank: 4, value: "b1" } },
      { kind: "await", listener: "primary", events: 1 },
      { kind: "write", client: "witness", doc: "delta", fields: { rank: 6, value: "d0" } },
      { kind: "await", listener: "primary", events: 2 },
    ],
  },
  {
    ...base,
    caseId: "FS-LISTEN-SDK-103T",
    dimension: "query-change-order",
    role: "observation",
    title: "One transaction commit of two documents is one callback; separate commits are one each",
    documents: ["alpha", "beta", "gamma", "delta"],
    collapseMetadataOnly: false,
    listeners: [queryListener({ includeMetadataChanges: false })],
    steps: [
      { kind: "listen", listener: "primary" },
      // Without metadata changes a server-confirmed empty result raises no callback to wait for.
      { kind: "settle", listener: "primary", seconds: 4 },
      { kind: "baseline" },
      // `__txn` marks writes the adapter commits together in one runTransaction.
      {
        kind: "write",
        client: "witness",
        doc: "alpha",
        fields: { rank: 1, value: "a0", __txn: { id: "t1", size: 2 } },
      },
      {
        kind: "write",
        client: "witness",
        doc: "beta",
        fields: { rank: 2, value: "b0", __txn: { id: "t1", size: 2 } },
      },
      { kind: "settle", listener: "primary", seconds: 3 },
      { kind: "write", client: "witness", doc: "gamma", fields: { rank: 3, value: "g0" } },
      { kind: "settle", listener: "primary", seconds: 2 },
      { kind: "write", client: "witness", doc: "delta", fields: { rank: 4, value: "d0" } },
      { kind: "settle", listener: "primary", seconds: 3 },
    ],
  },
  {
    ...base,
    caseId: "FS-LISTEN-SDK-111",
    dimension: "existence-filter",
    role: "observation",
    title:
      "A document deleted and one moved out of the query while offline are gone after reconnecting",
    documents: ["alpha", "beta", "gamma"],
    comparison: "aggregate-changes",
    comparedFields: ["listener", "snapshotKind", "changes", "docs", "exists", "error"],
    invariants: ["from-cache-true-then-false-across-break"],
    listeners: [queryListener({ metadataIsCompared: true })],
    steps: [
      { kind: "seed", doc: "alpha", fields: { rank: 1, value: "a0" } },
      { kind: "seed", doc: "beta", fields: { rank: 2, value: "b0" } },
      { kind: "seed", doc: "gamma", fields: { rank: 3, value: "g0" } },
      { kind: "listen", listener: "primary" },
      { kind: "awaitServer", listener: "primary" },
      { kind: "baseline" },
      { kind: "break", client: "primary", mode: "disable-network" },
      { kind: "delete", client: "witness", doc: "beta" },
      { kind: "write", client: "witness", doc: "gamma", fields: { rank: 99, value: "g1" } },
      { kind: "resume", client: "primary", mode: "enable-network" },
      { kind: "settle", listener: "primary", seconds: 5 },
    ],
  },
];

/** The retained catalog cases, then the extras; the cases that sign in (108, 108C) come last. */
export function sdkCases(catalog = JSON.parse(readFileSync(CATALOG, "utf8"))) {
  const kept = catalog.cases.filter((c) => !MOVED_CASES.has(c.caseId));
  const needsAccount = (c) => c.steps.some((s) => s.kind === "signIn") || c.requiresRules;
  // 106N needs the primary client signed out: it never signs in, so it keeps its place.
  const early = kept.filter((c) => c.caseId === "FS-LISTEN-SDK-106N" || !needsAccount(c));
  const late = kept.filter((c) => !early.includes(c));
  return [...early, ...EXTRA_CASES, ...late];
}
