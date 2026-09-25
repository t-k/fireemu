// FS-RULES/refusal-shape, FS-RULES/token-states, FS-RULES/token-expiry, FS-RULES/publication
// and FS-RULES/named-database.

import { allow, create, FRESH, get, runQuery, seedDocs, string } from "./common.mjs";

export const FRAGMENTS = [
  (rulesetId) =>
    [
      // The one rule `alt` changes: `main` allows the owner, `alt` refuses everyone.
      allow("/fsr-pub/{d}", "get", rulesetId === "alt" ? "false" : "request.auth != null"),
      allow("/fsr-pub-open/{d}", "get", "true"),
    ].join("\n"),
];

const OPEN = seedDocs([["fsr-open/d", { n: string("open") }]]);

const BEARERS = [
  ["empty-bearer", { bearer: "empty" }],
  ["malformed-bearer", { bearer: "malformed" }],
  ["basic-scheme", { bearer: "basic" }],
  ["lowercase-scheme", { bearer: "lowercase-scheme", of: "a" }],
  ["tampered-signature", { bearer: "tampered", of: "a" }],
  ["unsigned", { bearer: "unsigned", of: "a" }],
];

const state = (name) => ({ action: "principal", principal: name, spec: { provider: "password" } });

export const PROGRAMS = [
  {
    id: "fs-rules/publication/no-release",
    ruleset: null,
    refresh: FRESH,
    seed: OPEN,
    steps: [
      get("get-unauthenticated", "none", "fsr-open/d"),
      get("get-signed-in", "a", "fsr-open/d"),
      get("get-missing-signed-in", "a", "fsr-open/missing"),
      runQuery("list-signed-in", "a", "fsr-open"),
      create("create-signed-in", "a", "fsr-open/new", { n: string("new") }),
      get("get-signed-in-grpc", "a", "fsr-open/d", { transport: "grpc" }),
      get("get-unauthenticated-grpc", "none", "fsr-open/d", { transport: "grpc" }),
    ],
  },
  {
    id: "fs-rules/refusals/credentials",
    ruleset: "main",
    refresh: FRESH,
    seed: OPEN,
    steps: [
      get("denied-rest", "a", "fsr-null/d"),
      get("denied-grpc", "a", "fsr-null/d", { transport: "grpc" }),
      runQuery("denied-query-rest", "a", "fsr-q"),
      runQuery("denied-query-grpc", "a", "fsr-q", { transport: "grpc" }),
      ...BEARERS.flatMap(([name, as]) => [
        get(`${name}-rest`, as, "fsr-open/d"),
        get(`${name}-grpc`, as, "fsr-open/d", { transport: "grpc" }),
      ]),
      { id: "list-collection-ids-root", as: "a", rpc: "listCollectionIds", body: {} },
      {
        id: "list-collection-ids-document",
        as: "a",
        rpc: "listCollectionIds",
        parent: "fsr-open/d",
        body: {},
      },
      { id: "list-collection-ids-unauthenticated", as: "none", rpc: "listCollectionIds", body: {} },
      {
        id: "list-collection-ids-grpc",
        as: "a",
        rpc: "listCollectionIds",
        transport: "grpc",
        body: {},
      },
      {
        id: "partition-query",
        as: "a",
        rpc: "partitionQuery",
        body: {
          structuredQuery: {
            from: [{ collectionId: "fsr-open", allDescendants: true }],
            orderBy: [{ field: { fieldPath: "__name__" }, direction: "ASCENDING" }],
          },
          partitionCount: 2,
        },
      },
    ],
  },
  {
    id: "fs-rules/token-states/after-account-change",
    ruleset: "main",
    refresh: FRESH,
    seed: OPEN,
    steps: [
      state("revoked"),
      state("disabled"),
      state("deleted"),
      state("kept"),
      ...["revoked", "disabled", "deleted", "kept"].map((name) =>
        get(`${name}-before`, name, "fsr-any/d"),
      ),
      { action: "revoke", principal: "revoked" },
      { action: "disable", principal: "disabled" },
      { action: "delete-account", principal: "deleted" },
      { action: "sleep", ms: 3000 },
      ...["revoked", "disabled", "deleted", "kept"].flatMap((name) => [
        get(`${name}-after-get`, name, "fsr-any/d"),
        get(`${name}-after-get-grpc`, name, "fsr-any/d", { transport: "grpc" }),
        runQuery(`${name}-after-list`, name, "fsr-open"),
        create(`${name}-after-create`, name, `fsr-own/UID(${name})/items/x`, {
          owner: string(`UID(${name})`),
        }),
        get(`${name}-after-auth-null-clause`, name, "fsr-null/d"),
      ]),
      { action: "delete-account", principal: "revoked" },
      { action: "delete-account", principal: "disabled" },
      { action: "delete-account", principal: "kept" },
    ],
  },
  {
    id: "fs-rules/publication/switch",
    ruleset: "alt",
    refresh: FRESH,
    seed: seedDocs([
      ["fsr-pub/d", { n: string("pub") }],
      ["fsr-pub-open/d", { n: string("open") }],
    ]),
    steps: [
      get("alt-refuses-owner", "a", "fsr-pub/d"),
      get("alt-keeps-open", "none", "fsr-pub-open/d"),
      {
        id: "refused-compile",
        compile: "rules_version = '2';\nservice cloud.firestore {\n  allow get: if ;\n}\n",
      },
      get("alt-still-in-force", "a", "fsr-pub/d"),
      { action: "publish", ruleset: "main" },
      get("main-allows-owner", "a", "fsr-pub/d"),
      get("main-keeps-open", "none", "fsr-pub-open/d"),
      { action: "publish", ruleset: null },
      get("deleted-release-refuses-owner", "a", "fsr-pub/d"),
      get("deleted-release-refuses-open", "none", "fsr-pub-open/d"),
      get("deleted-release-refuses-open-grpc", "none", "fsr-pub-open/d", { transport: "grpc" }),
    ],
  },
  {
    id: "fs-rules/named-database/releases",
    ruleset: "main",
    refresh: FRESH,
    databases: ["named", "bare"],
    releases: { named: "named" },
    seed: [
      ...OPEN,
      ...seedDocs(
        [
          ["fsr-open/d", { n: string("named") }],
          ["fsr-named-only/d", { n: string("named") }],
          ["fsr-named-auth/d", { n: string("named") }],
        ],
        "named",
      ),
      ...seedDocs(
        [
          ["fsr-open/d", { n: string("bare") }],
          ["fsr-named-only/d", { n: string("bare") }],
        ],
        "bare",
      ),
    ],
    steps: [
      get("default-open", "a", "fsr-open/d"),
      get("default-named-only", "a", "fsr-named-only/d"),
      get("named-open", "a", "fsr-open/d", { database: "named" }),
      get("named-named-only", "a", "fsr-named-only/d", { database: "named" }),
      get("named-named-only-unauthenticated", "none", "fsr-named-only/d", { database: "named" }),
      get("named-auth-signed-in", "a", "fsr-named-auth/d", { database: "named" }),
      get("named-auth-unauthenticated", "none", "fsr-named-auth/d", { database: "named" }),
      get("bare-open", "a", "fsr-open/d", { database: "bare" }),
      get("bare-named-only", "none", "fsr-named-only/d", { database: "bare" }),
      runQuery("bare-list", "a", "fsr-open", { database: "bare" }),
      get("named-named-only-grpc", "a", "fsr-named-only/d", {
        database: "named",
        transport: "grpc",
      }),
      get("bare-open-grpc", "a", "fsr-open/d", { database: "bare", transport: "grpc" }),
    ],
  },
  {
    // Last: it waits for the `expiring` principal's ID token, which was issued at session start
    // and never refreshed, to pass its exp; fireemu moves its virtual clock instead.
    id: "fs-rules/expiry/around-exp",
    ruleset: "main",
    seed: OPEN,
    // Every row has its own instant; REST and gRPC alternate across neighbouring seconds so each
    // side of Firestore's allowance and of the 300 s Identity Toolkit allows is observed on both
    // transports. Each row is sent 0.3 s after its offset. The second recording bracketed the
    // allowance at (26.3, 30.3] s of token age; the half-second rows from 26.5 to 29.5 close it
    // to a sub-second window (coordinator decision 2026-09-25).
    steps: [
      [-60, "rest"],
      [-59, "grpc"],
      [1, "rest"],
      [2, "grpc"],
      [10, "rest"],
      [11, "grpc"],
      [15, "rest"],
      [16, "grpc"],
      [20, "rest"],
      [21, "grpc"],
      [25, "rest"],
      [26, "grpc"],
      [26.5, "rest"],
      [27, "grpc"],
      [27.5, "rest"],
      [28, "grpc"],
      [28.5, "rest"],
      [29, "grpc"],
      [29.5, "rest"],
      [30, "rest"],
      [31, "grpc"],
      [35, "rest"],
      [36, "grpc"],
      [40, "rest"],
      [41, "grpc"],
      [45, "rest"],
      [46, "grpc"],
      [50, "rest"],
      [51, "grpc"],
      [55, "rest"],
      [56, "grpc"],
      [60, "rest"],
      [61, "grpc"],
      [240, "rest"],
      [241, "grpc"],
      [298, "grpc"],
      [299, "rest"],
      [301, "grpc"],
      [302, "rest"],
      [330, "rest"],
      [331, "grpc"],
      [600, "rest"],
      [601, "grpc"],
    ].map(([offset, transport]) =>
      get(
        `exp-${offset < 0 ? `minus-${-offset}` : `plus-${Math.trunc(offset)}${offset % 1 ? "-half" : ""}`}-${transport}`,
        "expiring",
        "fsr-any/d",
        {
          waitUntil: { principal: "expiring", plus: offset },
          ...(transport === "grpc" ? { transport } : {}),
        },
      ),
    ),
  },
];
