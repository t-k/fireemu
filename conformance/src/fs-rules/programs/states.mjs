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
    steps: [-60, 1, 10, 60, 240, 299, 301, 330, 600].flatMap((offset) => {
      const tag = offset < 0 ? `minus-${-offset}` : `plus-${offset}`;
      return [
        get(`exp-${tag}`, "expiring", "fsr-any/d", {
          waitUntil: { principal: "expiring", plus: offset },
        }),
        get(`exp-${tag}-grpc`, "expiring", "fsr-any/d", { transport: "grpc" }),
      ];
    }),
  },
];
