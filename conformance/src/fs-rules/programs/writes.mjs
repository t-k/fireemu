// FS-RULES/request-resource, FS-RULES/document-access and FS-RULES/atomic-writes.
//
// Every case is a literal document path with its own rule, written or read by principal `a`.
// Each positive case has a negative control that differs in one value.

import {
  allow,
  commit,
  create,
  FRESH,
  get,
  integer,
  remove,
  seedDocs,
  string,
  update,
} from "./common.mjs";

const DB = "/databases/$(database)/documents";
const R = "request.resource";

/** `[case, method, predicate]` on `/fsr-res/<case>`. */
const RESOURCE_CASES = [
  [
    "create-shape",
    "create",
    `${R}.data.keys().hasOnly(['n', 's']) && ${R}.data.n is int && ${R}.data.s is string`,
  ],
  ["create-resource-null", "create", "resource == null"],
  ["create-id", "create", `${R}.id == 'create-id'`],
  [
    "create-name",
    "create",
    `${R}.__name__ == path('${DB.replace("$(database)", "' + database + '")}/fsr-res/create-name')`,
  ],
  ["create-name-path", "create", `${R}.__name__ == ${DB}/fsr-res/create-name-path`],
  ["create-method", "create", "request.method == 'create'"],
  ["create-request-path", "create", `request.path == ${DB}/fsr-res/create-request-path`],
  ["create-time-is-request-time", "create", `${R}.data.t == request.time`],
  ["create-time-type", "create", "request.time is timestamp"],
  ["create-size", "create", `${R}.data.size() == 2`],
  ["update-merged", "update", `${R}.data.a == 1 && ${R}.data.b == 2`],
  ["update-resource", "update", "resource.data.a == 1 && resource.data.keys().hasOnly(['a'])"],
  ["update-diff", "update", `${R}.data.diff(resource.data).affectedKeys().hasOnly(['b'])`],
  ["update-diff-changed", "update", `${R}.data.diff(resource.data).changedKeys().size() == 1`],
  ["update-method", "update", "request.method == 'update'"],
  ["update-set-replaces", "update", `${R}.data.keys().hasOnly(['b'])`],
  ["update-increment", "update", `${R}.data.a == resource.data.a + 5`],
  ["update-server-time", "update", `${R}.data.t == request.time`],
  ["update-array-union", "update", `${R}.data.list == ['x', 'y']`],
  ["update-remove-field", "update", `!('a' in ${R}.data)`],
  ["delete-resource", "delete", "resource.data.a == 1"],
  ["delete-missing", "delete", "resource == null"],
  ["delete-method", "delete", "request.method == 'delete'"],
  ["delete-no-request-resource", "delete", `${R} == null`],
  ["get-resource", "get", "resource.data.a == 1"],
  ["get-missing-resource-null", "get", "resource == null"],
  ["get-method", "get", "request.method == 'get'"],
  ["get-resource-id", "get", "resource.id == 'get-resource-id'"],
  ["get-name-type", "get", "resource.__name__ is path"],
];

const ACCESS_CASES = [
  ["get-present", "get", `get(${DB}/fsr-acc-src/present).data.n == 1`],
  ["get-missing", "get", `get(${DB}/fsr-acc-src/missing).data.n == 1`],
  ["get-missing-is-null", "get", `get(${DB}/fsr-acc-src/missing) == null`],
  ["exists-present", "get", `exists(${DB}/fsr-acc-src/present)`],
  ["exists-missing", "get", `!exists(${DB}/fsr-acc-src/missing)`],
  [
    "get-string-path",
    "get",
    `get(path('/databases/' + database + '/documents/fsr-acc-src/present')).data.n == 1`,
  ],
  ["get-id", "get", `get(${DB}/fsr-acc-src/present).id == 'present'`],
  ["get-after-in-read", "get", `getAfter(${DB}/fsr-acc-src/present).data.n == 1`],
  ["exists-after-in-read", "get", `existsAfter(${DB}/fsr-acc-src/present)`],
  ["write-exists", "create", `exists(${DB}/fsr-acc-src/present)`],
  [
    "write-get-after-partner",
    "create",
    `getAfter(${DB}/fsr-acc-partner/p1).data.owner == request.auth.uid`,
  ],
  [
    "write-get-before-partner",
    "create",
    `get(${DB}/fsr-acc-partner/p2).data.owner == request.auth.uid`,
  ],
  ["write-exists-after-partner", "create", `existsAfter(${DB}/fsr-acc-partner/p3)`],
  ["write-exists-after-deleted", "create", `!existsAfter(${DB}/fsr-acc-src/doomed)`],
  ["write-exists-before-deleted", "create", `exists(${DB}/fsr-acc-src/doomed)`],
  ["write-get-after-self", "create", `getAfter(${DB}/fsr-acc/write-get-after-self).data.n == 7`],
  ["write-get-after-updated", "create", `getAfter(${DB}/fsr-acc-src/present).data.n == 2`],
  ["write-get-before-updated", "create", `get(${DB}/fsr-acc-src/present).data.n == 1`],
];

/**
 * Negative controls and alternative routes on paths of their own, under the rule of the case
 * they test, so a control is refused by the predicate and not because an earlier row created
 * or changed its document.
 */
const RESOURCE_ALIASES = {
  "create-shape-ctl": "create-shape",
  "create-shape-by-create": "create-shape",
  "create-time-ctl": "create-time-is-request-time",
  "create-size-ctl": "create-size",
  "create-method-by-patch": "create-method",
  "update-diff-changed-same": "update-diff-changed",
};
const ACCESS_ALIASES = {
  "write-get-after-partner-ctl": "write-get-after-partner",
  "write-exists-after-partner-ctl": "write-exists-after-partner",
  "write-get-after-self-ctl": "write-get-after-self",
};

const withAliases = (cases, aliases) => [
  ...cases,
  ...Object.entries(aliases).map(([alias, name]) => {
    const [, method, predicate] = cases.find(([n]) => n === name);
    return [alias, method, predicate];
  }),
];

export const FRAGMENTS = [
  [
    ...withAliases(RESOURCE_CASES, RESOURCE_ALIASES).map(([name, method, predicate]) =>
      allow(`/fsr-res/${name}`, method, predicate),
    ),
    ...withAliases(ACCESS_CASES, ACCESS_ALIASES).map(([name, method, predicate]) =>
      allow(`/fsr-acc/${name}`, method, predicate),
    ),
    allow("/fsr-res/update-merged", "get", "true"),
    allow("/fsr-acc-partner/{d}", "create", `${R}.data.owner == request.auth.uid`),
    allow("/fsr-acc-src/{d}", "update, delete", "request.auth != null"),
    allow(
      "/fsr-at/{d}",
      "get, update",
      "request.auth != null && resource.data.owner == request.auth.uid",
    ),
    allow("/fsr-at/{d}", "create", `request.auth != null && ${R}.data.owner == request.auth.uid`),
  ].join("\n"),
];

const serverTime = (field) => ({ fieldPath: field, setToServerValue: "REQUEST_TIME" });

export const PROGRAMS = [
  {
    id: "fs-rules/request-resource/writes",
    ruleset: "main",
    refresh: FRESH,
    seed: seedDocs(
      [
        "update-merged",
        "update-resource",
        "update-diff",
        "update-diff-changed",
        "update-diff-changed-same",
        "update-method",
        "update-set-replaces",
        "update-increment",
        "update-server-time",
        "update-array-union",
        "update-remove-field",
        "delete-resource",
        "delete-method",
        "delete-no-request-resource",
        "get-resource",
        "get-method",
        "get-resource-id",
        "get-name-type",
      ].map((name) => [`fsr-res/${name}`, { a: integer(1) }]),
    ),
    steps: [
      create("create-shape", "a", "fsr-res/create-shape", { n: integer(1), s: string("x") }),
      create("create-shape-control", "a", "fsr-res/create-shape-ctl", {
        n: string("1"),
        s: string("x"),
      }),
      create("create-resource-null", "a", "fsr-res/create-resource-null", { n: integer(1) }),
      create("create-id", "a", "fsr-res/create-id", {}),
      create("create-name", "a", "fsr-res/create-name", {}),
      create("create-name-path", "a", "fsr-res/create-name-path", {}),
      create("create-method", "a", "fsr-res/create-method", {}),
      create("create-request-path", "a", "fsr-res/create-request-path", {}),
      commit("create-time-is-request-time", "a", [
        {
          update: { name: "{docs}/fsr-res/create-time-is-request-time", fields: {} },
          updateTransforms: [serverTime("t")],
          currentDocument: { exists: false },
        },
      ]),
      create("create-time-is-request-time-control", "a", "fsr-res/create-time-ctl", {
        t: { timestampValue: "2020-01-01T00:00:00Z" },
      }),
      create("create-time-type", "a", "fsr-res/create-time-type", {}),
      create("create-size", "a", "fsr-res/create-size", { x: integer(1), y: integer(2) }),
      create("create-size-control", "a", "fsr-res/create-size-ctl", { x: integer(1) }),
      {
        id: "create-by-patch-precondition",
        as: "a",
        rpc: "patch",
        doc: "fsr-res/create-method-by-patch",
        params: { "currentDocument.exists": false },
        body: { fields: {} },
      },
      {
        id: "create-by-create-document",
        as: "a",
        rpc: "create",
        collection: "fsr-res",
        params: { documentId: "create-shape-by-create" },
        body: { fields: { n: integer(2), s: string("y") } },
      },
      commit("update-merged", "a", [update("fsr-res/update-merged", { b: integer(2) }, ["b"])]),
      commit("update-merged-control", "a", [
        update("fsr-res/update-merged", { b: integer(3) }, ["b"]),
      ]),
      {
        id: "update-merged-by-patch",
        as: "a",
        rpc: "patch",
        doc: "fsr-res/update-merged",
        params: { "updateMask.fieldPaths": "b" },
        body: { fields: { b: integer(2) } },
      },
      commit("update-resource", "a", [update("fsr-res/update-resource", { b: integer(2) }, ["b"])]),
      commit("update-diff", "a", [update("fsr-res/update-diff", { b: integer(2) }, ["b"])]),
      commit("update-diff-control", "a", [
        update("fsr-res/update-diff", { a: integer(9), b: integer(2) }, ["a", "b"]),
      ]),
      commit("update-diff-changed", "a", [
        update("fsr-res/update-diff-changed", { a: integer(2) }, ["a"]),
      ]),
      commit("update-diff-changed-same-value", "a", [
        update("fsr-res/update-diff-changed-same", { a: integer(1) }, ["a"]),
      ]),
      commit("update-method", "a", [update("fsr-res/update-method", { a: integer(1) })]),
      commit("update-set-replaces", "a", [
        update("fsr-res/update-set-replaces", { b: integer(2) }),
      ]),
      commit("update-increment", "a", [
        {
          transform: {
            document: "{docs}/fsr-res/update-increment",
            fieldTransforms: [{ fieldPath: "a", increment: integer(5) }],
          },
        },
      ]),
      commit("update-increment-mixed-double", "a", [
        {
          transform: {
            document: "{docs}/fsr-res/update-increment",
            fieldTransforms: [{ fieldPath: "a", increment: { doubleValue: 5 } }],
          },
        },
      ]),
      commit("update-server-time", "a", [
        {
          update: { name: "{docs}/fsr-res/update-server-time", fields: {} },
          updateMask: { fieldPaths: [] },
          updateTransforms: [serverTime("t")],
        },
      ]),
      commit("update-array-union", "a", [
        {
          transform: {
            document: "{docs}/fsr-res/update-array-union",
            fieldTransforms: [
              { fieldPath: "list", appendMissingElements: { values: [string("x"), string("y")] } },
            ],
          },
        },
      ]),
      commit("update-remove-field", "a", [update("fsr-res/update-remove-field", {}, ["a"])]),
      commit("update-missing-document", "a", [
        {
          update: { name: "{docs}/fsr-res/update-method-missing", fields: { a: integer(1) } },
          currentDocument: { exists: true },
        },
      ]),
      commit("delete-resource", "a", [remove("fsr-res/delete-resource")]),
      commit("delete-missing", "a", [remove("fsr-res/delete-missing")]),
      commit("delete-method", "a", [remove("fsr-res/delete-method")]),
      commit("delete-no-request-resource", "a", [remove("fsr-res/delete-no-request-resource")]),
      { id: "delete-by-rest-delete", as: "a", rpc: "delete", doc: "fsr-res/delete-resource" },
      get("get-resource", "a", "fsr-res/get-resource"),
      get("get-missing-resource-null", "a", "fsr-res/get-missing-resource-null"),
      get("get-method", "a", "fsr-res/get-method"),
      get("get-resource-id", "a", "fsr-res/get-resource-id"),
      get("get-name-type", "a", "fsr-res/get-name-type"),
      get("get-resource-grpc", "a", "fsr-res/get-resource", { transport: "grpc" }),
      commit(
        "update-merged-grpc",
        "a",
        [update("fsr-res/update-merged", { b: integer(2) }, ["b"])],
        {
          transport: "grpc",
        },
      ),
      get("post-state-update-merged", "a", "fsr-res/update-merged"),
    ],
  },
  {
    id: "fs-rules/document-access/reads-and-writes",
    ruleset: "main",
    refresh: FRESH,
    seed: seedDocs([
      ["fsr-acc-src/present", { n: integer(1) }],
      ["fsr-acc-src/doomed", { n: integer(1) }],
      ["fsr-acc-partner/p2", { owner: string("UID(a)") }],
    ]),
    steps: [
      ...ACCESS_CASES.filter(([, method]) => method === "get").map(([name]) =>
        get(name, "a", `fsr-acc/${name}`),
      ),
      create("write-exists", "a", "fsr-acc/write-exists", {}),
      commit("write-get-after-partner", "a", [
        {
          update: { name: "{docs}/fsr-acc/write-get-after-partner", fields: {} },
          currentDocument: { exists: false },
        },
        {
          update: { name: "{docs}/fsr-acc-partner/p1", fields: { owner: string("UID(a)") } },
          currentDocument: { exists: false },
        },
      ]),
      create("write-get-after-partner-missing", "a", "fsr-acc/write-get-after-partner-ctl", {}),
      commit("write-get-before-partner-new", "a", [
        {
          update: { name: "{docs}/fsr-acc/write-get-before-partner", fields: {} },
          currentDocument: { exists: false },
        },
        {
          update: { name: "{docs}/fsr-acc-partner/p4", fields: { owner: string("UID(a)") } },
          currentDocument: { exists: false },
        },
      ]),
      create("write-get-before-partner-existing", "a", "fsr-acc/write-get-before-partner", {}),
      commit("write-exists-after-partner", "a", [
        {
          update: { name: "{docs}/fsr-acc/write-exists-after-partner", fields: {} },
          currentDocument: { exists: false },
        },
        {
          update: { name: "{docs}/fsr-acc-partner/p3", fields: { owner: string("UID(a)") } },
          currentDocument: { exists: false },
        },
      ]),
      create(
        "write-exists-after-partner-missing",
        "a",
        "fsr-acc/write-exists-after-partner-ctl",
        {},
      ),
      commit("write-exists-after-deleted", "a", [
        {
          update: { name: "{docs}/fsr-acc/write-exists-after-deleted", fields: {} },
          currentDocument: { exists: false },
        },
        remove("fsr-acc-src/doomed"),
      ]),
      create("write-exists-before-deleted", "a", "fsr-acc/write-exists-before-deleted", {}),
      create("write-get-after-self", "a", "fsr-acc/write-get-after-self", { n: integer(7) }),
      create("write-get-after-self-control", "a", "fsr-acc/write-get-after-self-ctl", {
        n: integer(8),
      }),
      commit("write-get-after-updated", "a", [
        {
          update: { name: "{docs}/fsr-acc/write-get-after-updated", fields: {} },
          currentDocument: { exists: false },
        },
        update("fsr-acc-src/present", { n: integer(2) }),
      ]),
      commit("write-get-before-updated", "a", [
        {
          update: { name: "{docs}/fsr-acc/write-get-before-updated", fields: {} },
          currentDocument: { exists: false },
        },
        update("fsr-acc-src/present", { n: integer(3) }),
      ]),
      get("get-present-grpc", "a", "fsr-acc/get-present", { transport: "grpc" }),
      get("get-missing-grpc", "a", "fsr-acc/get-missing", { transport: "grpc" }),
    ],
  },
  {
    id: "fs-rules/document-access/transaction",
    ruleset: "main",
    refresh: FRESH,
    seed: seedDocs([["fsr-acc-src/present", { n: integer(1) }]]),
    steps: [
      { id: "begin", as: "a", rpc: "beginTransaction", body: {} },
      get("read-in-transaction", "a", "fsr-acc/get-present", {
        params: { transaction: { $from: "begin", path: "transaction" } },
      }),
      commit("commit-get-after", "a", [
        {
          update: { name: "{docs}/fsr-acc/write-get-after-partner", fields: {} },
          currentDocument: { exists: false },
        },
        {
          update: { name: "{docs}/fsr-acc-partner/p1", fields: { owner: string("UID(a)") } },
          currentDocument: { exists: false },
        },
      ]),
      { id: "begin-denied", as: "a", rpc: "beginTransaction", body: {} },
      commit("commit-denied-write", "a", [update("fsr-acc-src/other", { n: integer(1) })]),
      { id: "begin-unauthenticated", as: "none", rpc: "beginTransaction", body: {} },
    ],
  },
  {
    id: "fs-rules/atomic/commit-and-batch-write",
    ruleset: "main",
    refresh: FRESH,
    seed: seedDocs([
      ["fsr-at/x", { owner: string("UID(a)"), n: integer(1) }],
      ["fsr-at/y", { owner: string("UID(b)"), n: integer(1) }],
      ["fsr-at/z", { owner: string("UID(a)"), n: integer(1) }],
    ]),
    steps: [
      commit("commit-one-denied", "a", [
        update("fsr-at/x", { owner: string("UID(a)"), n: integer(2) }),
        update("fsr-at/y", { owner: string("UID(b)"), n: integer(2) }),
      ]),
      get("commit-post-state", "a", "fsr-at/x"),
      commit("commit-denied-create", "a", [
        update("fsr-at/x", { owner: string("UID(a)"), n: integer(3) }),
        {
          update: { name: "{docs}/fsr-at/new-by-b", fields: { owner: string("UID(b)") } },
          currentDocument: { exists: false },
        },
      ]),
      get("commit-denied-create-post-state", "a", "fsr-at/x"),
      commit("commit-two-allowed", "a", [
        update("fsr-at/x", { owner: string("UID(a)"), n: integer(4) }),
        update("fsr-at/z", { owner: string("UID(a)"), n: integer(4) }),
      ]),
      get("commit-two-allowed-post-state", "a", "fsr-at/z"),
      commit("commit-same-document-twice", "a", [
        update("fsr-at/x", { owner: string("UID(a)"), n: integer(5) }),
        update("fsr-at/x", { owner: string("UID(a)"), n: integer(6) }),
      ]),
      {
        id: "batch-write-mixed",
        as: "a",
        rpc: "batchWrite",
        body: {
          writes: [
            update("fsr-at/z", { owner: string("UID(a)"), n: integer(7) }),
            update("fsr-at/y", { owner: string("UID(b)"), n: integer(7) }),
          ],
        },
      },
      get("batch-write-post-state-allowed", "a", "fsr-at/z"),
      { id: "begin", as: "a", rpc: "beginTransaction", body: {} },
      commit("transaction-one-denied", "a", [
        update("fsr-at/z", { owner: string("UID(a)"), n: integer(8) }),
        update("fsr-at/y", { owner: string("UID(b)"), n: integer(8) }),
      ]),
      get("transaction-post-state", "a", "fsr-at/z"),
      commit(
        "commit-one-denied-grpc",
        "a",
        [
          update("fsr-at/x", { owner: string("UID(a)"), n: integer(9) }),
          update("fsr-at/y", { owner: string("UID(b)"), n: integer(9) }),
        ],
        { transport: "grpc" },
      ),
      {
        id: "batch-write-mixed-grpc",
        as: "a",
        rpc: "batchWrite",
        transport: "grpc",
        body: {
          writes: [
            update("fsr-at/z", { owner: string("UID(a)"), n: integer(10) }),
            update("fsr-at/y", { owner: string("UID(b)"), n: integer(10) }),
          ],
        },
      },
      get("final-post-state", "a", "fsr-at/z"),
      get("masked-get", "a", "fsr-at/x", { params: { "mask.fieldPaths": "n" } }),
    ],
  },
];

// Transactions: the commit rows of the transaction programs carry the transaction id.
for (const program of PROGRAMS) {
  for (const step of program.steps) {
    if (step.id === "commit-get-after" || step.id === "transaction-one-denied") {
      step.body = { ...step.body, transaction: { $from: "begin", path: "transaction" } };
    }
    if (step.id === "commit-denied-write") {
      step.body = { ...step.body, transaction: { $from: "begin-denied", path: "transaction" } };
    }
  }
}
