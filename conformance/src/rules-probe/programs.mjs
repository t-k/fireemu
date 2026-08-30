// Whole-program probes: the half of the matrix that one expression cannot express.
//
// A claim answers `true` / `false` / `error` about an expression. Runtime errors, document
// access budgets, function recursion and query authorization need a ruleset *and* a request
// -- sometimes a request that writes, or that queries with constraints -- so each program
// here carries its own rules and its own steps, and the recorded value is the HTTP status,
// the canonical error code and the message the side produced.
//
// Seeding runs with `Authorization: Bearer owner`, which bypasses rules on both sides.

const ROOT = "/v1/projects/PROJECT/databases/(default)/documents";

/** `exists()` on `n` distinct documents, which is how a document-access budget is reached. */
const gets = (n) =>
  Array.from({ length: n }, (_, i) => `exists(/databases/$(database)/documents/budget/d${i})`).join(
    " && ",
  );

/** The documents `gets(n)` reads, so that each access succeeds and only the budget can fail. */
const budgetSeed = (n) =>
  Array.from({ length: n }, (_, i) => ({
    path: `${ROOT}/budget/d${i}`,
    fields: { n: { integerValue: String(i) } },
  }));

/** A ruleset with one `match /probe/{id}` block. */
const one = (condition, method = "read") => `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /probe/{id} {
      allow ${method}: if ${condition};
    }
  }
}`;

/** @type {{id: string, area: string, rules: string, steps: object[]}[]} */
export const PROGRAMS = [
  {
    id: "budget-get-10",
    area: "budget",
    rules: one(gets(10)),
    seed: budgetSeed(10),
    steps: [{ id: "read", method: "GET", path: `${ROOT}/probe/x` }],
  },
  {
    id: "budget-get-11",
    area: "budget",
    rules: one(gets(11)),
    seed: budgetSeed(11),
    steps: [{ id: "read", method: "GET", path: `${ROOT}/probe/x` }],
  },
  {
    id: "budget-get-12",
    area: "budget",
    rules: one(gets(12)),
    seed: budgetSeed(12),
    steps: [{ id: "read", method: "GET", path: `${ROOT}/probe/x` }],
  },
  {
    id: "budget-get-21",
    area: "budget",
    rules: one(gets(21)),
    seed: budgetSeed(21),
    steps: [{ id: "read", method: "GET", path: `${ROOT}/probe/x` }],
  },
  {
    // The same path read twice is charged once: a cache, not two accesses.
    id: "budget-get-repeated-path",
    area: "budget",
    rules: one(
      Array.from({ length: 30 }, () => "exists(/databases/$(database)/documents/budget/same)").join(
        " && ",
      ),
    ),
    seed: [{ path: `${ROOT}/budget/same`, fields: { n: { integerValue: "1" } } }],
    steps: [{ id: "read", method: "GET", path: `${ROOT}/probe/x` }],
  },
  {
    // A multi-document write: the budget of a commit is not the budget of a read.
    id: "budget-get-11-in-a-commit",
    area: "budget",
    rules: one(gets(11), "write"),
    seed: budgetSeed(11),
    steps: [
      {
        id: "commit",
        method: "POST",
        path: `${ROOT}:commit`,
        body: {
          writes: [
            {
              update: {
                name: `projects/PROJECT/databases/(default)/documents/probe/a`,
                fields: { n: { integerValue: "1" } },
              },
            },
            {
              update: {
                name: `projects/PROJECT/databases/(default)/documents/probe/b`,
                fields: { n: { integerValue: "2" } },
              },
            },
          ],
        },
      },
    ],
  },
  {
    id: "error-get-of-a-missing-document",
    area: "runtime-error",
    rules: one("get(/databases/$(database)/documents/absent/x).data.n == 1"),
    steps: [{ id: "read", method: "GET", path: `${ROOT}/probe/x` }],
  },
  {
    id: "error-undefined-member",
    area: "runtime-error",
    rules: one("resource.data.missing == 1"),
    steps: [
      { id: "missing-doc", method: "GET", path: `${ROOT}/probe/x` },
      { id: "present-doc", method: "GET", path: `${ROOT}/probe/seeded` },
    ],
    seed: [{ path: `${ROOT}/probe/seeded`, fields: { n: { integerValue: "1" } } }],
  },
  {
    id: "error-null-resource-on-a-missing-document",
    area: "runtime-error",
    rules: one("resource.data.n == 1"),
    steps: [{ id: "read", method: "GET", path: `${ROOT}/probe/x` }],
  },
  {
    id: "recursion-self-call",
    area: "recursion",
    rules: `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    function loop(n) {
      return n <= 0 ? true : loop(n - 1);
    }
    match /probe/{id} {
      allow read: if loop(3);
    }
  }
}`,
    steps: [{ id: "read", method: "GET", path: `${ROOT}/probe/x` }],
  },
  {
    id: "recursion-depth-chain",
    area: "recursion",
    rules: `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    ${Array.from({ length: 21 }, (_, i) => `function f${i}() { return ${i === 20 ? "true" : `f${i + 1}()`}; }`).join("\n    ")}
    match /probe/{id} {
      allow read: if f0();
    }
  }
}`,
    steps: [{ id: "read", method: "GET", path: `${ROOT}/probe/x` }],
  },
  {
    // f0 calls f1 ... f21 calls true: 22 frames, 21 calls. One deeper than the chain above,
    // which is how the exact boundary of "Maximum allowed call depth" is found.
    id: "recursion-depth-chain-21-calls",
    area: "recursion",
    rules: `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    ${Array.from({ length: 22 }, (_, i) => `function h${i}() { return ${i === 21 ? "true" : `h${i + 1}()`}; }`).join("\n    ")}
    match /probe/{id} {
      allow read: if h0();
    }
  }
}`,
    steps: [{ id: "read", method: "GET", path: `${ROOT}/probe/x` }],
  },
  {
    // What `request.query.orderBy` actually is, given a query ordered by `n` ascending.
    id: "query-order-by-shape",
    area: "query",
    rules: `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /o1/{id} { allow list: if request.query.orderBy.keys() == ['n']; }
    match /o2/{id} { allow list: if request.query.orderBy['n'] == 'ASC'; }
    match /o3/{id} { allow list: if request.query.orderBy['n'] == 'ASCENDING'; }
    match /o4/{id} { allow list: if request.query.orderBy.size() == 1; }
    match /o5/{id} { allow list: if request.query.orderBy['n'] is string; }
    match /o6/{id} { allow list: if request.query.orderBy['n'] is bool; }
  }
}`,
    steps: [1, 2, 3, 4, 5, 6].map((i) => ({
      id: `o${i}`,
      method: "POST",
      path: `${ROOT}:runQuery`,
      body: {
        structuredQuery: {
          from: [{ collectionId: `o${i}` }],
          orderBy: [{ field: { fieldPath: "n" }, direction: "ASCENDING" }],
        },
      },
    })),
  },
  {
    id: "recursion-depth-chain-60",
    area: "recursion",
    rules: `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    ${Array.from({ length: 61 }, (_, i) => `function g${i}() { return ${i === 60 ? "true" : `g${i + 1}()`}; }`).join("\n    ")}
    match /probe/{id} {
      allow read: if g0();
    }
  }
}`,
    steps: [{ id: "read", method: "GET", path: `${ROOT}/probe/x` }],
  },
  {
    // What `request.query` actually holds during a `list`, one collection per claim.
    id: "query-shape",
    area: "query",
    rules: `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /q1/{id} { allow list: if request.query.orderBy is list; }
    match /q2/{id} { allow list: if request.query.keys().hasAll(['limit', 'offset', 'orderBy']); }
    match /q3/{id} { allow list: if request.query.limit == null; }
    match /q4/{id} { allow list: if request.query.offset == 0; }
    match /q5/{id} { allow list: if request.query.orderBy is map; }
    match /q6/{id} { allow list: if request.query.orderBy == null; }
  }
}`,
    steps: [1, 2, 3, 4, 5, 6].map((i) => ({
      id: `q${i}`,
      method: "POST",
      path: `${ROOT}:runQuery`,
      body: {
        structuredQuery: {
          from: [{ collectionId: `q${i}` }],
          orderBy: [{ field: { fieldPath: "n" }, direction: "ASCENDING" }],
        },
      },
    })),
  },
  {
    id: "getafter-without-the-other-write",
    area: "atomic-write",
    rules: `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /probe/{id} {
      allow write: if getAfter(/databases/$(database)/documents/probe/mirror).data.n == 7;
    }
  }
}`,
    steps: [
      {
        id: "mirror-never-written",
        method: "POST",
        path: `${ROOT}:commit`,
        body: {
          writes: [
            {
              update: {
                name: `projects/PROJECT/databases/(default)/documents/probe/b`,
                fields: { n: { integerValue: "1" } },
              },
            },
          ],
        },
      },
    ],
  },
  {
    id: "query-limit",
    area: "query",
    rules: one("request.query.limit <= 10", "list"),
    steps: [
      {
        id: "limit-5",
        method: "POST",
        path: `${ROOT}:runQuery`,
        body: { structuredQuery: { from: [{ collectionId: "probe" }], limit: 5 } },
      },
      {
        id: "limit-50",
        method: "POST",
        path: `${ROOT}:runQuery`,
        body: { structuredQuery: { from: [{ collectionId: "probe" }], limit: 50 } },
      },
      {
        id: "no-limit",
        method: "POST",
        path: `${ROOT}:runQuery`,
        body: { structuredQuery: { from: [{ collectionId: "probe" }] } },
      },
    ],
  },
  {
    id: "query-order-by",
    area: "query",
    rules: one("request.query.orderBy == 'n ASC'", "list"),
    steps: [
      {
        id: "ordered",
        method: "POST",
        path: `${ROOT}:runQuery`,
        body: {
          structuredQuery: {
            from: [{ collectionId: "probe" }],
            orderBy: [{ field: { fieldPath: "n" }, direction: "ASCENDING" }],
          },
        },
      },
      {
        id: "unordered",
        method: "POST",
        path: `${ROOT}:runQuery`,
        body: { structuredQuery: { from: [{ collectionId: "probe" }] } },
      },
    ],
  },
  {
    id: "query-resource-proof",
    area: "query",
    rules: one("resource.data.owner == 'alice'", "list"),
    seed: [
      {
        path: `${ROOT}/probe/a`,
        fields: { owner: { stringValue: "alice" }, n: { integerValue: "1" } },
      },
      {
        path: `${ROOT}/probe/b`,
        fields: { owner: { stringValue: "bob" }, n: { integerValue: "2" } },
      },
    ],
    steps: [
      {
        id: "constrained",
        method: "POST",
        path: `${ROOT}:runQuery`,
        body: {
          structuredQuery: {
            from: [{ collectionId: "probe" }],
            where: {
              fieldFilter: {
                field: { fieldPath: "owner" },
                op: "EQUAL",
                value: { stringValue: "alice" },
              },
            },
          },
        },
      },
      {
        id: "unconstrained",
        method: "POST",
        path: `${ROOT}:runQuery`,
        body: { structuredQuery: { from: [{ collectionId: "probe" }] } },
      },
      {
        id: "wrongly-constrained",
        method: "POST",
        path: `${ROOT}:runQuery`,
        body: {
          structuredQuery: {
            from: [{ collectionId: "probe" }],
            where: {
              fieldFilter: {
                field: { fieldPath: "owner" },
                op: "EQUAL",
                value: { stringValue: "bob" },
              },
            },
          },
        },
      },
    ],
  },
  {
    id: "query-single-get-is-not-a-list",
    area: "query",
    rules: one("request.query.limit <= 10", "read"),
    seed: [{ path: `${ROOT}/probe/x`, fields: { n: { integerValue: "1" } } }],
    steps: [{ id: "get", method: "GET", path: `${ROOT}/probe/x` }],
  },
  {
    id: "getafter-in-a-commit",
    area: "atomic-write",
    rules: `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /probe/{id} {
      allow write: if getAfter(/databases/$(database)/documents/probe/mirror).data.n == 7;
    }
    match /probe/mirror {
      allow write: if true;
    }
  }
}`,
    steps: [
      {
        id: "both-written",
        method: "POST",
        path: `${ROOT}:commit`,
        body: {
          writes: [
            {
              update: {
                name: `projects/PROJECT/databases/(default)/documents/probe/a`,
                fields: { n: { integerValue: "1" } },
              },
            },
            {
              update: {
                name: `projects/PROJECT/databases/(default)/documents/probe/mirror`,
                fields: { n: { integerValue: "7" } },
              },
            },
          ],
        },
      },
      {
        id: "mirror-missing",
        method: "POST",
        path: `${ROOT}:commit`,
        body: {
          writes: [
            {
              update: {
                name: `projects/PROJECT/databases/(default)/documents/probe/b`,
                fields: { n: { integerValue: "1" } },
              },
            },
          ],
        },
      },
    ],
  },
  {
    id: "create-update-delete-methods",
    area: "methods",
    rules: `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /probe/{id} {
      allow create: if request.resource.data.n == 1;
      allow update: if resource.data.n == 1 && request.resource.data.n == 2;
      allow delete: if false;
      allow get: if true;
    }
  }
}`,
    steps: [
      {
        id: "create-ok",
        method: "PATCH",
        path: `${ROOT}/probe/m`,
        body: { fields: { n: { integerValue: "1" } } },
      },
      {
        id: "update-ok",
        method: "PATCH",
        path: `${ROOT}/probe/m`,
        body: { fields: { n: { integerValue: "2" } } },
      },
      {
        id: "update-again-denied",
        method: "PATCH",
        path: `${ROOT}/probe/m`,
        body: { fields: { n: { integerValue: "2" } } },
      },
      { id: "delete-denied", method: "DELETE", path: `${ROOT}/probe/m` },
    ],
  },
];
