// AUTH-FS-CROSS stage 1: the unary conditions (tenant-same-uid, read-only-transaction-binding,
// foreign-project-token). Steps use the FS-RULES step helpers; `TENANT(t1)` names a tenant of the
// run and is resolved by this lane's session.

import {
  and,
  equal,
  get,
  integer,
  runQuery,
  seedDocs,
  string,
} from "../fs-rules/programs/common.mjs";

const nullValue = { nullValue: null };

/**
 * The principals a session creates before the first program. The three `same-*` accounts are
 * created with one local id in the project and in two tenants. `foreign` is an ID token of
 * another Firebase project (X9): its account is created, its token taken, and the account deleted
 * and read back as absent before any program runs.
 */
export const PRINCIPALS = {
  owner: { provider: "password" },
  other: { provider: "password" },
  "same-project": { provider: "admin-password", sameUid: true },
  "same-t1": { provider: "admin-password", sameUid: true, tenant: "t1" },
  "same-t2": { provider: "admin-password", sameUid: true, tenant: "t2" },
  foreign: { provider: "foreign" },
};

/** The tenant each same-uid principal signs in to (`null`: the project). */
const SAME = [
  ["same-project", null, "p"],
  ["same-t1", "t1", "t1"],
  ["same-t2", "t2", "t2"],
];
const tenantValue = (slot) => (slot ? string(`TENANT(${slot})`) : nullValue);
const sameDocs = () =>
  SAME.map(([name, slot, doc]) => [
    `afc-same/${doc}`,
    { owner: string(`UID(${name})`), tenant: tenantValue(slot) },
  ]);
/** The tenant constraint of a query: `== null` is sent as IS_NULL, as client SDKs send it. */
const tenantIs = (slot) =>
  slot
    ? equal("tenant", tenantValue(slot))
    : { unaryFilter: { op: "IS_NULL", field: { fieldPath: "tenant" } } };
const both = (make) => [make("rest", {}), make("grpc", { transport: "grpc" })];

const separation = {
  id: "auth-fs-cross/tenant-same-uid/separation",
  ruleset: "cross",
  seed: seedDocs(sameDocs()),
  steps: [
    ...SAME.flatMap(([as]) =>
      SAME.flatMap(([, , doc]) =>
        both((transport, extra) =>
          get(`get-${doc}-as-${as}-${transport}`, as, `afc-same/${doc}`, extra),
        ),
      ),
    ),
    ...SAME.flatMap(([as]) =>
      both((transport, extra) => ({
        id: `batch-get-all-as-${as}-${transport}`,
        as,
        rpc: "batchGet",
        body: { documents: SAME.map(([, , doc]) => `{docs}/afc-same/${doc}`) },
        ...extra,
      })),
    ),
    // A query proves the rule only when it constrains both the owner and the tenant.
    ...SAME.flatMap(([as, slot]) =>
      both((transport, extra) =>
        runQuery(`query-owner-and-tenant-as-${as}-${transport}`, as, "afc-same", {
          where: and(equal("owner", string(`UID(${as})`)), tenantIs(slot)),
          ...extra,
        }),
      ),
    ),
    ...SAME.flatMap(([as]) =>
      both((transport, extra) =>
        runQuery(`query-owner-only-as-${as}-${transport}`, as, "afc-same", {
          where: equal("owner", string(`UID(${as})`)),
          ...extra,
        }),
      ),
    ),
  ],
};

const afterDeletion = (suffix) => [
  ...both((transport, extra) =>
    get(`t1-own-doc-${suffix}-${transport}`, "same-t1", "afc-same/t1", extra),
  ),
  ...both((transport, extra) =>
    get(`t1-signed-in-doc-${suffix}-${transport}`, "same-t1", "afc-signed-in/d", extra),
  ),
  ...both((transport, extra) =>
    get(`t1-open-doc-${suffix}-${transport}`, "same-t1", "afc-open/d", extra),
  ),
  ...both((transport, extra) =>
    runQuery(`t1-signed-in-query-${suffix}-${transport}`, "same-t1", "afc-signed-in", extra),
  ),
  ...both((transport, extra) => ({
    id: `t1-create-${suffix}-${transport}`,
    as: "same-t1",
    rpc: "commit",
    body: {
      writes: [
        {
          update: {
            name: `{docs}/afc-created/t1-${suffix}-${transport}`,
            fields: { owner: string("UID(same-t1)") },
          },
          currentDocument: { exists: false },
        },
      ],
    },
    ...extra,
  })),
  ...both((transport, extra) =>
    get(`t2-own-doc-${suffix}-${transport}`, "same-t2", "afc-same/t2", extra),
  ),
];

const deletedTenant = {
  id: "auth-fs-cross/tenant-same-uid/deleted-tenant",
  ruleset: "cross",
  seed: seedDocs([
    ...sameDocs(),
    ["afc-open/d", { n: integer(1) }],
    ["afc-signed-in/d", { n: integer(1) }],
  ]),
  steps: [
    get("t1-own-doc-before", "same-t1", "afc-same/t1"),
    { action: "delete-tenant", tenant: "t1" },
    // Two probes: soon after the deletion, and after a minute (C5: a probe, never silence).
    { action: "sleep", ms: 3000 },
    ...afterDeletion("3s"),
    // Timed from the deletion's answer, not from the end of the first probe.
    { action: "wait-since-deletion", tenant: "t1", ms: 65_000 },
    ...afterDeletion("65s"),
  ],
};

const transactionId = (from, path = "transaction") => ({ $from: from, path });
const OWNED_QUERY = runQuery("x", "owner", "afc-owned", {
  where: equal("owner", string("UID(owner)")),
}).body.structuredQuery;
const inTransaction = (id, as, rpc, body, extra = {}) => ({ id, as, rpc, body, ...extra });
const batchGetIn = (id, as, doc, transaction, extra) =>
  inTransaction(id, as, "batchGet", { documents: [`{docs}/${doc}`], transaction }, extra);
const queryIn = (id, as, transaction) =>
  inTransaction(id, as, "runQuery", { structuredQuery: OWNED_QUERY, transaction });

const readOnlyTransaction = {
  id: "auth-fs-cross/read-only-transaction/binding",
  ruleset: "cross",
  seed: seedDocs([
    ["afc-owned/a", { owner: string("UID(owner)") }],
    ["afc-open/d", { n: integer(1) }],
  ]),
  steps: [
    inTransaction("begin-read-only", "owner", "beginTransaction", { options: { readOnly: {} } }),
    // The owner's read-only transaction, used by the owner, another principal, a tenant
    // principal and no credential.
    ...["owner", "other", "same-t2", "none"].flatMap((as) => [
      batchGetIn(`batch-get-owned-as-${as}`, as, "afc-owned/a", transactionId("begin-read-only")),
      queryIn(`query-owned-as-${as}`, as, transactionId("begin-read-only")),
      batchGetIn(`batch-get-open-as-${as}`, as, "afc-open/d", transactionId("begin-read-only")),
    ]),
    ...["owner", "other"].map((as) =>
      batchGetIn(
        `batch-get-owned-as-${as}-grpc`,
        as,
        "afc-owned/a",
        transactionId("begin-read-only"),
        {
          transport: "grpc",
        },
      ),
    ),
    // A read-only transaction opened by a query, then read by another principal.
    inTransaction("query-opens-read-only", "owner", "runQuery", {
      structuredQuery: OWNED_QUERY,
      newTransaction: { readOnly: {} },
    }),
    ...["owner", "other"].map((as) =>
      batchGetIn(
        `batch-get-owned-in-query-transaction-as-${as}`,
        as,
        "afc-owned/a",
        transactionId("query-opens-read-only", "0.transaction"),
      ),
    ),
  ],
};

const foreignProject = {
  id: "auth-fs-cross/foreign-project/token",
  ruleset: "cross",
  seed: seedDocs([
    ["afc-open/d", { n: integer(1) }],
    ["afc-signed-in/d", { n: integer(1) }],
    ["afc-owned/f", { owner: string("UID(foreign)") }],
  ]),
  steps: [
    ...both((transport, extra) => get(`foreign-open-${transport}`, "foreign", "afc-open/d", extra)),
    ...both((transport, extra) =>
      get(`foreign-signed-in-${transport}`, "foreign", "afc-signed-in/d", extra),
    ),
    ...both((transport, extra) =>
      get(`foreign-owned-${transport}`, "foreign", "afc-owned/f", extra),
    ),
    ...both((transport, extra) =>
      runQuery(`foreign-query-open-${transport}`, "foreign", "afc-open", extra),
    ),
    ...both((transport, extra) =>
      get(`same-project-signed-in-${transport}`, "owner", "afc-signed-in/d", extra),
    ),
  ],
};

export const PROGRAMS = [separation, readOnlyTransaction, foreignProject, deletedTenant];
