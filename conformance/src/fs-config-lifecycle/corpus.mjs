// The FS-CONFIG-LIFECYCLE corpus: one program per behavior, each creating its own named
// databases (`databases`, by letter) that the session deletes afterwards. Every recorded step is
// a row `program#step`. See spec/compatibility/closure/FS-CONFIG-LIFECYCLE.json for the
// conditions each program area closes.
//
// Step fields:
//   path       REST path template ({project}, {foreign}, {db:x}, {bucket}, {prefix}, {objects})
//   pathFrom   { $from: step, path } a resource name an earlier step returned; suffix appended
//   method     GET (default), POST, PATCH, DELETE
//   query      query parameters; body: JSON body
//   delayMs    wait this long before sending
//   poll       { max, intervalMs, until } repeat until `until` holds or `max` polls; the row is
//              the collapsed trace of states and the settled answer (scope decision C10)
//   filterDatabases, objectListing   reduce list answers to this program's resources

const NATIVE = { locationId: "us-central1", type: "FIRESTORE_NATIVE" };

const docs = (db) => `{project}/databases/{db:${db}}/documents`;
const dbPath = (db) => `v1/{project}/databases/{db:${db}}`;
const fieldPath = (db, group, field) => `${dbPath(db)}/collectionGroups/${group}/fields/${field}`;

const integer = (n) => ({ integerValue: String(n) });

/** Every value type, for export and import round trips. */
const everyValue = (db) => ({
  s: { stringValue: "x" },
  i: integer(7),
  d: { doubleValue: 1.5 },
  b: { booleanValue: true },
  n: { nullValue: null },
  t: { timestampValue: "2026-01-02T03:04:05.123456Z" },
  g: { geoPointValue: { latitude: 1, longitude: 2 } },
  y: { bytesValue: "AAE=" },
  r: { referenceValue: `${docs(db)}/other/c` },
  m: {
    mapValue: {
      fields: { k: { stringValue: "v" }, deep: { mapValue: { fields: { z: integer(1) } } } },
    },
  },
  arr: { arrayValue: { values: [integer(1), { stringValue: "z" }, { nullValue: null }] } },
  v: {
    mapValue: {
      fields: {
        __type__: { stringValue: "__vector__" },
        value: { arrayValue: { values: [{ doubleValue: 1 }, { doubleValue: 2 }] } },
      },
    },
  },
});

const commit = (id, db, writes) => ({
  id,
  method: "POST",
  path: `v1/${docs(db)}:commit`,
  body: {
    writes: writes.map(([name, fields]) => ({ update: { name: `${docs(db)}/${name}`, fields } })),
  },
});

const create = (id, db, body = NATIVE, extra = {}) => ({
  id,
  method: "POST",
  path: "v1/{project}/databases",
  query: { databaseId: `{db:${db}}` },
  body,
  ...extra,
});

const get = (id, path, extra = {}) => ({ id, path, ...extra });

/** Polls a resource another step returned until `until` holds. */
const pollFrom = (
  id,
  from,
  until,
  { max = 40, intervalMs = 15_000, path = "name", suffix } = {},
) => ({
  id,
  pathFrom: { $from: from, path },
  ...(suffix ? { suffix } : {}),
  poll: { max, intervalMs, until },
});

const pollPath = (
  id,
  path,
  until,
  { max = 40, intervalMs = 15_000, method, body, query } = {},
) => ({
  id,
  path,
  ...(method ? { method, body } : {}),
  ...(query ? { query } : {}),
  poll: { max, intervalMs, until },
});

const query = (db, where, orderBy) => ({
  structuredQuery: {
    from: [{ collectionId: "items" }],
    ...(where ? { where } : {}),
    ...(orderBy ? { orderBy } : {}),
  },
});
const eq = (field, n) => ({
  fieldFilter: { field: { fieldPath: field }, op: "EQUAL", value: integer(n) },
});
const desc = (field) => [{ field: { fieldPath: field }, direction: "DESCENDING" }];

const runQuery = (id, db, body, extra = {}) => ({
  id,
  method: "POST",
  path: `v1/${docs(db)}:runQuery`,
  body,
  ...extra,
});

const composite = {
  queryScope: "COLLECTION",
  fields: [
    { fieldPath: "a", order: "ASCENDING" },
    { fieldPath: "b", order: "DESCENDING" },
  ],
};

const items = (db) =>
  commit("seed", db, [
    [
      "items/a",
      {
        a: integer(1),
        b: integer(2),
        nx: integer(5),
        ttl_at: { timestampValue: "2020-01-01T00:00:00Z" },
      },
    ],
    ["items/b", { a: integer(1), b: integer(3), nx: integer(6) }],
    ["other/c", { a: integer(1) }],
  ]);

const PROGRAMS_RAW = [
  // ---- database projection, create, delete, patch ------------------------------------------
  {
    id: "fs-config/database/projection/default-and-named",
    databases: ["a"],
    steps: [
      get("get-default", "v1/{project}/databases/(default)"),
      create("create", "a"),
      get("get-named", dbPath("a")),
      get("list", "v1/{project}/databases", { filterDatabases: true }),
      get("list-show-deleted-false", "v1/{project}/databases", {
        query: { showDeleted: "false" },
        filterDatabases: true,
      }),
      get("get-missing", "v1/{project}/databases/{db:z}"),
    ],
  },
  {
    id: "fs-config/database/create/basic",
    databases: ["a"],
    steps: [
      create("create", "a"),
      pollFrom("operation", "create", "done", { max: 3, intervalMs: 2_000 }),
      get("get", dbPath("a")),
      create("duplicate", "a"),
    ],
  },
  {
    id: "fs-config/database/create/variants",
    databases: ["a", "b", "c"],
    steps: [
      create("datastore-mode", "a", { locationId: "us-central1", type: "DATASTORE_MODE" }),
      create("enterprise", "b", { ...NATIVE, databaseEdition: "ENTERPRISE" }),
      create("multi-region-optimistic-protected", "c", {
        locationId: "nam5",
        type: "FIRESTORE_NATIVE",
        concurrencyMode: "OPTIMISTIC",
        deleteProtectionState: "DELETE_PROTECTION_ENABLED",
        appEngineIntegrationMode: "DISABLED",
      }),
      get("get-datastore-mode", dbPath("a")),
      get("get-enterprise", dbPath("b")),
      get("get-multi-region", dbPath("c")),
    ],
  },
  {
    id: "fs-config/database/create/refusals",
    databases: ["b", "c", "d", "e", "f", "g", "h"],
    steps: [
      { ...create("bad-id", "b"), query: { databaseId: "Bad_Id" } },
      { ...create("too-short", "b"), query: { databaseId: "ab" } },
      { ...create("too-long", "b"), query: { databaseId: "a".repeat(64) } },
      { ...create("leading-dash", "b"), query: { databaseId: "-leading-dash" } },
      { ...create("no-id", "b"), query: undefined },
      create("no-location", "c", { type: "FIRESTORE_NATIVE" }),
      create("no-type", "d", { locationId: "us-central1" }),
      create("unknown-location", "e", { ...NATIVE, locationId: "nowhere-1" }),
      create("unknown-edition", "f", { ...NATIVE, databaseEdition: "PREMIUM" }),
      create("unknown-type", "f", { ...NATIVE, type: "SPANNER" }),
      create("customer-managed-key", "g", {
        ...NATIVE,
        cmekConfig: {
          kmsKeyName: "{project}/locations/us-central1/keyRings/none/cryptoKeys/none",
        },
      }),
      create("tags", "h", { ...NATIVE, tags: { "tagKeys/000000": "tagValues/000000" } }),
      create("unknown-concurrency", "h", { ...NATIVE, concurrencyMode: "NOPE" }),
    ],
  },
  {
    id: "fs-config/database/create/id-reuse",
    databases: ["a"],
    steps: [
      create("create", "a"),
      { id: "delete", method: "DELETE", path: dbPath("a") },
      create("recreate", "a", NATIVE, { delayMs: 3_000 }),
      get("get-after", dbPath("a")),
    ],
  },
  {
    id: "fs-config/database/delete/basic",
    databases: ["a"],
    steps: [
      create("create", "a"),
      commit("seed", "a", [["items/a", { a: integer(1) }]]),
      { id: "delete", method: "DELETE", path: dbPath("a") },
      pollFrom("operation", "delete", "never", { max: 3, intervalMs: 3_000 }),
      get("get-after", dbPath("a")),
      get("list-show-deleted", "v1/{project}/databases", {
        query: { showDeleted: "true" },
        filterDatabases: true,
      }),
      get("list-after", "v1/{project}/databases", { filterDatabases: true }),
      get("document-after", `v1/${docs("a")}/items/a`),
      { id: "delete-again", method: "DELETE", path: dbPath("a") },
      { id: "delete-missing", method: "DELETE", path: "v1/{project}/databases/{db:z}" },
    ],
  },
  {
    id: "fs-config/database/delete/protection-and-etag",
    databases: ["a"],
    steps: [
      create("create", "a", { ...NATIVE, deleteProtectionState: "DELETE_PROTECTION_ENABLED" }),
      { id: "delete-protected", method: "DELETE", path: dbPath("a") },
      get("get", dbPath("a")),
      {
        id: "unprotect",
        method: "PATCH",
        path: dbPath("a"),
        query: { updateMask: "deleteProtectionState" },
        body: { deleteProtectionState: "DELETE_PROTECTION_DISABLED" },
        delayMs: 5_000,
      },
      {
        id: "delete-stale-etag",
        method: "DELETE",
        path: dbPath("a"),
        query: { etag: { $from: "get", path: "etag" } },
      },
      { id: "delete-malformed-etag", method: "DELETE", path: dbPath("a"), query: { etag: "abc" } },
      { id: "delete", method: "DELETE", path: dbPath("a") },
    ],
  },
  {
    id: "fs-config/database/patch/fields",
    databases: ["a"],
    steps: [
      create("create", "a"),
      {
        id: "protect",
        method: "PATCH",
        path: dbPath("a"),
        query: { updateMask: "deleteProtectionState" },
        body: { deleteProtectionState: "DELETE_PROTECTION_ENABLED" },
        delayMs: 5_000,
      },
      {
        id: "unprotect-and-optimistic",
        method: "PATCH",
        path: dbPath("a"),
        query: { updateMask: "deleteProtectionState,concurrencyMode" },
        body: {
          deleteProtectionState: "DELETE_PROTECTION_DISABLED",
          concurrencyMode: "OPTIMISTIC",
        },
        delayMs: 3_000,
      },
      {
        id: "no-mask",
        method: "PATCH",
        path: dbPath("a"),
        body: { concurrencyMode: "PESSIMISTIC" },
        delayMs: 3_000,
      },
      get("get", dbPath("a")),
      {
        id: "location",
        method: "PATCH",
        path: dbPath("a"),
        query: { updateMask: "locationId" },
        body: { locationId: "us-east1" },
      },
      {
        id: "type",
        method: "PATCH",
        path: dbPath("a"),
        query: { updateMask: "type" },
        body: { type: "DATASTORE_MODE" },
      },
      {
        id: "edition",
        method: "PATCH",
        path: dbPath("a"),
        query: { updateMask: "databaseEdition" },
        body: { databaseEdition: "ENTERPRISE" },
      },
      {
        id: "unknown-mask",
        method: "PATCH",
        path: dbPath("a"),
        query: { updateMask: "foo" },
        body: {},
      },
      {
        id: "missing",
        method: "PATCH",
        path: "v1/{project}/databases/{db:z}",
        query: { updateMask: "deleteProtectionState" },
        body: { deleteProtectionState: "DELETE_PROTECTION_DISABLED" },
      },
    ],
  },
  // ---- database type and edition gating ------------------------------------------------------
  {
    id: "fs-config/database/mode-gating/datastore-and-enterprise",
    databases: ["a", "b"],
    steps: [
      create("create-datastore", "a", { locationId: "us-central1", type: "DATASTORE_MODE" }),
      create("create-enterprise", "b", { ...NATIVE, databaseEdition: "ENTERPRISE" }),
      get("datastore-get-document", `v1/${docs("a")}/c/d`),
      commit("datastore-commit", "a", [["c/d", { a: integer(1) }]]),
      runQuery("datastore-query", "a", query("a")),
      get("enterprise-get-document", `v1/${docs("b")}/c/d`),
      commit("enterprise-commit", "b", [["c/d", { a: integer(1) }]]),
      get("datastore-list-indexes", `${dbPath("a")}/collectionGroups/-/indexes`),
      get("enterprise-list-indexes", `${dbPath("b")}/collectionGroups/-/indexes`),
    ],
  },
  {
    id: "fs-config/database/mode-gating/enterprise-only-apis",
    databases: ["a"],
    steps: [
      create("create", "a"),
      get("change-streams-list", `${dbPath("a")}/changeStreams`),
      get("change-streams-get", `${dbPath("a")}/changeStreams/s1`),
      {
        id: "change-streams-create",
        method: "POST",
        path: `${dbPath("a")}/changeStreams`,
        query: { changeStreamId: "s1" },
        body: {},
      },
      get("user-creds-list", `${dbPath("a")}/userCreds`),
      get("user-creds-get", `${dbPath("a")}/userCreds/u1`),
      {
        id: "user-creds-create",
        method: "POST",
        path: `${dbPath("a")}/userCreds`,
        query: { userCredsId: "u1" },
        body: {},
      },
    ],
  },
  // ---- project boundary and locations ------------------------------------------------------
  {
    id: "fs-config/project-boundary/foreign-and-missing",
    databases: [],
    steps: [
      get("foreign-list-databases", "v1/{foreign}/databases"),
      get("foreign-get-database", "v1/{foreign}/databases/(default)"),
      get("foreign-get-document", "v1/{foreign}/databases/(default)/documents/c/d"),
      get("foreign-list-locations", "v1/{foreign}/locations"),
      get("missing-database-get-document", "v1/{project}/databases/{db:z}/documents/c/d"),
      get("invalid-database-get-document", "v1/{project}/databases/Bad_Id/documents/c/d"),
      get(
        "missing-database-list-indexes",
        "v1/{project}/databases/{db:z}/collectionGroups/-/indexes",
      ),
      get("missing-database-operations", "v1/{project}/databases/{db:z}/operations"),
    ],
  },
  {
    id: "fs-config/locations/catalog",
    databases: [],
    steps: [
      get("list", "v1/{project}/locations"),
      get("get-region", "v1/{project}/locations/us-central1"),
      get("get-multi-region", "v1/{project}/locations/nam5"),
      get("get-unknown", "v1/{project}/locations/nowhere-1"),
      get("list-page", "v1/{project}/locations", { query: { pageSize: 2 } }),
    ],
  },
  // ---- indexes -------------------------------------------------------------------------------
  {
    id: "fs-config/index/lifecycle/composite",
    databases: ["a"],
    steps: [
      create("create-database", "a"),
      items("a"),
      {
        id: "create",
        method: "POST",
        path: `${dbPath("a")}/collectionGroups/items/indexes`,
        body: composite,
      },
      {
        id: "duplicate",
        method: "POST",
        path: `${dbPath("a")}/collectionGroups/items/indexes`,
        body: composite,
      },
      {
        id: "single-field",
        method: "POST",
        path: `${dbPath("a")}/collectionGroups/items/indexes`,
        body: { queryScope: "COLLECTION", fields: [{ fieldPath: "a", order: "ASCENDING" }] },
      },
      {
        id: "no-scope",
        method: "POST",
        path: `${dbPath("a")}/collectionGroups/items/indexes`,
        body: { fields: composite.fields },
      },
      {
        id: "two-modes",
        method: "POST",
        path: `${dbPath("a")}/collectionGroups/items/indexes`,
        body: {
          queryScope: "COLLECTION",
          fields: [
            { fieldPath: "a", order: "ASCENDING", arrayConfig: "CONTAINS" },
            { fieldPath: "b", order: "ASCENDING" },
          ],
        },
      },
      {
        id: "collection-group-array",
        method: "POST",
        path: `${dbPath("a")}/collectionGroups/items/indexes`,
        body: {
          queryScope: "COLLECTION_GROUP",
          fields: [
            { fieldPath: "tags", arrayConfig: "CONTAINS" },
            { fieldPath: "b", order: "ASCENDING" },
          ],
        },
      },
      {
        id: "vector",
        method: "POST",
        path: `${dbPath("a")}/collectionGroups/items/indexes`,
        body: {
          queryScope: "COLLECTION",
          fields: [{ fieldPath: "v", vectorConfig: { dimension: 2, flat: {} } }],
        },
      },
      get("get-creating", "", { pathFrom: { $from: "create", path: "metadata.index" } }),
      get("list-group", `${dbPath("a")}/collectionGroups/items/indexes`),
      get("list-every-group", `${dbPath("a")}/collectionGroups/-/indexes`),
      pollFrom("ready", "create", "ready", { path: "metadata.index" }),
      pollFrom("operation", "create", "done"),
      pollFrom("ready-vector", "vector", "ready", { path: "metadata.index" }),
      pollFrom("ready-collection-group", "collection-group-array", "ready", {
        path: "metadata.index",
      }),
      get("list-ready", `${dbPath("a")}/collectionGroups/-/indexes`),
      { id: "delete", method: "DELETE", pathFrom: { $from: "create", path: "metadata.index" } },
      get("get-deleted", "", { pathFrom: { $from: "create", path: "metadata.index" } }),
      {
        id: "delete-again",
        method: "DELETE",
        pathFrom: { $from: "create", path: "metadata.index" },
      },
      get("get-malformed", `${dbPath("a")}/collectionGroups/items/indexes/not-an-index`),
      get("list-after-delete", `${dbPath("a")}/collectionGroups/-/indexes`),
    ],
  },
  {
    id: "fs-config/index/query-effect/composite",
    databases: ["a"],
    steps: [
      create("create-database", "a"),
      items("a"),
      runQuery("query-before", "a", query("a", eq("a", 1), desc("b"))),
      {
        id: "create",
        method: "POST",
        path: `${dbPath("a")}/collectionGroups/items/indexes`,
        body: composite,
      },
      runQuery("query-building", "a", query("a", eq("a", 1), desc("b"))),
      pollFrom("ready", "create", "ready", { path: "metadata.index" }),
      runQuery("query-ready", "a", query("a", eq("a", 1), desc("b"))),
      { id: "delete", method: "DELETE", pathFrom: { $from: "create", path: "metadata.index" } },
      {
        ...pollPath("query-after-delete", `v1/${docs("a")}:runQuery`, "httpError", {
          method: "POST",
          body: query("a", eq("a", 1), desc("b")),
        }),
      },
    ],
  },
  // ---- fields: single-field index configuration and time-to-live ------------------------
  {
    id: "fs-config/field/index-config/exemption",
    databases: ["a"],
    steps: [
      create("create-database", "a"),
      items("a"),
      get("get-inherited", fieldPath("a", "items", "nx")),
      get("get-wildcard", fieldPath("a", "__default__", "*")),
      get("get-wildcard-in-group", fieldPath("a", "items", "*")),
      get("list-without-filter", `${dbPath("a")}/collectionGroups/items/fields`),
      get("list-bad-filter", `${dbPath("a")}/collectionGroups/items/fields`, {
        query: { filter: "foo" },
      }),
      {
        id: "exempt",
        method: "PATCH",
        path: fieldPath("a", "items", "nx"),
        query: { updateMask: "indexConfig" },
        body: { indexConfig: { indexes: [] } },
      },
      pollFrom("exempt-operation", "exempt", "done"),
      pollPath("exempted", fieldPath("a", "items", "nx"), "exempt"),
      get("list-overrides", `${dbPath("a")}/collectionGroups/items/fields`, {
        query: { filter: "indexConfig.usesAncestorConfig:false" },
      }),
      pollPath("query-exempt-field", `v1/${docs("a")}:runQuery`, "httpError", {
        method: "POST",
        body: query("a", eq("nx", 5)),
      }),
      {
        id: "collection-group-only",
        method: "PATCH",
        path: fieldPath("a", "items", "cg"),
        query: { updateMask: "indexConfig" },
        body: {
          indexConfig: {
            indexes: [
              { queryScope: "COLLECTION_GROUP", fields: [{ fieldPath: "cg", order: "ASCENDING" }] },
            ],
          },
        },
      },
      pollFrom("collection-group-operation", "collection-group-only", "done"),
      get("get-collection-group-only", fieldPath("a", "items", "cg")),
      {
        id: "revert",
        method: "PATCH",
        path: fieldPath("a", "items", "nx"),
        query: { updateMask: "indexConfig" },
        body: {},
      },
      pollFrom("revert-operation", "revert", "done"),
      pollPath("reverted", fieldPath("a", "items", "nx"), "inherits"),
      {
        id: "bad-mask",
        method: "PATCH",
        path: fieldPath("a", "items", "nx"),
        query: { updateMask: "foo" },
        body: { indexConfig: { indexes: [] } },
      },
      {
        id: "bad-field-path",
        method: "PATCH",
        path: fieldPath("a", "items", "a..b"),
        query: { updateMask: "indexConfig" },
        body: { indexConfig: { indexes: [] } },
      },
    ],
  },
  {
    id: "fs-config/field/ttl/policy",
    databases: ["a"],
    steps: [
      create("create-database", "a"),
      items("a"),
      {
        id: "enable",
        method: "PATCH",
        path: fieldPath("a", "items", "ttl_at"),
        query: { updateMask: "ttlConfig" },
        body: { ttlConfig: {} },
      },
      get("get-creating", fieldPath("a", "items", "ttl_at")),
      get("expired-document-readable", `v1/${docs("a")}/items/a`),
      pollFrom("enable-operation", "enable", "done"),
      pollPath("active", fieldPath("a", "items", "ttl_at"), "ttlActive"),
      get("list-ttl", `${dbPath("a")}/collectionGroups/items/fields`, {
        query: { filter: "ttlConfig:*" },
      }),
      {
        id: "second-field",
        method: "PATCH",
        path: fieldPath("a", "items", "other_at"),
        query: { updateMask: "ttlConfig" },
        body: { ttlConfig: {} },
      },
      {
        id: "disable",
        method: "PATCH",
        path: fieldPath("a", "items", "ttl_at"),
        query: { updateMask: "ttlConfig" },
        body: {},
      },
      pollFrom("disable-operation", "disable", "done"),
      pollPath("removed", fieldPath("a", "items", "ttl_at"), "ttlGone"),
      pollFrom("second-field-operation", "second-field", "done", { max: 40 }),
    ],
  },
  // ---- operations ----------------------------------------------------------------------------
  {
    id: "fs-config/operations/lifecycle",
    databases: ["a"],
    steps: [
      create("create-database", "a"),
      get("list-empty", `${dbPath("a")}/operations`),
      {
        id: "create-index",
        method: "POST",
        path: `${dbPath("a")}/collectionGroups/items/indexes`,
        body: composite,
      },
      get("get-running", "", { pathFrom: { $from: "create-index", path: "name" } }),
      get("list", `${dbPath("a")}/operations`),
      get("list-filter-done", `${dbPath("a")}/operations`, { query: { filter: "done=true" } }),
      get("list-bad-filter", `${dbPath("a")}/operations`, { query: { filter: "nope" } }),
      {
        id: "cancel-running",
        method: "POST",
        pathFrom: { $from: "create-index", path: "name" },
        suffix: ":cancel",
        body: {},
      },
      pollFrom("cancelled", "create-index", "done", { max: 20 }),
      get("index-after-cancel", "", {
        pathFrom: { $from: "create-index", path: "metadata.index" },
      }),
      {
        id: "cancel-finished",
        method: "POST",
        pathFrom: { $from: "create-index", path: "name" },
        suffix: ":cancel",
        body: {},
      },
      { id: "delete", method: "DELETE", pathFrom: { $from: "create-index", path: "name" } },
      get("get-deleted", "", { pathFrom: { $from: "create-index", path: "name" } }),
      get("get-missing", `${dbPath("a")}/operations/nonexistent-operation`),
      {
        id: "cancel-missing",
        method: "POST",
        path: `${dbPath("a")}/operations/nonexistent-operation:cancel`,
        body: {},
      },
    ],
  },
  // ---- managed export and import ------------------------------------------------------------
  {
    id: "fs-config/export/documents",
    databases: ["a"],
    steps: [
      create("create-database", "a"),
      commit("seed", "a", [
        ["items/a", everyValue("a")],
        ["items/b", { i: integer(8) }],
        ["items/a/sub/x", { i: integer(9) }],
        ["other/c", { i: integer(10) }],
      ]),
      {
        id: "all",
        method: "POST",
        path: `${dbPath("a")}:exportDocuments`,
        body: { outputUriPrefix: "{prefix}/all" },
      },
      {
        id: "collections",
        method: "POST",
        path: `${dbPath("a")}:exportDocuments`,
        body: { outputUriPrefix: "{prefix}/items", collectionIds: ["items", "sub"] },
      },
      {
        id: "namespace",
        method: "POST",
        path: `${dbPath("a")}:exportDocuments`,
        body: { outputUriPrefix: "{prefix}/ns", namespaceIds: ["foo"] },
      },
      { id: "no-prefix", method: "POST", path: `${dbPath("a")}:exportDocuments`, body: {} },
      {
        id: "bad-scheme",
        method: "POST",
        path: `${dbPath("a")}:exportDocuments`,
        body: { outputUriPrefix: "http://example.com/x" },
      },
      {
        id: "missing-bucket",
        method: "POST",
        path: `${dbPath("a")}:exportDocuments`,
        body: { outputUriPrefix: "gs://fireemu-no-such-bucket-cfg/x" },
      },
      {
        id: "missing-database",
        method: "POST",
        path: "v1/{project}/databases/{db:z}:exportDocuments",
        body: { outputUriPrefix: "{prefix}/none" },
      },
      pollFrom("all-operation", "all", "done", { max: 30, intervalMs: 10_000 }),
      pollFrom("collections-operation", "collections", "done", { max: 30, intervalMs: 10_000 }),
      pollFrom("namespace-operation", "namespace", "done", { max: 30, intervalMs: 10_000 }),
      get("objects", "storage/v1/b/{bucket}/o", {
        service: "storage",
        query: { prefix: "{objects}/" },
        objectListing: true,
      }),
    ],
  },
  {
    id: "fs-config/import/documents",
    databases: ["a", "b"],
    steps: [
      create("create-source", "a"),
      create("create-target", "b"),
      commit("seed", "a", [
        ["items/a", everyValue("a")],
        ["items/a/sub/x", { i: integer(9) }],
        ["other/c", { i: integer(10) }],
      ]),
      {
        id: "export-all",
        method: "POST",
        path: `${dbPath("a")}:exportDocuments`,
        body: { outputUriPrefix: "{prefix}/all" },
      },
      {
        id: "export-other",
        method: "POST",
        path: `${dbPath("a")}:exportDocuments`,
        body: { outputUriPrefix: "{prefix}/other", collectionIds: ["other"] },
      },
      pollFrom("export-all-operation", "export-all", "done", { max: 30, intervalMs: 10_000 }),
      pollFrom("export-other-operation", "export-other", "done", { max: 30, intervalMs: 10_000 }),
      {
        id: "import-all",
        method: "POST",
        path: `${dbPath("b")}:importDocuments`,
        body: { inputUriPrefix: "{prefix}/all" },
      },
      pollFrom("import-all-operation", "import-all", "done", { max: 30, intervalMs: 5_000 }),
      get("imported-document", `v1/${docs("b")}/items/a`),
      get("imported-subcollection", `v1/${docs("b")}/items/a/sub/x`),
      {
        id: "import-filter-from-unfiltered",
        method: "POST",
        path: `${dbPath("b")}:importDocuments`,
        body: { inputUriPrefix: "{prefix}/all", collectionIds: ["other"] },
      },
      {
        id: "import-filtered",
        method: "POST",
        path: `${dbPath("b")}:importDocuments`,
        body: { inputUriPrefix: "{prefix}/other", collectionIds: ["other"] },
      },
      pollFrom("import-filtered-operation", "import-filtered", "done", {
        max: 30,
        intervalMs: 5_000,
      }),
      {
        id: "import-absent",
        method: "POST",
        path: `${dbPath("b")}:importDocuments`,
        body: { inputUriPrefix: "{prefix}/nothing-here" },
      },
      { id: "import-no-prefix", method: "POST", path: `${dbPath("b")}:importDocuments`, body: {} },
    ],
  },
  {
    id: "fs-config/bulk-delete/collections",
    databases: ["a"],
    steps: [
      create("create-database", "a"),
      items("a"),
      { id: "empty-filter", method: "POST", path: `${dbPath("a")}:bulkDeleteDocuments`, body: {} },
      {
        id: "collections",
        method: "POST",
        path: `${dbPath("a")}:bulkDeleteDocuments`,
        body: { collectionIds: ["other"] },
      },
      pollFrom("operation", "collections", "done", { max: 30, intervalMs: 10_000 }),
      get("deleted-document", `v1/${docs("a")}/other/c`),
      get("kept-document", `v1/${docs("a")}/items/b`),
      {
        id: "missing-database",
        method: "POST",
        path: "v1/{project}/databases/{db:z}:bulkDeleteDocuments",
        body: { collectionIds: ["other"] },
      },
    ],
  },
  // ---- managed export format interop (C2) ----------------------------------------------------
  {
    // Production's export of every value type, captured for fireemu to import.
    id: "fs-config/export/interop/production-to-fireemu",
    databases: ["a", "b", "c"],
    steps: [
      create("create-source", "a"),
      create("create-target", "b"),
      create("create-filtered-target", "c"),
      {
        ...commit("seed", "a", [
          ["items/a", everyValue("a")],
          ["items/a/sub/x", { i: integer(9) }],
          ["other/c", { i: integer(10) }],
        ]),
        onlyOn: "production",
      },
      {
        id: "export-all",
        method: "POST",
        path: `${dbPath("a")}:exportDocuments`,
        body: { outputUriPrefix: "{prefix}/all" },
        onlyOn: "production",
      },
      {
        id: "export-items",
        method: "POST",
        path: `${dbPath("a")}:exportDocuments`,
        body: { outputUriPrefix: "{prefix}/items", collectionIds: ["items"] },
        onlyOn: "production",
      },
      {
        ...pollFrom("export-all-operation", "export-all", "done", { max: 30, intervalMs: 10_000 }),
        onlyOn: "production",
      },
      {
        ...pollFrom("export-items-operation", "export-items", "done", {
          max: 30,
          intervalMs: 10_000,
        }),
        onlyOn: "production",
      },
      { id: "capture-all", capture: { prefix: "all", as: "all" }, onlyOn: "production" },
      { id: "capture-items", capture: { prefix: "items", as: "items" }, onlyOn: "production" },
      {
        id: "upload-all",
        upload: { from: "fs-config/export/interop/production-to-fireemu:all" },
        onlyOn: "local",
      },
      {
        id: "upload-items",
        upload: { from: "fs-config/export/interop/production-to-fireemu:items" },
        onlyOn: "local",
      },
      {
        id: "import-all",
        method: "POST",
        path: `${dbPath("b")}:importDocuments`,
        body: { inputUriPrefix: "{prefix}/all" },
      },
      pollFrom("import-all-operation", "import-all", "done", { max: 30, intervalMs: 5_000 }),
      get("imported-document", `v1/${docs("b")}/items/a`),
      get("imported-subcollection", `v1/${docs("b")}/items/a/sub/x`),
      get("imported-other", `v1/${docs("b")}/other/c`),
      {
        id: "import-items",
        method: "POST",
        path: `${dbPath("c")}:importDocuments`,
        body: { inputUriPrefix: "{prefix}/items", collectionIds: ["items"] },
      },
      pollFrom("import-items-operation", "import-items", "done", { max: 30, intervalMs: 5_000 }),
      get("filtered-document", `v1/${docs("c")}/items/a`),
      get("filtered-excluded", `v1/${docs("c")}/other/c`),
    ],
  },
  {
    // fireemu's export of the same data: run locally by `capture-fireemu-export`, committed,
    // and checked against every later artifact (its export must reproduce the capture).
    id: "fs-config/export/interop/fireemu-source",
    databases: ["a"],
    local: true,
    steps: [
      create("create-source", "a"),
      commit("seed", "a", [
        ["items/a", everyValue("a")],
        ["items/a/sub/x", { i: integer(9) }],
        ["other/c", { i: integer(10) }],
      ]),
      {
        id: "export-all",
        method: "POST",
        path: `${dbPath("a")}:exportDocuments`,
        body: { outputUriPrefix: "{prefix}/all" },
      },
      {
        id: "export-items",
        method: "POST",
        path: `${dbPath("a")}:exportDocuments`,
        body: { outputUriPrefix: "{prefix}/items", collectionIds: ["items"] },
      },
      pollFrom("export-all-operation", "export-all", "done", { max: 30, intervalMs: 10_000 }),
      pollFrom("export-items-operation", "export-items", "done", { max: 30, intervalMs: 10_000 }),
      { id: "capture-all", capture: { prefix: "all", as: "all" } },
      { id: "capture-items", capture: { prefix: "items", as: "items" } },
      { id: "reproduces-all", reproduce: { prefix: "all", capture: "fireemu:all" } },
      { id: "reproduces-items", reproduce: { prefix: "items", capture: "fireemu:items" } },
    ],
  },
  {
    // Production importing fireemu's export.
    id: "fs-config/export/interop/fireemu-to-production",
    databases: ["a", "b", "c"],
    steps: [
      create("create-source-placeholder", "a"),
      create("create-target", "b"),
      create("create-filtered-target", "c"),
      { id: "upload-all", upload: { from: "fireemu:all" } },
      { id: "upload-items", upload: { from: "fireemu:items" } },
      {
        id: "import-all",
        method: "POST",
        path: `${dbPath("b")}:importDocuments`,
        body: { inputUriPrefix: "{prefix}/all" },
      },
      pollFrom("import-all-operation", "import-all", "done", { max: 30, intervalMs: 5_000 }),
      get("imported-document", `v1/${docs("b")}/items/a`),
      get("imported-subcollection", `v1/${docs("b")}/items/a/sub/x`),
      get("imported-other", `v1/${docs("b")}/other/c`),
      {
        id: "import-items",
        method: "POST",
        path: `${dbPath("c")}:importDocuments`,
        body: { inputUriPrefix: "{prefix}/items", collectionIds: ["items"] },
      },
      pollFrom("import-items-operation", "import-items", "done", { max: 30, intervalMs: 5_000 }),
      get("filtered-document", `v1/${docs("c")}/items/a`),
      get("filtered-excluded", `v1/${docs("c")}/other/c`),
    ],
  },
  // ---- gRPC google.firestore.admin.v1 (C7) --------------------------------------------------
  {
    id: "fs-config/grpc/admin",
    databases: ["a", "b"],
    steps: [
      {
        id: "list-databases",
        grpc: { rpc: "ListDatabases", request: { parent: "{project}" } },
        filterDatabases: true,
      },
      {
        id: "create-database",
        grpc: {
          rpc: "CreateDatabase",
          request: { parent: "{project}", databaseId: "{db:a}", database: NATIVE },
        },
      },
      {
        id: "create-target",
        grpc: {
          rpc: "CreateDatabase",
          request: { parent: "{project}", databaseId: "{db:b}", database: NATIVE },
        },
      },
      {
        id: "create-bad-id",
        grpc: {
          rpc: "CreateDatabase",
          request: { parent: "{project}", databaseId: "Bad_Id", database: NATIVE },
        },
      },
      {
        id: "get-database",
        grpc: { rpc: "GetDatabase", request: { name: "{project}/databases/{db:a}" } },
      },
      {
        id: "get-missing",
        grpc: { rpc: "GetDatabase", request: { name: "{project}/databases/{db:z}" } },
      },
      {
        id: "get-operation",
        grpc: { rpc: "GetOperation", nameFrom: { $from: "create-database", path: "name" } },
      },
      commit("seed", "a", [["items/a", everyValue("a")]]),
      {
        id: "create-index",
        grpc: {
          rpc: "CreateIndex",
          request: {
            parent: "{project}/databases/{db:a}/collectionGroups/items",
            index: composite,
          },
        },
      },
      {
        id: "get-index",
        grpc: { rpc: "GetIndex", nameFrom: { $from: "create-index", path: "metadata.index" } },
      },
      {
        id: "export",
        grpc: {
          rpc: "ExportDocuments",
          request: { name: "{project}/databases/{db:a}", outputUriPrefix: "{prefix}/all" },
        },
      },
      {
        id: "export-operation",
        grpc: { rpc: "GetOperation", nameFrom: { $from: "export", path: "name" } },
        poll: { max: 30, intervalMs: 10_000, until: "done" },
      },
      {
        id: "import",
        grpc: {
          rpc: "ImportDocuments",
          request: { name: "{project}/databases/{db:b}", inputUriPrefix: "{prefix}/all" },
        },
      },
      {
        id: "import-operation",
        grpc: { rpc: "GetOperation", nameFrom: { $from: "import", path: "name" } },
        poll: { max: 30, intervalMs: 5_000, until: "done" },
      },
      get("imported-document", `v1/${docs("b")}/items/a`),
      {
        id: "delete-database",
        grpc: { rpc: "DeleteDatabase", request: { name: "{project}/databases/{db:a}" } },
      },
      {
        id: "get-deleted",
        grpc: { rpc: "GetDatabase", request: { name: "{project}/databases/{db:a}" } },
      },
    ],
  },
  // ---- (default) lifecycle (C9): only in the FS-DATA-WRITE bisection project at its cleanup --
  {
    id: "fs-config/default-database/lifecycle",
    project: "fireemu-fs-bisect-0924a",
    defaultDatabase: true,
    databases: [],
    steps: [
      get("get-before", "v1/{project}/databases/(default)"),
      { id: "delete", method: "DELETE", path: "v1/{project}/databases/(default)" },
      pollPath("absent", "v1/{project}/databases/(default)", "notFound", {
        max: 20,
        intervalMs: 5_000,
      }),
      get("document-without-default", "v1/{project}/databases/(default)/documents/c/d"),
      {
        id: "query-without-default",
        method: "POST",
        path: "v1/{project}/databases/(default)/documents:runQuery",
        body: query("(default)"),
      },
      get("list-without-default", "v1/{project}/databases", { filterDatabases: true }),
      get("indexes-without-default", "v1/{project}/databases/(default)/collectionGroups/-/indexes"),
      pollPath("recreate", "v1/{project}/databases", "httpOk", {
        max: 30,
        intervalMs: 20_000,
        method: "POST",
        body: NATIVE,
        query: { databaseId: "(default)" },
      }),
      get("get-after", "v1/{project}/databases/(default)"),
      get("document-after", "v1/{project}/databases/(default)/documents/c/d"),
    ],
  },
];

/** The corpus, with each program's ordinal (its database ids) and object-prefix slug. */
/**
 * Letter `z` is the database a program names but never creates: the missing database of its
 * refusal rows. It is still one of the program's own ids (unique to the run), so the guard
 * admits it and cleanup would delete it if production unexpectedly created it.
 */
const withMissing = (program) =>
  JSON.stringify(program.steps).includes("{db:z}") && !(program.databases ?? []).includes("z")
    ? [...(program.databases ?? []), "z"]
    : program.databases;

export const PROGRAMS = PROGRAMS_RAW.map((program, ordinal) =>
  Object.assign(program, {
    databases: withMissing(program),
    ordinal,
    slug: program.id.replace(/^fs-config\//, "").replaceAll("/", "-"),
  }),
);
