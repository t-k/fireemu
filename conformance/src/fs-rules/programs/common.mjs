// Step helpers and the session principals shared by every FS-RULES area.

/**
 * The principals a session creates before the first program. `expiring` is signed in with the
 * rest and never refreshed, so its ID token expires about an hour into the run, where the last
 * program waits for it.
 */
export const PRINCIPALS = {
  a: {
    provider: "password",
    profile: { displayName: "Fsr A", photoUrl: "https://example.com/fsr-a.png" },
  },
  b: { provider: "password" },
  verified: {
    provider: "password",
    emailVerified: true,
    customAttributes: {
      role: "editor",
      level: 3,
      ratio: 0.5,
      flags: { beta: true },
      tags: ["x", "y"],
    },
  },
  anon: { provider: "anonymous" },
  phone: { provider: "phone", phone: 0 },
  custom: { provider: "custom", token: { claims: { role: "admin", tier: 2 } } },
  tenant: { provider: "password", tenant: true },
  expiring: { provider: "anonymous" },
};

/** Principals whose tokens every program refreshes first (all but `expiring`). */
export const FRESH = Object.keys(PRINCIPALS).filter((name) => name !== "expiring");

/** Every principal kind a matrix row is made as: no credential and each fresh principal. */
export const EVERYONE = ["none", "anon", "a", "b", "verified", "phone", "custom", "tenant"];

export const string = (value) => ({ stringValue: value });
export const integer = (value) => ({ integerValue: String(value) });
export const double = (value) => ({ doubleValue: value });
export const bool = (value) => ({ booleanValue: value });

export const get = (id, as, doc, extra = {}) => ({ id, as, rpc: "get", doc, ...extra });

/** A single-write commit that creates `doc` (fails if it exists) with `fields`. */
export const create = (id, as, doc, fields, extra = {}) => ({
  id,
  as,
  rpc: "commit",
  body: {
    writes: [{ update: { name: `{docs}/${doc}`, fields }, currentDocument: { exists: false } }],
  },
  ...extra,
});

/** A commit of several writes; `write` entries are REST Write messages with `{docs}` names. */
export const commit = (id, as, writes, extra = {}) => ({
  id,
  as,
  rpc: "commit",
  body: { writes },
  ...extra,
});

export const update = (doc, fields, mask) => ({
  update: { name: `{docs}/${doc}`, fields },
  ...(mask ? { updateMask: { fieldPaths: mask } } : {}),
});
export const remove = (doc) => ({ delete: `{docs}/${doc}` });

/** A runQuery on `collection` (under `parent`), with optional where/limit/offset/orderBy. */
export function runQuery(
  id,
  as,
  collection,
  { where, limit, offset, orderBy, parent, allDescendants, ...extra } = {},
) {
  return {
    id,
    as,
    rpc: "runQuery",
    ...(parent ? { parent } : {}),
    body: {
      structuredQuery: {
        from: [{ collectionId: collection, ...(allDescendants ? { allDescendants: true } : {}) }],
        ...(where ? { where } : {}),
        ...(orderBy ? { orderBy } : {}),
        ...(offset !== undefined ? { offset } : {}),
        ...(limit !== undefined ? { limit } : {}),
      },
    },
    ...extra,
  };
}

export const equal = (field, value) => ({
  fieldFilter: { field: { fieldPath: field }, op: "EQUAL", value },
});
export const within = (field, values) => ({
  fieldFilter: { field: { fieldPath: field }, op: "IN", value: { arrayValue: { values } } },
});
export const and = (...filters) => ({ compositeFilter: { op: "AND", filters } });

/** Seeds `docs` (`[path, fields]`) in one database. */
export const seedDocs = (docs, database) =>
  docs.map(([doc, fields]) => ({ doc, fields, ...(database ? { database } : {}) }));

/** A `match` block granting `methods` under `condition`, at a literal or wildcard path. */
export const allow = (path, methods, condition) =>
  [`    match ${path} {`, `      allow ${methods}: if ${condition};`, "    }"].join("\n");
