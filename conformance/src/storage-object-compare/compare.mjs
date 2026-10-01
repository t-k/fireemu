// Judges a local run (fireemu, strict) against the recorded production exchanges. Both sides are
// normalized by `normalize.mjs`; an exchange is compared on its status, its exact content type, its
// headers (the infrastructure ones are already left out) and its body. Nothing is fitted to a
// simulator: every expected value is a recorded production value.
//
// A pair is one of
//   MATCH                 status, content type, headers and body are the same;
//   DIVERGENCE            at least one of them differs (the differences are listed);
//   LOCAL_UNIMPLEMENTED   fireemu answered 501 (it does not serve the route), or the rehearsal's
//                         stand-in answered in its place (it marks its answer with
//                         `x-compare-standin`): neither a match nor a divergence;
//   TAINTED               an exchange after a stand-in answer that disagrees with production in the
//                         same recipe: the object's state is no longer fireemu's, so it is neither;
//   ONLY_PRODUCTION / ONLY_LOCAL   an exchange the other side has no counterpart for.

const queryNames = (row) => [...new Set(row.query.map(([name]) => name))].toSorted().join(",");
const alignmentKey = (row) => `${row.method} ${row.path} ?${queryNames(row)}`;

/** Longest-common-subsequence alignment of two lists by key: [[i, j], [i, null], [null, j]...]. */
export function align(left, right, keyOf = (value) => value) {
  const a = left.map(keyOf);
  const b = right.map(keyOf);
  const table = Array.from({ length: a.length + 1 }, () => new Uint32Array(b.length + 1));
  for (let i = a.length - 1; i >= 0; i--)
    for (let j = b.length - 1; j >= 0; j--)
      table[i][j] =
        a[i] === b[j] ? table[i + 1][j + 1] + 1 : Math.max(table[i + 1][j], table[i][j + 1]);
  const pairs = [];
  let i = 0;
  let j = 0;
  while (i < a.length && j < b.length) {
    if (a[i] === b[j]) pairs.push([i++, j++]);
    else if (table[i + 1][j] >= table[i][j + 1]) pairs.push([i++, null]);
    else pairs.push([null, j++]);
  }
  while (i < a.length) pairs.push([i++, null]);
  while (j < b.length) pairs.push([null, j++]);
  return pairs;
}

const same = (x, y) => JSON.stringify(x) === JSON.stringify(y);

/** The differences between two normalized JSON values, as `{ path, production, local }`. */
export function jsonDifferences(production, local, path = "$", limit = 8, out = []) {
  if (out.length >= limit) return out;
  if (same(production, local)) return out;
  const isObject = (value) => value && typeof value === "object" && !Array.isArray(value);
  if (isObject(production) && isObject(local)) {
    const productionKeys = Object.keys(production);
    const localKeys = Object.keys(local);
    for (const key of [...new Set([...productionKeys, ...localKeys])].toSorted()) {
      if (!(key in local))
        out.push({ path: `${path}.${key}`, production: production[key], local: "<absent>" });
      else if (!(key in production))
        out.push({ path: `${path}.${key}`, production: "<absent>", local: local[key] });
      else jsonDifferences(production[key], local[key], `${path}.${key}`, limit, out);
      if (out.length >= limit) break;
    }
    // The same members in another order are a difference: the order is part of the answer.
    if (
      out.length < limit &&
      productionKeys.length === localKeys.length &&
      productionKeys.every((key) => key in local) &&
      productionKeys.join("\u0000") !== localKeys.join("\u0000")
    )
      out.push({ path, memberOrder: true, production: productionKeys, local: localKeys });
  } else if (
    Array.isArray(production) &&
    Array.isArray(local) &&
    production.length === local.length
  ) {
    production.forEach((item, index) =>
      jsonDifferences(item, local[index], `${path}[${index}]`, limit, out),
    );
  } else out.push({ path, production, local });
  return out;
}

/** The differences between a production exchange and a local one. */
export function differences(production, local) {
  const found = [];
  if (production.status !== local.status)
    found.push({ kind: "status", production: production.status, local: local.status });
  if (production.contentType !== local.contentType)
    found.push({
      kind: "contentType",
      production: production.contentType,
      local: local.contentType,
    });
  for (const name of new Set([...Object.keys(production.headers), ...Object.keys(local.headers)])) {
    if (name === "content-type") continue;
    if (!(name in local.headers))
      found.push({ kind: "missingHeader", header: name, production: production.headers[name] });
    else if (!(name in production.headers))
      found.push({ kind: "extraHeader", header: name, local: local.headers[name] });
    else if (production.headers[name] !== local.headers[name])
      found.push({
        kind: "headerValue",
        header: name,
        production: production.headers[name],
        local: local.headers[name],
      });
  }
  if (production.body.type !== local.body.type)
    found.push({ kind: "bodyType", production: production.body.type, local: local.body.type });
  else if (production.body.type === "json") {
    for (const { memberOrder, ...diff } of jsonDifferences(production.body.value, local.body.value))
      found.push({ kind: memberOrder ? "memberOrder" : "body", ...diff });
  } else if (!same(production.body, local.body)) {
    found.push({
      kind: "body",
      production: production.body.value ?? {
        length: production.body.length,
        sha256: production.body.sha256,
      },
      local: local.body.value ?? { length: local.body.length, sha256: local.body.sha256 },
    });
  }
  // The bytes beyond the compact form (whitespace): only where both sides know their length.
  if (
    Number.isSafeInteger(production.layout) &&
    Number.isSafeInteger(local.layout) &&
    production.layout !== local.layout
  )
    found.push({ kind: "bodyLayout", production: production.layout, local: local.layout });
  const requestQuery = same(production.query, local.query)
    ? []
    : [{ kind: "requestQuery", production: production.query, local: local.query }];
  return [...found, ...requestQuery];
}

export const STANDIN_HEADER = "x-compare-standin";

// The members of an object resource that an update changes. A stand-in answer that differs from
// production in one of them (or in the status) has left the object in another state. The generation,
// the etag, the id and the links are formats of the server that answered, not state.
const STATE_MEMBERS = [
  "metageneration",
  "metadata",
  "contentType",
  "contentEncoding",
  "contentDisposition",
  "contentLanguage",
  "cacheControl",
  "size",
  "crc32c",
  "md5Hash",
];

// Checked member by member, not through the capped list of body differences: any number of other
// differences before them must not hide a difference in the object's state.
function standInDisagrees(production, local) {
  if (local.status !== production.status) return true;
  if (production.body?.type !== "json" || local.body?.type !== "json") return false;
  return STATE_MEMBERS.some(
    (name) => !same(production.body.value?.[name], local.body.value?.[name]),
  );
}

/**
 * Compare one recipe. `production` and `local` are lists of normalized exchanges. An exchange the
 * local side answered 501 to (and production did not), or that the rehearsal's stand-in answered,
 * is LOCAL_UNIMPLEMENTED.
 */
export function compareRecipe({ production, local }) {
  const results = [];
  let tainted = false;
  for (const [i, j] of align(production, local, alignmentKey)) {
    let result;
    if (i === null) result = { outcome: "ONLY_LOCAL", local: local[j] };
    else if (j === null)
      result = { outcome: "ONLY_PRODUCTION", n: production[i].n, production: production[i] };
    else {
      const standIn = STANDIN_HEADER in local[j].headers;
      if (standIn || (local[j].status === 501 && production[i].status !== 501)) {
        result = {
          outcome: "LOCAL_UNIMPLEMENTED",
          n: production[i].n,
          route: production[i].route,
          reason: standIn ? "answered by the rehearsal stand-in" : "fireemu answered 501",
          productionStatus: production[i].status,
          localStatus: local[j].status,
        };
        // A stand-in answer that disagrees with production leaves the object in another state: what
        // follows in this recipe says nothing about fireemu.
        if (standIn && standInDisagrees(production[i], local[j])) tainted = true;
        results.push(result);
        continue;
      }
      const found = differences(production[i], local[j]);
      result =
        found.length === 0
          ? { outcome: "MATCH", n: production[i].n }
          : {
              outcome: "DIVERGENCE",
              n: production[i].n,
              route: production[i].route,
              differences: found,
            };
    }
    results.push(
      tainted
        ? {
            outcome: "TAINTED",
            n: result.n ?? null,
            route: result.route ?? result.local?.route ?? null,
            was: result.outcome,
          }
        : result,
    );
  }
  return results;
}

export function summarize(results) {
  const counts = {
    MATCH: 0,
    DIVERGENCE: 0,
    LOCAL_UNIMPLEMENTED: 0,
    TAINTED: 0,
    ONLY_PRODUCTION: 0,
    ONLY_LOCAL: 0,
  };
  for (const result of results) counts[result.outcome]++;
  return counts;
}
