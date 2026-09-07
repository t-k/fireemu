// Verify observable partition semantics without assuming physical split positions.
import { Buffer } from "node:buffer";

const compareNames = (left, right) => Buffer.compare(Buffer.from(left), Buffer.from(right));
const compareReferences = (left, right) => {
  const a = left.split("/");
  const b = right.split("/");
  for (let index = 0; index < Math.min(a.length, b.length); index++) {
    const order = compareNames(a[index], b[index]);
    if (order) return order;
  }
  return a.length - b.length;
};

/** Validate pages before using their globally unordered cursors as adjacent ranges. */
export function partitionRanges({ pages, partitionCount, pageSize, parent, structuredQuery }) {
  if (!Number.isSafeInteger(partitionCount) || partitionCount < 1) {
    throw new Error("partitionCount must be a positive safe integer");
  }
  if (!Number.isSafeInteger(pageSize) || pageSize < 0) throw new Error("invalid pageSize");
  if (!Array.isArray(pages) || pages.length === 0) throw new Error("missing partition pages");
  const collection = structuredQuery.from?.[0]?.collectionId;
  if (structuredQuery.from?.length !== 1 || !structuredQuery.from[0].allDescendants) {
    throw new Error("a collection-group query is required");
  }
  const cursors = [];
  const seenNames = new Set();
  const seenTokens = new Set();
  for (const [index, page] of pages.entries()) {
    if (!page || typeof page !== "object" || Array.isArray(page)) throw new Error("invalid page");
    const partitions = page.partitions ?? [];
    if (!Array.isArray(partitions)) throw new Error("invalid partitions");
    if (pageSize > 0 && partitions.length > pageSize) throw new Error("page size exceeded");
    const token = page.nextPageToken ?? "";
    if (typeof token !== "string") throw new Error("invalid page token");
    if (index < pages.length - 1 && !token) throw new Error("page after terminal page");
    if (index === pages.length - 1 && token) throw new Error("incomplete pagination");
    if (token && seenTokens.has(token)) throw new Error("repeated page token");
    if (token) seenTokens.add(token);
    for (const cursor of partitions) {
      const name = cursor?.values?.[0]?.referenceValue;
      if (
        !Array.isArray(cursor?.values) ||
        cursor.values.length !== 1 ||
        typeof name !== "string"
      ) {
        throw new Error("partition cursor must contain one document reference");
      }
      if (cursor.before !== undefined && typeof cursor.before !== "boolean") {
        throw new Error("invalid cursor before flag");
      }
      if (!name.startsWith(`${parent}/`)) throw new Error("partition outside database");
      const segments = name.slice(parent.length + 1).split("/");
      if (
        segments.length % 2 !== 0 ||
        segments.some((part) => !part) ||
        segments.at(-2) !== collection
      ) {
        throw new Error("partition outside collection group");
      }
      if (seenNames.has(name)) throw new Error("duplicate partition cursor");
      seenNames.add(name);
      cursors.push(cursor);
    }
  }
  if (cursors.length > partitionCount) throw new Error("partition count exceeded");
  cursors.sort((a, b) => compareReferences(a.values[0].referenceValue, b.values[0].referenceValue));
  return Array.from({ length: cursors.length + 1 }, (_, index) => ({
    ...structuredQuery,
    ...(index > 0 ? { startAt: cursors[index - 1] } : {}),
    ...(index < cursors.length ? { endAt: cursors[index] } : {}),
  }));
}

/** Compare full document values and detect repeated documents, not only set equality. */
export function verifyPartitionDocuments(expectedRows, rangeRows) {
  const documents = (rows) => {
    if (!Array.isArray(rows)) throw new Error("runQuery response must be an array");
    const result = new Map();
    for (const row of rows) {
      if (row.error) throw new Error("runQuery returned an error");
      if (!row.document) continue;
      const { name, fields = {} } = row.document;
      if (typeof name !== "string") throw new Error("document missing name");
      if (result.has(name)) throw new Error("duplicate document in reconstruction");
      result.set(name, fields);
    }
    return result;
  };
  const expected = documents(expectedRows);
  const actual = documents(rangeRows.flat());
  const canonical = (value) =>
    JSON.stringify(value, function (_key, item) {
      if (item && typeof item === "object" && !Array.isArray(item)) {
        return Object.fromEntries(Object.entries(item).toSorted(([a], [b]) => compareNames(a, b)));
      }
      return item;
    });
  if (expected.size !== actual.size)
    throw new Error("partition reconstruction document count differs");
  for (const [name, fields] of expected) {
    if (!actual.has(name) || canonical(fields) !== canonical(actual.get(name))) {
      throw new Error(`partition reconstruction differs at ${name}`);
    }
  }
  return { documentCount: expected.size, rangeCount: rangeRows.length };
}

/** Run against a real REST endpoint. The caller supplies one valid snapshot readTime. */
export async function verifyPartitionReconstruction({
  origin,
  parent,
  structuredQuery,
  readTime,
  authorization,
  partitionCount = 10,
  pageSize = 3,
}) {
  if (typeof readTime !== "string" || !readTime) throw new Error("a shared readTime is required");
  const post = async (method, body) => {
    const response = await fetch(`${origin.replace(/\/$/, "")}/v1/${parent}:${method}`, {
      method: "POST",
      headers: { "content-type": "application/json", ...(authorization ? { authorization } : {}) },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(30_000),
    });
    if (!response.ok)
      throw new Error(`${method} returned HTTP ${response.status}: ${await response.text()}`);
    const text = await response.text();
    return text ? JSON.parse(text) : {};
  };
  const pages = [];
  const tokens = new Set();
  let pageToken = "";
  do {
    const page = await post("partitionQuery", {
      structuredQuery,
      readTime,
      partitionCount: String(partitionCount),
      pageSize,
      ...(pageToken ? { pageToken } : {}),
    });
    pages.push(page);
    pageToken = page.nextPageToken ?? "";
    if (pageToken && tokens.has(pageToken)) throw new Error("repeated page token");
    if (pageToken) tokens.add(pageToken);
    if (pages.length > partitionCount + 1)
      throw new Error("partition pagination made no bounded progress");
  } while (pageToken);
  const ranges = partitionRanges({ pages, partitionCount, pageSize, parent, structuredQuery });
  const expected = await post("runQuery", { structuredQuery, readTime });
  const results = [];
  for (const range of ranges)
    results.push(await post("runQuery", { structuredQuery: range, readTime }));
  return { ...verifyPartitionDocuments(expected, results), readTime, pages };
}
