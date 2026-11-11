// The judge of the Hosting observation: compares two shaped rows (production against local
// fireemu, or one production run against the other) and aggregates per condition. Pure.
//
// Rules, fixed before the first send:
//  - Only recorded shapes are judged. A row that is not an answer on either side is UNKNOWN, never
//    a match and never a mismatch; a request that is absent from one side is UNKNOWN.
//  - Compared: status, every header in COMPARED_HEADERS (and x-g<nn>), body size and digest (the
//    decoded body when either side has a Content-Encoding), the layout of the reserved
//    initialization JSON. ETag and Last-Modified are compared by form (weak flag, quotes, length,
//    character class; IMF-fixdate form), not by value; a form that agrees with different values is
//    MATCH_LAYOUT.
//  - Volatile edge headers (date, age, via, x-cache, ...) are never compared. Any other header that
//    is present is listed as unclassified; the review has to name each one before closure.
//  - A mask hides a value, never a format: nothing here normalizes a length, a precision or an order.
//  - Known differences (`known-differences.json`, one entry per ruling) take named fields of named rows
//    out of the comparison. A row whose only differences are known is KNOWN_DIFFERENCE, never MATCH:
//    its known fields were not compared. An entry may also name a suffix to strip from an ETag
//    (`etagSuffix`, the `-br` of a Brotli answer) so the rest of the tag is still compared by form.
//  - What the production-vs-local comparison does not compare: the body of `init.js` (only `init.json`
//    has a layout compared; `compareInitJs` is set for run-vs-run only), and the Content-Encoding
//    bodies by bytes (their decoded digest is compared, against the plain body of an unencoded answer).
//    KD-INIT-KEYS says so.
import {
  COMPARED_HEADERS,
  SDK_ROW_HEADERS,
  SHAPE_ONLY,
  VOLATILE_HEADERS,
  isComparedHeader,
} from "./rows.mjs";

export const STATUSES = ["MATCH", "MATCH_LAYOUT", "KNOWN_DIFFERENCE", "MISMATCH", "UNKNOWN"];

/** The form of an ETag value: weak flag, quotes, length of the opaque tag and its character class. */
export function etagShape(value) {
  const weak = value.startsWith("W/");
  const rest = weak ? value.slice(2) : value;
  const quoted = rest.length >= 2 && rest.startsWith('"') && rest.endsWith('"');
  const tag = quoted ? rest.slice(1, -1) : rest;
  const charset = /^[0-9a-f]*$/.test(tag)
    ? "hex"
    : /^[0-9A-Za-z+/=_-]*$/.test(tag)
      ? "base64"
      : "other";
  return { weak, quoted, length: tag.length, charset };
}

const IMF_FIXDATE =
  /^(Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2} (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4} \d{2}:\d{2}:\d{2} GMT$/;

/** The form of a Last-Modified value. */
export const lastModifiedShape = (value) => ({ imfFixdate: IMF_FIXDATE.test(value) });

const shapeOf = (name, value) => (name === "etag" ? etagShape(value) : lastModifiedShape(value));

const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

function headerDifferences(a, b) {
  const differences = [];
  let layoutOnly = false;
  const names = new Set(
    [...Object.keys(a.headers ?? {}), ...Object.keys(b.headers ?? {})].filter(
      (name) => isComparedHeader(name) && !VOLATILE_HEADERS.has(name),
    ),
  );
  for (const name of [...names].toSorted()) {
    const left = a.headers?.[name];
    const right = b.headers?.[name];
    if (left === undefined || right === undefined) {
      differences.push({ field: `header:${name}`, a: left, b: right });
    } else if (SHAPE_ONLY.has(name)) {
      if (left.length !== right.length) {
        differences.push({ field: `header:${name}`, a: left, b: right });
        continue;
      }
      const shapes = left.map((v) => shapeOf(name, v));
      const others = right.map((v) => shapeOf(name, v));
      if (!same(shapes, others)) {
        differences.push({ field: `header:${name}`, a: shapes, b: others, reason: "form" });
      } else if (!same(left, right)) layoutOnly = true;
    } else if (!same(left, right)) {
      differences.push({ field: `header:${name}`, a: left, b: right });
    }
  }
  return { differences, layoutOnly };
}

function bodyDifferences(a, b, options) {
  const differences = [];
  if (a.bodyKind?.startsWith("init-") || b.bodyKind?.startsWith("init-")) {
    if (a.bodyKind !== b.bodyKind) {
      differences.push({ field: "bodyKind", a: a.bodyKind, b: b.bodyKind });
    } else if (a.bodyKind === "init-json" || options.compareInitJs) {
      if (!same(a.layout, b.layout))
        differences.push({ field: "layout", a: a.layout, b: b.layout });
    }
    return differences;
  }
  const encoded =
    a.headers?.["content-encoding"] !== undefined || b.headers?.["content-encoding"] !== undefined;
  if (encoded) {
    // The decoded body of an encoded answer against the body of an unencoded one: a row without a
    // Content-Encoding keeps its plain body's size and digest as bodyBytes and bodySha256.
    const plain = (row, field, wire) => row[field] ?? row[wire];
    for (const [field, wire] of [
      ["decodedBytes", "bodyBytes"],
      ["decodedSha256", "bodySha256"],
    ]) {
      const left = plain(a, field, wire);
      const right = plain(b, field, wire);
      if (left !== right) differences.push({ field, a: left, b: right });
    }
    return differences;
  }
  if (a.bodyBytes !== b.bodyBytes) {
    differences.push({ field: "bodyBytes", a: a.bodyBytes, b: b.bodyBytes });
  } else if (a.bodySha256 !== b.bodySha256) {
    differences.push({ field: "bodySha256", a: a.bodySha256, b: b.bodySha256 });
  }
  return differences;
}

/**
 * Splits the differences of one request into those a known-difference entry covers and the rest.
 * An entry names its rows, the fields (`"*"` for all) and the comparison kinds it applies to.
 * @returns {{ remaining: object[], known: { field: string, entry: string }[] }}
 */
export function applyKnownDifferences(id, differences, entries = [], kind) {
  const remaining = [];
  const known = [];
  for (const difference of differences) {
    const entry = entries.find(
      (candidate) =>
        candidate.appliesTo.includes(kind) &&
        candidate.rows.includes(id) &&
        (candidate.fields === "*" || candidate.fields.includes(difference.field)),
    );
    if (entry) known.push({ field: difference.field, entry: entry.id });
    else remaining.push(difference);
  }
  return { remaining, known };
}

/**
 * The rows with the suffix of an ETag removed where an entry names one for the row (`etagSuffix`),
 * and the entries that did it. Only a tag that ends in the suffix inside the quotes is changed.
 */
export function stripEtagSuffixes(id, a, b, entries = [], kind) {
  const applied = [];
  const strip = (row, suffix) => {
    const etag = row.headers?.etag;
    if (!etag) return row;
    const stripped = etag.map((value) =>
      value.endsWith(`${suffix}"`) ? `${value.slice(0, -suffix.length - 1)}"` : value,
    );
    return same(stripped, etag) ? row : { ...row, headers: { ...row.headers, etag: stripped } };
  };
  let left = a;
  let right = b;
  for (const entry of entries) {
    if (!entry.etagSuffix || !entry.appliesTo.includes(kind) || !entry.rows.includes(id)) continue;
    const before = [left, right];
    left = strip(left, entry.etagSuffix);
    right = strip(right, entry.etagSuffix);
    if (left !== before[0] || right !== before[1]) {
      applied.push({ field: "header:etag", entry: entry.id });
    }
  }
  return { a: left, b: right, applied };
}

/**
 * Compares two shaped rows of the same request.
 * @returns {{ status: string, differences: object[], reason?: string }}
 */
export function compareRows(a, b, options = {}) {
  if (a === undefined || b === undefined) {
    return { status: "UNKNOWN", differences: [], reason: "missing-row" };
  }
  if (a.id !== b.id) throw new Error(`rows of different requests: ${a.id} / ${b.id}`);
  if (a.outcome !== "answered" || b.outcome !== "answered") {
    return {
      status: "UNKNOWN",
      differences: [],
      reason: a.outcome !== "answered" ? `a:${a.reason}` : `b:${b.reason}`,
    };
  }
  const stripped = options.known
    ? stripEtagSuffixes(a.id, a, b, options.known.entries, options.known.kind)
    : { a, b, applied: [] };
  ({ a, b } = stripped);
  const differences = [];
  if (a.status !== b.status) differences.push({ field: "status", a: a.status, b: b.status });
  const headers = headerDifferences(a, b);
  differences.push(...headers.differences, ...bodyDifferences(a, b, options));
  const { remaining, known } = options.known
    ? applyKnownDifferences(a.id, differences, options.known.entries, options.known.kind)
    : { remaining: differences, known: [] };
  known.push(...stripped.applied);
  const extra = known.length ? { known } : {};
  if (remaining.length) return { status: "MISMATCH", differences: remaining, ...extra };
  if (known.length) return { status: "KNOWN_DIFFERENCE", differences: remaining, ...extra };
  return {
    status: headers.layoutOnly ? "MATCH_LAYOUT" : "MATCH",
    differences: remaining,
    ...extra,
  };
}

/** Header names present on answered rows that are neither compared nor volatile. */
export function unclassifiedHeaderNames(rows) {
  const names = new Set();
  for (const row of rows) {
    if (row?.outcome !== "answered") continue;
    for (const name of row.headerNames ?? []) {
      if (
        !COMPARED_HEADERS.has(name) &&
        !isComparedHeader(name) &&
        !VOLATILE_HEADERS.has(name) &&
        !SDK_ROW_HEADERS.has(name)
      ) {
        names.add(name);
      }
    }
  }
  return [...names].toSorted();
}

/**
 * Compares two row lists by request id. `ids` (the corpus order) fixes the rows reported.
 */
export function compareRuns(ids, rowsA, rowsB, options = {}) {
  const byId = (rows) => new Map(rows.map((row) => [row.id, row]));
  const left = byId(rowsA);
  const right = byId(rowsB);
  const rows = ids.map((id) => ({ id, ...compareRows(left.get(id), right.get(id), options) }));
  const summary = Object.fromEntries(STATUSES.map((s) => [s, 0]));
  for (const row of rows) summary[row.status] += 1;
  return {
    rows,
    summary,
    unclassifiedHeaders: {
      a: unclassifiedHeaderNames(rowsA),
      b: unclassifiedHeaderNames(rowsB),
    },
  };
}

/**
 * Per condition: the rows that belong to it (primary or `also`, never information-only), their
 * status counts and whether the condition is closable on this comparison: every row is MATCH or
 * MATCH_LAYOUT.
 */
export function conditionVerdicts(requests, results) {
  const status = new Map(results.rows.map((row) => [row.id, row.status]));
  const known = new Map(results.rows.map((row) => [row.id, row.known]));
  const verdicts = {};
  for (const request of requests) {
    if (request.infoOnly) continue;
    for (const condition of [request.condition, ...(request.also ?? [])]) {
      const verdict = (verdicts[condition] ??= {
        rows: 0,
        counts: Object.fromEntries(STATUSES.map((s) => [s, 0])),
        mismatched: [],
        knownDifferenceRows: 0,
      });
      const s = status.get(request.id) ?? "UNKNOWN";
      verdict.rows += 1;
      verdict.counts[s] += 1;
      if (s === "MISMATCH") verdict.mismatched.push(request.id);
      if (known.get(request.id)?.length) verdict.knownDifferenceRows += 1;
    }
  }
  for (const verdict of Object.values(verdicts)) {
    verdict.closable = verdict.counts.MISMATCH === 0 && verdict.counts.UNKNOWN === 0;
  }
  return verdicts;
}
