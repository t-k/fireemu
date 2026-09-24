// Owner-approved FS-QUERY-INDEX divergences (spec/compatibility/closure/FS-QUERY-INDEX.json scope
// decisions S4 and S5). Each entry names the exact rows and a normalization that removes only
// the part production decides with an internal hash fireemu cannot reproduce; everything else
// in those rows is still compared strictly, and the raw recordings stay as they are.

import { PROGRAMS } from "./corpus.mjs";

const INEQUALITY_ROWS = [
  "inequality-fields-11-letters",
  "inequality-fields-12-reversed",
  "inequality-fields-11",
  "inequality-fields-10-and-not-equal",
].map((step) => `fs-query-index/query-limits/not-in-and-inequalities#${step}`);

const MERGE_ROWS = [
  ...["merge-with-order-plan", "merge-with-order-analyze"].map(
    (step) => `fs-query-index/explain/queries#${step}`,
  ),
  ...[
    "larger-later-field",
    "larger-earlier-field",
    "filters-reversed",
    "automatic-members",
    "automatic-members-reversed",
    "three-automatic-members",
  ].flatMap((id) =>
    ["plan", "analyze"].map((kind) => `fs-query-index/explain/merge-order#${id}-${kind}`),
  ),
];

const PARTITION_ROWS = [
  ...[
    "count-1",
    "count-2",
    "count-3",
    "count-8",
    "count-8-repeat",
    "count-4-page-1",
    "count-4-page-2",
    "count-4-page-size-3",
    "count-4-page-size-3-next",
  ].map((step) => `fs-query-index/partition-query/large-group#${step}`),
  ...["count-2", "count-4-page-1", "count-4-page-2"].map(
    (step) => `fs-query-index/grpc/partitions#${step}`,
  ),
];

/** A count above the number of samples returns every sample; how many that is is part of the
 * sampling too. */
const ALL_SAMPLES_ROW = "fs-query-index/partition-query/large-group#count-64";
const ALL_SAMPLES_REQUESTED = 64;

/** The range reconstruction rows: their counts follow the cursors, their sum does not. */
export const RANGE_ROWS = [0, 1, 2, 3].map(
  (i) => `fs-query-index/partition-query/large-group#range-${i}`,
);

/** Deep copy with `replace(key, value)` applied to every object entry (`undefined` keeps it). */
function mapEntries(value, replace) {
  if (Array.isArray(value)) return value.map((item) => mapEntries(item, replace));
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => {
        const replaced = replace(key, item);
        return [key, replaced === undefined ? mapEntries(item, replace) : replaced];
      }),
    );
  }
  return value;
}

/** `[g, f, e]` in any message becomes `[e, f, g]`. */
const sortBracketedLists = (recorded) =>
  mapEntries(recorded, (key, item) =>
    typeof item === "string" && key === "message"
      ? item.replace(/\[([^\]]*)\]/g, (_, list) => `[${list.split(", ").toSorted().join(", ")}]`)
      : undefined,
  );

/** The `indexesUsed` lists of a recorded answer, in order. */
function indexLists(recorded) {
  const lists = [];
  mapEntries(recorded, (key, item) => {
    if (key === "indexesUsed" && Array.isArray(item)) lists.push(JSON.stringify(item));
    return undefined;
  });
  return lists;
}

/** Merge members as a multiset, and the join's entry count, which follows their order. */
const unorderedMergeMembers = (recorded) =>
  mapEntries(recorded, (key, item) => {
    if (key === "indexesUsed" && Array.isArray(item))
      return item.toSorted((a, b) =>
        JSON.stringify(a) < JSON.stringify(b) ? -1 : JSON.stringify(a) > JSON.stringify(b) ? 1 : 0,
      );
    if (key === "index_entries_scanned") return "<merge-entries>";
    return undefined;
  });

/** The `index_entries_scanned` and `documents_scanned` of an analyzed answer, if any. */
function scanCounts(recorded) {
  let entries;
  let documents;
  mapEntries(recorded, (key, item) => {
    if (key === "index_entries_scanned") entries = Number(item);
    if (key === "documents_scanned") documents = Number(item);
    return undefined;
  });
  return { entries, documents };
}

const valueEquals = (a, b) => JSON.stringify(a) === JSON.stringify(b);

/**
 * The bounds any join order's walk stays within for a merge row, from the corpus seed: every
 * returned document is read once in each member (lower), and no walk reads more than every
 * entry of every member (upper). A member's entries are the seed documents of the queried
 * collection that match its equality field and hold every ordered field.
 */
function mergeEntryBounds(row, recorded) {
  const [programId, stepId] = row.split("#");
  const program = PROGRAMS.find((candidate) => candidate.id === programId);
  const query = program?.steps.find((step) => step.id === stepId)?.body?.structuredQuery;
  const lists = indexLists(recorded).map((list) => JSON.parse(list));
  if (!query || lists.length !== 1) return undefined;
  const collection = query.from[0].collectionId;
  const equalities = (query.where?.compositeFilter?.filters ?? [query.where])
    .map((filter) => filter?.fieldFilter)
    .filter((filter) => filter?.op === "EQUAL");
  const ordered = (query.orderBy ?? []).map((order) => order.field.fieldPath);
  const documents = program.seed.filter(
    ([path]) => path.startsWith(`${collection}/`) && path.split("/").length === 2,
  );
  const members = lists[0].map((used) => /^\(([^ ]+) /.exec(used.properties)?.[1]);
  const sizes = members.map((field) => {
    const filter = equalities.find((candidate) => candidate.field.fieldPath === field);
    if (!filter) return undefined;
    return documents.filter(
      ([, fields]) =>
        valueEquals(fields[field], filter.value) && ordered.every((name) => name in fields),
    ).length;
  });
  if (sizes.some((size) => size === undefined)) return undefined;
  const { documents: returned } = scanCounts(recorded);
  return { lower: members.length * returned, upper: sizes.reduce((a, b) => a + b, 0) };
}

/**
 * A merge row differs only by member order: the members differ in order (when they are in the
 * same order, the walk is the same and its entry count must match too), the rows are equal
 * with the members compared as a multiset and the walk's entry count masked, and on an
 * analyzed row both entry counts lie within the bounds every join order keeps to.
 */
const mergeOrderOnly = (production, fireemu, row) => {
  if (JSON.stringify(indexLists(production)) === JSON.stringify(indexLists(fireemu))) return false;
  if (!same(unorderedMergeMembers(production), unorderedMergeMembers(fireemu))) return false;
  const counted = [scanCounts(production).entries, scanCounts(fireemu).entries];
  if (counted.every((entries) => entries === undefined)) return true;
  const bounds = mergeEntryBounds(row, production);
  return (
    bounds !== undefined &&
    counted.every((entries) => entries >= bounds.lower && entries <= bounds.upper)
  );
};

/** A partition cursor's sampled document: `.../qroot/r<k>/qp/d<nnnnn>` loses `r<k>` and the id. */
const SAMPLED_KEY = /\/qroot\/r\d+\/qp\/d\d{5}$/;
const maskKey = (reference) =>
  typeof reference === "string" && SAMPLED_KEY.test(reference)
    ? reference.replace(SAMPLED_KEY, "/qroot/<r>/qp/<id>")
    : reference;

/** Partition cursors keep their number, shape and group; the sampled document is masked. */
const maskedPartitionKeys = (recorded) =>
  mapEntries(recorded, (key, item) => (key === "referenceValue" ? maskKey(item) : undefined));

/** The fewest cursors every sample gives: the largest count answered in full (`count-8`). */
const FEWEST_SAMPLES = 8;
/** The sampling rate production and fireemu share (S5): about one key in 141. */
const SAMPLE_RATE = 1 / 141;
/** The documents of the large partition group. */
const LARGE_GROUP_SIZE = 2000;

/**
 * How many samples a group of `size` plausibly has at that rate: the binomial mean within 3.5
 * standard deviations, and never fewer than the largest count answered in full.
 */
export function plausibleSamples(size) {
  const mean = size * SAMPLE_RATE;
  const spread = 3.5 * Math.sqrt(size * SAMPLE_RATE * (1 - SAMPLE_RATE));
  return {
    fewest: Math.max(FEWEST_SAMPLES, Math.ceil(mean - spread)),
    most: Math.min(ALL_SAMPLES_REQUESTED - 1, Math.floor(mean + spread)),
  };
}

/**
 * Every sample: a number of cursors a group of 2,000 documents plausibly samples (production
 * 14, fireemu 20 as recorded), each with a masked key and the same shape as production's.
 */
const allSamples = (recorded) =>
  mapEntries(maskedPartitionKeys(recorded), (key, item) => {
    if (key !== "partitions" || !Array.isArray(item)) return undefined;
    const shapes = [...new Set(item.map((cursor) => JSON.stringify(cursor)))];
    const { fewest, most } = plausibleSamples(LARGE_GROUP_SIZE);
    const count = item.length >= fewest && item.length <= most ? "<every sample>" : item.length;
    return { count, shapes };
  });

const maskedCount = (recorded) =>
  mapEntries(recorded, (key) => (key === "integerValue" ? "<range-count>" : undefined));

const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const equalAfter = (normalize) => (production, fireemu) =>
  same(normalize(production), normalize(fireemu));

export const DIVERGENCES = [
  { decision: "S4", rows: INEQUALITY_ROWS, approve: equalAfter(sortBracketedLists) },
  { decision: "S4", rows: MERGE_ROWS, approve: mergeOrderOnly },
  { decision: "S5", rows: PARTITION_ROWS, approve: equalAfter(maskedPartitionKeys) },
  { decision: "S5", rows: [ALL_SAMPLES_ROW], approve: equalAfter(allSamples) },
  { decision: "S5", rows: RANGE_ROWS, approve: equalAfter(maskedCount) },
];

/**
 * The scope decision under which a mismatching row is an approved divergence, or `undefined`:
 * the row is listed and its entry approves the difference.
 */
export function approvedDivergence(row, production, fireemu) {
  const entry = DIVERGENCES.find((candidate) => candidate.rows.includes(row));
  if (!entry || production === undefined || fireemu === undefined) return undefined;
  return entry.approve(production, fireemu, row) ? entry.decision : undefined;
}

/** The sum of the range counts of one side, or `undefined` when a range did not answer one. */
export function rangeTotal(recordings) {
  let total = 0n;
  for (const recorded of recordings) {
    const value = recorded?.body?.[0]?.result?.aggregateFields?.c?.integerValue;
    if (value === undefined) return undefined;
    total += BigInt(value);
  }
  return total;
}

/** The count rows whose fireemu cursors must nest, smallest count first. */
const NESTED_COUNT_ROWS = ["count-1", "count-2", "count-3", "count-8", "count-64"].map(
  (step) => `fs-query-index/partition-query/large-group#${step}`,
);

const cursorKeys = (recorded) =>
  (recorded?.body?.partitions ?? []).map((cursor) => cursor.values?.[0]?.referenceValue);

/** Resource names compared segment by segment, as keys are ordered. */
const byKey = (a, b) => {
  const [x, y] = [a.split("/"), b.split("/")];
  for (let i = 0; i < Math.min(x.length, y.length); i += 1) {
    if (x[i] !== y[i]) return x[i] < y[i] ? -1 : 1;
  }
  return x.length - y.length;
};

/**
 * What S5 still requires across rows once the keys are masked: the range counts add up to
 * the same total on both sides, and fireemu's cursors come in key order and nest from one
 * count to the next. Returns the rows to demote and the totals, for the evidence.
 */
export function crossRowChecks(rows) {
  const find = (id) => rows.find((row) => row.row === id);
  const demote = new Set();
  const ranges = RANGE_ROWS.map(find);
  const totals = ranges.every(Boolean)
    ? {
        production: rangeTotal(ranges.map((row) => row.production))?.toString(),
        fireemu: rangeTotal(ranges.map((row) => row.fireemu))?.toString(),
      }
    : undefined;
  if (totals && (totals.production === undefined || totals.production !== totals.fireemu)) {
    for (const row of ranges) demote.add(row.row);
  }
  const counts = NESTED_COUNT_ROWS.map(find);
  if (counts.every(Boolean)) {
    const keys = counts.map((row) => cursorKeys(row.fireemu));
    const ordered = keys.every((list) =>
      list.every((key, i) => i === 0 || byKey(list[i - 1], key) < 0),
    );
    const nested = keys.every(
      (list, i) => i === 0 || keys[i - 1].every((key) => list.includes(key)),
    );
    if (!ordered || !nested) for (const row of counts) demote.add(row.row);
  }
  return { demote, rangeTotals: totals };
}
