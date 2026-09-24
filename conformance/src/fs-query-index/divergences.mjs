// Owner-approved FS-QUERY-INDEX divergences (spec/compatibility/closure/FS-QUERY-INDEX.json scope
// decisions S4 and S5). Each entry names the exact rows and a normalization that removes only
// the part production decides with an internal hash fireemu cannot reproduce; everything else
// in those rows is still compared strictly, and the raw recordings stay as they are.

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

/**
 * A merge row differs only by member order: the members differ in order (when they are in the
 * same order, the walk is the same and its entry count must match too), and the rows are equal
 * with the members compared as a multiset and the walk's entry count masked.
 */
const mergeOrderOnly = (production, fireemu) =>
  JSON.stringify(indexLists(production)) !== JSON.stringify(indexLists(fireemu)) &&
  same(unorderedMergeMembers(production), unorderedMergeMembers(fireemu));

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

/**
 * Every sample: at least as many cursors as the largest count answered in full and fewer than
 * requested, each with a masked key and the same shape as production's.
 */
const allSamples = (recorded) =>
  mapEntries(maskedPartitionKeys(recorded), (key, item) => {
    if (key !== "partitions" || !Array.isArray(item)) return undefined;
    const shapes = [...new Set(item.map((cursor) => JSON.stringify(cursor)))];
    const count =
      item.length >= FEWEST_SAMPLES && item.length < ALL_SAMPLES_REQUESTED
        ? "<every sample>"
        : item.length;
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
  return entry.approve(production, fireemu) ? entry.decision : undefined;
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
