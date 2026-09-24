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

/** Partition cursors keep their number and shape; the sampled key is masked. */
const maskedPartitionKeys = (recorded) =>
  mapEntries(recorded, (key, item) =>
    key === "partitions" && Array.isArray(item)
      ? item.map((cursor) =>
          mapEntries(cursor, (inner) => (inner === "referenceValue" ? "<sample>" : undefined)),
        )
      : undefined,
  );

/** Every sample: fewer cursors than requested, keys masked. */
const allSamples = (recorded) =>
  mapEntries(recorded, (key, item) =>
    key === "partitions" && Array.isArray(item)
      ? item.length < ALL_SAMPLES_REQUESTED
        ? "<every sample>"
        : item.length
      : undefined,
  );

const maskedCount = (recorded) =>
  mapEntries(recorded, (key) => (key === "integerValue" ? "<range-count>" : undefined));

export const DIVERGENCES = [
  { decision: "S4", rows: INEQUALITY_ROWS, normalize: sortBracketedLists },
  { decision: "S4", rows: MERGE_ROWS, normalize: unorderedMergeMembers },
  { decision: "S5", rows: PARTITION_ROWS, normalize: maskedPartitionKeys },
  { decision: "S5", rows: [ALL_SAMPLES_ROW], normalize: allSamples },
  { decision: "S5", rows: RANGE_ROWS, normalize: maskedCount },
];

/**
 * The scope decision under which a mismatching row is an approved divergence, or `undefined`:
 * the row is listed and the two recordings are equal once that entry's normalization is applied.
 */
export function approvedDivergence(row, production, fireemu) {
  const entry = DIVERGENCES.find((candidate) => candidate.rows.includes(row));
  if (!entry || production === undefined || fireemu === undefined) return undefined;
  const same =
    JSON.stringify(entry.normalize(production)) === JSON.stringify(entry.normalize(fireemu));
  return same ? entry.decision : undefined;
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
