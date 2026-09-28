// Comparison of two recorded rows modulo the names of opaque server ids.
import { sameRecording } from "./harness.mjs";

const SYMBOL = /<(index|op|uid|t)\d+>/g;

const LISTING_KEYS = ["indexes", "databases", "operations", "fields"];

const canonical = (value) =>
  Array.isArray(value)
    ? value.map(canonical)
    : value && typeof value === "object"
      ? Object.fromEntries(
          Object.keys(value)
            .toSorted()
            .map((k) => [k, canonical(value[k])]),
        )
      : value;

/** An entry's content with every symbol reduced to its kind: the order a listing is put in. */
const masked = (entry) =>
  JSON.stringify(canonical(entry)).replace(SYMBOL, (_symbol, kind) => `<${kind}>`);

/**
 * Renumbers the id and instant symbols of a row in the order they first appear once its
 * listings are in content order. Symbols are numbered by first appearance in the order the
 * server listed the resources, which follows ids each side draws at random; two rows that
 * differ only in that numbering describe the same resources. Entries are ordered by their
 * content with every symbol masked, so the order never depends on the numbering itself, and
 * the renaming is one-to-one on each side, so two distinct resources or instants can never be
 * made to look like one.
 */
export function relabel(row) {
  const ordered = JSON.parse(JSON.stringify(row), (_key, value) => {
    if (!value || typeof value !== "object" || Array.isArray(value)) return value;
    const out = { ...value };
    for (const key of LISTING_KEYS)
      if (Array.isArray(out[key]))
        out[key] = out[key].toSorted((a, b) => masked(a).localeCompare(masked(b)));
    return out;
  });
  const names = new Map();
  const counts = new Map();
  return JSON.parse(
    JSON.stringify(ordered).replace(SYMBOL, (symbol, kind) => {
      if (!names.has(symbol)) {
        counts.set(kind, (counts.get(kind) ?? 0) + 1);
        names.set(symbol, `<${kind}${counts.get(kind)}>`);
      }
      return names.get(symbol);
    }),
  );
}

const LISTINGS = ["indexes", "databases", "operations", "fields"];

/** Whether a row answers a listing: the only rows whose order follows server-drawn ids. */
export const isListing = (row) =>
  LISTINGS.some((key) => Array.isArray(row?.body?.[key]) && row.body[key].length > 1);

/**
 * Whether two listing rows are equal once each side's id symbols are renamed consistently.
 * Any other row must match as recorded.
 */
export const sameModuloIdNames = (a, b) =>
  isListing(a) && isListing(b) && sameRecording(relabel(a), relabel(b));
