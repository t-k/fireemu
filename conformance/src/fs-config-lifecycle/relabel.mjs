// Comparison of two recorded rows modulo the names of opaque server ids.
import { sameRecording, sortListings } from "./harness.mjs";

const SYMBOL = /<(index|op|uid)\d+>/g;

/**
 * Renumbers the id symbols of a row in the order they first appear once its listings are in
 * content order. Symbols are numbered by first appearance in the order the server listed the
 * resources, which follows ids each side draws at random; two rows that differ only in that
 * numbering describe the same resources. The renaming is one-to-one on each side, so two
 * distinct resources can never be made to look like one.
 */
export function relabel(row) {
  const ordered = JSON.parse(JSON.stringify(row), (_key, value) =>
    value && typeof value === "object" && !Array.isArray(value) ? sortListings(value) : value,
  );
  const text = JSON.stringify(ordered);
  const names = new Map();
  return JSON.parse(
    text.replace(SYMBOL, (symbol, kind) => {
      if (!names.has(symbol)) {
        const count = [...names.values()].filter((v) => v.startsWith(`<${kind}`)).length;
        names.set(symbol, `<${kind}${count + 1}>`);
      }
      return names.get(symbol);
    }),
  );
}

/** Whether two rows are equal once each side's id symbols are renamed consistently. */
export const sameModuloIdNames = (a, b) => sameRecording(relabel(a), relabel(b));
