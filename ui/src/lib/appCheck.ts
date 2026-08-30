import { err, ok, type Result } from "neverthrow";
import type { AppCheckCounter } from "../api/appcheck";

// Pure App Check helpers. The daemon is the authority on every one of these rules; the page
// applies them first only so a mistyped secret is refused without a round trip.

const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

/**
 * A debug secret in the canonical form the registry hashes: lowercase, hyphenated UUIDv4.
 * Hexadecimal case never changes the credential, so the input is lowercased before the
 * shape is checked.
 */
export const canonicalDebugSecret = (text: string): Result<string, "shape"> => {
  const canonical = text.trim().toLowerCase();
  return UUID_V4.test(canonical) ? ok(canonical) : err("shape");
};

/** One aggregated line of the counters view. */
export type CounterTotals = {
  admitted: number;
  denied: number;
  /** Counts by credential category (`bypass`, `missing`, `valid`, `invalid`). */
  byCategory: { category: string; count: number }[];
};

/**
 * Totals over the per-service counters the control API returns. Categories come back in a
 * stable order so the table does not reshuffle between refreshes.
 */
export const counterTotals = (counters: readonly AppCheckCounter[]): CounterTotals => {
  const byCategory = new Map<string, number>();
  let admitted = 0;
  let denied = 0;
  for (const counter of counters) {
    byCategory.set(counter.category, (byCategory.get(counter.category) ?? 0) + counter.count);
    if (counter.outcome === "admitted") {
      admitted += counter.count;
    } else {
      denied += counter.count;
    }
  }
  return {
    admitted,
    denied,
    byCategory: [...byCategory.entries()]
      .map(([category, count]) => ({ category, count }))
      .toSorted((a, b) => a.category.localeCompare(b.category)),
  };
};
