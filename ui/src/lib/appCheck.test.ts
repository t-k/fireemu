import { describe, expect, it } from "vitest";
import { canonicalDebugSecret, counterTotals } from "./appCheck";
import type { AppCheckCounter } from "../api/appcheck";

describe("canonicalDebugSecret", () => {
  it("lowercases a UUIDv4, because hexadecimal case never changes the credential", () => {
    const result = canonicalDebugSecret("A1B2C3D4-E5F6-4A7B-8C9D-0E1F2A3B4C5D");
    expect(result.isOk()).toBe(true);
    expect(result.unwrapOr("")).toBe("a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d");
  });

  it("accepts surrounding whitespace from a paste", () => {
    expect(canonicalDebugSecret("  00000000-0000-4000-8000-000000000000\n").unwrapOr("")).toBe(
      "00000000-0000-4000-8000-000000000000",
    );
  });

  it("refuses anything that is not a canonical UUIDv4", () => {
    for (const bad of [
      "",
      "not-a-uuid",
      "00000000000040008000000000000000",
      "{00000000-0000-4000-8000-000000000000}",
      "00000000-0000-3000-8000-000000000000",
      "00000000-0000-4000-c000-000000000000",
      "00000000-0000-4000-8000-00000000000",
      "00000000-0000-4000-8000-000000000000-",
    ]) {
      expect(canonicalDebugSecret(bad).isErr(), bad).toBe(true);
    }
  });
});

describe("counterTotals", () => {
  const counter = (
    service: string,
    appId: string,
    category: string,
    outcome: string,
    count: number,
    fn: string | null = null,
  ): AppCheckCounter => ({ service, appId, function: fn, category, outcome, count });

  const counters: AppCheckCounter[] = [
    counter("firestore", "unknown", "invalid", "denied", 3),
    counter("firestore", "app-1", "valid", "admitted", 5),
    counter("storage", "unknown", "bypass", "admitted", 2),
    counter("auth", "unknown", "invalid", "denied", 1),
  ];

  it("sums the outcomes", () => {
    const totals = counterTotals(counters);
    expect(totals.admitted).toBe(7);
    expect(totals.denied).toBe(4);
  });

  it("counts the per-callable rows of the functions service like any other row", () => {
    const totals = counterTotals([
      ...counters,
      counter("functions", "app-1", "valid", "admitted", 4, "addMessage"),
      counter("functions", "unknown", "missing", "admitted", 2, "deleteMessage"),
    ]);
    expect(totals.admitted).toBe(13);
    expect(totals.denied).toBe(4);
    expect(totals.byCategory).toContainEqual({ category: "missing", count: 2 });
  });

  it("merges the categories across services in a stable order", () => {
    expect(counterTotals(counters).byCategory).toEqual([
      { category: "bypass", count: 2 },
      { category: "invalid", count: 4 },
      { category: "valid", count: 5 },
    ]);
  });

  it("answers an empty ring with zeroes", () => {
    expect(counterTotals([])).toEqual({ admitted: 0, denied: 0, byCategory: [] });
  });
});

describe("canonicalDebugSecret shape", () => {
  it("names the failure and anchors the whole string", () => {
    expect(canonicalDebugSecret("x").unwrapOr("ok")).toBe("ok");
    expect(canonicalDebugSecret("x")._unsafeUnwrapErr()).toBe("shape");
    expect(canonicalDebugSecret("z00000000-0000-4000-8000-000000000000").isErr()).toBe(true);
    expect(canonicalDebugSecret("00000000-0000-4000-8000-000000000000z").isErr()).toBe(true);
    expect(canonicalDebugSecret("00000000-0000-4000-8000-00000000000g").isErr()).toBe(true);
  });
});
