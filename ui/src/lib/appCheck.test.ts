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
  const counters: AppCheckCounter[] = [
    { service: "firestore", appId: "unknown", category: "invalid", outcome: "denied", count: 3 },
    { service: "firestore", appId: "app-1", category: "valid", outcome: "admitted", count: 5 },
    { service: "storage", appId: "unknown", category: "bypass", outcome: "admitted", count: 2 },
    { service: "auth", appId: "unknown", category: "invalid", outcome: "denied", count: 1 },
  ];

  it("sums the outcomes", () => {
    const totals = counterTotals(counters);
    expect(totals.admitted).toBe(7);
    expect(totals.denied).toBe(4);
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
