import { describe, expect, it } from "vitest";
import { lineLevel, matchesLog } from "./logFilter";

describe("lineLevel", () => {
  it("reads the severity from the leading token of a log-frame line", () => {
    expect(lineLevel("info hello world")).toBe("info");
    expect(lineLevel("warn something happened")).toBe("warn");
    expect(lineLevel("error boom")).toBe("error");
    expect(lineLevel("debug details")).toBe("debug");
  });

  it("collapses aliases into their bucket", () => {
    expect(lineLevel("warning careful")).toBe("warn");
    expect(lineLevel("notice fyi")).toBe("info");
    expect(lineLevel("fatal down")).toBe("error");
    expect(lineLevel("CRITICAL down")).toBe("error");
  });

  it("returns null for a line with no recognized prefix (stderr)", () => {
    expect(lineLevel("Traceback (most recent call last):")).toBeNull();
    expect(lineLevel("")).toBeNull();
    expect(lineLevel("<script>alert(1)</script>")).toBeNull();
  });
});

describe("matchesLog", () => {
  it("passes everything when the filter is empty", () => {
    expect(matchesLog("anything", { level: "all", text: "" })).toBe(true);
  });

  it("filters by level bucket", () => {
    expect(matchesLog("warn late", { level: "warn", text: "" })).toBe(true);
    expect(matchesLog("info fine", { level: "warn", text: "" })).toBe(false);
  });

  it("treats lines with no prefix as `other`", () => {
    expect(matchesLog("raw stderr line", { level: "other", text: "" })).toBe(true);
    expect(matchesLog("info structured", { level: "other", text: "" })).toBe(false);
  });

  it("filters by case-insensitive substring", () => {
    expect(matchesLog("info Deploying users", { level: "all", text: "deploy" })).toBe(true);
    expect(matchesLog("info Deploying users", { level: "all", text: "storage" })).toBe(false);
  });

  it("requires both the level and the text to match", () => {
    expect(matchesLog("error write failed", { level: "error", text: "write" })).toBe(true);
    expect(matchesLog("error write failed", { level: "warn", text: "write" })).toBe(false);
    expect(matchesLog("error write failed", { level: "error", text: "read" })).toBe(false);
  });
});
