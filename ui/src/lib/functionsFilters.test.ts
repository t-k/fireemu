import { describe, expect, it } from "vitest";
import { readFunctionFilters, functionFiltersUrl } from "./functionsFilters";

describe("function filter links", () => {
  it("restores valid filters and normalizes an unknown level", () => {
    expect(readFunctionFilters(new URLSearchParams("function=hello&level=error&q=secret"))).toEqual(
      { function: "hello", level: "error", text: "secret" },
    );
    expect(readFunctionFilters(new URLSearchParams("level=invalid"))).toEqual({
      function: "",
      level: "all",
      text: "",
    });
  });
  it("shares only allowlisted fields and excludes text unless explicitly requested", () => {
    const filters = { function: "hello", level: "warn" as const, text: "private text" };
    const url = new URL(
      functionFiltersUrl(
        "http://localhost/ui/functions?token=secret&other=secret#secret",
        filters,
        false,
      ),
    );
    expect([...url.searchParams]).toEqual([
      ["function", "hello"],
      ["level", "warn"],
    ]);
    expect(url.hash).toBe("");
    expect(new URL(functionFiltersUrl(url.href, filters, true)).searchParams.get("q")).toBe(
      "private text",
    );
  });
});
