import type { LevelFilter } from "./logFilter";

export type FunctionFilters = { function: string; level: LevelFilter; text: string };
const levels = new Set(["all", "debug", "info", "warn", "error", "other"]);
export const readFunctionFilters = (params: URLSearchParams): FunctionFilters => ({
  function: params.get("function") ?? "",
  level: levels.has(params.get("level") ?? "") ? (params.get("level") as LevelFilter) : "all",
  text: params.get("q") ?? "",
});

/** Share only explicit filter fields, never inherited credentials or arbitrary URL data. */
export const functionFiltersUrl = (
  base: string,
  filters: FunctionFilters,
  includeText: boolean,
): string => {
  const url = new URL(base);
  url.search = "";
  url.hash = "";
  if (filters.function) url.searchParams.set("function", filters.function);
  if (filters.level !== "all") url.searchParams.set("level", filters.level);
  if (includeText && filters.text) url.searchParams.set("q", filters.text);
  return url.href;
};
