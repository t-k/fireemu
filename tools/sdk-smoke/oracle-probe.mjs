import { isDeepStrictEqual } from "node:util";

// Report acceptance separately from result correctness and observation-only evidence.
export async function probe(name, expected, fn) {
  let outcome;
  let detail = "";
  let value;
  try {
    value = await fn();
    outcome = "ok";
    detail = JSON.stringify(value);
  } catch (e) {
    outcome = e.code !== undefined ? String(e.code) : "error";
    detail = String(e.message ?? e)
      .split("\n")[0]
      .slice(0, 160);
  }
  const outcomeMatches = expected === null ? null : expected.outcome === outcome;
  const valueMatches =
    expected !== null && Object.hasOwn(expected, "value")
      ? outcome === "ok" && isDeepStrictEqual(value, expected.value)
      : null;
  return {
    name,
    mode: expected === null ? "observation" : "regression",
    expected,
    outcome,
    detail,
    outcomeMatches,
    valueMatches,
    matches: expected === null ? null : outcomeMatches && valueMatches !== false,
  };
}
