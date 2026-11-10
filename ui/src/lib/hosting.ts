import type { HostingRule } from "../api/hosting";

/** How a rule picks the paths it applies to. */
export type RuleMatcher = { kind: "glob" | "regex"; pattern: string } | { kind: "none" };

const text = (value: unknown): string | null =>
  typeof value === "string" && value !== "" ? value : null;

/**
 * The matcher of a rule as the server reads it: the first non-empty of `glob` and `source`
 * (a glob), otherwise `regex`. A rule with neither matches nothing.
 */
export const ruleMatcher = (rule: HostingRule): RuleMatcher => {
  const glob = text(rule.glob) ?? text(rule.source);
  if (glob !== null) return { kind: "glob", pattern: glob };
  const regex = text(rule.regex);
  return regex !== null ? { kind: "regex", pattern: regex } : { kind: "none" };
};

/** Where a rewrite sends a request. */
export type RewriteTarget =
  | { kind: "file"; destination: string }
  | { kind: "function"; id: string; region: string | null }
  | { kind: "run"; id: string; region: string | null }
  | { kind: "none" };

const serviceTarget = (
  kind: "function" | "run",
  value: unknown,
  idKey: "functionId" | "serviceId",
): RewriteTarget => {
  if (typeof value === "string") return { kind, id: value, region: null };
  if (value !== null && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return { kind, id: text(record[idKey]) ?? "", region: text(record.region) };
  }
  return { kind, id: "", region: null };
};

/**
 * The target of a rewrite in the order the server tries them: a `destination` file wins over
 * a `function`, which wins over `run`.
 */
export const rewriteTarget = (rule: HostingRule): RewriteTarget => {
  const destination = text(rule.destination);
  if (destination !== null) return { kind: "file", destination };
  if (rule.function !== undefined) return serviceTarget("function", rule.function, "functionId");
  if (rule.run !== undefined) return serviceTarget("run", rule.run, "serviceId");
  return { kind: "none" };
};

/** A redirect's destination and status (301 when the rule gives none). */
export const redirectTarget = (rule: HostingRule): { destination: string; status: number } => ({
  destination: text(rule.destination) ?? "",
  status: typeof rule.type === "number" && Number.isInteger(rule.type) ? rule.type : 301,
});

/** The `key: value` pairs of a headers rule, skipping entries the server would skip. */
export const ruleHeaders = (rule: HostingRule): { key: string; value: string }[] => {
  const list = Array.isArray(rule.headers) ? (rule.headers as unknown[]) : [];
  const pairs: { key: string; value: string }[] = [];
  for (const entry of list) {
    if (entry === null || typeof entry !== "object") continue;
    const { key, value } = entry as Record<string, unknown>;
    if (typeof key === "string" && typeof value === "string") pairs.push({ key, value });
  }
  return pairs;
};
