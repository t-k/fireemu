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
  | { kind: "function"; id: string; region: string }
  | { kind: "run"; id: string; region: string }
  | { kind: "none" };

/** The region the server routes a service rewrite to when nothing names one. */
const DEFAULT_REGION = "us-central1";

/**
 * The region the server routes to: the target object's own `region` when that key is present,
 * otherwise the rule's `region`, otherwise `us-central1`. A key that is present but not a string
 * still wins and leaves the default, as in the server (hosting.rs `proxy`).
 */
const effectiveRegion = (rule: HostingRule, target: unknown): string => {
  const own =
    target !== null && typeof target === "object" && Object.hasOwn(target, "region")
      ? (target as Record<string, unknown>)
      : rule;
  return typeof own.region === "string" ? own.region : DEFAULT_REGION;
};

const serviceTarget = (
  kind: "function" | "run",
  rule: HostingRule,
  idKey: "functionId" | "serviceId",
): RewriteTarget => {
  const value = rule[kind];
  const region = effectiveRegion(rule, value);
  if (typeof value === "string") return { kind, id: value, region };
  if (value !== null && typeof value === "object") {
    return { kind, id: text((value as Record<string, unknown>)[idKey]) ?? "", region };
  }
  return { kind, id: "", region };
};

/**
 * The target of a rewrite in the order the server tries them: a `destination` file wins over
 * a `function`, which wins over `run`.
 */
export const rewriteTarget = (rule: HostingRule): RewriteTarget => {
  const destination = text(rule.destination);
  if (destination !== null) return { kind: "file", destination };
  if (rule.function !== undefined) return serviceTarget("function", rule, "functionId");
  if (rule.run !== undefined) return serviceTarget("run", rule, "serviceId");
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
