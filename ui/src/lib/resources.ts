// The session resource report (`GET /v1/sessions/{s}/resources`) as the Runtime panel reads
// it: the wire shape, and the small pure summaries the panel renders. Nothing here fetches.

export type Measure = "logical" | "estimate" | "process";
export type Unit = "bytes" | "count";

export type Gauge = {
  id: string;
  measure: Measure;
  unit: Unit;
  current: number;
  limit: number | null;
  reclaimable: number;
};

export type Refusal = { reason: string; count: number };

export type RetentionRoot = {
  kind: string;
  id: string;
  count: number;
  bytes: number;
  outstanding: boolean;
};

export type ServiceResources = {
  service: string;
  gauges: Gauge[];
  refusals: Refusal[];
  roots: { total: number; truncated: boolean; items: RetentionRoot[] };
};

export type ResourceReport = {
  schemaVersion: number;
  session: string;
  project: string;
  complete: boolean;
  rootBudget: number;
  services: ServiceResources[];
  errors: { service: string; message: string }[];
};

export type Allowance = { service: string; kind: string; id: string; reason: string };

export type QuiescenceResult =
  | { quiescent: true; allowed: number }
  | {
      quiescent: false;
      leaks: { service: string; kind: string; id: string; count: number; bytes: number }[];
      staleAllowances: Allowance[];
      truncatedServices: string[];
    };

/** `1.5 MiB`-style text for a byte count; counts are rendered as plain integers. */
export const formatQuantity = (value: number, unit: Unit): string => {
  if (unit === "count") return String(value);
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let scaled = value;
  let index = 0;
  while (scaled >= 1024 && index < units.length - 1) {
    scaled /= 1024;
    index += 1;
  }
  const digits = index === 0 || scaled >= 100 ? 0 : scaled >= 10 ? 1 : 2;
  return `${scaled.toFixed(digits)} ${units[index]}`;
};

/** The share of a gauge's limit in use, in whole percent; `null` without a limit. */
export const saturation = (gauge: Gauge): number | null => {
  if (gauge.limit === null || gauge.limit <= 0) return null;
  return Math.min(100, Math.floor((gauge.current / gauge.limit) * 100));
};

export type ServiceSummary = {
  service: string;
  outstanding: number;
  saturated: string[];
  refused: number;
  truncated: boolean;
};

/** One line per service: what blocks quiescence, what is at its limit, what was refused. */
export const summarize = (report: ResourceReport): ServiceSummary[] =>
  report.services.map((service) => ({
    service: service.service,
    outstanding: service.roots.items.filter((root) => root.outstanding).length,
    saturated: service.gauges
      .filter((gauge) => gauge.limit !== null && gauge.current >= gauge.limit)
      .map((gauge) => gauge.id),
    refused: service.refusals.reduce((sum, refusal) => sum + refusal.count, 0),
    truncated: service.roots.truncated,
  }));

/** Whether anything in the report needs attention before the runtime can be called idle. */
export const needsAttention = (report: ResourceReport): boolean =>
  !report.complete ||
  summarize(report).some(
    (line) => line.outstanding > 0 || line.saturated.length > 0 || line.truncated,
  );

/**
 * Parses the allow-list textarea: one `service kind id reason...` per line, blank lines and
 * `#` comments ignored. Returns the offending line number on a malformed entry.
 */
export const parseAllowances = (
  text: string,
): { ok: true; allow: Allowance[] } | { ok: false; line: number } => {
  const allow: Allowance[] = [];
  const lines = text.split("\n");
  for (let index = 0; index < lines.length; index += 1) {
    const line = (lines[index] ?? "").trim();
    if (line === "" || line.startsWith("#")) continue;
    const parts = line.split(/\s+/);
    if (parts.length < 4) return { ok: false, line: index + 1 };
    const [service, kind, id, ...reason] = parts;
    if (!service || !kind || !id) return { ok: false, line: index + 1 };
    allow.push({ service, kind, id, reason: reason.join(" ") });
  }
  return { ok: true, allow };
};
