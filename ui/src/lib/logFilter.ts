// Client-side filtering for the function log stream. The daemon's `functions/logs` SSE sends
// each log line as a plain string: a `log`-frame line is stored as `"{level} {message}"` or
// `"{level} {id} {message}"` (default level `info`), while a stderr line has no level prefix.
// So severity is recovered from the leading token, and everything else is a case-insensitive
// substring match. These are pure functions so they are unit-tested without a DOM.

/** The severity buckets the level filter offers, plus `other` for lines with no known prefix. */
export const LOG_LEVELS = ["debug", "info", "warn", "error"] as const;
export type LogLevel = (typeof LOG_LEVELS)[number];

/** The level filter's selectable values. */
export type LevelFilter = "all" | LogLevel | "other";

// The runner emits Cloud-Logging-style severities; several collapse into one bucket so the
// filter stays short and predictable.
const LEVEL_ALIASES: Readonly<Record<string, LogLevel>> = {
  debug: "debug",
  info: "info",
  notice: "info",
  warn: "warn",
  warning: "warn",
  error: "error",
  fatal: "error",
  critical: "error",
};

/**
 * The severity of a function log line when it begins with one of the runner's level tokens,
 * or `null` for a line with no recognized prefix (a raw stderr line).
 */
export const lineLevel = (line: string): LogLevel | null => {
  const token = line.trimStart().split(/\s/, 1)[0]?.toLowerCase() ?? "";
  return LEVEL_ALIASES[token] ?? null;
};

export type LogFilter = { level: LevelFilter; text: string };

/** Whether a log line passes both the level bucket and the case-insensitive text query. */
export const matchesLog = (line: string, filter: LogFilter): boolean => {
  if (filter.level !== "all") {
    const level = lineLevel(line);
    if (filter.level === "other") {
      if (level !== null) {
        return false;
      }
    } else if (level !== filter.level) {
      return false;
    }
  }
  if (filter.text !== "") {
    return line.toLowerCase().includes(filter.text.toLowerCase());
  }
  return true;
};
